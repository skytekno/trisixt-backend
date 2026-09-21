//! OAuth 2.1 public clients and the REST backend used by Trisixt MCP tools.
use crate::{
    auth::{AuthUser, InternalPrincipal, authorize_project, new_token, token_hash},
    domains::rate_limit,
    error::AppError,
    state::AppState,
};
use axum::{
    Form, Json, Router,
    body::Body,
    extract::{FromRequestParts, Path, Query, Request, State},
    http::{HeaderMap, Method, StatusCode, request::Parts},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tower::ServiceExt;
use uuid::Uuid;

type Api = Result<Json<Value>, AppError>;
fn issuer(st: &AppState) -> String {
    std::env::var("PUBLIC_URL")
        .unwrap_or_else(|_| format!("https://{}", st.config.server_host))
        .trim_end_matches('/')
        .to_owned()
}
fn resource(st: &AppState) -> String {
    format!("{}/api/v1/mcp", issuer(st))
}
fn scope(input: &str) -> Result<String, AppError> {
    let mut scopes = input.split_whitespace().collect::<Vec<_>>();
    scopes.sort_unstable();
    scopes.dedup();
    if scopes.is_empty()
        || scopes
            .iter()
            .any(|s| !matches!(*s, "mcp:full" | "mcp:read" | "mcp:write"))
    {
        return Err(AppError::BadRequest("invalid_scope".into()));
    }
    Ok(scopes.join(" "))
}
pub fn validate_redirect(input: &str) -> Result<(), AppError> {
    let u =
        url::Url::parse(input).map_err(|_| AppError::BadRequest("invalid_redirect_uri".into()))?;
    if input.len() > 2048
        || u.fragment().is_some()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.host_str().is_none()
        || !(u.scheme() == "https"
            || (u.scheme() == "http"
                && matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))))
    {
        return Err(AppError::BadRequest("invalid_redirect_uri".into()));
    }
    if let Ok(allowed) = std::env::var("MCP_ALLOWED_REDIRECT_ORIGINS")
        && !allowed
            .split(',')
            .any(|s| s.trim() == u.origin().ascii_serialization())
    {
        return Err(AppError::BadRequest(
            "redirect origin is not registered with this deployment".into(),
        ));
    }
    Ok(())
}
pub fn verify_pkce(verifier: &str, challenge: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-._~".contains(&c))
        && URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) == challenge
}
async fn metadata(State(st): State<AppState>) -> Json<Value> {
    let i = issuer(&st);
    Json(
        json!({"issuer":i,"authorization_endpoint":format!("{i}/authorize"),"token_endpoint":format!("{i}/token"),"registration_endpoint":format!("{i}/register"),"revocation_endpoint":format!("{i}/revoke"),"response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],"token_endpoint_auth_methods_supported":["none"],"code_challenge_methods_supported":["S256"],"scopes_supported":["mcp:full","mcp:read","mcp:write"]}),
    )
}
async fn protected(State(st): State<AppState>) -> Json<Value> {
    Json(
        json!({"resource":resource(&st),"authorization_servers":[issuer(&st)],"scopes_supported":["mcp:full","mcp:read","mcp:write"],"bearer_methods_supported":["header"]}),
    )
}
#[derive(Deserialize)]
struct Registration {
    client_name: String,
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: Option<String>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
}
async fn register(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(v): Json<Registration>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    // A deployment-wide cap cannot be bypassed with a forged forwarded IP.
    rate_limit(&st.pg, "mcp:registration", 20).await?;
    if let Ok(required) = std::env::var("MCP_REGISTRATION_TOKEN") {
        let supplied = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if required.is_empty() || token_hash(supplied) != token_hash(&required) {
            return Err(AppError::Unauthorized);
        }
    }
    if v.client_name.trim().is_empty()
        || v.client_name.len() > 200
        || v.redirect_uris.is_empty()
        || v.redirect_uris.len() > 10
        || v.token_endpoint_auth_method
            .as_deref()
            .is_some_and(|s| s != "none")
        || v.grant_types.as_ref().is_some_and(|x| {
            x.iter()
                .any(|s| s != "authorization_code" && s != "refresh_token")
        })
        || v.response_types.as_ref().is_some_and(|x| x != &["code"])
    {
        return Err(AppError::BadRequest("invalid_client_metadata".into()));
    }
    for uri in &v.redirect_uris {
        validate_redirect(uri)?
    }
    let id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO mcp_clients(name,redirect_uris) VALUES($1,$2) RETURNING id",
    )
    .bind(v.client_name.trim())
    .bind(json!(v.redirect_uris))
    .fetch_one(&st.pg)
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({"client_id":id,"client_name":v.client_name,"redirect_uris":v.redirect_uris,"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"]}),
        ),
    ))
}
#[derive(Clone, Deserialize)]
struct Authorization {
    client_id: Uuid,
    redirect_uri: String,
    code_challenge: String,
    code_challenge_method: String,
    scope: Option<String>,
    state: Option<String>,
    resource: String,
    response_type: Option<String>,
    #[serde(default)]
    project_ids: Vec<Uuid>,
}
async fn validate_authorization(
    st: &AppState,
    v: &Authorization,
) -> Result<(String, String), AppError> {
    if v.response_type.as_deref().unwrap_or("code") != "code"
        || v.code_challenge_method != "S256"
        || v.code_challenge.len() != 43
        || !v
            .code_challenge
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
        || v.state.as_ref().is_some_and(|s| s.len() > 2048)
        || v.resource != resource(st)
    {
        return Err(AppError::BadRequest("invalid_request".into()));
    }
    let row = sqlx::query_as::<_, (String, Value)>(
        "SELECT name,redirect_uris FROM mcp_clients WHERE id=$1",
    )
    .bind(v.client_id)
    .fetch_optional(&st.pg)
    .await?
    .ok_or_else(|| AppError::BadRequest("invalid_client".into()))?;
    if !row
        .1
        .as_array()
        .is_some_and(|a| a.iter().any(|s| s.as_str() == Some(&v.redirect_uri)))
    {
        return Err(AppError::BadRequest("invalid_redirect_uri".into()));
    }
    Ok((row.0, scope(v.scope.as_deref().unwrap_or("mcp:full"))?))
}
async fn authorize(
    State(st): State<AppState>,
    Query(v): Query<Authorization>,
) -> Result<Redirect, AppError> {
    let (name, scopes) = validate_authorization(&st, &v).await?;
    let base = std::env::var("MCP_CONSENT_URL")
        .map_err(|_| AppError::Config("MCP_CONSENT_URL required".into()))?;
    validate_redirect(&base)?;
    let mut u = url::Url::parse(&base).map_err(|_| AppError::Internal)?;
    u.query_pairs_mut()
        .append_pair("client_id", &v.client_id.to_string())
        .append_pair("client_name", &name)
        .append_pair("redirect_uri", &v.redirect_uri)
        .append_pair("code_challenge", &v.code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("scope", &scopes)
        .append_pair("state", v.state.as_deref().unwrap_or(""))
        .append_pair("resource", &v.resource);
    Ok(Redirect::to(u.as_str()))
}
async fn approve(
    State(st): State<AppState>,
    user: AuthUser,
    headers: HeaderMap,
    Json(v): Json<Authorization>,
) -> Api {
    let (_, scopes) = validate_authorization(&st, &v).await?;
    let projects = if v.project_ids.is_empty() {
        sqlx::query_scalar::<_,Uuid>("SELECT p.id FROM projects p JOIN instance_roles r ON r.instance_id=p.instance_id WHERE r.user_id=$1 ORDER BY p.id").bind(user.id).fetch_all(&st.pg).await?
    } else {
        v.project_ids.clone()
    };
    if projects.len() > 1000 {
        return Err(AppError::BadRequest("too many projects".into()));
    }
    for p in &projects {
        authorize_project(&st, &user, *p, false).await?;
    }
    let mut tx = st.pg.begin().await?;
    lock_user(&mut tx, user.id).await?;
    let bearer = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;
    if !sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM access_tokens WHERE user_id=$1 AND token_hash=$2 AND expires_at>now())").bind(user.id).bind(token_hash(bearer)).fetch_one(&mut *tx).await? {return Err(AppError::Unauthorized)}
    let (code, hash) = new_token();
    sqlx::query("INSERT INTO mcp_authorization_codes(code_hash,client_id,user_id,redirect_uri,challenge,scope,issuer,audience,project_ids,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,now()+interval '60 seconds')").bind(hash).bind(v.client_id).bind(user.id).bind(&v.redirect_uri).bind(v.code_challenge).bind(scopes).bind(issuer(&st)).bind(resource(&st)).bind(&projects).execute(&mut *tx).await?;
    sqlx::query("SELECT trisixt_audit(instance_id,$1,'mcp.consent.granted',$2,jsonb_build_object('project_ids',$3::jsonb)) FROM projects WHERE id=ANY($4) GROUP BY instance_id").bind(user.id).bind(v.client_id).bind(json!(projects)).bind(&projects).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"code":code,"redirect_uri":v.redirect_uri,"state":v.state}),
    ))
}
#[derive(sqlx::FromRow)]
struct Grant {
    user_id: Uuid,
    client_id: Uuid,
    scope: String,
    issuer: String,
    audience: String,
    project_ids: Vec<Uuid>,
}
#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    client_id: Uuid,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    resource: String,
}
fn oauth_error(error: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [("cache-control", "no-store"), ("pragma", "no-cache")],
        Json(json!({"error":error})),
    )
        .into_response()
}
async fn lock_user(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user: Uuid,
) -> Result<(), AppError> {
    let allowed = sqlx::query_scalar::<_, bool>(
        "SELECT NOT invitation_pending FROM users WHERE id=$1 FOR UPDATE",
    )
    .bind(user)
    .fetch_optional(&mut **tx)
    .await?
    .unwrap_or(false);
    if !allowed {
        return Err(AppError::Unauthorized);
    }
    let active =
        sqlx::query_scalar::<_, bool>("SELECT active FROM scim_users WHERE user_id=$1 FOR SHARE")
            .bind(user)
            .fetch_optional(&mut **tx)
            .await?;
    if active == Some(false) {
        return Err(AppError::Unauthorized);
    }
    Ok(())
}
async fn mint(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    g: &Grant,
    family: Uuid,
) -> Result<Value, AppError> {
    let (access, ah) = new_token();
    let (refresh, rh) = new_token();
    sqlx::query("INSERT INTO mcp_tokens(family_id,client_id,user_id,access_hash,refresh_hash,scope,issuer,audience,project_ids,expires_at,refresh_expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,now()+interval '1 hour',now()+interval '90 days')").bind(family).bind(g.client_id).bind(g.user_id).bind(ah).bind(rh).bind(&g.scope).bind(&g.issuer).bind(&g.audience).bind(&g.project_ids).execute(&mut **tx).await?;
    Ok(
        json!({"access_token":access,"token_type":"Bearer","expires_in":3600,"refresh_token":refresh,"scope":g.scope}),
    )
}
async fn token(
    State(st): State<AppState>,
    Form(v): Form<TokenRequest>,
) -> Result<Response, AppError> {
    rate_limit(&st.pg, &format!("mcp:token:{}", v.client_id), 60).await?;
    if v.resource != resource(&st) {
        return Ok(oauth_error("invalid_target"));
    }
    let mut tx = st.pg.begin().await?;
    let (g, family) = match v.grant_type.as_str() {
        "authorization_code" => {
            let code = v.code.unwrap_or_default();
            let owner = sqlx::query_scalar::<_, Uuid>(
                "SELECT user_id FROM mcp_authorization_codes WHERE code_hash=$1 AND client_id=$2",
            )
            .bind(token_hash(&code))
            .bind(v.client_id)
            .fetch_optional(&mut *tx)
            .await?;
            let Some(owner) = owner else {
                return Ok(oauth_error("invalid_grant"));
            };
            if lock_user(&mut tx, owner).await.is_err() {
                return Ok(oauth_error("invalid_grant"));
            }
            let row=sqlx::query_as::<_,(String,String,Option<DateTime<Utc>>,DateTime<Utc>)>("SELECT challenge,redirect_uri,used_at,expires_at FROM mcp_authorization_codes WHERE code_hash=$1 AND client_id=$2 FOR UPDATE").bind(token_hash(&code)).bind(v.client_id).fetch_optional(&mut *tx).await?;
            let Some((challenge, redirect, used, expires)) = row else {
                return Ok(oauth_error("invalid_grant"));
            };
            if used.is_some()
                || expires <= Utc::now()
                || v.redirect_uri.as_deref() != Some(&redirect)
                || !verify_pkce(v.code_verifier.as_deref().unwrap_or(""), &challenge)
            {
                return Ok(oauth_error("invalid_grant"));
            }
            let g=sqlx::query_as::<_,Grant>("UPDATE mcp_authorization_codes SET used_at=now() WHERE code_hash=$1 RETURNING user_id,client_id,scope,issuer,audience,project_ids").bind(token_hash(&code)).fetch_one(&mut *tx).await?;
            (g, Uuid::new_v4())
        }
        "refresh_token" => {
            let hash = token_hash(&v.refresh_token.unwrap_or_default());
            let owner = sqlx::query_scalar::<_, Uuid>(
                "SELECT user_id FROM mcp_tokens WHERE refresh_hash=$1 AND client_id=$2",
            )
            .bind(&hash)
            .bind(v.client_id)
            .fetch_optional(&mut *tx)
            .await?;
            let Some(owner) = owner else {
                return Ok(oauth_error("invalid_grant"));
            };
            if lock_user(&mut tx, owner).await.is_err() {
                return Ok(oauth_error("invalid_grant"));
            }
            let row=sqlx::query_as::<_,(Uuid,Option<DateTime<Utc>>,DateTime<Utc>)>("SELECT family_id,revoked_at,refresh_expires_at FROM mcp_tokens WHERE refresh_hash=$1 AND client_id=$2 FOR UPDATE").bind(&hash).bind(v.client_id).fetch_optional(&mut *tx).await?;
            let Some((family, revoked, expires)) = row else {
                return Ok(oauth_error("invalid_grant"));
            };
            if revoked.is_some() {
                sqlx::query("UPDATE mcp_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE family_id=$1").bind(family).execute(&mut *tx).await?;
                tx.commit().await?;
                return Ok(oauth_error("invalid_grant"));
            }
            if expires <= Utc::now() {
                return Ok(oauth_error("invalid_grant"));
            }
            let g=sqlx::query_as::<_,Grant>("UPDATE mcp_tokens SET revoked_at=now() WHERE refresh_hash=$1 RETURNING user_id,client_id,scope,issuer,audience,project_ids").bind(hash).fetch_one(&mut *tx).await?;
            (g, family)
        }
        _ => return Ok(oauth_error("unsupported_grant_type")),
    };
    if g.issuer != issuer(&st) || g.audience != resource(&st) {
        return Ok(oauth_error("invalid_grant"));
    }
    let body = mint(&mut tx, &g, family).await?;
    tx.commit().await?;
    Ok((
        [("cache-control", "no-store"), ("pragma", "no-cache")],
        Json(body),
    )
        .into_response())
}
#[derive(Deserialize)]
struct Revocation {
    token: String,
    client_id: Uuid,
}
async fn revoke_family(st: &AppState, user: Uuid, family: Uuid) -> Result<(), AppError> {
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user)
        .fetch_optional(&mut *tx)
        .await?;
    sqlx::query("UPDATE mcp_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE family_id=$1 AND user_id=$2").bind(family).bind(user).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
async fn revoke(
    State(st): State<AppState>,
    Form(v): Form<Revocation>,
) -> Result<StatusCode, AppError> {
    if let Some((user,family))=sqlx::query_as::<_,(Uuid,Uuid)>("SELECT user_id,family_id FROM mcp_tokens WHERE client_id=$1 AND(access_hash=$2 OR refresh_hash=$2)").bind(v.client_id).bind(token_hash(&v.token)).fetch_optional(&st.pg).await?{revoke_family(&st,user,family).await?;}
    Ok(StatusCode::OK)
}

#[derive(Clone)]
struct McpAuth {
    id: Uuid,
    user: AuthUser,
    scope: String,
    projects: Vec<Uuid>,
}
impl FromRequestParts<AppState> for McpAuth {
    type Rejection = Response;
    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, Response> {
        let supplied = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        let invalid = || {
            let challenge = format!(
                "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\", scope=\"mcp:full\"{}",
                issuer(st),
                if supplied.is_some() {
                    ", error=\"invalid_token\""
                } else {
                    ""
                }
            );
            (
                StatusCode::UNAUTHORIZED,
                [("www-authenticate", challenge)],
                Json(json!({"error":"unauthorized"})),
            )
                .into_response()
        };
        let raw = supplied.filter(|s| s.len() == 64).ok_or_else(invalid)?;
        let row=sqlx::query_as::<_,(Uuid,Uuid,String,String,Vec<Uuid>)>("SELECT t.id,u.id,u.email,t.scope,t.project_ids FROM mcp_tokens t JOIN users u ON u.id=t.user_id WHERE t.access_hash=$1 AND t.revoked_at IS NULL AND t.expires_at>now() AND t.issuer=$2 AND t.audience=$3").bind(token_hash(raw)).bind(issuer(st)).bind(resource(st)).fetch_optional(&st.pg).await.map_err(|e|AppError::Db(e).into_response())?.ok_or_else(invalid)?;
        rate_limit(&st.pg, &format!("mcp:api:{}", row.0), 300)
            .await
            .map_err(IntoResponse::into_response)?;
        sqlx::query("UPDATE mcp_tokens SET last_used_at=now() WHERE id=$1")
            .bind(row.0)
            .execute(&st.pg)
            .await
            .map_err(|e| AppError::Db(e).into_response())?;
        sqlx::query("INSERT INTO mcp_usage(token_id) VALUES($1) ON CONFLICT(token_id,day) DO UPDATE SET requests=mcp_usage.requests+1").bind(row.0).execute(&st.pg).await.map_err(|e|AppError::Db(e).into_response())?;
        Ok(Self {
            id: row.0,
            user: AuthUser {
                id: row.1,
                email: row.2,
            },
            scope: row.3,
            projects: row.4,
        })
    }
}
impl McpAuth {
    async fn project(&self, st: &AppState, p: Uuid, write: bool) -> Result<(), AppError> {
        if !self.projects.contains(&p)
            || !self
                .scope
                .split_whitespace()
                .any(|s| s == "mcp:full" || s == if write { "mcp:write" } else { "mcp:read" })
        {
            return Err(AppError::Forbidden);
        }
        authorize_project(st, &self.user, p, write).await?;
        Ok(())
    }
}
async fn status(State(st): State<AppState>, auth: McpAuth) -> Api {
    let projects=sqlx::query_scalar::<_,Value>("SELECT to_jsonb(p)||jsonb_build_object('instance_name',i.name,'role',r.role) FROM projects p JOIN instances i ON i.id=p.instance_id JOIN instance_roles r ON r.instance_id=p.instance_id WHERE r.user_id=$1 AND p.id=ANY($2) ORDER BY p.id").bind(auth.user.id).bind(auth.projects).fetch_all(&st.pg).await?;
    Ok(Json(
        json!({"valid":true,"user":auth.user,"projects":projects,"scope":auth.scope}),
    ))
}
async fn usage(State(st): State<AppState>, auth: McpAuth) -> Api {
    let rows = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(u) FROM mcp_usage u WHERE token_id=$1 ORDER BY day DESC LIMIT 90",
    )
    .bind(auth.id)
    .fetch_all(&st.pg)
    .await?;
    Ok(Json(json!({"usage":rows})))
}
async fn self_revoke(State(st): State<AppState>, auth: McpAuth) -> Result<StatusCode, AppError> {
    if let Some(family) =
        sqlx::query_scalar::<_, Uuid>("SELECT family_id FROM mcp_tokens WHERE id=$1 AND user_id=$2")
            .bind(auth.id)
            .bind(auth.user.id)
            .fetch_optional(&st.pg)
            .await?
    {
        revoke_family(&st, auth.user.id, family).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn tokens(State(st): State<AppState>, user: AuthUser) -> Api {
    let rows=sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('id',t.id,'name',c.name,'scope',t.scope,'project_ids',t.project_ids,'expires_at',t.expires_at,'last_used_at',t.last_used_at,'created_at',t.created_at) FROM mcp_tokens t JOIN mcp_clients c ON c.id=t.client_id WHERE t.user_id=$1 AND t.revoked_at IS NULL ORDER BY t.created_at DESC").bind(user.id).fetch_all(&st.pg).await?;
    Ok(Json(json!({"tokens":rows})))
}
async fn delete_token(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    if let Some(family) =
        sqlx::query_scalar::<_, Uuid>("SELECT family_id FROM mcp_tokens WHERE id=$1 AND user_id=$2")
            .bind(id)
            .bind(user.id)
            .fetch_optional(&st.pg)
            .await?
    {
        revoke_family(&st, user.id, family).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn delegate(
    st: AppState,
    auth: McpAuth,
    method: Method,
    path: String,
    body: Value,
) -> Result<Response, AppError> {
    let req = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .extension(InternalPrincipal(auth.user))
        .body(Body::from(body.to_string()))
        .map_err(|_| AppError::Internal)?;
    Ok(crate::core_api::router()
        .merge(crate::analytics_api::router())
        .with_state(st)
        .oneshot(req)
        .await
        .unwrap())
}
fn id(v: &Value, key: &str) -> Result<Uuid, AppError> {
    v[key]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| AppError::BadRequest(format!("{key} UUID required")))
}
fn configuration(platform: &str, mut value: Value) -> Result<Value, AppError> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| AppError::BadRequest("configuration object required".into()))?;
    for (old, new) in [
        ("app_prefix", "team_id"),
        ("identifier", "package_name"),
        ("sha256s", "sha256_cert_fingerprints"),
    ] {
        if let Some(v) = object.remove(old) {
            object.insert(new.into(), v);
        }
    }
    let allowed: &[&str] = match platform {
        "ios" => &[
            "bundle_id",
            "team_id",
            "tablet_enabled",
            "enabled",
            "app_store_url",
            "uri_scheme",
        ],
        "android" => &[
            "package_name",
            "sha256_cert_fingerprints",
            "tablet_enabled",
            "enabled",
            "store_url",
            "uri_scheme",
        ],
        "desktop" => &[
            "generated_page",
            "fallback_url",
            "mac_uri",
            "windows_uri",
            "mac_enabled",
            "windows_enabled",
            "enabled",
        ],
        _ => return Err(AppError::BadRequest("invalid platform".into())),
    };
    for (k, v) in object {
        if !allowed.contains(&k.as_str()) {
            return Err(AppError::BadRequest(format!(
                "unsupported {platform} setting {k}"
            )));
        }
        if k.ends_with("enabled") || k == "generated_page" {
            if !v.is_boolean() {
                return Err(AppError::BadRequest("boolean setting required".into()));
            }
        } else if k == "sha256_cert_fingerprints" {
            if !v.as_array().is_some_and(|a| {
                !a.is_empty()
                    && a.len() <= 10
                    && a.iter().all(|v| {
                        v.as_str().is_some_and(|s| {
                            let parts = s.split(':').collect::<Vec<_>>();
                            parts.len() == 32
                                && parts.iter().all(|s| {
                                    s.len() == 2 && s.bytes().all(|b| b.is_ascii_hexdigit())
                                })
                        })
                    })
            }) {
                return Err(AppError::BadRequest("invalid SHA256 fingerprints".into()));
            }
        } else {
            let text = v
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 4096)
                .ok_or_else(|| AppError::BadRequest("text setting required".into()))?;
            if k.ends_with("url") || k.ends_with("uri") {
                let parsed = url::Url::parse(text)
                    .map_err(|_| AppError::BadRequest("absolute URL required".into()))?;
                if !parsed.username().is_empty()
                    || parsed.password().is_some()
                    || ["javascript", "data", "vbscript", "file", "about", "blob"]
                        .contains(&parsed.scheme())
                {
                    return Err(AppError::BadRequest("unsafe URL".into()));
                }
            } else if !text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
            {
                return Err(AppError::BadRequest("invalid identifier".into()));
            }
        }
    }
    Ok(value)
}
async fn configure(
    st: &AppState,
    auth: &McpAuth,
    body: &Value,
    sdk: bool,
) -> Result<Response, AppError> {
    let projects = if sdk {
        let instance = id(body, "instance_id")?;
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM projects WHERE instance_id=$1")
            .bind(instance)
            .fetch_all(&st.pg)
            .await?
    } else {
        vec![id(body, "project_id")?]
    };
    if projects.is_empty() {
        return Err(AppError::NotFound);
    }
    for project in &projects {
        auth.project(st, *project, true).await?;
    }
    let mut updates = Vec::new();
    if sdk {
        let platforms = body["platforms"]
            .as_object()
            .ok_or_else(|| AppError::BadRequest("platforms object required".into()))?;
        for (p, v) in platforms {
            updates.push((p.clone(), configuration(p, v.clone())?));
        }
    } else {
        let mut redirect = json!({});
        for key in [
            "default_fallback",
            "show_preview_ios",
            "show_preview_android",
            "copy_to_clipboard_ios",
            "copy_to_clipboard_android",
        ] {
            if let Some(v) = body.get(key) {
                if key == "default_fallback" {
                    let u = url::Url::parse(v.as_str().unwrap_or(""))
                        .map_err(|_| AppError::BadRequest("fallback URL required".into()))?;
                    if !matches!(u.scheme(), "https" | "http")
                        || !u.username().is_empty()
                        || u.password().is_some()
                    {
                        return Err(AppError::BadRequest("HTTP(S) fallback required".into()));
                    }
                } else if !v.is_boolean() {
                    return Err(AppError::BadRequest(
                        "preview and clipboard settings require booleans".into(),
                    ));
                }
                redirect[key] = v.clone();
            }
        }
        if let Some(platforms) = body["platforms"].as_object() {
            for (p, v) in platforms {
                if !["ios", "android", "desktop"].contains(&p.as_str()) {
                    return Err(AppError::BadRequest("invalid platform".into()));
                }
                let variant =
                    v["variation"]
                        .as_str()
                        .unwrap_or(if p == "desktop" { "all" } else { "phone" });
                if !["phone", "tablet", "all", "mac", "windows", "linux"].contains(&variant) {
                    return Err(AppError::BadRequest("invalid variation".into()));
                }
                if !v.is_object() {
                    return Err(AppError::BadRequest(
                        "platform redirect must be an object".into(),
                    ));
                }
                if let Some(enabled) = v.get("enabled")
                    && !enabled.is_boolean()
                {
                    return Err(AppError::BadRequest("enabled must be boolean".into()));
                }
                redirect[format!("{p}_{variant}")] = json!({"fallback":v["fallback_url"],"appstore":v["appstore"],"enabled":v["enabled"].as_bool().unwrap_or(true)});
            }
        }
        crate::core_api::validate_configuration("redirect", &redirect)?;
        updates.push(("redirect".into(), redirect));
    }
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT set_config('trisixt.actor_id',$1,true)")
        .bind(auth.user.id.to_string())
        .execute(&mut *tx)
        .await?;
    for project in &projects {
        for (platform, value) in &updates {
            let sql = format!(
                "INSERT INTO project_configurations(project_id,{platform})VALUES($1,$2)ON CONFLICT(project_id)DO UPDATE SET {platform}=project_configurations.{platform}||excluded.{platform},updated_at=now()"
            );
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(project)
                .bind(value)
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await?;
    Ok(Json(json!({"project_ids":projects,"configurations":updates.into_iter().collect::<HashMap<_,_>>()})).into_response())
}
async fn gateway(
    State(st): State<AppState>,
    auth: McpAuth,
    request: Request,
) -> Result<Response, AppError> {
    let method = request.method().clone();
    let suffix = request
        .uri()
        .path()
        .trim_start_matches("/api/v1/mcp/")
        .to_owned();
    let query: HashMap<String, String> =
        url::form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes())
            .into_owned()
            .collect();
    let bytes = axum::body::to_bytes(request.into_body(), 131072)
        .await
        .map_err(|_| AppError::BadRequest("body too large".into()))?;
    let mut body: Value = if bytes.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&bytes).map_err(|_| AppError::BadRequest("invalid JSON".into()))?
    };
    for (k, v) in query {
        if body.get(&k).is_none() {
            body[&k] = json!(v)
        }
    }
    if suffix == "projects" && method == Method::POST {
        if !auth
            .scope
            .split_whitespace()
            .any(|s| s == "mcp:full" || s == "mcp:write")
        {
            return Err(AppError::Forbidden);
        }
        let name = body["name"]
            .as_str()
            .ok_or_else(|| AppError::BadRequest("name required".into()))?;
        return Ok((
            StatusCode::CREATED,
            Json(crate::provisioning::provision(&st, &auth.user, name).await?),
        )
            .into_response());
    }
    let expected = match suffix.as_str() {
        "links"
        | "campaigns"
        | "links/search"
        | "campaigns/search"
        | "analytics/link"
        | "analytics/overview"
        | "analytics/top_links" => method == Method::POST,
        "redirects" | "sdk" => method == Method::PUT,
        x if x.starts_with("links/by-path/") => method == Method::GET,
        x if x.starts_with("links/") => method == Method::PATCH || method == Method::DELETE,
        x if x.starts_with("campaigns/") => method == Method::DELETE,
        _ => false,
    };
    if !expected {
        return Err(AppError::NotFound);
    }
    if suffix == "redirects" || suffix == "sdk" {
        return configure(&st, &auth, &body, suffix == "sdk").await;
    }
    let p = id(&body, "project_id")?;
    let write = !matches!(
        suffix.as_str(),
        "links/search"
            | "campaigns/search"
            | "analytics/link"
            | "analytics/overview"
            | "analytics/top_links"
    ) && method != Method::GET;
    auth.project(&st, p, write).await?;
    let (verb, target) = match suffix.as_str() {
        "links" => (Method::POST, format!("/api/v1/projects/{p}/links")),
        "links/search" => (Method::GET, format!("/api/v1/projects/{p}/links")),
        "campaigns" => (Method::POST, format!("/api/v1/projects/{p}/campaigns")),
        "campaigns/search" => (Method::GET, format!("/api/v1/projects/{p}/campaigns")),
        "analytics/overview" => (
            Method::GET,
            format!("/api/v1/projects/{p}/analytics/overview/key-metrics"),
        ),
        "analytics/link" | "analytics/top_links" => {
            (Method::GET, format!("/api/v1/projects/{p}/analytics/links"))
        }
        "redirects" | "sdk" => {
            let platform = body["platform"].as_str().unwrap_or("desktop");
            if !matches!(platform, "desktop" | "ios" | "android") {
                return Err(AppError::BadRequest("invalid platform".into()));
            }
            (
                Method::PUT,
                format!("/api/v1/projects/{p}/configurations/{platform}"),
            )
        }
        x if x.starts_with("links/by-path/") => {
            let path = x.trim_start_matches("links/by-path/");
            let link = sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM links WHERE project_id=$1 AND path=$2 AND archived_at IS NULL",
            )
            .bind(p)
            .bind(path)
            .fetch_optional(&st.pg)
            .await?
            .ok_or(AppError::NotFound)?;
            (Method::GET, format!("/api/v1/projects/{p}/links/{link}"))
        }
        x if x.starts_with("links/") => {
            let link: Uuid = x[6..].parse().map_err(|_| AppError::NotFound)?;
            (method, format!("/api/v1/projects/{p}/links/{link}"))
        }
        x if x.starts_with("campaigns/") => {
            let campaign: Uuid = x[10..].parse().map_err(|_| AppError::NotFound)?;
            (method, format!("/api/v1/projects/{p}/campaigns/{campaign}"))
        }
        _ => return Err(AppError::NotFound),
    };
    if suffix == "links" && !body["name"].as_str().is_some_and(|s| !s.trim().is_empty()) {
        return Err(AppError::BadRequest("name required".into()));
    }
    if let Some(hidden) = body.get("hidden").cloned() {
        let hidden = hidden
            .as_bool()
            .ok_or_else(|| AppError::BadRequest("hidden must be boolean".into()))?;
        if body["metadata"].is_null() {
            body["metadata"] = json!({});
        }
        if !body["metadata"].is_object() {
            return Err(AppError::BadRequest("metadata object required".into()));
        }
        body["metadata"]["sdk_generated"] = json!(hidden);
        body.as_object_mut().unwrap().remove("hidden");
    }
    if let Some(obj) = body.as_object_mut() {
        obj.remove("project_id");
        obj.remove("instance_id");
    }
    for (legacy, canonical) in [("date_from", "start_date"), ("date_to", "end_date")] {
        if let Some(v) = body.as_object_mut().and_then(|o| o.remove(legacy)) {
            body[canonical] = v;
        }
    }
    let target = if verb == Method::GET {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        if let Some(obj) = body.as_object() {
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    serializer.append_pair(k, s);
                } else if !v.is_null() {
                    serializer.append_pair(k, &v.to_string());
                }
            }
        }
        format!("{target}?{}", serializer.finish())
    } else {
        target
    };
    delegate(st, auth, verb, target, body).await
}
pub async fn revoke_user_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user: Uuid,
) -> Result<(), AppError> {
    sqlx::query("UPDATE mcp_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE user_id=$1")
        .bind(user)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM mcp_authorization_codes WHERE user_id=$1")
        .bind(user)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
const TOOLS: &[(&str, &str, &str)] = &[
    ("create_project", "POST", "projects"),
    ("create_link", "POST", "links"),
    ("search_links", "POST", "links/search"),
    ("get_link", "GET", "links/by-path/{path}"),
    ("update_link", "PATCH", "links/{id}"),
    ("archive_link", "DELETE", "links/{id}"),
    ("create_campaign", "POST", "campaigns"),
    ("search_campaigns", "POST", "campaigns/search"),
    ("archive_campaign", "DELETE", "campaigns/{id}"),
    ("setup_redirects", "PUT", "redirects"),
    ("setup_sdk", "PUT", "sdk"),
    ("link_analytics", "POST", "analytics/link"),
    ("overview_analytics", "POST", "analytics/overview"),
    ("top_links", "POST", "analytics/top_links"),
];
async fn rpc(
    State(st): State<AppState>,
    auth: McpAuth,
    headers: HeaderMap,
    Json(v): Json<Value>,
) -> Result<Response, AppError> {
    if headers
        .get("mcp-protocol-version")
        .is_some_and(|v| v != "2025-06-18")
    {
        return Err(AppError::BadRequest(
            "unsupported MCP protocol version".into(),
        ));
    }
    let id = v.get("id").cloned().unwrap_or(Value::Null);
    let reply =
        |result: Value| Json(json!({"jsonrpc":"2.0","id":id,"result":result})).into_response();
    let error = |code: i32, message: &str| {
        Json(json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}}))
            .into_response()
    };
    if v["jsonrpc"] != "2.0" || !v.is_object() {
        return Ok(error(-32600, "Invalid Request"));
    }
    match v["method"].as_str().unwrap_or("") {
        "initialize" => Ok(reply(
            json!({"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"trisixt","version":env!("CARGO_PKG_VERSION")}}),
        )),
        "notifications/initialized" => Ok(StatusCode::ACCEPTED.into_response()),
        "ping" => Ok(reply(json!({}))),
        "tools/list" => Ok(reply(
            json!({"tools":TOOLS.iter().map(|(name,method,path)|json!({"name":name,"description":format!("Trisixt {name}. Uses the authenticated projects and current tenant permissions."),"inputSchema":{"type":"object","properties":{"project_id":{"type":"string","format":"uuid"},"instance_id":{"type":"string","format":"uuid"},"id":{"type":"string","format":"uuid"},"path":{"type":"string"},"name":{"type":"string"},"target_url":{"type":"string"},"metadata":{"type":"object"},"platforms":{"type":"object"}},"additionalProperties":true},"annotations":{"readOnlyHint":*method=="GET"||path.ends_with("search")||path.starts_with("analytics/"),"destructiveHint":*method=="DELETE"}})).collect::<Vec<_>>()}),
        )),
        "tools/call" => {
            let Some((_, method, template)) = TOOLS
                .iter()
                .find(|(name, _, _)| Some(*name) == v["params"]["name"].as_str())
            else {
                return Ok(error(-32602, "Unknown tool"));
            };
            let mut args = v["params"].get("arguments").cloned().unwrap_or(json!({}));
            if !args.is_object() {
                return Ok(error(-32602, "Arguments must be an object"));
            }
            let path = if template.contains("{id}") {
                let entity = id_fn(&args, "id")?;
                args.as_object_mut().unwrap().remove("id");
                template.replace("{id}", &entity.to_string())
            } else if template.contains("{path}") {
                let path = args["path"]
                    .as_str()
                    .filter(|s| {
                        !s.is_empty()
                            && s.len() <= 100
                            && s.bytes()
                                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
                    })
                    .ok_or_else(|| AppError::BadRequest("valid link path required".into()))?;
                template.replace("{path}", path)
            } else {
                template.to_string()
            };
            let mut target = format!("/api/v1/mcp/{path}");
            if *method == "GET" || *method == "DELETE" {
                let mut serializer = url::form_urlencoded::Serializer::new(String::new());
                if let Some(project) = args["project_id"].as_str() {
                    serializer.append_pair("project_id", project);
                }
                target.push('?');
                target.push_str(&serializer.finish());
            }
            let request = axum::http::Request::builder()
                .method(*method)
                .uri(target)
                .header("content-type", "application/json")
                .body(Body::from(args.to_string()))
                .map_err(|_| AppError::Internal)?;
            let response = match gateway(State(st), auth, request).await {
                Ok(r) => r,
                Err(e) => e.into_response(),
            };
            let failed = !response.status().is_success();
            let bytes = axum::body::to_bytes(response.into_body(), 1_048_576)
                .await
                .map_err(|_| AppError::Internal)?;
            let text = String::from_utf8(bytes.to_vec()).map_err(|_| AppError::Internal)?;
            Ok(reply(
                json!({"content":[{"type":"text","text":text}],"isError":failed}),
            ))
        }
        _ => Ok(error(-32601, "Method not found")),
    }
}
fn id_fn(v: &Value, key: &str) -> Result<Uuid, AppError> {
    id(v, key)
}
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/mcp", post(rpc))
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route("/.well-known/oauth-protected-resource", get(protected))
        .route("/register", post(register))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/revoke", post(revoke))
        .route("/api/v1/mcp/approve_consent", post(approve))
        .route("/api/v1/mcp/tokens", get(tokens))
        .route(
            "/api/v1/mcp/tokens/{id}",
            axum::routing::delete(delete_token),
        )
        .route("/api/v1/mcp/status", get(status))
        .route("/api/v1/mcp/validate", get(status))
        .route("/api/v1/mcp/usage", get(usage))
        .route("/api/v1/mcp/token", axum::routing::delete(self_revoke))
        .route("/api/v1/mcp/{*action}", axum::routing::any(gateway))
}
