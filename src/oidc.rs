//! Enterprise OIDC authorization code flow with PKCE and explicit identity linking.
//! Password-authenticated users link their own IdP identity; emails never auto-link accounts.
use crate::{
    auth::{AuthUser, authorize_instance, new_token, token_hash},
    enterprise::require_enterprise,
    error::AppError,
    state::AppState,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use oauth2::{
    AsyncHttpClient, AuthUrl, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken,
    EndpointNotSet, EndpointSet, ExtraTokenFields, HttpRequest, HttpResponse, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, StandardRevocableToken, StandardTokenResponse,
    TokenResponse, TokenUrl,
    basic::{
        BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
        BasicTokenType,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    pin::Pin,
    time::Duration,
};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IdTokenFields {
    pub id_token: String,
}
impl ExtraTokenFields for IdTokenFields {}
pub type OidcTokenResponse = StandardTokenResponse<IdTokenFields, BasicTokenType>;
type DiscoveredClient = Client<
    BasicErrorResponse,
    OidcTokenResponse,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    id_token_signing_alg_values_supported: Vec<String>,
    response_types_supported: Vec<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderProfile {
    pub issuer: String,
    pub client_id: String,
    pub client_secret_env: Option<String>,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

impl ProviderProfile {
    pub fn validate(&self) -> Result<HashSet<String>, AppError> {
        let issuer = secure_url(&self.issuer)?;
        if self.client_id.is_empty() || self.client_id.len() > 512 {
            return Err(AppError::Config("invalid OIDC client id".into()));
        }
        if let Some(name) = &self.client_secret_env
            && (!name.starts_with("OIDC_CLIENT_SECRET_")
                || !name
                    .bytes()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_'))
        {
            return Err(AppError::Config(
                "invalid OIDC secret environment reference".into(),
            ));
        }
        let mut origins = HashSet::from([issuer.origin().ascii_serialization()]);
        for value in &self.allowed_origins {
            let url = secure_url(value)?;
            if url.path() != "/" {
                return Err(AppError::Config(
                    "OIDC allowed origins cannot contain paths".into(),
                ));
            }
            origins.insert(url.origin().ascii_serialization());
        }
        Ok(origins)
    }
}

fn profile(key: &str) -> Result<ProviderProfile, AppError> {
    let value = std::env::var("OIDC_PROVIDERS_JSON")
        .map_err(|_| AppError::Config("OIDC_PROVIDERS_JSON is required".into()))?;
    let profiles: HashMap<String, ProviderProfile> = serde_json::from_str(&value)
        .map_err(|_| AppError::Config("invalid OIDC_PROVIDERS_JSON".into()))?;
    let profile = profiles
        .get(key)
        .ok_or_else(|| AppError::BadRequest("provider is not operator-approved".into()))?
        .clone();
    profile.validate()?;
    Ok(profile)
}

fn secure_url(value: &str) -> Result<url::Url, AppError> {
    let url = url::Url::parse(value).map_err(|_| AppError::Config("invalid OIDC URL".into()))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err(AppError::Config(
            "OIDC URLs must use HTTPS without credentials or query parameters".into(),
        ));
    }
    Ok(url)
}

struct RestrictedClient {
    client: reqwest::Client,
    origins: HashSet<String>,
}
impl<'a> AsyncHttpClient<'a> for RestrictedClient {
    type Error = AppError;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + 'a>>;
    fn call(&'a self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let url =
                url::Url::parse(&request.uri().to_string()).map_err(|_| AppError::Upstream)?;
            if url.scheme() != "https"
                || !self.origins.contains(&url.origin().ascii_serialization())
            {
                return Err(AppError::Upstream);
            }
            let request = reqwest::Request::try_from(request).map_err(|_| AppError::Upstream)?;
            let mut response = self
                .client
                .execute(request)
                .await
                .map_err(|_| AppError::Upstream)?;
            if response.content_length().is_some_and(|n| n > 1048576) {
                return Err(AppError::Upstream);
            }
            let mut result = axum::http::Response::builder().status(response.status());
            for (key, value) in response.headers() {
                result = result.header(key, value);
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| AppError::Upstream)? {
                if body.len() + chunk.len() > 1048576 {
                    return Err(AppError::Upstream);
                }
                body.extend_from_slice(&chunk);
            }
            result.body(body).map_err(|_| AppError::Upstream)
        })
    }
}

async fn discover(
    profile: &ProviderProfile,
) -> Result<(DiscoveredClient, RestrictedClient, JwkSet), AppError> {
    let http = RestrictedClient {
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| AppError::Internal)?,
        origins: profile.validate()?,
    };
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        profile.issuer.trim_end_matches('/')
    );
    let metadata: Discovery = fetch_json(&http, &discovery_url).await?;
    if metadata.issuer != profile.issuer
        || !metadata
            .response_types_supported
            .iter()
            .any(|s| s == "code")
        || !metadata
            .id_token_signing_alg_values_supported
            .iter()
            .any(|s| s == "RS256" || s == "ES256")
    {
        return Err(AppError::Upstream);
    }
    for value in [
        &metadata.authorization_endpoint,
        &metadata.token_endpoint,
        &metadata.jwks_uri,
    ] {
        let url = secure_url(value)?;
        if !http.origins.contains(&url.origin().ascii_serialization()) {
            return Err(AppError::Upstream);
        }
    }
    let jwks: JwkSet = fetch_json(&http, &metadata.jwks_uri).await?;
    if jwks.keys.is_empty() || jwks.keys.len() > 100 {
        return Err(AppError::Upstream);
    }
    let redirect = std::env::var("OIDC_REDIRECT_URL")
        .map_err(|_| AppError::Config("OIDC_REDIRECT_URL required".into()))?;
    secure_url(&redirect)?;
    let mut client = Client::new(ClientId::new(profile.client_id.clone()))
        .set_auth_uri(
            AuthUrl::new(metadata.authorization_endpoint).map_err(|_| AppError::Upstream)?,
        )
        .set_token_uri(TokenUrl::new(metadata.token_endpoint).map_err(|_| AppError::Upstream)?)
        .set_redirect_uri(RedirectUrl::new(redirect).map_err(|_| AppError::Internal)?);
    if let Some(name) = &profile.client_secret_env {
        let secret = std::env::var(name)
            .map_err(|_| AppError::Config("OIDC client secret missing".into()))?;
        if secret.is_empty() {
            return Err(AppError::Config("OIDC client secret empty".into()));
        }
        client = client.set_client_secret(ClientSecret::new(secret));
    }
    Ok((client, http, jwks))
}
async fn fetch_json<T: serde::de::DeserializeOwned>(
    http: &RestrictedClient,
    url: &str,
) -> Result<T, AppError> {
    let response = http
        .call(
            axum::http::Request::builder()
                .uri(url)
                .body(Vec::new())
                .map_err(|_| AppError::Upstream)?,
        )
        .await?;
    if !response.status().is_success() {
        return Err(AppError::Upstream);
    }
    serde_json::from_slice(response.body()).map_err(|_| AppError::Upstream)
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/instances/{id}/sso",
            get(settings).put(configure).delete(disable),
        )
        .route(
            "/api/v1/instances/{id}/sso/link",
            post(link_start).delete(unlink),
        )
        .route("/auth/oidc/{id}/start", get(login_start))
        .route("/auth/oidc/callback", get(callback))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsInput {
    provider_key: String,
    enabled: bool,
}

async fn settings(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, AppError> {
    require_enterprise(&st)?;
    authorize_instance(&st, &user, id, true).await?;
    let row = sqlx::query_as::<_, (String, bool)>(
        "SELECT provider_key,enabled FROM instance_sso WHERE instance_id=$1",
    )
    .bind(id)
    .fetch_optional(&st.pg)
    .await?;
    Ok(Json(match row {
        Some((key, enabled)) => json!({"provider_key":key,"enabled":enabled}),
        None => json!({"enabled":false}),
    }))
}

async fn configure(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(input): Json<SettingsInput>,
) -> Result<Json<Value>, AppError> {
    require_enterprise(&st)?;
    authorize_instance(&st, &user, id, true).await?;
    if input.provider_key.is_empty() || input.provider_key.len() > 128 {
        return Err(AppError::BadRequest("invalid provider key".into()));
    }
    profile(&input.provider_key)?;
    let mut tx = st.pg.begin().await?;
    let enforced = sqlx::query_scalar::<_, bool>(
        "SELECT enforced FROM instance_sso WHERE instance_id=$1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .unwrap_or(false);
    if enforced && !input.enabled {
        return Err(AppError::Conflict(
            "disable enforcement before disabling SSO".into(),
        ));
    }
    sqlx::query("INSERT INTO instance_sso(instance_id,provider_key,enabled) VALUES($1,$2,$3) ON CONFLICT(instance_id) DO UPDATE SET provider_key=excluded.provider_key,enabled=excluded.enabled,version=gen_random_uuid(),updated_at=now()")
        .bind(id).bind(&input.provider_key).bind(input.enabled).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM oidc_transactions WHERE instance_id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT trisixt_audit($1,$2,'sso.configured',NULL,$3)")
        .bind(id)
        .bind(user.id)
        .bind(json!({"provider_key":input.provider_key,"enabled":input.enabled}))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"provider_key":input.provider_key,"enabled":input.enabled}),
    ))
}

async fn disable(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    require_enterprise(&st)?;
    authorize_instance(&st, &user, id, true).await?;
    let mut tx = st.pg.begin().await?;
    let enforced = sqlx::query_scalar::<_, bool>(
        "SELECT enforced FROM instance_sso WHERE instance_id=$1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .unwrap_or(false);
    if enforced {
        return Err(AppError::Conflict(
            "disable enforcement before deleting SSO".into(),
        ));
    }
    sqlx::query("DELETE FROM instance_sso WHERE instance_id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT trisixt_audit($1,$2,'sso.disabled',NULL,'{}')")
        .bind(id)
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn unlink(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    require_enterprise(&st)?;
    authorize_instance(&st, &user, id, false).await?;
    let mut tx = st.pg.begin().await?;
    let key = sqlx::query_scalar::<_, String>(
        "SELECT provider_key FROM instance_sso WHERE instance_id=$1 FOR SHARE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::NotFound)?;
    let profile = profile(&key)?;
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user.id)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM oidc_identities WHERE issuer=$1 AND user_id=$2")
        .bind(profile.issuer)
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    crate::accounts::revoke_all(&mut tx, user.id).await?;
    sqlx::query("SELECT trisixt_audit($1,$2,'sso.identity.unlinked',$2,'{}')")
        .bind(id)
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn login_start(
    State(st): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Response, AppError> {
    start(&st, id, None).await
}
async fn link_start(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    authorize_instance(&st, &user, id, false).await?;
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|s| s.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;
    start(&st, id, Some((user.id, token_hash(token)))).await
}

async fn start(
    st: &AppState,
    id: Uuid,
    binding: Option<(Uuid, String)>,
) -> Result<Response, AppError> {
    require_enterprise(st)?;
    let linking = binding.is_some();
    let (key, version) = sqlx::query_as::<_, (String, Uuid)>(
        "SELECT provider_key,version FROM instance_sso WHERE instance_id=$1 AND enabled",
    )
    .bind(id)
    .fetch_optional(&st.pg)
    .await?
    .ok_or(AppError::NotFound)?;
    // Bound transaction growth even if an anonymous caller repeatedly starts login.
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,11))")
        .bind(id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM oidc_transactions WHERE expires_at<now()")
        .execute(&mut *tx)
        .await?;
    let pending =
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM oidc_transactions WHERE instance_id=$1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    if pending >= 100 {
        return Err(AppError::TooManyRequests);
    }
    let (client, _, _) = discover(&profile(&key)?).await?;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (nonce, _) = new_token();
    let (url, state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".into()))
        .add_scope(Scope::new("email".into()))
        .add_extra_param("nonce", nonce.clone())
        .set_pkce_challenge(challenge)
        .url();
    let (browser, browser_hash) = new_token();
    sqlx::query("INSERT INTO oidc_transactions(state_hash,browser_hash,instance_id,config_version,nonce,pkce_verifier,binding_user_id,binding_token_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(token_hash(state.secret())).bind(browser_hash).bind(id).bind(version).bind(&nonce).bind(verifier.secret()).bind(binding.as_ref().map(|b|b.0)).bind(binding.map(|b|b.1)).execute(&mut *tx).await?;
    tx.commit().await?;
    // An authenticated SPA calls the linking endpoint with its bearer header,
    // then navigates to this URL. Returning JSON avoids fetch following the
    // cross-origin IdP redirect before the browser can start interactive login.
    let mut response = if linking {
        Json(json!({"authorization_url":url.as_str()})).into_response()
    } else {
        Redirect::to(url.as_str()).into_response()
    };
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!(
            "__Host-trisixt_oidc={browser}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600"
        )
        .parse()
        .map_err(|_| AppError::Internal)?,
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    Ok(response)
}

#[derive(Deserialize)]
struct Callback {
    state: String,
    code: Option<String>,
    error: Option<String>,
}
#[derive(sqlx::FromRow)]
struct LoginTransaction {
    instance_id: Uuid,
    config_version: Uuid,
    nonce: String,
    pkce_verifier: String,
    binding_user_id: Option<Uuid>,
    binding_token_hash: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub issuer: String,
    pub subject: String,
    pub email: String,
    pub name: Option<String>,
    pub groups: Vec<String>,
}

#[derive(Clone, Deserialize)]
struct IdClaims {
    iss: String,
    sub: String,
    aud: Value,
    exp: u64,
    iat: i64,
    nonce: String,
    email: String,
    email_verified: bool,
    azp: Option<String>,
    at_hash: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    roles: Vec<String>,
}

/// Only asymmetric RS256/ES256 ID tokens are accepted. The JOSE library performs
/// signature/issuer/audience/expiry checks; OIDC-specific binding checks follow.
pub fn verify_identity(
    response: &OidcTokenResponse,
    jwks: &JwkSet,
    profile: &ProviderProfile,
    nonce: &str,
) -> Result<VerifiedIdentity, AppError> {
    let token = &response.extra_fields().id_token;
    if token.len() > 16384 {
        return Err(AppError::Unauthorized);
    }
    let header = decode_header(token).map_err(|_| AppError::Unauthorized)?;
    if !matches!(header.alg, Algorithm::RS256 | Algorithm::ES256) {
        return Err(AppError::Unauthorized);
    }
    let keys: Vec<_> = jwks
        .keys
        .iter()
        .filter(|key| {
            header
                .kid
                .as_ref()
                .is_none_or(|id| key.common.key_id.as_ref() == Some(id))
        })
        .collect();
    if keys.len() != 1 {
        return Err(AppError::Unauthorized);
    }
    let key = keys[0];
    let key_json = serde_json::to_value(key).map_err(|_| AppError::Unauthorized)?;
    if key_json.get("use").is_some_and(|v| v != "sig")
        || key_json
            .get("alg")
            .is_some_and(|v| v.as_str() != Some(format!("{:?}", header.alg).as_str()))
        || key_json.get("key_ops").is_some_and(|ops| {
            !ops.as_array()
                .is_some_and(|a| a.iter().any(|s| s == "verify"))
        })
    {
        return Err(AppError::Unauthorized);
    }
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[&profile.issuer]);
    validation.set_audience(&[&profile.client_id]);
    validation.set_required_spec_claims(&["iss", "sub", "aud", "exp", "iat"]);
    validation.validate_nbf = true;
    validation.leeway = 60;
    let claims = decode::<IdClaims>(
        token,
        &DecodingKey::from_jwk(key).map_err(|_| AppError::Unauthorized)?,
        &validation,
    )
    .map_err(|_| AppError::Unauthorized)?
    .claims;
    let audiences = match &claims.aud {
        Value::String(s) => vec![s.as_str()],
        Value::Array(a) => a
            .iter()
            .map(|s| s.as_str().ok_or(AppError::Unauthorized))
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(AppError::Unauthorized),
    };
    let now = chrono::Utc::now().timestamp();
    if !claims.email_verified
        || claims.email.trim().len() > 254
        || claims.email.trim().parse::<lettre::Address>().is_err()
        || claims.sub.is_empty()
        || claims.sub.len() > 255
        || claims.exp == 0
        || claims.iat > now + 60
        || claims.iat < now - 600
        || token_hash(&claims.nonce) != token_hash(nonce)
        || (audiences.len() > 1 && claims.azp.is_none())
        || claims.azp.as_ref().is_some_and(|s| s != &profile.client_id)
    {
        return Err(AppError::Unauthorized);
    }
    if let Some(expected) = claims.at_hash {
        let hash = Sha256::digest(response.access_token().secret().as_bytes());
        if expected != URL_SAFE_NO_PAD.encode(&hash[..16]) {
            return Err(AppError::Unauthorized);
        }
    }
    Ok(VerifiedIdentity {
        issuer: claims.iss,
        subject: claims.sub,
        email: claims.email.trim().to_ascii_lowercase(),
        name: claims.name,
        groups: claims.groups.into_iter().chain(claims.roles).collect(),
    })
}

async fn callback(
    State(st): State<AppState>,
    Query(query): Query<Callback>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    require_enterprise(&st)?;
    if query.state.len() > 512 || query.code.as_ref().is_some_and(|s| s.len() > 8192) {
        return Err(AppError::Unauthorized);
    }
    let browser = headers
        .get(header::COOKIE)
        .and_then(|s| s.to_str().ok())
        .and_then(|s| {
            s.split(';')
                .find_map(|part| part.trim().strip_prefix("__Host-trisixt_oidc="))
        })
        .filter(|s| s.len() == 64)
        .ok_or(AppError::Unauthorized)?;
    // DELETE is its own committed statement: replay cannot reuse a state after any
    // token exchange failure, and concurrent callbacks cannot both consume it.
    let txn=sqlx::query_as::<_,LoginTransaction>("DELETE FROM oidc_transactions WHERE state_hash=$1 AND browser_hash=$2 AND expires_at>now() RETURNING instance_id,config_version,nonce,pkce_verifier,binding_user_id,binding_token_hash")
        .bind(token_hash(&query.state)).bind(token_hash(browser)).fetch_optional(&st.pg).await?.ok_or(AppError::Unauthorized)?;
    if query.error.is_some() {
        return Err(AppError::Unauthorized);
    }
    let code = query
        .code
        .filter(|s| !s.is_empty())
        .ok_or(AppError::Unauthorized)?;
    let key = sqlx::query_scalar::<_, String>(
        "SELECT provider_key FROM instance_sso WHERE instance_id=$1 AND version=$2 AND enabled",
    )
    .bind(txn.instance_id)
    .bind(txn.config_version)
    .fetch_optional(&st.pg)
    .await?
    .ok_or(AppError::Unauthorized)?;
    let provider = profile(&key)?;
    let (client, http, jwks) = discover(&provider).await?;
    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(PkceCodeVerifier::new(txn.pkce_verifier))
        .request_async(&http)
        .await
        .map_err(|_| AppError::Unauthorized)?;
    let identity = verify_identity(&token, &jwks, &provider, &txn.nonce)?;
    let mut tx = st.pg.begin().await?;
    // Recheck after network work and keep configuration stable through token issuance.
    let current = sqlx::query_scalar::<_, Uuid>(
        "SELECT version FROM instance_sso WHERE instance_id=$1 AND version=$2 AND enabled FOR SHARE",
    )
    .bind(txn.instance_id)
    .bind(txn.config_version)
    .fetch_optional(&mut *tx)
    .await?;
    if current.is_none() {
        return Err(AppError::Unauthorized);
    }
    // Serialize identity linking and reject reassignment to a different user.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,12))")
        .bind(format!("{}:{}", identity.issuer, identity.subject))
        .execute(&mut *tx)
        .await?;
    let linked = sqlx::query_scalar::<_, Uuid>(
        "SELECT user_id FROM oidc_identities WHERE issuer=$1 AND subject=$2",
    )
    .bind(&identity.issuer)
    .bind(&identity.subject)
    .fetch_optional(&mut *tx)
    .await?;
    let user = match txn.binding_user_id {
        Some(user) => {
            sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
                .bind(user)
                .fetch_one(&mut *tx)
                .await?;
            let valid=sqlx::query_scalar::<_,Uuid>("SELECT id FROM access_tokens WHERE user_id=$1 AND token_hash=$2 AND expires_at>now() FOR SHARE").bind(user).bind(&txn.binding_token_hash).fetch_optional(&mut *tx).await?;
            if valid.is_none() || linked.is_some_and(|existing| existing != user) {
                return Err(AppError::Unauthorized);
            }
            user
        }
        None => match linked {
            Some(user) => user,
            None => {
                crate::enterprise_admin::provision_identity(&mut tx, txn.instance_id, &identity)
                    .await?
            }
        },
    };
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user)
        .fetch_one(&mut *tx)
        .await?;
    // Identity may have been unlinked while this callback waited for the user.
    if txn.binding_user_id.is_none() {
        let bound = sqlx::query_scalar::<_, Uuid>(
            "SELECT user_id FROM oidc_identities WHERE issuer=$1 AND subject=$2",
        )
        .bind(&identity.issuer)
        .bind(&identity.subject)
        .fetch_optional(&mut *tx)
        .await?;
        if bound != Some(user) {
            return Err(AppError::Unauthorized);
        }
    }
    crate::enterprise_admin::apply_identity_policy(&mut tx, txn.instance_id, user, &identity)
        .await?;
    let scim_active = sqlx::query_scalar::<_, bool>(
        "SELECT active FROM scim_users WHERE user_id=$1 AND instance_id=$2 FOR SHARE",
    )
    .bind(user)
    .bind(txn.instance_id)
    .fetch_optional(&mut *tx)
    .await?;
    let member = sqlx::query_scalar::<_, Uuid>(
        "SELECT user_id FROM instance_roles WHERE user_id=$1 AND instance_id=$2 FOR SHARE",
    )
    .bind(user)
    .bind(txn.instance_id)
    .fetch_optional(&mut *tx)
    .await?;
    if scim_active == Some(false) || member.is_none() {
        return Err(AppError::Forbidden);
    }
    if txn.binding_user_id.is_some() {
        sqlx::query("INSERT INTO oidc_identities(issuer,subject,user_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING").bind(identity.issuer).bind(identity.subject).bind(user).execute(&mut *tx).await?;
    }
    let session = crate::accounts::session_tx_oidc(&mut tx, user, Uuid::new_v4()).await?;
    sqlx::query("SELECT trisixt_audit($1,$2,$3,$2,'{}')")
        .bind(txn.instance_id)
        .bind(user)
        .bind(if txn.binding_user_id.is_some() {
            "sso.identity.linked"
        } else {
            "sso.login"
        })
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((
        [
            (header::CACHE_CONTROL, "no-store"),
            (
                header::SET_COOKIE,
                "__Host-trisixt_oidc=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
            ),
        ],
        Json(session),
    )
        .into_response())
}
