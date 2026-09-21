//! Server SDK and operator automation. Credentials are hashed and scoped to a project.
use crate::{
    auth::{AuthUser, SdkProject, authorize_instance, new_token, token_hash},
    domains::{display_host, rate_limit},
    error::AppError,
    state::AppState,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde_json::{Value, json};
use uuid::Uuid;
type Api = Result<Json<Value>, AppError>;
pub async fn authenticate_key(
    st: &AppState,
    key: &str,
    environment: &str,
) -> Result<Uuid, AppError> {
    if !["production", "test"].contains(&environment) {
        return Err(AppError::BadRequest(
            "ENVIRONMENT must be production or test".into(),
        ));
    }
    if key.len() != 64 {
        return Err(AppError::Unauthorized);
    }
    if let Some((project,key_id))=sqlx::query_as::<_,(Uuid,Uuid)>("SELECT p.id,k.id FROM instance_api_keys k JOIN projects p ON p.instance_id=k.instance_id WHERE k.token_hash=$1 AND k.revoked_at IS NULL AND p.environment=$2").bind(token_hash(key)).bind(environment).fetch_optional(&st.pg).await?{
 let mut tx=st.pg.begin().await?;
 if sqlx::query("INSERT INTO automation_key_usage(key_id) VALUES($1) ON CONFLICT DO NOTHING").bind(key_id).execute(&mut *tx).await?.rows_affected()>0 {sqlx::query("SELECT trisixt_audit(instance_id,NULL,'api_key.used',$2,'{}') FROM projects WHERE id=$1").bind(project).bind(key_id).execute(&mut *tx).await?;}
 tx.commit().await?;return Ok(project)}
    sqlx::query_scalar("SELECT p.id FROM project_api_keys k JOIN projects p ON p.id=k.project_id WHERE k.token_hash=$1 AND k.revoked_at IS NULL AND p.environment=$2").bind(token_hash(key)).bind(environment).fetch_optional(&st.pg).await?.ok_or(AppError::Unauthorized)
}
async fn server_project(st: &AppState, h: &HeaderMap) -> Result<Uuid, AppError> {
    authenticate_key(
        st,
        h.get("project-key")
            .or(h.get("x-project-key"))
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        h.get("environment")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
    )
    .await
}
async fn new_key(
    State(st): State<AppState>,
    user: AuthUser,
    Path(instance): Path<Uuid>,
    Json(body): Json<Value>,
) -> Api {
    authorize_instance(&st, &user, instance, true).await?;
    let name = body["name"].as_str().unwrap_or("Server SDK");
    if name.is_empty() || name.len() > 200 {
        return Err(AppError::BadRequest("invalid key name".into()));
    }
    let (key, hash) = new_token();
    let id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO instance_api_keys(instance_id,token_hash,name) VALUES($1,$2,$3) RETURNING id",
    )
    .bind(instance)
    .bind(hash)
    .bind(name)
    .fetch_one(&st.pg)
    .await?;
    Ok(Json(json!({"id":id,"key":key,"name":name})))
}
async fn keys(State(st): State<AppState>, user: AuthUser, Path(instance): Path<Uuid>) -> Api {
    authorize_instance(&st, &user, instance, false).await?;
    let rows=sqlx::query_scalar::<_,Value>("SELECT to_jsonb(k)-'token_hash' FROM instance_api_keys k WHERE instance_id=$1 ORDER BY created_at").bind(instance).fetch_all(&st.pg).await?;
    Ok(Json(json!({"keys":rows})))
}
async fn revoke(
    State(st): State<AppState>,
    user: AuthUser,
    Path((instance, key)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    authorize_instance(&st, &user, instance, true).await?;
    sqlx::query("UPDATE instance_api_keys SET revoked_at=now() WHERE id=$1 AND instance_id=$2")
        .bind(key)
        .bind(instance)
        .execute(&st.pg)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
fn url(s: &str, mobile: bool) -> Result<(), AppError> {
    let u = url::Url::parse(s)
        .map_err(|_| AppError::BadRequest("absolute redirect URL required".into()))?;
    if !u.username().is_empty()
        || u.password().is_some()
        || (!mobile && !matches!(u.scheme(), "http" | "https"))
        || ["javascript", "data", "file", "vbscript", "about"].contains(&u.scheme())
    {
        return Err(AppError::BadRequest("unsafe redirect URL".into()));
    }
    Ok(())
}
pub async fn build_link(st: &AppState, project: Uuid, mut v: Value) -> Result<Value, AppError> {
    if !v.is_object() || v.to_string().len() > 65536 {
        return Err(AppError::BadRequest(
            "link must be an object up to 64 KiB".into(),
        ));
    }
    rate_limit(&st.pg, &format!("sdk:generate:{project}"), 600).await?;
    let visitor = if let Some(id) = v["visitor_id"].as_str().or(v["id"].as_str()) {
        let id: Uuid = id
            .parse()
            .map_err(|_| AppError::BadRequest("visitor UUID required".into()))?;
        let canonical = crate::sdk::canonical(st, project, id).await?;
        if !sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM visitors WHERE id=$1 AND project_id=$2)",
        )
        .bind(canonical)
        .bind(project)
        .fetch_one(&st.pg)
        .await?
        {
            return Err(AppError::NotFound);
        }
        Some(canonical)
    } else {
        None
    };
    crate::billing::enforce_project_quota(st, project, visitor.unwrap_or(Uuid::nil())).await?;
    let path = v["path"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
    if path.is_empty()
        || path.len() > 100
        || !path
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
    {
        return Err(AppError::BadRequest("invalid link path".into()));
    }
    let name = v["name"]
        .as_str()
        .or(v["title"].as_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("SDK link")
        .to_owned();
    if name.len() > 200 {
        return Err(AppError::BadRequest("link name too long".into()));
    }
    for key in [
        "title",
        "subtitle",
        "tracking_source",
        "tracking_medium",
        "tracking_campaign",
    ] {
        if v[key].as_str().is_some_and(|s| s.len() > 2048) {
            return Err(AppError::BadRequest(format!("{key} too long")));
        }
    }
    if !v["data"].is_null() && (!v["data"].is_object() || v["data"].to_string().len() > 32768) {
        return Err(AppError::BadRequest(
            "data object up to 32 KiB required".into(),
        ));
    }
    if !v["tags"].is_null()
        && !v["tags"].as_array().is_some_and(|a| {
            a.len() <= 100
                && a.iter()
                    .all(|s| s.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 255))
        })
    {
        return Err(AppError::BadRequest(
            "at most 100 string tags required".into(),
        ));
    }
    let config = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(c) FROM project_configurations c WHERE project_id=$1",
    )
    .bind(project)
    .fetch_optional(&st.pg)
    .await?
    .unwrap_or(json!({}));
    let mut targets = Vec::new();
    for p in ["desktop", "ios", "android"] {
        let nested = &v["custom_redirects"][p];
        let s = nested
            .as_str()
            .or(nested["url"].as_str())
            .or(v[format!("{p}_url")].as_str())
            .map(str::to_owned);
        if let Some(s) = &s {
            url(s, p != "desktop")?;
        }
        targets.push(s);
    }
    let default = format!("https://{}/", display_host(&st.pg, project).await?);
    let target = targets[0]
        .as_deref()
        .or(v["target_url"].as_str())
        .or(config["redirect"]["default_fallback"].as_str())
        .or(config["desktop"]["fallback_url"].as_str())
        .unwrap_or(&default)
        .to_owned();
    url(&target, false)?;
    if let Some(visitor) = visitor {
        v["visitor_id"] = json!(visitor)
    }
    v["sdk_generated"] = json!(true);
    v["platform"] = json!("API");
    let mut tx = st.pg.begin().await?;
    let row=sqlx::query_scalar::<_,Value>("INSERT INTO links(project_id,name,path,target_url,ios_url,android_url,metadata) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING to_jsonb(links)").bind(project).bind(name).bind(&path).bind(target).bind(&targets[1]).bind(&targets[2]).bind(v).fetch_one(&mut *tx).await?;
    sqlx::query("SELECT trisixt_audit(instance_id,NULL,'link.created',$2,jsonb_build_object('source','server_sdk')) FROM projects WHERE id=$1").bind(project).bind(row["id"].as_str().and_then(|s|s.parse::<Uuid>().ok()).ok_or(AppError::Internal)?).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(json!({"link":format!("https://{}/{path}",display_host(&st.pg,project).await?),"data":row}))
}
async fn generate(State(st): State<AppState>, headers: HeaderMap, Json(v): Json<Value>) -> Api {
    let p = server_project(&st, &headers).await?;
    Ok(Json(build_link(&st, p, v).await?))
}
async fn sdk_create(
    State(st): State<AppState>,
    SdkProject(p): SdkProject,
    Json(v): Json<Value>,
) -> Api {
    Ok(Json(build_link(&st, p, v).await?))
}
async fn link_row(st: &AppState, p: Uuid, path: &str) -> Result<Value, AppError> {
    sqlx::query_scalar(
        "SELECT to_jsonb(l) FROM links l WHERE project_id=$1 AND path=$2 AND archived_at IS NULL",
    )
    .bind(p)
    .bind(path)
    .fetch_optional(&st.pg)
    .await?
    .ok_or(AppError::NotFound)
}
async fn details(State(st): State<AppState>, headers: HeaderMap, Path(path): Path<String>) -> Api {
    let p = server_project(&st, &headers).await?;
    Ok(Json(json!({"link":link_row(&st,p,&path).await?})))
}
pub async fn metrics(
    st: &AppState,
    p: Uuid,
    link: Option<Uuid>,
    visitor: Option<Uuid>,
    referrals: bool,
) -> Result<Value, AppError> {
    crate::analytics_api::metrics_for_scope(st, p, link, visitor, referrals).await
}
async fn link_metrics(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Api {
    let p = server_project(&st, &headers).await?;
    let link = link_row(&st, p, &path).await?;
    let id = link["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or(AppError::Internal)?;
    Ok(Json(
        json!({"metrics":metrics(&st,p,Some(id),None,false).await?}),
    ))
}
async fn project_metrics(State(st): State<AppState>, headers: HeaderMap) -> Api {
    let p = server_project(&st, &headers).await?;
    Ok(Json(
        json!({"metrics":metrics(&st,p,None,None,false).await?}),
    ))
}
fn operator(h: &HeaderMap) -> Result<(), AppError> {
    let required = std::env::var("ADMIN_API_KEY").unwrap_or_default();
    let supplied = h.get("x-auth").and_then(|v| v.to_str().ok()).unwrap_or("");
    if required.is_empty() || token_hash(&required) != token_hash(supplied) {
        Err(AppError::Forbidden)
    } else {
        Ok(())
    }
}
async fn automation_project(st: &AppState, v: &Value) -> Result<Uuid, AppError> {
    let key = v["key"]
        .as_str()
        .ok_or_else(|| AppError::BadRequest("key required".into()))?;
    let test = v["test"]
        .as_bool()
        .ok_or_else(|| AppError::BadRequest("test boolean required".into()))?;
    authenticate_key(st, key, if test { "test" } else { "production" }).await
}
async fn automation_link(State(st): State<AppState>, h: HeaderMap, Json(v): Json<Value>) -> Api {
    operator(&h)?;
    let p = automation_project(&st, &v).await?;
    let path = v["path"]
        .as_str()
        .ok_or_else(|| AppError::BadRequest("path required".into()))?;
    let link = match link_row(&st, p, path).await {
        Ok(l) => l,
        Err(AppError::NotFound) => return Ok(Json(json!({"link":null,"metrics":null}))),
        Err(e) => return Err(e),
    };
    let id = link["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or(AppError::Internal)?;
    Ok(Json(
        json!({"metrics":metrics(&st,p,Some(id),None,false).await?,"link":link}),
    ))
}
async fn automation_user(State(st): State<AppState>, h: HeaderMap, Json(v): Json<Value>) -> Api {
    operator(&h)?;
    let p = automation_project(&st, &v).await?;
    let vendor = v["vendor_id"]
        .as_str()
        .ok_or_else(|| AppError::BadRequest("vendor_id required".into()))?;
    let visitor: Uuid =
        sqlx::query_scalar("SELECT visitor_id FROM devices WHERE project_id=$1 AND vendor_id=$2")
            .bind(p)
            .bind(vendor)
            .fetch_optional(&st.pg)
            .await?
            .ok_or(AppError::NotFound)?;
    let visitor = crate::sdk::canonical(&st, p, visitor).await?;
    let row = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(v) FROM visitors v WHERE project_id=$1 AND id=$2",
    )
    .bind(p)
    .bind(visitor)
    .fetch_one(&st.pg)
    .await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM links WHERE project_id=$1 AND metadata->>'visitor_id'=$2",
    )
    .bind(p)
    .bind(visitor.to_string())
    .fetch_one(&st.pg)
    .await?;
    Ok(Json(
        json!({"visitor":row,"metrics":metrics(&st,p,None,Some(visitor),false).await?,"aggregated_metrics":metrics(&st,p,None,Some(visitor),true).await?,"number_of_generated_links":count}),
    ))
}
pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/instances/{id}/server-keys",
            get(keys).post(new_key),
        )
        .route(
            "/api/v1/instances/{id}/server-keys/{key}",
            axum::routing::delete(revoke),
        )
        .route("/api/v1/sdk/generate_link", post(generate))
        .route("/api/v1/sdk/create_link", post(sdk_create))
        .route("/api/v1/sdk/link/{path}", get(details))
        .route("/api/v1/sdk/metrics_for_link/{path}", get(link_metrics))
        .route("/api/v1/sdk/metrics_for_project", get(project_metrics))
        .route("/api/v1/automation/details_for_link", post(automation_link))
        .route("/api/v1/automation/metrics_for_user", post(automation_user))
}
