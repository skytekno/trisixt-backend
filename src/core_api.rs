//! Native application API: tenant administration, links, and durable SDK ingestion.
use crate::{
    auth::{self, AuthUser, SdkProject, authorize_instance, authorize_project},
    error::AppError,
    state::AppState,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

type Api = Result<Json<Value>, AppError>;

async fn actor_tx(
    st: &AppState,
    user: &AuthUser,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, AppError> {
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT set_config('trisixt.actor_id',$1,true)")
        .bind(user.id.to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

fn email(value: &str) -> Result<String, AppError> {
    let value = value.trim().to_ascii_lowercase();
    let parts: Vec<_> = value.split('@').collect();
    if value.len() > 254
        || parts.len() != 2
        || parts[0].is_empty()
        || !parts[1].contains('.')
        || value.chars().any(char::is_whitespace)
    {
        return Err(AppError::BadRequest("valid email required".into()));
    }
    Ok(value)
}
fn name(value: &str) -> Result<(), AppError> {
    if value.trim().is_empty() || value.chars().count() > 200 {
        return Err(AppError::BadRequest(
            "name must have 1 to 200 characters".into(),
        ));
    }
    Ok(())
}
fn object(value: &Value) -> Result<(), AppError> {
    if !value.is_object() || value.to_string().len() > 32_768 {
        return Err(AppError::BadRequest(
            "properties must be an object of at most 32 KiB".into(),
        ));
    }
    Ok(())
}
fn empty_object() -> Value {
    json!({})
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Name {
    name: String,
}
async fn create_instance(
    State(st): State<AppState>,
    user: AuthUser,
    Json(body): Json<Name>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    name(&body.name)?;
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT set_config('trisixt.actor_id',$1,true)")
        .bind(user.id.to_string())
        .execute(&mut *tx)
        .await?;
    let id = sqlx::query_scalar::<_, Uuid>("INSERT INTO instances(name) VALUES($1) RETURNING id")
        .bind(body.name.trim())
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO instance_roles(user_id,instance_id,role) VALUES($1,$2,'owner')")
        .bind(user.id)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"id":id,"name":body.name.trim(),"role":"owner"})),
    ))
}
async fn instances(State(st): State<AppState>, user: AuthUser) -> Api {
    let rows=sqlx::query_scalar::<_,Value>("SELECT to_jsonb(i)||jsonb_build_object('role',r.role) FROM instances i JOIN instance_roles r ON r.instance_id=i.id WHERE r.user_id=$1 ORDER BY i.created_at,i.id")
        .bind(user.id).fetch_all(&st.pg).await?;
    Ok(Json(json!({"instances":rows})))
}
async fn instance(State(st): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Api {
    let role = authorize_instance(&st, &user, id, false).await?;
    let row = sqlx::query_scalar::<_, Value>("SELECT to_jsonb(i) FROM instances i WHERE id=$1")
        .bind(id)
        .fetch_one(&st.pg)
        .await?;
    Ok(Json(json!({"instance":row,"role":role})))
}
async fn update_instance(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<Name>,
) -> Api {
    authorize_instance(&st, &user, id, true).await?;
    name(&body.name)?;
    let mut tx = actor_tx(&st, &user).await?;
    let row = sqlx::query_scalar::<_, Value>(
        "UPDATE instances SET name=$2 WHERE id=$1 RETURNING to_jsonb(instances)",
    )
    .bind(id)
    .bind(body.name.trim())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(row))
}

async fn delete_instance(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    if authorize_instance(&st, &user, id, true).await? != "owner" {
        return Err(AppError::Forbidden);
    }
    let mut tx = actor_tx(&st, &user).await?;
    sqlx::query("DELETE FROM instances WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn members(State(st): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Api {
    authorize_instance(&st, &user, id, false).await?;
    let rows=sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('user_id',u.id,'email',u.email,'name',u.name,'invitation_pending',u.invitation_pending,'role',r.role) FROM instance_roles r JOIN users u ON u.id=r.user_id WHERE r.instance_id=$1 ORDER BY u.email")
        .bind(id).fetch_all(&st.pg).await?;
    Ok(Json(json!({"members":rows})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Membership {
    email: String,
    role: String,
}
async fn add_member(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<Membership>,
) -> Api {
    let actor = authorize_instance(&st, &user, id, true).await?;
    if !matches!(body.role.as_str(), "admin" | "member")
        || (actor != "owner" && body.role != "member")
    {
        return Err(AppError::Forbidden);
    }
    let email = email(&body.email)?;
    let pending =
        sqlx::query_scalar::<_, bool>("SELECT invitation_pending FROM users WHERE lower(email)=$1")
            .bind(&email)
            .fetch_optional(&st.pg)
            .await?;
    if pending.is_none() || pending == Some(true) {
        return Ok(Json(
            crate::accounts::invite_member(&st, &user, id, &email, &body.role).await?,
        ));
    }
    // Lock the instance so membership transitions cannot race each other.
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT set_config('trisixt.actor_id',$1,true)")
        .bind(user.id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT id FROM instances WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    let member = sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE lower(email)=$1")
        .bind(email)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AppError::NotFound)?;
    let current = sqlx::query_scalar::<_, String>(
        "SELECT role FROM instance_roles WHERE instance_id=$1 AND user_id=$2",
    )
    .bind(id)
    .bind(member)
    .fetch_optional(&mut *tx)
    .await?;
    if current.as_deref() == Some("owner")
        || (actor != "owner" && current.as_deref() == Some("admin"))
    {
        return Err(AppError::Forbidden);
    }
    sqlx::query("INSERT INTO instance_roles(instance_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT(user_id,instance_id) DO UPDATE SET role=excluded.role")
        .bind(id).bind(member).bind(&body.role).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"user_id":member,"role":body.role})))
}
async fn remove_member(
    State(st): State<AppState>,
    user: AuthUser,
    Path((id, member)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let actor = authorize_instance(&st, &user, id, true).await?;
    let mut tx = actor_tx(&st, &user).await?;
    let deleted=sqlx::query("DELETE FROM instance_roles WHERE instance_id=$1 AND user_id=$2 AND role<>'owner' AND (role='member' OR $3='owner')")
        .bind(id).bind(member).bind(actor).execute(&mut *tx).await?.rows_affected();
    if deleted == 0 {
        return Err(AppError::Forbidden);
    }
    sqlx::query("UPDATE account_tokens SET used_at=now() WHERE instance_id=$1 AND user_id=$2 AND purpose='invite' AND used_at IS NULL").bind(id).bind(member).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewProject {
    name: String,
    environment: String,
    domain: String,
}
fn domain(value: &str) -> Result<String, AppError> {
    let value = value.trim().to_ascii_lowercase();
    if value.len() > 253
        || value.split('.').any(|p| {
            p.is_empty()
                || p.len() > 63
                || p.starts_with('-')
                || p.ends_with('-')
                || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(AppError::BadRequest("invalid project domain".into()));
    }
    Ok(value)
}
async fn create_project(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<NewProject>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    authorize_instance(&st, &user, id, true).await?;
    name(&body.name)?;
    if !matches!(body.environment.as_str(), "test" | "production") {
        return Err(AppError::BadRequest(
            "environment must be test or production".into(),
        ));
    }
    let domain = domain(&body.domain)?;
    let mut tx = actor_tx(&st, &user).await?;
    let row=sqlx::query_scalar::<_,Value>("INSERT INTO projects(instance_id,name,environment,domain) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING to_jsonb(projects)")
        .bind(id).bind(body.name.trim()).bind(body.environment).bind(domain).fetch_optional(&mut *tx).await?.ok_or_else(||AppError::Conflict("domain or environment already exists".into()))?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(row)))
}

async fn projects(State(st): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Api {
    authorize_instance(&st, &user, id, false).await?;
    let rows = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(p) FROM projects p WHERE instance_id=$1 ORDER BY environment",
    )
    .bind(id)
    .fetch_all(&st.pg)
    .await?;
    Ok(Json(json!({"projects":rows})))
}
async fn project(State(st): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Api {
    authorize_project(&st, &user, id, false).await?;
    Ok(Json(
        sqlx::query_scalar::<_, Value>("SELECT to_jsonb(p) FROM projects p WHERE id=$1")
            .bind(id)
            .fetch_one(&st.pg)
            .await?,
    ))
}
async fn delete_project(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let instance = authorize_project(&st, &user, id, true).await?;
    if authorize_instance(&st, &user, instance, true).await? != "owner" {
        return Err(AppError::Forbidden);
    }
    let mut tx = actor_tx(&st, &user).await?;
    sqlx::query("DELETE FROM projects WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_key(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<Name>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    authorize_project(&st, &user, id, true).await?;
    name(&body.name)?;
    let (key, hash) = auth::new_token();
    let mut tx = actor_tx(&st, &user).await?;
    let key_id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO project_api_keys(project_id,token_hash,name) VALUES($1,$2,$3) RETURNING id",
    )
    .bind(id)
    .bind(hash)
    .bind(body.name.trim())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"id":key_id,"key":key,"name":body.name.trim()})),
    ))
}

async fn keys(State(st): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Api {
    authorize_project(&st, &user, id, true).await?;
    let rows=sqlx::query_scalar::<_,Value>("SELECT to_jsonb(k)-'token_hash' FROM project_api_keys k WHERE project_id=$1 ORDER BY created_at").bind(id).fetch_all(&st.pg).await?;
    Ok(Json(json!({"keys":rows})))
}
async fn revoke_key(
    State(st): State<AppState>,
    user: AuthUser,
    Path((id, key)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    authorize_project(&st, &user, id, true).await?;
    let mut tx = actor_tx(&st, &user).await?;
    if sqlx::query("UPDATE project_api_keys SET revoked_at=now() WHERE project_id=$1 AND id=$2")
        .bind(id)
        .bind(key)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        == 0
    {
        return Err(AppError::NotFound);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CampaignInput {
    name: String,
    #[serde(default = "empty_object")]
    metadata: Value,
}
async fn campaigns(State(st): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Api {
    authorize_project(&st, &user, id, false).await?;
    let rows=sqlx::query_scalar::<_,Value>("SELECT to_jsonb(c) FROM campaigns c WHERE project_id=$1 AND archived_at IS NULL ORDER BY created_at DESC LIMIT 1000").bind(id).fetch_all(&st.pg).await?;
    Ok(Json(json!({"campaigns":rows})))
}
async fn create_campaign(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<CampaignInput>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    authorize_project(&st, &user, id, true).await?;
    name(&body.name)?;
    object(&body.metadata)?;
    let mut tx = actor_tx(&st, &user).await?;
    let row=sqlx::query_scalar::<_,Value>("INSERT INTO campaigns(project_id,name,metadata) VALUES($1,$2,$3) RETURNING to_jsonb(campaigns)")
        .bind(id).bind(body.name.trim()).bind(body.metadata).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(row)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CampaignUpdate {
    name: Option<String>,
    metadata: Option<Value>,
    archived: Option<bool>,
}
async fn update_campaign(
    State(st): State<AppState>,
    user: AuthUser,
    Path((id, campaign)): Path<(Uuid, Uuid)>,
    Json(body): Json<CampaignUpdate>,
) -> Api {
    authorize_project(&st, &user, id, true).await?;
    if let Some(value) = &body.name {
        name(value)?;
    }
    if let Some(value) = &body.metadata {
        object(value)?;
    }
    let mut tx = actor_tx(&st, &user).await?;
    let row=sqlx::query_scalar::<_,Value>("UPDATE campaigns SET name=coalesce($3,name),metadata=metadata||coalesce($4,'{}'::jsonb),archived_at=CASE WHEN $5::bool IS NULL THEN archived_at WHEN $5 THEN coalesce(archived_at,now()) ELSE NULL END,updated_at=now() WHERE project_id=$1 AND id=$2 RETURNING to_jsonb(campaigns)")
        .bind(id).bind(campaign).bind(body.name.map(|s|s.trim().to_owned())).bind(body.metadata).bind(body.archived).fetch_optional(&mut *tx).await?.ok_or(AppError::NotFound)?;
    tx.commit().await?;
    Ok(Json(row))
}

async fn archive_campaign(
    State(st): State<AppState>,
    user: AuthUser,
    Path((id, campaign)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    authorize_project(&st, &user, id, true).await?;
    let mut tx = actor_tx(&st, &user).await?;
    if sqlx::query("UPDATE campaigns SET archived_at=now(),updated_at=now() WHERE project_id=$1 AND id=$2 AND archived_at IS NULL").bind(id).bind(campaign).execute(&mut *tx).await?.rows_affected()==0 {return Err(AppError::NotFound);}
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkInput {
    #[serde(default = "enabled_by_default")]
    active: bool,
    name: String,
    path: String,
    target_url: String,
    ios_url: Option<String>,
    android_url: Option<String>,
    campaign_id: Option<Uuid>,
    #[serde(default = "empty_object")]
    metadata: Value,
}
fn enabled_by_default() -> bool {
    true
}
fn redirect_url(value: &str) -> Result<(), AppError> {
    let url = reqwest::Url::parse(value)
        .map_err(|_| AppError::BadRequest("invalid redirect URL".into()))?;
    if value.len() > 4096
        || !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(AppError::BadRequest(
            "redirect must be an absolute HTTP(S) URL without credentials".into(),
        ));
    }
    Ok(())
}
fn validate_link(body: &LinkInput) -> Result<(), AppError> {
    name(&body.name)?;
    object(&body.metadata)?;
    if body.path.is_empty()
        || body.path.len() > 100
        || !body
            .path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(AppError::BadRequest(
            "path must have 1 to 100 letters, digits, hyphens or underscores".into(),
        ));
    }
    redirect_url(&body.target_url)?;
    for url in [&body.ios_url, &body.android_url].into_iter().flatten() {
        navigation_url(url)?;
    }
    validate_metadata(&body.metadata)?;
    Ok(())
}
async fn check_campaign(
    st: &AppState,
    project: Uuid,
    campaign: Option<Uuid>,
) -> Result<(), AppError> {
    if let Some(id) = campaign {
        let exists=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM campaigns WHERE project_id=$1 AND id=$2 AND archived_at IS NULL)").bind(project).bind(id).fetch_one(&st.pg).await?;
        if !exists {
            return Err(AppError::BadRequest(
                "campaign is not active in this project".into(),
            ));
        }
    }
    Ok(())
}
async fn create_link(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(raw): Json<Value>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    authorize_project(&st, &user, id, true).await?;
    let body = normalize_link(&st, id, raw, None).await?;
    validate_link(&body)?;
    check_campaign(&st, id, body.campaign_id).await?;
    let mut tx = actor_tx(&st, &user).await?;
    let row=sqlx::query_scalar::<_,Value>("INSERT INTO links(project_id,name,path,target_url,ios_url,android_url,campaign_id,metadata,archived_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,CASE WHEN $9 THEN NULL ELSE now() END) ON CONFLICT DO NOTHING RETURNING to_jsonb(links)")
        .bind(id).bind(body.name.trim()).bind(body.path).bind(body.target_url).bind(body.ios_url).bind(body.android_url).bind(body.campaign_id).bind(body.metadata).bind(body.active)
        .fetch_optional(&mut *tx).await?.ok_or_else(||AppError::Conflict("path already exists".into()))?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(row)))
}

#[derive(Deserialize, Default)]
struct Pagination {
    limit: Option<i64>,
    offset: Option<i64>,
}
impl Pagination {
    fn values(&self) -> Result<(i64, i64), AppError> {
        let l = self.limit.unwrap_or(100);
        let o = self.offset.unwrap_or(0);
        if !(1..=1000).contains(&l) || !(0..=1_000_000).contains(&o) {
            return Err(AppError::BadRequest("invalid pagination".into()));
        }
        Ok((l, o))
    }
}
async fn links(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Query(page): Query<Pagination>,
) -> Api {
    authorize_project(&st, &user, id, false).await?;
    let (limit, offset) = page.values()?;
    let rows=sqlx::query_scalar::<_,Value>("SELECT to_jsonb(l) FROM links l WHERE project_id=$1 AND archived_at IS NULL ORDER BY created_at DESC,id LIMIT $2 OFFSET $3")
        .bind(id).bind(limit).bind(offset).fetch_all(&st.pg).await?;
    Ok(Json(json!({"links":rows})))
}
async fn link(
    State(st): State<AppState>,
    user: AuthUser,
    Path((id, link)): Path<(Uuid, Uuid)>,
) -> Api {
    authorize_project(&st, &user, id, false).await?;
    let row = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(l) FROM links l WHERE project_id=$1 AND id=$2 AND archived_at IS NULL",
    )
    .bind(id)
    .bind(link)
    .fetch_optional(&st.pg)
    .await?
    .ok_or(AppError::NotFound)?;
    Ok(Json(row))
}
async fn update_link(
    State(st): State<AppState>,
    user: AuthUser,
    Path((id, link)): Path<(Uuid, Uuid)>,
    Json(raw): Json<Value>,
) -> Api {
    authorize_project(&st, &user, id, true).await?;
    let mut tx = actor_tx(&st, &user).await?;
    let existing = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(l) FROM links l WHERE project_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(id)
    .bind(link)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::NotFound)?;
    let body = normalize_link(&st, id, raw, Some(existing)).await?;
    validate_link(&body)?;
    if let Some(campaign) = body.campaign_id {
        let active=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM campaigns WHERE project_id=$1 AND id=$2 AND archived_at IS NULL)").bind(id).bind(campaign).fetch_one(&mut *tx).await?;
        if !active {
            return Err(AppError::BadRequest(
                "campaign is not active in this project".into(),
            ));
        }
    }

    let row=sqlx::query_scalar::<_,Value>("UPDATE links SET name=$3,path=$4,target_url=$5,ios_url=$6,android_url=$7,campaign_id=$8,metadata=$9,archived_at=CASE WHEN $10 THEN NULL ELSE coalesce(archived_at,now()) END,updated_at=now() WHERE project_id=$1 AND id=$2 RETURNING to_jsonb(links)")
        .bind(id).bind(link).bind(body.name.trim()).bind(body.path).bind(body.target_url).bind(body.ios_url).bind(body.android_url).bind(body.campaign_id).bind(body.metadata).bind(body.active)
        .fetch_optional(&mut *tx).await?.ok_or(AppError::NotFound)?;
    tx.commit().await?;
    Ok(Json(row))
}

async fn archive_link(
    State(st): State<AppState>,
    user: AuthUser,
    Path((id, link)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    authorize_project(&st, &user, id, true).await?;
    let mut tx = actor_tx(&st, &user).await?;
    if sqlx::query("UPDATE links SET archived_at=now(),updated_at=now() WHERE project_id=$1 AND id=$2 AND archived_at IS NULL").bind(id).bind(link).execute(&mut *tx).await?.rows_affected()==0 {return Err(AppError::NotFound);}
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn public_redirect(
    State(st): State<AppState>,
    Path((id, path)): Path<(Uuid, String)>,
    ctx: crate::sdk::ClientContext,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Result<axum::response::Response, AppError> {
    crate::public_links::render(
        &st,
        id,
        &path,
        &headers,
        &ctx,
        uri.query().unwrap_or(""),
        false,
    )
    .await
}
async fn domain_redirect(
    State(st): State<AppState>,
    Path(path): Path<String>,
    ctx: crate::sdk::ClientContext,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Result<axum::response::Response, AppError> {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::NotFound)?
        .split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let project = crate::public_links::project_for_host(&st, &host)
        .await?
        .ok_or(AppError::NotFound)?;
    crate::public_links::render(
        &st,
        project,
        &path,
        &headers,
        &ctx,
        uri.query().unwrap_or(""),
        false,
    )
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VisitorInput {
    visitor_id: Uuid,
    external_id: Option<String>,
    #[serde(default = "empty_object")]
    attributes: Value,
}
async fn sdk_visitor(
    State(st): State<AppState>,
    sdk: SdkProject,
    Json(body): Json<VisitorInput>,
) -> Api {
    let id = sdk.id;
    if body.visitor_id.is_nil() {
        return Err(AppError::BadRequest("visitor_id must not be nil".into()));
    }
    object(&body.attributes)?;
    if body.external_id.as_ref().is_some_and(|s| s.len() > 254) {
        return Err(AppError::BadRequest("external_id exceeds 254 bytes".into()));
    }
    let row=sqlx::query_scalar::<_,Value>("INSERT INTO visitors(project_id,id,external_id,attributes) VALUES($1,$2,$3,$4) ON CONFLICT(project_id,id) DO UPDATE SET external_id=coalesce(excluded.external_id,visitors.external_id),attributes=visitors.attributes||excluded.attributes,last_seen_at=now() RETURNING to_jsonb(visitors)")
        .bind(id).bind(body.visitor_id).bind(body.external_id).bind(body.attributes).fetch_one(&st.pg).await?;
    Ok(Json(row))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventInput {
    pub(crate) event_id: Uuid,
    pub(crate) visitor_id: Uuid,
    pub(crate) event_type: String,
    pub(crate) occurred_at: DateTime<Utc>,
    #[serde(default = "empty_object")]
    pub(crate) properties: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventBatch {
    events: Vec<EventInput>,
}
fn validate_event(event: &EventInput) -> Result<(), AppError> {
    if event.event_id.is_nil() || event.visitor_id.is_nil() {
        return Err(AppError::BadRequest(
            "event_id and visitor_id must not be nil".into(),
        ));
    }

    if event.event_type.is_empty()
        || event.event_type.len() > 100
        || !event
            .event_type
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
    {
        return Err(AppError::BadRequest("invalid event_type".into()));
    }
    if event.occurred_at > Utc::now() + chrono::Duration::minutes(5)
        || event.occurred_at < Utc::now() - chrono::Duration::days(3650)
    {
        return Err(AppError::BadRequest(
            "event timestamp is outside supported bounds".into(),
        ));
    }
    object(&event.properties)
}
pub(crate) async fn persist_events(
    st: &AppState,
    project: Uuid,
    mut events: Vec<EventInput>,
) -> Api {
    if events.is_empty() || events.len() > 100 {
        return Err(AppError::BadRequest(
            "batch must contain 1 to 100 events".into(),
        ));
    }
    for event in &mut events {
        validate_event(event)?;
    }
    // Acquire every event lock first, then every visitor row lock in a stable
    // order. Different batches can map event UUID order to reversed visitor
    // UUID order, so interleaving those two lock classes can deadlock.
    let submitted = events.len();
    events.sort_by_key(|event| event.event_id);
    events.dedup_by_key(|event| event.event_id);
    let mut tx = st.pg.begin().await?;
    // Identity merges take the exclusive version of this lock. Resolve aliases
    // inside the ingestion transaction so a merge cannot split a new batch.
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,42))")
        .bind(project.to_string())
        .execute(&mut *tx)
        .await?;
    for event in &mut events {
        event.visitor_id = sqlx::query_scalar::<_,Uuid>("SELECT coalesce((SELECT visitor_id FROM visitor_aliases WHERE project_id=$1 AND alias_id=$2),$2)")
            .bind(project).bind(event.visitor_id).fetch_one(&mut *tx).await?;
    }
    let mut pending = Vec::new();
    for event in &events {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("{project}:{}", event.event_id))
            .execute(&mut *tx)
            .await?;
        let duplicate = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM events WHERE project_id=$1 AND event_id=$2)",
        )
        .bind(project)
        .bind(event.event_id)
        .fetch_one(&mut *tx)
        .await?;
        if !duplicate {
            pending.push(event);
        }
    }
    let mut visitor_ids: Vec<Uuid> = pending.iter().map(|event| event.visitor_id).collect();
    visitor_ids.sort_unstable();
    visitor_ids.dedup();
    for visitor in visitor_ids {
        sqlx::query("INSERT INTO visitors(project_id,id) VALUES($1,$2) ON CONFLICT(project_id,id) DO UPDATE SET last_seen_at=now()")
            .bind(project).bind(visitor).execute(&mut *tx).await?;
    }
    let mut inserted = 0;
    for event in pending {
        let mut properties = event.properties.clone();
        let profile=sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('attributes',attributes,'external_id',external_id) FROM visitors WHERE project_id=$1 AND id=$2").bind(project).bind(event.visitor_id).fetch_one(&mut *tx).await?;
        properties["_user_attributes"] = profile["attributes"].clone();
        properties["_sdk_identifier"] = profile["external_id"].clone();
        let link_input = properties
            .get("link_id")
            .filter(|v| !v.is_null())
            .map(|v| {
                v.as_str()
                    .and_then(|s| s.parse::<Uuid>().ok())
                    .ok_or_else(|| AppError::BadRequest("invalid link_id".into()))
            })
            .transpose()?;
        let link_id = match link_input {
            Some(id) => Some(id),
            None => sqlx::query_scalar::<_, Option<Uuid>>(
                "SELECT link_id FROM visitor_attributions WHERE project_id=$1 AND visitor_id=$2",
            )
            .bind(project)
            .bind(event.visitor_id)
            .fetch_optional(&mut *tx)
            .await?
            .flatten(),
        };
        let snapshot = if let Some(link) = link_id {
            sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('link_id',id,'campaign_id',campaign_id,'sdk_generated',coalesce(metadata->'sdk_generated','false'),'link_visitor_id',metadata->'visitor_id','tracking_source',metadata->'tracking_source','tracking_medium',metadata->'tracking_medium','tracking_campaign',metadata->'tracking_campaign') FROM links WHERE project_id=$1 AND id=$2").bind(project).bind(link).fetch_optional(&mut *tx).await?.ok_or_else(||AppError::BadRequest("link belongs to another project or does not exist".into()))?
        } else {
            json!({"link_id":null,"campaign_id":null,"sdk_generated":false,"link_visitor_id":null})
        };
        properties["link_id"] = snapshot["link_id"].clone();
        properties["_attribution"] = snapshot.clone();
        for key in ["tracking_source", "tracking_medium", "tracking_campaign"] {
            if !snapshot[key].is_null() {
                properties[key] = snapshot[key].clone();
            }
        }
        properties["_device_id"] = Value::Null;
        let device=sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('_device_id',id,'platform',platform,'app_version',app_version,'device_model',model,'build',build,'language',language) FROM devices WHERE project_id=$1 AND visitor_id=$2 ORDER BY updated_at DESC LIMIT 1").bind(project).bind(event.visitor_id).fetch_optional(&mut *tx).await?;
        if let Some(device) = device {
            for (key, value) in device.as_object().unwrap() {
                if !properties.get(key).is_some_and(|v| !v.is_null()) {
                    properties[key] = value.clone();
                }
            }
        }
        if [
            "view",
            "open",
            "install",
            "reinstall",
            "time_spent",
            "reactivation",
            "app_open",
            "user_referred",
        ]
        .contains(&event.event_type.to_ascii_lowercase().as_str())
        {
            crate::billing::record_usage(&mut tx, project, event.visitor_id, event.occurred_at)
                .await?;
        }
        sqlx::query("UPDATE visitors SET first_seen_at=least(first_seen_at,$3),last_seen_at=greatest(last_seen_at,$3) WHERE project_id=$1 AND id=$2").bind(project).bind(event.visitor_id).bind(event.occurred_at).execute(&mut *tx).await?;
        let id=sqlx::query_scalar::<_,Uuid>("INSERT INTO events(project_id,event_id,visitor_id,event_type,properties,occurred_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(project_id,event_id) DO NOTHING RETURNING id")
            .bind(project).bind(event.event_id).bind(event.visitor_id).bind(&event.event_type).bind(&properties).bind(event.occurred_at).fetch_optional(&mut *tx).await?;
        if let Some(id) = id {
            let payload = json!({"id":id,"event_id":event.event_id,"project_id":project,"visitor_id":event.visitor_id,"event_type":event.event_type,"occurred_at":event.occurred_at,"properties":properties});
            sqlx::query(
                "INSERT INTO analytics_outbox(project_id,event_id,payload) VALUES($1,$2,$3)",
            )
            .bind(project)
            .bind(id)
            .bind(payload)
            .execute(&mut *tx)
            .await?;
            inserted += 1;
        }
    }
    tx.commit().await?;
    Ok(Json(
        json!({"accepted":inserted,"duplicates":submitted-inserted}),
    ))
}
async fn sdk_events(
    State(st): State<AppState>,
    sdk: SdkProject,
    Json(mut body): Json<EventBatch>,
) -> Api {
    let project = sdk.id;
    for event in &mut body.events {
        sdk.bind_event_platform(&mut event.properties)?;
    }
    persist_events(&st, project, body.events).await
}
async fn sdk_event(
    State(st): State<AppState>,
    sdk: SdkProject,
    Json(mut body): Json<EventInput>,
) -> Api {
    let project = sdk.id;
    sdk.bind_event_platform(&mut body.properties)?;
    persist_events(&st, project, vec![body]).await
}
async fn events(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Query(page): Query<Pagination>,
) -> Api {
    authorize_project(&st, &user, id, false).await?;
    let (limit, offset) = page.values()?;
    let rows=sqlx::query_scalar::<_,Value>("SELECT to_jsonb(e) FROM events e WHERE project_id=$1 ORDER BY occurred_at DESC,id LIMIT $2 OFFSET $3").bind(id).bind(limit).bind(offset).fetch_all(&st.pg).await?;
    Ok(Json(json!({"events":rows})))
}
async fn visitors(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Query(page): Query<Pagination>,
) -> Api {
    authorize_project(&st, &user, id, false).await?;
    let (limit, offset) = page.values()?;
    let rows=sqlx::query_scalar::<_,Value>("SELECT to_jsonb(v) FROM visitors v WHERE project_id=$1 ORDER BY last_seen_at DESC,id LIMIT $2 OFFSET $3").bind(id).bind(limit).bind(offset).fetch_all(&st.pg).await?;
    Ok(Json(json!({"visitors":rows})))
}
async fn visitor(
    State(st): State<AppState>,
    user: AuthUser,
    Path((id, visitor)): Path<(Uuid, Uuid)>,
) -> Api {
    authorize_project(&st, &user, id, false).await?;
    let row = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(v) FROM visitors v WHERE project_id=$1 AND id=$2",
    )
    .bind(id)
    .bind(visitor)
    .fetch_optional(&st.pg)
    .await?
    .ok_or(AppError::NotFound)?;
    Ok(Json(row))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/projects/{id}/configurations", get(configurations))
        .route(
            "/api/v1/projects/{id}/configurations/{platform}",
            axum::routing::put(set_configuration).delete(clear_configuration),
        )
        .route("/api/v1/sdk/configurations", get(sdk_configurations))
        .route("/api/v1/sdk/links/{path}", get(sdk_link))
        .route(
            "/.well-known/apple-app-site-association",
            get(apple_association),
        )
        .route("/.well-known/assetlinks.json", get(android_association))
        .route("/api/v1/instances", get(instances).post(create_instance))
        .route(
            "/api/v1/instances/{id}",
            get(instance).put(update_instance).delete(delete_instance),
        )
        .route(
            "/api/v1/instances/{id}/members",
            get(members).post(add_member),
        )
        .route(
            "/api/v1/instances/{id}/members/{user_id}",
            axum::routing::delete(remove_member),
        )
        .route(
            "/api/v1/instances/{id}/projects",
            get(projects).post(create_project),
        )
        .route("/api/v1/projects/{id}", get(project).delete(delete_project))
        .route("/api/v1/projects/{id}/keys", get(keys).post(create_key))
        .route(
            "/api/v1/projects/{id}/keys/{key_id}",
            axum::routing::delete(revoke_key),
        )
        .route(
            "/api/v1/projects/{id}/campaigns",
            get(campaigns).post(create_campaign),
        )
        .route(
            "/api/v1/projects/{id}/campaigns/{campaign_id}",
            axum::routing::patch(update_campaign).delete(archive_campaign),
        )
        .route("/api/v1/projects/{id}/links", get(links).post(create_link))
        .route(
            "/api/v1/projects/{id}/links/{link_id}",
            get(link)
                .put(update_link)
                .patch(update_link)
                .delete(archive_link),
        )
        .route("/api/v1/projects/{id}/events", get(events))
        .route("/api/v1/projects/{id}/visitors", get(visitors))
        .route("/api/v1/projects/{id}/visitors/{visitor_id}", get(visitor))
        .route("/api/v1/sdk/visitors", post(sdk_visitor))
        .route("/api/v1/sdk/events", post(sdk_events))
        .route("/api/v1/sdk/events/batch", post(sdk_events))
        .route("/api/v1/sdk/event", post(sdk_event))
        .route("/r/{project_id}/{path}", get(public_redirect))
        .route("/l/{path}", get(domain_redirect))
}

async fn configurations(State(st): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Api {
    authorize_project(&st, &user, id, false).await?;
    read_configurations(&st, id).await
}
async fn read_configurations(st: &AppState, id: Uuid) -> Api {
    let row = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(c) FROM project_configurations c WHERE project_id=$1",
    )
    .bind(id)
    .fetch_optional(&st.pg)
    .await?;
    Ok(Json(row.unwrap_or_else(
        || json!({"project_id":id,"ios":{},"android":{},"web":{},"desktop":{},"redirect":{}}),
    )))
}
async fn sdk_configurations(State(st): State<AppState>, sdk: SdkProject) -> Api {
    read_configurations(&st, sdk.id).await
}
pub(crate) fn validate_configuration(platform: &str, body: &Value) -> Result<(), AppError> {
    object(body)?;
    let allowed: &[&str] = match platform {
        "ios" => &[
            "team_id",
            "bundle_id",
            "app_store_url",
            "enabled",
            "tablet_enabled",
            "generated_page",
            "uri_scheme",
        ],
        "android" => &[
            "package_name",
            "sha256_cert_fingerprints",
            "store_url",
            "enabled",
            "tablet_enabled",
            "generated_page",
            "uri_scheme",
        ],
        "web" => &[
            "domains",
            "fallback_url",
            "enabled",
            "generated_page",
            "uri_scheme",
        ],
        "desktop" => &[
            "fallback_url",
            "enabled",
            "generated_page",
            "mac_uri",
            "windows_uri",
            "mac_enabled",
            "windows_enabled",
            "uri_scheme",
        ],
        "redirect" => &[
            "default_fallback",
            "ios_fallback",
            "android_fallback",
            "desktop_fallback",
            "ios_phone",
            "ios_tablet",
            "android_phone",
            "android_tablet",
            "desktop_all",
            "desktop_mac",
            "desktop_windows",
            "desktop_linux",
            "show_preview",
            "copy_to_clipboard",
            "show_preview_ios",
            "show_preview_android",
            "show_preview_desktop",
            "copy_to_clipboard_ios",
            "copy_to_clipboard_android",
            "copy_to_clipboard_desktop",
            "uri_scheme",
        ],
        _ => return Err(AppError::BadRequest("unsupported platform".into())),
    };
    for (key, value) in body.as_object().ok_or(AppError::Internal)? {
        if !allowed.contains(&key.as_str()) {
            return Err(AppError::BadRequest(format!(
                "unsupported {platform} setting: {key}"
            )));
        }
        if key.ends_with("enabled")
            || [
                "generated_page",
                "show_preview",
                "copy_to_clipboard",
                "show_preview_ios",
                "show_preview_android",
                "show_preview_desktop",
                "copy_to_clipboard_ios",
                "copy_to_clipboard_android",
                "copy_to_clipboard_desktop",
            ]
            .contains(&key.as_str())
        {
            if !value.is_boolean() {
                return Err(AppError::BadRequest(format!("{key} must be boolean")));
            }
        } else if [
            "ios_phone",
            "ios_tablet",
            "android_phone",
            "android_tablet",
            "desktop_all",
            "desktop_mac",
            "desktop_windows",
            "desktop_linux",
        ]
        .contains(&key.as_str())
        {
            validate_redirect_settings(value)?;
        } else if key == "domains" {
            let domains = value.as_array().filter(|v| v.len() <= 100).ok_or_else(|| {
                AppError::BadRequest("domains must be an array of at most 100 hostnames".into())
            })?;
            for domain in domains {
                crate::auth::web_identifier(
                    domain
                        .as_str()
                        .ok_or_else(|| AppError::BadRequest("domain must be text".into()))?,
                )?;
            }
        } else if key == "uri_scheme" {
            let scheme = value
                .as_str()
                .ok_or_else(|| AppError::BadRequest("uri_scheme must be text".into()))?;
            navigation_url(&format!("{}://open", scheme.trim_end_matches("://")))?;
        } else if key.ends_with("_uri") {
            navigation_url(
                value
                    .as_str()
                    .ok_or_else(|| AppError::BadRequest("URI must be text".into()))?,
            )?;
        } else if key == "sha256_cert_fingerprints" {
            let fingerprints = value
                .as_array()
                .ok_or_else(|| AppError::BadRequest("fingerprints must be an array".into()))?;
            if fingerprints.is_empty() || fingerprints.len() > 10 {
                return Err(AppError::BadRequest(
                    "provide 1 to 10 certificate fingerprints".into(),
                ));
            }
            for fingerprint in fingerprints {
                let fingerprint = fingerprint
                    .as_str()
                    .ok_or_else(|| AppError::BadRequest("fingerprint must be text".into()))?;
                let segments: Vec<_> = fingerprint.split(':').collect();
                if segments.len() != 32
                    || segments
                        .iter()
                        .any(|s| s.len() != 2 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
                {
                    return Err(AppError::BadRequest(
                        "certificate fingerprint must contain 32 colon-separated hex bytes".into(),
                    ));
                }
            }
        } else {
            let value = value
                .as_str()
                .ok_or_else(|| AppError::BadRequest(format!("{key} must be text")))?;
            if key.ends_with("url") || key.ends_with("fallback") {
                redirect_url(value)?;
            } else if value.is_empty()
                || value.len() > 255
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
            {
                return Err(AppError::BadRequest(format!("invalid {key}")));
            }
        }
    }
    Ok(())
}
async fn clear_configuration(
    State(st): State<AppState>,
    user: AuthUser,
    Path((project, platform)): Path<(Uuid, String)>,
) -> Api {
    set_configuration(State(st), user, Path((project, platform)), Json(json!({}))).await
}
async fn set_configuration(
    State(st): State<AppState>,
    user: AuthUser,
    Path((id, platform)): Path<(Uuid, String)>,
    Json(body): Json<Value>,
) -> Api {
    authorize_project(&st, &user, id, true).await?;
    validate_configuration(&platform, &body)?;
    // Platform is validated against the fixed allowlist above before interpolation.
    let query = format!(
        "INSERT INTO project_configurations(project_id,{platform}) VALUES($1,$2) ON CONFLICT(project_id) DO UPDATE SET {platform}=excluded.{platform},updated_at=now() RETURNING to_jsonb(project_configurations)"
    );
    let mut tx = actor_tx(&st, &user).await?;
    let row = sqlx::query_scalar::<_, Value>(sqlx::AssertSqlSafe(query))
        .bind(id)
        .bind(body)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(row))
}

async fn association_project(st: &AppState, headers: &HeaderMap) -> Result<Uuid, AppError> {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::NotFound)?
        .split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    crate::public_links::project_for_host(st, &host)
        .await?
        .ok_or(AppError::NotFound)
}

async fn apple_association(State(st): State<AppState>, headers: HeaderMap) -> Api {
    let project = association_project(&st, &headers).await?;
    let config = sqlx::query_scalar::<_, Value>(
        "SELECT ios FROM project_configurations WHERE project_id=$1",
    )
    .bind(project)
    .fetch_optional(&st.pg)
    .await?
    .ok_or(AppError::NotFound)?;
    let team = config["team_id"].as_str().ok_or(AppError::NotFound)?;
    let bundle = config["bundle_id"].as_str().ok_or(AppError::NotFound)?;
    Ok(Json(
        json!({"applinks":{"details":[{"appIDs":[format!("{team}.{bundle}")],"components":[{"/":"/*"}]}]}}),
    ))
}
async fn android_association(State(st): State<AppState>, headers: HeaderMap) -> Api {
    let project = association_project(&st, &headers).await?;
    let config = sqlx::query_scalar::<_, Value>(
        "SELECT android FROM project_configurations WHERE project_id=$1",
    )
    .bind(project)
    .fetch_optional(&st.pg)
    .await?
    .ok_or(AppError::NotFound)?;
    let package = config["package_name"].as_str().ok_or(AppError::NotFound)?;
    let fingerprints = config["sha256_cert_fingerprints"]
        .as_array()
        .ok_or(AppError::NotFound)?;
    Ok(Json(
        json!([{"relation":["delegate_permission/common.handle_all_urls"],"target":{"namespace":"android_app","package_name":package,"sha256_cert_fingerprints":fingerprints}}]),
    ))
}
async fn sdk_link(State(st): State<AppState>, sdk: SdkProject, Path(path): Path<String>) -> Api {
    let id = sdk.id;
    let row = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(l) FROM links l WHERE project_id=$1 AND path=$2 AND archived_at IS NULL",
    )
    .bind(id)
    .bind(path)
    .fetch_optional(&st.pg)
    .await?
    .ok_or(AppError::NotFound)?;
    Ok(Json(row))
}

pub(crate) fn navigation_url(value: &str) -> Result<(), AppError> {
    let u = url::Url::parse(value)
        .map_err(|_| AppError::BadRequest("invalid navigation URI".into()))?;
    if value.len() > 4096
        || value.chars().any(char::is_control)
        || ["javascript", "data", "file", "vbscript", "blob", "about"].contains(&u.scheme())
        || !u.username().is_empty()
        || u.password().is_some()
        || (["http", "https"].contains(&u.scheme()) && u.host_str().is_none())
    {
        return Err(AppError::BadRequest("unsafe navigation URI".into()));
    }
    Ok(())
}
fn validate_redirect_settings(value: &Value) -> Result<(), AppError> {
    if let Some(s) = value.as_str() {
        return navigation_url(s);
    }
    let obj = value
        .as_object()
        .ok_or_else(|| AppError::BadRequest("redirect settings must be an object".into()))?;
    for (k, v) in obj {
        match k.as_str() {
            "appstore" if v.is_boolean() => {}
            "url" | "fallback" | "fallback_url" | "appstore" | "uri" => {
                if !v.is_null() {
                    navigation_url(v.as_str().ok_or_else(|| {
                        AppError::BadRequest("redirect URL must be text".into())
                    })?)?;
                }
            }
            "open_app"
            | "open_app_if_installed"
            | "enabled"
            | "show_preview"
            | "copy_to_clipboard" => {
                if !v.is_boolean() {
                    return Err(AppError::BadRequest(
                        "redirect option must be boolean".into(),
                    ));
                }
            }
            _ => {
                return Err(AppError::BadRequest(format!(
                    "unknown redirect setting: {k}"
                )));
            }
        };
    }
    Ok(())
}
fn validate_metadata(value: &Value) -> Result<(), AppError> {
    object(value)?;
    for (k, v) in value.as_object().unwrap() {
        if k.starts_with("show_preview")
            || k.starts_with("copy_to_clipboard")
            || k.starts_with("disable_")
        {
            if !v.is_boolean() {
                return Err(AppError::BadRequest(format!("{k} must be boolean")));
            }
        } else if [
            "title",
            "subtitle",
            "og_title",
            "og_description",
            "tracking_campaign",
            "tracking_medium",
            "tracking_source",
            "ads_platform",
        ]
        .contains(&k.as_str())
        {
            if !v.is_null() && !v.as_str().is_some_and(|s| s.len() <= 2048) {
                return Err(AppError::BadRequest(format!("invalid {k}")));
            }
        } else if k == "image_url" || k == "og_image_url" {
            if let Some(url) = v.as_str().filter(|s| !s.is_empty()) {
                redirect_url(url)?;
            } else if !v.is_null() {
                return Err(AppError::BadRequest("image URL must be text".into()));
            }
        } else if k == "custom_redirects" {
            let values = v
                .as_object()
                .ok_or_else(|| AppError::BadRequest("custom_redirects must be an object".into()))?;
            for (p, r) in values {
                if !["ios", "android", "desktop", "web"].contains(&p.as_str()) {
                    return Err(AppError::BadRequest("invalid redirect platform".into()));
                }
                validate_redirect_settings(r)?;
            }
        } else if k == "tags"
            && !v.as_array().is_some_and(|a| {
                a.len() <= 100 && a.iter().all(|v| v.as_str().is_some_and(|s| s.len() <= 255))
            })
        {
            return Err(AppError::BadRequest(
                "tags must be at most 100 text entries".into(),
            ));
        }
    }
    Ok(())
}
async fn normalize_link(
    st: &AppState,
    project: Uuid,
    raw: Value,
    existing: Option<Value>,
) -> Result<LinkInput, AppError> {
    object(&raw)?;
    let core = [
        "name",
        "path",
        "target_url",
        "ios_url",
        "android_url",
        "campaign_id",
        "active",
    ];
    let rich = [
        "title",
        "subtitle",
        "image_url",
        "og_title",
        "og_description",
        "og_image_url",
        "data",
        "tags",
        "tracking_campaign",
        "tracking_medium",
        "tracking_source",
        "ads_platform",
        "custom_redirects",
        "show_preview",
        "show_preview_ios",
        "show_preview_android",
        "show_preview_desktop",
        "copy_to_clipboard_ios",
        "copy_to_clipboard_android",
        "copy_to_clipboard_desktop",
        "disable_ios",
        "disable_android",
        "disable_desktop",
    ];
    let mut result = json!({"active":true,"name":"Link","path":Uuid::new_v4().simple().to_string(),"ios_url":null,"android_url":null,"campaign_id":null,"metadata":{}});
    if let Some(existing) = existing {
        for k in core.into_iter().chain(["metadata"]) {
            if k == "active" {
                result[k] = json!(existing["archived_at"].is_null());
            } else {
                result[k] = existing[k].clone();
            }
        }
    }
    if result.get("target_url").is_none() {
        let configured=sqlx::query_scalar::<_,Option<String>>("SELECT coalesce(redirect->>'default_fallback',web->>'fallback_url') FROM project_configurations WHERE project_id=$1").bind(project).fetch_optional(&st.pg).await?.flatten();
        result["target_url"] =
            json!(configured.unwrap_or_else(|| format!("https://{}", st.config.server_host)));
    }
    for (k, v) in raw.as_object().unwrap() {
        if core.contains(&k.as_str()) {
            result[k] = v.clone();
        } else if k == "metadata" {
            object(v)?;
            for (k, v) in v.as_object().unwrap() {
                result["metadata"][k] = v.clone();
            }
        } else if rich.contains(&k.as_str()) {
            if k == "tags" && v.is_string() {
                result["metadata"][k] = json!(
                    v.as_str()
                        .unwrap()
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                );
            } else {
                result["metadata"][k] = v.clone();
            }
        } else {
            return Err(AppError::BadRequest(format!("unsupported link field: {k}")));
        }
    }
    serde_json::from_value(result).map_err(|_| AppError::BadRequest("invalid link fields".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_inputs() {
        assert_eq!(email(" Owner@EXAMPLE.com ").unwrap(), "owner@example.com");
        for invalid in ["bad", "x@y", "x@@example.com", "x y@example.com"] {
            assert!(email(invalid).is_err());
        }
        assert!(name("  ").is_err());
        assert!(object(&json!([])).is_err());
        assert!(domain("tenant.example.com").is_ok());
        assert!(domain("https://example.com").is_err());
    }
    #[test]
    fn rejects_unsafe_redirects() {
        for value in [
            "javascript:alert(1)",
            "//example.com",
            "https://user:pass@example.com",
            "/relative",
        ] {
            assert!(redirect_url(value).is_err());
        }
        assert!(redirect_url("https://example.com/a?q=x").is_ok());
    }
    #[test]
    fn caps_pagination() {
        assert!(
            Pagination {
                limit: Some(1001),
                offset: None
            }
            .values()
            .is_err()
        );
        assert!(
            Pagination {
                limit: None,
                offset: Some(-1)
            }
            .values()
            .is_err()
        );
    }
}
