//! Enterprise audit and SCIM provisioning, included in every build.
use crate::{
    auth::{AuthUser, authorize_instance, new_token, token_hash},
    error::AppError,
    state::AppState,
};
use axum::{
    Json, Router,
    extract::{FromRequestParts, Path, Query, State},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

pub fn require_enterprise(st: &AppState) -> Result<(), AppError> {
    if st.config.ee_enabled {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/instances/{id}/enterprise", get(features))
        .route("/api/v1/instances/{id}/audit-events", get(audit_events))
        .route("/api/v1/instances/{id}/audit-events/head", get(audit_head))
        .route(
            "/api/v1/instances/{id}/scim-token",
            post(rotate_scim_token).delete(revoke_scim_token),
        )
        .route("/scim/v2/ServiceProviderConfig", get(scim_config))
        .route("/scim/v2/Users", get(scim_list).post(scim_create))
        .route(
            "/scim/v2/Users/{id}",
            get(scim_show)
                .put(scim_replace)
                .patch(scim_patch)
                .delete(scim_delete),
        )
}
async fn features(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, AppError> {
    authorize_instance(&st, &user, id, false).await?;
    Ok(Json(
        json!({"enabled":st.config.ee_enabled,"audit_log":st.config.ee_enabled,"scim":st.config.ee_enabled}),
    ))
}
#[derive(Deserialize)]
struct AuditQuery {
    after: Option<i64>,
    limit: Option<i64>,
}
#[derive(Serialize, sqlx::FromRow)]
struct AuditEvent {
    instance_id: Uuid,
    sequence: i64,
    actor_id: Option<Uuid>,
    action: String,
    target_id: Option<Uuid>,
    details: Value,
    occurred_at: DateTime<Utc>,
    previous_hash: String,
    hash: String,
}
async fn audit_events(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Query(q): Query<AuditQuery>,
) -> Result<Json<Value>, AppError> {
    require_enterprise(&st)?;
    authorize_instance(&st, &user, id, true).await?;
    let events=sqlx::query_as::<_,AuditEvent>("SELECT * FROM audit_events WHERE instance_id=$1 AND sequence>$2 ORDER BY sequence LIMIT $3")
        .bind(id).bind(q.after.unwrap_or(0).max(0)).bind(q.limit.unwrap_or(100).clamp(1,1000)).fetch_all(&st.pg).await?;
    Ok(Json(
        json!({"next_after":events.last().map(|e|e.sequence),"events":events}),
    ))
}
async fn audit_head(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, AppError> {
    require_enterprise(&st)?;
    authorize_instance(&st, &user, id, true).await?;
    let row=sqlx::query_as::<_,(i64,String)>("SELECT sequence,hash FROM audit_events WHERE instance_id=$1 ORDER BY sequence DESC LIMIT 1").bind(id).fetch_optional(&st.pg).await?;
    Ok(Json(match row {
        Some((seq, hash)) => json!({"sequence":seq,"hash":hash}),
        None => json!({"sequence":0,"hash":null}),
    }))
}
async fn rotate_scim_token(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, AppError> {
    require_enterprise(&st)?;
    authorize_instance(&st, &user, id, true).await?;
    let (token, hash) = new_token();
    let mut tx = st.pg.begin().await?;
    sqlx::query("INSERT INTO scim_tokens(instance_id,token_hash) VALUES($1,$2) ON CONFLICT(instance_id) DO UPDATE SET token_hash=excluded.token_hash,created_at=now()")
        .bind(id).bind(hash).execute(&mut *tx).await?;
    sqlx::query("SELECT trisixt_audit($1,$2,'scim.token.rotated',NULL,'{}')")
        .bind(id)
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({"token":token})))
}
async fn revoke_scim_token(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    require_enterprise(&st)?;
    authorize_instance(&st, &user, id, true).await?;
    let mut tx = st.pg.begin().await?;
    sqlx::query("DELETE FROM scim_tokens WHERE instance_id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT trisixt_audit($1,$2,'scim.token.revoked',NULL,'{}')")
        .bind(id)
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
struct ScimTenant(Uuid);
impl FromRequestParts<AppState> for ScimTenant {
    type Rejection = ScimError;
    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, ScimError> {
        require_enterprise(st)?;
        let token = parts
            .headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .filter(|s| s.len() == 64)
            .ok_or(AppError::Unauthorized)?;
        let id = sqlx::query_scalar("SELECT instance_id FROM scim_tokens WHERE token_hash=$1")
            .bind(token_hash(token))
            .fetch_optional(&st.pg)
            .await
            .map_err(AppError::from)?
            .ok_or(AppError::Unauthorized)?;
        Ok(Self(id))
    }
}
struct ScimError(AppError);
impl From<AppError> for ScimError {
    fn from(e: AppError) -> Self {
        Self(e)
    }
}
impl From<sqlx::Error> for ScimError {
    fn from(e: sqlx::Error) -> Self {
        Self(AppError::Db(e))
    }
}
impl IntoResponse for ScimError {
    fn into_response(self) -> Response {
        let (status, detail) = match self.0 {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_owned()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "forbidden".to_owned()),
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found".to_owned()),
            AppError::BadRequest(s) => (StatusCode::BAD_REQUEST, s),
            AppError::Conflict(s) => (StatusCode::CONFLICT, s),
            e => {
                tracing::error!(error=%e,"SCIM request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal service error".into(),
                )
            }
        };
        scim_response(
            status,
            json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":status.as_u16().to_string(),"detail":detail}),
        )
    }
}
fn scim_response(status: StatusCode, body: Value) -> Response {
    (
        status,
        [("content-type", "application/scim+json")],
        Json(body),
    )
        .into_response()
}
async fn scim_config(_tenant: ScimTenant) -> Response {
    scim_response(
        StatusCode::OK,
        json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],"patch":{"supported":true},"bulk":{"supported":false,"maxOperations":0,"maxPayloadSize":0},"filter":{"supported":true,"maxResults":200},"changePassword":{"supported":false},"sort":{"supported":false},"etag":{"supported":false},"authenticationSchemes":[{"type":"oauthbearertoken","name":"Bearer token","description":"Instance-scoped provisioning token","primary":true}]}),
    )
}
#[derive(Deserialize)]
struct ScimListQuery {
    #[serde(rename = "startIndex")]
    start: Option<i64>,
    count: Option<i64>,
    filter: Option<String>,
}
#[derive(sqlx::FromRow)]
struct ScimUser {
    user_id: Uuid,
    email: String,
    external_id: Option<String>,
    display_name: String,
    active: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}
impl ScimUser {
    fn json(&self) -> Value {
        json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":self.user_id,"userName":self.email,"externalId":self.external_id,"displayName":self.display_name,"active":self.active,"emails":[{"value":self.email,"primary":true}],"meta":{"resourceType":"User","created":self.created_at,"lastModified":self.updated_at}})
    }
}
fn parse_filter(filter: Option<&str>) -> Result<Option<String>, AppError> {
    let Some(filter) = filter else {
        return Ok(None);
    };
    let value = filter
        .strip_prefix("userName eq ")
        .ok_or_else(|| AppError::BadRequest("only userName eq filters are supported".into()))?;
    let value: String =
        serde_json::from_str(value).map_err(|_| AppError::BadRequest("invalid filter".into()))?;
    Ok(Some(value.to_ascii_lowercase()))
}
async fn scim_list(
    State(st): State<AppState>,
    ScimTenant(tenant): ScimTenant,
    Query(q): Query<ScimListQuery>,
) -> Result<Response, ScimError> {
    let filter = parse_filter(q.filter.as_deref())?;
    let start = q.start.unwrap_or(1).max(1);
    let count = q.count.unwrap_or(100).clamp(0, 200);
    let total:i64=sqlx::query_scalar("SELECT count(*) FROM scim_users s JOIN users u ON u.id=s.user_id WHERE s.instance_id=$1 AND ($2::text IS NULL OR lower(u.email)=$2)").bind(tenant).bind(&filter).fetch_one(&st.pg).await?;
    let users=sqlx::query_as::<_,ScimUser>("SELECT s.user_id,u.email,s.external_id,s.display_name,s.active,s.created_at,s.updated_at FROM scim_users s JOIN users u ON u.id=s.user_id WHERE s.instance_id=$1 AND ($2::text IS NULL OR lower(u.email)=$2) ORDER BY s.created_at,s.user_id LIMIT $3 OFFSET $4").bind(tenant).bind(filter).bind(count).bind(start-1).fetch_all(&st.pg).await?;
    Ok(scim_response(
        StatusCode::OK,
        json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":total,"startIndex":start,"itemsPerPage":users.len(),"Resources":users.iter().map(ScimUser::json).collect::<Vec<_>>()}),
    ))
}
async fn scim_show(
    State(st): State<AppState>,
    ScimTenant(tenant): ScimTenant,
    Path(id): Path<Uuid>,
) -> Result<Response, ScimError> {
    let user = sqlx::query_as::<_, ScimUser>("SELECT s.user_id,u.email,s.external_id,s.display_name,s.active,s.created_at,s.updated_at FROM scim_users s JOIN users u ON u.id=s.user_id WHERE s.instance_id=$1 AND s.user_id=$2")
    .bind(tenant)
    .bind(id)
    .fetch_optional(&st.pg)
    .await?
    .ok_or(AppError::NotFound)?;
    Ok(scim_response(StatusCode::OK, user.json()))
}
#[derive(Deserialize)]
struct ScimInput {
    #[serde(rename = "userName")]
    user_name: String,
    #[serde(rename = "externalId")]
    external_id: Option<String>,
    #[serde(rename = "displayName", default)]
    display_name: String,
    #[serde(default = "default_true")]
    active: bool,
}
fn default_true() -> bool {
    true
}
fn validate_scim(input: &ScimInput) -> Result<(), AppError> {
    if input.user_name.len() > 254
        || !input.user_name.contains('@')
        || input.user_name.chars().any(char::is_whitespace)
        || input.display_name.len() > 200
        || input.external_id.as_ref().is_some_and(|s| s.len() > 256)
    {
        return Err(AppError::BadRequest("invalid SCIM user".into()));
    }
    Ok(())
}
async fn scim_create(
    State(st): State<AppState>,
    ScimTenant(tenant): ScimTenant,
    Json(input): Json<ScimInput>,
) -> Result<Response, ScimError> {
    validate_scim(&input)?;
    let email = input.user_name.to_ascii_lowercase();
    let mut tx = st.pg.begin().await?;
    let id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO users(email) VALUES($1) ON CONFLICT DO NOTHING RETURNING id",
    )
    .bind(email)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| {
        AppError::Conflict(
            "user already exists; existing accounts cannot be claimed through SCIM".into(),
        )
    })?;
    let insert=sqlx::query("INSERT INTO scim_users(instance_id,user_id,external_id,display_name,active) VALUES($1,$2,$3,$4,$5)").bind(tenant).bind(id).bind(input.external_id).bind(input.display_name).bind(input.active).execute(&mut *tx).await;
    if insert.as_ref().is_err_and(|e| {
        e.as_database_error()
            .is_some_and(|e| e.is_unique_violation())
    }) {
        return Err(AppError::Conflict("externalId already exists".into()).into());
    }
    insert?;
    if input.active {
        sqlx::query("INSERT INTO instance_roles(user_id,instance_id,role) VALUES($1,$2,'member')")
            .bind(id)
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("SELECT trisixt_audit($1,NULL,'scim.user.created',$2,'{}')")
        .bind(tenant)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let mut response = scim_show(State(st), ScimTenant(tenant), Path(id)).await?;
    *response.status_mut() = StatusCode::CREATED;
    Ok(response)
}
async fn update_scim(
    st: &AppState,
    tenant: Uuid,
    id: Uuid,
    input: Option<ScimInput>,
    active: Option<bool>,
) -> Result<(), AppError> {
    if let Some(ref input) = input {
        validate_scim(input)?;
    }
    let mut tx = st.pg.begin().await?;
    // Account/session operations acquire the user before SCIM and credential rows.
    // This also makes deactivation atomic with password and refresh issuance.
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AppError::NotFound)?;
    let existing = sqlx::query_scalar::<_, bool>(
        "SELECT active FROM scim_users WHERE instance_id=$1 AND user_id=$2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::NotFound)?;
    let wanted = active
        .or(input.as_ref().map(|i| i.active))
        .unwrap_or(existing);
    let role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM instance_roles WHERE instance_id=$1 AND user_id=$2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    if role.as_deref().is_some_and(|r| r != "member") {
        return Err(AppError::Forbidden);
    }
    if let Some(input) = input {
        let current = sqlx::query_scalar::<_, String>("SELECT email FROM users WHERE id=$1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
        if current != input.user_name.to_ascii_lowercase() {
            return Err(AppError::BadRequest("userName is immutable".into()));
        }
        sqlx::query("UPDATE scim_users SET external_id=$3,display_name=$4 WHERE instance_id=$1 AND user_id=$2").bind(tenant).bind(id).bind(input.external_id).bind(input.display_name).execute(&mut *tx).await?;
    }
    sqlx::query(
        "UPDATE scim_users SET active=$3,updated_at=now() WHERE instance_id=$1 AND user_id=$2",
    )
    .bind(tenant)
    .bind(id)
    .bind(wanted)
    .execute(&mut *tx)
    .await?;
    if wanted {
        sqlx::query("INSERT INTO instance_roles(instance_id,user_id,role) VALUES($1,$2,'member') ON CONFLICT DO NOTHING").bind(tenant).bind(id).execute(&mut *tx).await?;
    } else {
        sqlx::query("DELETE FROM instance_roles WHERE instance_id=$1 AND user_id=$2")
            .bind(tenant)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        crate::accounts::revoke_all(&mut tx, id).await?;
    }
    sqlx::query("SELECT trisixt_audit($1,NULL,'scim.user.updated',$2,$3)")
        .bind(tenant)
        .bind(id)
        .bind(json!({"active":wanted}))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}
async fn scim_replace(
    State(st): State<AppState>,
    ScimTenant(tenant): ScimTenant,
    Path(id): Path<Uuid>,
    Json(input): Json<ScimInput>,
) -> Result<Response, ScimError> {
    update_scim(&st, tenant, id, Some(input), None).await?;
    scim_show(State(st), ScimTenant(tenant), Path(id)).await
}
#[derive(Deserialize)]
struct PatchInput {
    #[serde(rename = "Operations")]
    operations: Vec<PatchOperation>,
}
#[derive(Deserialize)]
struct PatchOperation {
    op: String,
    path: Option<String>,
    value: Value,
}
fn patch_active(input: PatchInput) -> Result<bool, AppError> {
    if input.operations.is_empty() || input.operations.len() > 10 {
        return Err(AppError::BadRequest("invalid SCIM patch".into()));
    }
    let mut active = None;
    for op in input.operations {
        if !matches!(op.op.to_ascii_lowercase().as_str(), "replace" | "add") {
            return Err(AppError::BadRequest("unsupported SCIM operation".into()));
        }
        active = Some(
            match op.path.as_deref() {
                Some("active") => op.value.as_bool(),
                None => op.value.get("active").and_then(Value::as_bool),
                _ => None,
            }
            .ok_or_else(|| AppError::BadRequest("only active patches are supported".into()))?,
        );
    }
    active.ok_or_else(|| AppError::BadRequest("empty patch".into()))
}
async fn scim_patch(
    State(st): State<AppState>,
    ScimTenant(tenant): ScimTenant,
    Path(id): Path<Uuid>,
    Json(input): Json<PatchInput>,
) -> Result<Response, ScimError> {
    update_scim(&st, tenant, id, None, Some(patch_active(input)?)).await?;
    scim_show(State(st), ScimTenant(tenant), Path(id)).await
}
async fn scim_delete(
    State(st): State<AppState>,
    ScimTenant(tenant): ScimTenant,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ScimError> {
    update_scim(&st, tenant, id, None, Some(false)).await?;
    Ok(StatusCode::NO_CONTENT)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scim_filter_rejects_sql_and_unsupported_operators() {
        assert!(
            parse_filter(Some("userName eq \"a@example.com\""))
                .unwrap()
                .is_some()
        );
        assert!(parse_filter(Some("userName co \"a\"")).is_err());
        assert!(parse_filter(Some("userName eq ' OR true")).is_err());
    }
    #[test]
    fn scim_patch_cannot_promote_roles() {
        let input = serde_json::from_value(
            json!({"Operations":[{"op":"replace","path":"roles","value":["owner"]}]}),
        )
        .unwrap();
        assert!(patch_active(input).is_err());
        let input = serde_json::from_value(
            json!({"Operations":[{"op":"replace","value":{"active":false}}]}),
        )
        .unwrap();
        assert!(!patch_active(input).unwrap());
    }
}
