//! Enterprise domain ownership, enforcement and revocable SIEM credentials.
use crate::{
    auth::{self, AuthUser, authorize_instance},
    enterprise::require_enterprise,
    error::AppError,
    state::AppState,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;
type Api = Result<Json<Value>, AppError>;
fn bad(s: &str) -> AppError {
    AppError::BadRequest(s.into())
}
pub fn operator_email(email: &str) -> bool {
    std::env::var("SUPER_ADMIN_EMAILS")
        .unwrap_or_default()
        .split(',')
        .any(|s| !s.trim().is_empty() && s.trim().eq_ignore_ascii_case(email))
}
pub async fn password_email_allowed(st: &AppState, email: &str) -> Result<bool, AppError> {
    if !st.config.ee_enabled || operator_email(email) {
        return Ok(true);
    }
    let domain = email
        .rsplit_once('@')
        .map(|p| p.1.to_lowercase())
        .unwrap_or_default();
    Ok(!sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM instance_sso s JOIN instance_sso_domains d ON d.instance_id=s.instance_id WHERE s.enabled AND s.enforced AND d.verified_at IS NOT NULL AND d.domain=$1)").bind(domain).fetch_one(&st.pg).await?)
}
pub async fn password_allowed(st: &AppState, user: Uuid) -> Result<bool, AppError> {
    let email = sqlx::query_scalar::<_, String>("SELECT email FROM users WHERE id=$1")
        .bind(user)
        .fetch_one(&st.pg)
        .await?;
    password_email_allowed(st, &email).await
}
async fn policy(State(st): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Api {
    require_enterprise(&st)?;
    authorize_instance(&st, &user, id, true).await?;
    let config = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(s) FROM instance_sso s WHERE instance_id=$1",
    )
    .bind(id)
    .fetch_optional(&st.pg)
    .await?
    .ok_or(AppError::NotFound)?;
    let domains=sqlx::query_scalar::<_,Value>("SELECT to_jsonb(d)||jsonb_build_object('record_name','_trisixt-sso.'||domain,'record_value','trisixt-sso='||verification_token) FROM instance_sso_domains d WHERE instance_id=$1 ORDER BY domain").bind(id).fetch_all(&st.pg).await?;
    Ok(Json(json!({"sso_connection":config,"domains":domains})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    enforced: bool,
    #[serde(default)]
    jit_provision: bool,
    admin_claim_value: Option<String>,
    domains: Vec<String>,
}
async fn set_policy(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<Policy>,
) -> Api {
    require_enterprise(&st)?;
    authorize_instance(&st, &user, id, true).await?;
    if body.domains.len() > 50
        || body
            .admin_claim_value
            .as_ref()
            .is_some_and(|v| v.len() > 255)
    {
        return Err(bad("too many domains or invalid admin claim"));
    }
    let domains: Vec<String> = body
        .domains
        .iter()
        .map(|d| d.trim().to_ascii_lowercase())
        .collect();
    for domain in &domains {
        if domain.len() > 253
            || !domain.contains('.')
            || domain.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(bad("invalid email domain"));
        }
    }
    let mut tx = st.pg.begin().await?;
    let current =
        sqlx::query("SELECT enabled,enforced FROM instance_sso WHERE instance_id=$1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(AppError::NotFound)?;
    let verified=sqlx::query_scalar::<_,i64>("SELECT count(*) FROM instance_sso_domains WHERE instance_id=$1 AND domain=ANY($2) AND verified_at IS NOT NULL").bind(id).bind(&domains).fetch_one(&mut *tx).await?;
    if body.enforced && (!current.get::<bool, _>("enabled") || verified == 0) {
        return Err(bad("enable SSO and verify a domain before enforcement"));
    }
    sqlx::query("DELETE FROM instance_sso_domains WHERE instance_id=$1 AND NOT domain=ANY($2)")
        .bind(id)
        .bind(&domains)
        .execute(&mut *tx)
        .await?;
    for domain in domains {
        let (token, _) = auth::new_token();
        sqlx::query("INSERT INTO instance_sso_domains(instance_id,domain,verification_token) VALUES($1,$2,$3) ON CONFLICT(instance_id,domain) DO NOTHING").bind(id).bind(domain).bind(token).execute(&mut *tx).await?;
    }
    sqlx::query("UPDATE instance_sso SET enforced=$2,jit_provision=$3,admin_claim_value=$4,version=gen_random_uuid(),updated_at=now() WHERE instance_id=$1").bind(id).bind(body.enforced).bind(body.jit_provision).bind(body.admin_claim_value).execute(&mut *tx).await?;
    let mut revoked = 0;
    if body.enforced && !current.get::<bool, _>("enforced") {
        revoked = revoke_domain_sessions(&mut tx, id).await?;
    }
    sqlx::query("DELETE FROM oidc_transactions WHERE instance_id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT trisixt_audit($1,$2,'sso.policy.updated',NULL,$3)").bind(id).bind(user.id).bind(json!({"enforced":body.enforced,"jit_provision":body.jit_provision,"sessions_revoked":revoked})).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"enforced":body.enforced,"sessions_revoked":revoked}),
    ))
}
async fn revoke_domain_sessions(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance: Uuid,
) -> Result<u64, AppError> {
    let users=sqlx::query_as::<_,(Uuid,String)>("SELECT u.id,u.email FROM users u JOIN instance_sso_domains d ON d.domain=split_part(lower(u.email),'@',2) WHERE d.instance_id=$1 AND d.verified_at IS NOT NULL ORDER BY u.id").bind(instance).fetch_all(&mut **tx).await?;
    let mut count = 0;
    for (user, email) in users {
        if operator_email(&email) {
            continue;
        }
        crate::accounts::revoke_all(tx, user).await?;
        count += 1;
    }
    Ok(count)
}
/// Separate proof application allows deterministic DNS tests without trusting
/// caller-provided TXT records in an HTTP handler.
pub async fn verify_domain_records(
    st: &AppState,
    id: Uuid,
    records: &[String],
) -> Result<bool, AppError> {
    let mut tx = st.pg.begin().await?;
    let instance =
        sqlx::query_scalar::<_, Uuid>("SELECT instance_id FROM instance_sso_domains WHERE id=$1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(AppError::NotFound)?;
    let enforced = sqlx::query_scalar::<_, bool>(
        "SELECT enforced FROM instance_sso WHERE instance_id=$1 FOR UPDATE",
    )
    .bind(instance)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::NotFound)?;
    let row=sqlx::query("SELECT instance_id,verification_token FROM instance_sso_domains WHERE id=$1 AND instance_id=$2 FOR UPDATE").bind(id).bind(instance).fetch_optional(&mut *tx).await?.ok_or(AppError::NotFound)?;
    let expected = format!("trisixt-sso={}", row.get::<String, _>("verification_token"));
    if !records.contains(&expected) {
        return Ok(false);
    }
    let instance: Uuid = row.get("instance_id");
    sqlx::query("UPDATE instance_sso_domains SET verified_at=now() WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    if enforced {
        revoke_domain_sessions(&mut tx, instance).await?;
    }
    sqlx::query("SELECT trisixt_audit($1,NULL,'sso.domain.verified',$2,'{}')")
        .bind(instance)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}
async fn verify_domains(State(st): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Api {
    require_enterprise(&st)?;
    authorize_instance(&st, &user, id, true).await?;
    let rows=sqlx::query_as::<_,(Uuid,String)>("SELECT id,domain FROM instance_sso_domains WHERE instance_id=$1 AND verified_at IS NULL ORDER BY domain").bind(id).fetch_all(&st.pg).await?;
    let resolver = hickory_resolver::Resolver::builder_tokio()
        .map_err(|_| AppError::Upstream)?
        .build()
        .map_err(|_| AppError::Upstream)?;
    let mut results = Vec::new();
    for (domain_id, domain) in rows {
        let records = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            resolver.txt_lookup(format!("_trisixt-sso.{domain}.")),
        )
        .await
        {
            Ok(Ok(records)) => records
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    hickory_resolver::proto::rr::RData::TXT(txt) => Some(txt),
                    _ => None,
                })
                .map(|txt| {
                    txt.txt_data
                        .iter()
                        .map(|b| String::from_utf8_lossy(b))
                        .collect::<String>()
                })
                .collect::<Vec<_>>(),
            _ => vec![],
        };
        let verified = verify_domain_records(&st, domain_id, &records).await?;
        results.push(json!({"domain":domain,"verified":verified}));
    }
    Ok(Json(json!({"domains":results})))
}
#[derive(Deserialize)]
struct Discovery {
    email: String,
}
async fn discover(State(st): State<AppState>, Query(q): Query<Discovery>) -> Api {
    if q.email.len() > 254 {
        return Err(bad("invalid email"));
    }
    let domain = q
        .email
        .rsplit_once('@')
        .map(|p| p.1.to_lowercase())
        .unwrap_or_default();
    let row = if st.config.ee_enabled {
        sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('connection_id',s.instance_id,'enforce',s.enforced,'start_url','/auth/oidc/'||s.instance_id||'/start') FROM instance_sso s JOIN instance_sso_domains d ON d.instance_id=s.instance_id WHERE s.enabled AND d.verified_at IS NOT NULL AND d.domain=$1").bind(domain).fetch_optional(&st.pg).await?
    } else {
        None
    };
    Ok(Json(row.unwrap_or(json!({"connection_id":null}))))
}
#[derive(Deserialize)]
struct TokenInput {
    name: String,
}
async fn tokens(State(st): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Api {
    require_enterprise(&st)?;
    authorize_instance(&st, &user, id, true).await?;
    let rows=sqlx::query_scalar::<_,Value>("SELECT to_jsonb(t)-'token_hash' FROM audit_export_tokens t WHERE instance_id=$1 AND revoked_at IS NULL ORDER BY created_at DESC").bind(id).fetch_all(&st.pg).await?;
    Ok(Json(json!({"audit_export_tokens":rows})))
}
async fn create_token(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<TokenInput>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    require_enterprise(&st)?;
    authorize_instance(&st, &user, id, true).await?;
    if body.name.trim().is_empty() || body.name.chars().count() > 255 {
        return Err(bad("name must have 1 to 255 characters"));
    }
    let (token, _) = auth::new_token();
    let token = format!("aet_{token}");
    let mut tx = st.pg.begin().await?;
    let row=sqlx::query_scalar::<_,Value>("INSERT INTO audit_export_tokens(instance_id,created_by,name,token_hash) VALUES($1,$2,$3,$4) RETURNING to_jsonb(audit_export_tokens)-'token_hash'").bind(id).bind(user.id).bind(body.name.trim()).bind(auth::token_hash(&token)).fetch_one(&mut *tx).await?;
    sqlx::query("SELECT trisixt_audit($1,$2,'audit_export_token.created',$3,'{}')")
        .bind(id)
        .bind(user.id)
        .bind(row["id"].as_str().unwrap().parse::<Uuid>().unwrap())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"audit_export_token":row,"token":token})),
    ))
}
async fn revoke_token(
    State(st): State<AppState>,
    user: AuthUser,
    Path((id, token)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    require_enterprise(&st)?;
    authorize_instance(&st, &user, id, true).await?;
    let mut tx = st.pg.begin().await?;
    if sqlx::query("UPDATE audit_export_tokens SET revoked_at=now() WHERE instance_id=$1 AND id=$2 AND revoked_at IS NULL").bind(id).bind(token).execute(&mut *tx).await?.rows_affected()==0{return Err(AppError::NotFound);}
    sqlx::query("SELECT trisixt_audit($1,$2,'audit_export_token.revoked',$3,'{}')")
        .bind(id)
        .bind(user.id)
        .bind(token)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Default, Deserialize)]
struct AuditQuery {
    after: Option<i64>,
    before: Option<i64>,
    limit: Option<i64>,
    order: Option<String>,
    event_action: Option<String>,
    actor_email: Option<String>,
    from: Option<chrono::DateTime<chrono::Utc>>,
    to: Option<chrono::DateTime<chrono::Utc>>,
}
async fn reader(st: &AppState, id: Uuid, headers: &HeaderMap) -> Result<(), AppError> {
    require_enterprise(st)?;
    let raw = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;
    if raw.starts_with("aet_") {
        let instance=sqlx::query_scalar::<_,Uuid>("UPDATE audit_export_tokens SET last_used_at=now() WHERE token_hash=$1 AND revoked_at IS NULL RETURNING instance_id").bind(auth::token_hash(raw)).fetch_optional(&st.pg).await?.ok_or(AppError::Unauthorized)?;
        if id != instance {
            return Err(AppError::Forbidden);
        }
    } else {
        let user=sqlx::query_as::<_,AuthUser>("SELECT u.id,u.email FROM users u JOIN access_tokens t ON t.user_id=u.id WHERE t.token_hash=$1 AND t.expires_at>now()").bind(auth::token_hash(raw)).fetch_optional(&st.pg).await?.ok_or(AppError::Unauthorized)?;
        authorize_instance(st, &user, id, true).await?;
    }
    Ok(())
}
async fn audit_events(
    State(st): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Query(q): Query<AuditQuery>,
) -> Api {
    reader(&st, id, &headers).await?;
    let order = match q.order.as_deref().unwrap_or("asc") {
        "asc" => "ASC",
        "desc" => "DESC",
        _ => return Err(bad("order must be asc or desc")),
    };
    let limit = q.limit.unwrap_or(100);
    if !(1..=1000).contains(&limit) {
        return Err(bad("limit must be 1 to 1000"));
    }
    let sql = format!(
        "SELECT to_jsonb(e) FROM audit_events e LEFT JOIN users u ON u.id=e.actor_id WHERE e.instance_id=$1 AND ($2::bigint IS NULL OR e.sequence>$2) AND ($3::bigint IS NULL OR e.sequence<$3) AND ($4::text IS NULL OR e.action=$4) AND ($5::text IS NULL OR u.email=$5) AND ($6::timestamptz IS NULL OR e.occurred_at>=$6) AND ($7::timestamptz IS NULL OR e.occurred_at<=$7) ORDER BY e.sequence {order} LIMIT $8"
    );
    let rows = sqlx::query_scalar::<_, Value>(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .bind(q.after)
        .bind(q.before)
        .bind(q.event_action)
        .bind(q.actor_email)
        .bind(q.from)
        .bind(q.to)
        .bind(limit)
        .fetch_all(&st.pg)
        .await?;
    let sequences: Vec<_> = rows.iter().filter_map(|r| r["sequence"].as_i64()).collect();
    Ok(Json(
        json!({"schema_version":1,"events":rows,"next_after":sequences.iter().max(),"next_before":sequences.iter().min()}),
    ))
}
async fn head(State(st): State<AppState>, Path(id): Path<Uuid>, headers: HeaderMap) -> Api {
    reader(&st, id, &headers).await?;
    let row=sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('sequence',sequence,'hash',hash,'schema_version',1) FROM audit_events WHERE instance_id=$1 ORDER BY sequence DESC LIMIT 1").bind(id).fetch_optional(&st.pg).await?;
    Ok(Json(row.unwrap_or(
        json!({"sequence":0,"hash":null,"schema_version":1}),
    )))
}
pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/instances/{id}/sso/policy",
            get(policy).put(set_policy),
        )
        .route(
            "/api/v1/instances/{id}/sso/verify-domains",
            post(verify_domains),
        )
        .route("/api/v1/identity/sso/discover", get(discover))
        .route(
            "/api/v1/instances/{id}/audit_export_tokens",
            get(tokens).post(create_token),
        )
        .route(
            "/api/v1/instances/{id}/audit_export_tokens/{token}",
            axum::routing::delete(revoke_token),
        )
        .route("/api/v1/instances/{id}/audit_events", get(audit_events))
        .route("/api/v1/instances/{id}/audit_events/head", get(head))
}

/// JIT requires both an authenticated IdP and verified ownership of its email
/// domain. An existing account in another organisation is never claimed by JIT.
pub async fn provision_identity(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance: Uuid,
    identity: &crate::oidc::VerifiedIdentity,
) -> Result<Uuid, AppError> {
    if operator_email(&identity.email) {
        return Err(AppError::Forbidden);
    }
    let domain = identity
        .email
        .rsplit_once('@')
        .map(|v| v.1)
        .ok_or(AppError::Unauthorized)?;
    let policy=sqlx::query("SELECT s.jit_provision,s.admin_claim_value FROM instance_sso s JOIN instance_sso_domains d ON d.instance_id=s.instance_id WHERE s.instance_id=$1 AND s.enabled AND d.domain=$2 AND d.verified_at IS NOT NULL FOR SHARE OF s,d").bind(instance).bind(domain).fetch_optional(&mut **tx).await?.ok_or(AppError::Unauthorized)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,44))")
        .bind(&identity.email)
        .execute(&mut **tx)
        .await?;
    let existing =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE lower(email)=$1 FOR UPDATE")
            .bind(&identity.email)
            .fetch_optional(&mut **tx)
            .await?;
    let user = if let Some(user) = existing {
        let other=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM instance_roles WHERE user_id=$1 AND instance_id<>$2) OR EXISTS(SELECT 1 FROM oidc_identities WHERE user_id=$1 AND (issuer<>$3 OR subject<>$4))").bind(user).bind(instance).bind(&identity.issuer).bind(&identity.subject).fetch_one(&mut **tx).await?;
        let managed=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM instance_roles WHERE user_id=$1 AND instance_id=$2) OR EXISTS(SELECT 1 FROM scim_users WHERE user_id=$1 AND instance_id=$2)").bind(user).bind(instance).fetch_one(&mut **tx).await?;
        if other || !managed {
            return Err(AppError::Forbidden);
        }
        user
    } else {
        if !policy.get::<bool, _>("jit_provision") {
            return Err(AppError::Unauthorized);
        }
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO users(email,name,email_confirmed_at) VALUES($1,$2,now()) RETURNING id",
        )
        .bind(&identity.email)
        .bind(identity.name.as_deref().unwrap_or(&identity.email))
        .fetch_one(&mut **tx)
        .await?
    };
    let active = sqlx::query_scalar::<_, bool>(
        "SELECT active FROM scim_users WHERE instance_id=$1 AND user_id=$2 FOR SHARE",
    )
    .bind(instance)
    .bind(user)
    .fetch_optional(&mut **tx)
    .await?;
    if active == Some(false) {
        return Err(AppError::Forbidden);
    }
    let admin = policy
        .get::<Option<String>, _>("admin_claim_value")
        .is_some_and(|v| !v.is_empty() && identity.groups.contains(&v));
    sqlx::query("INSERT INTO instance_roles(instance_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT(instance_id,user_id) DO UPDATE SET role=CASE WHEN instance_roles.role='owner' THEN 'owner' WHEN excluded.role='admin' THEN 'admin' ELSE instance_roles.role END").bind(instance).bind(user).bind(if admin{"admin"}else{"member"}).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO oidc_identities(issuer,subject,user_id) VALUES($1,$2,$3)")
        .bind(&identity.issuer)
        .bind(&identity.subject)
        .bind(user)
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE users SET invitation_pending=false,email_confirmed_at=coalesce(email_confirmed_at,now()) WHERE id=$1").bind(user).execute(&mut **tx).await?;
    Ok(user)
}

/// Called with configuration and user locks held by the OIDC callback. Applies
/// current domain ownership and IdP administrator claims on every login.
pub async fn apply_identity_policy(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance: Uuid,
    user: Uuid,
    identity: &crate::oidc::VerifiedIdentity,
) -> Result<(), AppError> {
    let email = sqlx::query_scalar::<_, String>("SELECT email FROM users WHERE id=$1")
        .bind(user)
        .fetch_one(&mut **tx)
        .await?;
    if operator_email(&email) || operator_email(&identity.email) {
        return Err(AppError::Forbidden);
    }
    let policy=sqlx::query("SELECT s.admin_claim_value,EXISTS(SELECT 1 FROM instance_sso_domains d WHERE d.instance_id=s.instance_id) has_domains,EXISTS(SELECT 1 FROM instance_sso_domains d WHERE d.instance_id=s.instance_id AND d.verified_at IS NOT NULL AND d.domain=split_part($2,'@',2)) allowed_domain FROM instance_sso s WHERE instance_id=$1 AND enabled FOR SHARE OF s").bind(instance).bind(&identity.email).fetch_optional(&mut **tx).await?.ok_or(AppError::Unauthorized)?;
    if policy.get::<bool, _>("has_domains") && !policy.get::<bool, _>("allowed_domain") {
        return Err(AppError::Forbidden);
    }
    if policy
        .get::<Option<String>, _>("admin_claim_value")
        .is_some_and(|v| !v.is_empty() && identity.groups.contains(&v))
    {
        sqlx::query("UPDATE instance_roles SET role='admin' WHERE instance_id=$1 AND user_id=$2 AND role='member'").bind(instance).bind(user).execute(&mut **tx).await?;
    }
    Ok(())
}
