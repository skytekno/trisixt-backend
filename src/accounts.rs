//! Account lifecycle, rotating sessions, encrypted TOTP and durable email delivery.
use crate::{
    auth::{self, AuthUser, authorize_instance},
    error::AppError,
    state::AppState,
};
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, AeadCore, OsRng, Payload},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    transport::smtp::authentication::Credentials as SmtpCredentials,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha1::Sha1;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;
type Api = Result<Json<Value>, AppError>;

pub fn encrypt_secret(context: &str, plaintext: &[u8]) -> Result<String, AppError> {
    let key = std::env::var("TRISIXT_ENCRYPTION_KEY").map_err(|_| {
        AppError::Config("TRISIXT_ENCRYPTION_KEY is required for account secrets and mail".into())
    })?;
    crypt_encrypt(
        &STANDARD
            .decode(key)
            .map_err(|_| AppError::Config("invalid encryption key".into()))?,
        context,
        plaintext,
    )
}
pub fn decrypt_secret(context: &str, ciphertext: &str) -> Result<Vec<u8>, AppError> {
    let key = std::env::var("TRISIXT_ENCRYPTION_KEY")
        .map_err(|_| AppError::Config("TRISIXT_ENCRYPTION_KEY is required".into()))?;
    crypt_decrypt(
        &STANDARD
            .decode(key)
            .map_err(|_| AppError::Config("invalid encryption key".into()))?,
        context,
        ciphertext,
    )
}
fn crypt_encrypt(key: &[u8], context: &str, plaintext: &[u8]) -> Result<String, AppError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| AppError::Config("encryption key must decode to 32 bytes".into()))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let sealed = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: context.as_bytes(),
            },
        )
        .map_err(|_| AppError::Internal)?;
    Ok(STANDARD.encode([nonce.as_slice(), sealed.as_slice()].concat()))
}
fn crypt_decrypt(key: &[u8], context: &str, ciphertext: &str) -> Result<Vec<u8>, AppError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| AppError::Config("encryption key must decode to 32 bytes".into()))?;
    let bytes = STANDARD
        .decode(ciphertext)
        .map_err(|_| AppError::Internal)?;
    if bytes.len() < 28 {
        return Err(AppError::Internal);
    }
    cipher
        .decrypt(
            aes_gcm::Nonce::from_slice(&bytes[..12]),
            Payload {
                msg: &bytes[12..],
                aad: context.as_bytes(),
            },
        )
        .map_err(|_| AppError::Internal)
}
fn email(s: &str) -> Result<String, AppError> {
    let s = s.trim().to_lowercase();
    if s.len() > 254 || s.parse::<lettre::Address>().is_err() {
        return Err(AppError::BadRequest("valid email required".into()));
    }
    Ok(s)
}
fn password(s: &str) -> Result<(), AppError> {
    if !(12..=1024).contains(&s.len()) {
        return Err(AppError::BadRequest(
            "password must have 12 to 1024 bytes".into(),
        ));
    }
    Ok(())
}
fn name(s: &str) -> Result<(), AppError> {
    if s.chars().count() > 200 {
        return Err(AppError::BadRequest(
            "name must have at most 200 characters".into(),
        ));
    }
    Ok(())
}
pub async fn rate_limit(st: &AppState, key: &str, limit: i32) -> Result<(), AppError> {
    let count=sqlx::query_scalar::<_,i32>("INSERT INTO auth_attempts(email_hash) VALUES($1) ON CONFLICT(email_hash) DO UPDATE SET attempts=CASE WHEN auth_attempts.window_start<now()-interval '15 minutes' THEN 1 ELSE auth_attempts.attempts+1 END,window_start=CASE WHEN auth_attempts.window_start<now()-interval '15 minutes' THEN now() ELSE auth_attempts.window_start END RETURNING attempts").bind(auth::token_hash(key)).fetch_one(&st.pg).await?;
    if count > limit {
        return Err(AppError::TooManyRequests);
    }
    Ok(())
}
async fn actor_tx(st: &AppState, user: Uuid) -> Result<Transaction<'static, Postgres>, AppError> {
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT set_config('trisixt.actor_id',$1,true)")
        .bind(user.to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}
async fn audit(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    action: &str,
) -> Result<(), AppError> {
    sqlx::query("SELECT trisixt_audit(instance_id,$1,$2,$1,'{}') FROM instance_roles WHERE user_id=$1 ORDER BY instance_id").bind(user).bind(action).execute(&mut **tx).await?;
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    email: String,
    password: String,
    #[serde(default)]
    name: String,
    #[serde(default, alias = "otp_attempt")]
    otp_code: Option<String>,
}
async fn register(
    State(st): State<AppState>,
    Json(body): Json<Credentials>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let email = email(&body.email)?;
    if !crate::enterprise_admin::password_email_allowed(&st, &email).await? {
        return Err(AppError::Forbidden);
    }
    password(&body.password)?;
    name(&body.name)?;
    rate_limit(&st, &format!("login:{email}"), 10).await?;
    if std::env::var("DISABLE_REGISTRATION").is_ok_and(|s| s == "true") {
        return Err(AppError::Forbidden);
    }
    let hash = auth::hash_password_async(body.password).await?;
    let mut tx = st.pg.begin().await?;
    lock_password_email_policy(&mut tx, &email, st.config.ee_enabled).await?;
    let id=sqlx::query_scalar::<_,Uuid>("INSERT INTO users(email,password_hash,name) VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING id").bind(&email).bind(hash).bind(&body.name).fetch_optional(&mut *tx).await?.ok_or_else(||AppError::Conflict("account already exists".into()))?;
    if std::env::var("SMTP_HOST").is_ok() {
        enqueue_mail(
            &mut tx,
            &Mail {
                to: email.clone(),
                subject: "Welcome to Trisixt".into(),
                text: "Welcome to Trisixt. Your account is ready.".into(),
            },
            Some(&format!("welcome:{id}")),
        )
        .await?;
    }
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"id":id,"email":email,"name":body.name})),
    ))
}
/// Authentication always checks the password before disclosing MFA requirements.
pub async fn authenticate(
    st: &AppState,
    address: &str,
    password: String,
    otp: Option<String>,
) -> Result<Option<(Uuid, i64)>, AppError> {
    let address = email(address)?;
    if password.len() > 1024 {
        return Err(AppError::Unauthorized);
    }
    rate_limit(st, &format!("login:{address}"), 10).await?;
    let row=sqlx::query("SELECT id,password_hash,otp_enabled,invitation_pending,credential_version FROM users WHERE lower(email)=$1").bind(&address).fetch_optional(&st.pg).await?;
    let hash = row
        .as_ref()
        .and_then(|r| r.get::<Option<String>, _>("password_hash"));
    if !auth::verify_password_async(password, hash).await? {
        return Err(AppError::Unauthorized);
    }
    let row = row.ok_or(AppError::Unauthorized)?;
    let id: Uuid = row.get("id");
    if row.get::<bool, _>("invitation_pending")
        || !crate::enterprise_admin::password_allowed(st, id).await?
    {
        return Err(AppError::Unauthorized);
    }
    if sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM scim_users WHERE user_id=$1 AND NOT active)",
    )
    .bind(id)
    .fetch_one(&st.pg)
    .await?
    {
        return Err(AppError::Unauthorized);
    }
    if row.get::<bool, _>("otp_enabled") {
        let Some(code) = otp else { return Ok(None) };
        let mut tx = st.pg.begin().await?;
        consume_otp(&mut tx, id, &code, true).await?;
        tx.commit().await?;
    }
    Ok(Some((id, row.get("credential_version"))))
}
async fn login(State(st): State<AppState>, Json(body): Json<Credentials>) -> Api {
    match authenticate(&st, &body.email, body.password, body.otp_code).await? {
        Some((id, version)) => Ok(Json(issue_password_session(&st, id, Some(version)).await?)),
        None => Ok(Json(json!({"requires_otp":true}))),
    }
}
pub async fn issue_session(st: &AppState, user_id: Uuid) -> Result<Value, AppError> {
    issue_password_session(st, user_id, None).await
}
async fn lock_password_policy(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    enforce: bool,
) -> Result<(), AppError> {
    if !enforce {
        return Ok(());
    }
    let address = sqlx::query_scalar::<_, String>("SELECT email FROM users WHERE id=$1")
        .bind(user)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(AppError::Unauthorized)?;
    lock_password_email_policy(tx, &address, enforce).await
}
async fn lock_password_email_policy(
    tx: &mut Transaction<'_, Postgres>,
    address: &str,
    enforce: bool,
) -> Result<(), AppError> {
    if !enforce || crate::enterprise_admin::operator_email(address) {
        return Ok(());
    }
    let rows=sqlx::query("SELECT s.enabled,s.enforced,d.verified_at IS NOT NULL AS verified FROM instance_sso s JOIN instance_sso_domains d ON d.instance_id=s.instance_id WHERE d.domain=split_part(lower($1),'@',2) ORDER BY s.instance_id FOR SHARE OF s").bind(address).fetch_all(&mut **tx).await?;
    if rows.iter().any(|r| {
        r.get::<bool, _>("enabled") && r.get::<bool, _>("enforced") && r.get::<bool, _>("verified")
    }) {
        return Err(AppError::Unauthorized);
    }
    Ok(())
}
async fn issue_password_session(
    st: &AppState,
    user: Uuid,
    version: Option<i64>,
) -> Result<Value, AppError> {
    let mut tx = st.pg.begin().await?;
    lock_password_policy(&mut tx, user, st.config.ee_enabled).await?;
    let current = sqlx::query_scalar::<_, i64>(
        "SELECT credential_version FROM users WHERE id=$1 AND NOT invitation_pending FOR UPDATE",
    )
    .bind(user)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::Unauthorized)?;
    if version.is_some_and(|v| v != current) {
        return Err(AppError::Unauthorized);
    }
    let active =
        sqlx::query_scalar::<_, bool>("SELECT active FROM scim_users WHERE user_id=$1 FOR SHARE")
            .bind(user)
            .fetch_optional(&mut *tx)
            .await?;
    if active == Some(false) {
        return Err(AppError::Unauthorized);
    }
    let result = session_tx(&mut tx, user, Uuid::new_v4()).await?;
    audit(&mut tx, user, "user.login").await?;
    tx.commit().await?;
    Ok(result)
}
pub(crate) async fn session_tx(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    family: Uuid,
) -> Result<Value, AppError> {
    session_tx_method(tx, user, family, "password").await
}
pub(crate) async fn session_tx_oidc(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    family: Uuid,
) -> Result<Value, AppError> {
    session_tx_method(tx, user, family, "oidc").await
}
async fn session_tx_method(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    family: Uuid,
    method: &str,
) -> Result<Value, AppError> {
    let (access, access_hash) = auth::new_token();
    let (refresh, refresh_hash) = auth::new_token();
    let row=sqlx::query("INSERT INTO access_tokens(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '1 hour') RETURNING id,expires_at").bind(user).bind(access_hash).fetch_one(&mut **tx).await?;
    let expiry: DateTime<Utc> = row.get("expires_at");
    sqlx::query("INSERT INTO refresh_sessions(user_id,family_id,token_hash,access_token_id,auth_method) VALUES($1,$2,$3,$4,$5)").bind(user).bind(family).bind(refresh_hash).bind(row.get::<Uuid,_>("id")).bind(method).execute(&mut **tx).await?;
    Ok(
        json!({"token":access,"access_token":access,"refresh_token":refresh,"token_type":"Bearer","expires_in":3600,"expires_at":expiry}),
    )
}
#[derive(Deserialize)]
struct OAuthGrant {
    grant_type: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    refresh_token: String,
    #[serde(default)]
    otp_attempt: Option<String>,
}
async fn oauth_body<T: serde::de::DeserializeOwned>(
    request: axum::extract::Request,
) -> Result<T, AppError> {
    let form = request
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/x-www-form-urlencoded"));
    let bytes = axum::body::to_bytes(request.into_body(), 32_768)
        .await
        .map_err(|_| AppError::BadRequest("invalid OAuth body".into()))?;
    if form {
        let mut map = serde_json::Map::new();
        for (key, value) in url::form_urlencoded::parse(&bytes) {
            if map.insert(key.to_string(), json!(value)).is_some() {
                return Err(AppError::BadRequest("duplicate OAuth parameter".into()));
            }
        }
        serde_json::from_value(Value::Object(map))
            .map_err(|_| AppError::BadRequest("invalid OAuth parameters".into()))
    } else {
        serde_json::from_slice(&bytes)
            .map_err(|_| AppError::BadRequest("invalid OAuth parameters".into()))
    }
}
async fn oauth_token(State(st): State<AppState>, request: axum::extract::Request) -> Api {
    let body: OAuthGrant = oauth_body(request).await?;
    match body.grant_type.as_str() {
        "password" => match authenticate(&st, &body.username, body.password, body.otp_attempt)
            .await?
        {
            Some((id, version)) => Ok(Json(issue_password_session(&st, id, Some(version)).await?)),
            None => Ok(Json(json!({"requires_otp":true}))),
        },
        "refresh_token" => Ok(Json(rotate_refresh(&st, &body.refresh_token).await?)),
        _ => Err(AppError::BadRequest("unsupported_grant_type".into())),
    }
}
pub async fn rotate_refresh(st: &AppState, raw: &str) -> Result<Value, AppError> {
    if raw.len() != 64 {
        return Err(AppError::Unauthorized);
    }
    let mut tx = st.pg.begin().await?;
    let initial =
        sqlx::query("SELECT user_id,auth_method FROM refresh_sessions WHERE token_hash=$1")
            .bind(auth::token_hash(raw))
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(AppError::Unauthorized)?;
    if initial.get::<String, _>("auth_method") == "password" {
        lock_password_policy(&mut tx, initial.get("user_id"), st.config.ee_enabled).await?;
    }
    sqlx::query("SELECT id FROM users WHERE id=(SELECT user_id FROM refresh_sessions WHERE token_hash=$1) FOR UPDATE").bind(auth::token_hash(raw)).fetch_optional(&mut *tx).await?;
    let row=sqlx::query("SELECT id,user_id,family_id,access_token_id,auth_method,consumed_at,revoked_at,expires_at FROM refresh_sessions WHERE token_hash=$1 FOR UPDATE").bind(auth::token_hash(raw)).fetch_optional(&mut *tx).await?.ok_or(AppError::Unauthorized)?;
    let family: Uuid = row.get("family_id");
    let user: Uuid = row.get("user_id");
    let method: String = row.get("auth_method");
    if method == "password" && !crate::enterprise_admin::password_allowed(st, user).await? {
        return Err(AppError::Unauthorized);
    }
    if row.get::<Option<DateTime<Utc>>, _>("consumed_at").is_some()
        || row.get::<Option<DateTime<Utc>>, _>("revoked_at").is_some()
        || row.get::<DateTime<Utc>, _>("expires_at") <= Utc::now()
    {
        sqlx::query("DELETE FROM access_tokens WHERE id IN(SELECT access_token_id FROM refresh_sessions WHERE family_id=$1)").bind(family).execute(&mut *tx).await?;
        sqlx::query("UPDATE refresh_sessions SET revoked_at=now() WHERE family_id=$1")
            .bind(family)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Err(AppError::Unauthorized);
    }
    if sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM scim_users WHERE user_id=$1 AND NOT active)",
    )
    .bind(user)
    .fetch_one(&mut *tx)
    .await?
    {
        return Err(AppError::Unauthorized);
    }
    sqlx::query("UPDATE refresh_sessions SET consumed_at=now() WHERE id=$1")
        .bind(row.get::<Uuid, _>("id"))
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM access_tokens WHERE id=$1")
        .bind(row.get::<Option<Uuid>, _>("access_token_id"))
        .execute(&mut *tx)
        .await?;
    let result = session_tx_method(&mut tx, user, family, &method).await?;
    tx.commit().await?;
    Ok(result)
}
#[derive(Deserialize)]
struct Revoke {
    token: String,
}
async fn revoke(State(st): State<AppState>, request: axum::extract::Request) -> Api {
    let body: Revoke = oauth_body(request).await?;
    revoke_token(&st, &body.token).await?;
    Ok(Json(json!({})))
}
async fn revoke_token(st: &AppState, raw: &str) -> Result<(), AppError> {
    if raw.len() != 64 {
        return Ok(());
    }
    let mut tx = st.pg.begin().await?;
    let hash = auth::token_hash(raw);
    let user=sqlx::query_scalar::<_,Uuid>("SELECT user_id FROM refresh_sessions WHERE token_hash=$1 UNION SELECT user_id FROM access_tokens WHERE token_hash=$1 LIMIT 1").bind(&hash).fetch_optional(&mut *tx).await?;
    if let Some(user) = user {
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(user)
            .fetch_optional(&mut *tx)
            .await?;
        let families=sqlx::query_scalar::<_,Uuid>("SELECT family_id FROM refresh_sessions WHERE token_hash=$1 OR access_token_id IN(SELECT id FROM access_tokens WHERE token_hash=$1)").bind(&hash).fetch_all(&mut *tx).await?;
        sqlx::query("UPDATE refresh_sessions SET revoked_at=now() WHERE family_id=ANY($1)")
            .bind(&families)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM access_tokens WHERE token_hash=$1 OR id IN(SELECT access_token_id FROM refresh_sessions WHERE family_id=ANY($2))").bind(hash).bind(families).execute(&mut *tx).await?;
        audit(&mut tx, user, "user.logout").await?;
    }
    tx.commit().await?;
    Ok(())
}
async fn logout(
    State(st): State<AppState>,
    _user: AuthUser,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;
    revoke_token(&st, token).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn me(State(st): State<AppState>, user: AuthUser) -> Api {
    let row=sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('id',id,'email',email,'name',name,'otp_enabled',otp_enabled,'roles',(SELECT coalesce(jsonb_agg(jsonb_build_object('instance_id',instance_id,'role',role)),'[]') FROM instance_roles WHERE user_id=users.id)) FROM users WHERE id=$1").bind(user.id).fetch_one(&st.pg).await?;
    Ok(Json(row))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Edit {
    name: String,
}
async fn edit(State(st): State<AppState>, user: AuthUser, Json(body): Json<Edit>) -> Api {
    name(&body.name)?;
    sqlx::query("UPDATE users SET name=$2 WHERE id=$1")
        .bind(user.id)
        .bind(body.name.trim())
        .execute(&st.pg)
        .await?;
    me(State(st), user).await
}
async fn delete_account(
    State(st): State<AppState>,
    user: AuthUser,
) -> Result<StatusCode, AppError> {
    let mut tx = actor_tx(&st, user.id).await?;
    // Serialize deletions of administrators, so two concurrent removals cannot leave an orphan tenant.
    sqlx::query("SELECT id FROM instances WHERE id IN(SELECT instance_id FROM instance_roles WHERE user_id=$1) ORDER BY id FOR UPDATE").bind(user.id).fetch_all(&mut *tx).await?;
    audit(&mut tx, user.id, "user.deleted").await?;
    revoke_all(&mut tx, user.id).await?;
    sqlx::query("DELETE FROM instances i WHERE EXISTS(SELECT 1 FROM instance_roles r WHERE r.instance_id=i.id AND r.user_id=$1 AND r.role IN('owner','admin')) AND NOT EXISTS(SELECT 1 FROM instance_roles r WHERE r.instance_id=i.id AND r.user_id<>$1 AND r.role IN('owner','admin'))").bind(user.id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn sessions(State(st): State<AppState>, user: AuthUser) -> Api {
    let rows=sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('id',family_id,'created_at',min(created_at),'expires_at',max(expires_at)) FROM refresh_sessions WHERE user_id=$1 AND revoked_at IS NULL GROUP BY family_id ORDER BY min(created_at) DESC").bind(user.id).fetch_all(&st.pg).await?;
    Ok(Json(json!({"sessions":rows})))
}
async fn revoke_sessions(
    State(st): State<AppState>,
    user: AuthUser,
) -> Result<StatusCode, AppError> {
    let mut tx = st.pg.begin().await?;
    revoke_all(&mut tx, user.id).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
pub(crate) async fn revoke_all(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> Result<(), AppError> {
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user)
        .fetch_optional(&mut **tx)
        .await?;
    crate::mcp::revoke_user_tx(tx, user).await?;
    sqlx::query("UPDATE refresh_sessions SET revoked_at=now() WHERE user_id=$1")
        .bind(user)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM access_tokens WHERE user_id=$1")
        .bind(user)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Mail {
    pub to: String,
    pub subject: String,
    pub text: String,
}
/// Shared transactional mail primitive for quota, migration, export and membership jobs.
pub async fn enqueue_mail(
    tx: &mut Transaction<'_, Postgres>,
    mail: &Mail,
    dedup: Option<&str>,
) -> Result<Uuid, AppError> {
    if mail.to.parse::<lettre::Address>().is_err()
        || mail.subject.len() > 500
        || mail.text.len() > 1024 * 1024
    {
        return Err(AppError::BadRequest("invalid mail".into()));
    }
    let payload = encrypt_secret(
        "mail-outbox",
        &serde_json::to_vec(mail).map_err(|_| AppError::Internal)?,
    )?;
    let id=sqlx::query_scalar::<_,Uuid>("INSERT INTO mail_outbox(payload_encrypted,dedup_key) VALUES($1,$2) ON CONFLICT(dedup_key) DO UPDATE SET dedup_key=EXCLUDED.dedup_key RETURNING id").bind(payload).bind(dedup).fetch_one(&mut **tx).await?;
    Ok(id)
}
fn frontend_url(path: &str, token: &str) -> Result<String, AppError> {
    let origin =
        std::env::var("ACCOUNT_FRONTEND_URL").unwrap_or_else(|_| "https://app.trisixt.com".into());
    let mut url = url::Url::parse(&origin)
        .map_err(|_| AppError::Config("invalid ACCOUNT_FRONTEND_URL".into()))?;
    if !matches!(url.scheme(), "https" | "http") {
        return Err(AppError::Config("invalid account URL scheme".into()));
    }
    url.set_path(path);
    url.query_pairs_mut().append_pair("token", token);
    Ok(url.to_string())
}
#[derive(Deserialize)]
struct EmailBody {
    email: String,
}
async fn reset_request(State(st): State<AppState>, Json(body): Json<EmailBody>) -> Api {
    let address = email(&body.email)?;
    rate_limit(&st, &format!("reset:{address}"), 5).await?;
    // Validate delivery encryption uniformly before looking up the address.
    let _ = encrypt_secret("mail-outbox", b"configuration-check")?;
    let id = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM users WHERE email=$1 AND NOT invitation_pending",
    )
    .bind(&address)
    .fetch_optional(&st.pg)
    .await?;
    if let Some(id) = id {
        if !crate::enterprise_admin::password_allowed(&st, id).await? {
            return Ok(Json(json!({"message":"Email sent"})));
        }
        let mut tx = st.pg.begin().await?;
        let (raw, hash) = auth::new_token();
        sqlx::query("UPDATE account_tokens SET used_at=now() WHERE user_id=$1 AND purpose='reset' AND used_at IS NULL").bind(id).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO account_tokens(user_id,purpose,token_hash,expires_at) VALUES($1,'reset',$2,now()+interval '6 hours')").bind(id).bind(hash).execute(&mut *tx).await?;
        enqueue_mail(
            &mut tx,
            &Mail {
                to: address,
                subject: "Change password link for Trisixt".into(),
                text: format!(
                    "Reset your password: {}\nThis link expires in six hours.",
                    frontend_url("/reset-password", &raw)?
                ),
            },
            None,
        )
        .await?;
        audit(&mut tx, id, "user.password_reset_requested").await?;
        tx.commit().await?;
    }
    Ok(Json(json!({"message":"Email sent"})))
}
async fn confirmation_request(State(st): State<AppState>, Json(body): Json<EmailBody>) -> Api {
    let address = email(&body.email)?;
    rate_limit(&st, &format!("confirm:{address}"), 5).await?;
    let _ = encrypt_secret("mail-outbox", b"configuration-check")?;
    let id=sqlx::query_scalar::<_,Uuid>("SELECT id FROM users WHERE email=$1 AND email_confirmed_at IS NULL AND NOT invitation_pending").bind(&address).fetch_optional(&st.pg).await?;
    if let Some(id) = id {
        let mut tx = st.pg.begin().await?;
        let (raw, hash) = auth::new_token();
        sqlx::query("UPDATE account_tokens SET used_at=now() WHERE user_id=$1 AND purpose='confirm' AND used_at IS NULL").bind(id).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO account_tokens(user_id,purpose,token_hash,expires_at) VALUES($1,'confirm',$2,now()+interval '24 hours')").bind(id).bind(hash).execute(&mut *tx).await?;
        enqueue_mail(
            &mut tx,
            &Mail {
                to: address,
                subject: "Confirm your Trisixt email".into(),
                text: format!(
                    "Confirm your email: {}",
                    frontend_url("/confirm-email", &raw)?
                ),
            },
            None,
        )
        .await?;
        tx.commit().await?;
    }
    Ok(Json(json!({"message":"Email sent"})))
}
#[derive(Deserialize)]
struct Confirmation {
    token: String,
}
async fn confirm_email(State(st): State<AppState>, Json(body): Json<Confirmation>) -> Api {
    if body.token.len() != 64 {
        return Err(AppError::NotFound);
    }
    let mut tx = st.pg.begin().await?;
    let row = consume_token(&mut tx, &body.token, "confirm").await?;
    sqlx::query("UPDATE users SET email_confirmed_at=now() WHERE id=$1")
        .bind(row.get::<Uuid, _>("user_id"))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({"confirmed":true})))
}

#[derive(Deserialize)]
struct Reset {
    reset_token: String,
    new_password: String,
}
async fn reset_password(State(st): State<AppState>, Json(body): Json<Reset>) -> Api {
    password(&body.new_password)?;
    if body.reset_token.len() != 64 {
        return Err(AppError::NotFound);
    }
    rate_limit(
        &st,
        &format!("reset-token:{}", auth::token_hash(&body.reset_token)),
        10,
    )
    .await?;
    let hash = auth::hash_password_async(body.new_password).await?;
    let mut tx = st.pg.begin().await?;
    let id = account_token_user(&mut tx, &body.reset_token, "reset").await?;
    lock_password_policy(&mut tx, id, st.config.ee_enabled)
        .await
        .map_err(|e| {
            if matches!(e, AppError::Unauthorized) {
                AppError::Forbidden
            } else {
                e
            }
        })?;
    consume_token(&mut tx, &body.reset_token, "reset").await?;
    sqlx::query("UPDATE users SET password_hash=$2 WHERE id=$1")
        .bind(id)
        .bind(hash)
        .execute(&mut *tx)
        .await?;
    revoke_all(&mut tx, id).await?;
    audit(&mut tx, id, "user.password_changed").await?;
    tx.commit().await?;
    Ok(Json(json!({"message":"Password changed"})))
}
async fn account_token_user(
    tx: &mut Transaction<'_, Postgres>,
    token: &str,
    purpose: &str,
) -> Result<Uuid, AppError> {
    sqlx::query_scalar::<_,Uuid>("SELECT user_id FROM account_tokens WHERE token_hash=$1 AND purpose=$2 AND used_at IS NULL AND expires_at>now()")
        .bind(auth::token_hash(token)).bind(purpose).fetch_optional(&mut **tx).await?.ok_or(AppError::NotFound)
}
async fn consume_token(
    tx: &mut Transaction<'_, Postgres>,
    token: &str,
    purpose: &str,
) -> Result<sqlx::postgres::PgRow, AppError> {
    let user = account_token_user(tx, token, purpose).await?;
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(AppError::NotFound)?;
    sqlx::query("UPDATE account_tokens SET used_at=now() WHERE token_hash=$1 AND purpose=$2 AND used_at IS NULL AND expires_at>now() RETURNING user_id,instance_id,invited_role").bind(auth::token_hash(token)).bind(purpose).fetch_optional(&mut **tx).await?.ok_or(AppError::NotFound)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invitation {
    email: String,
    #[serde(default = "member_role")]
    role: String,
}
fn member_role() -> String {
    "member".into()
}
async fn invite(
    State(st): State<AppState>,
    user: AuthUser,
    Path(instance): Path<Uuid>,
    Json(body): Json<Invitation>,
) -> Api {
    Ok(Json(
        invite_member(&st, &user, instance, &body.email, &body.role).await?,
    ))
}
pub async fn invite_member(
    st: &AppState,
    user: &AuthUser,
    instance: Uuid,
    address: &str,
    invited_role: &str,
) -> Result<Value, AppError> {
    let body = Invitation {
        email: address.into(),
        role: invited_role.into(),
    };
    let role = authorize_instance(st, user, instance, true).await?;
    if !matches!(body.role.as_str(), "admin" | "member")
        || (body.role == "admin" && role != "owner")
    {
        return Err(AppError::Forbidden);
    }
    let address = email(&body.email)?;
    rate_limit(st, &format!("invite:{}", user.id), 30).await?;
    let mut tx = actor_tx(st, user.id).await?;
    let row=sqlx::query("INSERT INTO users(email,invitation_pending) VALUES($1,true) ON CONFLICT(email) DO UPDATE SET email=EXCLUDED.email RETURNING id,invitation_pending").bind(&address).fetch_one(&mut *tx).await?;
    let id: Uuid = row.get("id");
    let mut invitation_url = None;
    if !row.get::<bool, _>("invitation_pending") {
        sqlx::query("INSERT INTO instance_roles(user_id,instance_id,role) VALUES($1,$2,$3) ON CONFLICT(user_id,instance_id) DO NOTHING").bind(id).bind(instance).bind(&body.role).execute(&mut *tx).await?;
        enqueue_mail(
            &mut tx,
            &Mail {
                to: address,
                subject: "New project access - Trisixt".into(),
                text: "You have been granted access to a Trisixt instance. Sign in to view it."
                    .into(),
            },
            None,
        )
        .await?;
    } else {
        let (raw, hash) = auth::new_token();
        if crate::billing::self_hosted() {
            invitation_url = Some(frontend_url("/accept-invite", &raw)?);
        }
        sqlx::query("UPDATE account_tokens SET used_at=now() WHERE user_id=$1 AND instance_id=$2 AND purpose='invite'").bind(id).bind(instance).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO account_tokens(user_id,purpose,token_hash,instance_id,invited_role,expires_at) VALUES($1,'invite',$2,$3,$4,now()+interval '14 days')").bind(id).bind(hash).bind(instance).bind(&body.role).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO instance_roles(user_id,instance_id,role) VALUES($1,$2,$3) ON CONFLICT(user_id,instance_id) DO NOTHING").bind(id).bind(instance).bind(&body.role).execute(&mut *tx).await?;
        enqueue_mail(
            &mut tx,
            &Mail {
                to: address,
                subject: "You're invited to join Trisixt".into(),
                text: format!(
                    "Accept your invitation: {}",
                    frontend_url("/accept-invite", &raw)?
                ),
            },
            None,
        )
        .await?;
    }
    tx.commit().await?;
    let mut result = json!({"invited":true,"user_id":id,"role":body.role});
    if let Some(url) = invitation_url {
        result["invite_url"] = json!(url);
    }
    Ok(result)
}
#[derive(Deserialize)]
struct AcceptInvite {
    invitation_token: String,
    password: String,
    #[serde(default)]
    name: String,
}
async fn accept_invite(State(st): State<AppState>, Json(body): Json<AcceptInvite>) -> Api {
    password(&body.password)?;
    name(&body.name)?;
    if body.invitation_token.len() != 64 {
        return Err(AppError::NotFound);
    }
    let hash = auth::hash_password_async(body.password).await?;
    let mut tx = st.pg.begin().await?;
    let row = consume_token(&mut tx, &body.invitation_token, "invite").await?;
    let id: Uuid = row.get("user_id");
    let updated=sqlx::query("UPDATE users SET password_hash=$2,name=$3,invitation_pending=false,email_confirmed_at=now() WHERE id=$1 AND invitation_pending").bind(id).bind(hash).bind(body.name).execute(&mut *tx).await?.rows_affected();
    if updated != 1 {
        return Err(AppError::Conflict("invitation already accepted".into()));
    }
    // Accept all outstanding instance invitations addressed to this verified account.
    sqlx::query("INSERT INTO instance_roles(user_id,instance_id,role) SELECT user_id,instance_id,invited_role FROM account_tokens WHERE user_id=$1 AND purpose='invite' AND expires_at>now() AND (used_at IS NULL OR token_hash=$2) ON CONFLICT(user_id,instance_id) DO NOTHING").bind(id).bind(auth::token_hash(&body.invitation_token)).execute(&mut *tx).await?;
    sqlx::query("UPDATE account_tokens SET used_at=now() WHERE user_id=$1 AND purpose='invite'")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    audit(&mut tx, id, "user.invitation_accepted").await?;
    tx.commit().await?;
    Ok(Json(issue_session(&st, id).await?))
}

fn totp(secret: &[u8], counter: u64) -> String {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("HMAC accepts any key");
    mac.update(&counter.to_be_bytes());
    let bytes = mac.finalize().into_bytes();
    let offset = (bytes[19] & 15) as usize;
    let value = u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("HMAC truncation"),
    ) & 0x7fffffff;
    format!("{:06}", value % 1_000_000)
}
fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |n, (a, b)| n | (a ^ b)) == 0
}
async fn consume_otp(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    code: &str,
    recovery: bool,
) -> Result<(), AppError> {
    let row = sqlx::query(
        "SELECT otp_secret_encrypted,otp_last_counter FROM users WHERE id=$1 FOR UPDATE",
    )
    .bind(user)
    .fetch_one(&mut **tx)
    .await?;
    if recovery && code.len() == 32 {
        let used=sqlx::query("UPDATE otp_recovery_codes SET used_at=now() WHERE user_id=$1 AND code_hash=$2 AND used_at IS NULL").bind(user).bind(auth::token_hash(code)).execute(&mut **tx).await?.rows_affected();
        if used == 1 {
            return Ok(());
        }
    }
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AppError::Unauthorized);
    }
    let cipher = row
        .get::<Option<String>, _>("otp_secret_encrypted")
        .ok_or(AppError::Unauthorized)?;
    let secret = decrypt_secret(&format!("totp:{user}"), &cipher)?;
    let now = Utc::now().timestamp() / 30;
    let last = row.get::<Option<i64>, _>("otp_last_counter").unwrap_or(-1);
    for counter in [now, now - 1, now + 1] {
        if counter > last && constant_eq(totp(&secret, counter as u64).as_bytes(), code.as_bytes())
        {
            sqlx::query("UPDATE users SET otp_last_counter=$2 WHERE id=$1")
                .bind(user)
                .bind(counter)
                .execute(&mut **tx)
                .await?;
            return Ok(());
        }
    }
    Err(AppError::Unauthorized)
}
async fn otp_status(State(st): State<AppState>, user: AuthUser) -> Api {
    let enabled = sqlx::query_scalar::<_, bool>("SELECT otp_enabled FROM users WHERE id=$1")
        .bind(user.id)
        .fetch_one(&st.pg)
        .await?;
    Ok(Json(json!({"otp_enabled":enabled})))
}
async fn otp_qr(State(st): State<AppState>, user: AuthUser) -> Result<Response, AppError> {
    let mut tx = st.pg.begin().await?;
    let row =
        sqlx::query("SELECT otp_enabled,otp_secret_encrypted FROM users WHERE id=$1 FOR UPDATE")
            .bind(user.id)
            .fetch_one(&mut *tx)
            .await?;
    // An authenticated session alone must not reveal an enrolled second factor.
    if row.get::<bool, _>("otp_enabled") {
        return Err(AppError::Conflict(
            "two-factor authentication already enabled".into(),
        ));
    }
    let secret = if let Some(cipher) = row.get::<Option<String>, _>("otp_secret_encrypted") {
        decrypt_secret(&format!("totp:{}", user.id), &cipher)?
    } else {
        let bytes = [
            Uuid::new_v4().as_bytes().as_slice(),
            Uuid::new_v4().as_bytes().as_slice(),
        ]
        .concat();
        let cipher = encrypt_secret(&format!("totp:{}", user.id), &bytes)?;
        sqlx::query("UPDATE users SET otp_secret_encrypted=$2,otp_last_counter=NULL WHERE id=$1")
            .bind(user.id)
            .bind(cipher)
            .execute(&mut *tx)
            .await?;
        bytes
    };
    tx.commit().await?;
    let issuer = std::env::var("OTP_ISSUER").unwrap_or_else(|_| "Trisixt".into());
    let mut uri = url::Url::parse("otpauth://totp/").map_err(|_| AppError::Internal)?;
    uri.set_path(&format!("{issuer}:{}", user.email));
    uri.query_pairs_mut()
        .append_pair("secret", &data_encoding::BASE32_NOPAD.encode(&secret))
        .append_pair("issuer", &issuer)
        .append_pair("algorithm", "SHA1")
        .append_pair("digits", "6")
        .append_pair("period", "30");
    let svg = qrcode::QrCode::new(uri.as_str())
        .map_err(|_| AppError::Internal)?
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(256, 256)
        .build();
    Ok((
        [
            ("content-type", "image/svg+xml"),
            ("cache-control", "no-store"),
        ],
        svg,
    )
        .into_response())
}
#[derive(Deserialize)]
struct ToggleOtp {
    enable_2fa: bool,
    otp_code: String,
}
async fn toggle_otp(
    State(st): State<AppState>,
    user: AuthUser,
    Json(body): Json<ToggleOtp>,
) -> Api {
    rate_limit(&st, &format!("otp:{}", user.id), 10).await?;
    let mut tx = st.pg.begin().await?;
    consume_otp(&mut tx, user.id, &body.otp_code, true).await?;
    sqlx::query("UPDATE users SET otp_enabled=$2,otp_secret_encrypted=CASE WHEN $2 THEN otp_secret_encrypted ELSE NULL END,otp_last_counter=CASE WHEN $2 THEN otp_last_counter ELSE NULL END WHERE id=$1").bind(user.id).bind(body.enable_2fa).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM otp_recovery_codes WHERE user_id=$1")
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    let mut recovery = Vec::new();
    if body.enable_2fa {
        for _ in 0..10 {
            let code = Uuid::new_v4().simple().to_string();
            sqlx::query("INSERT INTO otp_recovery_codes(user_id,code_hash) VALUES($1,$2)")
                .bind(user.id)
                .bind(auth::token_hash(&code))
                .execute(&mut *tx)
                .await?;
            recovery.push(code)
        }
    }
    revoke_all(&mut tx, user.id).await?;
    audit(
        &mut tx,
        user.id,
        if body.enable_2fa {
            "user.mfa_enabled"
        } else {
            "user.mfa_disabled"
        },
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"otp_enabled":body.enable_2fa,"recovery_codes":recovery}),
    ))
}

#[derive(Clone)]
pub struct SmtpOptions {
    pub host: String,
    pub port: u16,
    pub from: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub plaintext_local: bool,
}
impl SmtpOptions {
    fn from_env() -> Result<Self, AppError> {
        let host = std::env::var("SMTP_HOST")
            .map_err(|_| AppError::Config("SMTP_HOST is required for mail delivery".into()))?;
        Ok(Self {
            host,
            port: std::env::var("SMTP_PORT")
                .unwrap_or_else(|_| "587".into())
                .parse()
                .map_err(|_| AppError::Config("invalid SMTP_PORT".into()))?,
            from: std::env::var("MAILER_FROM")
                .map_err(|_| AppError::Config("MAILER_FROM is required".into()))?,
            username: std::env::var("SMTP_USERNAME").ok(),
            password: std::env::var("SMTP_PASSWORD").ok(),
            plaintext_local: std::env::var("SMTP_PLAINTEXT_LOCAL").is_ok_and(|v| v == "true"),
        })
    }
}
pub async fn send_mail(
    options: &SmtpOptions,
    mail: &Mail,
    message_id: Uuid,
) -> Result<(), AppError> {
    let message = Message::builder()
        .from(
            options
                .from
                .parse()
                .map_err(|_| AppError::Config("invalid MAILER_FROM".into()))?,
        )
        .to(mail.to.parse().map_err(|_| AppError::Internal)?)
        .subject(&mail.subject)
        .message_id(Some(format!("<{message_id}@trisixt.local>")))
        .body(mail.text.clone())
        .map_err(|_| AppError::Internal)?;
    let mut builder = if options.plaintext_local {
        if !matches!(options.host.as_str(), "127.0.0.1" | "::1" | "localhost") {
            return Err(AppError::Config(
                "plaintext SMTP is only allowed on loopback".into(),
            ));
        }
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&options.host)
    } else if options.port == 465 {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&options.host)
            .map_err(|_| AppError::Config("invalid SMTP TLS configuration".into()))?
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&options.host)
            .map_err(|_| AppError::Config("invalid SMTP TLS configuration".into()))?
    };
    builder = builder
        .port(options.port)
        .timeout(Some(std::time::Duration::from_secs(20)));
    if let (Some(user), Some(password)) = (&options.username, &options.password) {
        builder = builder.credentials(SmtpCredentials::new(user.clone(), password.clone()));
    }
    builder
        .build()
        .send(message)
        .await
        .map_err(|_| AppError::Upstream)?;
    Ok(())
}
pub async fn dispatch_mail_once(st: &AppState) -> Result<usize, AppError> {
    let options = SmtpOptions::from_env()?;
    dispatch_mail_with(st, &options).await
}
pub async fn dispatch_mail_with(st: &AppState, options: &SmtpOptions) -> Result<usize, AppError> {
    let lease = Uuid::new_v4();
    let row=sqlx::query("UPDATE mail_outbox SET lease_id=$1,lease_until=now()+interval '60 seconds',attempts=attempts+1 WHERE id=(SELECT id FROM mail_outbox WHERE sent_at IS NULL AND available_at<=now() AND (lease_until IS NULL OR lease_until<now()) ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING id,payload_encrypted").bind(lease).fetch_optional(&st.pg).await?;
    let Some(row) = row else { return Ok(0) };
    let id: Uuid = row.get("id");
    let result = async {
        let mail: Mail = serde_json::from_slice(&decrypt_secret(
            "mail-outbox",
            row.get("payload_encrypted"),
        )?)
        .map_err(|_| AppError::Internal)?;
        send_mail(options, &mail, id).await
    }
    .await;
    match result {
        Ok(()) => {
            sqlx::query("UPDATE mail_outbox SET sent_at=now(),lease_id=NULL,lease_until=NULL,last_error=NULL WHERE id=$1 AND lease_id=$2").bind(id).bind(lease).execute(&st.pg).await?;
            Ok(1)
        }
        Err(error) => {
            sqlx::query("UPDATE mail_outbox SET available_at=now()+make_interval(secs=>least(3600,30*power(2,least(attempts,7)))::double precision),lease_id=NULL,lease_until=NULL,last_error='mail delivery failed' WHERE id=$1 AND lease_id=$2").bind(id).bind(lease).execute(&st.pg).await?;
            Err(error)
        }
    }
}

/// Snapshot billing/import alerts into encrypted durable mail without exposing recipient lists.
/// `delivered_at` advances only after every corresponding SMTP delivery succeeds.
pub async fn enqueue_alerts(st: &AppState) -> Result<usize, AppError> {
    let mut tx = st.pg.begin().await?;
    sqlx::query("UPDATE billing_alerts a SET delivered_at=now() WHERE a.delivered_at IS NULL AND EXISTS(SELECT 1 FROM mail_outbox m WHERE m.source_type='billing' AND m.source_ref=a.instance_id::text||':'||a.kind||':'||extract(epoch FROM a.created_at)::text) AND NOT EXISTS(SELECT 1 FROM mail_outbox m WHERE m.source_type='billing' AND m.source_ref=a.instance_id::text||':'||a.kind||':'||extract(epoch FROM a.created_at)::text AND m.sent_at IS NULL)").execute(&mut *tx).await?;
    sqlx::query("UPDATE migration_alerts a SET delivered_at=now() WHERE a.delivered_at IS NULL AND EXISTS(SELECT 1 FROM mail_outbox m WHERE m.source_type='migration' AND m.source_ref=a.id::text) AND NOT EXISTS(SELECT 1 FROM mail_outbox m WHERE m.source_type='migration' AND m.source_ref=a.id::text AND m.sent_at IS NULL)").execute(&mut *tx).await?;
    let rows=sqlx::query("SELECT a.instance_id,a.kind,a.quantity,a.limit_value,a.instance_id::text||':'||a.kind||':'||extract(epoch FROM a.created_at)::text AS ref FROM billing_alerts a WHERE a.delivered_at IS NULL AND NOT EXISTS(SELECT 1 FROM mail_outbox m WHERE m.source_type='billing' AND m.source_ref=a.instance_id::text||':'||a.kind||':'||extract(epoch FROM a.created_at)::text) ORDER BY a.created_at FOR UPDATE SKIP LOCKED LIMIT 10").fetch_all(&mut *tx).await?;
    let mut count = 0;
    for row in rows {
        let instance: Uuid = row.get("instance_id");
        let reference: String = row.get("ref");
        let addresses=sqlx::query_scalar::<_,String>("SELECT u.email FROM users u JOIN instance_roles r ON r.user_id=u.id WHERE r.instance_id=$1 AND r.role IN('owner','admin') ORDER BY u.id").bind(instance).fetch_all(&mut *tx).await?;
        for address in addresses {
            let kind: String = row.get("kind");
            let quantity: i64 = row.get("quantity");
            let limit: i64 = row.get("limit_value");
            let id=enqueue_mail(&mut tx,&Mail{to:address.clone(),subject:format!("Trisixt usage {kind}"),text:format!("Your instance {instance} has used {quantity} monthly active visitors against a limit of {limit}.")},Some(&format!("billing:{reference}:{}",auth::token_hash(&address)))).await?;
            sqlx::query("UPDATE mail_outbox SET source_type='billing',source_ref=$2 WHERE id=$1")
                .bind(id)
                .bind(&reference)
                .execute(&mut *tx)
                .await?;
            count += 1;
        }
    }
    let rows=sqlx::query("SELECT a.id,a.kind,a.payload,p.instance_id FROM migration_alerts a JOIN migration_sources s ON s.id=a.source_id JOIN projects p ON p.id=s.project_id WHERE a.delivered_at IS NULL AND NOT EXISTS(SELECT 1 FROM mail_outbox m WHERE m.source_type='migration' AND m.source_ref=a.id::text) ORDER BY a.created_at FOR UPDATE OF a SKIP LOCKED LIMIT 10").fetch_all(&mut *tx).await?;
    for row in rows {
        let reference = row.get::<Uuid, _>("id").to_string();
        let addresses=sqlx::query_scalar::<_,String>("SELECT u.email FROM users u JOIN instance_roles r ON r.user_id=u.id WHERE r.instance_id=$1 AND r.role IN('owner','admin') ORDER BY u.id").bind(row.get::<Uuid,_>("instance_id")).fetch_all(&mut *tx).await?;
        for address in addresses {
            let kind: String = row.get("kind");
            let payload: Value = row.get("payload");
            let id = enqueue_mail(
                &mut tx,
                &Mail {
                    to: address.clone(),
                    subject: format!("Trisixt migration {kind}"),
                    text: format!("Migration source needs attention: {payload}"),
                },
                Some(&format!(
                    "migration:{reference}:{}",
                    auth::token_hash(&address)
                )),
            )
            .await?;
            sqlx::query("UPDATE mail_outbox SET source_type='migration',source_ref=$2 WHERE id=$1")
                .bind(id)
                .bind(&reference)
                .execute(&mut *tx)
                .await?;
            count += 1;
        }
    }
    tx.commit().await?;
    Ok(count)
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
        .route("/oauth/token", post(oauth_token))
        .route("/oauth/revoke", post(revoke))
        .route("/api/v1/users", post(register))
        .route(
            "/api/v1/users/me",
            get(me).patch(edit).put(edit).delete(delete_account),
        )
        .route("/api/v1/users/reset_password", post(reset_request))
        .route("/api/v1/users/confirmation", post(confirmation_request))
        .route("/api/v1/users/confirm", post(confirm_email))
        .route("/api/v1/users/change_password", post(reset_password))
        .route("/api/v1/users/accept_invite", post(accept_invite))
        .route("/api/v1/instances/{id}/invitations", post(invite))
        .route("/api/v1/users/me/otp_status", get(otp_status))
        .route("/api/v1/users/otp_status", post(otp_status))
        .route("/api/v1/users/me/otp_qr", get(otp_qr))
        .route(
            "/api/v1/users/me/two_factor",
            axum::routing::put(toggle_otp),
        )
        .route(
            "/api/v1/users/me/sessions",
            get(sessions).delete(revoke_sessions),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_encryption_binds_context() {
        let key = [7u8; 32];
        let sealed = crypt_encrypt(&key, "one", b"secret").unwrap();
        assert_eq!(crypt_decrypt(&key, "one", &sealed).unwrap(), b"secret");
        assert!(crypt_decrypt(&key, "two", &sealed).is_err());
        assert!(crypt_decrypt(&[8u8; 32], "one", &sealed).is_err());
        assert!(!sealed.contains("secret"));
    }
    #[test]
    fn totp_rfc6238_vectors() {
        let key = b"12345678901234567890";
        for (seconds, six) in [
            (59, "287082"),
            (1111111109, "081804"),
            (1111111111, "050471"),
            (1234567890, "005924"),
            (2000000000, "279037"),
        ] {
            assert_eq!(totp(key, seconds / 30), six);
        }
    }
}
