//! Scheduled in-app marketing notifications and durable authenticated FCM/APNs delivery.
use crate::{
    auth::{AuthUser, SdkProject, authorize_project},
    error::AppError,
    state::AppState,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use gcp_auth::TokenProvider;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use std::{collections::HashMap, time::Duration};
use uuid::Uuid;
type Api = Result<Json<Value>, AppError>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateNotification {
    title: String,
    #[serde(default)]
    subtitle: String,
    #[serde(default)]
    html: String,
    #[serde(default)]
    auto_display: bool,
    #[serde(default)]
    send_push: bool,
    new_users: bool,
    existing_users: bool,
    #[serde(default)]
    platforms: Vec<String>,
    scheduled_at: Option<DateTime<Utc>>,
}
fn validate_notification(body: &CreateNotification) -> Result<(), AppError> {
    if body.title.trim().is_empty()
        || body.title.chars().count() > 250
        || body.subtitle.chars().count() > 1000
        || body.html.len() > 512 * 1024
    {
        return Err(AppError::BadRequest(
            "invalid notification content size".into(),
        ));
    }
    if body.new_users == body.existing_users {
        return Err(AppError::BadRequest(
            "select exactly one user segment".into(),
        ));
    }
    if body.platforms.iter().any(|p| {
        !matches!(
            p.as_str(),
            "ios" | "android" | "web" | "windows" | "mac" | "linux" | "other"
        )
    }) {
        return Err(AppError::BadRequest("invalid platform".into()));
    }
    Ok(())
}
async fn create(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Json(body): Json<CreateNotification>,
) -> Api {
    authorize_project(&st, &user, project, true).await?;
    validate_notification(&body)?;
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT set_config('trisixt.actor_id',$1,true)")
        .bind(user.id.to_string())
        .execute(&mut *tx)
        .await?;
    let row=sqlx::query_scalar::<_,Value>("INSERT INTO notifications(project_id,title,subtitle,html,auto_display,send_push,new_users,existing_users,platforms,scheduled_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,coalesce($10,now())) RETURNING to_jsonb(notifications)").bind(project).bind(body.title.trim()).bind(body.subtitle).bind(sanitize_html(&body.html)).bind(body.auto_display).bind(body.send_push).bind(body.new_users).bind(body.existing_users).bind(body.platforms).bind(body.scheduled_at).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"notification":decorate(row)})))
}
fn decorate(mut row: Value) -> Value {
    row["target"] = json!({"new_users":row["new_users"],"existing_users":row["existing_users"],"platforms":row["platforms"]});
    row["access_url"] = json!(format!("/mm/{}", row["id"].as_str().unwrap_or_default()));
    row
}
#[derive(Deserialize, Default)]
struct Search {
    #[serde(default)]
    archived: bool,
    for_new_users: Option<bool>,
    #[serde(default)]
    search_term: String,
    #[serde(default = "one")]
    page: i64,
    #[serde(default = "page_size")]
    per_page: i64,
}
fn one() -> i64 {
    1
}
fn page_size() -> i64 {
    25
}
async fn search_inner(st: &AppState, user: &AuthUser, project: Uuid, q: Search) -> Api {
    authorize_project(st, user, project, false).await?;
    let limit = q.per_page.clamp(1, 100);
    let offset = (q.page.clamp(1, 1_000_000) - 1) * limit;
    let rows=sqlx::query_scalar::<_,Value>("SELECT to_jsonb(n)||jsonb_build_object('read_count',(SELECT count(*) FROM notification_messages m WHERE m.notification_id=n.id AND m.read)) FROM notifications n WHERE n.project_id=$1 AND n.archived=$2 AND ($3::boolean IS NULL OR n.new_users=$3) AND (strpos(lower(n.title),lower($4))>0 OR strpos(lower(n.subtitle),lower($4))>0) ORDER BY n.updated_at DESC,n.id LIMIT $5 OFFSET $6").bind(project).bind(q.archived).bind(q.for_new_users).bind(&q.search_term).bind(limit).bind(offset).fetch_all(&st.pg).await?;
    let total=sqlx::query_scalar::<_,i64>("SELECT count(*) FROM notifications WHERE project_id=$1 AND archived=$2 AND ($3::boolean IS NULL OR new_users=$3) AND (strpos(lower(title),lower($4))>0 OR strpos(lower(subtitle),lower($4))>0)").bind(project).bind(q.archived).bind(q.for_new_users).bind(q.search_term).fetch_one(&st.pg).await?;
    Ok(Json(
        json!({"notifications":rows.into_iter().map(decorate).collect::<Vec<_>>(),"total":total,"page":q.page.max(1),"per_page":limit}),
    ))
}
async fn list(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Query(q): Query<Search>,
) -> Api {
    search_inner(&st, &user, project, q).await
}
async fn search(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Json(q): Json<Search>,
) -> Api {
    search_inner(&st, &user, project, q).await
}
async fn archive(
    State(st): State<AppState>,
    user: AuthUser,
    Path((project, id)): Path<(Uuid, Uuid)>,
) -> Api {
    authorize_project(&st, &user, project, true).await?;
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT set_config('trisixt.actor_id',$1,true)")
        .bind(user.id.to_string())
        .execute(&mut *tx)
        .await?;
    let row = sqlx::query(
        "SELECT existing_users FROM notifications WHERE id=$1 AND project_id=$2 FOR UPDATE",
    )
    .bind(id)
    .bind(project)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::NotFound)?;
    if row.get::<bool, _>("existing_users") {
        return Err(AppError::BadRequest(
            "existing-user notifications cannot be archived".into(),
        ));
    }
    let row=sqlx::query_scalar::<_,Value>("UPDATE notifications SET archived=true,updated_at=now() WHERE id=$1 RETURNING to_jsonb(notifications)").bind(id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"notifications":decorate(row)})))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct VisitorQuery {
    visitor_id: Option<Uuid>,
    #[serde(default = "one")]
    page: i64,
    #[serde(default)]
    platform: Option<String>,
    id: Option<Uuid>,
}
fn visitor_id(headers: &HeaderMap, q: &VisitorQuery) -> Result<Uuid, AppError> {
    q.visitor_id
        .or_else(|| {
            headers
                .get("x-visitor-id")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| Uuid::parse_str(v).ok())
        })
        .filter(|v| !v.is_nil())
        .ok_or_else(|| AppError::BadRequest("visitor_id is required".into()))
}
async fn check_visitor(st: &AppState, project: Uuid, visitor: Uuid) -> Result<(), AppError> {
    if !sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM visitors WHERE project_id=$1 AND id=$2)",
    )
    .bind(project)
    .bind(visitor)
    .fetch_one(&st.pg)
    .await?
    {
        return Err(AppError::NotFound);
    }
    Ok(())
}
async fn visitor_messages(
    st: &AppState,
    project: Uuid,
    visitor: Uuid,
    q: VisitorQuery,
    automatic: bool,
) -> Api {
    check_visitor(st, project, visitor).await?;
    // Reads also perform bounded fanout for this visitor, avoiding a worker-latency race after SDK registration.
    fanout_for_visitor(st, project, visitor).await?;
    let rows=sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('id',m.id,'read',m.read,'notification_id',n.id,'title',n.title,'subtitle',n.subtitle,'auto_display',n.auto_display,'updated_at',m.updated_at,'access_url','/mm/'||n.id::text) FROM notification_messages m JOIN notifications n ON n.id=m.notification_id WHERE m.project_id=$1 AND m.visitor_id=$2 AND NOT n.archived AND (NOT $3 OR (NOT m.read AND n.auto_display)) AND ($4::text IS NULL OR cardinality(n.platforms)=0 OR $4=ANY(n.platforms) OR ($4 IN('desktop','windows','mac','linux','other') AND 'web'=ANY(n.platforms))) ORDER BY m.created_at DESC,m.id LIMIT 100 OFFSET $5").bind(project).bind(visitor).bind(automatic).bind(q.platform).bind((q.page.clamp(1,1_000_000)-1)*100).fetch_all(&st.pg).await?;
    Ok(Json(json!({"notifications":rows})))
}
async fn sdk_list(
    State(st): State<AppState>,
    sdk: SdkProject,
    headers: HeaderMap,
    Query(mut q): Query<VisitorQuery>,
) -> Api {
    let project = sdk.id;
    sdk.check_platform(q.platform.as_deref())?;
    if q.platform.is_none() {
        q.platform = sdk.declared_platform().map(str::to_owned);
    }
    let visitor = visitor_id(&headers, &q)?;
    visitor_messages(&st, project, visitor, q, false).await
}
async fn sdk_list_post(
    State(st): State<AppState>,
    sdk: SdkProject,
    headers: HeaderMap,
    Json(mut q): Json<VisitorQuery>,
) -> Api {
    let project = sdk.id;
    sdk.check_platform(q.platform.as_deref())?;
    if q.platform.is_none() {
        q.platform = sdk.declared_platform().map(str::to_owned);
    }
    let visitor = visitor_id(&headers, &q)?;
    visitor_messages(&st, project, visitor, q, false).await
}
async fn automatic(
    State(st): State<AppState>,
    sdk: SdkProject,
    headers: HeaderMap,
    Query(mut q): Query<VisitorQuery>,
) -> Api {
    let project = sdk.id;
    sdk.check_platform(q.platform.as_deref())?;
    if q.platform.is_none() {
        q.platform = sdk.declared_platform().map(str::to_owned);
    }
    let visitor = visitor_id(&headers, &q)?;
    visitor_messages(&st, project, visitor, q, true).await
}
async fn unread(
    State(st): State<AppState>,
    sdk: SdkProject,
    headers: HeaderMap,
    Query(mut q): Query<VisitorQuery>,
) -> Api {
    let project = sdk.id;
    sdk.check_platform(q.platform.as_deref())?;
    if q.platform.is_none() {
        q.platform = sdk.declared_platform().map(str::to_owned);
    }
    let visitor = visitor_id(&headers, &q)?;
    check_visitor(&st, project, visitor).await?;
    fanout_for_visitor(&st, project, visitor).await?;
    let count=sqlx::query_scalar::<_,i64>("SELECT count(*) FROM notification_messages m JOIN notifications n ON n.id=m.notification_id WHERE m.project_id=$1 AND m.visitor_id=$2 AND NOT m.read AND NOT n.archived").bind(project).bind(visitor).fetch_one(&st.pg).await?;
    Ok(Json(json!({"number_of_unread_notifications":count})))
}
async fn read(
    State(st): State<AppState>,
    sdk: SdkProject,
    headers: HeaderMap,
    Json(mut q): Json<VisitorQuery>,
) -> Api {
    let project = sdk.id;
    sdk.check_platform(q.platform.as_deref())?;
    if q.platform.is_none() {
        q.platform = sdk.declared_platform().map(str::to_owned);
    }
    let visitor = visitor_id(&headers, &q)?;
    let id =
        q.id.ok_or_else(|| AppError::BadRequest("id is required".into()))?;
    let count=sqlx::query("UPDATE notification_messages SET read=true,updated_at=now() WHERE project_id=$1 AND visitor_id=$2 AND id=$3").bind(project).bind(visitor).bind(id).execute(&st.pg).await?.rows_affected();
    if count == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Json(json!({"message":"Marked as read"})))
}

/// Ammonia parses HTML rather than trying to remove script text with regular expressions.
pub fn sanitize_html(html: &str) -> String {
    let mut builder = ammonia::Builder::default();
    builder.add_tags(
        [
            "section",
            "header",
            "footer",
            "figure",
            "figcaption",
            "video",
            "source",
            "audio",
        ]
        .iter()
        .copied(),
    );
    builder.add_generic_attributes(["class", "id", "width", "height", "style"].iter().copied());
    builder.attribute_filter(|_, attr, value| {
        if attr == "style" {
            let normalized = value
                .chars()
                .filter(|c| !c.is_whitespace() && !c.is_control())
                .collect::<String>()
                .to_ascii_lowercase();
            if [
                "url(",
                "expression(",
                "-moz-binding",
                "behavior:",
                "@import",
                "javascript:",
                "\\",
            ]
            .iter()
            .any(|bad| normalized.contains(bad))
            {
                return None;
            }
        }
        Some(std::borrow::Cow::Borrowed(value))
    });
    builder.clean(html).to_string()
}
async fn public_message(
    State(st): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(':').next())
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_lowercase();
    let row=sqlx::query("SELECT n.title,n.html FROM notifications n JOIN projects p ON p.id=n.project_id WHERE n.id=$1 AND NOT n.archived AND n.scheduled_at<=now() AND (lower(p.domain)=$2 OR EXISTS(SELECT 1 FROM custom_hostnames h WHERE h.project_id=p.id AND lower(h.hostname)=$2 AND h.status='active'))").bind(id).bind(host).fetch_optional(&st.pg).await?.ok_or(AppError::NotFound)?;
    let body = sanitize_html(row.get("html"));
    Ok(([("content-security-policy","default-src 'none'; img-src https:; media-src https:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"),("x-content-type-options","nosniff")],Html(body)).into_response())
}

async fn fanout_for_visitor(st: &AppState, project: Uuid, visitor: Uuid) -> Result<u64, AppError> {
    let result=sqlx::query("INSERT INTO notification_messages(project_id,visitor_id,notification_id) SELECT n.project_id,v.id,n.id FROM notifications n JOIN visitors v ON v.project_id=n.project_id LEFT JOIN LATERAL(SELECT platform FROM devices WHERE project_id=v.project_id AND visitor_id=v.id ORDER BY updated_at DESC LIMIT 1)d ON true WHERE n.project_id=$1 AND v.id=$2 AND NOT n.archived AND n.scheduled_at<=now() AND ((n.new_users AND v.first_seen_at>=n.created_at) OR (n.existing_users AND v.first_seen_at<=n.scheduled_at)) AND (cardinality(n.platforms)=0 OR coalesce(d.platform,'web')=ANY(n.platforms) OR (coalesce(d.platform,'web') IN('web','desktop','windows','mac','linux','other') AND 'web'=ANY(n.platforms))) ORDER BY n.created_at LIMIT 1000 ON CONFLICT(notification_id,visitor_id) DO NOTHING").bind(project).bind(visitor).execute(&st.pg).await?;
    Ok(result.rows_affected())
}
pub async fn fanout_once(st: &AppState) -> Result<u64, AppError> {
    let result=sqlx::query("INSERT INTO notification_messages(project_id,visitor_id,notification_id) SELECT n.project_id,v.id,n.id FROM notifications n JOIN visitors v ON v.project_id=n.project_id LEFT JOIN LATERAL(SELECT platform FROM devices WHERE project_id=v.project_id AND visitor_id=v.id ORDER BY updated_at DESC LIMIT 1)d ON true WHERE NOT n.archived AND n.scheduled_at<=now() AND ((n.new_users AND v.first_seen_at>=n.created_at) OR (n.existing_users AND v.first_seen_at<=n.scheduled_at)) AND (cardinality(n.platforms)=0 OR coalesce(d.platform,'web')=ANY(n.platforms) OR (coalesce(d.platform,'web') IN('web','desktop','windows','mac','linux','other') AND 'web'=ANY(n.platforms))) AND NOT EXISTS(SELECT 1 FROM notification_messages m WHERE m.notification_id=n.id AND m.visitor_id=v.id) ORDER BY n.created_at,v.id LIMIT 500 ON CONFLICT(notification_id,visitor_id) DO NOTHING").execute(&st.pg).await?;
    sqlx::query("INSERT INTO push_outbox(project_id,message_id,device_id) SELECT m.project_id,m.id,d.id FROM notification_messages m JOIN notifications n ON n.id=m.notification_id JOIN devices d ON d.project_id=m.project_id AND d.visitor_id=m.visitor_id WHERE n.send_push AND NOT n.archived AND d.push_token IS NOT NULL AND d.platform IN('ios','android') AND (cardinality(n.platforms)=0 OR d.platform=ANY(n.platforms)) AND NOT EXISTS(SELECT 1 FROM push_outbox o WHERE o.message_id=m.id AND o.device_id=d.id) ORDER BY m.created_at LIMIT 500 ON CONFLICT(message_id,device_id) DO NOTHING").execute(&st.pg).await?;
    Ok(result.rows_affected())
}

#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PushProfile {
    Fcm {
        project_ids: Vec<Uuid>,
        firebase_project_id: String,
        credentials_file: String,
    },
    Apns {
        project_ids: Vec<Uuid>,
        team_id: String,
        key_id: String,
        bundle_id: String,
        key_file: String,
    },
}
impl PushProfile {
    fn projects(&self) -> &[Uuid] {
        match self {
            Self::Fcm { project_ids, .. } | Self::Apns { project_ids, .. } => project_ids,
        }
    }
    fn platform(&self) -> &'static str {
        match self {
            Self::Fcm { .. } => "android",
            Self::Apns { .. } => "ios",
        }
    }
}
fn profiles() -> Result<HashMap<String, PushProfile>, AppError> {
    serde_json::from_str(&std::env::var("PUSH_PROFILES_JSON").unwrap_or_else(|_| "{}".into()))
        .map_err(|_| AppError::Config("invalid PUSH_PROFILES_JSON".into()))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileRefs {
    android_profile: Option<String>,
    ios_profile: Option<String>,
}
async fn set_profiles(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Json(body): Json<ProfileRefs>,
) -> Api {
    authorize_project(&st, &user, project, true).await?;
    let available = profiles()?;
    for (name, platform) in [
        (&body.android_profile, "android"),
        (&body.ios_profile, "ios"),
    ] {
        if let Some(name) = name {
            let profile = available
                .get(name)
                .ok_or_else(|| AppError::BadRequest("unknown push profile".into()))?;
            if !profile.projects().contains(&project) || profile.platform() != platform {
                return Err(AppError::Forbidden);
            }
        }
    }
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT set_config('trisixt.actor_id',$1,true)")
        .bind(user.id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO project_push_profiles(project_id,android_profile,ios_profile) VALUES($1,$2,$3) ON CONFLICT(project_id) DO UPDATE SET android_profile=$2,ios_profile=$3,updated_at=now()").bind(project).bind(body.android_profile).bind(body.ios_profile).execute(&mut *tx).await?;
    tx.commit().await?;
    get_profiles(State(st), user, Path(project)).await
}
async fn get_profiles(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
) -> Api {
    authorize_project(&st, &user, project, false).await?;
    let row = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(p) FROM project_push_profiles p WHERE project_id=$1",
    )
    .bind(project)
    .fetch_optional(&st.pg)
    .await?;
    Ok(Json(json!({"push_profiles":row})))
}
#[derive(Clone, Debug)]
pub struct PushMessage {
    pub id: Uuid,
    pub device_token: String,
    pub title: String,
    pub subtitle: String,
    pub test_environment: bool,
}
#[derive(Debug, PartialEq)]
pub enum PushOutcome {
    Delivered,
    InvalidToken,
}
fn fcm_body(message: &PushMessage) -> Value {
    json!({"message":{"token":message.device_token,"notification":{"title":message.title,"body":message.subtitle},"data":{"linksquared":"true","notification_id":message.id.to_string()}}})
}
fn apns_body(message: &PushMessage) -> Value {
    json!({"aps":{"alert":{"title":message.title,"subtitle":message.subtitle},"sound":"default"},"notification_id":message.id})
}
/// Explicit request primitive for adapter tests. Production callers use send_push's fixed provider hosts.
pub async fn send_push_http(
    client: &reqwest::Client,
    url: &str,
    bearer: &str,
    topic: Option<&str>,
    message: &PushMessage,
) -> Result<PushOutcome, AppError> {
    let mut request = client
        .post(url)
        .bearer_auth(bearer)
        .timeout(Duration::from_secs(20));
    if let Some(topic) = topic {
        request = request
            .header("apns-topic", topic)
            .header("apns-push-type", "alert")
            .header("apns-id", message.id.to_string())
            .json(&apns_body(message));
        if url.starts_with("https://") {
            request = request.version(reqwest::Version::HTTP_2)
        }
    } else {
        request = request.json(&fcm_body(message));
    }
    let response = request.send().await.map_err(|_| AppError::Upstream)?;
    let status = response.status();
    if status.is_success() {
        return Ok(PushOutcome::Delivered);
    }
    if response.content_length().is_some_and(|n| n > 100_000) {
        return Err(AppError::Upstream);
    }
    let body: Value = response.json().await.map_err(|_| AppError::Upstream)?;
    if topic.is_some() {
        if (status == StatusCode::GONE && body["reason"] == "Unregistered")
            || (status == StatusCode::BAD_REQUEST && body["reason"] == "BadDeviceToken")
        {
            return Ok(PushOutcome::InvalidToken);
        }
    } else if body["error"]["details"]
        .as_array()
        .is_some_and(|details| details.iter().any(|d| d["errorCode"] == "UNREGISTERED"))
    {
        return Ok(PushOutcome::InvalidToken);
    }
    Err(AppError::Upstream)
}
#[derive(Serialize)]
struct ApnsClaims {
    iss: String,
    iat: i64,
}
pub async fn send_push(
    profile: &PushProfile,
    message: &PushMessage,
) -> Result<PushOutcome, AppError> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|_| AppError::Internal)?;
    match profile {
        PushProfile::Fcm {
            firebase_project_id,
            credentials_file,
            ..
        } => {
            if firebase_project_id.is_empty()
                || !firebase_project_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(AppError::Config("invalid Firebase project id".into()));
            }
            let provider = gcp_auth::CustomServiceAccount::from_file(credentials_file)
                .map_err(|_| AppError::Config("cannot load FCM service account".into()))?;
            let token = provider
                .token(&["https://www.googleapis.com/auth/firebase.messaging"])
                .await
                .map_err(|_| AppError::Upstream)?;
            send_push_http(
                &client,
                &format!(
                    "https://fcm.googleapis.com/v1/projects/{firebase_project_id}/messages:send"
                ),
                token.as_str(),
                None,
                message,
            )
            .await
        }
        PushProfile::Apns {
            team_id,
            key_id,
            bundle_id,
            key_file,
            ..
        } => {
            if message.device_token.is_empty()
                || message.device_token.len() > 256
                || !message.device_token.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Ok(PushOutcome::InvalidToken);
            }
            let pem = tokio::fs::read(key_file)
                .await
                .map_err(|_| AppError::Config("cannot load APNs key".into()))?;
            let key = jsonwebtoken::EncodingKey::from_ec_pem(&pem)
                .map_err(|_| AppError::Config("invalid APNs key".into()))?;
            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
            header.kid = Some(key_id.clone());
            let jwt = jsonwebtoken::encode(
                &header,
                &ApnsClaims {
                    iss: team_id.clone(),
                    iat: Utc::now().timestamp(),
                },
                &key,
            )
            .map_err(|_| AppError::Internal)?;
            let host = if message.test_environment {
                "api.sandbox.push.apple.com"
            } else {
                "api.push.apple.com"
            };
            send_push_http(
                &client,
                &format!("https://{host}/3/device/{}", message.device_token),
                &jwt,
                Some(bundle_id),
                message,
            )
            .await
        }
    }
}
pub async fn dispatch_once(st: &AppState) -> Result<usize, AppError> {
    fanout_once(st).await?;
    let lease = Uuid::new_v4();
    let row=sqlx::query("UPDATE push_outbox SET lease_id=$1,lease_until=now()+interval '60 seconds',attempts=attempts+1 WHERE id=(SELECT o.id FROM push_outbox o JOIN notification_messages m ON m.id=o.message_id JOIN notifications n ON n.id=m.notification_id WHERE o.sent_at IS NULL AND o.invalidated_at IS NULL AND o.available_at<=now() AND (o.lease_until IS NULL OR o.lease_until<now()) AND NOT n.archived ORDER BY o.available_at FOR UPDATE OF o SKIP LOCKED LIMIT 1) RETURNING id,project_id,message_id,device_id").bind(lease).fetch_optional(&st.pg).await?;
    let Some(row) = row else { return Ok(0) };
    let id: Uuid = row.get("id");
    let project: Uuid = row.get("project_id");
    let device: Uuid = row.get("device_id");
    let result=async{let data=sqlx::query("SELECT d.platform,d.push_token,d.push_environment,n.id,n.title,n.subtitle,p.android_profile,p.ios_profile FROM devices d JOIN notification_messages m ON m.id=$2 JOIN notifications n ON n.id=m.notification_id LEFT JOIN project_push_profiles p ON p.project_id=d.project_id WHERE d.id=$1 AND d.project_id=$3").bind(device).bind(row.get::<Uuid,_>("message_id")).bind(project).fetch_one(&st.pg).await?;let token=data.get::<Option<String>,_>("push_token").unwrap_or_default();if token.is_empty(){return Ok((PushOutcome::InvalidToken,token))}let platform:String=data.get("platform");let key=data.get::<Option<String>,_>(if platform=="ios"{"ios_profile"}else{"android_profile"}).ok_or_else(||AppError::Config("project has no push profile".into()))?;let available=profiles()?;let profile=available.get(&key).ok_or_else(||AppError::Config("unknown push profile".into()))?;if !profile.projects().contains(&project)||profile.platform()!=platform{return Err(AppError::Forbidden)}let outcome=send_push(profile,&PushMessage{id:data.get("id"),device_token:token.clone(),title:data.get("title"),subtitle:data.get("subtitle"),test_environment:data.get::<String,_>("push_environment")=="test"}).await?;Ok::<_,AppError>((outcome,token))}.await;
    match result {
        Ok((outcome, token)) => {
            let mut tx = st.pg.begin().await?;
            let count=sqlx::query("UPDATE push_outbox SET sent_at=CASE WHEN $3 THEN now() ELSE NULL END,invalidated_at=CASE WHEN $3 THEN NULL ELSE now() END,lease_id=NULL,lease_until=NULL,last_error=NULL WHERE id=$1 AND lease_id=$2").bind(id).bind(lease).bind(outcome==PushOutcome::Delivered).execute(&mut *tx).await?.rows_affected();
            if count == 1 && outcome == PushOutcome::InvalidToken {
                sqlx::query("UPDATE devices SET push_token=NULL WHERE id=$1 AND push_token=$2")
                    .bind(device)
                    .bind(token)
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
            Ok(count as usize)
        }
        Err(error) => {
            sqlx::query("UPDATE push_outbox SET available_at=now()+make_interval(secs=>least(3600,30*power(2,least(attempts,7)))::double precision),lease_id=NULL,lease_until=NULL,last_error='push delivery failed' WHERE id=$1 AND lease_id=$2").bind(id).bind(lease).execute(&st.pg).await?;
            Err(error)
        }
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/projects/{id}/notifications",
            post(create).get(list),
        )
        .route("/api/v1/projects/{id}/notifications/search", post(search))
        .route(
            "/api/v1/projects/{project}/notifications/{id}",
            axum::routing::delete(archive),
        )
        .route(
            "/api/v1/projects/{id}/push-profiles",
            get(get_profiles).put(set_profiles),
        )
        .route("/api/v1/sdk/notifications", get(sdk_list))
        .route("/api/v1/sdk/notifications_for_device", post(sdk_list_post))
        .route("/api/v1/sdk/number_of_unread_notifications", get(unread))
        .route("/api/v1/sdk/mark_notification_as_read", post(read))
        .route(
            "/api/v1/sdk/notifications_to_display_automatically",
            get(automatic),
        )
        .route("/mm/{id}", get(public_message))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sanitizer_preserves_rich_text_and_removes_active_content() {
        let html = sanitize_html(
            "<h1>Hello</h1><script>alert(1)</script><a href='javascript:alert(1)'>x</a><p style='background:url(https://evil)'>y</p><p style='color:red'>safe</p><img src='data:text/html,bad' onerror='bad()'>",
        );
        assert!(html.contains("<h1>Hello</h1>"));
        assert!(html.contains("color:red"));
        assert!(!html.contains("javascript"));
        assert!(!html.contains("alert"));
        assert!(!html.contains("url("));
        assert!(!html.contains("onerror"));
        assert!(!html.contains("data:"));
    }
    #[test]
    fn target_validation_requires_exactly_one_segment() {
        let mut b = CreateNotification {
            title: "a".into(),
            subtitle: String::new(),
            html: String::new(),
            auto_display: false,
            send_push: false,
            new_users: true,
            existing_users: true,
            platforms: vec![],
            scheduled_at: None,
        };
        assert!(validate_notification(&b).is_err());
        b.existing_users = false;
        assert!(validate_notification(&b).is_ok());
        b.platforms.push("unknown".into());
        assert!(validate_notification(&b).is_err());
    }
}
