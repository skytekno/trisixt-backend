//! Stripe and enterprise billing. Store raw signed webhook payloads before ack;
//! replay safely from the durable inbox, hydrating current Stripe truth.
use crate::{
    auth::{AuthUser, authorize_instance},
    error::AppError,
    state::AppState,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};
use chrono::{DateTime, Datelike, Utc};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

type Api = Result<Json<Value>, AppError>;
pub fn self_hosted() -> bool {
    std::env::var("TRISIXT_SELF_HOSTED").as_deref() == Ok("true")
}
fn free_limit() -> i64 {
    std::env::var("FREE_MAU_COUNT")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(10000)
}
fn required(key: &str) -> Result<String, AppError> {
    std::env::var(key)
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Config(format!("{key} required")))
}
fn bad(message: &str) -> AppError {
    AppError::BadRequest(message.into())
}
fn stamp(value: &Value) -> Option<DateTime<Utc>> {
    value.as_i64().and_then(|s| DateTime::from_timestamp(s, 0))
}
fn free_pass(id: Uuid) -> bool {
    std::env::var("FREE_PASS_PROJECT_IDS")
        .unwrap_or_default()
        .split(',')
        .chain(
            std::env::var("PUBLIC_GO_PROJECT_IDENTIFIER_ID")
                .unwrap_or_default()
                .split(','),
        )
        .any(|v| v.trim() == id.to_string())
}

pub struct StripeClient {
    client: reqwest::Client,
    secret: String,
    base: String,
}
impl StripeClient {
    pub fn new(secret: String, base: String) -> Result<Self, AppError> {
        let url = reqwest::Url::parse(&base).map_err(|_| bad("invalid Stripe base URL"))?;
        if !(url.scheme() == "https" && url.host_str() == Some("api.stripe.com"))
            && !(url.scheme() == "http"
                && matches!(url.host_str(), Some("127.0.0.1" | "localhost")))
        {
            return Err(bad(
                "Stripe endpoint must be official HTTPS or loopback test server",
            ));
        }
        Ok(Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(20))
                .build()
                .map_err(|_| AppError::Internal)?,
            secret,
            base,
        })
    }
    fn from_env() -> Result<Self, AppError> {
        Self::new(
            required("STRIPE_SECRET_KEY")?,
            "https://api.stripe.com".into(),
        )
    }
    pub async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        fields: &[(String, String)],
        idempotency: Option<&str>,
    ) -> Result<Value, AppError> {
        if !path.starts_with("/v1/") || path.contains("..") || path.contains('?') {
            return Err(AppError::Internal);
        }
        let mut request = self
            .client
            .request(method.clone(), format!("{}{}", self.base, path))
            .bearer_auth(&self.secret)
            .header("Stripe-Version", "2024-06-20");
        if method == reqwest::Method::GET {
            request = request.query(fields);
        } else {
            request = request.form(fields);
        }
        if let Some(key) = idempotency {
            request = request.header("Idempotency-Key", key);
        }
        let mut response = request.send().await.map_err(|_| AppError::Upstream)?;
        if !response.status().is_success() {
            return Err(AppError::Upstream);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| AppError::Upstream)? {
            if bytes.len() + chunk.len() > 1_048_576 {
                return Err(AppError::Upstream);
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| AppError::Upstream)
    }
    async fn get(&self, path: &str) -> Result<Value, AppError> {
        self.request(reqwest::Method::GET, path, &[], None).await
    }
}
fn identifier(value: &str) -> Result<(), AppError> {
    if value.is_empty()
        || value.len() > 255
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(bad("invalid Stripe identifier"));
    }
    Ok(())
}
fn dashboard() -> Result<String, AppError> {
    let value = required("TRISIXT_DASHBOARD_URL")?;
    let url = reqwest::Url::parse(&value).map_err(|_| bad("invalid dashboard URL"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(bad("invalid dashboard URL"));
    }
    Ok(value.trim_end_matches('/').into())
}
async fn billing_access(st: &AppState, user: &AuthUser, id: Uuid) -> Result<(), AppError> {
    authorize_instance(st, user, id, true).await?;
    if self_hosted() {
        return Err(AppError::Forbidden);
    }
    Ok(())
}
async fn customer(
    st: &AppState,
    client: &StripeClient,
    id: Uuid,
    email: &str,
) -> Result<String, AppError> {
    if let Some(customer) = sqlx::query_scalar::<_, String>(
        "SELECT customer_id FROM billing_customers WHERE instance_id=$1",
    )
    .bind(id)
    .fetch_optional(&st.pg)
    .await?
    {
        return Ok(customer);
    }
    let response = client
        .request(
            reqwest::Method::POST,
            "/v1/customers",
            &[
                ("email".into(), email.into()),
                ("metadata[instance_id]".into(), id.to_string()),
            ],
            Some(&format!("trisixt-customer-{id}")),
        )
        .await?;
    let customer = response["id"].as_str().ok_or(AppError::Upstream)?;
    identifier(customer)?;
    sqlx::query("INSERT INTO billing_customers(instance_id,customer_id) VALUES($1,$2) ON CONFLICT(instance_id) DO NOTHING").bind(id).bind(customer).execute(&st.pg).await?;
    Ok(customer.into())
}
async fn checkout(State(st): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Api {
    billing_access(&st, &user, id).await?;
    let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM billing_subscriptions WHERE instance_id=$1 AND status NOT IN ('canceled','incomplete_expired'))").bind(id).fetch_one(&st.pg).await?;
    if active {
        return Err(AppError::Conflict(
            "instance already has a subscription".into(),
        ));
    }
    let client = StripeClient::from_env()?;
    let customer = customer(&st, &client, id, &user.email).await?;
    let base = dashboard()?;
    let session = client
        .request(
            reqwest::Method::POST,
            "/v1/checkout/sessions",
            &[
                ("mode".into(), "subscription".into()),
                ("customer".into(), customer),
                ("client_reference_id".into(), id.to_string()),
                (
                    "subscription_data[metadata][instance_id]".into(),
                    id.to_string(),
                ),
                (
                    "line_items[0][price]".into(),
                    required("STRIPE_STANDARD_PRICE_ID")?,
                ),
                (
                    "success_url".into(),
                    format!("{base}/settings?instance_id={id}"),
                ),
                (
                    "cancel_url".into(),
                    format!("{base}/settings?instance_id={id}&cancel=true"),
                ),
            ],
            Some(&format!(
                "trisixt-checkout-{id}-{}",
                Utc::now().timestamp() / 1800
            )),
        )
        .await?;
    let session_id = session["id"].as_str().ok_or(AppError::Upstream)?;
    let url = session["url"].as_str().ok_or(AppError::Upstream)?;
    sqlx::query("INSERT INTO billing_checkout_sessions(id,instance_id,user_id,url) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO NOTHING").bind(session_id).bind(id).bind(user.id).bind(url).execute(&st.pg).await?;
    Ok(Json(json!({"url":url})))
}
async fn portal(State(st): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Api {
    billing_access(&st, &user, id).await?;
    let customer = sqlx::query_scalar::<_, String>(
        "SELECT customer_id FROM billing_customers WHERE instance_id=$1",
    )
    .bind(id)
    .fetch_optional(&st.pg)
    .await?
    .ok_or(AppError::NotFound)?;
    let result = StripeClient::from_env()?
        .request(
            reqwest::Method::POST,
            "/v1/billing_portal/sessions",
            &[
                ("customer".into(), customer),
                ("return_url".into(), dashboard()?),
            ],
            None,
        )
        .await?;
    Ok(Json(json!({"url":result["url"]})))
}
async fn subscription_id(st: &AppState, id: Uuid) -> Result<String, AppError> {
    sqlx::query_scalar("SELECT id FROM billing_subscriptions WHERE instance_id=$1 AND status NOT IN ('canceled','incomplete_expired') ORDER BY updated_at DESC LIMIT 1").bind(id).fetch_optional(&st.pg).await?.ok_or(AppError::NotFound)
}
async fn cancel(State(st): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Api {
    billing_access(&st, &user, id).await?;
    let sub = subscription_id(&st, id).await?;
    identifier(&sub)?;
    let remote = StripeClient::from_env()?
        .request(
            reqwest::Method::DELETE,
            &format!("/v1/subscriptions/{sub}"),
            &[],
            Some(&format!("trisixt-cancel-{sub}")),
        )
        .await?;
    apply_snapshot(&st, id, &remote, Utc::now().timestamp()).await?;
    Ok(Json(json!({"result":remote})))
}
#[derive(Deserialize)]
struct Pause {
    paused: bool,
}
async fn pause(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<Pause>,
) -> Api {
    billing_access(&st, &user, id).await?;
    let sub = subscription_id(&st, id).await?;
    identifier(&sub)?;
    let fields = if body.paused {
        vec![("pause_collection[behavior]".into(), "void".into())]
    } else {
        vec![("pause_collection".into(), "".into())]
    };
    let remote = StripeClient::from_env()?
        .request(
            reqwest::Method::POST,
            &format!("/v1/subscriptions/{sub}"),
            &fields,
            Some(&format!(
                "trisixt-pause-{sub}-{}-{}",
                body.paused,
                Utc::now().timestamp() / 60
            )),
        )
        .await?;
    apply_snapshot(&st, id, &remote, Utc::now().timestamp()).await?;
    Ok(Json(remote))
}
pub async fn mau(
    st: &AppState,
    id: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<i64, AppError> {
    sqlx::query_scalar("SELECT count(*) FROM monthly_active_visitors WHERE instance_id=$1 AND month>=date_trunc('month',$2::timestamptz AT TIME ZONE 'UTC')::date AND month<=date_trunc('month',$3::timestamptz AT TIME ZONE 'UTC')::date").bind(id).bind(from).bind(to).fetch_one(&st.pg).await.map_err(Into::into)
}
async fn current_mau(State(st): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Api {
    authorize_instance(&st, &user, id, false).await?;
    let now = Utc::now();
    Ok(Json(
        json!({"current_quantity":mau(&st,id,now,now).await?,"total_available":free_limit().to_string()}),
    ))
}
async fn details(State(st): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Api {
    authorize_instance(&st, &user, id, false).await?;
    if let Some(subscription)=sqlx::query_scalar::<_,Value>("SELECT to_jsonb(s) FROM billing_subscriptions s WHERE instance_id=$1 AND status NOT IN ('canceled','incomplete_expired') ORDER BY updated_at DESC LIMIT 1").bind(id).fetch_optional(&st.pg).await?{
        let mut result=json!({"type":"stripe","details":subscription,"maus":mau(&st,id,Utc::now(),Utc::now()).await?});
        if !self_hosted(){let client=StripeClient::from_env()?;let sid=subscription["id"].as_str().ok_or(AppError::Internal)?;identifier(sid)?;result["stripe_subscription"]=client.get(&format!("/v1/subscriptions/{sid}")).await?;result["invoice"]=client.request(reqwest::Method::GET,"/v1/invoices/upcoming",&[("subscription".into(),sid.into())],None).await?;}
        return Ok(Json(result));
    }
    let enterprise=sqlx::query_scalar::<_,Value>("SELECT to_jsonb(e) FROM enterprise_subscriptions e WHERE instance_id=$1 AND active AND start_date<=now() AND end_date>now() ORDER BY created_at DESC LIMIT 1").bind(id).fetch_optional(&st.pg).await?.ok_or(AppError::NotFound)?;
    let from =
        serde_json::from_value(enterprise["start_date"].clone()).map_err(|_| AppError::Internal)?;
    Ok(Json(
        json!({"type":"enterprise","current_maus":mau(&st,id,from,Utc::now()).await?,"total_maus":enterprise["total_maus"],"start_at":enterprise["start_date"],"end_at":enterprise["end_date"]}),
    ))
}

pub fn verify_signature(secret: &str, header: &str, body: &[u8], now: i64) -> Result<(), AppError> {
    if secret.len() < 16 || body.len() > 1_048_576 {
        return Err(AppError::Unauthorized);
    }
    let timestamp = header
        .split(',')
        .find_map(|p| p.strip_prefix("t="))
        .and_then(|v| v.parse::<i64>().ok())
        .ok_or(AppError::Unauthorized)?;
    if now.abs_diff(timestamp) > 300 {
        return Err(AppError::Unauthorized);
    }
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| AppError::Internal)?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    if !header
        .split(',')
        .filter_map(|p| p.strip_prefix("v1="))
        .filter_map(|v| hex::decode(v).ok())
        .any(|sig| mac.clone().verify_slice(&sig).is_ok())
    {
        return Err(AppError::Unauthorized);
    }
    Ok(())
}
async fn stripe_webhook(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Api {
    if self_hosted() {
        return Err(AppError::Forbidden);
    }
    let header = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    verify_signature(
        &required("STRIPE_WEBHOOK_SECRET")?,
        header,
        &body,
        Utc::now().timestamp(),
    )?;
    let event: Value =
        serde_json::from_slice(&body).map_err(|_| bad("invalid Stripe event JSON"))?;
    let id = event["id"]
        .as_str()
        .ok_or_else(|| bad("missing event id"))?;
    identifier(id)?;
    let kind = event["type"]
        .as_str()
        .ok_or_else(|| bad("missing event type"))?;
    let created = event["created"]
        .as_i64()
        .ok_or_else(|| bad("missing event timestamp"))?;
    sqlx::query("INSERT INTO billing_webhooks(id,event_type,created,payload) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO NOTHING").bind(id).bind(kind).bind(created).bind(&event).execute(&st.pg).await?;
    Ok(Json(json!({"received":true,"queued":true})))
}
pub async fn apply_snapshot(
    st: &AppState,
    instance: Uuid,
    snapshot: &Value,
    event_at: i64,
) -> Result<(), AppError> {
    let id = snapshot["id"].as_str().ok_or(AppError::Upstream)?;
    identifier(id)?;
    let customer = snapshot["customer"].as_str().ok_or(AppError::Upstream)?;
    let status = snapshot["status"].as_str().ok_or(AppError::Upstream)?;
    let item = &snapshot["items"]["data"][0];
    let paused = snapshot["pause_collection"].is_object();
    let active = matches!(status, "active" | "trialing") && !paused;
    let status = if paused { "paused" } else { status };
    let start =
        stamp(&snapshot["current_period_start"]).or_else(|| stamp(&item["current_period_start"]));
    let end = stamp(&snapshot["current_period_end"]).or_else(|| stamp(&item["current_period_end"]));
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("billing:{instance}"))
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO billing_subscriptions(id,instance_id,customer_id,item_id,status,active,period_start,period_end,cancels_at,cancel_at_period_end,last_event_at,snapshot) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(id) DO UPDATE SET item_id=excluded.item_id,status=excluded.status,active=excluded.active,period_start=excluded.period_start,period_end=excluded.period_end,cancels_at=excluded.cancels_at,cancel_at_period_end=excluded.cancel_at_period_end,last_event_at=excluded.last_event_at,snapshot=excluded.snapshot,updated_at=now() WHERE billing_subscriptions.instance_id=excluded.instance_id AND billing_subscriptions.last_event_at<=excluded.last_event_at")
        .bind(id).bind(instance).bind(customer).bind(item["id"].as_str()).bind(status).bind(active).bind(start).bind(end).bind(stamp(&snapshot["cancel_at"])).bind(snapshot["cancel_at_period_end"].as_bool().unwrap_or(false)).bind(event_at).bind(snapshot).execute(&mut *tx).await?;
    tx.commit().await?;
    refresh_quota(st, instance).await?;
    Ok(())
}
async fn process_event(
    st: &AppState,
    client: &StripeClient,
    event: &Value,
) -> Result<(), AppError> {
    let kind = event["type"].as_str().ok_or(AppError::Upstream)?;
    let object = &event["data"]["object"];
    let sub = if kind == "checkout.session.completed" {
        object["subscription"].as_str()
    } else if kind.starts_with("customer.subscription.") {
        object["id"].as_str()
    } else if matches!(kind, "invoice.paid" | "invoice.payment_failed") {
        object["subscription"]
            .as_str()
            .or_else(|| object["parent"]["subscription_details"]["subscription"].as_str())
    } else {
        return Ok(());
    };
    let Some(sub) = sub else {
        return Ok(());
    };
    identifier(sub)?;
    let remote = client.get(&format!("/v1/subscriptions/{sub}")).await?;
    let instance = if let Some(id) = remote["metadata"]["instance_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        Some(id)
    } else {
        sqlx::query_scalar::<_, Uuid>("SELECT instance_id FROM billing_subscriptions WHERE id=$1")
            .bind(sub)
            .fetch_optional(&st.pg)
            .await?
    };
    let instance = if let Some(id) = instance {
        Some(id)
    } else if kind == "checkout.session.completed" {
        sqlx::query_scalar::<_, Uuid>(
            "SELECT instance_id FROM billing_checkout_sessions WHERE id=$1",
        )
        .bind(object["id"].as_str().unwrap_or(""))
        .fetch_optional(&st.pg)
        .await?
    } else {
        None
    };
    let instance = instance.ok_or_else(|| {
        AppError::Conflict("subscription tenant mapping not available yet".into())
    })?;
    // Current provider truth, never an old delivery snapshot. Timestamp watermark
    // prevents a slow earlier worker overwriting a newer completed reconciliation.
    apply_snapshot(
        st,
        instance,
        &remote,
        event["created"].as_i64().ok_or(AppError::Upstream)?,
    )
    .await
}
pub async fn process_pending(st: &AppState, limit: i64) -> Result<u64, AppError> {
    if self_hosted() {
        return Ok(0);
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM billing_webhooks WHERE processed_at IS NULL AND available_at<=now()",
    )
    .fetch_one(&st.pg)
    .await?;
    if count == 0 {
        return Ok(0);
    }
    let client = StripeClient::from_env()?;
    dispatch_pending(st, &client, limit).await
}
/// Processes the durable inbox with an explicit client, including test gateways.
pub async fn dispatch_pending(
    st: &AppState,
    client: &StripeClient,
    limit: i64,
) -> Result<u64, AppError> {
    let mut completed = 0;
    for _ in 0..limit.clamp(1, 100) {
        let mut tx = st.pg.begin().await?;
        let row=sqlx::query("SELECT id,payload FROM billing_webhooks WHERE processed_at IS NULL AND available_at<=now() ORDER BY received_at FOR UPDATE SKIP LOCKED LIMIT 1").fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            break;
        };
        let id: String = row.get("id");
        let payload: Value = row.get("payload");
        match process_event(st, client, &payload).await {
            Ok(()) => {
                sqlx::query(
                    "UPDATE billing_webhooks SET processed_at=now(),last_error=NULL WHERE id=$1",
                )
                .bind(&id)
                .execute(&mut *tx)
                .await?;
                completed += 1;
            }
            Err(_) => {
                sqlx::query("UPDATE billing_webhooks SET attempts=attempts+1,available_at=now()+make_interval(secs=>least(3600,30*power(2,least(attempts,7)))::int),last_error='provider processing failed; retry scheduled' WHERE id=$1").bind(&id).execute(&mut *tx).await?;
            }
        }
        tx.commit().await?;
    }
    Ok(completed)
}
async fn exempt_tx(tx: &mut Transaction<'_, Postgres>, instance: Uuid) -> Result<bool, AppError> {
    Ok(self_hosted()||free_pass(instance)||sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM billing_subscriptions WHERE instance_id=$1 AND active) OR EXISTS(SELECT 1 FROM enterprise_subscriptions WHERE instance_id=$1 AND active AND start_date<=now() AND end_date>now())").bind(instance).fetch_one(&mut **tx).await?)
}
pub async fn record_usage(
    tx: &mut Transaction<'_, Postgres>,
    project: Uuid,
    visitor: Uuid,
    at: DateTime<Utc>,
) -> Result<(), AppError> {
    let instance: Uuid = sqlx::query_scalar("SELECT instance_id FROM projects WHERE id=$1")
        .bind(project)
        .fetch_one(&mut **tx)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("quota:{instance}"))
        .execute(&mut **tx)
        .await?;
    let month = at.date_naive().with_day(1).ok_or(AppError::Internal)?;
    if !exempt_tx(tx, instance).await? {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM monthly_active_visitors WHERE instance_id=$1 AND month=$2",
        )
        .bind(instance)
        .bind(month)
        .fetch_one(&mut **tx)
        .await?;
        let existing:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM monthly_active_visitors WHERE instance_id=$1 AND month=$2 AND visitor_id=$3)").bind(instance).bind(month).bind(visitor).fetch_one(&mut **tx).await?;
        if count >= free_limit() && !existing {
            return Err(AppError::Forbidden);
        }
    }
    sqlx::query("INSERT INTO monthly_active_visitors(instance_id,month,visitor_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING").bind(instance).bind(month).bind(visitor).execute(&mut **tx).await?;
    Ok(())
}
pub async fn enforce_project_quota(
    st: &AppState,
    project: Uuid,
    _visitor: Uuid,
) -> Result<(), AppError> {
    let quota:bool=sqlx::query_scalar("SELECT i.quota_exceeded FROM instances i JOIN projects p ON p.instance_id=i.id WHERE p.id=$1").bind(project).fetch_one(&st.pg).await?;
    if quota && !self_hosted() {
        Err(AppError::Forbidden)
    } else {
        Ok(())
    }
}
async fn refresh_quota(st: &AppState, instance: Uuid) -> Result<(), AppError> {
    let mut tx = st.pg.begin().await?;
    let exempt = exempt_tx(&mut tx, instance).await?;
    let quantity:i64=sqlx::query_scalar("SELECT count(*) FROM monthly_active_visitors WHERE instance_id=$1 AND month=date_trunc('month',now() AT TIME ZONE 'UTC')::date").bind(instance).fetch_one(&mut *tx).await?;
    let limit = free_limit();
    sqlx::query(
        "UPDATE instances SET quota_exceeded=$2 WHERE id=$1 AND quota_exceeded IS DISTINCT FROM $2",
    )
    .bind(instance)
    .bind(!exempt && quantity > limit)
    .execute(&mut *tx)
    .await?;
    if !exempt && quantity * 100 >= limit * 85 {
        let kind = if quantity > limit {
            "exceeded"
        } else {
            "warning"
        };
        sqlx::query("INSERT INTO billing_alerts(instance_id,kind,quantity,limit_value) SELECT $1,$2,$3,$4 WHERE NOT EXISTS(SELECT 1 FROM billing_alerts WHERE instance_id=$1 AND kind=$2 AND created_at>now()-interval '3 days')").bind(instance).bind(kind).bind(quantity).bind(limit).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}
pub async fn report_usage(st: &AppState) -> Result<u64, AppError> {
    if self_hosted() {
        return Ok(0);
    }
    let instances: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM instances")
        .fetch_all(&st.pg)
        .await?;
    for instance in instances {
        refresh_quota(st, instance).await?;
    }
    let rows=sqlx::query("SELECT id,instance_id,item_id,period_start,period_end FROM billing_subscriptions WHERE active AND period_start IS NOT NULL AND period_end IS NOT NULL AND item_id IS NOT NULL").fetch_all(&st.pg).await?;
    if rows.is_empty() {
        return Ok(0);
    }
    let client = StripeClient::from_env()?;
    let mut total = 0;
    for row in rows {
        let sub: String = row.get("id");
        let instance: Uuid = row.get("instance_id");
        let item: String = row.get("item_id");
        identifier(&item)?;
        let start: DateTime<Utc> = row.get("period_start");
        let end: DateTime<Utc> = row.get("period_end");
        let qty = mau(st, instance, start, end - chrono::Duration::nanoseconds(1)).await?;
        let key = format!("trisixt-usage-{sub}-{}-{qty}", start.timestamp());
        client
            .request(
                reqwest::Method::POST,
                &format!("/v1/subscription_items/{item}/usage_records"),
                &[
                    ("quantity".into(), qty.to_string()),
                    ("timestamp".into(), Utc::now().timestamp().to_string()),
                    ("action".into(), "set".into()),
                ],
                Some(&key),
            )
            .await?;
        sqlx::query("INSERT INTO billing_usage_reports(subscription_id,period_start,quantity,last_report_at) VALUES($1,$2,$3,now()) ON CONFLICT(subscription_id,period_start) DO UPDATE SET quantity=excluded.quantity,last_report_at=now()").bind(&sub).bind(start).bind(qty).execute(&st.pg).await?;
        apply_discount(&client, &sub, qty).await?;
        total += 1;
    }
    Ok(total)
}
async fn apply_discount(client: &StripeClient, sub: &str, quantity: i64) -> Result<(), AppError> {
    let mut selected = None;
    for prefix in ["SECOND", "FIRST"] {
        let threshold = std::env::var(format!("{prefix}_DISCOUNT_MAUS_THRESHOLD"))
            .ok()
            .and_then(|v| v.parse::<i64>().ok());
        let percent = std::env::var(format!("{prefix}_DISCOUNT_PERCENTAGE"))
            .ok()
            .and_then(|v| v.parse::<i64>().ok());
        if let (Some(t), Some(p)) = (threshold, percent)
            && quantity >= t
            && (1..=100).contains(&p)
        {
            selected = Some(p);
            break;
        }
    }
    let fields = if let Some(percent) = selected {
        vec![
            ("duration".into(), "once".into()),
            ("percent_off".into(), percent.to_string()),
        ]
    } else if quantity >= free_limit() {
        vec![
            ("duration".into(), "once".into()),
            ("amount_off".into(), "1999".into()),
            ("currency".into(), "usd".into()),
        ]
    } else {
        client
            .request(
                reqwest::Method::POST,
                &format!("/v1/subscriptions/{sub}"),
                &[("discounts".into(), "".into())],
                None,
            )
            .await?;
        return Ok(());
    };
    let coupon = client
        .request(
            reqwest::Method::POST,
            "/v1/coupons",
            &fields,
            Some(&format!(
                "trisixt-discount-{sub}-{}-{}",
                selected.unwrap_or(0),
                Utc::now().format("%Y-%m")
            )),
        )
        .await?;
    let id = coupon["id"].as_str().ok_or(AppError::Upstream)?;
    client
        .request(
            reqwest::Method::POST,
            &format!("/v1/subscriptions/{sub}"),
            &[("discounts[0][coupon]".into(), id.into())],
            None,
        )
        .await?;
    Ok(())
}
fn admin(headers: &HeaderMap) -> Result<(), AppError> {
    let expected = required("TRISIXT_ADMIN_KEY")?;
    let supplied = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(expected.as_bytes()).map_err(|_| AppError::Internal)?;
    mac.update(b"trisixt-admin");
    let mut actual =
        Hmac::<Sha256>::new_from_slice(supplied.as_bytes()).map_err(|_| AppError::Internal)?;
    actual.update(b"trisixt-admin");
    mac.verify_slice(&actual.finalize().into_bytes())
        .map_err(|_| AppError::Unauthorized)
}
#[derive(Deserialize)]
struct EnterpriseInput {
    instance_id: Uuid,
    start_date: DateTime<Utc>,
    end_date: DateTime<Utc>,
    total_maus: i64,
    #[serde(default = "yes")]
    active: bool,
}
fn yes() -> bool {
    true
}
async fn enterprise_create(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<EnterpriseInput>,
) -> Api {
    admin(&headers)?;
    if !st.config.ee_enabled {
        return Err(AppError::Forbidden);
    }
    if body.start_date >= body.end_date || body.total_maus <= 0 {
        return Err(bad(
            "invalid enterprise subscription dates or MAU allowance",
        ));
    }
    let row=sqlx::query_scalar::<_,Value>("INSERT INTO enterprise_subscriptions(instance_id,start_date,end_date,total_maus,active) VALUES($1,$2,$3,$4,$5) RETURNING to_jsonb(enterprise_subscriptions)").bind(body.instance_id).bind(body.start_date).bind(body.end_date).bind(body.total_maus).bind(body.active).fetch_one(&st.pg).await?;
    refresh_quota(&st, body.instance_id).await?;
    Ok(Json(row))
}
async fn enterprise_update(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<EnterpriseInput>,
) -> Api {
    admin(&headers)?;
    if !st.config.ee_enabled {
        return Err(AppError::Forbidden);
    }
    if body.start_date >= body.end_date || body.total_maus <= 0 {
        return Err(bad("invalid enterprise subscription"));
    }
    let row=sqlx::query_scalar::<_,Value>("UPDATE enterprise_subscriptions SET start_date=$3,end_date=$4,total_maus=$5,active=$6 WHERE id=$1 AND instance_id=$2 RETURNING to_jsonb(enterprise_subscriptions)").bind(id).bind(body.instance_id).bind(body.start_date).bind(body.end_date).bind(body.total_maus).bind(body.active).fetch_optional(&st.pg).await?.ok_or(AppError::NotFound)?;
    refresh_quota(&st, body.instance_id).await?;
    Ok(Json(row))
}
async fn send_usage(State(st): State<AppState>, headers: HeaderMap) -> Api {
    admin(&headers)?;
    Ok(Json(json!({"reported":report_usage(&st).await?})))
}
#[derive(Deserialize)]
struct RevenueSetting {
    enabled: bool,
}
async fn revenue_setting(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<RevenueSetting>,
) -> Api {
    authorize_instance(&st, &user, id, true).await?;
    sqlx::query("UPDATE instances SET revenue_collection_enabled=$2 WHERE id=$1")
        .bind(id)
        .bind(body.enabled)
        .execute(&st.pg)
        .await?;
    Ok(Json(json!({"enabled":body.enabled})))
}
pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/instances/{id}/billing/subscriptions",
            post(checkout),
        )
        .route("/api/v1/instances/{id}/billing/stripe_portal", get(portal))
        .route(
            "/api/v1/instances/{id}/billing/subscription",
            get(details).delete(cancel),
        )
        .route(
            "/api/v1/instances/{id}/billing/subscription/pause",
            axum::routing::put(pause),
        )
        .route("/api/v1/instances/{id}/billing/mau", get(current_mau))
        .route("/api/v1/instances/{id}/billing/usage", get(details))
        .route("/api/v1/webhooks/stripe", post(stripe_webhook))
        .route("/api/v1/webhooks/send_stripe_quotas", post(send_usage))
        .route(
            "/api/v1/admin/create_enterprise_subscription",
            post(enterprise_create),
        )
        .route(
            "/api/v1/admin/enterprise_subscriptions/{id}",
            axum::routing::patch(enterprise_update),
        )
        .route(
            "/api/v1/instances/{id}/revenue_collection",
            axum::routing::put(revenue_setting),
        )
}

pub async fn has_paid_entitlement(st: &AppState, instance: Uuid) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM billing_subscriptions WHERE instance_id=$1 AND active) OR EXISTS(SELECT 1 FROM enterprise_subscriptions WHERE instance_id=$1 AND active AND start_date<=now() AND end_date>now())").bind(instance).fetch_one(&st.pg).await.map_err(Into::into)
}
