//! Verified store notifications, signed revenue ledger, subscription lifecycle,
//! attribution, exchange rates and durable reconciliation.
use crate::{
    auth::{AuthUser, authorize_project},
    error::AppError,
    purchases::{self, Profile, VerifiedPurchase},
    state::AppState,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use std::collections::HashMap;
use uuid::Uuid;
fn bad(s: &str) -> AppError {
    AppError::BadRequest(s.into())
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, AppError> {
    v[key].as_str().ok_or_else(|| bad("missing store field"))
}
fn profiles() -> Result<HashMap<Uuid, Profile>, AppError> {
    serde_json::from_str(
        &std::env::var("TRISIXT_IAP_PROFILES")
            .map_err(|_| AppError::Config("IAP profiles required".into()))?,
    )
    .map_err(|_| AppError::Config("invalid IAP profiles".into()))
}
fn time(v: &Value) -> Result<DateTime<Utc>, AppError> {
    v.as_i64()
        .and_then(DateTime::from_timestamp_millis)
        .ok_or_else(|| bad("invalid store timestamp"))
}
pub(crate) fn anonymous(provider: &str, original: &str) -> Uuid {
    let hash = Sha256::digest(format!("{provider}:{original}"));
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hash[..16]);
    Uuid::from_bytes(bytes)
}

/// Trust is anchored to Apple's published G3 root, not a certificate supplied
/// by the caller. Verify path signatures, CA/key usage, signing-purpose OIDs,
/// certificate validity at Apple's signedDate and the ES256 JWS signature.
pub fn verify_apple_jws(compact: &str) -> Result<Value, AppError> {
    use x509_parser::prelude::*;
    if compact.len() > 262_144 {
        return Err(AppError::Unauthorized);
    }
    let header = jsonwebtoken::decode_header(compact).map_err(|_| AppError::Unauthorized)?;
    if header.alg != jsonwebtoken::Algorithm::ES256 {
        return Err(AppError::Unauthorized);
    }
    let chain = header.x5c.ok_or(AppError::Unauthorized)?;
    if chain.len() != 3 {
        return Err(AppError::Unauthorized);
    }
    let der: Vec<Vec<u8>> = chain
        .iter()
        .map(|s| STANDARD.decode(s).map_err(|_| AppError::Unauthorized))
        .collect::<Result<_, _>>()?;
    if der[2].as_slice() != include_bytes!("apple-root-ca-g3.der") {
        return Err(AppError::Unauthorized);
    }
    let certs: Vec<_> = der
        .iter()
        .map(|d| {
            parse_x509_certificate(d)
                .map(|(_, c)| c)
                .map_err(|_| AppError::Unauthorized)
        })
        .collect::<Result<_, _>>()?;
    let hints = purchases::apple_api_payload(&json!({"signedTransactionInfo":compact}))?;
    let signed = time(&hints["signedDate"])?;
    if signed > Utc::now() + chrono::Duration::minutes(5) {
        return Err(AppError::Unauthorized);
    }
    let at = ASN1Time::from_timestamp(signed.timestamp()).map_err(|_| AppError::Unauthorized)?;
    for cert in &certs {
        if !cert.validity().is_valid_at(at) {
            return Err(AppError::Unauthorized);
        }
    }
    for index in 0..2 {
        if certs[index].issuer() != certs[index + 1].subject() {
            return Err(AppError::Unauthorized);
        }
        certs[index]
            .verify_signature(Some(certs[index + 1].public_key()))
            .map_err(|_| AppError::Unauthorized)?;
    }
    for index in [1, 2] {
        if !certs[index]
            .basic_constraints()
            .map_err(|_| AppError::Unauthorized)?
            .is_some_and(|c| c.value.ca)
        {
            return Err(AppError::Unauthorized);
        }
        if certs[index]
            .key_usage()
            .map_err(|_| AppError::Unauthorized)?
            .is_some_and(|c| !c.value.key_cert_sign())
        {
            return Err(AppError::Unauthorized);
        }
    }
    if certs[0]
        .basic_constraints()
        .map_err(|_| AppError::Unauthorized)?
        .is_some_and(|c| c.value.ca)
        || certs[0]
            .key_usage()
            .map_err(|_| AppError::Unauthorized)?
            .is_some_and(|k| !k.value.digital_signature())
    {
        return Err(AppError::Unauthorized);
    }
    for (index, oid) in [
        (0, "1.2.840.113635.100.6.11.1"),
        (1, "1.2.840.113635.100.6.2.1"),
    ] {
        if !certs[index]
            .extensions()
            .iter()
            .any(|e| e.oid.to_id_string() == oid)
        {
            return Err(AppError::Unauthorized);
        }
    }
    let public = certs[0].public_key().subject_public_key.data.as_ref();
    if public.len() != 65 || public[0] != 4 {
        return Err(AppError::Unauthorized);
    }
    let key = jsonwebtoken::DecodingKey::from_ec_components(
        &URL_SAFE_NO_PAD.encode(&public[1..33]),
        &URL_SAFE_NO_PAD.encode(&public[33..]),
    )
    .map_err(|_| AppError::Unauthorized)?;
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    jsonwebtoken::decode::<Value>(compact, &key, &validation)
        .map(|d| d.claims)
        .map_err(|_| AppError::Unauthorized)
}
async fn verify_google_push(headers: &HeaderMap) -> Result<(), AppError> {
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;
    let audience = std::env::var("GOOGLE_PUBSUB_AUDIENCE")
        .map_err(|_| AppError::Config("GOOGLE_PUBSUB_AUDIENCE required".into()))?;
    let email = std::env::var("GOOGLE_PUBSUB_SERVICE_ACCOUNT_EMAIL")
        .map_err(|_| AppError::Config("GOOGLE_PUBSUB_SERVICE_ACCOUNT_EMAIL required".into()))?;
    let header = jsonwebtoken::decode_header(token).map_err(|_| AppError::Unauthorized)?;
    if header.alg != jsonwebtoken::Algorithm::RS256 {
        return Err(AppError::Unauthorized);
    }
    let response = purchases::http_client()?
        .get("https://www.googleapis.com/oauth2/v3/certs")
        .send()
        .await
        .map_err(|_| AppError::Upstream)?
        .error_for_status()
        .map_err(|_| AppError::Upstream)?;
    let jwks: jsonwebtoken::jwk::JwkSet = response.json().await.map_err(|_| AppError::Upstream)?;
    let jwk = jwks
        .find(header.kid.as_deref().ok_or(AppError::Unauthorized)?)
        .ok_or(AppError::Unauthorized)?;
    let key = jsonwebtoken::DecodingKey::from_jwk(jwk).map_err(|_| AppError::Unauthorized)?;
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[audience]);
    validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);
    let claims = jsonwebtoken::decode::<Value>(token, &key, &validation)
        .map_err(|_| AppError::Unauthorized)?
        .claims;
    if claims["email"].as_str() != Some(email.as_str())
        || claims["email_verified"].as_bool() != Some(true)
    {
        return Err(AppError::Unauthorized);
    }
    Ok(())
}
#[derive(Deserialize)]
struct AppleBody {
    #[serde(rename = "signedPayload")]
    signed_payload: String,
}
async fn apple_webhook(
    State(st): State<AppState>,
    Path((environment, project)): Path<(String, Uuid)>,
    Json(body): Json<AppleBody>,
) -> Result<Json<Value>, AppError> {
    if !st.config.ee_enabled {
        return Err(AppError::Forbidden);
    }
    let config = profiles()?;
    let profile = config
        .get(&project)
        .and_then(|p| p.apple.as_ref())
        .ok_or(AppError::Forbidden)?;
    let payload = verify_apple_jws(&body.signed_payload)?;
    let expected = match environment.as_str() {
        "production" => "Production",
        "test" => "Sandbox",
        _ => return Err(AppError::NotFound),
    };
    if payload["data"]["bundleId"].as_str() != Some(profile.bundle_id.as_str())
        || payload["data"]["environment"].as_str() != Some(expected)
    {
        return Err(AppError::Forbidden);
    }
    let row=sqlx::query("SELECT p.instance_id,p.environment,i.revenue_collection_enabled FROM projects p JOIN instances i ON i.id=p.instance_id WHERE p.id=$1").bind(project).fetch_one(&st.pg).await?;
    let actual: String = row.get("environment");
    if actual
        != if expected == "Sandbox" {
            "test"
        } else {
            "production"
        }
    {
        return Err(AppError::Forbidden);
    }
    let id = text(&payload, "notificationUUID")?;
    let instance: Uuid = row.get("instance_id");
    if let Some(signed) = payload["data"]["signedTransactionInfo"].as_str() {
        let tx = verify_apple_jws(signed)?;
        if tx["bundleId"] != payload["data"]["bundleId"]
            || tx["environment"] != payload["data"]["environment"]
        {
            return Err(AppError::Forbidden);
        }
    }
    let enabled: bool = row.get("revenue_collection_enabled");
    if !enabled {
        return Ok(Json(json!({"ignored":"revenue collection disabled"})));
    }
    sqlx::query("INSERT INTO purchase_notifications(provider,external_id,instance_id,project_id,payload) VALUES('apple',$1,$2,$3,$4) ON CONFLICT DO NOTHING").bind(id).bind(instance).bind(project).bind(&payload).execute(&st.pg).await?;
    Ok(Json(json!({"queued":true})))
}
async fn google_webhook(
    State(st): State<AppState>,
    Path(instance): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    if !st.config.ee_enabled {
        return Err(AppError::Forbidden);
    }
    verify_google_push(&headers).await?;
    let message = &body["message"];
    let id = text(message, "messageId")?;
    let data = STANDARD
        .decode(text(message, "data")?)
        .map_err(|_| bad("invalid Pub/Sub data"))?;
    if data.len() > 262_144 {
        return Err(bad("notification too large"));
    }
    let notification: Value =
        serde_json::from_slice(&data).map_err(|_| bad("invalid Pub/Sub JSON"))?;
    let package = text(&notification, "packageName")?;
    let config = profiles()?;
    let projects: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM projects WHERE instance_id=$1")
        .bind(instance)
        .fetch_all(&st.pg)
        .await?;
    if !projects.iter().any(|id| {
        config
            .get(id)
            .and_then(|p| p.google.as_ref())
            .is_some_and(|p| p.package_name == package)
    }) {
        return Err(AppError::Forbidden);
    }
    let enabled: bool =
        sqlx::query_scalar("SELECT revenue_collection_enabled FROM instances WHERE id=$1")
            .bind(instance)
            .fetch_one(&st.pg)
            .await?;
    if !enabled {
        return Ok(Json(json!({"ignored":"revenue collection disabled"})));
    }
    sqlx::query("INSERT INTO purchase_notifications(provider,external_id,instance_id,payload) VALUES('google',$1,$2,$3) ON CONFLICT DO NOTHING").bind(id).bind(instance).bind(notification).execute(&st.pg).await?;
    Ok(Json(json!({"queued":true})))
}

pub(crate) async fn lock_chain(
    tx: &mut Transaction<'_, Postgres>,
    project: Uuid,
    provider: &str,
    original: &str,
) -> Result<(), AppError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("purchase-chain:{project}:{provider}:{original}"))
        .execute(&mut **tx)
        .await?;
    Ok(())
}
/// A later authoritative store response may bind an anonymous webhook purchase
/// to its real account. Callers must already verify the provider account binding.
pub(crate) async fn claim_anonymous_tx(
    tx: &mut Transaction<'_, Postgres>,
    project: Uuid,
    old: Uuid,
    visitor: Uuid,
    provider: &str,
    original: &str,
) -> Result<(), AppError> {
    sqlx::query("INSERT INTO visitors(project_id,id) VALUES($1,$2) ON CONFLICT DO NOTHING")
        .bind(project)
        .bind(visitor)
        .execute(&mut **tx)
        .await?;
    let link: Option<Uuid> = sqlx::query_scalar(
        "SELECT link_id FROM visitor_attributions WHERE project_id=$1 AND visitor_id=$2",
    )
    .bind(project)
    .bind(visitor)
    .fetch_optional(&mut **tx)
    .await?
    .flatten();
    sqlx::query("UPDATE verified_purchases SET visitor_id=$4,link_id=coalesce(link_id,$5) WHERE project_id=$1 AND provider=$2 AND original_transaction_id=$3 AND visitor_id=$6").bind(project).bind(provider).bind(original).bind(visitor).bind(link).bind(old).execute(&mut **tx).await?;
    sqlx::query("UPDATE purchase_ledger l SET visitor_id=$4,link_id=coalesce(l.link_id,$5) FROM verified_purchases p WHERE p.id=l.purchase_id AND p.project_id=$1 AND p.provider=$2 AND p.original_transaction_id=$3 AND l.visitor_id=$6").bind(project).bind(provider).bind(original).bind(visitor).bind(link).bind(old).execute(&mut **tx).await?;
    sqlx::query("UPDATE subscription_states SET visitor_id=$4,link_id=coalesce(link_id,$5) WHERE project_id=$1 AND provider=$2 AND original_transaction_id=$3 AND visitor_id=$6").bind(project).bind(provider).bind(original).bind(visitor).bind(link).bind(old).execute(&mut **tx).await?;
    Ok(())
}
/// Backfill attribution when a SDK/deep-link visit arrives after its purchase.
/// Existing purchase attribution remains immutable across subsequent campaigns.
pub async fn backfill_attribution(
    st: &AppState,
    project: Uuid,
    visitor: Uuid,
) -> Result<u64, AppError> {
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,42))")
        .bind(project.to_string())
        .execute(&mut *tx)
        .await?;
    let link: Option<Uuid> = sqlx::query_scalar(
        "SELECT link_id FROM visitor_attributions WHERE project_id=$1 AND visitor_id=$2",
    )
    .bind(project)
    .bind(visitor)
    .fetch_optional(&mut *tx)
    .await?
    .flatten();
    let Some(link) = link else { return Ok(0) };
    let changed=sqlx::query("UPDATE verified_purchases SET link_id=$3 WHERE project_id=$1 AND visitor_id=$2 AND attributed_link_id IS NULL").bind(project).bind(visitor).bind(link).execute(&mut *tx).await?.rows_affected();
    sqlx::query("UPDATE purchase_ledger SET link_id=$3 WHERE project_id=$1 AND visitor_id=$2 AND attributed_link_id IS NULL").bind(project).bind(visitor).bind(link).execute(&mut *tx).await?;
    sqlx::query("UPDATE subscription_states SET link_id=$3 WHERE project_id=$1 AND visitor_id=$2 AND link_id IS NULL").bind(project).bind(visitor).bind(link).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(changed)
}

pub(crate) async fn record_purchase_tx(
    tx: &mut Transaction<'_, Postgres>,
    project: Uuid,
    visitor: Uuid,
    purchase: Uuid,
    verified: &VerifiedPurchase,
) -> Result<(), AppError> {
    let attribution: Option<Uuid> = sqlx::query_scalar(
        "SELECT link_id FROM visitor_attributions WHERE project_id=$1 AND visitor_id=$2",
    )
    .bind(project)
    .bind(visitor)
    .fetch_optional(&mut **tx)
    .await?
    .flatten();
    let previous:Option<Uuid>=sqlx::query_scalar("SELECT link_id FROM subscription_states WHERE project_id=$1 AND provider=$2 AND original_transaction_id=$3").bind(project).bind(&verified.provider).bind(&verified.original_transaction_id).fetch_optional(&mut **tx).await?.flatten();
    let link = attribution.or(previous);
    sqlx::query("UPDATE verified_purchases SET link_id=$2 WHERE id=$1")
        .bind(purchase)
        .bind(link)
        .execute(&mut **tx)
        .await?;
    sqlx::query("INSERT INTO purchase_ledger(purchase_id,project_id,visitor_id,link_id,event_type,source_key,amount_nanos,quantity,currency,usd_nanos,occurred_at) VALUES($1,$2,$3,$4,'BUY','initial',$5,$6,$7,CASE WHEN $7='USD' THEN $5::numeric ELSE (SELECT round($5::numeric/units_per_usd) FROM fx_rates WHERE currency=$7) END,$8) ON CONFLICT DO NOTHING")
        .bind(purchase).bind(project).bind(visitor).bind(link).bind(verified.amount_nanos).bind(verified.quantity).bind(&verified.currency).bind(verified.purchased_at).execute(&mut **tx).await?;
    if verified.purchase_kind == "subscription" {
        // Product switches cancel the previously active product exactly once.
        sqlx::query("INSERT INTO purchase_ledger(purchase_id,project_id,visitor_id,link_id,event_type,source_key,amount_nanos,quantity,currency,usd_nanos,occurred_at) SELECT p.id,p.project_id,p.visitor_id,p.link_id,'CANCEL',$4,0,0,p.currency,0,$5 FROM subscription_states s JOIN verified_purchases p ON p.project_id=s.project_id AND p.provider=s.provider AND p.transaction_id=s.latest_transaction_id AND p.product_id=s.product_id WHERE s.project_id=$1 AND s.provider=$2 AND s.original_transaction_id=$3 AND s.product_id<>$6 AND s.status='active' AND s.last_event_at<=$5 ON CONFLICT DO NOTHING")
            .bind(project).bind(&verified.provider).bind(&verified.original_transaction_id).bind(format!("product-change:{purchase}")).bind(verified.purchased_at).bind(&verified.product_id).execute(&mut **tx).await?;
        sqlx::query("INSERT INTO subscription_states(project_id,provider,original_transaction_id,product_id,latest_transaction_id,visitor_id,link_id,expires_at,last_event_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(project_id,provider,original_transaction_id) DO UPDATE SET product_id=excluded.product_id,latest_transaction_id=excluded.latest_transaction_id,visitor_id=excluded.visitor_id,link_id=coalesce(excluded.link_id,subscription_states.link_id),expires_at=excluded.expires_at,last_event_at=excluded.last_event_at,status='active',updated_at=now() WHERE subscription_states.last_event_at<=excluded.last_event_at")
            .bind(project).bind(&verified.provider).bind(&verified.original_transaction_id).bind(&verified.product_id).bind(&verified.transaction_id).bind(visitor).bind(link).bind(verified.expires_at).bind(verified.purchased_at).execute(&mut **tx).await?;
    }
    Ok(())
}
fn apple_event(kind: &str, subtype: &str) -> Option<&'static str> {
    match kind {
        "SUBSCRIBED" | "DID_RENEW" | "ONE_TIME_CHARGE" => Some("BUY"),
        "OFFER_REDEEMED" if subtype != "DOWNGRADE" => Some("BUY"),
        "DID_CHANGE_RENEWAL_PREF" if subtype == "UPGRADE" => Some("BUY"),
        "EXPIRED" | "GRACE_PERIOD_EXPIRED" | "REVOKE" => Some("CANCEL"),
        "DID_FAIL_TO_RENEW" if !matches!(subtype, "GRACE_PERIOD" | "BILLING_RETRY") => {
            Some("CANCEL")
        }
        "REFUND" => Some("REFUND"),
        "REFUND_REVERSED" => Some("REFUND_REVERSED"),
        _ => None,
    }
}
fn google_event(kind: i64) -> Option<&'static str> {
    match kind {
        1 | 2 | 4 | 7 => Some("BUY"),
        3 | 12 | 13 | 20 => Some("CANCEL"),
        _ => None,
    }
}
struct Adjustment<'a> {
    kind: &'a str,
    source: &'a str,
    amount: Option<i64>,
    quantity: Option<i32>,
    at: DateTime<Utc>,
}
async fn append_adjustment(
    st: &AppState,
    project: Uuid,
    purchase: Uuid,
    adjustment: Adjustment<'_>,
) -> Result<(), AppError> {
    let Adjustment {
        kind,
        source,
        amount,
        quantity,
        at,
    } = adjustment;
    let cumulative = kind == "REFUND_TOTAL";
    let mut kind = if cumulative { "REFUND" } else { kind };
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,42))")
        .bind(project.to_string())
        .execute(&mut *tx)
        .await?;
    let (provider, original):(String,String)=sqlx::query_as("SELECT provider,original_transaction_id FROM verified_purchases WHERE id=$1 AND project_id=$2").bind(purchase).bind(project).fetch_one(&mut *tx).await?;
    lock_chain(&mut tx, project, &provider, &original).await?;
    sqlx::query("SELECT id FROM verified_purchases WHERE id=$1 AND project_id=$2 FOR UPDATE")
        .bind(purchase)
        .bind(project)
        .fetch_one(&mut *tx)
        .await?;
    if matches!(kind, "REFUND" | "REFUND_REVERSED") {
        let last: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT refund_updated_at FROM verified_purchases WHERE id=$1")
                .bind(purchase)
                .fetch_one(&mut *tx)
                .await?;
        if last.is_some_and(|last| last > at) {
            tx.commit().await?;
            return Ok(());
        }
        sqlx::query("UPDATE verified_purchases SET refund_updated_at=$2 WHERE id=$1")
            .bind(purchase)
            .bind(at)
            .execute(&mut *tx)
            .await?;
    }
    // Cumulative refund reversals cannot produce net revenue above original sale.
    let outstanding:Option<i64>=sqlx::query_scalar("SELECT -sum(amount_nanos)::bigint FROM purchase_ledger WHERE purchase_id=$1 AND event_type IN ('REFUND','REFUND_REVERSED')").bind(purchase).fetch_one(&mut *tx).await?;
    let base: i64 = sqlx::query_scalar("SELECT amount_nanos FROM verified_purchases WHERE id=$1")
        .bind(purchase)
        .fetch_one(&mut *tx)
        .await?;
    let base_quantity: i32 =
        sqlx::query_scalar("SELECT quantity FROM verified_purchases WHERE id=$1")
            .bind(purchase)
            .fetch_one(&mut *tx)
            .await?;
    let outstanding_quantity:Option<i64>=sqlx::query_scalar("SELECT -sum(quantity)::bigint FROM purchase_ledger WHERE purchase_id=$1 AND event_type IN ('REFUND','REFUND_REVERSED')").bind(purchase).fetch_one(&mut *tx).await?;
    let available_quantity = if kind == "REFUND" {
        i64::from(base_quantity) - outstanding_quantity.unwrap_or(0)
    } else if kind == "REFUND_REVERSED" {
        outstanding_quantity.unwrap_or(0)
    } else {
        0
    };
    let delta = if cumulative {
        amount.unwrap_or(base) - outstanding.unwrap_or(0)
    } else {
        amount.unwrap_or(base)
    };
    if cumulative && delta < 0 {
        kind = "REFUND_REVERSED";
    }
    let amount_sign = if kind == "REFUND" {
        -1_i64
    } else if kind == "REFUND_REVERSED" {
        1
    } else {
        0
    };
    let requested_quantity = if cumulative {
        (i64::from(quantity.unwrap_or(base_quantity)) - outstanding_quantity.unwrap_or(0)).abs()
    } else {
        i64::from(quantity.unwrap_or(base_quantity))
    };
    let available_quantity = if cumulative && delta < 0 {
        outstanding_quantity.unwrap_or(0)
    } else {
        available_quantity
    };
    let quantity = Some(requested_quantity.max(0).min(available_quantity.max(0)) as i32);
    let requested = delta.abs();
    let allowed = if kind == "REFUND" {
        base - outstanding.unwrap_or(0)
    } else if kind == "REFUND_REVERSED" {
        outstanding.unwrap_or(0)
    } else {
        0
    };
    let amount = requested.max(0).min(allowed.max(0));
    if kind != "CANCEL" && amount == 0 {
        tx.commit().await?;
        return Ok(());
    }
    sqlx::query("INSERT INTO purchase_ledger(purchase_id,project_id,visitor_id,link_id,event_type,source_key,amount_nanos,quantity,currency,usd_nanos,occurred_at) SELECT id,project_id,visitor_id,link_id,$3,$4,$5,CASE WHEN $3='CANCEL' THEN 0 ELSE coalesce($6,quantity)*$7 END,currency,CASE WHEN currency='USD' THEN $5::numeric WHEN amount_nanos=0 THEN 0 ELSE (SELECT round($5::numeric*usd_nanos/verified_purchases.amount_nanos) FROM purchase_ledger WHERE purchase_id=verified_purchases.id AND event_type='BUY' AND source_key='initial') END,$8 FROM verified_purchases WHERE id=$1 AND project_id=$2 ON CONFLICT DO NOTHING")
        .bind(purchase).bind(project).bind(kind).bind(source).bind(amount*amount_sign).bind(quantity).bind(amount_sign as i32).bind(at).execute(&mut *tx).await?;
    if kind == "CANCEL" {
        sqlx::query("UPDATE subscription_states s SET status='canceled',last_event_at=$3,updated_at=now() FROM verified_purchases p WHERE p.id=$1 AND p.project_id=$2 AND s.project_id=p.project_id AND s.provider=p.provider AND s.original_transaction_id=p.original_transaction_id AND s.latest_transaction_id=p.transaction_id AND s.product_id=p.product_id AND s.last_event_at<=$3").bind(purchase).bind(project).bind(at).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}
async fn process_apple(st: &AppState, project: Uuid, notification: &Value) -> Result<(), AppError> {
    let kind = text(notification, "notificationType")?;
    let subtype = notification["subtype"].as_str().unwrap_or("");
    let event = apple_event(kind, subtype);
    let Some(signed) = notification["data"]["signedTransactionInfo"].as_str() else {
        if kind == "TEST" {
            return Ok(());
        }
        return Err(bad("notification transaction missing"));
    };
    let payload = verify_apple_jws(signed)?;
    let config = profiles()?;
    let profile = config
        .get(&project)
        .and_then(|p| p.apple.as_ref())
        .ok_or(AppError::Forbidden)?;
    let environment: String = sqlx::query_scalar("SELECT environment FROM projects WHERE id=$1")
        .bind(project)
        .fetch_one(&st.pg)
        .await?;
    if payload["bundleId"].as_str() != Some(profile.bundle_id.as_str())
        || payload["environment"].as_str()
            != Some(if environment == "test" {
                "Sandbox"
            } else {
                "Production"
            })
    {
        return Err(AppError::Forbidden);
    }
    let original = text(&payload, "originalTransactionId")?;
    let visitor = payload["appAccountToken"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .filter(|id| !id.is_nil())
        .unwrap_or_else(|| anonymous("apple", original));
    let amount = payload["price"]
        .as_i64()
        .filter(|v| *v >= 0)
        .and_then(|v| v.checked_mul(1_000_000))
        .ok_or(AppError::Upstream)?;
    let verified = VerifiedPurchase {
        provider: "apple".into(),
        application_id: profile.bundle_id.clone(),
        environment,
        transaction_id: text(&payload, "transactionId")?.into(),
        original_transaction_id: original.into(),
        product_id: text(&payload, "productId")?.into(),
        purchase_kind: if payload["type"]
            .as_str()
            .is_some_and(|s| s.contains("Subscription"))
        {
            "subscription"
        } else {
            "one_time"
        }
        .into(),
        currency: text(&payload, "currency")?.into(),
        amount_nanos: amount,
        quantity: payload["quantity"]
            .as_i64()
            .and_then(|v| i32::try_from(v).ok())
            .filter(|v| *v > 0)
            .ok_or(AppError::Upstream)?,
        purchased_at: time(&payload["purchaseDate"])?,
        expires_at: payload["expiresDate"]
            .as_i64()
            .and_then(DateTime::from_timestamp_millis),
    };
    let Json(result) = purchases::persist_verified(st, project, visitor, verified).await?;
    let id = Uuid::parse_str(text(&result, "id")?).map_err(|_| AppError::Internal)?;
    let at = time(&notification["signedDate"])?;
    if let Some(event) = event
        && event != "BUY"
    {
        append_adjustment(
            st,
            project,
            id,
            Adjustment {
                kind: event,
                source: text(notification, "notificationUUID")?,
                amount: None,
                quantity: None,
                at,
            },
        )
        .await?;
    }
    if let Some(renewal) = notification["data"]["signedRenewalInfo"].as_str() {
        let renewal = verify_apple_jws(renewal)?;
        if renewal["environment"] != payload["environment"] {
            return Err(AppError::Forbidden);
        }
        sqlx::query("UPDATE subscription_states SET auto_renew=$4,expires_at=coalesce($5,expires_at),last_event_at=greatest(last_event_at,$6),updated_at=now() WHERE project_id=$1 AND provider='apple' AND original_transaction_id=$2 AND product_id=$3 AND last_event_at<=$6").bind(project).bind(original).bind(text(&payload,"productId")?).bind(renewal["autoRenewStatus"].as_i64().map(|v|v==1)).bind(renewal["renewalDate"].as_i64().and_then(DateTime::from_timestamp_millis)).bind(at).execute(&st.pg).await?;
    }
    sqlx::query("INSERT INTO purchase_reconciliation(project_id,provider,original_transaction_id,product_id,available_at) VALUES($1,'apple',$2,$3,now()+interval '1 day') ON CONFLICT(project_id,provider,original_transaction_id) DO NOTHING").bind(project).bind(original).bind(text(&payload,"productId")?).execute(&st.pg).await?;
    Ok(())
}
fn google_project(
    projects: &[(Uuid, String)],
    config: &HashMap<Uuid, Profile>,
    package: &str,
    test: bool,
) -> Result<Uuid, AppError> {
    projects
        .iter()
        .find(|(id, env)| {
            (env == "test") == test
                && config
                    .get(id)
                    .and_then(|p| p.google.as_ref())
                    .is_some_and(|p| p.package_name == package)
        })
        .map(|(id, _)| *id)
        .ok_or(AppError::NotFound)
}
async fn process_google(
    st: &AppState,
    instance: Uuid,
    notification: &Value,
    source: &str,
) -> Result<(), AppError> {
    if notification["testNotification"].is_object() {
        return Ok(());
    }
    let package = text(notification, "packageName")?;
    let config = profiles()?;
    let projects: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id,environment FROM projects WHERE instance_id=$1")
            .bind(instance)
            .fetch_all(&st.pg)
            .await?;
    let available = projects
        .iter()
        .find_map(|(id, _)| {
            config
                .get(id)
                .and_then(|p| p.google.as_ref())
                .filter(|p| p.package_name == package)
        })
        .ok_or(AppError::Forbidden)?;
    let token = purchases::google_token(available).await?;
    let client = purchases::http_client()?;
    let base = "https://androidpublisher.googleapis.com";
    let (sub, one, voided) = (
        &notification["subscriptionNotification"],
        &notification["oneTimeProductNotification"],
        &notification["voidedPurchaseNotification"],
    );
    let purchase_token = sub["purchaseToken"]
        .as_str()
        .or_else(|| one["purchaseToken"].as_str())
        .or_else(|| voided["purchaseToken"].as_str())
        .ok_or_else(|| bad("missing purchase token"))?;
    let is_subscription = sub.is_object() || voided["productType"].as_i64() == Some(1);
    let product_hint = sub["subscriptionId"]
        .as_str()
        .or_else(|| one["sku"].as_str())
        .unwrap_or("");
    let purchase = if is_subscription {
        purchases::fetch_json(
            &client,
            purchases::endpoint(
                base,
                &[
                    "androidpublisher",
                    "v3",
                    "applications",
                    package,
                    "purchases",
                    "subscriptionsv2",
                    "tokens",
                    purchase_token,
                ],
            )?,
            &token,
        )
        .await?
    } else {
        purchases::fetch_json(
            &client,
            purchases::endpoint(
                base,
                &[
                    "androidpublisher",
                    "v3",
                    "applications",
                    package,
                    "purchases",
                    "productsv2",
                    "tokens",
                    purchase_token,
                ],
            )?,
            &token,
        )
        .await?
    };
    let test = if is_subscription {
        purchase["testPurchase"].is_object()
    } else {
        purchase["testPurchaseContext"].is_object()
    };
    let project = google_project(&projects, &config, package, test)?;
    let order_id = voided["orderId"]
        .as_str()
        .or_else(|| purchase["orderId"].as_str())
        .or_else(|| purchase["lineItems"][0]["latestSuccessfulOrderId"].as_str())
        .or_else(|| purchase["latestOrderId"].as_str())
        .ok_or_else(|| bad("verified purchase has no order"))?;
    let order = purchases::fetch_json(
        &client,
        purchases::endpoint(
            base,
            &[
                "androidpublisher",
                "v3",
                "applications",
                package,
                "orders",
                order_id,
            ],
        )?,
        &token,
    )
    .await?;
    if order["purchaseToken"].as_str() != Some(purchase_token) {
        return Err(AppError::Forbidden);
    }
    let visitor = purchase["externalAccountIdentifiers"]["obfuscatedExternalAccountId"]
        .as_str()
        .or_else(|| purchase["obfuscatedExternalAccountId"].as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .filter(|v| !v.is_nil())
        .unwrap_or_else(|| anonymous("google", purchase_token));
    let items = order["lineItems"].as_array().ok_or(AppError::Upstream)?;
    let mut purchase_ids = Vec::new();
    let total = purchases::money_nanos(&order["total"])?.1;
    for item in items {
        let product = text(item, "productId")?;
        let (currency, amount) = purchases::money_nanos(if item["total"].is_object() {
            &item["total"]
        } else if items.len() == 1 {
            &order["total"]
        } else {
            return Err(AppError::Upstream);
        })?;
        let quantity = if item["subscriptionDetails"].is_object() {
            1
        } else {
            item["oneTimePurchaseDetails"]["quantity"]
                .as_i64()
                .and_then(|v| i32::try_from(v).ok())
                .filter(|v| *v > 0)
                .ok_or(AppError::Upstream)?
        };
        if matches!(
            order["state"].as_str(),
            Some("PENDING" | "CANCELED" | "CANCELLED")
        ) {
            continue;
        }
        if !matches!(
            order["state"].as_str(),
            Some("PROCESSED" | "REFUNDED" | "PARTIALLY_REFUNDED")
        ) {
            return Err(AppError::Upstream);
        }
        let verified = VerifiedPurchase {
            provider: "google".into(),
            application_id: package.into(),
            environment: if test { "test" } else { "production" }.into(),
            transaction_id: order_id.into(),
            original_transaction_id: purchase_token.into(),
            product_id: product.into(),
            purchase_kind: if is_subscription {
                "subscription"
            } else {
                purchases::google_product_kind(&purchase, product)
            }
            .into(),
            currency,
            amount_nanos: amount,
            quantity,
            purchased_at: DateTime::parse_from_rfc3339(text(&order, "createTime")?)
                .map_err(|_| AppError::Upstream)?
                .with_timezone(&Utc),
            expires_at: item["subscriptionDetails"]["servicePeriodEndTime"]
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc)),
        };
        let Json(result) = purchases::persist_verified(st, project, visitor, verified).await?;
        let id = Uuid::parse_str(text(&result, "id")?).map_err(|_| AppError::Internal)?;
        purchase_ids.push((id, amount, quantity, product.to_owned()));
        if is_subscription
            && google_event(sub["notificationType"].as_i64().unwrap_or(0)) == Some("CANCEL")
        {
            append_adjustment(
                st,
                project,
                id,
                Adjustment {
                    kind: "CANCEL",
                    source,
                    amount: None,
                    quantity: None,
                    at: Utc::now(),
                },
            )
            .await?;
        }
    }
    // Refund totals come exclusively from the authoritative Orders API; distribute
    // bundle refunds across verified line totals while preserving the exact sum.
    let history = &order["orderHistory"];
    let mut refund = 0_i64;
    if let Some(partials) = history["partialRefundEvents"].as_array() {
        for part in partials {
            if part["state"].as_str() == Some("PROCESSED_SUCCESSFULLY") {
                refund = refund
                    .checked_add(purchases::money_nanos(&part["refundDetails"]["total"])?.1)
                    .ok_or(AppError::Upstream)?;
            }
        }
    }
    if order["state"].as_str() == Some("REFUNDED") {
        refund = total;
    } else if history["refundEvent"].is_object() {
        refund = refund
            .checked_add(
                purchases::money_nanos(&history["refundEvent"]["refundDetails"]["total"])?.1,
            )
            .ok_or(AppError::Upstream)?;
    }
    let mut assigned = 0_i64;
    let last = purchase_ids.len().saturating_sub(1);
    for (index, (id, amount, quantity, product)) in purchase_ids.iter().enumerate() {
        let refundable = purchase["productLineItem"]
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .find(|line| line["productId"].as_str() == Some(product))
            })
            .and_then(|line| line["productOfferDetails"]["refundableQuantity"].as_i64());
        let quantity_refund = refundable.map(|remaining| {
            (i64::from(*quantity) - remaining)
                .max(0)
                .min(i64::from(*quantity)) as i32
        });
        let desired = if voided["refundType"].as_i64() == Some(2) {
            match quantity_refund {
                Some(q) if *quantity > 0 => {
                    ((*amount as i128) * i128::from(q) / i128::from(*quantity)) as i64
                }
                _ => return Err(AppError::Upstream),
            }
        } else if index == last {
            refund - assigned
        } else if total > 0 {
            ((refund as i128) * (*amount as i128) / (total as i128)) as i64
        } else {
            0
        };
        assigned += desired;
        let q = if order["state"].as_str() == Some("REFUNDED") {
            *quantity
        } else if let Some(q) = quantity_refund {
            q
        } else if *amount > 0 {
            (((*quantity as i128) * (desired as i128) + (*amount as i128) - 1) / (*amount as i128))
                as i32
        } else {
            0
        };
        append_adjustment(
            st,
            project,
            *id,
            Adjustment {
                kind: "REFUND_TOTAL",
                source: &format!("{source}:{desired}"),
                amount: Some(desired),
                quantity: Some(q),
                at: Utc::now(),
            },
        )
        .await?;
    }
    if is_subscription {
        let status = purchase["subscriptionState"]
            .as_str()
            .unwrap_or("SUBSCRIPTION_STATE_UNSPECIFIED")
            .trim_start_matches("SUBSCRIPTION_STATE_")
            .to_ascii_lowercase();
        let auto_renew = purchase["lineItems"][0]["autoRenewingPlan"]["autoRenewEnabled"].as_bool();
        let expires = purchase["lineItems"][0]["expiryTime"]
            .as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc));
        sqlx::query("UPDATE subscription_states SET status=$4,auto_renew=$5,expires_at=coalesce($6,expires_at),updated_at=now() WHERE project_id=$1 AND provider='google' AND original_transaction_id=$2 AND product_id=$3").bind(project).bind(purchase_token).bind(product_hint).bind(&status).bind(auto_renew).bind(expires).execute(&st.pg).await?;
        if matches!(status.as_str(), "expired" | "pending_purchase_canceled") {
            for (id, _, _, _) in &purchase_ids {
                append_adjustment(
                    st,
                    project,
                    *id,
                    Adjustment {
                        kind: "CANCEL",
                        source: &format!("state:{status}:{order_id}"),
                        amount: None,
                        quantity: None,
                        at: Utc::now(),
                    },
                )
                .await?;
            }
        }
    }
    let acknowledge =
        purchase["acknowledgementState"].as_str() == Some("ACKNOWLEDGEMENT_STATE_PENDING");
    if acknowledge && !product_hint.is_empty() {
        let path = if is_subscription {
            "subscriptions"
        } else {
            "products"
        };
        let mut url = purchases::endpoint(
            base,
            &[
                "androidpublisher",
                "v3",
                "applications",
                package,
                "purchases",
                path,
                product_hint,
                "tokens",
                purchase_token,
            ],
        )?;
        let final_path = format!("{}:acknowledge", url.path());
        url.set_path(&final_path);
        client
            .post(url)
            .bearer_auth(&token)
            .json(&json!({}))
            .send()
            .await
            .map_err(|_| AppError::Upstream)?
            .error_for_status()
            .map_err(|_| AppError::Upstream)?;
    }
    sqlx::query("INSERT INTO purchase_reconciliation(project_id,provider,original_transaction_id,purchase_token,product_id,purchase_kind,available_at) VALUES($1,'google',$2,$2,$3,$4,now()+interval '1 day') ON CONFLICT(project_id,provider,original_transaction_id) DO UPDATE SET purchase_token=excluded.purchase_token,product_id=excluded.product_id").bind(project).bind(purchase_token).bind(product_hint).bind(if is_subscription{"subscription"}else{"one_time"}).execute(&st.pg).await?;
    Ok(())
}

pub async fn process_pending(st: &AppState, limit: i64) -> Result<u64, AppError> {
    let mut count = 0;
    for _ in 0..limit.clamp(1, 100) {
        let mut tx = st.pg.begin().await?;
        let row=sqlx::query("SELECT id,provider,instance_id,project_id,payload,external_id FROM purchase_notifications WHERE processed_at IS NULL AND available_at<=now() ORDER BY received_at FOR UPDATE SKIP LOCKED LIMIT 1").fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            break;
        };
        let id: Uuid = row.get("id");
        let provider: String = row.get("provider");
        let payload: Value = row.get("payload");
        let result = if provider == "apple" {
            process_apple(st, row.get("project_id"), &payload).await
        } else {
            process_google(
                st,
                row.get("instance_id"),
                &payload,
                row.get::<String, _>("external_id").as_str(),
            )
            .await
        };
        match result {
            Ok(()) => {
                sqlx::query("UPDATE purchase_notifications SET processed_at=now(),last_error=NULL WHERE id=$1").bind(id).execute(&mut *tx).await?;
                count += 1;
            }
            Err(_) => {
                sqlx::query("UPDATE purchase_notifications SET attempts=attempts+1,available_at=now()+make_interval(secs=>least(86400,30*power(2,least(attempts,11)))::int),last_error='verification or processing failed; retry scheduled' WHERE id=$1").bind(id).execute(&mut *tx).await?;
            }
        }
        tx.commit().await?;
    }
    Ok(count)
}
pub async fn refresh_fx(st: &AppState) -> Result<u64, AppError> {
    let fresh:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM fx_rates WHERE currency<>'USD' AND fetched_at>now()-interval '1 hour')").fetch_one(&st.pg).await?;
    if fresh {
        return Ok(0);
    }
    let client = purchases::http_client()?;
    let mut rates = None;
    for url in [
        "https://open.exchangerate-api.com/v6/latest/USD",
        "https://api.frankfurter.dev/v1/latest?base=USD",
    ] {
        if let Ok(response) = client.get(url).send().await
            && response.status().is_success()
            && let Ok(value) = response.json::<Value>().await
            && value["rates"].is_object()
        {
            rates = Some(value["rates"].clone());
            break;
        }
    }
    let Some(rates) = rates else {
        return Err(AppError::Upstream);
    };
    let mut count = 0;
    let mut tx = st.pg.begin().await?;
    for (currency, rate) in rates.as_object().ok_or(AppError::Upstream)? {
        if currency.len() != 3
            || !currency.bytes().all(|b| b.is_ascii_uppercase())
            || rate.as_f64().is_none_or(|r| !r.is_finite() || r <= 0.0)
        {
            continue;
        }
        sqlx::query("INSERT INTO fx_rates(currency,units_per_usd) VALUES($1,$2::text::numeric) ON CONFLICT(currency) DO UPDATE SET units_per_usd=excluded.units_per_usd,fetched_at=now()").bind(currency).bind(rate.to_string()).execute(&mut *tx).await?;
        count += 1;
    }
    sqlx::query("UPDATE purchase_ledger l SET usd_nanos=round(l.amount_nanos::numeric/f.units_per_usd) FROM fx_rates f WHERE l.currency=f.currency AND l.usd_nanos IS NULL").execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(count)
}
pub async fn reconcile_due(st: &AppState, limit: i64) -> Result<u64, AppError> {
    let rows=sqlx::query("SELECT r.*,p.instance_id,p.environment FROM purchase_reconciliation r JOIN projects p ON p.id=r.project_id WHERE r.available_at<=now() ORDER BY r.available_at LIMIT $1").bind(limit.clamp(1,100)).fetch_all(&st.pg).await?;
    if rows.is_empty() {
        return Ok(0);
    }
    let config = profiles()?;
    let mut count = 0;
    for row in rows {
        let project: Uuid = row.get("project_id");
        let provider: String = row.get("provider");
        let original: String = row.get("original_transaction_id");
        let environment: String = row.get("environment");
        let instance: Uuid = row.get("instance_id");
        let result=async {
            let profile=config.get(&project).ok_or(AppError::Forbidden)?;
            if provider=="apple" {
                let apple=profile.apple.as_ref().ok_or(AppError::Forbidden)?;
                let token=purchases::apple_token(apple).await?;
                let base=if environment=="test"{"https://api.storekit-sandbox.apple.com"}else{"https://api.storekit.apple.com"};
                let client=purchases::http_client()?;let mut revision:Option<String>=None;
                for _ in 0..1000 {
                    let mut url=purchases::endpoint(base,&["inApps","v2","history",&original])?;
                    if let Some(revision)=&revision{url.query_pairs_mut().append_pair("revision",revision);}
                    let response=purchases::fetch_json(&client,url,&token).await?;
                    let signed=response["signedTransactions"].as_array().ok_or(AppError::Upstream)?;
                    for value in signed {
                        let compact=value.as_str().ok_or(AppError::Upstream)?;let payload=verify_apple_jws(compact)?;
                        let event=if !payload["revocationDate"].is_null(){"REFUND"}else{"DID_RENEW"};
                        let notification=json!({"notificationType":event,"notificationUUID":format!("reconcile:{}:{}",text(&payload,"transactionId")?,event),"signedDate":Utc::now().timestamp_millis(),"data":{"signedTransactionInfo":compact}});
                        process_apple(st,project,&notification).await?;
                        if payload["revocationDate"].is_null(){
                            let id:Option<Uuid>=sqlx::query_scalar("SELECT id FROM verified_purchases WHERE project_id=$1 AND provider='apple' AND transaction_id=$2 AND product_id=$3").bind(project).bind(text(&payload,"transactionId")?).bind(text(&payload,"productId")?).fetch_optional(&st.pg).await?;
                            if let Some(id)=id{append_adjustment(st, project, id, Adjustment{kind:"REFUND_REVERSED", source:&format!("reconcile-reversal:{id}"), amount:None, quantity:None, at:Utc::now()}).await?;}
                        }
                    }
                    if response["hasMore"].as_bool()!=Some(true){
                        let expired:Option<(Uuid,DateTime<Utc>)>=sqlx::query_as("SELECT p.id,s.expires_at FROM subscription_states s JOIN verified_purchases p ON p.project_id=s.project_id AND p.provider=s.provider AND p.transaction_id=s.latest_transaction_id AND p.product_id=s.product_id WHERE s.project_id=$1 AND s.provider='apple' AND s.original_transaction_id=$2 AND s.expires_at<=now()").bind(project).bind(&original).fetch_optional(&st.pg).await?;
                        if let Some((id,at))=expired{append_adjustment(st, project, id, Adjustment{kind:"CANCEL", source:&format!("reconcile-expiry:{id}"), amount:None, quantity:None, at}).await?;}
                        return Ok(());
                    }
                    revision=Some(text(&response,"revision")?.to_owned());
                }
                return Err(AppError::Upstream);
            }else {
                let google=profile.google.as_ref().ok_or(AppError::Forbidden)?;let product:String=row.get("product_id");let token:String=row.get("purchase_token");let kind:String=row.get("purchase_kind");
                let notification=if kind=="subscription"{json!({"packageName":google.package_name,"subscriptionNotification":{"purchaseToken":token,"subscriptionId":product,"notificationType":2}})}else{json!({"packageName":google.package_name,"oneTimeProductNotification":{"purchaseToken":token,"sku":product,"notificationType":1}})};
                process_google(st,instance,&notification,&format!("reconcile:{original}:{}",Utc::now().format("%Y-%m-%d"))).await?;
            }
            Ok::<(),AppError>(())
        }.await;
        if result.is_ok() {
            sqlx::query("UPDATE purchase_reconciliation SET available_at=now()+interval '1 day',attempts=0,last_error=NULL WHERE project_id=$1 AND provider=$2 AND original_transaction_id=$3").bind(project).bind(&provider).bind(&original).execute(&st.pg).await?;
            count += 1;
        } else {
            sqlx::query("UPDATE purchase_reconciliation SET available_at=now()+interval '1 hour',attempts=attempts+1,last_error='provider reconciliation failed' WHERE project_id=$1 AND provider=$2 AND original_transaction_id=$3").bind(project).bind(&provider).bind(&original).execute(&st.pg).await?;
        }
    }
    Ok(count)
}

pub async fn revenue_metrics(
    st: &AppState,
    project: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    platform: Option<&str>,
) -> Result<Value, AppError> {
    if from >= to {
        return Err(bad("invalid revenue range"));
    }
    let platform = match platform {
        Some("apple") => Some("ios"),
        Some("google") => Some("android"),
        other => other,
    };
    let mut tx = st.pg.begin().await?;
    sqlx::query("SET LOCAL statement_timeout='15s'")
        .execute(&mut *tx)
        .await?;
    let row=sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('revenue',coalesce(sum(l.usd_nanos),0)/1000000000,'revenue_usd_nanos',coalesce(sum(l.usd_nanos),0)::text,'units_sold',coalesce(sum(CASE WHEN l.event_type IN ('BUY','REFUND','REFUND_REVERSED') THEN l.quantity ELSE 0 END),0),'cancellations',count(*) FILTER(WHERE l.event_type='CANCEL'),'paying_users',count(DISTINCT l.visitor_id) FILTER(WHERE l.event_type IN ('BUY','REFUND_REVERSED')),'first_time_purchases',count(DISTINCT l.visitor_id) FILTER(WHERE l.event_type='BUY' AND NOT EXISTS(SELECT 1 FROM verified_purchases prev WHERE prev.project_id=p.project_id AND prev.visitor_id=p.visitor_id AND prev.purchased_at<p.purchased_at)),'unconverted_transactions',count(*) FILTER(WHERE l.usd_nanos IS NULL)) FROM purchase_ledger l JOIN verified_purchases p ON p.id=l.purchase_id WHERE l.project_id=$1 AND l.occurred_at>=$2 AND l.occurred_at<$3 AND ($4::text IS NULL OR p.platform=$4)").bind(project).bind(from).bind(to).bind(platform).fetch_one(&mut *tx).await?;
    let currency=sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('currency',l.currency,'net_amount_nanos',sum(l.amount_nanos)::text) FROM purchase_ledger l JOIN verified_purchases p ON p.id=l.purchase_id WHERE l.project_id=$1 AND l.occurred_at>=$2 AND l.occurred_at<$3 AND ($4::text IS NULL OR p.platform=$4) GROUP BY l.currency ORDER BY l.currency").bind(project).bind(from).bind(to).bind(platform).fetch_all(&mut *tx).await?;
    let series=sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('date',(l.occurred_at AT TIME ZONE 'UTC')::date,'revenue_usd_nanos',coalesce(sum(l.usd_nanos),0)::text,'units_sold',sum(l.quantity)) FROM purchase_ledger l JOIN verified_purchases p ON p.id=l.purchase_id WHERE l.project_id=$1 AND l.occurred_at>=$2 AND l.occurred_at<$3 AND ($4::text IS NULL OR p.platform=$4) GROUP BY (l.occurred_at AT TIME ZONE 'UTC')::date ORDER BY (l.occurred_at AT TIME ZONE 'UTC')::date").bind(project).bind(from).bind(to).bind(platform).fetch_all(&mut *tx).await?;
    let mut result = row;
    result["by_currency"] = json!(currency);
    result["daily_series"] = json!(series);
    tx.commit().await?;
    Ok(result)
}
async fn retry(
    State(st): State<AppState>,
    user: AuthUser,
    Path((project, id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Value>, AppError> {
    authorize_project(&st, &user, project, true).await?;
    let count=sqlx::query("UPDATE purchase_notifications SET available_at=now(),last_error=NULL WHERE id=$1 AND project_id=$2 AND processed_at IS NULL").bind(id).bind(project).execute(&st.pg).await?.rows_affected();
    if count == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Json(json!({"queued":true})))
}
async fn status(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
) -> Result<Json<Value>, AppError> {
    authorize_project(&st, &user, project, false).await?;
    let rows=sqlx::query_scalar::<_,Value>("SELECT to_jsonb(s) FROM subscription_states s WHERE project_id=$1 ORDER BY updated_at DESC LIMIT 1000").bind(project).fetch_all(&st.pg).await?;
    Ok(Json(json!({"subscriptions":rows})))
}
/// Render only operator-controlled public values; quote every value as shell data.
/// Request Host and arbitrary script parameters never enter this template.
pub fn google_setup_script(
    origin: &str,
    instance: Uuid,
    audience: Option<&str>,
    service_account: Option<&str>,
) -> Result<String, AppError> {
    let mut base = url::Url::parse(origin).map_err(|_| bad("invalid public origin"))?;
    if base.scheme() != "https"
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
        || !matches!(base.path(), "" | "/")
        || base.query().is_some()
        || base.fragment().is_some()
        || origin.chars().any(char::is_control)
    {
        return Err(bad(
            "public origin must be an HTTPS origin without credentials",
        ));
    }
    base.set_path(&format!("/api/v1/iap/google/{instance}"));
    let endpoint = base.as_str();
    let audience = audience.unwrap_or(endpoint);
    if audience.is_empty() || audience.len() > 2048 || audience.chars().any(char::is_control) {
        return Err(bad("invalid Google push audience"));
    }
    let account = service_account.unwrap_or("");
    if !account.is_empty() {
        let (name, domain) = account
            .split_once('@')
            .ok_or_else(|| bad("invalid Google push service account"))?;
        let project = domain
            .strip_suffix(".iam.gserviceaccount.com")
            .ok_or_else(|| bad("invalid Google push service account"))?;
        if !(6..=30).contains(&name.len())
            || !(6..=30).contains(&project.len())
            || !name
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            || !project
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            || !name.as_bytes()[0].is_ascii_lowercase()
            || !project.as_bytes()[0].is_ascii_lowercase()
            || name.ends_with('-')
            || project.ends_with('-')
        {
            return Err(bad("invalid Google push service account"));
        }
    }
    let quote = |value: &str| format!("'{}'", value.replace('\'', "'\"'\"'"));
    let instance_text = instance.to_string();
    let mut script = String::new();
    for (index, part) in include_str!("google_play_setup.sh").split("@@").enumerate() {
        if index % 2 == 0 {
            script.push_str(part);
        } else {
            script.push_str(&quote(match part {
                "ENDPOINT" => endpoint,
                "AUDIENCE" => audience,
                "ACCOUNT" => account,
                "INSTANCE" => &instance_text,
                _ => return Err(AppError::Internal),
            }));
        }
    }
    Ok(script)
}
async fn download_google_setup(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
) -> Result<impl axum::response::IntoResponse, AppError> {
    crate::enterprise::require_enterprise(&st)?;
    let instance = authorize_project(&st, &user, project, true).await?;
    let origin = std::env::var("TRISIXT_PUBLIC_BASE_URL")
        .unwrap_or_else(|_| format!("https://{}", st.config.server_host));
    let audience = std::env::var("GOOGLE_PUBSUB_AUDIENCE").ok();
    let account = std::env::var("GOOGLE_PUBSUB_SERVICE_ACCOUNT_EMAIL").ok();
    let script = google_setup_script(&origin, instance, audience.as_deref(), account.as_deref())?;
    Ok((
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/x-shellscript; charset=utf-8",
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"trisixt_android_gcloud_setup.sh\"",
            ),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        script,
    ))
}
pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/projects/{id}/purchases/google_configuration_script",
            get(download_google_setup),
        )
        .route("/api/v1/sdk/add_payment_event", post(reported_purchase))
        .route(
            "/api/v1/iap/apple/{environment}/{project_id}",
            post(apple_webhook),
        )
        .route("/api/v1/iap/google/{instance_id}", post(google_webhook))
        .route("/api/v1/projects/{id}/purchases/subscriptions", get(status))
        .route(
            "/api/v1/projects/{id}/purchases/notifications/{notification_id}/retry",
            post(retry),
        )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportedPurchase {
    visitor_id: Uuid,
    transaction_id: String,
    product_id: String,
    currency: String,
    price_cents: i64,
    #[serde(default = "one")]
    quantity: i32,
    #[serde(default)]
    store: bool,
    #[serde(default = "buy")]
    event_type: String,
    #[serde(default)]
    purchase_kind: Option<String>,
    #[serde(default)]
    original_transaction_id: Option<String>,
    #[serde(default)]
    date: Option<DateTime<Utc>>,
    #[serde(default)]
    device_id: Option<Uuid>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    platform: Option<String>,
}
fn one() -> i32 {
    1
}
fn buy() -> String {
    "BUY".into()
}
async fn reported_purchase(
    State(st): State<AppState>,
    sdk: crate::auth::SdkProject,
    Json(mut body): Json<ReportedPurchase>,
) -> Result<Json<Value>, AppError> {
    let project = sdk.id;
    body.platform = Some(sdk.platform(body.platform.as_deref(), "other")?.to_owned());
    if !st.config.ee_enabled {
        return Err(AppError::Forbidden);
    }
    if body.store {
        return Err(bad("store purchases require /api/v1/sdk/purchases/verify"));
    }
    if body.visitor_id.is_nil()
        || body.price_cents < 0
        || body.quantity <= 0
        || body
            .platform
            .as_deref()
            .is_some_and(|p| !matches!(p, "ios" | "android" | "web" | "desktop" | "other"))
        || body.device_id.is_some_and(|id| id.is_nil())
        || body
            .session_id
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > 200)
        || body.currency.len() != 3
        || !body.currency.bytes().all(|b| b.is_ascii_uppercase())
        || !matches!(
            body.event_type.as_str(),
            "BUY" | "REFUND" | "REFUND_REVERSED" | "CANCEL"
        )
    {
        return Err(bad("invalid reported purchase"));
    }
    for value in [&body.transaction_id, &body.product_id] {
        if value.is_empty() || value.len() > 255 {
            return Err(bad("invalid transaction or product id"));
        }
    }
    let enabled:bool=sqlx::query_scalar("SELECT i.revenue_collection_enabled FROM instances i JOIN projects p ON p.instance_id=i.id WHERE p.id=$1").bind(project).fetch_one(&st.pg).await?;
    if !enabled {
        return Ok(Json(json!({"ignored":"revenue collection disabled"})));
    }
    let visitor = crate::sdk::canonical(&st, project, body.visitor_id).await?;
    let environment: String = sqlx::query_scalar("SELECT environment FROM projects WHERE id=$1")
        .bind(project)
        .fetch_one(&st.pg)
        .await?;
    let amount = body
        .price_cents
        .checked_mul(body.quantity as i64)
        .and_then(|v| v.checked_mul(10_000_000))
        .ok_or_else(|| bad("purchase amount overflow"))?;
    let at = body.date.unwrap_or_else(Utc::now);
    if at > Utc::now() + chrono::Duration::minutes(5) {
        return Err(bad("purchase timestamp is in future"));
    }
    let kind = body.purchase_kind.as_deref().unwrap_or("one_time");
    if !matches!(kind, "one_time" | "subscription") {
        return Err(bad("invalid purchase kind"));
    }
    let (id, mut result) = if body.event_type == "BUY" {
        let verified = VerifiedPurchase {
            provider: "reported".into(),
            application_id: project.to_string(),
            environment,
            transaction_id: body.transaction_id.clone(),
            original_transaction_id: body
                .original_transaction_id
                .clone()
                .unwrap_or_else(|| body.transaction_id.clone()),
            product_id: body.product_id.clone(),
            purchase_kind: kind.into(),
            currency: body.currency.clone(),
            amount_nanos: amount,
            quantity: body.quantity,
            purchased_at: at,
            expires_at: None,
        };
        let Json(result) = purchases::persist_verified(&st, project, visitor, verified).await?;
        (
            Uuid::parse_str(text(&result, "id")?).map_err(|_| AppError::Internal)?,
            result,
        )
    } else {
        let id:Uuid=sqlx::query_scalar("SELECT id FROM verified_purchases WHERE project_id=$1 AND provider='reported' AND visitor_id=$2 AND product_id=$3 AND currency=$4 AND (transaction_id=$5 OR original_transaction_id=$6) ORDER BY (transaction_id=$5) DESC,purchased_at DESC LIMIT 1")
            .bind(project).bind(visitor).bind(&body.product_id).bind(&body.currency).bind(&body.transaction_id).bind(body.original_transaction_id.as_deref().unwrap_or(&body.transaction_id)).fetch_optional(&st.pg).await?.ok_or_else(||AppError::Conflict("original purchase must be recorded before an adjustment".into()))?;
        append_adjustment(
            &st,
            project,
            id,
            Adjustment {
                kind: &body.event_type,
                source: &format!("reported:{}:{}", body.transaction_id, body.event_type),
                amount: Some(amount),
                quantity: Some(body.quantity),
                at,
            },
        )
        .await?;
        (id, json!({"id":id}))
    };
    attach_metadata(
        &st,
        project,
        id,
        body.device_id,
        body.session_id.as_deref(),
        body.platform.as_deref(),
    )
    .await?;
    result["id"] = json!(id);
    result["verified"] = json!(false);
    result["source"] = json!("sdk_reported");
    Ok(Json(result))
}

/// First known device/session wins; provider webhook updates never erase it.
pub(crate) async fn attach_metadata(
    st: &AppState,
    project: Uuid,
    id: Uuid,
    device: Option<Uuid>,
    session: Option<&str>,
    platform: Option<&str>,
) -> Result<(), AppError> {
    if device.is_some_and(|v| v.is_nil()) || session.is_some_and(|v| v.is_empty() || v.len() > 200)
    {
        return Err(bad("invalid device or session id"));
    }
    sqlx::query("UPDATE verified_purchases SET device_id=coalesce(device_id,$3),session_id=coalesce(session_id,$4),platform=CASE WHEN platform='other' THEN coalesce($5,platform) ELSE platform END WHERE project_id=$1 AND id=$2").bind(project).bind(id).bind(device).bind(session).bind(platform).execute(&st.pg).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AnalyticsBackend, Config, StorageBackend};
    use sqlx::{PgPool, postgres::PgPoolOptions};
    use std::sync::Arc;
    async fn fixture() -> (AppState, PgPool, String) {
        let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL required");
        let admin = PgPool::connect(&url).await.unwrap();
        let schema = format!("test_lifecycle_internal_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        let path = format!("SET search_path TO {schema}");
        let pool = PgPoolOptions::new()
            .after_connect(move |conn, _| {
                let path = path.clone();
                Box::pin(async move {
                    sqlx::query(sqlx::AssertSqlSafe(path)).execute(conn).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let st = AppState {
            pg: pool,
            config: Arc::new(Config {
                env: "test".into(),
                host: "127.0.0.1".into(),
                port: 0,
                server_host: "example.test".into(),
                database_url: url,
                redis_url: "redis://127.0.0.1:56386".into(),
                ee_enabled: true,
                analytics_backend: AnalyticsBackend::ClickHouse,
                storage_backend: StorageBackend::S3,
                storage_region: None,
                storage_bucket: None,
                clickhouse_url: None,
                pubsub_topic: None,
                bigquery_dataset: None,
                gcs_credentials: None,
            }),
        };
        (st, admin, schema)
    }

    #[test]
    fn google_environment_routing_also_requires_the_configured_package() {
        let prod = Uuid::new_v4();
        let sandbox = Uuid::new_v4();
        let projects = vec![(prod, "production".into()), (sandbox, "test".into())];
        let profiles: HashMap<Uuid, Profile> = serde_json::from_value(json!({
            prod.to_string():{"google":{"package_name":"com.production.app"}},
            sandbox.to_string():{"google":{"package_name":"com.test.app"}}
        }))
        .unwrap();
        assert_eq!(
            google_project(&projects, &profiles, "com.production.app", false).unwrap(),
            prod
        );
        assert_eq!(
            google_project(&projects, &profiles, "com.test.app", true).unwrap(),
            sandbox
        );
        assert!(google_project(&projects, &profiles, "com.production.app", true).is_err());
        assert!(google_project(&projects, &profiles, "com.test.app", false).is_err());
    }
    #[test]
    fn provider_notifications_map_only_actual_revenue_and_cancellation_events() {
        assert_eq!(apple_event("DID_CHANGE_RENEWAL_PREF", "DOWNGRADE"), None);
        assert_eq!(
            apple_event("DID_CHANGE_RENEWAL_PREF", "UPGRADE"),
            Some("BUY")
        );
        assert_eq!(apple_event("DID_FAIL_TO_RENEW", "GRACE_PERIOD"), None);
        assert_eq!(apple_event("REFUND_REVERSED", ""), Some("REFUND_REVERSED"));
        for kind in [1, 2, 4, 7] {
            assert_eq!(google_event(kind), Some("BUY"));
        }
        for kind in [3, 12, 13, 20] {
            assert_eq!(google_event(kind), Some("CANCEL"));
        }
        for kind in [5, 6, 8, 9, 10, 11, 19] {
            assert_eq!(google_event(kind), None);
        }
    }
    #[test]
    fn forged_apple_jws_and_untrusted_certificate_roots_are_rejected() {
        assert!(verify_apple_jws("invalid").is_err());
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.x5c = Some(vec![
            STANDARD.encode(include_bytes!("apple-root-ca-g3.der"));
            3
        ]);
        let key = jsonwebtoken::EncodingKey::from_ec_pem(include_bytes!(
            "../tests/fixtures/apple-test-key.p8"
        ))
        .unwrap();
        let token = jsonwebtoken::encode(
            &header,
            &json!({"signedDate":Utc::now().timestamp_millis()}),
            &key,
        )
        .unwrap();
        assert!(verify_apple_jws(&token).is_err());
    }
    #[tokio::test]
    #[ignore = "requires PostgreSQL via TEST_DATABASE_URL; run scripts/integration.sh"]
    async fn subscription_switch_late_account_attribution_and_cumulative_refund_races() {
        let (st, admin, schema) = fixture().await;
        let instance: Uuid = sqlx::query_scalar(
            "INSERT INTO instances(name) VALUES('Internal lifecycle') RETURNING id",
        )
        .fetch_one(&st.pg)
        .await
        .unwrap();
        let project:Uuid=sqlx::query_scalar("INSERT INTO projects(instance_id,environment,domain) VALUES($1,'production','internal.example.test') RETURNING id").bind(instance).fetch_one(&st.pg).await.unwrap();
        let link:Uuid=sqlx::query_scalar("INSERT INTO links(project_id,name,path,target_url) VALUES($1,'campaign','campaign','https://example.test') RETURNING id").bind(project).fetch_one(&st.pg).await.unwrap();
        let visitor = Uuid::new_v4();
        sqlx::query("INSERT INTO visitors(project_id,id) VALUES($1,$2)")
            .bind(project)
            .bind(visitor)
            .execute(&st.pg)
            .await
            .unwrap();
        sqlx::query("INSERT INTO visitor_attributions(project_id,visitor_id,link_id,method) VALUES($1,$2,$3,'direct')").bind(project).bind(visitor).bind(link).execute(&st.pg).await.unwrap();
        let at = Utc::now() - chrono::Duration::days(1);
        let purchase = |transaction: &str, product: &str, date| VerifiedPurchase {
            provider: "apple".into(),
            application_id: "com.example.app".into(),
            environment: "production".into(),
            transaction_id: transaction.into(),
            original_transaction_id: "chain".into(),
            product_id: product.into(),
            purchase_kind: "subscription".into(),
            currency: "USD".into(),
            amount_nanos: 10_000_000_000,
            quantity: 2,
            purchased_at: date,
            expires_at: Some(date + chrono::Duration::days(30)),
        };
        let anon = anonymous("apple", "chain");
        let first = purchases::persist_verified(&st, project, anon, purchase("first", "basic", at))
            .await
            .unwrap()
            .0;
        let id = Uuid::parse_str(first["id"].as_str().unwrap()).unwrap();
        let claimed =
            purchases::persist_verified(&st, project, visitor, purchase("first", "basic", at))
                .await
                .unwrap()
                .0;
        assert_eq!(claimed["duplicate"], true);
        let assigned: (Uuid, Uuid) =
            sqlx::query_as("SELECT visitor_id,link_id FROM purchase_ledger WHERE purchase_id=$1")
                .bind(id)
                .fetch_one(&st.pg)
                .await
                .unwrap();
        assert_eq!(assigned, (visitor, link));
        assert!(matches!(
            purchases::persist_verified(
                &st,
                project,
                Uuid::new_v4(),
                purchase("first", "basic", at)
            )
            .await,
            Err(AppError::Conflict(_))
        ));
        let later = at + chrono::Duration::hours(1);
        let _ = purchases::persist_verified(
            &st,
            project,
            visitor,
            purchase("upgrade", "premium", later),
        )
        .await
        .unwrap();
        // A late old transaction cannot cancel the currently active product.
        let _ = purchases::persist_verified(
            &st,
            project,
            visitor,
            purchase("late-old", "basic", at - chrono::Duration::hours(1)),
        )
        .await
        .unwrap();
        let state: (String, String) =
            sqlx::query_as("SELECT product_id,status FROM subscription_states WHERE project_id=$1")
                .bind(project)
                .fetch_one(&st.pg)
                .await
                .unwrap();
        assert_eq!(state, ("premium".into(), "active".into()));
        let cancels: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM purchase_ledger WHERE project_id=$1 AND event_type='CANCEL'",
        )
        .bind(project)
        .fetch_one(&st.pg)
        .await
        .unwrap();
        assert_eq!(cancels, 1);
        let time = Utc::now();
        let (a, b) = tokio::join!(
            append_adjustment(
                &st,
                project,
                id,
                Adjustment {
                    kind: "REFUND_TOTAL",
                    source: "r1",
                    amount: Some(5_000_000_000),
                    quantity: Some(1),
                    at: time
                }
            ),
            append_adjustment(
                &st,
                project,
                id,
                Adjustment {
                    kind: "REFUND_TOTAL",
                    source: "r2",
                    amount: Some(5_000_000_000),
                    quantity: Some(1),
                    at: time
                }
            )
        );
        a.unwrap();
        b.unwrap();
        let total:(String,i64)=sqlx::query_as("SELECT sum(amount_nanos)::text,sum(quantity)::bigint FROM purchase_ledger WHERE purchase_id=$1").bind(id).fetch_one(&st.pg).await.unwrap();
        assert_eq!(total, ("5000000000".into(), 1));
        append_adjustment(
            &st,
            project,
            id,
            Adjustment {
                kind: "REFUND_TOTAL",
                source: "r3",
                amount: Some(10_000_000_000),
                quantity: Some(2),
                at: time + chrono::Duration::seconds(1),
            },
        )
        .await
        .unwrap();
        append_adjustment(
            &st,
            project,
            id,
            Adjustment {
                kind: "REFUND_TOTAL",
                source: "r4",
                amount: Some(0),
                quantity: Some(0),
                at: time + chrono::Duration::seconds(2),
            },
        )
        .await
        .unwrap();
        let total:(String,i64)=sqlx::query_as("SELECT sum(amount_nanos)::text,sum(quantity)::bigint FROM purchase_ledger WHERE purchase_id=$1").bind(id).fetch_one(&st.pg).await.unwrap();
        assert_eq!(total, ("10000000000".into(), 2));
        st.pg.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }
}
