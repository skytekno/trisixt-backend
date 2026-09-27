//! Server-verified purchase ingestion. SDK amounts and signed payloads are never
//! accepted as financial evidence. Store APIs supply the recorded gross amount.
use crate::{
    auth::{AuthUser, SdkProject, authorize_project},
    error::AppError,
    state::AppState,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc, time::Duration};
use uuid::Uuid;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AppleProfile {
    pub(crate) issuer_id: String,
    pub(crate) key_id: String,
    pub(crate) private_key_path: String,
    pub(crate) bundle_id: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GoogleProfile {
    pub(crate) package_name: String,
    pub(crate) service_account_path: Option<String>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Profile {
    pub(crate) apple: Option<AppleProfile>,
    pub(crate) google: Option<GoogleProfile>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PurchaseInput {
    pub(crate) visitor_id: Uuid,
    pub(crate) provider: String,
    pub(crate) transaction_id: String,
    pub(crate) product_id: String,
    pub(crate) purchase_kind: String,
    pub(crate) purchase_token: Option<String>,
    #[serde(default)]
    pub(crate) device_id: Option<Uuid>,
    #[serde(default)]
    pub(crate) session_id: Option<String>,
    #[serde(default)]
    pub(crate) platform: Option<String>,
}
#[derive(Debug)]
pub(crate) struct VerifiedPurchase {
    pub(crate) original_transaction_id: String,
    pub(crate) expires_at: Option<DateTime<Utc>>,
    pub(crate) provider: String,
    pub(crate) application_id: String,
    pub(crate) environment: String,
    pub(crate) transaction_id: String,
    pub(crate) product_id: String,
    pub(crate) purchase_kind: String,
    pub(crate) currency: String,
    pub(crate) amount_nanos: i64,
    pub(crate) quantity: i32,
    pub(crate) purchased_at: DateTime<Utc>,
}

fn invalid(message: &str) -> AppError {
    AppError::BadRequest(message.into())
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, AppError> {
    value[key].as_str().ok_or(AppError::Upstream)
}
fn currency(value: &str) -> Result<String, AppError> {
    if value.len() != 3 || !value.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(AppError::Upstream);
    }
    Ok(value.into())
}
fn validate_input(input: &PurchaseInput) -> Result<(), AppError> {
    if input.visitor_id.is_nil() {
        return Err(invalid("visitor_id must not be nil"));
    }

    if !matches!(input.provider.as_str(), "apple" | "google")
        || !matches!(
            input.purchase_kind.as_str(),
            "one_time" | "subscription" | "rental"
        )
    {
        return Err(invalid("unsupported provider or purchase_kind"));
    }
    for value in [&input.transaction_id, &input.product_id] {
        if value.is_empty()
            || value.len() > 256
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(invalid("invalid transaction_id or product_id"));
        }
    }
    if input
        .platform
        .as_deref()
        .is_some_and(|p| !matches!(p, "ios" | "android" | "web" | "desktop" | "other"))
    {
        return Err(invalid("invalid platform"));
    }
    if input.device_id.is_some_and(|id| id.is_nil())
        || input
            .session_id
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > 200)
    {
        return Err(invalid("invalid device or session id"));
    }
    if input.provider == "google"
        && input
            .purchase_token
            .as_ref()
            .is_none_or(|v| v.is_empty() || v.len() > 4096)
    {
        return Err(invalid("Google purchase_token required"));
    }
    Ok(())
}
pub(crate) fn http_client() -> Result<reqwest::Client, AppError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| AppError::Internal)
}
pub(crate) async fn fetch_json(
    client: &reqwest::Client,
    url: reqwest::Url,
    token: &str,
) -> Result<Value, AppError> {
    let mut response = client
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| AppError::Upstream)?;
    if response.status().as_u16() == 404 {
        return Err(invalid("store transaction was not found"));
    }
    if !response.status().is_success() {
        return Err(AppError::Upstream);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| AppError::Upstream)? {
        if bytes.len() + chunk.len() > 262_144 {
            return Err(AppError::Upstream);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| AppError::Upstream)
}
pub(crate) fn endpoint(base: &str, segments: &[&str]) -> Result<reqwest::Url, AppError> {
    let mut url = reqwest::Url::parse(base).map_err(|_| AppError::Internal)?;
    url.path_segments_mut()
        .map_err(|_| AppError::Internal)?
        .extend(segments);
    Ok(url)
}
#[derive(Serialize)]
struct AppleClaims<'a> {
    iss: &'a str,
    iat: i64,
    exp: i64,
    aud: &'a str,
    bid: &'a str,
}
pub(crate) async fn apple_token(profile: &AppleProfile) -> Result<String, AppError> {
    let pem = tokio::fs::read(&profile.private_key_path)
        .await
        .map_err(|_| AppError::Internal)?;
    let key = jsonwebtoken::EncodingKey::from_ec_pem(&pem).map_err(|_| AppError::Internal)?;
    let now = Utc::now().timestamp();
    let claims = AppleClaims {
        iss: &profile.issuer_id,
        iat: now,
        exp: now + 300,
        aud: "appstoreconnect-v1",
        bid: &profile.bundle_id,
    };
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(profile.key_id.clone());
    jsonwebtoken::encode(&header, &claims, &key).map_err(|_| AppError::Internal)
}
// Only called with a body fetched from Apple's fixed authenticated TLS endpoint.
// This does not accept or trust a JWS supplied by an SDK or webhook caller.
pub(crate) fn apple_api_payload(response: &Value) -> Result<Value, AppError> {
    let compact = string(response, "signedTransactionInfo")?;
    let parts: Vec<_> = compact.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::Upstream);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AppError::Upstream)?;
    serde_json::from_slice(&decoded).map_err(|_| AppError::Upstream)
}
pub(crate) fn verify_apple_payload(
    profile: &AppleProfile,
    environment: &str,
    input: &PurchaseInput,
    payload: &Value,
) -> Result<VerifiedPurchase, AppError> {
    let expected_env = if environment == "test" {
        "Sandbox"
    } else {
        "Production"
    };
    if string(payload, "bundleId")? != profile.bundle_id
        || string(payload, "environment")? != expected_env
        || string(payload, "transactionId")? != input.transaction_id
        || string(payload, "productId")? != input.product_id
    {
        return Err(invalid(
            "store transaction does not match this application or request",
        ));
    }
    if payload["appAccountToken"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        != Some(input.visitor_id)
    {
        return Err(invalid("purchase account binding does not match visitor"));
    }
    if !payload["revocationDate"].is_null() {
        return Err(invalid("revoked purchases are not accepted as new revenue"));
    }
    let kind = match string(payload, "type")? {
        "Auto-Renewable Subscription" | "Non-Renewing Subscription" => "subscription",
        "Consumable" | "Non-Consumable" => "one_time",
        _ => return Err(invalid("unsupported Apple purchase type")),
    };
    if kind != input.purchase_kind {
        return Err(invalid("purchase_kind does not match store transaction"));
    }
    let price = payload["price"]
        .as_i64()
        .filter(|p| *p >= 0)
        .ok_or(AppError::Upstream)?;
    let amount_nanos = price.checked_mul(1_000_000).ok_or(AppError::Upstream)?;
    // Apple's price is the TOTAL for the transaction quantity, not unit price.
    let quantity = payload["quantity"]
        .as_i64()
        .and_then(|v| i32::try_from(v).ok())
        .filter(|v| *v > 0)
        .ok_or(AppError::Upstream)?;
    let purchased_at = payload["purchaseDate"]
        .as_i64()
        .and_then(DateTime::from_timestamp_millis)
        .ok_or(AppError::Upstream)?;
    Ok(VerifiedPurchase {
        original_transaction_id: payload["originalTransactionId"]
            .as_str()
            .unwrap_or(&input.transaction_id)
            .into(),
        expires_at: payload["expiresDate"]
            .as_i64()
            .and_then(DateTime::from_timestamp_millis),
        provider: "apple".into(),
        application_id: profile.bundle_id.clone(),
        environment: environment.into(),
        transaction_id: input.transaction_id.clone(),
        product_id: input.product_id.clone(),
        purchase_kind: kind.into(),
        currency: currency(string(payload, "currency")?)?,
        amount_nanos,
        quantity,
        purchased_at,
    })
}
pub(crate) async fn verify_apple(
    profile: &AppleProfile,
    environment: &str,
    input: &PurchaseInput,
) -> Result<VerifiedPurchase, AppError> {
    let base = if environment == "test" {
        "https://api.storekit-sandbox.apple.com"
    } else {
        "https://api.storekit.apple.com"
    };
    let token = apple_token(profile).await?;
    let response = fetch_json(
        &http_client()?,
        endpoint(
            base,
            &["inApps", "v1", "transactions", &input.transaction_id],
        )?,
        &token,
    )
    .await?;
    verify_apple_payload(profile, environment, input, &apple_api_payload(&response)?)
}
pub(crate) async fn google_token(profile: &GoogleProfile) -> Result<String, AppError> {
    let provider: Arc<dyn gcp_auth::TokenProvider> = if let Some(path) =
        &profile.service_account_path
    {
        Arc::new(gcp_auth::CustomServiceAccount::from_file(path).map_err(|_| AppError::Internal)?)
    } else {
        gcp_auth::provider().await.map_err(|_| AppError::Internal)?
    };
    Ok(provider
        .token(&["https://www.googleapis.com/auth/androidpublisher"])
        .await
        .map_err(|_| AppError::Upstream)?
        .as_str()
        .into())
}
pub(crate) fn money_nanos(value: &Value) -> Result<(String, i64), AppError> {
    let units = match &value["units"] {
        Value::Null => 0,
        Value::String(value) => value.parse::<i64>().map_err(|_| AppError::Upstream)?,
        _ => return Err(AppError::Upstream),
    };
    let nanos = match &value["nanos"] {
        Value::Null => 0,
        value => value.as_i64().ok_or(AppError::Upstream)?,
    };
    if units < 0 || !(0..1_000_000_000).contains(&nanos) {
        return Err(AppError::Upstream);
    }
    let total = units
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(nanos))
        .ok_or(AppError::Upstream)?;
    Ok((currency(string(value, "currencyCode")?)?, total))
}
pub(crate) fn verify_google_payload(
    profile: &GoogleProfile,
    environment: &str,
    input: &PurchaseInput,
    purchase: &Value,
    order: &Value,
) -> Result<VerifiedPurchase, AppError> {
    let visitor = input.visitor_id.to_string();
    let is_test = if input.purchase_kind == "subscription" {
        if purchase["externalAccountIdentifiers"]["obfuscatedExternalAccountId"].as_str()
            != Some(visitor.as_str())
        {
            return Err(invalid("purchase account binding does not match visitor"));
        }
        if !purchase["lineItems"].as_array().is_some_and(|items| {
            items
                .iter()
                .any(|i| i["productId"].as_str() == Some(input.product_id.as_str()))
        }) {
            return Err(invalid("subscription product does not match"));
        }
        !purchase["testPurchase"].is_null()
    } else {
        if !(purchase["purchaseState"].as_i64() == Some(0)
            || purchase["purchaseStateContext"]["purchaseState"].as_str() == Some("PURCHASED"))
            || purchase["orderId"].as_str() != Some(input.transaction_id.as_str())
        {
            return Err(invalid("purchase is not completed or order does not match"));
        }
        if purchase["obfuscatedExternalAccountId"].as_str() != Some(visitor.as_str()) {
            return Err(invalid("purchase account binding does not match visitor"));
        }
        purchase["purchaseType"].as_i64() == Some(0) || purchase["testPurchaseContext"].is_object()
    };
    if is_test != (environment == "test") {
        return Err(invalid("store environment does not match project"));
    }
    if order["orderId"].as_str() != Some(input.transaction_id.as_str())
        || order["purchaseToken"].as_str() != input.purchase_token.as_deref()
        || order["state"].as_str() != Some("PROCESSED")
    {
        return Err(invalid("order is not processed or token does not match"));
    }
    let items = order["lineItems"].as_array().ok_or(AppError::Upstream)?;
    // Bundle orders are split by product using authoritative line totals.
    let matching: Vec<_> = items
        .iter()
        .filter(|item| item["productId"].as_str() == Some(input.product_id.as_str()))
        .collect();
    if matching.len() != 1 {
        return Err(invalid("order product does not match uniquely"));
    }
    let item = matching[0];
    let kind = if item["subscriptionDetails"].is_object() {
        "subscription"
    } else if item["oneTimePurchaseDetails"].is_object() {
        google_product_kind(purchase, &input.product_id)
    } else {
        return Err(invalid("unsupported order item"));
    };
    if kind != input.purchase_kind && !(kind == "rental" && input.purchase_kind == "one_time") {
        return Err(invalid("purchase_kind does not match order"));
    }
    let (quantity, currency, amount_nanos) = {
        let (c, n) = money_nanos(if item["total"].is_object() {
            &item["total"]
        } else if items.len() == 1 {
            &order["total"]
        } else {
            return Err(AppError::Upstream);
        })?;
        let q = if kind == "subscription" {
            1
        } else {
            item["oneTimePurchaseDetails"]["quantity"]
                .as_i64()
                .and_then(|v| i32::try_from(v).ok())
                .filter(|v| *v > 0)
                .ok_or(AppError::Upstream)?
        };
        (q, c, n)
    };
    let purchased_at = DateTime::parse_from_rfc3339(string(order, "createTime")?)
        .map_err(|_| AppError::Upstream)?
        .with_timezone(&Utc);
    Ok(VerifiedPurchase {
        original_transaction_id: input
            .purchase_token
            .clone()
            .unwrap_or_else(|| input.transaction_id.clone()),
        expires_at: item["subscriptionDetails"]["servicePeriodEndTime"]
            .as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc)),
        provider: "google".into(),
        application_id: profile.package_name.clone(),
        environment: environment.into(),
        transaction_id: input.transaction_id.clone(),
        product_id: input.product_id.clone(),
        purchase_kind: kind.into(),
        currency,
        amount_nanos,
        quantity,
        purchased_at,
    })
}
pub(crate) fn google_product_kind(purchase: &Value, product: &str) -> &'static str {
    let rental = purchase["productLineItem"].as_array().is_some_and(|items| {
        items.iter().any(|item| {
            item["productId"].as_str() == Some(product)
                && item["productOfferDetails"]["rentOfferDetails"].is_object()
        })
    }) || purchase["productOfferDetails"]["rentOfferDetails"].is_object();
    if rental { "rental" } else { "one_time" }
}
pub(crate) async fn verify_google_with(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    profile: &GoogleProfile,
    environment: &str,
    input: &PurchaseInput,
) -> Result<VerifiedPurchase, AppError> {
    let purchase_token = input
        .purchase_token
        .as_deref()
        .ok_or_else(|| invalid("purchase_token required"))?;
    let mut path = vec![
        "androidpublisher",
        "v3",
        "applications",
        profile.package_name.as_str(),
        "purchases",
    ];
    if input.purchase_kind == "subscription" {
        path.extend(["subscriptionsv2", "tokens", purchase_token]);
    } else {
        path.extend(["productsv2", "tokens", purchase_token]);
    }
    let purchase = fetch_json(client, endpoint(base, &path)?, token).await?;
    let order = fetch_json(
        client,
        endpoint(
            base,
            &[
                "androidpublisher",
                "v3",
                "applications",
                &profile.package_name,
                "orders",
                &input.transaction_id,
            ],
        )?,
        token,
    )
    .await?;
    verify_google_payload(profile, environment, input, &purchase, &order)
}
pub(crate) async fn verify_google(
    profile: &GoogleProfile,
    environment: &str,
    input: &PurchaseInput,
) -> Result<VerifiedPurchase, AppError> {
    let token = google_token(profile).await?;
    verify_google_with(
        &http_client()?,
        "https://androidpublisher.googleapis.com",
        &token,
        profile,
        environment,
        input,
    )
    .await
}
pub(crate) async fn persist_verified(
    st: &AppState,
    project: Uuid,
    visitor: Uuid,
    verified: VerifiedPurchase,
) -> Result<Json<Value>, AppError> {
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,42))")
        .bind(project.to_string())
        .execute(&mut *tx)
        .await?;
    let visitor=sqlx::query_scalar::<_,Uuid>("SELECT coalesce((SELECT visitor_id FROM visitor_aliases WHERE project_id=$1 AND alias_id=$2),$2)").bind(project).bind(visitor).fetch_one(&mut *tx).await?;
    crate::purchase_lifecycle::lock_chain(
        &mut tx,
        project,
        &verified.provider,
        &verified.original_transaction_id,
    )
    .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!(
            "iap:{}:{}:{}:{}",
            verified.provider,
            verified.application_id,
            verified.environment,
            verified.transaction_id
        ))
        .execute(&mut *tx)
        .await?;
    let existing=sqlx::query_as::<_,(Uuid,Uuid,Uuid)>("SELECT id,project_id,visitor_id FROM verified_purchases WHERE provider=$1 AND application_id=$2 AND environment=$3 AND transaction_id=$4 AND product_id=$5")
        .bind(&verified.provider).bind(&verified.application_id).bind(&verified.environment).bind(&verified.transaction_id).bind(&verified.product_id).fetch_optional(&mut *tx).await?;
    if let Some((id, owner, account)) = existing {
        if owner == project
            && account != visitor
            && account
                == crate::purchase_lifecycle::anonymous(
                    &verified.provider,
                    &verified.original_transaction_id,
                )
            && verified.provider != "reported"
        {
            crate::purchase_lifecycle::claim_anonymous_tx(
                &mut tx,
                project,
                account,
                visitor,
                &verified.provider,
                &verified.original_transaction_id,
            )
            .await?;
        } else if owner != project || account != visitor {
            return Err(AppError::Conflict(
                "store transaction is already assigned".into(),
            ));
        }
        tx.commit().await?;
        return Ok(Json(json!({"id":id,"verified":true,"duplicate":true})));
    }
    sqlx::query("INSERT INTO visitors(project_id,id) VALUES($1,$2) ON CONFLICT DO NOTHING")
        .bind(project)
        .bind(visitor)
        .execute(&mut *tx)
        .await?;
    let id=sqlx::query_scalar::<_,Uuid>("INSERT INTO verified_purchases(project_id,visitor_id,provider,application_id,environment,transaction_id,product_id,purchase_kind,currency,amount_nanos,quantity,purchased_at,original_transaction_id,expires_at,verification_source) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id")
        .bind(project).bind(visitor).bind(&verified.provider).bind(&verified.application_id).bind(&verified.environment).bind(&verified.transaction_id).bind(&verified.product_id).bind(&verified.purchase_kind).bind(&verified.currency).bind(verified.amount_nanos).bind(verified.quantity).bind(verified.purchased_at).bind(&verified.original_transaction_id).bind(verified.expires_at).bind(if verified.provider=="reported"{"sdk_reported"}else{"store_api"}).fetch_one(&mut *tx).await?;
    sqlx::query("UPDATE verified_purchases SET platform=CASE provider WHEN 'apple' THEN 'ios' WHEN 'google' THEN 'android' ELSE 'other' END WHERE id=$1").bind(id).execute(&mut *tx).await?;
    crate::purchase_lifecycle::record_purchase_tx(&mut tx, project, visitor, id, &verified).await?;
    if verified.provider != "reported" {
        sqlx::query("INSERT INTO purchase_reconciliation(project_id,provider,original_transaction_id,purchase_token,product_id,purchase_kind,available_at) VALUES($1,$2,$3,$4,$5,$6,now()+interval '1 day') ON CONFLICT DO NOTHING").bind(project).bind(&verified.provider).bind(&verified.original_transaction_id).bind(if verified.provider=="google" {Some(&verified.original_transaction_id)}else{None}).bind(&verified.product_id).bind(&verified.purchase_kind).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(Json(json!({"id":id,"verified":true,"duplicate":false})))
}
async fn sdk_purchase(
    State(st): State<AppState>,
    sdk: SdkProject,
    Json(input): Json<PurchaseInput>,
) -> Result<Json<Value>, AppError> {
    let project = sdk.id;
    sdk.check_platform(input.platform.as_deref())?;
    sdk.check_platform(match input.provider.as_str() {
        "apple" => Some("ios"),
        "google" => Some("android"),
        _ => None,
    })?;
    if !st.config.ee_enabled {
        return Err(AppError::NotFound);
    }
    validate_input(&input)?;
    let enabled: bool = sqlx::query_scalar("SELECT i.revenue_collection_enabled FROM instances i JOIN projects p ON p.instance_id=i.id WHERE p.id=$1").bind(project).fetch_one(&st.pg).await?;
    if !enabled {
        return Ok(Json(json!({"ignored":"revenue collection disabled"})));
    }
    let profiles = std::env::var("TRISIXT_IAP_PROFILES").map_err(|_| {
        AppError::Config("TRISIXT_IAP_PROFILES is required for purchase verification".into())
    })?;
    let profiles: HashMap<Uuid, Profile> = serde_json::from_str(&profiles)
        .map_err(|_| AppError::Config("invalid IAP profiles".into()))?;
    let profile = profiles.get(&project).ok_or_else(|| {
        AppError::BadRequest("store verification is not configured for this project".into())
    })?;
    let environment =
        sqlx::query_scalar::<_, String>("SELECT environment FROM projects WHERE id=$1")
            .bind(project)
            .fetch_one(&st.pg)
            .await?;
    let verified = match input.provider.as_str() {
        "apple" => {
            verify_apple(
                profile
                    .apple
                    .as_ref()
                    .ok_or_else(|| invalid("Apple is not configured"))?,
                &environment,
                &input,
            )
            .await?
        }
        "google" => {
            verify_google(
                profile
                    .google
                    .as_ref()
                    .ok_or_else(|| invalid("Google Play is not configured"))?,
                &environment,
                &input,
            )
            .await?
        }
        _ => return Err(invalid("unsupported provider")),
    };
    let original = verified.original_transaction_id.clone();
    let result = persist_verified(&st, project, input.visitor_id, verified).await?;
    let id = Uuid::parse_str(result.0["id"].as_str().ok_or(AppError::Internal)?)
        .map_err(|_| AppError::Internal)?;
    crate::purchase_lifecycle::attach_metadata(
        &st,
        project,
        id,
        input.device_id,
        input.session_id.as_deref(),
        input.platform.as_deref(),
    )
    .await?;
    sqlx::query("INSERT INTO purchase_reconciliation(project_id,provider,original_transaction_id,purchase_token,product_id,purchase_kind,available_at) VALUES($1,$2,$3,$4,$5,$6,now()+interval '1 day') ON CONFLICT(project_id,provider,original_transaction_id) DO UPDATE SET purchase_token=coalesce(excluded.purchase_token,purchase_reconciliation.purchase_token),product_id=excluded.product_id,purchase_kind=excluded.purchase_kind")
        .bind(project).bind(&input.provider).bind(original).bind(&input.purchase_token).bind(&input.product_id).bind(&input.purchase_kind).execute(&st.pg).await?;
    Ok(result)
}
#[derive(Deserialize)]
struct Range {
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    limit: Option<i64>,
}
impl Range {
    fn values(&self) -> Result<(DateTime<Utc>, DateTime<Utc>, i64), AppError> {
        let to = self.to.unwrap_or_else(Utc::now);
        let from = self.from.unwrap_or(to - chrono::Duration::days(30));
        let limit = self.limit.unwrap_or(100);
        if from >= to || to - from > chrono::Duration::days(366) || !(1..=1000).contains(&limit) {
            return Err(invalid("invalid date range or limit"));
        }
        Ok((from, to, limit))
    }
}
async fn purchase_list(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Query(range): Query<Range>,
) -> Result<Json<Value>, AppError> {
    if !st.config.ee_enabled {
        return Err(AppError::NotFound);
    }
    authorize_project(&st, &user, project, false).await?;
    let (from, to, limit) = range.values()?;
    let rows=sqlx::query_scalar::<_,Value>("SELECT to_jsonb(p) FROM verified_purchases p WHERE project_id=$1 AND purchased_at>=$2 AND purchased_at<$3 ORDER BY purchased_at DESC,id LIMIT $4").bind(project).bind(from).bind(to).bind(limit).fetch_all(&st.pg).await?;
    Ok(Json(
        json!({"purchases":rows,"amount_unit":"currency nanounits"}),
    ))
}
async fn revenue(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Query(range): Query<Range>,
) -> Result<Json<Value>, AppError> {
    if !st.config.ee_enabled {
        return Err(AppError::NotFound);
    }
    authorize_project(&st, &user, project, false).await?;
    let (from, to, _) = range.values()?;
    let rows=sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('currency',currency,'gross_amount_nanos',sum(amount_nanos)::text,'transactions',count(*),'quantity',sum(quantity)) FROM verified_purchases WHERE project_id=$1 AND purchased_at>=$2 AND purchased_at<$3 GROUP BY currency ORDER BY currency")
        .bind(project).bind(from).bind(to).fetch_all(&st.pg).await?;
    let mut metrics =
        crate::purchase_lifecycle::revenue_metrics(&st, project, from, to, None).await?;
    metrics["from"] = json!(from);
    metrics["to"] = json!(to);
    metrics["gross_sales"] = json!(rows);
    metrics["amount_unit"] = json!("currency nanounits");
    metrics["includes_refunds"] = json!(true);
    Ok(Json(metrics))
}
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/sdk/purchases/verify", post(sdk_purchase))
        .route("/api/v1/projects/{id}/purchases", get(purchase_list))
        .route("/api/v1/projects/{id}/purchases/revenue", get(revenue))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input(provider: &str) -> PurchaseInput {
        PurchaseInput {
            visitor_id: Uuid::new_v4(),
            provider: provider.into(),
            transaction_id: if provider == "apple" {
                "12345678"
            } else {
                "GPA.1234-5678-9012-34567"
            }
            .into(),
            product_id: "coins".into(),
            purchase_kind: "one_time".into(),
            purchase_token: Some("secret-purchase-token".into()),
            device_id: None,
            session_id: None,
            platform: None,
        }
    }
    fn apple() -> AppleProfile {
        AppleProfile {
            issuer_id: "issuer".into(),
            key_id: "key".into(),
            private_key_path: "unused".into(),
            bundle_id: "com.example.app".into(),
        }
    }
    fn apple_payload(input: &PurchaseInput) -> Value {
        json!({"bundleId":"com.example.app","environment":"Production","transactionId":input.transaction_id,"productId":input.product_id,"appAccountToken":input.visitor_id,"type":"Consumable","price":5990,"currency":"USD","quantity":2,"purchaseDate":1_789_819_200_000_i64})
    }
    fn google() -> GoogleProfile {
        GoogleProfile {
            package_name: "com.example.app".into(),
            service_account_path: None,
        }
    }
    fn google_payloads(input: &PurchaseInput) -> (Value, Value) {
        (
            json!({"purchaseState":0,"orderId":input.transaction_id,"obfuscatedExternalAccountId":input.visitor_id}),
            json!({"orderId":input.transaction_id,"purchaseToken":input.purchase_token,"state":"PROCESSED","createTime":"2026-09-19T12:00:00Z","total":{"currencyCode":"USD","units":"5","nanos":990000000},"lineItems":[{"productId":input.product_id,"oneTimePurchaseDetails":{"quantity":2}}]}),
        )
    }
    #[test]
    fn apple_validates_identity_environment_revocation_and_total_quantity() {
        let input = input("apple");
        let payload = apple_payload(&input);
        let profile = apple();
        let verified = verify_apple_payload(&profile, "production", &input, &payload).unwrap();
        assert_eq!(verified.amount_nanos, 5_990_000_000);
        assert_eq!(verified.quantity, 2);
        assert!(verify_apple_payload(&profile, "test", &input, &payload).is_err());
        for (key, value) in [
            ("bundleId", json!("other.app")),
            ("transactionId", json!("wrong")),
            ("appAccountToken", json!(Uuid::new_v4())),
            ("productId", json!("wrong")),
            ("revocationDate", json!(1789819200000_i64)),
        ] {
            let mut changed = payload.clone();
            changed[key] = value;
            assert!(
                verify_apple_payload(&profile, "production", &input, &changed).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn google_requires_processed_order_account_token_and_exact_money() {
        let input = input("google");
        let (purchase, order) = google_payloads(&input);
        let profile = google();
        let verified =
            verify_google_payload(&profile, "production", &input, &purchase, &order).unwrap();
        assert_eq!(verified.amount_nanos, 5_990_000_000);
        assert_eq!(verified.quantity, 2);
        for (key, value) in [
            ("state", json!("PENDING")),
            ("state", json!("REFUNDED")),
            ("purchaseToken", json!("wrong")),
            ("orderId", json!("wrong")),
        ] {
            let mut changed = order.clone();
            changed[key] = value;
            assert!(
                verify_google_payload(&profile, "production", &input, &purchase, &changed).is_err(),
                "{key}"
            );
        }
        let mut changed = purchase.clone();
        changed["obfuscatedExternalAccountId"] = json!(Uuid::new_v4());
        assert!(verify_google_payload(&profile, "production", &input, &changed, &order).is_err());
        assert!(verify_google_payload(&profile, "test", &input, &purchase, &order).is_err());
        for value in [
            json!({"currencyCode":"USD","units":"9223372036854775807"}),
            json!({"currencyCode":"USD","units":"-1"}),
            json!({"currencyCode":"USD","nanos":1_000_000_000}),
            json!({"currencyCode":"USD","nanos":"invalid"}),
            json!({"currencyCode":"usd","units":"1"}),
        ] {
            assert!(money_nanos(&value).is_err());
        }
    }
    #[test]
    fn input_never_accepts_client_prices_or_receipt_payload() {
        let body = json!({"visitor_id":Uuid::new_v4(),"provider":"apple","transaction_id":"123","product_id":"coins","purchase_kind":"one_time","amount_nanos":1});
        assert!(serde_json::from_value::<PurchaseInput>(body).is_err());
        assert!(apple_api_payload(&json!({"signedTransactionInfo":"malformed"})).is_err());
    }
    #[tokio::test]
    async fn google_http_contract_fetches_purchase_and_authoritative_order() {
        use axum::{
            http::{HeaderMap, Uri},
            response::IntoResponse,
        };
        let input = input("google");
        let (purchase, order) = google_payloads(&input);
        let app = Router::new().fallback(move |headers: HeaderMap, uri: Uri| {
            let p = purchase.clone();
            let o = order.clone();
            async move {
                assert_eq!(headers.get("authorization").unwrap(), "Bearer test-token");
                if uri
                    .path()
                    .contains("/purchases/productsv2/tokens/secret-purchase-token")
                {
                    Json(p).into_response()
                } else if uri.path().contains("/orders/GPA.1234-5678-9012-34567") {
                    Json(o).into_response()
                } else {
                    panic!("unexpected purchase URL: {}", uri.path())
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let verified = verify_google_with(
            &http_client().unwrap(),
            &base,
            "test-token",
            &google(),
            "production",
            &input,
        )
        .await
        .unwrap();
        assert_eq!(verified.amount_nanos, 5_990_000_000);
        server.abort();
    }
    #[tokio::test]
    async fn store_redirects_are_rejected_without_forwarding_credentials() {
        let app = Router::new().fallback(|| async {
            axum::response::Redirect::temporary("http://127.0.0.1:1/secret")
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        assert!(matches!(
            fetch_json(
                &http_client().unwrap(),
                reqwest::Url::parse(&base).unwrap(),
                "secret"
            )
            .await,
            Err(AppError::Upstream)
        ));
        server.abort();
    }
    #[tokio::test]
    #[ignore = "requires PostgreSQL via TEST_DATABASE_URL"]
    async fn verified_ledger_deduplicates_preserves_currency_and_isolates_tenants() {
        use crate::config::{AnalyticsBackend, Config, StorageBackend};
        let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL required");
        let admin = sqlx::PgPool::connect(&url).await.unwrap();
        let schema = format!("test_purchases_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        let path = format!("SET search_path TO {schema}");
        let pool = sqlx::postgres::PgPoolOptions::new()
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
            pg: pool.clone(),
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
        let user = AuthUser {
            id: Uuid::new_v4(),
            email: "owner@example.test".into(),
        };
        sqlx::query("INSERT INTO users(id,email) VALUES($1,$2)")
            .bind(user.id)
            .bind(&user.email)
            .execute(&pool)
            .await
            .unwrap();
        let tenant: Uuid =
            sqlx::query_scalar("INSERT INTO instances(name) VALUES('Purchases') RETURNING id")
                .fetch_one(&pool)
                .await
                .unwrap();
        sqlx::query("INSERT INTO instance_roles(user_id,instance_id,role) VALUES($1,$2,'owner')")
            .bind(user.id)
            .bind(tenant)
            .execute(&pool)
            .await
            .unwrap();
        let project:Uuid=sqlx::query_scalar("INSERT INTO projects(instance_id,environment,domain) VALUES($1,'production','purchases.example.test') RETURNING id").bind(tenant).fetch_one(&pool).await.unwrap();
        let input = input("apple");
        let mut payload = apple_payload(&input);
        payload["purchaseDate"] =
            json!((Utc::now() - chrono::Duration::hours(1)).timestamp_millis());
        let verified = || verify_apple_payload(&apple(), "production", &input, &payload).unwrap();
        let (a, b) = tokio::join!(
            persist_verified(&st, project, input.visitor_id, verified()),
            persist_verified(&st, project, input.visitor_id, verified())
        );
        let a = a.unwrap().0;
        let b = b.unwrap().0;
        assert_eq!(a["id"], b["id"]);
        assert_ne!(a["duplicate"], b["duplicate"]);
        assert!(matches!(
            persist_verified(&st, project, Uuid::new_v4(), verified()).await,
            Err(AppError::Conflict(_))
        ));
        let mut second = verified();
        second.transaction_id = "another-transaction".into();
        second.currency = "JPY".into();
        second.amount_nanos = 500_000_000_000;
        second.purchased_at = Utc::now();
        let _ = persist_verified(&st, project, input.visitor_id, second)
            .await
            .unwrap();
        let Json(summary) = revenue(
            State(st.clone()),
            user.clone(),
            Path(project),
            Query(Range {
                from: Some(Utc::now() - chrono::Duration::days(365)),
                to: None,
                limit: None,
            }),
        )
        .await
        .unwrap();
        let rows = summary["gross_sales"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["currency"], "JPY");
        assert_eq!(rows[0]["gross_amount_nanos"], "500000000000");
        assert_eq!(rows[1]["gross_amount_nanos"], "5990000000");
        assert_eq!(summary["includes_refunds"], true);
        let stranger = AuthUser {
            id: Uuid::new_v4(),
            email: "other@example.test".into(),
        };
        assert!(matches!(
            revenue(
                State(st.clone()),
                stranger,
                Path(project),
                Query(Range {
                    from: None,
                    to: None,
                    limit: None
                })
            )
            .await,
            Err(AppError::Forbidden)
        ));
        let audits:i64=sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE instance_id=$1 AND action='verified_purchases.insert'").bind(tenant).fetch_one(&pool).await.unwrap();
        assert_eq!(audits, 2);
        drop(st);
        pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }
    #[tokio::test]
    async fn apple_api_token_is_signed_with_scoped_claims_and_short_expiry() {
        // Dedicated generated test key, never used for any deployed account.
        let profile = AppleProfile {
            issuer_id: "test-issuer".into(),
            key_id: "test-key-id".into(),
            private_key_path: format!(
                "{}/tests/fixtures/apple-test-key.p8",
                env!("CARGO_MANIFEST_DIR")
            ),
            bundle_id: "com.example.app".into(),
        };
        let token = apple_token(&profile).await.unwrap();
        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.alg, jsonwebtoken::Algorithm::ES256);
        assert_eq!(header.kid.as_deref(), Some("test-key-id"));
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_audience(&["appstoreconnect-v1"]);
        validation.set_issuer(&["test-issuer"]);
        let key = jsonwebtoken::DecodingKey::from_ec_pem(include_bytes!(
            "../tests/fixtures/apple-test-key-public.pem"
        ))
        .unwrap();
        let claims = jsonwebtoken::decode::<Value>(&token, &key, &validation)
            .unwrap()
            .claims;
        assert_eq!(claims["bid"], "com.example.app");
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            300
        );
    }
}
