//! Branded hostname provisioning, DNS/TLS proof, and resumable lifecycle.
use crate::{
    auth::{AuthUser, authorize_project},
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
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CustomHostname {
    pub id: Uuid,
    pub project_id: Uuid,
    pub hostname: String,
    pub purpose: String,
    pub source: String,
    pub mode: String,
    pub status: String,
    pub cf_id: Option<String>,
    pub ssl_status: Option<String>,
    pub ssl_method: Option<String>,
    pub validation_records: Value,
    pub ownership_verification: Option<Value>,
    pub verification_errors: Option<String>,
    pub grace_until: Option<DateTime<Utc>>,
    pub activated_at: Option<DateTime<Utc>>,
    pub last_checked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub fn normalize_hostname(input: &str) -> Result<String, AppError> {
    let host = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.len() > 253
        || !host.is_ascii()
        || host.split('.').count() < 2
        || host.split('.').any(|p| {
            p.is_empty()
                || p.len() > 63
                || p.starts_with('-')
                || p.ends_with('-')
                || !p.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
        || host.parse::<IpAddr>().is_ok()
    {
        return Err(AppError::BadRequest("valid ASCII hostname required".into()));
    }
    Ok(host)
}
fn custom_hostname(input: &str, base: &str) -> Result<String, AppError> {
    let host = normalize_hostname(input)?;
    let registered = psl::domain(host.as_bytes())
        .ok_or_else(|| AppError::BadRequest("public subdomain required".into()))?;
    if registered.as_bytes() == host.as_bytes()
        || host == base
        || host.ends_with(&format!(".{base}"))
    {
        return Err(AppError::BadRequest(
            "hostname must be a non-reserved subdomain".into(),
        ));
    }
    Ok(host)
}

pub async fn rate_limit(pg: &sqlx::PgPool, key: &str, limit: i32) -> Result<(), AppError> {
    let count=sqlx::query_scalar::<_,i32>("INSERT INTO connectivity_rate_limits(bucket,attempts,expires_at) VALUES($1,1,now()+interval '1 minute') ON CONFLICT(bucket) DO UPDATE SET attempts=CASE WHEN connectivity_rate_limits.expires_at<now() THEN 1 ELSE connectivity_rate_limits.attempts+1 END,expires_at=CASE WHEN connectivity_rate_limits.expires_at<now() THEN now()+interval '1 minute' ELSE connectivity_rate_limits.expires_at END RETURNING attempts").bind(key).fetch_one(pg).await?;
    if count > limit {
        Err(AppError::TooManyRequests)
    } else {
        Ok(())
    }
}

#[derive(Clone)]
pub struct Cloudflare {
    client: reqwest::Client,
    base: String,
    zone: String,
    token: String,
}
impl Cloudflare {
    pub fn new(base: String, zone: String, token: String) -> Result<Self, AppError> {
        if zone.is_empty() || !zone.bytes().all(|b| b.is_ascii_alphanumeric()) || token.is_empty() {
            return Err(AppError::Config("Cloudflare credentials required".into()));
        }
        let url = url::Url::parse(&base)
            .map_err(|_| AppError::Config("invalid Cloudflare endpoint".into()))?;
        if url.scheme() != "https"
            && !(url.scheme() == "http"
                && matches!(url.host_str(), Some("127.0.0.1" | "localhost")))
        {
            return Err(AppError::Config("Cloudflare requires HTTPS".into()));
        }
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| AppError::Internal)?,
            base: base.trim_end_matches('/').into(),
            zone,
            token,
        })
    }
    fn from_env() -> Result<Self, AppError> {
        Self::new(
            "https://api.cloudflare.com/client/v4".into(),
            std::env::var("CLOUDFLARE_ZONE_ID")
                .map_err(|_| AppError::Config("CLOUDFLARE_ZONE_ID required".into()))?,
            std::env::var("CLOUDFLARE_API_TOKEN")
                .map_err(|_| AppError::Config("CLOUDFLARE_API_TOKEN required".into()))?,
        )
    }
    async fn request(
        &self,
        method: reqwest::Method,
        id: Option<&str>,
        body: Option<Value>,
        hostname: Option<&str>,
    ) -> Result<(u16, Value), AppError> {
        if id.is_some_and(|s| {
            s.is_empty() || !s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        }) {
            return Err(AppError::BadRequest("invalid Cloudflare id".into()));
        }
        let mut url = format!("{}/zones/{}/custom_hostnames", self.base, self.zone);
        if let Some(id) = id {
            url.push('/');
            url.push_str(id);
        }
        let mut req = self.client.request(method, url).bearer_auth(&self.token);
        if let Some(body) = body {
            req = req.json(&body);
        }
        if let Some(host) = hostname {
            req = req.query(&[("hostname", host)]);
        }
        let response = req.send().await.map_err(|_| AppError::Upstream)?;
        let status = response.status().as_u16();
        let value = bounded_json(response, 1048576).await?;
        Ok((status, value))
    }
    pub async fn create(&self, hostname: &str) -> Result<Value, AppError> {
        let (s, v) = self
            .request(
                reqwest::Method::POST,
                None,
                Some(json!({"hostname":hostname,"ssl":{"method":"txt","type":"dv"}})),
                None,
            )
            .await?;
        if (200..300).contains(&s) && v["success"] == true && v["result"]["id"].is_string() {
            Ok(v["result"].clone())
        } else {
            self.lookup(hostname).await
        }
    }
    pub async fn lookup(&self, hostname: &str) -> Result<Value, AppError> {
        let (s, v) = self
            .request(reqwest::Method::GET, None, None, Some(hostname))
            .await?;
        if !(200..300).contains(&s) || v["success"] != true {
            return Err(AppError::Upstream);
        }
        v["result"]
            .as_array()
            .and_then(|a| {
                a.iter()
                    .find(|r| r["hostname"] == hostname && r["id"].is_string())
            })
            .cloned()
            .ok_or(AppError::NotFound)
    }
    pub async fn status(&self, id: &str) -> Result<Value, AppError> {
        let (s, v) = self
            .request(reqwest::Method::GET, Some(id), None, None)
            .await?;
        if (200..300).contains(&s) && v["success"] == true {
            Ok(v["result"].clone())
        } else {
            Err(AppError::Upstream)
        }
    }
    pub async fn delete(&self, id: &str) -> Result<(), AppError> {
        let (s, v) = self
            .request(reqwest::Method::DELETE, Some(id), None, None)
            .await?;
        let gone = v["errors"].as_array().is_some_and(|a| {
            a.iter()
                .any(|e| matches!(e["code"].as_i64(), Some(1436 | 1437)))
        });
        if ((200..300).contains(&s) && v["success"] == true) || gone {
            Ok(())
        } else {
            Err(AppError::Upstream)
        }
    }
}
pub async fn bounded_json(mut response: reqwest::Response, max: usize) -> Result<Value, AppError> {
    if response.content_length().is_some_and(|n| n > max as u64) {
        return Err(AppError::Upstream);
    }
    let mut b = Vec::new();
    while let Some(c) = response.chunk().await.map_err(|_| AppError::Upstream)? {
        if b.len() + c.len() > max {
            return Err(AppError::Upstream);
        }
        b.extend(c);
    }
    serde_json::from_slice(&b).map_err(|_| AppError::Upstream)
}
pub fn cloudflare_records(v: &Value) -> Value {
    let mut records = Vec::new();
    if let Some(a) = v["ssl"]["validation_records"].as_array() {
        for r in a {
            if r["txt_name"].is_string() && r["status"] != "valid" {
                records.push(json!({"name":r["txt_name"],"value":r["txt_value"]}));
            }
        }
    }
    json!(records)
}
fn verification_token(host: &str) -> Result<String, AppError> {
    let secret = std::env::var("DOMAIN_VERIFICATION_SECRET").map_err(|_| {
        AppError::Config("DOMAIN_VERIFICATION_SECRET required for manual domains".into())
    })?;
    if secret.len() < 32 {
        return Err(AppError::Config(
            "DOMAIN_VERIFICATION_SECRET must have at least32 characters".into(),
        ));
    }
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| AppError::Internal)?;
    mac.update(host.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}
pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            !v.is_private()
                && !v.is_loopback()
                && !v.is_link_local()
                && !v.is_unspecified()
                && !v.is_broadcast()
                && !v.is_multicast()
                && !v.is_documentation()
                && !(o[0] == 192 && o[1] == 88 && o[2] == 99)
                && o[0] != 0
                && o[0] < 240
                && !(o[0] == 100 && (64..128).contains(&o[1]))
                && !(o[0] == 192 && o[1] == 0)
                && !(o[0] == 198 && (18..=19).contains(&o[1]))
        }
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                public_ip(IpAddr::V4(v4))
            } else {
                let segments = v.segments();
                (segments[0] & 0xe000) == 0x2000
                    && !(segments[0] == 0x2001 && segments[1] < 0x200)
                    && !(segments[0] == 0x2001 && segments[1] == 0xdb8)
                    && segments[0] != 0x2002
            }
        }
    }
}
pub async fn verify_manual(host: &str) -> Result<(), AppError> {
    let host = normalize_hostname(host)?;
    let addresses = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::lookup_host((host.as_str(), 443)),
    )
    .await
    .map_err(|_| AppError::Upstream)?
    .map_err(|_| AppError::Upstream)?
    .collect::<Vec<SocketAddr>>();
    if addresses.is_empty() || addresses.iter().any(|a| !public_ip(a.ip())) {
        return Err(AppError::BadRequest(
            "hostname resolves to a non-public address".into(),
        ));
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .resolve_to_addrs(&host, &addresses)
        .timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| AppError::Internal)?;
    let response = client
        .get(format!(
            "https://{host}/.well-known/trisixt-domain-verification"
        ))
        .send()
        .await
        .map_err(|_| AppError::Upstream)?;
    if !response.status().is_success() {
        return Err(AppError::Upstream);
    }
    let result = bounded_json(response, 8192).await?;
    if result["token"] != verification_token(&host)? {
        return Err(AppError::BadRequest(
            "hostname does not reach this deployment over valid TLS".into(),
        ));
    }
    Ok(())
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/projects/{id}/domain",
            get(domain).put(update_domain),
        )
        .route(
            "/api/v1/projects/{id}/domain/defaults",
            get(domain_defaults),
        )
        .route(
            "/api/v1/projects/{id}/domain/google_tracking_id",
            axum::routing::put(set_google_tracking_id),
        )
        .route(
            "/api/v1/projects/{id}/domain/availability",
            get(availability),
        )
        .route(
            "/api/v1/projects/{id}/custom_domains",
            get(list).post(create),
        )
        .route(
            "/api/v1/projects/{id}/custom_domains/{purpose}",
            axum::routing::delete(remove),
        )
        .route(
            "/api/v1/projects/{id}/custom_domains/preflight",
            get(preflight),
        )
        .route("/api/v1/projects/{id}/custom_domains/verify", post(verify))
        .route("/.well-known/trisixt-domain-verification", get(proof))
}
#[derive(Deserialize)]
struct Create {
    hostname: String,
    #[serde(default = "primary")]
    purpose: String,
}
fn primary() -> String {
    "primary".into()
}
pub async fn provision(
    st: &AppState,
    project: Uuid,
    hostname: &str,
    purpose: &str,
) -> Result<CustomHostname, AppError> {
    if !["primary", "migration"].contains(&purpose) {
        return Err(AppError::BadRequest("invalid hostname purpose".into()));
    }
    let host = custom_hostname(hostname, &st.config.server_host)?;
    let mode = std::env::var("CUSTOM_DOMAIN_MODE").unwrap_or_else(|_| "manual".into());
    if !["manual", "cloudflare"].contains(&mode.as_str()) {
        return Err(AppError::Config(
            "CUSTOM_DOMAIN_MODE must be manual or cloudflare".into(),
        ));
    }
    if mode == "manual" {
        verification_token(&host)?;
    }
    let occupied: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM projects WHERE lower(domain)=$1)")
            .bind(&host)
            .fetch_one(&st.pg)
            .await?;
    if occupied {
        return Err(AppError::Conflict("hostname is already assigned".into()));
    }
    let instance: Uuid = sqlx::query_scalar("SELECT instance_id FROM projects WHERE id=$1")
        .bind(project)
        .fetch_one(&st.pg)
        .await?;
    let source = if crate::billing::self_hosted() {
        "enterprise"
    } else {
        if !crate::billing::has_paid_entitlement(st, instance).await? {
            return Err(AppError::Forbidden);
        }
        "saas"
    };
    let ch=sqlx::query_as::<_,CustomHostname>("INSERT INTO custom_hostnames(project_id,hostname,purpose,source,mode,status) VALUES($1,$2,$3,$6,$4,$5) ON CONFLICT DO NOTHING RETURNING*").bind(project).bind(host).bind(purpose).bind(&mode).bind(if mode=="manual"{"pending"}else{"provisioning"}).bind(source).fetch_optional(&st.pg).await?.ok_or_else(||AppError::Conflict("hostname or project purpose already claimed".into()))?;
    if mode == "cloudflare" {
        match Cloudflare::from_env()?.create(&ch.hostname).await {
            Ok(v) => apply_cloudflare(&st.pg, ch.id, &v).await?,
            Err(e) => {
                sqlx::query("UPDATE custom_hostnames SET verification_errors='Cloudflare provisioning failed',last_checked_at=now() WHERE id=$1").bind(ch.id).execute(&st.pg).await?;
                return Err(e);
            }
        }
    }
    get_hostname(&st.pg, ch.id).await
}
async fn get_hostname(pg: &sqlx::PgPool, id: Uuid) -> Result<CustomHostname, AppError> {
    sqlx::query_as("SELECT* FROM custom_hostnames WHERE id=$1")
        .bind(id)
        .fetch_optional(pg)
        .await?
        .ok_or(AppError::NotFound)
}
async fn create(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(b): Json<Create>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    authorize_project(&st, &user, id, true).await?;
    rate_limit(&st.pg, &format!("domain-write:{id}"), 10).await?;
    let ch = provision(&st, id, &b.hostname, &b.purpose).await?;
    audit(&st, id, Some(user.id), "custom_domain.created", ch.id).await?;
    Ok((StatusCode::CREATED, Json(json!({"custom_domain":ch}))))
}
async fn list(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, AppError> {
    authorize_project(&st, &user, id, false).await?;
    let rows=sqlx::query_as::<_,CustomHostname>("SELECT* FROM custom_hostnames WHERE project_id=$1 ORDER BY CASE purpose WHEN 'primary' THEN 0 ELSE 1 END").bind(id).fetch_all(&st.pg).await?;
    Ok(Json(
        json!({"custom_domains":rows,"ingress_host":st.config.server_host}),
    ))
}
async fn proof(State(st): State<AppState>, headers: HeaderMap) -> Result<Json<Value>, AppError> {
    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .ok_or(AppError::NotFound)?;
    let host = normalize_hostname(host.split(':').next().unwrap_or(""))?;
    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM custom_hostnames WHERE hostname=$1 AND mode='manual' AND status IN('pending','active'))").bind(&host).fetch_one(&st.pg).await?;
    if !exists {
        return Err(AppError::NotFound);
    }
    Ok(Json(json!({"token":verification_token(&host)?})))
}
#[derive(Deserialize)]
struct HostQuery {
    hostname: String,
}
async fn verify(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(b): Json<HostQuery>,
) -> Result<Json<Value>, AppError> {
    authorize_project(&st, &user, id, true).await?;
    rate_limit(&st.pg, &format!("domain-write:{id}"), 10).await?;
    let ch = sqlx::query_as::<_, CustomHostname>(
        "SELECT* FROM custom_hostnames WHERE project_id=$1 AND hostname=$2",
    )
    .bind(id)
    .bind(normalize_hostname(&b.hostname)?)
    .fetch_optional(&st.pg)
    .await?
    .ok_or(AppError::NotFound)?;
    refresh(&st, &ch).await?;
    Ok(Json(
        json!({"custom_domain":get_hostname(&st.pg,ch.id).await?}),
    ))
}
async fn apply_cloudflare(pg: &sqlx::PgPool, id: Uuid, v: &Value) -> Result<(), AppError> {
    let cfid = v["id"].as_str().ok_or(AppError::Upstream)?;
    let active = v["status"] == "active" && v["ssl"]["status"] == "active";
    let ov = if v["ownership_verification"]["type"] == "txt" {
        Some(v["ownership_verification"].clone())
    } else {
        None
    };
    let mut tx = pg.begin().await?;
    let row=sqlx::query_as::<_,(Uuid,String,String)>("UPDATE custom_hostnames SET cf_id=$2,status=CASE WHEN $3 THEN 'active' WHEN created_at<now()-interval '72 hours' THEN 'failed' ELSE 'pending' END,ssl_status=$4,ssl_method=$5,validation_records=$6,ownership_verification=$7,verification_errors=NULL,last_checked_at=now(),updated_at=now(),activated_at=CASE WHEN $3 THEN coalesce(activated_at,now()) ELSE activated_at END WHERE id=$1 AND status IN('provisioning','pending','active') RETURNING project_id,purpose,hostname").bind(id).bind(cfid).bind(active).bind(v["ssl"]["status"].as_str()).bind(v["ssl"]["method"].as_str()).bind(cloudflare_records(v)).bind(ov).fetch_optional(&mut *tx).await?;
    if let Some((project, purpose, host)) = row
        && purpose == "primary"
        && active
    {
        sqlx::query("INSERT INTO project_domains(project_id,active_custom_host) VALUES($1,$2) ON CONFLICT(project_id) DO UPDATE SET active_custom_host=excluded.active_custom_host").bind(project).bind(host).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}
async fn domain_lock(
    st: &AppState,
    id: Uuid,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, AppError> {
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,31))")
        .bind(id.to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}
async fn refresh(st: &AppState, ch: &CustomHostname) -> Result<(), AppError> {
    if ch.status == "suspended" {
        return teardown(st, ch.id).await.map(|_| ());
    }
    let _guard = domain_lock(st, ch.id).await?;
    let ch = get_hostname(&st.pg, ch.id).await?;
    if !["pending", "provisioning", "active"].contains(&ch.status.as_str()) {
        return Ok(());
    }
    if ch.mode == "cloudflare" {
        let cf = Cloudflare::from_env()?;
        let result = match &ch.cf_id {
            Some(id) => cf.status(id).await,
            None => match cf.lookup(&ch.hostname).await {
                Ok(value) => Ok(value),
                Err(_) => cf.create(&ch.hostname).await,
            },
        };
        match result {
            Ok(v) => apply_cloudflare(&st.pg, ch.id, &v).await,
            Err(e) => {
                sqlx::query("UPDATE custom_hostnames SET verification_errors='Cloudflare status unavailable',last_checked_at=now() WHERE id=$1").bind(ch.id).execute(&st.pg).await?;
                Err(e)
            }
        }
    } else {
        match verify_manual(&ch.hostname).await {
            Ok(()) => {
                let mut tx = st.pg.begin().await?;
                let updated=sqlx::query("UPDATE custom_hostnames SET status='active',verification_errors=NULL,activated_at=coalesce(activated_at,now()),last_checked_at=now(),updated_at=now() WHERE id=$1 AND status='pending'").bind(ch.id).execute(&mut *tx).await?;
                if updated.rows_affected() > 0 && ch.purpose == "primary" {
                    sqlx::query("INSERT INTO project_domains(project_id,active_custom_host) VALUES($1,$2) ON CONFLICT(project_id) DO UPDATE SET active_custom_host=excluded.active_custom_host").bind(ch.project_id).bind(&ch.hostname).execute(&mut *tx).await?;
                }
                tx.commit().await?;
                Ok(())
            }
            Err(e) => {
                sqlx::query("UPDATE custom_hostnames SET verification_errors='DNS or TLS proof not satisfied',last_checked_at=now() WHERE id=$1 AND status='pending'").bind(ch.id).execute(&st.pg).await?;
                Err(e)
            }
        }
    }
}
pub async fn teardown(st: &AppState, id: Uuid) -> Result<bool, AppError> {
    let _guard = domain_lock(st, id).await?;
    let ch = get_hostname(&st.pg, id).await?;
    let mut tx = st.pg.begin().await?;
    sqlx::query("UPDATE custom_hostnames SET status='suspended',updated_at=now() WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE project_domains SET active_custom_host=NULL WHERE project_id=$1 AND active_custom_host=$2").bind(ch.project_id).bind(&ch.hostname).execute(&mut *tx).await?;
    tx.commit().await?;
    if ch.mode == "cloudflare" {
        let cf = Cloudflare::from_env()?;
        let remote = match ch.cf_id {
            Some(id) => Some(id),
            None => match cf.lookup(&ch.hostname).await {
                Ok(v) => v["id"].as_str().map(str::to_owned),
                Err(AppError::NotFound) => None,
                Err(_) => return Ok(false),
            },
        };
        if let Some(id) = remote
            && cf.delete(&id).await.is_err()
        {
            return Ok(false);
        }
    }
    sqlx::query("DELETE FROM custom_hostnames WHERE id=$1 AND status='suspended'")
        .bind(id)
        .execute(&st.pg)
        .await?;
    Ok(true)
}
async fn remove(
    State(st): State<AppState>,
    user: AuthUser,
    Path((project, purpose)): Path<(Uuid, String)>,
) -> Result<StatusCode, AppError> {
    authorize_project(&st, &user, project, true).await?;
    rate_limit(&st.pg, &format!("domain-write:{project}"), 10).await?;
    let id = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM custom_hostnames WHERE project_id=$1 AND purpose=$2",
    )
    .bind(project)
    .bind(purpose)
    .fetch_optional(&st.pg)
    .await?
    .ok_or(AppError::NotFound)?;
    let removed = teardown(&st, id).await?;
    audit(&st, project, Some(user.id), "custom_domain.deleted", id).await?;
    Ok(if removed {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::ACCEPTED
    })
}
pub async fn resolve_project(pg: &sqlx::PgPool, host: &str) -> Result<Option<Uuid>, AppError> {
    Ok(sqlx::query_scalar(
        "SELECT project_id FROM custom_hostnames WHERE hostname=$1 AND status='active'",
    )
    .bind(normalize_hostname(host)?)
    .fetch_optional(pg)
    .await?)
}
pub async fn display_host(pg: &sqlx::PgPool, project: Uuid) -> Result<String, AppError> {
    Ok(sqlx::query_scalar("SELECT coalesce(d.active_custom_host,p.domain) FROM projects p LEFT JOIN project_domains d ON d.project_id=p.id WHERE p.id=$1").bind(project).fetch_one(pg).await?)
}
pub async fn tick(st: &AppState) -> Result<usize, AppError> {
    tokio::time::timeout(Duration::from_secs(90), maintenance(st))
        .await
        .map_err(|_| AppError::Upstream)?
}
async fn maintenance(st: &AppState) -> Result<usize, AppError> {
    let paid_rows=sqlx::query_as::<_,(Uuid,Uuid,Option<DateTime<Utc>>)>("SELECT c.id,p.instance_id,c.grace_until FROM custom_hostnames c JOIN projects p ON p.id=c.project_id WHERE c.source='saas' AND c.status IN('active','pending','provisioning') ORDER BY c.updated_at LIMIT 500").fetch_all(&st.pg).await?;
    for (id, instance, grace) in paid_rows {
        if crate::billing::has_paid_entitlement(st, instance).await? {
            sqlx::query("UPDATE custom_hostnames SET grace_until=NULL WHERE id=$1 AND grace_until IS NOT NULL").bind(id).execute(&st.pg).await?;
        } else if grace.is_some_and(|g| g < Utc::now()) {
            let _ = teardown(st, id).await;
        } else if grace.is_none() {
            sqlx::query("UPDATE custom_hostnames SET grace_until=now()+interval '7 days' WHERE id=$1 AND grace_until IS NULL").bind(id).execute(&st.pg).await?;
        }
    }
    let stale=sqlx::query_scalar::<_,Uuid>("SELECT id FROM custom_hostnames WHERE status='failed' AND updated_at<now()-interval '7 days' LIMIT 50").fetch_all(&st.pg).await?;
    for id in stale {
        let _ = teardown(st, id).await;
    }

    let rows=sqlx::query_as::<_,CustomHostname>("SELECT* FROM custom_hostnames WHERE status IN('provisioning','pending','suspended') AND NOT(mode='manual' AND status='pending' AND created_at<now()-interval '72 hours') AND(last_checked_at IS NULL OR last_checked_at<now()-interval '1 minute') ORDER BY CASE status WHEN 'suspended' THEN 0 ELSE 1 END,last_checked_at NULLS FIRST LIMIT 50").fetch_all(&st.pg).await?;
    let mut n = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    for ch in rows {
        if tokio::time::Instant::now() > deadline {
            break;
        }
        let _ = refresh(st, &ch).await;
        n += 1;
    }
    sqlx::query("DELETE FROM connectivity_rate_limits WHERE expires_at<now()-interval '1 day'")
        .execute(&st.pg)
        .await?;
    Ok(n)
}
async fn audit(
    st: &AppState,
    project: Uuid,
    user: Option<Uuid>,
    action: &str,
    id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("SELECT trisixt_audit(instance_id,$2,$3,$4,'{}') FROM projects WHERE id=$1")
        .bind(project)
        .bind(user)
        .bind(action)
        .bind(id)
        .execute(&st.pg)
        .await?;
    Ok(())
}
async fn preflight(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Query(q): Query<HostQuery>,
) -> Result<Json<Value>, AppError> {
    authorize_project(&st, &user, id, false).await?;
    rate_limit(&st.pg, &format!("domain-read:{id}"), 60).await?;
    let host = normalize_hostname(&q.hostname)?;
    if let Some(value)=sqlx::query_scalar::<_,Value>("SELECT result FROM domain_preflight_cache WHERE project_id=$1 AND hostname=$2 AND expires_at>now()").bind(id).bind(&host).fetch_optional(&st.pg).await?{return Ok(Json(value));}
    let resolver = hickory_resolver::TokioResolver::builder_tokio()
        .map_err(|_| AppError::Upstream)?
        .build()
        .map_err(|_| AppError::Upstream)?;
    let lookup = tokio::time::timeout(
        Duration::from_secs(3),
        resolver.lookup(host.clone(), hickory_resolver::proto::rr::RecordType::CNAME),
    )
    .await;
    let actual = match lookup {
        Ok(Ok(records)) => records
            .answers()
            .iter()
            .find_map(|record| match &record.data {
                hickory_resolver::proto::rr::RData::CNAME(name) => {
                    Some(name.to_string().trim_end_matches('.').to_ascii_lowercase())
                }
                _ => None,
            }),
        _ => None,
    };
    let mode = sqlx::query_scalar::<_, String>(
        "SELECT mode FROM custom_hostnames WHERE project_id=$1 AND hostname=$2",
    )
    .bind(id)
    .bind(&host)
    .fetch_optional(&st.pg)
    .await?
    .unwrap_or_else(|| std::env::var("CUSTOM_DOMAIN_MODE").unwrap_or_else(|_| "manual".into()));
    let expected = if mode == "cloudflare" {
        std::env::var("CLOUDFLARE_SAAS_CNAME_TARGET")
            .unwrap_or_else(|_| st.config.server_host.clone())
    } else {
        st.config.server_host.clone()
    };
    let result = json!({"hostname":host,"cname_expected":expected,"cname_actual":actual,"cname_matches":actual.as_ref()==Some(&expected),"checked_at":Utc::now()});
    sqlx::query("INSERT INTO domain_preflight_cache(project_id,hostname,result,expires_at) VALUES($1,$2,$3,now()+interval '30 seconds') ON CONFLICT(project_id,hostname) DO UPDATE SET result=excluded.result,expires_at=excluded.expires_at").bind(id).bind(host).bind(&result).execute(&st.pg).await?;
    Ok(Json(result))
}
async fn domain(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, AppError> {
    authorize_project(&st, &user, id, false).await?;
    sqlx::query("INSERT INTO project_domains(project_id) VALUES($1) ON CONFLICT DO NOTHING")
        .bind(id)
        .execute(&st.pg)
        .await?;
    let v=sqlx::query_scalar::<_,Value>("SELECT to_jsonb(d)||jsonb_build_object('domain',p.domain,'display_host',coalesce(d.active_custom_host,p.domain)) FROM project_domains d JOIN projects p ON p.id=d.project_id WHERE d.project_id=$1").bind(id).fetch_one(&st.pg).await?;
    Ok(Json(json!({"domain":v})))
}
async fn availability(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Query(q): Query<HostQuery>,
) -> Result<Json<Value>, AppError> {
    authorize_project(&st, &user, id, false).await?;
    let host = normalize_hostname(&q.hostname)?;
    let used=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM projects WHERE lower(domain)=$1 AND id<>$2) OR EXISTS(SELECT 1 FROM custom_hostnames WHERE hostname=$1) OR EXISTS(SELECT 1 FROM migration_hosts WHERE hostname=$1)").bind(&host).bind(id).fetch_one(&st.pg).await?;
    Ok(Json(json!({"hostname":host,"available":!used})))
}
async fn update_domain(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(v): Json<Value>,
) -> Result<Json<Value>, AppError> {
    authorize_project(&st, &user, id, true).await?;
    if !v.is_object() || v.to_string().len() > 8192 {
        return Err(AppError::BadRequest("invalid branding".into()));
    }
    if let Some(value) = v.get("google_tracking_id") {
        validate_tracking_id(value)?;
    }
    if let Some(label) = v["subdomain"].as_str() {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            || crate::routing::is_reserved(&label.to_ascii_lowercase())
        {
            return Err(AppError::BadRequest("invalid or reserved subdomain".into()));
        }
        let host = format!("{}.{}", label.to_ascii_lowercase(), st.config.server_host);
        let occupied=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM custom_hostnames WHERE hostname=$1) OR EXISTS(SELECT 1 FROM migration_hosts WHERE hostname=$1)").bind(&host).fetch_one(&st.pg).await?;
        if occupied {
            return Err(AppError::Conflict("hostname already claimed".into()));
        }
        sqlx::query("UPDATE projects SET domain=$2 WHERE id=$1")
            .bind(id)
            .bind(host)
            .execute(&st.pg)
            .await?;
    }
    if let Some(image) = v["generic_image_url"].as_str() {
        let u =
            url::Url::parse(image).map_err(|_| AppError::BadRequest("invalid image URL".into()))?;
        if !["http", "https"].contains(&u.scheme()) {
            return Err(AppError::BadRequest("image URL must use HTTP(S)".into()));
        }
    }
    sqlx::query("INSERT INTO project_domains(project_id,generic_title,generic_subtitle,generic_image_url,google_tracking_id) VALUES($1,coalesce($2,'Trisixt'),coalesce($3,''),$4,$5) ON CONFLICT(project_id) DO UPDATE SET generic_title=coalesce($2,project_domains.generic_title),generic_subtitle=coalesce($3,project_domains.generic_subtitle),generic_image_url=coalesce($4,project_domains.generic_image_url),google_tracking_id=coalesce($5,project_domains.google_tracking_id),updated_at=now()").bind(id).bind(v["generic_title"].as_str()).bind(v["generic_subtitle"].as_str()).bind(v["generic_image_url"].as_str()).bind(v["google_tracking_id"].as_str()).execute(&st.pg).await?;
    audit(&st, id, Some(user.id), "domain.updated", id).await?;
    domain(State(st), user, Path(id)).await
}

/// Google tag identifiers are data, never executable script content.
pub fn validate_tracking_id(value: &Value) -> Result<(), AppError> {
    if value.is_null() || value.as_str() == Some("") {
        return Ok(());
    }
    let valid = value.as_str().is_some_and(|s| {
        s.len() <= 64
            && ["G-", "GT-", "UA-"].iter().any(|p| s.starts_with(p))
            && s.len() > 3
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    if valid {
        Ok(())
    } else {
        Err(AppError::BadRequest("invalid Google tracking ID".into()))
    }
}
async fn set_google_tracking_id(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(v): Json<Value>,
) -> Result<Json<Value>, AppError> {
    authorize_project(&st, &user, id, true).await?;
    let value = v
        .get("google_tracking_id")
        .ok_or_else(|| AppError::BadRequest("google_tracking_id required".into()))?;
    validate_tracking_id(value)?;
    sqlx::query("INSERT INTO project_domains(project_id,google_tracking_id)VALUES($1,$2)ON CONFLICT(project_id)DO UPDATE SET google_tracking_id=excluded.google_tracking_id,updated_at=now()")
        .bind(id).bind(value.as_str().filter(|s|!s.is_empty())).execute(&st.pg).await?;
    audit(
        &st,
        id,
        Some(user.id),
        "domain.google_tracking_id_updated",
        id,
    )
    .await?;
    domain(State(st), user, Path(id)).await
}

async fn domain_defaults(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
) -> Result<Json<Value>, AppError> {
    authorize_project(&st, &user, project, false).await?;
    let title = std::env::var("DEFAULT_LINK_TITLE").unwrap_or_else(|_| "Trisixt".into());
    let subtitle = std::env::var("DEFAULT_LINK_SUBTITLE").unwrap_or_else(|_| {
        "Dynamic links, attributions, and referrals across mobile and web platforms.".into()
    });
    let image = std::env::var("DEFAULT_SOCIAL_PREVIEW_URL")
        .ok()
        .filter(|s| !s.trim().is_empty());
    if let Some(ref value) = image {
        let parsed = url::Url::parse(value)
            .map_err(|_| AppError::Config("invalid DEFAULT_SOCIAL_PREVIEW_URL".into()))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(AppError::Config(
                "invalid DEFAULT_SOCIAL_PREVIEW_URL".into(),
            ));
        }
    }
    Ok(Json(
        json!({"generic_title":title,"generic_subtitle":subtitle,"generic_image_url":image}),
    ))
}
