//! Branch/AppsFlyer first-hit migration and Firebase export ingestion.
use crate::{
    auth::{AuthUser, authorize_project, new_token},
    domains::{bounded_json, normalize_hostname, rate_limit},
    error::AppError,
    state::AppState,
};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone, sqlx::FromRow)]
struct Source {
    id: Uuid,
    project_id: Uuid,
    provider: String,
    old_host: String,
    provider_hosted: bool,
    credentials_ciphertext: String,
    enabled: bool,
    consecutive_failures: i32,
    first_failure_at: Option<DateTime<Utc>>,
    last_error_status: Option<i32>,
    auto_disabled_at: Option<DateTime<Utc>>,
    degraded_email_sent_at: Option<DateTime<Utc>>,
}
const SOURCE_SELECT: &str = "SELECT id,project_id,provider,old_host,provider_hosted,credentials_ciphertext,enabled,consecutive_failures,first_failure_at,last_error_status,auto_disabled_at,degraded_email_sent_at FROM migration_sources";
impl Source {
    fn public(&self) -> Value {
        json!({"id":self.id,"project_id":self.project_id,"provider":self.provider,"old_host":self.old_host,"provider_hosted":self.provider_hosted,"enabled":self.enabled,"health":if !self.enabled{"disabled"}else if self.consecutive_failures>0{"degraded"}else{"healthy"},"consecutive_failures":self.consecutive_failures,"first_failure_at":self.first_failure_at,"last_error_status":self.last_error_status,"auto_disabled_at":self.auto_disabled_at,"degraded_email_sent_at":self.degraded_email_sent_at})
    }
}
fn cipher() -> Result<Aes256Gcm, AppError> {
    let key = std::env::var("MIGRATION_ENCRYPTION_KEY")
        .map_err(|_| AppError::Config("MIGRATION_ENCRYPTION_KEY hex32-byte key required".into()))?;
    let key = hex::decode(key)
        .map_err(|_| AppError::Config("invalid migration encryption key".into()))?;
    Aes256Gcm::new_from_slice(&key)
        .map_err(|_| AppError::Config("migration encryption key must have32 bytes".into()))
}
fn encrypt(v: &Value) -> Result<String, AppError> {
    let random = Sha256::digest(new_token().0.as_bytes());
    let nonce = Nonce::from_slice(&random[..12]);
    let mut data = random[..12].to_vec();
    data.extend(
        cipher()?
            .encrypt(nonce, v.to_string().as_bytes())
            .map_err(|_| AppError::Internal)?,
    );
    Ok(STANDARD.encode(data))
}
fn decrypt(s: &str) -> Result<Value, AppError> {
    let data = STANDARD.decode(s).map_err(|_| AppError::Internal)?;
    if data.len() < 28 {
        return Err(AppError::Internal);
    }
    let bytes = cipher()?
        .decrypt(Nonce::from_slice(&data[..12]), &data[12..])
        .map_err(|_| AppError::Internal)?;
    serde_json::from_slice(&bytes).map_err(|_| AppError::Internal)
}
fn credentials(provider: &str, v: &Value) -> Result<Value, AppError> {
    let keys: Vec<&str> = match provider {
        "branch" => vec!["branch_key"],
        "appsflyer" => vec!["onelink_id", "api_token"],
        "firebase" => vec![],
        _ => {
            return Err(AppError::BadRequest(
                "unsupported migration provider".into(),
            ));
        }
    };
    let mut out = serde_json::Map::new();
    for key in keys {
        let value = v[key]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 4096)
            .ok_or_else(|| AppError::BadRequest(format!("credential {key} required")))?;
        out.insert(key.into(), json!(value));
    }
    Ok(Value::Object(out))
}
pub fn parse_retry_after(value: &str) -> Option<u64> {
    let seconds = value.trim().parse::<i64>().ok().or_else(|| {
        chrono::DateTime::parse_from_rfc2822(value)
            .ok()
            .map(|date| (date.with_timezone(&Utc) - Utc::now()).num_seconds())
    })?;
    (seconds > 0).then(|| seconds.clamp(5, 3600) as u64)
}
#[derive(Debug, Clone, PartialEq)]
pub enum Lookup {
    Found(Value),
    NotFound,
    Transient {
        status: u16,
        retry_after: Option<u64>,
    },
}
#[derive(Clone)]
pub struct ProviderClient {
    client: reqwest::Client,
    branch: String,
    appsflyer: String,
}
impl ProviderClient {
    pub fn new(branch: String, appsflyer: String) -> Result<Self, AppError> {
        for s in [&branch, &appsflyer] {
            let u = url::Url::parse(s)
                .map_err(|_| AppError::Config("invalid import provider endpoint".into()))?;
            if u.scheme() != "https"
                && !(u.scheme() == "http"
                    && matches!(u.host_str(), Some("127.0.0.1" | "localhost")))
            {
                return Err(AppError::Config("import providers require HTTPS".into()));
            }
        }
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| AppError::Internal)?,
            branch,
            appsflyer,
        })
    }
    fn from_env() -> Result<Self, AppError> {
        Self::new(
            std::env::var("BRANCH_API_ENDPOINT")
                .unwrap_or_else(|_| "https://api2.branch.io/v1/url".into()),
            std::env::var("APPSFLYER_API_ENDPOINT")
                .unwrap_or_else(|_| "https://onelink.appsflyer.com/api/v2.0/shortlinks".into()),
        )
    }
    pub async fn fetch(
        &self,
        provider: &str,
        host: &str,
        path: &str,
        query: &str,
        creds: &Value,
    ) -> Lookup {
        if provider == "firebase" {
            return Lookup::NotFound;
        }
        let req = if provider == "branch" {
            let Ok(mut old) = url::Url::parse(&format!("https://{host}/")) else {
                return Lookup::Transient {
                    status: 0,
                    retry_after: None,
                };
            };
            old.set_path(&format!("/{path}"));
            if !query.is_empty() {
                old.set_query(Some(query));
            }
            self.client.get(&self.branch).query(&[
                ("url", old.as_str()),
                ("branch_key", creds["branch_key"].as_str().unwrap_or("")),
            ])
        } else {
            let mut url = match url::Url::parse(&self.appsflyer) {
                Ok(u) => u,
                Err(_) => {
                    return Lookup::Transient {
                        status: 0,
                        retry_after: None,
                    };
                }
            };
            if let Ok(mut segments) = url.path_segments_mut() {
                segments
                    .pop_if_empty()
                    .push(creds["onelink_id"].as_str().unwrap_or(""))
                    .push(path.rsplit('/').find(|s| !s.is_empty()).unwrap_or(""));
            }
            self.client
                .get(url)
                .bearer_auth(creds["api_token"].as_str().unwrap_or(""))
        };
        let response = match req.send().await {
            Ok(r) => r,
            Err(_) => {
                return Lookup::Transient {
                    status: 0,
                    retry_after: None,
                };
            }
        };
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_retry_after);
        if status == 404 {
            return Lookup::NotFound;
        }
        if status != 200 {
            return Lookup::Transient {
                status,
                retry_after,
            };
        }
        match bounded_json(response, 262144)
            .await
            .and_then(|v| map_payload(provider, v))
        {
            Ok(payload) => Lookup::Found(payload),
            Err(_) => Lookup::Transient {
                status,
                retry_after: None,
            },
        }
    }
}
pub fn map_payload(provider: &str, body: Value) -> Result<Value, AppError> {
    let mut data = if provider == "branch" {
        body.get("data").unwrap_or(&body).clone()
    } else {
        body
    };
    if let Some(s) = data.as_str() {
        data = serde_json::from_str(s).map_err(|_| AppError::Upstream)?;
    }
    let mut data = data.as_object().cloned().ok_or(AppError::Upstream)?;
    let fields: Vec<(&str, Vec<&str>)> = if provider == "branch" {
        vec![
            ("ios_url", vec!["$ios_url"]),
            ("android_url", vec!["$android_url"]),
            ("desktop_url", vec!["$desktop_url"]),
            ("og_title", vec!["$og_title"]),
            ("og_description", vec!["$og_description"]),
            ("og_image_url", vec!["$og_image_url"]),
            (
                "name",
                vec!["$link_title", "$marketing_title", "$og_title", "~feature"],
            ),
            ("tracking_campaign", vec!["~campaign", "utm_campaign"]),
            ("tracking_source", vec!["~channel", "utm_source"]),
            ("tracking_medium", vec!["~feature", "utm_medium"]),
        ]
    } else {
        vec![
            ("ios_url", vec!["af_ios_url", "af_dp"]),
            ("android_url", vec!["af_android_url", "af_dp"]),
            ("desktop_url", vec!["af_web_dp"]),
            ("og_title", vec!["af_og_title", "af_title"]),
            ("og_description", vec!["af_og_description", "af_subtitle"]),
            ("og_image_url", vec!["af_og_image"]),
            ("name", vec!["af_ad", "af_title"]),
            ("tracking_campaign", vec!["c"]),
            ("tracking_source", vec!["pid"]),
            ("tracking_medium", vec!["af_channel"]),
        ]
    };
    let original = data.clone();
    let mut out = serde_json::Map::new();
    for (target, keys) in fields {
        if let Some(v) = keys
            .iter()
            .find_map(|k| original.get(*k).filter(|v| v.is_string()))
        {
            out.insert(target.into(), v.clone());
        }
        for k in keys {
            data.remove(k);
        }
    }
    let tags = data
        .remove("~tags")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .take(100)
        .map(|s| s.chars().take(255).collect::<String>())
        .collect::<Vec<_>>();
    data.remove("~stage");
    let custom = Value::Object(data);
    out.insert(
        "custom_data".into(),
        if custom.to_string().len() <= 65536 {
            custom
        } else {
            json!({})
        },
    );
    out.insert("tags".into(), json!(tags));
    out.insert("provider".into(), json!(provider));
    for key in ["desktop_url", "og_image_url", "ios_url", "android_url"] {
        if let Some(v) = out.get(key).and_then(Value::as_str)
            && !safe_url(v, key.starts_with("ios") || key.starts_with("android"))
        {
            out.remove(key);
        }
    }
    Ok(Value::Object(out))
}
fn safe_url(s: &str, mobile: bool) -> bool {
    url::Url::parse(s).is_ok_and(|u| {
        if mobile {
            !["javascript", "data", "file", "vbscript", "about", "blob"].contains(&u.scheme())
        } else {
            ["http", "https"].contains(&u.scheme()) && u.host_str().is_some()
        }
    })
}

#[derive(Debug)]
pub enum ImportOutcome {
    Link(Value),
    Defaults,
}
async fn source_project(pg: &sqlx::PgPool, project: Uuid) -> Result<Source, AppError> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{SOURCE_SELECT} WHERE project_id=$1"
    )))
    .bind(project)
    .fetch_optional(pg)
    .await?
    .ok_or(AppError::NotFound)
}
pub async fn resolve(
    st: &AppState,
    project: Uuid,
    host: &str,
    path: &str,
    query: &str,
) -> Result<Option<ImportOutcome>, AppError> {
    if path.len() > 2048 || query.len() > 8192 {
        return Ok(None);
    }
    let host = normalize_hostname(host)?;
    let source=sqlx::query_as::<_,Source>(sqlx::AssertSqlSafe(format!("{SOURCE_SELECT} WHERE project_id=$1 AND id=(SELECT source_id FROM migration_hosts WHERE hostname=$2)"))).bind(project).bind(&host).fetch_optional(&st.pg).await?;
    let Some(source) = source else {
        return Ok(None);
    };
    if !source.provider_hosted {
        let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM custom_hostnames WHERE project_id=$1 AND hostname=$2 AND purpose='migration' AND status='active')").bind(project).bind(&host).fetch_one(&st.pg).await?;
        if !active {
            return Ok(None);
        }
    }
    if let Some((status,link))=sqlx::query_as::<_,(String,Option<Value>)>("SELECT m.status,to_jsonb(l) FROM migrated_links m LEFT JOIN links l ON l.id=m.link_id WHERE m.source_id=$1 AND m.old_path=$2 AND(m.status='resolved' OR m.cached_until>now())").bind(source.id).bind(path).fetch_optional(&st.pg).await?{return Ok(Some(if status=="resolved"{link.filter(|v|v["archived_at"].is_null()).map(ImportOutcome::Link).unwrap_or(ImportOutcome::Defaults)}else{ImportOutcome::Defaults}));}
    if !source.enabled {
        return Ok(if source.auto_disabled_at.is_some() {
            Some(ImportOutcome::Defaults)
        } else {
            None
        });
    }
    let mut tx = st.pg.begin().await?;
    let lock: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,20))")
            .bind(format!("{}:{path}", source.id))
            .fetch_one(&mut *tx)
            .await?;
    if !lock {
        return Ok(Some(ImportOutcome::Defaults));
    }
    // Recheck after claiming the lock: another request may have populated the cache.
    if let Some((status,link))=sqlx::query_as::<_,(String,Option<Value>)>("SELECT m.status,to_jsonb(l) FROM migrated_links m LEFT JOIN links l ON l.id=m.link_id WHERE m.source_id=$1 AND m.old_path=$2 AND(m.status='resolved' OR m.cached_until>now())").bind(source.id).bind(path).fetch_optional(&mut *tx).await? {return Ok(Some(if status=="resolved" {link.filter(|v|v["archived_at"].is_null()).map(ImportOutcome::Link).unwrap_or(ImportOutcome::Defaults)}else{ImportOutcome::Defaults}));}
    if rate_limit(&st.pg, &format!("import:{}", source.id), 6000)
        .await
        .is_err()
    {
        return Ok(Some(ImportOutcome::Defaults));
    }
    let lookup = ProviderClient::from_env()?
        .fetch(
            &source.provider,
            &source.old_host,
            path,
            query,
            &decrypt(&source.credentials_ciphertext)?,
        )
        .await;
    let outcome = match lookup {
        Lookup::Found(payload) => {
            let link = materialize(&mut tx, project, &payload, None).await?;
            cache(
                &mut tx,
                source.id,
                path,
                "resolved",
                Some(
                    link["id"]
                        .as_str()
                        .and_then(|s| s.parse().ok())
                        .ok_or(AppError::Internal)?,
                ),
                None,
            )
            .await?;
            success(&mut tx, source.id).await?;
            ImportOutcome::Link(link)
        }
        Lookup::NotFound => {
            cache(&mut tx, source.id, path, "not_found", None, Some(86400)).await?;
            success(&mut tx, source.id).await?;
            ImportOutcome::Defaults
        }
        Lookup::Transient {
            status,
            retry_after,
        } => {
            let ladder = [5, 30, 60, 300, 1800, 3600];
            let ttl =
                retry_after.unwrap_or(ladder[source.consecutive_failures.clamp(0, 5) as usize]);
            cache(
                &mut tx,
                source.id,
                path,
                "transient_error",
                None,
                Some(ttl as i64),
            )
            .await?;
            failure(&mut tx, &source, status).await?;
            ImportOutcome::Defaults
        }
    };
    tx.commit().await?;
    Ok(Some(outcome))
}
async fn materialize(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    project: Uuid,
    payload: &Value,
    path: Option<&str>,
) -> Result<Value, AppError> {
    let fallback: Option<String> = sqlx::query_scalar(
        "SELECT redirect->>'default_fallback' FROM project_configurations WHERE project_id=$1",
    )
    .bind(project)
    .fetch_optional(&mut **tx)
    .await?
    .flatten();
    let default: String =
        sqlx::query_scalar("SELECT 'https://'||domain||'/' FROM projects WHERE id=$1")
            .bind(project)
            .fetch_one(&mut **tx)
            .await?;
    let target = payload["desktop_url"]
        .as_str()
        .or(fallback.as_deref())
        .unwrap_or(&default);
    let path = path
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
    let name = payload["name"]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("Imported link")
        .chars()
        .take(200)
        .collect::<String>();
    let mut metadata = payload.clone();
    metadata["data"] = payload["custom_data"].clone();
    Ok(sqlx::query_scalar("INSERT INTO links(project_id,path,name,target_url,ios_url,android_url,metadata) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING to_jsonb(links)").bind(project).bind(path).bind(name).bind(target).bind(payload["ios_url"].as_str()).bind(payload["android_url"].as_str()).bind(metadata).fetch_one(&mut **tx).await?)
}
async fn cache(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    source: Uuid,
    path: &str,
    status: &str,
    link: Option<Uuid>,
    ttl: Option<i64>,
) -> Result<(), AppError> {
    sqlx::query("INSERT INTO migrated_links(source_id,old_path,status,link_id,cached_until) VALUES($1,$2,$3,$4,CASE WHEN $5::bigint IS NULL THEN NULL ELSE now()+make_interval(secs=>$5::double precision) END) ON CONFLICT(source_id,old_path) DO UPDATE SET status=excluded.status,link_id=excluded.link_id,cached_until=excluded.cached_until,updated_at=now()").bind(source).bind(path).bind(status).bind(link).bind(ttl).execute(&mut **tx).await?;
    Ok(())
}
async fn success(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    source: Uuid,
) -> Result<(), AppError> {
    sqlx::query("UPDATE migration_sources SET consecutive_failures=0,first_failure_at=NULL,last_error_status=NULL,degraded_email_sent_at=CASE WHEN degraded_email_sent_at<now()-interval '24 hours' THEN NULL ELSE degraded_email_sent_at END WHERE id=$1").bind(source).execute(&mut **tx).await?;
    Ok(())
}
async fn failure(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    source: &Source,
    status: u16,
) -> Result<(), AppError> {
    sqlx::query("UPDATE migration_sources SET consecutive_failures=consecutive_failures+1,first_failure_at=coalesce(first_failure_at,now()),last_error_status=$2,updated_at=now() WHERE id=$1").bind(source.id).bind(i32::from(status)).execute(&mut **tx).await?;
    let notify:bool=sqlx::query_scalar("UPDATE migration_sources SET degraded_email_sent_at=now() WHERE id=$1 AND first_failure_at<now()-interval '1 hour' AND(degraded_email_sent_at IS NULL OR degraded_email_sent_at<now()-interval '24 hours') RETURNING true").bind(source.id).fetch_optional(&mut **tx).await?.unwrap_or(false);
    let disabled:bool=sqlx::query_scalar("UPDATE migration_sources SET enabled=false,auto_disabled_at=now() WHERE id=$1 AND enabled AND(consecutive_failures>=500 OR first_failure_at<now()-interval '2 days') RETURNING true").bind(source.id).fetch_optional(&mut **tx).await?.unwrap_or(false);
    for (kind, yes) in [("degraded", notify), ("disabled", disabled)] {
        if yes {
            sqlx::query("INSERT INTO migration_alerts(source_id,kind,payload) VALUES($1,$2,$3)").bind(source.id).bind(kind).bind(json!({"project_id":source.project_id,"provider":source.provider,"hostname":source.old_host,"http_status":status})).execute(&mut **tx).await?;
        }
    }
    Ok(())
}
pub async fn resolve_sdk(
    st: &AppState,
    project: Uuid,
    input: &str,
) -> Result<Option<ImportOutcome>, AppError> {
    let input = input.trim();
    if input.is_empty() || input.len() > 8192 {
        return Ok(None);
    }
    if let Ok(url) = url::Url::parse(input)
        && ["http", "https"].contains(&url.scheme())
        && let Some(host) = url.host_str()
    {
        return resolve(
            st,
            project,
            host,
            url.path().trim_start_matches('/'),
            url.query().unwrap_or(""),
        )
        .await;
    }
    if !input.contains("://") && input.contains('=') {
        if let Some((_, value)) =
            url::form_urlencoded::parse(input.as_bytes()).find(|(k, _)| k == "~referring_link")
            && let Ok(url) = url::Url::parse(&value)
            && let Some(host) = url.host_str()
        {
            return resolve(
                st,
                project,
                host,
                url.path().trim_start_matches('/'),
                url.query().unwrap_or(""),
            )
            .await;
        }
        return Ok(None);
    }
    let source = match source_project(&st.pg, project).await {
        Ok(s) => s,
        Err(AppError::NotFound) => return Ok(None),
        Err(e) => return Err(e),
    };
    let slug = input
        .split_once("://")
        .map(|(_, s)| s)
        .unwrap_or(input)
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .trim_start_matches('/');
    resolve(st, project, &source.old_host, slug, "").await
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/projects/{id}/migrations", post(create))
        .route(
            "/api/v1/projects/{id}/migration_source",
            get(show).patch(update).delete(remove),
        )
        .route("/api/v1/projects/{id}/migration_source/test", post(probe))
        .route(
            "/api/v1/projects/{id}/migration_source/backfill",
            post(backfill),
        )
        .route("/api/v1/projects/{id}/migrations/firebase", post(firebase))
        .layer(DefaultBodyLimit::max(8 * 1024 * 1024))
}
#[derive(Deserialize)]
struct CreateSource {
    provider: String,
    hostname: String,
    credentials: Value,
    #[serde(default)]
    provider_hosted: bool,
    #[serde(default)]
    extra_hosts: Vec<String>,
}
async fn create(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Json(b): Json<CreateSource>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    authorize_project(&st, &user, project, true).await?;
    let host = normalize_hostname(&b.hostname)?;
    let creds = credentials(&b.provider, &b.credentials)?;
    let encrypted = encrypt(&creds)?;
    let probe = ProviderClient::from_env()?
        .fetch(
            &b.provider,
            &host,
            &format!("__trisixt_setup_probe_{}", Uuid::new_v4()),
            "",
            &creds,
        )
        .await;
    if matches!(
        probe,
        Lookup::Transient {
            status: 400 | 401 | 403,
            ..
        }
    ) {
        return Err(AppError::BadRequest(
            "provider credentials are invalid".into(),
        ));
    }

    if !b.provider_hosted && !b.extra_hosts.is_empty() {
        return Err(AppError::BadRequest(
            "extra hosts require provider_hosted".into(),
        ));
    }
    if b.extra_hosts.len() > 20 {
        return Err(AppError::BadRequest(
            "at most 20 extra hosts allowed".into(),
        ));
    }
    let mut hosts = vec![host.clone()];
    for host in b.extra_hosts.iter().take(20) {
        hosts.push(normalize_hostname(host)?);
    }
    hosts.sort();
    hosts.dedup();
    let occupied=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM projects WHERE lower(domain)=ANY($1)) OR EXISTS(SELECT 1 FROM custom_hostnames WHERE hostname=ANY($1) AND(project_id<>$2 OR purpose<>'migration'))").bind(&hosts).bind(project).fetch_one(&st.pg).await?;
    if occupied {
        return Err(AppError::Conflict("hostname is already assigned".into()));
    }
    let mut tx = st.pg.begin().await?;
    let id=sqlx::query_scalar::<_,Uuid>("INSERT INTO migration_sources(project_id,provider,old_host,provider_hosted,credentials_ciphertext) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING RETURNING id").bind(project).bind(&b.provider).bind(&host).bind(b.provider_hosted).bind(encrypted).fetch_optional(&mut *tx).await?.ok_or_else(||AppError::Conflict("source or hostname already exists".into()))?;
    for h in hosts {
        let n = sqlx::query(
            "INSERT INTO migration_hosts(hostname,source_id) VALUES($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(h)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::Conflict(
                "hostname already claimed by another source".into(),
            ));
        }
    }
    tx.commit().await?;
    let existing=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM custom_hostnames WHERE project_id=$1 AND hostname=$2 AND purpose='migration')").bind(project).bind(&host).fetch_one(&st.pg).await?;
    if !b.provider_hosted
        && !existing
        && let Err(e) = crate::domains::provision(&st, project, &host, "migration").await
    {
        sqlx::query("DELETE FROM migration_sources WHERE id=$1")
            .bind(id)
            .execute(&st.pg)
            .await?;
        return Err(e);
    }
    let source = source_project(&st.pg, project).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"migration_source":source.public()})),
    ))
}
async fn show(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
) -> Result<Json<Value>, AppError> {
    authorize_project(&st, &user, project, true).await?;
    let source = match source_project(&st.pg, project).await {
        Ok(s) => Some(s.public()),
        Err(AppError::NotFound) => None,
        Err(e) => return Err(e),
    };
    Ok(Json(json!({"migration_source":source})))
}
async fn update(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Json(v): Json<Value>,
) -> Result<Json<Value>, AppError> {
    authorize_project(&st, &user, project, true).await?;
    let source = source_project(&st.pg, project).await?;
    let encrypted = v
        .get("credentials")
        .map(|v| credentials(&source.provider, v).and_then(|v| encrypt(&v)))
        .transpose()?;
    let enabled = v["enabled"].as_bool().or_else(|| {
        if encrypted.is_some() && source.auto_disabled_at.is_some() {
            Some(true)
        } else {
            None
        }
    });
    let mut tx = st.pg.begin().await?;
    sqlx::query("UPDATE migration_sources SET credentials_ciphertext=coalesce($2,credentials_ciphertext),enabled=coalesce($3,enabled),consecutive_failures=CASE WHEN $2 IS NOT NULL OR $3=true THEN 0 ELSE consecutive_failures END,first_failure_at=CASE WHEN $2 IS NOT NULL OR $3=true THEN NULL ELSE first_failure_at END,auto_disabled_at=CASE WHEN $3 IS NOT NULL THEN NULL ELSE auto_disabled_at END,updated_at=now() WHERE id=$1").bind(source.id).bind(encrypted).bind(enabled).execute(&mut *tx).await?;
    if let Some(hosts) = v["extra_hosts"].as_array() {
        if !source.provider_hosted || hosts.len() > 20 {
            return Err(AppError::BadRequest(
                "extra hosts require provider_hosted and at most20 entries".into(),
            ));
        }
        sqlx::query("DELETE FROM migration_hosts WHERE source_id=$1 AND hostname<>$2")
            .bind(source.id)
            .bind(&source.old_host)
            .execute(&mut *tx)
            .await?;
        for h in hosts {
            let h = normalize_hostname(
                h.as_str()
                    .ok_or_else(|| AppError::BadRequest("hostname string required".into()))?,
            )?;
            let owner=sqlx::query_scalar::<_,Uuid>("INSERT INTO migration_hosts(hostname,source_id) VALUES($1,$2) ON CONFLICT(hostname) DO UPDATE SET hostname=excluded.hostname RETURNING source_id").bind(h).bind(source.id).fetch_one(&mut *tx).await?;
            if owner != source.id {
                return Err(AppError::Conflict("hostname already claimed".into()));
            }
        }
    }
    tx.commit().await?;
    show(State(st), user, Path(project)).await
}
async fn remove(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    authorize_project(&st, &user, project, true).await?;
    sqlx::query("DELETE FROM migration_sources WHERE project_id=$1")
        .bind(project)
        .execute(&st.pg)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn probe(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
) -> Result<Json<Value>, AppError> {
    authorize_project(&st, &user, project, true).await?;
    let source = source_project(&st.pg, project).await?;
    rate_limit(&st.pg, &format!("import:{}", source.id), 6000).await?;
    let lookup = ProviderClient::from_env()?
        .fetch(
            &source.provider,
            &source.old_host,
            &format!("__trisixt_setup_probe_{}", Uuid::new_v4()),
            "",
            &decrypt(&source.credentials_ciphertext)?,
        )
        .await;
    let (outcome, status) = match lookup {
        Lookup::NotFound => ("credentials_ok", 404),
        Lookup::Found(_) => ("unexpected_success", 200),
        Lookup::Transient {
            status: 400 | 401 | 403,
            ..
        } => ("credentials_invalid", 401),
        Lookup::Transient { status: 429, .. } => ("upstream_rate_limited", 429),
        Lookup::Transient { status, .. } => ("upstream_unreachable", status),
    };
    if outcome == "credentials_ok" || outcome == "unexpected_success" {
        let mut tx = st.pg.begin().await?;
        success(&mut tx, source.id).await?;
        tx.commit().await?;
    }
    Ok(Json(json!({"outcome":outcome,"http_status":status})))
}
async fn backfill(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Json(v): Json<Value>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    authorize_project(&st, &user, project, true).await?;
    let source = source_project(&st.pg, project).await?;
    let paths = v["paths"]
        .as_array()
        .filter(|a| a.len() <= 10000)
        .ok_or_else(|| AppError::BadRequest("up to10000 paths required".into()))?;
    let mut tx = st.pg.begin().await?;
    let mut queued = 0;
    for path in paths {
        let p = path
            .as_str()
            .filter(|p| p.len() <= 2048)
            .ok_or_else(|| AppError::BadRequest("invalid import path".into()))?;
        queued += sqlx::query(
            "INSERT INTO migration_jobs(source_id,old_path) VALUES($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(source.id)
        .bind(p)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    }
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(json!({"queued":queued}))))
}
pub async fn tick(st: &AppState) -> Result<usize, AppError> {
    let rows=sqlx::query_as::<_,(Uuid,Uuid,String,String)>("SELECT j.id,s.project_id,s.old_host,j.old_path FROM migration_jobs j JOIN migration_sources s ON s.id=j.source_id WHERE j.finished_at IS NULL AND j.available_at<=now() AND s.enabled ORDER BY j.available_at LIMIT 20").fetch_all(&st.pg).await?;
    let n = rows.len();
    for (id, project, host, path) in rows {
        let result = resolve(st, project, &host, &path, "").await;
        let found = matches!(result, Ok(Some(ImportOutcome::Link(_)))) || sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM migrated_links m JOIN migration_jobs j ON j.source_id=m.source_id AND j.old_path=m.old_path WHERE j.id=$1 AND m.status='not_found' AND m.cached_until>now())").bind(id).fetch_one(&st.pg).await?;
        sqlx::query("UPDATE migration_jobs SET attempts=attempts+1,finished_at=CASE WHEN $2 THEN now() ELSE NULL END,available_at=now()+interval '5 minutes',last_error=CASE WHEN $2 THEN NULL ELSE 'not resolved; retry scheduled' END WHERE id=$1").bind(id).bind(found).execute(&st.pg).await?;
    }
    Ok(n)
}
#[derive(Deserialize)]
struct FirebaseInput {
    csv: String,
    #[serde(default)]
    deeplink_prefix: Option<String>,
    #[serde(default)]
    short_link_prefix: Option<String>,
}
async fn firebase(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Json(b): Json<FirebaseInput>,
) -> Result<Json<Value>, AppError> {
    authorize_project(&st, &user, project, true).await?;
    if b.csv.len() > 5 * 1024 * 1024 {
        return Err(AppError::BadRequest("CSV exceeds5MiB".into()));
    }
    let mut reader = csv::Reader::from_reader(b.csv.as_bytes());
    let headers = reader
        .headers()
        .map_err(|_| AppError::BadRequest("invalid CSV".into()))?
        .clone();
    for required in ["name", "short_link", "link"] {
        if !headers.iter().any(|h| h == required) {
            return Err(AppError::BadRequest(format!(
                "CSV column {required} required"
            )));
        }
    }
    let mut tx = st.pg.begin().await?;
    let mut created = Vec::new();
    let mut skipped = Vec::new();
    for (i, row) in reader.records().enumerate() {
        if i >= 10000 {
            return Err(AppError::BadRequest("CSV exceeds10000 rows".into()));
        }
        let row = row.map_err(|_| AppError::BadRequest("malformed CSV row".into()))?;
        let get = |key: &str| {
            headers
                .iter()
                .position(|h| h == key)
                .and_then(|n| row.get(n))
                .unwrap_or("")
                .trim()
                .to_owned()
        };
        let short = get("short_link");
        let path = b
            .short_link_prefix
            .as_deref()
            .and_then(|prefix| short.strip_prefix(prefix))
            .unwrap_or(&short)
            .trim_matches('/');
        if path.is_empty()
            || path.len() > 100
            || !path
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
        {
            skipped.push(json!({"row":i+2,"reason":"invalid_path"}));
            continue;
        }
        let duplicate: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM links WHERE project_id=$1 AND path=$2)",
        )
        .bind(project)
        .bind(path)
        .fetch_one(&mut *tx)
        .await?;
        if duplicate {
            skipped.push(json!({"row":i+2,"reason":"duplicate_on_domain"}));
            continue;
        }
        let mut deep = get("link");
        if let Some(prefix) = &b.deeplink_prefix
            && deep.starts_with(prefix)
        {
            let scheme = prefix
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/');
            deep = format!("{scheme}://{}", deep.trim_start_matches(prefix));
        }
        if !safe_url(&deep, true) {
            skipped.push(json!({"row":i+2,"reason":"invalid_url"}));
            continue;
        }
        let payload = json!({"provider":"firebase","name":get("name"),"ios_url":deep,"android_url":deep,"desktop_url":if safe_url(&deep,false){Some(deep.clone())}else{None},"custom_data":{"appLink":deep},"tracking_campaign":get("utm_campaign"),"tracking_medium":get("utm_medium"),"tracking_source":get("utm_source")});
        created.push(materialize(&mut tx, project, &payload, Some(path)).await?);
    }
    tx.commit().await?;
    Ok(Json(
        json!({"created_count":created.len(),"skipped_count":skipped.len(),"skipped":skipped,"links":created}),
    ))
}
