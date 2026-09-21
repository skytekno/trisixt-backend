use std::{sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use reqwest::{Client, Method, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::OnceCell;
use uuid::Uuid;

use super::{ProviderError, env_default, env_opt};
use crate::config::{AnalyticsBackend, Config};

const MAX_BATCH_EVENTS: usize = 1000;
const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsEvent {
    pub id: Uuid,
    pub event_id: Uuid,
    pub project_id: Uuid,
    pub visitor_id: Uuid,
    pub event_type: String,
    pub occurred_at: DateTime<Utc>,
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventCount {
    pub event_type: String,
    pub count: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dashboard {
    pub total_events: u64,
    pub unique_visitors: u64,
    pub events: Vec<EventCount>,
}

#[derive(Clone)]
pub struct ClickHouseConfig {
    pub url: String,
    pub database: String,
    pub table: String,
    pub username: String,
    pub password: String,
}

#[derive(Clone)]
pub struct BigQueryConfig {
    pub project: String,
    pub dataset: String,
    pub table: String,
    pub location: String,
    pub topic: String,
    pub pubsub_endpoint: String,
    pub bigquery_endpoint: String,
    pub maximum_bytes_billed: u64,
    pub auth: GoogleAuth,
}

/// ADC providers cache and refresh OAuth tokens. Static tokens are useful for short-lived
/// development sessions; production should use ADC or an attached service account.
#[derive(Clone)]
pub enum GoogleAuth {
    ApplicationDefault {
        service_account_path: Option<String>,
        provider: Arc<OnceCell<Arc<dyn gcp_auth::TokenProvider>>>,
    },
    AccessToken(String),
    /// Pub/Sub emulator only. BigQuery requests still require credentials.
    Emulator,
}

impl GoogleAuth {
    pub fn application_default(service_account_path: Option<String>) -> Self {
        Self::ApplicationDefault {
            service_account_path,
            provider: Arc::new(OnceCell::new()),
        }
    }

    async fn token(&self) -> Result<Option<String>, ProviderError> {
        match self {
            Self::Emulator => Ok(None),
            Self::AccessToken(token) => {
                if token.is_empty() {
                    return Err(ProviderError::Authentication);
                }
                Ok(Some(token.clone()))
            }
            Self::ApplicationDefault {
                service_account_path,
                provider,
            } => {
                let provider = provider
                    .get_or_try_init(|| async {
                        if let Some(path) = service_account_path {
                            let account = gcp_auth::CustomServiceAccount::from_file(path)
                                .map_err(|_| ProviderError::Authentication)?;
                            Ok::<Arc<dyn gcp_auth::TokenProvider>, ProviderError>(Arc::new(account))
                        } else {
                            gcp_auth::provider()
                                .await
                                .map_err(|_| ProviderError::Authentication)
                        }
                    })
                    .await?;
                let token = provider
                    .token(&["https://www.googleapis.com/auth/cloud-platform"])
                    .await
                    .map_err(|_| ProviderError::Authentication)?;
                Ok(Some(token.as_str().to_owned()))
            }
        }
    }
}

#[derive(Clone)]
enum Backend {
    ClickHouse(ClickHouseConfig),
    BigQuery(BigQueryConfig),
}

#[derive(Clone)]
pub struct Analytics {
    client: Client,
    backend: Backend,
}

impl Analytics {
    pub fn from_env(config: &Config) -> Result<Self, ProviderError> {
        match config.analytics_backend {
            AnalyticsBackend::ClickHouse => Self::clickhouse(ClickHouseConfig {
                url: config
                    .clickhouse_url
                    .clone()
                    .unwrap_or_else(|| "http://127.0.0.1:8123".into()),
                database: env_default("CLICKHOUSE_DATABASE", "trisixt"),
                table: env_default("CLICKHOUSE_TABLE", "events"),
                username: env_default("CLICKHOUSE_USER", "default"),
                password: env_default("CLICKHOUSE_PASSWORD", ""),
            }),
            AnalyticsBackend::BigQuery => {
                let project = env_opt("GOOGLE_CLOUD_PROJECT").ok_or_else(|| {
                    ProviderError::Configuration("GOOGLE_CLOUD_PROJECT is required".into())
                })?;
                let topic = config.pubsub_topic.clone().ok_or_else(|| {
                    ProviderError::Configuration("PUBSUB_TOPIC is required".into())
                })?;
                let topic = if topic.starts_with("projects/") {
                    topic
                } else {
                    format!("projects/{project}/topics/{topic}")
                };
                let emulator = env_opt("PUBSUB_EMULATOR_HOST");
                let auth = if emulator.is_some() {
                    GoogleAuth::Emulator
                } else if let Some(token) = env_opt("GOOGLE_ACCESS_TOKEN") {
                    GoogleAuth::AccessToken(token)
                } else {
                    GoogleAuth::application_default(config.gcs_credentials.clone())
                };
                Self::bigquery(BigQueryConfig {
                    project,
                    topic,
                    dataset: config
                        .bigquery_dataset
                        .clone()
                        .unwrap_or_else(|| "trisixt".into()),
                    table: env_default("BIGQUERY_TABLE", "events"),
                    location: env_default("BIGQUERY_LOCATION", "US"),
                    pubsub_endpoint: emulator
                        .map(|s| format!("http://{s}"))
                        .unwrap_or_else(|| "https://pubsub.googleapis.com".into()),
                    bigquery_endpoint: "https://bigquery.googleapis.com".into(),
                    maximum_bytes_billed: env_default(
                        "BIGQUERY_MAXIMUM_BYTES_BILLED",
                        "1073741824",
                    )
                    .parse()
                    .map_err(|_| {
                        ProviderError::Configuration("invalid BIGQUERY_MAXIMUM_BYTES_BILLED".into())
                    })?,
                    auth,
                })
            }
        }
    }

    pub fn clickhouse(mut config: ClickHouseConfig) -> Result<Self, ProviderError> {
        identifier(&config.database)?;
        identifier(&config.table)?;
        let mut url = endpoint(&config.url)?;
        // Accept conventional ClickHouse URLs without carrying secrets into errors or queries.
        if !url.username().is_empty() {
            config.username = url.username().to_owned();
        }
        if let Some(password) = url.password() {
            config.password = password.to_owned();
        }
        url.set_username("")
            .map_err(|_| ProviderError::Configuration("invalid ClickHouse URL".into()))?;
        url.set_password(None)
            .map_err(|_| ProviderError::Configuration("invalid ClickHouse URL".into()))?;
        if url.query().is_some() {
            return Err(ProviderError::Configuration(
                "ClickHouse URL cannot contain query parameters".into(),
            ));
        }
        config.url = url.to_string();
        Ok(Self {
            client: client()?,
            backend: Backend::ClickHouse(config),
        })
    }

    pub fn bigquery(config: BigQueryConfig) -> Result<Self, ProviderError> {
        identifier(&config.dataset)?;
        identifier(&config.table)?;
        if !cloud_name(&config.project)
            || config.location.is_empty()
            || !cloud_name(&config.location)
            || config.maximum_bytes_billed == 0
        {
            return Err(ProviderError::Configuration(
                "invalid BigQuery project, location, or byte budget".into(),
            ));
        }
        let parts: Vec<_> = config.topic.split('/').collect();
        if parts.len() != 4
            || parts[0] != "projects"
            || parts[2] != "topics"
            || !cloud_name(parts[1])
            || !cloud_name(parts[3])
        {
            return Err(ProviderError::Configuration(
                "PUBSUB_TOPIC must be projects/PROJECT/topics/TOPIC".into(),
            ));
        }
        for value in [&config.pubsub_endpoint, &config.bigquery_endpoint] {
            let url = endpoint(value)?;
            if !url.username().is_empty() || url.password().is_some() || url.query().is_some() {
                return Err(ProviderError::Configuration(
                    "invalid Google API endpoint".into(),
                ));
            }
        }
        if matches!(config.auth, GoogleAuth::Emulator)
            && config.pubsub_endpoint == "https://pubsub.googleapis.com"
        {
            return Err(ProviderError::Configuration(
                "emulator auth requires an emulator endpoint".into(),
            ));
        }
        Ok(Self {
            client: client()?,
            backend: Backend::BigQuery(config),
        })
    }

    /// At-least-once delivery; dashboards deduplicate event IDs. The durable outbox
    /// must retain a failed batch and retry using the original event IDs.
    pub async fn publish(&self, events: &[AnalyticsEvent]) -> Result<(), ProviderError> {
        if events.is_empty() {
            return Ok(());
        }
        if events.len() > MAX_BATCH_EVENTS {
            return Err(ProviderError::InvalidInput("batch exceeds 1000 events"));
        }
        let rows = events
            .iter()
            .map(event_wire)
            .collect::<Result<Vec<_>, _>>()?;
        match &self.backend {
            Backend::ClickHouse(config) => {
                let mut body = Vec::new();
                for row in rows {
                    serde_json::to_writer(&mut body, &row)
                        .map_err(|_| ProviderError::InvalidInput("invalid event JSON"))?;
                    body.push(b'\n');
                }
                if body.len() > MAX_BATCH_BYTES {
                    return Err(ProviderError::InvalidInput("batch exceeds 8 MiB"));
                }
                let query = format!(
                    "INSERT INTO {}.{} FORMAT JSONEachRow",
                    config.database, config.table
                );
                let mut url = endpoint(&config.url)?;
                url.query_pairs_mut()
                    .append_pair("query", &query)
                    .append_pair("date_time_input_format", "best_effort")
                    .append_pair("wait_end_of_query", "1");
                let response = self
                    .request(Method::POST, url, body, None, Some(config))
                    .await?;
                if !response.iter().all(u8::is_ascii_whitespace) {
                    return Err(ProviderError::Response);
                }
            }
            Backend::BigQuery(config) => {
                let messages: Vec<_> = rows.iter().map(|row| {
                    let data = STANDARD.encode(serde_json::to_vec(row).expect("serializable JSON value"));
                    json!({"data":data,"attributes":{"project_id":row["project_id"],"event_id":row["event_id"]}})
                }).collect();
                let body = serde_json::to_vec(&json!({"messages":messages}))
                    .map_err(|_| ProviderError::Response)?;
                if body.len() > MAX_BATCH_BYTES {
                    return Err(ProviderError::InvalidInput("batch exceeds 8 MiB"));
                }
                let url = endpoint(&format!(
                    "{}/v1/{}:publish",
                    config.pubsub_endpoint.trim_end_matches('/'),
                    config.topic
                ))?;
                let value: Value = serde_json::from_slice(
                    &self
                        .request(Method::POST, url, body, Some(&config.auth), None)
                        .await?,
                )
                .map_err(|_| ProviderError::Response)?;
                let ids = value
                    .get("messageIds")
                    .and_then(Value::as_array)
                    .ok_or(ProviderError::Response)?;
                if ids.len() != events.len()
                    || ids.iter().any(|id| id.as_str().is_none_or(str::is_empty))
                {
                    return Err(ProviderError::Response);
                }
            }
        }
        Ok(())
    }

    /// Delete only this project's expired canonical warehouse events. Synchronous
    /// completion is required before the relational ledger may be purged.
    pub async fn purge_before(
        &self,
        project: Uuid,
        cutoff: DateTime<Utc>,
    ) -> Result<(), ProviderError> {
        if project.is_nil() || cutoff >= Utc::now() {
            return Err(ProviderError::InvalidInput(
                "retention requires project and past cutoff",
            ));
        }
        self.purge(project, Some(cutoff)).await
    }
    /// Remove every warehouse row belonging to a deleted project. Callers retain
    /// a deletion tombstone to reconcile late at-least-once Pub/Sub deliveries.
    pub async fn purge_project(&self, project: Uuid) -> Result<(), ProviderError> {
        if project.is_nil() {
            return Err(ProviderError::InvalidInput("project is required"));
        }
        self.purge(project, None).await
    }
    async fn purge(
        &self,
        project: Uuid,
        cutoff: Option<DateTime<Utc>>,
    ) -> Result<(), ProviderError> {
        match &self.backend {
            Backend::ClickHouse(config) => {
                // Avoid adding mutations to an already overloaded retention table.
                let backlog = "SELECT count() AS pending FROM system.mutations WHERE database={database:String} AND table={table:String} AND is_done=0 FORMAT JSON".to_owned();
                let mut url = endpoint(&config.url)?;
                url.query_pairs_mut()
                    .append_pair("param_database", &config.database)
                    .append_pair("param_table", &config.table)
                    .append_pair("wait_end_of_query", "1");
                let response: Value = serde_json::from_slice(
                    &self
                        .request(Method::POST, url, backlog.into_bytes(), None, Some(config))
                        .await?,
                )
                .map_err(|_| ProviderError::Response)?;
                if number(&response["data"][0]["pending"])? > 50 {
                    return Err(ProviderError::InvalidInput(
                        "retention mutation backlog exceeds 50",
                    ));
                }
                let condition = if cutoff.is_some() {
                    " AND occurred_at<parseDateTime64BestEffort({cutoff:String},6)"
                } else {
                    ""
                };
                let query = format!(
                    "ALTER TABLE {}.{} DELETE WHERE project_id={{project:UUID}}{condition} SETTINGS mutations_sync=2",
                    config.database, config.table
                );
                let mut url = endpoint(&config.url)?;
                url.query_pairs_mut()
                    .append_pair("param_project", &project.to_string())
                    .append_pair("wait_end_of_query", "1");
                if let Some(cutoff) = cutoff {
                    url.query_pairs_mut()
                        .append_pair("param_cutoff", &cutoff.to_rfc3339());
                }
                let response = self
                    .request(Method::POST, url, query.into_bytes(), None, Some(config))
                    .await?;
                if !response.iter().all(u8::is_ascii_whitespace) {
                    return Err(ProviderError::Response);
                }
                Ok(())
            }
            Backend::BigQuery(config) => {
                if matches!(config.auth, GoogleAuth::Emulator) {
                    return Err(ProviderError::Authentication);
                }
                let condition = if cutoff.is_some() {
                    " AND occurred_at<@cutoff"
                } else {
                    ""
                };
                let query = format!(
                    "DELETE FROM `{}.{}.{}` WHERE project_id=@project{condition}",
                    config.project, config.dataset, config.table
                );
                let mut parameters = vec![
                    json!({"name":"project","parameterType":{"type":"STRING"},"parameterValue":{"value":project.to_string()}}),
                ];
                if let Some(cutoff) = cutoff {
                    parameters.push(json!({"name":"cutoff","parameterType":{"type":"TIMESTAMP"},"parameterValue":{"value":cutoff.to_rfc3339()}}));
                }
                let body = json!({"query":query,"useLegacySql":false,"parameterMode":"NAMED","queryParameters":parameters,"location":config.location,"timeoutMs":10000,"maximumBytesBilled":config.maximum_bytes_billed.to_string(),"requestId":Uuid::new_v4().to_string()});
                let url = endpoint(&format!(
                    "{}/bigquery/v2/projects/{}/queries",
                    config.bigquery_endpoint.trim_end_matches('/'),
                    config.project
                ))?;
                let mut response: Value = serde_json::from_slice(
                    &self
                        .request(
                            Method::POST,
                            url,
                            serde_json::to_vec(&body).map_err(|_| ProviderError::Response)?,
                            Some(&config.auth),
                            None,
                        )
                        .await?,
                )
                .map_err(|_| ProviderError::Response)?;
                for _ in 0..30 {
                    if response.get("error").is_some()
                        || response["errors"].as_array().is_some_and(|e| !e.is_empty())
                    {
                        return Err(ProviderError::Response);
                    }
                    if response["jobComplete"].as_bool() == Some(true) {
                        // A completed DML response includes affected rows even when zero.
                        number(&response["numDmlAffectedRows"])?;
                        return Ok(());
                    }
                    let job = response["jobReference"]["jobId"]
                        .as_str()
                        .filter(|id| cloud_name(id))
                        .ok_or(ProviderError::Response)?;
                    let mut url = endpoint(&format!(
                        "{}/bigquery/v2/projects/{}/queries/{job}",
                        config.bigquery_endpoint.trim_end_matches('/'),
                        config.project
                    ))?;
                    url.query_pairs_mut()
                        .append_pair("location", &config.location)
                        .append_pair("timeoutMs", "1000");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    response = serde_json::from_slice(
                        &self
                            .request(Method::GET, url, Vec::new(), Some(&config.auth), None)
                            .await?,
                    )
                    .map_err(|_| ProviderError::Response)?;
                }
                Err(ProviderError::Timeout)
            }
        }
    }

    pub async fn dashboard(
        &self,
        project_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Dashboard, ProviderError> {
        if project_id.is_nil()
            || from >= to
            || to.signed_duration_since(from) > chrono::Duration::days(366)
        {
            return Err(ProviderError::InvalidInput(
                "dashboard requires a nonempty range of at most 366 days",
            ));
        }
        match &self.backend {
            Backend::ClickHouse(config) => {
                self.clickhouse_dashboard(config, project_id, from, to)
                    .await
            }
            Backend::BigQuery(config) => {
                self.bigquery_dashboard(config, project_id, from, to).await
            }
        }
    }

    async fn clickhouse_dashboard(
        &self,
        config: &ClickHouseConfig,
        project: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Dashboard, ProviderError> {
        let scope = format!(
            "FROM {}.{} WHERE project_id = {{project:UUID}} AND occurred_at >= parseDateTime64BestEffort({{from:String}}, 6) AND occurred_at < parseDateTime64BestEffort({{to:String}}, 6)",
            config.database, config.table
        );
        let query = format!(
            "SELECT event_type, uniqExact(event_id) AS count, uniqExact(visitor_id) AS visitors, 0 AS is_total {scope} GROUP BY event_type UNION ALL SELECT '' AS event_type, uniqExact(event_id) AS count, uniqExact(visitor_id) AS visitors, 1 AS is_total {scope} FORMAT JSON"
        );
        let mut url = endpoint(&config.url)?;
        url.query_pairs_mut()
            .append_pair("param_project", &project.to_string())
            .append_pair("param_from", &from.to_rfc3339())
            .append_pair("param_to", &to.to_rfc3339())
            .append_pair("wait_end_of_query", "1")
            .append_pair("max_execution_time", "15")
            .append_pair("max_result_rows", "10001")
            .append_pair("result_overflow_mode", "throw");
        let value: Value = serde_json::from_slice(
            &self
                .request(Method::POST, url, query.into_bytes(), None, Some(config))
                .await?,
        )
        .map_err(|_| ProviderError::Response)?;
        let rows = value
            .get("data")
            .and_then(Value::as_array)
            .ok_or(ProviderError::Response)?;
        let mut result = Dashboard::default();
        let mut has_total = false;
        for row in rows {
            let count = number(&row["count"])?;
            if number(&row["is_total"])? == 1 {
                result.total_events = count;
                result.unique_visitors = number(&row["visitors"])?;
                has_total = true;
            } else {
                result.events.push(EventCount {
                    event_type: row["event_type"]
                        .as_str()
                        .ok_or(ProviderError::Response)?
                        .to_owned(),
                    count,
                });
            }
        }
        if !has_total {
            return Err(ProviderError::Response);
        }
        result
            .events
            .sort_by(|a, b| a.event_type.cmp(&b.event_type));
        Ok(result)
    }

    async fn bigquery_dashboard(
        &self,
        config: &BigQueryConfig,
        project: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Dashboard, ProviderError> {
        if matches!(config.auth, GoogleAuth::Emulator) {
            return Err(ProviderError::Authentication);
        }
        let table = format!("`{}.{}.{}`", config.project, config.dataset, config.table);
        let query = format!(
            "WITH scoped AS (SELECT event_id, visitor_id, event_type FROM {table} WHERE project_id = @project AND occurred_at >= @from AND occurred_at < @to) SELECT event_type, COUNT(DISTINCT event_id) AS count, COUNT(DISTINCT visitor_id) AS visitors, FALSE AS is_total FROM scoped GROUP BY event_type UNION ALL SELECT '', COUNT(DISTINCT event_id), COUNT(DISTINCT visitor_id), TRUE FROM scoped"
        );
        let parameter = |name: &str, kind: &str, value: String| json!({"name":name,"parameterType":{"type":kind},"parameterValue":{"value":value}});
        let body = json!({"query":query,"useLegacySql":false,"parameterMode":"NAMED","queryParameters":[parameter("project","STRING",project.to_string()),parameter("from","TIMESTAMP",from.to_rfc3339()),parameter("to","TIMESTAMP",to.to_rfc3339())],"location":config.location,"timeoutMs":10000,"maxResults":10001,"maximumBytesBilled":config.maximum_bytes_billed.to_string(),"requestId":Uuid::new_v4().to_string()});
        let url = endpoint(&format!(
            "{}/bigquery/v2/projects/{}/queries",
            config.bigquery_endpoint.trim_end_matches('/'),
            config.project
        ))?;
        let mut value: Value = serde_json::from_slice(
            &self
                .request(
                    Method::POST,
                    url,
                    serde_json::to_vec(&body).map_err(|_| ProviderError::Response)?,
                    Some(&config.auth),
                    None,
                )
                .await?,
        )
        .map_err(|_| ProviderError::Response)?;
        let mut result = Dashboard::default();
        let mut has_total = false;
        for poll in 0..30 {
            if value
                .get("errors")
                .and_then(Value::as_array)
                .is_some_and(|v| !v.is_empty())
                || value.get("error").is_some()
            {
                return Err(ProviderError::Response);
            }
            let complete = value
                .get("jobComplete")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if complete {
                if let Some(rows) = value.get("rows").and_then(Value::as_array) {
                    for row in rows {
                        let cells = row
                            .get("f")
                            .and_then(Value::as_array)
                            .filter(|c| c.len() == 4)
                            .ok_or(ProviderError::Response)?;
                        let count = number(&cells[1]["v"])?;
                        if cells[3]["v"] == "true" || cells[3]["v"] == true {
                            result.total_events = count;
                            result.unique_visitors = number(&cells[2]["v"])?;
                            has_total = true;
                        } else {
                            result.events.push(EventCount {
                                event_type: cells[0]["v"]
                                    .as_str()
                                    .ok_or(ProviderError::Response)?
                                    .to_owned(),
                                count,
                            });
                        }
                    }
                }
                if result.events.len() > 10000 {
                    return Err(ProviderError::Response);
                }
                if value
                    .get("pageToken")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
                {
                    if !has_total {
                        return Err(ProviderError::Response);
                    }
                    result
                        .events
                        .sort_by(|a, b| a.event_type.cmp(&b.event_type));
                    return Ok(result);
                }
            }
            let job = value["jobReference"]["jobId"]
                .as_str()
                .filter(|s| cloud_name(s))
                .ok_or(ProviderError::Response)?;
            let mut url = endpoint(&format!(
                "{}/bigquery/v2/projects/{}/queries/{}",
                config.bigquery_endpoint.trim_end_matches('/'),
                config.project,
                job
            ))?;
            url.query_pairs_mut()
                .append_pair("location", &config.location)
                .append_pair("maxResults", "10001")
                .append_pair("timeoutMs", "1000");
            if let Some(page) = value.get("pageToken").and_then(Value::as_str) {
                url.query_pairs_mut().append_pair("pageToken", page);
            }
            if !complete {
                tokio::time::sleep(Duration::from_millis(100 + poll * 10)).await;
            }
            value = serde_json::from_slice(
                &self
                    .request(Method::GET, url, Vec::new(), Some(&config.auth), None)
                    .await?,
            )
            .map_err(|_| ProviderError::Response)?;
        }
        Err(ProviderError::Timeout)
    }

    async fn request(
        &self,
        method: Method,
        url: Url,
        body: Vec<u8>,
        google: Option<&GoogleAuth>,
        clickhouse: Option<&ClickHouseConfig>,
    ) -> Result<Vec<u8>, ProviderError> {
        for attempt in 0..3 {
            let mut request = self.client.request(method.clone(), url.clone());
            if method != Method::GET {
                request = request.body(body.clone());
            }
            if let Some(auth) = google {
                if let Some(token) = auth.token().await? {
                    request = request.bearer_auth(token);
                }
                request = request.header(reqwest::header::CONTENT_TYPE, "application/json");
            }
            if let Some(config) = clickhouse {
                request = request.basic_auth(&config.username, Some(&config.password));
            }
            match request.send().await {
                Ok(mut response) => {
                    let status = response.status();
                    if (status.is_server_error() || status.as_u16() == 429) && attempt < 2 {
                        tokio::time::sleep(Duration::from_millis(100 << attempt)).await;
                        continue;
                    }
                    if !status.is_success() {
                        return Err(ProviderError::Http(status.as_u16()));
                    }
                    if response
                        .headers()
                        .get("x-clickhouse-exception-code")
                        .is_some_and(|v| v != "0")
                    {
                        return Err(ProviderError::Response);
                    }
                    if response
                        .content_length()
                        .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
                    {
                        return Err(ProviderError::Response);
                    }
                    let mut bytes = Vec::new();
                    while let Some(chunk) = response
                        .chunk()
                        .await
                        .map_err(|_| ProviderError::Transport)?
                    {
                        if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                            return Err(ProviderError::Response);
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    return Ok(bytes);
                }
                Err(_) if attempt < 2 => {
                    tokio::time::sleep(Duration::from_millis(100 << attempt)).await
                }
                Err(_) => return Err(ProviderError::Transport),
            }
        }
        Err(ProviderError::Transport)
    }
}

fn event_wire(event: &AnalyticsEvent) -> Result<Value, ProviderError> {
    if event.id.is_nil()
        || event.event_id.is_nil()
        || event.project_id.is_nil()
        || event.visitor_id.is_nil()
        || event.event_type.trim().is_empty()
        || event.event_type.len() > 128
    {
        return Err(ProviderError::InvalidInput(
            "invalid event identity or type",
        ));
    }
    let properties = serde_json::to_string(&event.properties)
        .map_err(|_| ProviderError::InvalidInput("invalid event JSON"))?;
    if properties.len() > 65536 {
        return Err(ProviderError::InvalidInput(
            "event properties exceed 64 KiB",
        ));
    }
    // BigQuery table-schema subscriptions require JSON columns encoded as JSON strings.
    Ok(
        json!({"id":event.id,"event_id":event.event_id,"project_id":event.project_id,"visitor_id":event.visitor_id,"event_type":event.event_type,"occurred_at":event.occurred_at.to_rfc3339(),"properties":properties}),
    )
}

fn client() -> Result<Client, ProviderError> {
    Client::builder()
        .timeout(Duration::from_secs(20))
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| ProviderError::Transport)
}

fn endpoint(value: &str) -> Result<Url, ProviderError> {
    let url = Url::parse(value)
        .map_err(|_| ProviderError::Configuration("invalid provider URL".into()))?;
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || url.fragment().is_some()
    {
        return Err(ProviderError::Configuration("invalid provider URL".into()));
    }
    Ok(url)
}

fn identifier(value: &str) -> Result<(), ProviderError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_')
        || value.as_bytes()[0].is_ascii_digit()
    {
        return Err(ProviderError::Configuration(
            "invalid analytics identifier".into(),
        ));
    }
    Ok(())
}

fn cloud_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
}

fn number(value: &Value) -> Result<u64, ProviderError> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
        .ok_or(ProviderError::Response)
}
