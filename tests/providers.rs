use std::{collections::VecDeque, sync::Arc};

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::IntoResponse,
    routing::any,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use object_store::{
    ClientOptions, StaticCredentialProvider,
    aws::AmazonS3Builder,
    gcp::{GcpCredential, GoogleCloudStorageBuilder},
    memory::InMemory,
};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use trisixt::providers::{
    Analytics, AnalyticsEvent, BigQueryConfig, ClickHouseConfig, GoogleAuth, ProviderError, Storage,
};
use uuid::Uuid;

#[derive(Clone)]
struct ResponseSpec {
    status: StatusCode,
    body: String,
    headers: HeaderMap,
}

#[derive(Debug)]
struct Recorded {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Vec<u8>,
}

#[derive(Clone)]
struct MockState {
    responses: Arc<Mutex<VecDeque<ResponseSpec>>>,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

struct Mock {
    url: String,
    state: MockState,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Mock {
    async fn new(responses: Vec<ResponseSpec>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = MockState {
            responses: Arc::new(Mutex::new(responses.into())),
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        let app = Router::new()
            .fallback(any(mock_request))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { url, state, task }
    }
}

async fn mock_request(
    State(state): State<MockState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    state.requests.lock().await.push(Recorded {
        method,
        uri,
        headers,
        body: body.to_vec(),
    });
    let spec = state
        .responses
        .lock()
        .await
        .pop_front()
        .unwrap_or_else(|| response(500, "unexpected request"));
    (spec.status, spec.headers, spec.body)
}

fn response(status: u16, body: impl Into<String>) -> ResponseSpec {
    ResponseSpec {
        status: StatusCode::from_u16(status).unwrap(),
        body: body.into(),
        headers: HeaderMap::new(),
    }
}

fn event() -> AnalyticsEvent {
    AnalyticsEvent {
        id: Uuid::new_v4(),
        event_id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        visitor_id: Uuid::new_v4(),
        event_type: "purchase".into(),
        occurred_at: Utc::now(),
        properties: json!({"amount":123,"nested":{"campaign":"hello"}}),
    }
}

fn ch_config(url: &str) -> ClickHouseConfig {
    ClickHouseConfig {
        url: url.into(),
        database: "trisixt".into(),
        table: "events".into(),
        username: "trisixt".into(),
        password: "test-secret".into(),
    }
}

fn bq_config(url: &str) -> BigQueryConfig {
    BigQueryConfig {
        project: "test-cloud".into(),
        dataset: "trisixt".into(),
        table: "events".into(),
        location: "US".into(),
        topic: "projects/test-cloud/topics/events".into(),
        pubsub_endpoint: url.into(),
        bigquery_endpoint: url.into(),
        maximum_bytes_billed: 1073741824,
        auth: GoogleAuth::AccessToken("test-token".into()),
    }
}

#[tokio::test]
async fn clickhouse_retries_transient_failure_and_preserves_payload_identity() {
    let mock = Mock::new(vec![response(503, "unavailable"), response(200, "")]).await;
    let analytics = Analytics::clickhouse(ch_config(&mock.url)).unwrap();
    let event = event();
    analytics
        .publish(std::slice::from_ref(&event))
        .await
        .unwrap();
    let requests = mock.state.requests.lock().await;
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].body, requests[1].body);
    assert_eq!(requests[1].method, Method::POST);
    let row: Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(row["event_id"], event.event_id.to_string());
    assert_eq!(
        serde_json::from_str::<Value>(row["properties"].as_str().unwrap()).unwrap(),
        event.properties
    );
    assert_eq!(
        requests[1].headers["authorization"],
        format!("Basic {}", STANDARD.encode("trisixt:test-secret"))
    );
    assert!(
        requests[1]
            .uri
            .query()
            .unwrap()
            .contains("wait_end_of_query=1")
    );
}

#[tokio::test]
async fn clickhouse_auth_failure_is_not_retried_or_leaked() {
    let mock = Mock::new(vec![response(401, "sensitive upstream details")]).await;
    let error = Analytics::clickhouse(ch_config(&mock.url))
        .unwrap()
        .publish(&[event()])
        .await
        .unwrap_err();
    assert!(matches!(error, ProviderError::Http(401)));
    assert!(!error.to_string().contains("sensitive"));
    assert_eq!(mock.state.requests.lock().await.len(), 1);
}

#[tokio::test]
async fn clickhouse_success_status_with_exception_is_failure() {
    let mut spec = response(200, "");
    spec.headers
        .insert("x-clickhouse-exception-code", "241".parse().unwrap());
    let mock = Mock::new(vec![spec]).await;
    assert!(
        Analytics::clickhouse(ch_config(&mock.url))
            .unwrap()
            .publish(&[event()])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn clickhouse_dashboard_uses_tenant_and_time_parameters_and_deduplicates() {
    let mock = Mock::new(vec![response(200,json!({"data":[{"event_type":"purchase","count":"3","visitors":"2","is_total":0},{"event_type":"","count":"3","visitors":"2","is_total":1}]}).to_string())]).await;
    let project = Uuid::new_v4();
    let now = Utc::now();
    let result = Analytics::clickhouse(ch_config(&mock.url))
        .unwrap()
        .dashboard(project, now - Duration::days(1), now)
        .await
        .unwrap();
    assert_eq!(result.total_events, 3);
    assert_eq!(result.unique_visitors, 2);
    assert_eq!(result.events[0].event_type, "purchase");
    let requests = mock.state.requests.lock().await;
    assert!(
        requests[0]
            .uri
            .query()
            .unwrap()
            .contains(&format!("param_project={project}"))
    );
    let sql = std::str::from_utf8(&requests[0].body).unwrap();
    assert!(sql.contains("project_id = {project:UUID}"));
    assert!(sql.contains("uniqExact(event_id)"));
    assert!(sql.contains("occurred_at <"));
}

#[tokio::test]
async fn pubsub_serializes_bigquery_compatible_json_and_bearer_auth() {
    let mock = Mock::new(vec![response(200, r#"{"messageIds":["1"]}"#)]).await;
    let event = event();
    Analytics::bigquery(bq_config(&mock.url))
        .unwrap()
        .publish(std::slice::from_ref(&event))
        .await
        .unwrap();
    let requests = mock.state.requests.lock().await;
    assert_eq!(
        requests[0].uri.path(),
        "/v1/projects/test-cloud/topics/events:publish"
    );
    assert_eq!(requests[0].headers["authorization"], "Bearer test-token");
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    let wire: Value = serde_json::from_slice(
        &STANDARD
            .decode(body["messages"][0]["data"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(wire["project_id"], event.project_id.to_string());
    assert_eq!(wire["event_id"], event.event_id.to_string());
    assert_eq!(
        serde_json::from_str::<Value>(wire["properties"].as_str().unwrap()).unwrap(),
        event.properties
    );
    assert_eq!(
        body["messages"][0]["attributes"]["project_id"],
        event.project_id.to_string()
    );
}

#[tokio::test]
async fn pubsub_partial_ack_and_permanent_errors_are_failures() {
    let mock = Mock::new(vec![
        response(200, r#"{"messageIds":[]}"#),
        response(403, "credentials rejected"),
    ])
    .await;
    let analytics = Analytics::bigquery(bq_config(&mock.url)).unwrap();
    assert!(matches!(
        analytics.publish(&[event()]).await,
        Err(ProviderError::Response)
    ));
    assert!(matches!(
        analytics.publish(&[event()]).await,
        Err(ProviderError::Http(403))
    ));
    assert_eq!(mock.state.requests.lock().await.len(), 2);
}

#[tokio::test]
async fn pubsub_emulator_does_not_send_google_credentials_and_cannot_query_bigquery() {
    let mock = Mock::new(vec![response(200, r#"{"messageIds":["1"]}"#)]).await;
    let mut config = bq_config(&mock.url);
    config.auth = GoogleAuth::Emulator;
    let analytics = Analytics::bigquery(config).unwrap();
    analytics.publish(&[event()]).await.unwrap();
    assert!(
        !mock.state.requests.lock().await[0]
            .headers
            .contains_key("authorization")
    );
    let now = Utc::now();
    assert!(matches!(
        analytics
            .dashboard(Uuid::new_v4(), now - Duration::days(1), now)
            .await,
        Err(ProviderError::Authentication)
    ));
}

#[tokio::test]
async fn bigquery_polls_jobs_and_pages_all_results_with_parameterized_scope() {
    let row = |name: &str, count: &str, visitors: &str, total: &str| json!({"f":[{"v":name},{"v":count},{"v":visitors},{"v":total}]});
    let mock = Mock::new(vec![
        response(200,json!({"jobComplete":false,"jobReference":{"jobId":"query-1"}}).to_string()),
        response(200,json!({"jobComplete":true,"jobReference":{"jobId":"query-1"},"pageToken":"next+page","rows":[row("purchase","3","2","false")]}).to_string()),
        response(200,json!({"jobComplete":true,"jobReference":{"jobId":"query-1"},"rows":[row("","3","2","true")]}).to_string()),
    ]).await;
    let project = Uuid::new_v4();
    let now = Utc::now();
    let result = Analytics::bigquery(bq_config(&mock.url))
        .unwrap()
        .dashboard(project, now - Duration::days(1), now)
        .await
        .unwrap();
    assert_eq!(result.total_events, 3);
    assert_eq!(result.unique_visitors, 2);
    assert_eq!(result.events.len(), 1);
    let requests = mock.state.requests.lock().await;
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(
        body["queryParameters"][0]["parameterValue"]["value"],
        project.to_string()
    );
    assert_eq!(body["parameterMode"], "NAMED");
    assert_eq!(body["useLegacySql"], false);
    assert_eq!(body["maximumBytesBilled"], "1073741824");
    assert!(
        body["query"]
            .as_str()
            .unwrap()
            .contains("COUNT(DISTINCT event_id)")
    );
    assert_eq!(requests[1].method, Method::GET);
    assert!(
        requests[2]
            .uri
            .query()
            .unwrap()
            .contains("pageToken=next%2Bpage")
    );
}

#[tokio::test]
async fn bigquery_query_errors_in_success_response_are_failures() {
    let mock = Mock::new(vec![response(
        200,
        r#"{"jobComplete":true,"errors":[{"reason":"accessDenied"}]}"#,
    )])
    .await;
    let now = Utc::now();
    assert!(matches!(
        Analytics::bigquery(bq_config(&mock.url))
            .unwrap()
            .dashboard(Uuid::new_v4(), now - Duration::days(1), now)
            .await,
        Err(ProviderError::Response)
    ));
}

#[tokio::test]
async fn invalid_batches_identifiers_and_ranges_fail_before_network() {
    let mock = Mock::new(vec![]).await;
    let analytics = Analytics::clickhouse(ch_config(&mock.url)).unwrap();
    assert!(analytics.publish(&vec![event(); 1001]).await.is_err());
    let mut invalid = event();
    invalid.properties = json!({"large":"x".repeat(65537)});
    assert!(analytics.publish(&[invalid]).await.is_err());
    let now = Utc::now();
    assert!(analytics.dashboard(Uuid::new_v4(), now, now).await.is_err());
    assert!(
        analytics
            .dashboard(Uuid::new_v4(), now - Duration::days(367), now)
            .await
            .is_err()
    );
    let mut config = ch_config(&mock.url);
    config.table = "events;DROP TABLE users".into();
    assert!(Analytics::clickhouse(config).is_err());
    assert!(mock.state.requests.lock().await.is_empty());
}

#[tokio::test]
async fn storage_enforces_project_isolation_traversal_validation_and_size_limit() {
    let storage = Storage::new(Arc::new(InMemory::new()));
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    storage
        .put(a, "icons/app.png", b"image".to_vec())
        .await
        .unwrap();
    assert_eq!(storage.get(a, "icons/app.png").await.unwrap(), b"image");
    assert!(
        storage
            .get(b, "icons/app.png")
            .await
            .unwrap_err()
            .is_not_found()
    );
    for key in [
        "",
        "../secret",
        "/secret",
        "a//b",
        "a/../b",
        "a%2Fb",
        "a\\b",
    ] {
        assert!(matches!(
            storage.get(a, key).await,
            Err(ProviderError::InvalidInput(_))
        ));
    }
    assert!(
        storage
            .put(a, "huge", vec![0; 20 * 1024 * 1024 + 1])
            .await
            .is_err()
    );
    storage.delete(a, "icons/app.png").await.unwrap();
    assert!(
        storage
            .get(a, "icons/app.png")
            .await
            .unwrap_err()
            .is_not_found()
    );
}

#[tokio::test]
async fn s3_adapter_signs_scoped_put_get_and_delete_requests() {
    let project = Uuid::new_v4();
    let mut get = response(200, "image");
    get.headers.insert(
        "last-modified",
        "Sat, 19 Sep 2026 00:00:00 GMT".parse().unwrap(),
    );
    get.headers.insert("etag", "\"abc\"".parse().unwrap());
    let mut put = response(200, "");
    put.headers.insert("etag", "\"abc\"".parse().unwrap());
    let deleted = response(
        200,
        format!(
            "<DeleteResult><Deleted><Key>projects/{project}/logo.png</Key></Deleted></DeleteResult>"
        ),
    );
    let mock = Mock::new(vec![put, get, deleted]).await;
    let store = AmazonS3Builder::new()
        .with_bucket_name("trisixt")
        .with_region("us-east-1")
        .with_endpoint(&mock.url)
        .with_allow_http(true)
        .with_access_key_id("test-access")
        .with_secret_access_key("test-secret")
        .build()
        .unwrap();
    let storage = Storage::new(Arc::new(store));
    storage
        .put(project, "logo.png", b"image".to_vec())
        .await
        .unwrap();
    assert_eq!(storage.get(project, "logo.png").await.unwrap(), b"image");
    storage.delete(project, "logo.png").await.unwrap();
    let requests = mock.state.requests.lock().await;
    assert_eq!(requests.len(), 3);
    for request in &requests[..2] {
        assert_eq!(
            request.uri.path(),
            format!("/trisixt/projects/{project}/logo.png")
        );
        assert!(
            request.headers["authorization"]
                .to_str()
                .unwrap()
                .starts_with("AWS4-HMAC-SHA256 ")
        );
    }
    assert_eq!(requests[0].method, Method::PUT);
    assert_eq!(requests[1].method, Method::GET);
    // object_store 0.14 uses the S3 DeleteObjects API even for one key.
    assert_eq!(requests[2].method, Method::POST);
    assert_eq!(requests[2].uri.path(), "/trisixt");
    assert_eq!(requests[2].uri.query(), Some("delete"));
    assert!(
        std::str::from_utf8(&requests[2].body)
            .unwrap()
            .contains(&format!("<Key>projects/{project}/logo.png</Key>"))
    );
    assert!(
        requests[2].headers["authorization"]
            .to_str()
            .unwrap()
            .starts_with("AWS4-HMAC-SHA256 ")
    );
}

#[tokio::test]
async fn gcs_adapter_sends_bearer_auth_for_scoped_put_get_delete() {
    let mut get = response(200, "image");
    get.headers.insert(
        "last-modified",
        "Sat, 19 Sep 2026 00:00:00 GMT".parse().unwrap(),
    );
    get.headers.insert("etag", "\"abc\"".parse().unwrap());
    let mut put = response(200, "");
    put.headers.insert("etag", "\"abc\"".parse().unwrap());
    put.headers
        .insert("x-goog-generation", "1".parse().unwrap());
    let mock = Mock::new(vec![put, get, response(204, "")]).await;
    // The maintained GCS adapter's documented test endpoint override, with a
    // static credential provider, exercises real request construction over HTTP.
    let key = json!({"private_key":"unused","private_key_id":"unused","client_email":"test@example.invalid","disable_oauth":true,"gcs_base_url":mock.url});
    let adc_path = std::env::temp_dir().join(format!("trisixt-test-adc-{}.json", Uuid::new_v4()));
    std::fs::write(&adc_path,r#"{"type":"authorized_user","client_id":"unused","client_secret":"unused","refresh_token":"unused"}"#).unwrap();
    let store = GoogleCloudStorageBuilder::new()
        .with_bucket_name("trisixt")
        .with_application_credentials(adc_path.to_str().unwrap())
        .with_service_account_key(key.to_string())
        .with_credentials(Arc::new(StaticCredentialProvider::new(GcpCredential {
            bearer: "test-token".into(),
        })))
        .with_client_options(ClientOptions::new().with_allow_http(true))
        .build()
        .unwrap();
    std::fs::remove_file(adc_path).unwrap();
    let storage = Storage::new(Arc::new(store));
    let project = Uuid::new_v4();
    storage
        .put(project, "logo.png", b"image".to_vec())
        .await
        .unwrap();
    assert_eq!(storage.get(project, "logo.png").await.unwrap(), b"image");
    storage.delete(project, "logo.png").await.unwrap();
    let requests = mock.state.requests.lock().await;
    assert_eq!(requests.len(), 3);
    for request in requests.iter() {
        assert_eq!(
            request.uri.path(),
            format!(
                "/trisixt/projects%2F{}%2Flogo%2Epng",
                project.to_string().replace('-', "%2D")
            )
        );
        assert_eq!(request.headers["authorization"], "Bearer test-token");
    }
}

#[tokio::test]
#[ignore = "requires TEST_CLICKHOUSE_URL; run scripts/integration.sh"]
async fn clickhouse_live_write_dedup_and_tenant_scope() {
    let url = std::env::var("TEST_CLICKHOUSE_URL").expect("TEST_CLICKHOUSE_URL required");
    let analytics = Analytics::clickhouse(ch_config(&url)).unwrap();
    let event = event();
    let mut other = event.clone();
    other.project_id = Uuid::new_v4();
    other.id = Uuid::new_v4();
    other.event_id = Uuid::new_v4();
    analytics
        .publish(&[event.clone(), event.clone(), other.clone()])
        .await
        .unwrap();
    let result = analytics
        .dashboard(
            event.project_id,
            event.occurred_at - Duration::seconds(1),
            event.occurred_at + Duration::seconds(1),
        )
        .await
        .unwrap();
    assert_eq!(result.total_events, 1);
    assert_eq!(result.unique_visitors, 1);
    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0].count, 1);
    let result = analytics
        .dashboard(
            other.project_id,
            event.occurred_at - Duration::seconds(1),
            event.occurred_at + Duration::seconds(1),
        )
        .await
        .unwrap();
    assert_eq!(result.total_events, 1);
}

#[tokio::test]
#[ignore = "requires TEST_S3_ENDPOINT; run scripts/integration.sh"]
async fn s3_live_object_roundtrip_and_tenant_scope() {
    let endpoint = std::env::var("TEST_S3_ENDPOINT").expect("TEST_S3_ENDPOINT required");
    let bucket = std::env::var("TEST_S3_BUCKET").expect("TEST_S3_BUCKET required");
    let store = AmazonS3Builder::from_env()
        .with_endpoint(endpoint)
        .with_bucket_name(bucket)
        .with_region("us-east-1")
        .with_allow_http(true)
        .build()
        .unwrap();
    let storage = Storage::new(Arc::new(store));
    let project = Uuid::new_v4();
    storage
        .put(
            project,
            "smoke/roundtrip.txt",
            b"Trisixt storage integration".to_vec(),
        )
        .await
        .unwrap();
    let found = storage.get(project, "smoke/roundtrip.txt").await;
    let isolated = storage.get(Uuid::new_v4(), "smoke/roundtrip.txt").await;
    let deleted = storage.delete(project, "smoke/roundtrip.txt").await;
    assert_eq!(found.unwrap(), b"Trisixt storage integration");
    assert!(isolated.unwrap_err().is_not_found());
    deleted.unwrap();
    assert!(
        storage
            .get(project, "smoke/roundtrip.txt")
            .await
            .unwrap_err()
            .is_not_found()
    );
}

#[tokio::test]
async fn project_purge_has_no_time_cutoff_and_waits_for_completion() {
    let project = Uuid::new_v4();
    let ch = Mock::new(vec![
        response(200, r#"{"data":[{"pending":0}]}"#),
        response(200, ""),
    ])
    .await;
    let adapter = Analytics::clickhouse(ch_config(&ch.url)).unwrap();
    assert!(adapter.purge_project(Uuid::nil()).await.is_err());
    adapter.purge_project(project).await.unwrap();
    let requests = ch.state.requests.lock().await;
    let sql = String::from_utf8_lossy(&requests[1].body);
    assert!(sql.contains("DELETE WHERE project_id={project:UUID} SETTINGS mutations_sync=2"));
    assert!(!sql.contains("occurred_at"));
    assert!(
        requests[1]
            .uri
            .query()
            .unwrap()
            .contains(&project.to_string())
    );
    drop(requests);
    let bq = Mock::new(vec![
        response(
            200,
            r#"{"jobComplete":false,"jobReference":{"jobId":"purge-job"}}"#,
        ),
        response(200, r#"{"jobComplete":true,"numDmlAffectedRows":"7"}"#),
    ])
    .await;
    Analytics::bigquery(bq_config(&bq.url))
        .unwrap()
        .purge_project(project)
        .await
        .unwrap();
    let requests = bq.state.requests.lock().await;
    assert_eq!(requests.len(), 2);
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(
        body["query"],
        "DELETE FROM `test-cloud.trisixt.events` WHERE project_id=@project"
    );
    assert_eq!(body["queryParameters"].as_array().unwrap().len(), 1);
    assert_eq!(
        body["queryParameters"][0]["parameterValue"]["value"],
        project.to_string()
    );
    assert_eq!(requests[1].method, Method::GET);
    let failed = Mock::new(vec![response(
        200,
        r#"{"jobComplete":true,"errors":[{"reason":"accessDenied"}]}"#,
    )])
    .await;
    assert!(
        Analytics::bigquery(bq_config(&failed.url))
            .unwrap()
            .purge_project(project)
            .await
            .is_err()
    );
}
