//! Actual HTTP -> PostgreSQL outbox -> ClickHouse dashboard and MinIO object flow.
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;
use trisixt::{
    config::{AnalyticsBackend, Config, StorageBackend},
    providers::Analytics,
    state::AppState,
    worker,
};
use uuid::Uuid;
async fn json_request(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: String,
    token: Option<&str>,
    body: Value,
    status: u16,
) -> Value {
    let mut req = client.request(method, url).json(&body);
    if let Some(token) = token {
        req = req.bearer_auth(token)
    }
    let response = req.send().await.unwrap();
    assert_eq!(response.status().as_u16(), status);
    response.json().await.unwrap()
}
#[tokio::test]
#[ignore = "requires PostgreSQL, ClickHouse, MinIO and AWS_ENDPOINT via scripts/integration.sh"]
async fn http_ingestion_analytics_and_storage_flow() {
    let db = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL required");
    let admin = PgPool::connect(&db).await.unwrap();
    let schema = format!("test_e2e_{}", Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await
        .unwrap();
    let search = format!("SET search_path TO {schema}");
    let pool = PgPoolOptions::new()
        .after_connect(move |c, _| {
            let s = search.clone();
            Box::pin(async move {
                sqlx::query(sqlx::AssertSqlSafe(s)).execute(c).await?;
                Ok(())
            })
        })
        .connect(&db)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    assert_eq!(
        std::env::var("AWS_ENDPOINT").expect("AWS_ENDPOINT must target isolated MinIO"),
        std::env::var("TEST_S3_ENDPOINT").expect("TEST_S3_ENDPOINT required")
    );
    let config = Config {
        env: "test".into(),
        host: "127.0.0.1".into(),
        port: 0,
        server_host: "example.test".into(),
        database_url: db,
        redis_url: std::env::var("TEST_REDIS_URL").unwrap(),
        ee_enabled: true,
        analytics_backend: AnalyticsBackend::ClickHouse,
        storage_backend: StorageBackend::S3,
        storage_region: Some("us-east-1".into()),
        storage_bucket: Some(std::env::var("TEST_S3_BUCKET").unwrap_or_else(|_| "trisixt".into())),
        clickhouse_url: Some(
            std::env::var("TEST_CLICKHOUSE_URL").expect("TEST_CLICKHOUSE_URL required"),
        ),
        pubsub_topic: None,
        bigquery_dataset: None,
        gcs_credentials: None,
    };
    let state = AppState {
        config: Arc::new(config),
        pg: pool.clone(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = trisixt::routes::router(state.clone());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let credentials = json!({"email":"owner@e2e.test","password":"correct horse battery staple"});
    json_request(
        &client,
        reqwest::Method::POST,
        format!("{base}/auth/register"),
        None,
        credentials.clone(),
        201,
    )
    .await;
    let login = json_request(
        &client,
        reqwest::Method::POST,
        format!("{base}/auth/login"),
        None,
        credentials,
        200,
    )
    .await;
    let token = login["token"].as_str().unwrap();
    let tenant = json_request(
        &client,
        reqwest::Method::POST,
        format!("{base}/api/v1/instances"),
        Some(token),
        json!({"name":"E2E tenant"}),
        201,
    )
    .await;
    let tenant = tenant["id"].as_str().unwrap();
    let project = json_request(
        &client,
        reqwest::Method::POST,
        format!("{base}/api/v1/instances/{tenant}/projects"),
        Some(token),
        json!({"name":"E2E","environment":"test","domain":"e2e.example.test"}),
        201,
    )
    .await;
    let project = project["id"].as_str().unwrap();
    json_request(
        &client,
        reqwest::Method::PUT,
        format!("{base}/api/v1/projects/{project}/configurations/ios"),
        Some(token),
        json!({"enabled":true,"bundle_id":"com.example.app"}),
        200,
    )
    .await;
    let key = json_request(
        &client,
        reqwest::Method::POST,
        format!("{base}/api/v1/projects/{project}/keys"),
        Some(token),
        json!({"name":"SDK"}),
        201,
    )
    .await;
    let key = key["key"]
        .as_str()
        .or_else(|| key["token"].as_str())
        .expect("SDK credential");
    let event = json!({"event_id":Uuid::new_v4(),"visitor_id":Uuid::new_v4(),"event_type":"purchase_view","occurred_at":Utc::now(),"properties":{"source":"test"}});
    for _ in 0..2 {
        let response = client
            .post(format!("{base}/api/v1/sdk/events"))
            .header("x-project-key", key)
            .header("platform", "ios")
            .header("identifier", "com.example.app")
            .json(&json!({"events":[event]}))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success(), "{}", response.status());
    }
    let analytics = Analytics::from_env(&state.config).unwrap();
    assert_eq!(worker::dispatch_once(&state, &analytics).await.unwrap(), 1);
    assert_eq!(worker::dispatch_once(&state, &analytics).await.unwrap(), 0);
    let response = client
        .get(format!("{base}/api/v1/projects/{project}/analytics"))
        .bearer_auth(token)
        .query(&[
            ("from", (Utc::now() - Duration::days(1)).to_rfc3339()),
            ("to", (Utc::now() + Duration::hours(1)).to_rfc3339()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let dashboard: Value = response.json().await.unwrap();
    assert_eq!(dashboard["total_events"], 1);
    assert_eq!(dashboard["unique_visitors"], 1);
    let asset = format!("{base}/api/v1/projects/{project}/objects/export/example.txt");
    let response = client
        .put(&asset)
        .bearer_auth(token)
        .body("test asset")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 204);
    let response = client.get(&asset).bearer_auth(token).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers()["content-disposition"], "attachment");
    assert_eq!(response.text().await.unwrap(), "test asset");
    assert_eq!(
        client.get(&asset).send().await.unwrap().status().as_u16(),
        401
    );
    assert_eq!(
        client
            .delete(&asset)
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        204
    );
    assert_eq!(
        client
            .get(&asset)
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
    task.abort();
    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
