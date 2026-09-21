//! Test durable delivery using real PostgreSQL and controlled HTTP provider failures.
use axum::{Router, extract::State, http::StatusCode, routing::post};
use chrono::Utc;
use serde_json::json;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::{
    Arc,
    atomic::{AtomicU16, AtomicUsize, Ordering},
};
use trisixt::{
    auth::new_token,
    config::{AnalyticsBackend, Config, StorageBackend},
    providers::{Analytics, AnalyticsEvent, ClickHouseConfig},
    state::AppState,
    worker,
};
use uuid::Uuid;
#[derive(Clone)]
struct MockState {
    status: Arc<AtomicU16>,
    calls: Arc<AtomicUsize>,
}
async fn mock(State(st): State<MockState>) -> StatusCode {
    st.calls.fetch_add(1, Ordering::SeqCst);
    StatusCode::from_u16(st.status.load(Ordering::SeqCst)).unwrap()
}
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL and TEST_REDIS_URL"]
async fn outbox_retries_preserves_identity_and_parallel_workers_do_not_double_claim() {
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL required");
    let admin = PgPool::connect(&url).await.unwrap();
    let schema = format!("test_worker_{}", Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await
        .unwrap();
    let path = format!("SET search_path TO {schema}");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .after_connect(move |c, _| {
            let path = path.clone();
            Box::pin(async move {
                sqlx::query(sqlx::AssertSqlSafe(path)).execute(c).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let control = MockState {
        status: Arc::new(AtomicU16::new(403)),
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let router = Router::new()
        .route("/", post(mock))
        .with_state(control.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let config = Config {
        env: "test".into(),
        host: "127.0.0.1".into(),
        port: 0,
        server_host: "example.test".into(),
        database_url: url,
        redis_url: std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL required"),
        ee_enabled: true,
        analytics_backend: AnalyticsBackend::ClickHouse,
        storage_backend: StorageBackend::S3,
        storage_region: None,
        storage_bucket: None,
        clickhouse_url: Some(endpoint.clone()),
        pubsub_topic: None,
        bigquery_dataset: None,
        gcs_credentials: None,
    };
    let st = AppState {
        config: Arc::new(config),
        pg: pool.clone(),
    };
    let analytics = Analytics::clickhouse(ClickHouseConfig {
        url: endpoint,
        database: "trisixt".into(),
        table: "events".into(),
        username: "test".into(),
        password: "secret".into(),
    })
    .unwrap();
    let instance: Uuid =
        sqlx::query_scalar("INSERT INTO instances(name)VALUES('Worker')RETURNING id")
            .fetch_one(&pool)
            .await
            .unwrap();
    let project: Uuid = sqlx::query_scalar(
        "INSERT INTO projects(instance_id,environment,domain)VALUES($1,'test',$2)RETURNING id",
    )
    .bind(instance)
    .bind(format!("{}.test", new_token().0))
    .fetch_one(&pool)
    .await
    .unwrap();
    let visitor = Uuid::new_v4();
    sqlx::query("INSERT INTO visitors(id,project_id)VALUES($1,$2)")
        .bind(visitor)
        .bind(project)
        .execute(&pool)
        .await
        .unwrap();
    let event = AnalyticsEvent {
        id: Uuid::new_v4(),
        event_id: Uuid::new_v4(),
        project_id: project,
        visitor_id: visitor,
        event_type: "open".into(),
        occurred_at: Utc::now(),
        properties: json!({}),
    };
    sqlx::query("INSERT INTO events(id,event_id,project_id,visitor_id,event_type,occurred_at)VALUES($1,$2,$3,$4,$5,$6)").bind(event.id).bind(event.event_id).bind(project).bind(visitor).bind(&event.event_type).bind(event.occurred_at).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO analytics_outbox(project_id,event_id,payload)VALUES($1,$2,$3)")
        .bind(project)
        .bind(event.id)
        .bind(serde_json::to_value(&event).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(worker::dispatch_once(&st, &analytics).await.unwrap(), 1);
    let (attempts, pending, error): (i32, bool, String) = sqlx::query_as(
        "SELECT attempts,processed_at IS NULL,last_error FROM analytics_outbox WHERE event_id=$1",
    )
    .bind(event.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(attempts, 1);
    assert!(pending);
    assert_eq!(error, "provider delivery failed");
    assert_eq!(worker::dispatch_once(&st, &analytics).await.unwrap(), 0);
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
    control.status.store(200, Ordering::SeqCst);
    sqlx::query("UPDATE analytics_outbox SET available_at=now() WHERE event_id=$1")
        .bind(event.id)
        .execute(&pool)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        worker::dispatch_once(&st, &analytics),
        worker::dispatch_once(&st, &analytics)
    );
    assert_eq!(a.unwrap() + b.unwrap(), 1);
    assert_eq!(control.calls.load(Ordering::SeqCst), 2);
    let (attempts, done, payload): (i32, bool, serde_json::Value) = sqlx::query_as(
        "SELECT attempts,processed_at IS NOT NULL,payload FROM analytics_outbox WHERE event_id=$1",
    )
    .bind(event.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(attempts, 2);
    assert!(done);
    assert_eq!(payload["event_id"], event.event_id.to_string());
    let (tx, rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(worker::run(st.clone(), rx));
    let client = redis::Client::open(st.config.redis_url.as_str()).unwrap();
    let mut conn = client.get_multiplexed_async_connection().await.unwrap();
    let mut heartbeat = false;
    for _ in 0..20 {
        let value: Option<String> = redis::cmd("GET")
            .arg("trisixt:worker:heartbeat")
            .query_async(&mut conn)
            .await
            .unwrap();
        if value.is_some() {
            heartbeat = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(heartbeat);
    tx.send(true).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .unwrap()
        .unwrap();
    redis::cmd("DEL")
        .arg("trisixt:worker:heartbeat")
        .query_async::<()>(&mut conn)
        .await
        .unwrap();
    server.abort();
    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
