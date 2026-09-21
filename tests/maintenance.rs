use axum::{
    Json, Router,
    body::Bytes,
    http::{HeaderMap, StatusCode, Uri},
    response::IntoResponse,
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Mutex;
use trisixt::{
    config::{AnalyticsBackend, Config, StorageBackend},
    maintenance,
    providers::{Analytics, AnalyticsEvent, BigQueryConfig, ClickHouseConfig, GoogleAuth},
    state::AppState,
};
use uuid::Uuid;
fn ch(base: &str) -> Analytics {
    Analytics::clickhouse(ClickHouseConfig {
        url: base.into(),
        database: "trisixt".into(),
        table: "events".into(),
        username: "default".into(),
        password: "".into(),
    })
    .unwrap()
}
async fn serve(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    (
        url,
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() }),
    )
}
async fn fixture() -> (AppState, PgPool, String) {
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL required");
    let admin = PgPool::connect(&url).await.unwrap();
    let schema = format!("test_maintenance_{}", Uuid::new_v4().simple());
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

#[tokio::test]
async fn bigquery_retention_parameters_polling_and_errors() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorded = calls.clone();
    let project = Uuid::new_v4();
    let cutoff = Utc::now() - Duration::days(2);
    let app = Router::new().fallback(move |headers: HeaderMap, uri: Uri, body: Bytes| {
        let recorded = recorded.clone();
        async move {
            assert_eq!(headers["authorization"], "Bearer mock-token");
            recorded.lock().await.push((uri.clone(), body.clone()));
            if uri.path().ends_with("/queries") {
                let value: Value = serde_json::from_slice(&body).unwrap();
                assert!(value["query"].as_str().unwrap().starts_with(
                    "DELETE FROM `test-cloud.trisixt.events` WHERE project_id=@project"
                ));
                assert_eq!(
                    value["queryParameters"][0]["parameterValue"]["value"],
                    project.to_string()
                );
                assert_eq!(
                    value["queryParameters"][1]["parameterValue"]["value"],
                    cutoff.to_rfc3339()
                );
                Json(json!({"jobComplete":false,"jobReference":{"jobId":"retention_job"}}))
            } else {
                assert!(uri.path().ends_with("/queries/retention_job"));
                Json(json!({"jobComplete":true,"numDmlAffectedRows":"2"}))
            }
        }
    });
    let (base, server) = serve(app).await;
    let analytics = Analytics::bigquery(BigQueryConfig {
        project: "test-cloud".into(),
        dataset: "trisixt".into(),
        table: "events".into(),
        location: "US".into(),
        topic: "projects/test-cloud/topics/events".into(),
        pubsub_endpoint: base.clone(),
        bigquery_endpoint: base,
        maximum_bytes_billed: 1000000,
        auth: GoogleAuth::AccessToken("mock-token".into()),
    })
    .unwrap();
    analytics.purge_before(project, cutoff).await.unwrap();
    assert_eq!(calls.lock().await.len(), 2);
    assert!(analytics.purge_before(Uuid::nil(), cutoff).await.is_err());
    server.abort();
    let (base, server) = serve(Router::new().fallback(|| async {
        Json(json!({"jobComplete":true,"errors":[{"message":"permission denied"}]}))
    }))
    .await;
    let analytics = Analytics::bigquery(BigQueryConfig {
        project: "test-cloud".into(),
        dataset: "trisixt".into(),
        table: "events".into(),
        location: "US".into(),
        topic: "projects/test-cloud/topics/events".into(),
        pubsub_endpoint: base.clone(),
        bigquery_endpoint: base,
        maximum_bytes_billed: 1000000,
        auth: GoogleAuth::AccessToken("mock-token".into()),
    })
    .unwrap();
    assert!(analytics.purge_before(project, cutoff).await.is_err());
    server.abort();
}
#[tokio::test]
async fn clickhouse_backlog_prevents_destructive_mutation() {
    let calls = Arc::new(Mutex::new(0));
    let recorded = calls.clone();
    let app = Router::new().fallback(move |body: Bytes| {
        let recorded = recorded.clone();
        async move {
            *recorded.lock().await += 1;
            assert!(String::from_utf8_lossy(&body).contains("system.mutations"));
            Json(json!({"data":[{"pending":"51"}]}))
        }
    });
    let (base, server) = serve(app).await;
    assert!(
        ch(&base)
            .purge_before(Uuid::new_v4(), Utc::now() - Duration::days(1))
            .await
            .is_err()
    );
    assert_eq!(*calls.lock().await, 1);
    server.abort();
}
#[tokio::test]
#[ignore = "requires PostgreSQL via TEST_DATABASE_URL; run scripts/integration.sh"]
async fn retention_retries_preserves_queue_purchases_billing_and_repairs_delivery() {
    let (st, admin, schema) = fixture().await;
    let instance: Uuid = sqlx::query_scalar(
        "INSERT INTO instances(name,delete_days) VALUES('Retention',2) RETURNING id",
    )
    .fetch_one(&st.pg)
    .await
    .unwrap();
    let project:Uuid=sqlx::query_scalar("INSERT INTO projects(instance_id,environment,domain) VALUES($1,'production','retention.example.test') RETURNING id").bind(instance).fetch_one(&st.pg).await.unwrap();
    let visitor = Uuid::new_v4();
    sqlx::query("INSERT INTO visitors(project_id,id) VALUES($1,$2)")
        .bind(project)
        .bind(visitor)
        .execute(&st.pg)
        .await
        .unwrap();
    let mut ids = Vec::new();
    for (days, pending) in [(5, false), (4, true), (3, false), (1, false)] {
        let event = Uuid::new_v4();
        let id:Uuid=sqlx::query_scalar("INSERT INTO events(project_id,visitor_id,event_id,event_type,occurred_at) VALUES($1,$2,$3,'view',$4) RETURNING id").bind(project).bind(visitor).bind(event).bind(Utc::now()-Duration::days(days)).fetch_one(&st.pg).await.unwrap();
        sqlx::query("INSERT INTO analytics_outbox(project_id,event_id,payload,processed_at) VALUES($1,$2,'{}',CASE WHEN $3 THEN NULL ELSE now() END)").bind(project).bind(id).bind(pending).execute(&st.pg).await.unwrap();
        ids.push(id);
    }
    sqlx::query("INSERT INTO monthly_active_visitors(instance_id,month,visitor_id) VALUES($1,'2020-01-01',$2)").bind(instance).bind(visitor).execute(&st.pg).await.unwrap();
    sqlx::query("INSERT INTO verified_purchases(project_id,visitor_id,provider,application_id,environment,transaction_id,original_transaction_id,product_id,purchase_kind,currency,amount_nanos,quantity,purchased_at) VALUES($1,$2,'apple','com.test','production','old','old','item','one_time','USD',1000,1,now()-interval '1000 days')").bind(project).bind(visitor).execute(&st.pg).await.unwrap();
    let fail = Arc::new(AtomicBool::new(true));
    let fail_provider = fail.clone();
    let mutations = Arc::new(Mutex::new(Vec::new()));
    let stored = mutations.clone();
    let app = Router::new().fallback(move |uri: Uri, body: Bytes| {
        let fail = fail_provider.clone();
        let stored = stored.clone();
        async move {
            if fail.load(Ordering::SeqCst) {
                return StatusCode::FORBIDDEN.into_response();
            }
            let body = String::from_utf8_lossy(&body);
            if body.contains("system.mutations") {
                Json(json!({"data":[{"pending":"0"}]})).into_response()
            } else {
                assert!(body.contains("mutations_sync=2"));
                assert!(
                    uri.query()
                        .unwrap()
                        .contains(&format!("param_project={project}"))
                );
                stored.lock().await.push(body.to_string());
                StatusCode::OK.into_response()
            }
        }
    });
    let (base, server) = serve(app).await;
    let analytics = ch(&base);
    let failed = maintenance::process_due(&st, &analytics, 1).await.unwrap();
    assert_eq!(failed.projects_failed, 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM events")
        .fetch_one(&st.pg)
        .await
        .unwrap();
    assert_eq!(count, 4);
    fail.store(false, Ordering::SeqCst);
    sqlx::query("UPDATE retention_jobs SET available_at=now()")
        .execute(&st.pg)
        .await
        .unwrap();
    let success = maintenance::process_due(&st, &analytics, 1).await.unwrap();
    assert_eq!(success.events_deleted, 1);
    assert_eq!(mutations.lock().await.len(), 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM events")
        .fetch_one(&st.pg)
        .await
        .unwrap();
    assert_eq!(count, 3);
    let preserved:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM verified_purchases),(SELECT count(*) FROM monthly_active_visitors),(SELECT count(*) FROM analytics_outbox WHERE processed_at IS NULL)").fetch_one(&st.pg).await.unwrap();
    assert_eq!(preserved, (1, 1, 1));
    sqlx::query("DELETE FROM analytics_outbox WHERE event_id=$1")
        .bind(ids[3])
        .execute(&st.pg)
        .await
        .unwrap();
    let repaired =
        maintenance::reconcile_range(&st, project, Utc::now() - Duration::days(10), Utc::now())
            .await
            .unwrap();
    assert_eq!(repaired["outbox_repaired"], 1);
    let payload: Value =
        sqlx::query_scalar("SELECT payload FROM analytics_outbox WHERE event_id=$1")
            .bind(ids[3])
            .fetch_one(&st.pg)
            .await
            .unwrap();
    assert!(serde_json::from_value::<AnalyticsEvent>(payload).is_ok());
    sqlx::query("INSERT INTO mail_outbox(payload_encrypted,created_at) VALUES('still pending',now()-interval '100 days')").execute(&st.pg).await.unwrap();
    sqlx::query("INSERT INTO mail_outbox(payload_encrypted,sent_at) VALUES('delivered',now()-interval '31 days')").execute(&st.pg).await.unwrap();
    assert_eq!(maintenance::cleanup_expired(&st).await.unwrap(), 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM mail_outbox WHERE sent_at IS NULL")
        .fetch_one(&st.pg)
        .await
        .unwrap();
    assert_eq!(count, 1);
    server.abort();
    st.pg.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[tokio::test]
#[ignore = "requires ClickHouse via TEST_CLICKHOUSE_URL; run scripts/integration.sh"]
async fn real_clickhouse_retention_is_tenant_scoped_and_completed() {
    let supplied = std::env::var("TEST_CLICKHOUSE_URL").expect("TEST_CLICKHOUSE_URL required");
    let mut url = reqwest::Url::parse(&supplied).unwrap();
    let user = url.username().to_owned();
    let password = url.password().unwrap_or("").to_owned();
    url.set_username("").unwrap();
    url.set_password(None).unwrap();
    let database = format!("test_retention_{}", Uuid::new_v4().simple());
    let http = reqwest::Client::new();
    for query in [
        format!("CREATE DATABASE {database}"),
        format!(
            "CREATE TABLE {database}.events (id UUID,event_id UUID,project_id UUID,visitor_id UUID,event_type String,occurred_at DateTime64(6,'UTC'),properties String) ENGINE=ReplacingMergeTree ORDER BY (project_id,event_id)"
        ),
    ] {
        let response = http
            .post(url.clone())
            .basic_auth(&user, Some(&password))
            .body(query)
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "{}",
            response.text().await.unwrap()
        );
    }
    let analytics = Analytics::clickhouse(ClickHouseConfig {
        url: url.to_string(),
        database: database.clone(),
        table: "events".into(),
        username: user.clone(),
        password: password.clone(),
    })
    .unwrap();
    let project = Uuid::new_v4();
    let other = Uuid::new_v4();
    let now = Utc::now();
    let event = |p, days| AnalyticsEvent {
        id: Uuid::new_v4(),
        event_id: Uuid::new_v4(),
        project_id: p,
        visitor_id: Uuid::new_v4(),
        event_type: "view".into(),
        occurred_at: now - Duration::days(days),
        properties: json!({}),
    };
    analytics
        .publish(&[event(project, 5), event(project, 1), event(other, 5)])
        .await
        .unwrap();
    analytics
        .purge_before(project, now - Duration::days(2))
        .await
        .unwrap();
    assert_eq!(
        analytics
            .dashboard(project, now - Duration::days(10), now + Duration::days(1))
            .await
            .unwrap()
            .total_events,
        1
    );
    assert_eq!(
        analytics
            .dashboard(other, now - Duration::days(10), now + Duration::days(1))
            .await
            .unwrap()
            .total_events,
        1
    );
    let response = http
        .post(url)
        .basic_auth(user, Some(password))
        .body(format!("DROP DATABASE {database}"))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
}
