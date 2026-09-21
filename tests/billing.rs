use axum::{
    Json, Router,
    http::{HeaderMap, Method, Uri},
};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;
use trisixt::{
    billing::{self, StripeClient},
    config::{AnalyticsBackend, Config, StorageBackend},
    state::AppState,
};
use uuid::Uuid;

#[test]
fn stripe_signatures_verify_timestamp_raw_body_and_rotated_signatures() {
    let secret = "whsec_test_secret_only";
    let body = br#"{"id":"evt_test","type":"customer.subscription.updated"}"#;
    let now = Utc::now().timestamp();
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{now}.").as_bytes());
    mac.update(body);
    let signature = hex::encode(mac.finalize().into_bytes());
    let header = format!("t={now},v1=0000,v1={signature}");
    assert!(billing::verify_signature(secret, &header, body, now).is_ok());
    assert!(billing::verify_signature(secret, &header, b"{}", now).is_err());
    assert!(billing::verify_signature(secret, &header, body, now + 301).is_err());
    assert!(billing::verify_signature(secret, &header, body, now - 301).is_err());
    assert!(billing::verify_signature("", &header, body, now).is_err());
}
#[tokio::test]
async fn stripe_http_uses_authenticated_form_idempotency_and_no_redirects() {
    let app = Router::new().fallback(
        |method: Method, uri: Uri, headers: HeaderMap, body: String| async move {
            assert_eq!(method, Method::POST);
            assert_eq!(uri.path(), "/v1/checkout/sessions");
            assert_eq!(headers["authorization"], "Bearer sk_test_only");
            assert_eq!(headers["idempotency-key"], "stable-key");
            assert!(body.contains("mode=subscription"));
            Json(json!({"id":"cs_test","url":"https://checkout.stripe.com/test"}))
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = StripeClient::new("sk_test_only".into(), base).unwrap();
    let result = client
        .request(
            reqwest::Method::POST,
            "/v1/checkout/sessions",
            &[("mode".into(), "subscription".into())],
            Some("stable-key"),
        )
        .await
        .unwrap();
    assert_eq!(result["id"], "cs_test");
    server.abort();
    assert!(StripeClient::new("secret".into(), "https://evil.example".into()).is_err());
}
async fn fixture() -> (AppState, PgPool, String) {
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL required");
    let admin = PgPool::connect(&url).await.unwrap();
    let schema = format!("test_billing_{}", Uuid::new_v4().simple());
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
#[ignore = "requires PostgreSQL via TEST_DATABASE_URL; run scripts/integration.sh"]
async fn billing_snapshot_ordering_paid_through_cancel_and_monthly_usage() {
    let (st, admin, schema) = fixture().await;
    let instance: Uuid =
        sqlx::query_scalar("INSERT INTO instances(name) VALUES('Billing') RETURNING id")
            .fetch_one(&st.pg)
            .await
            .unwrap();
    let project:Uuid=sqlx::query_scalar("INSERT INTO projects(instance_id,environment,domain) VALUES($1,'production','billing.example.test') RETURNING id").bind(instance).fetch_one(&st.pg).await.unwrap();
    let current = Utc::now().timestamp();
    let mut remote = json!({"id":"sub_test","customer":"cus_test","status":"active","current_period_start":current-100,"current_period_end":current+3600,"cancel_at_period_end":true,"cancel_at":current+3600,"items":{"data":[{"id":"si_test"}]}});
    billing::apply_snapshot(&st, instance, &remote, 20)
        .await
        .unwrap();
    assert!(billing::has_paid_entitlement(&st, instance).await.unwrap());
    remote["status"] = json!("past_due");
    billing::apply_snapshot(&st, instance, &remote, 10)
        .await
        .unwrap();
    assert!(billing::has_paid_entitlement(&st, instance).await.unwrap());
    billing::apply_snapshot(&st, instance, &remote, 30)
        .await
        .unwrap();
    assert!(!billing::has_paid_entitlement(&st, instance).await.unwrap());
    remote["status"] = json!("active");
    remote["pause_collection"] = json!({"behavior":"void"});
    billing::apply_snapshot(&st, instance, &remote, 40)
        .await
        .unwrap();
    assert!(!billing::has_paid_entitlement(&st, instance).await.unwrap());
    let visitor = Uuid::new_v4();
    let mut tx = st.pg.begin().await.unwrap();
    billing::record_usage(&mut tx, project, visitor, Utc::now())
        .await
        .unwrap();
    billing::record_usage(&mut tx, project, visitor, Utc::now())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        billing::mau(&st, instance, Utc::now(), Utc::now())
            .await
            .unwrap(),
        1
    );
    sqlx::query("INSERT INTO enterprise_subscriptions(instance_id,start_date,end_date,total_maus) VALUES($1,now()-interval '1 day',now()+interval '1 day',100000)").bind(instance).execute(&st.pg).await.unwrap();
    assert!(billing::has_paid_entitlement(&st, instance).await.unwrap());
    st.pg.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL via TEST_DATABASE_URL; run scripts/integration.sh"]
async fn stripe_inbox_failure_retries_and_duplicate_delivery_is_idempotent() {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use std::sync::atomic::{AtomicBool, Ordering};
    let (st, admin, schema) = fixture().await;
    let instance: Uuid =
        sqlx::query_scalar("INSERT INTO instances(name) VALUES('Stripe inbox') RETURNING id")
            .fetch_one(&st.pg)
            .await
            .unwrap();
    let failing = Arc::new(AtomicBool::new(true));
    let provider_failing = failing.clone();
    let app = Router::new().fallback(move |headers:HeaderMap,uri:Uri| {
        let failing=provider_failing.clone();
        async move {
            assert_eq!(headers["authorization"],"Bearer sk_test");
            assert_eq!(uri.path(),"/v1/subscriptions/sub_inbox");
            if failing.load(Ordering::SeqCst) { return StatusCode::SERVICE_UNAVAILABLE.into_response(); }
            Json(json!({"id":"sub_inbox","customer":"cus_inbox","metadata":{"instance_id":instance},"status":"active","items":{"data":[{"id":"si_inbox"}]},"current_period_start":Utc::now().timestamp()-100,"current_period_end":Utc::now().timestamp()+3600})).into_response()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = StripeClient::new(
        "sk_test".into(),
        format!("http://{}", listener.local_addr().unwrap()),
    )
    .unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let event = json!({"id":"evt_inbox","type":"customer.subscription.updated","created":20,"data":{"object":{"id":"sub_inbox","status":"past_due"}}});
    for _ in 0..2 {
        sqlx::query("INSERT INTO billing_webhooks(id,event_type,created,payload) VALUES('evt_inbox','customer.subscription.updated',20,$1) ON CONFLICT DO NOTHING").bind(&event).execute(&st.pg).await.unwrap();
    }
    assert_eq!(billing::dispatch_pending(&st, &client, 5).await.unwrap(), 0);
    let pending:(i32,bool,bool)=sqlx::query_as("SELECT attempts,available_at>now(),processed_at IS NULL FROM billing_webhooks WHERE id='evt_inbox'").fetch_one(&st.pg).await.unwrap();
    assert_eq!(pending, (1, true, true));
    failing.store(false, Ordering::SeqCst);
    sqlx::query("UPDATE billing_webhooks SET available_at=now() WHERE id='evt_inbox'")
        .execute(&st.pg)
        .await
        .unwrap();
    assert_eq!(billing::dispatch_pending(&st, &client, 5).await.unwrap(), 1);
    assert_eq!(billing::dispatch_pending(&st, &client, 5).await.unwrap(), 0);
    // Delivery payload says past_due, but current verified provider state is active.
    assert!(billing::has_paid_entitlement(&st, instance).await.unwrap());
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM billing_subscriptions WHERE instance_id=$1")
            .bind(instance)
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
