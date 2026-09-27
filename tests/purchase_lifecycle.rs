use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;
use tower::ServiceExt;
use trisixt::{
    config::{AnalyticsBackend, Config, StorageBackend},
    purchase_lifecycle,
    state::AppState,
};
use uuid::Uuid;
async fn fixture() -> (AppState, PgPool, String) {
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL required");
    let admin = PgPool::connect(&url).await.unwrap();
    let schema = format!("test_lifecycle_{}", Uuid::new_v4().simple());
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

async fn payment(app: &Router, key: &str, value: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/sdk/add_payment_event")
                .header("x-project-key", key)
                .header("platform", "ios")
                .header("identifier", "com.example.app")
                .header("content-type", "application/json")
                .body(Body::from(value.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}
#[tokio::test]
#[ignore = "requires PostgreSQL via TEST_DATABASE_URL; run scripts/integration.sh"]
async fn sdk_reported_payments_signed_refunds_metadata_and_retry_persistence() {
    let (st, admin, schema) = fixture().await;
    let instance: Uuid =
        sqlx::query_scalar("INSERT INTO instances(name) VALUES('Lifecycle') RETURNING id")
            .fetch_one(&st.pg)
            .await
            .unwrap();
    let project:Uuid=sqlx::query_scalar("INSERT INTO projects(instance_id,environment,domain) VALUES($1,'production','life.example.test') RETURNING id").bind(instance).fetch_one(&st.pg).await.unwrap();
    sqlx::query("INSERT INTO project_configurations(project_id,ios) VALUES($1,$2)")
        .bind(project)
        .bind(json!({"enabled":true,"bundle_id":"com.example.app"}))
        .execute(&st.pg)
        .await
        .unwrap();
    let key = "7".repeat(64);
    sqlx::query("INSERT INTO project_api_keys(project_id,name,token_hash) VALUES($1,'test',$2)")
        .bind(project)
        .bind(trisixt::auth::token_hash(&key))
        .execute(&st.pg)
        .await
        .unwrap();
    let app = purchase_lifecycle::router().with_state(st.clone());
    let visitor = Uuid::new_v4();
    let now = Utc::now();
    let inviter = Uuid::new_v4();
    sqlx::query("INSERT INTO visitors(project_id,id) VALUES($1,$2)")
        .bind(project)
        .bind(visitor)
        .execute(&st.pg)
        .await
        .unwrap();
    let link:Uuid=sqlx::query_scalar("INSERT INTO links(project_id,name,path,target_url,metadata) VALUES($1,'Referral','referral','https://example.test',$2) RETURNING id").bind(project).bind(json!({"sdk_generated":true,"visitor_id":inviter})).fetch_one(&st.pg).await.unwrap();
    sqlx::query("INSERT INTO visitor_attributions(project_id,visitor_id,link_id,method) VALUES($1,$2,$3,'direct')").bind(project).bind(visitor).bind(link).execute(&st.pg).await.unwrap();
    let mut buy = json!({"visitor_id":visitor,"transaction_id":"order1","product_id":"item","currency":"EUR","price_cents":1000,"quantity":2,"date":now-Duration::hours(2),"session_id":"session-original","platform":"ios"});
    sqlx::query("INSERT INTO fx_rates(currency,units_per_usd) VALUES('EUR',2)")
        .execute(&st.pg)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        payment(&app, &key, buy.clone()),
        payment(&app, &key, buy.clone())
    );
    assert_eq!(a.0, StatusCode::OK, "{:?}", a);
    assert_eq!(b.0, StatusCode::OK, "{:?}", b);
    assert_eq!(a.1["id"], b.1["id"]);
    assert_eq!(a.1["verified"], false);
    assert_eq!(a.1["source"], "sdk_reported");
    buy["session_id"] = json!("second-session");
    assert_eq!(payment(&app, &key, buy.clone()).await.0, StatusCode::OK);
    let stored: (String, String) = sqlx::query_as(
        "SELECT session_id,verification_source FROM verified_purchases WHERE project_id=$1",
    )
    .bind(project)
    .fetch_one(&st.pg)
    .await
    .unwrap();
    assert_eq!(stored, ("session-original".into(), "sdk_reported".into()));
    // Link deletion and mutable referral metadata cannot erase purchase-time attribution.
    sqlx::query("UPDATE links SET metadata=$2 WHERE id=$1")
        .bind(link)
        .bind(json!({"sdk_generated":true,"visitor_id":Uuid::new_v4()}))
        .execute(&st.pg)
        .await
        .unwrap();
    sqlx::query("DELETE FROM links WHERE id=$1")
        .bind(link)
        .execute(&st.pg)
        .await
        .unwrap();
    // Today's FX must not change the original monetary value of a refund.
    sqlx::query("UPDATE fx_rates SET units_per_usd=4 WHERE currency='EUR'")
        .execute(&st.pg)
        .await
        .unwrap();
    let refund = json!({"visitor_id":visitor,"transaction_id":"refund1","original_transaction_id":"order1","product_id":"item","currency":"EUR","price_cents":1000,"quantity":1,"event_type":"REFUND","date":now-Duration::hours(1)});
    assert_eq!(payment(&app, &key, refund.clone()).await.0, StatusCode::OK);
    assert_eq!(payment(&app, &key, refund.clone()).await.0, StatusCode::OK);
    let metrics = purchase_lifecycle::revenue_metrics(
        &st,
        project,
        now - Duration::days(1),
        now + Duration::days(1),
        None,
    )
    .await
    .unwrap();
    assert_eq!(metrics["revenue_usd_nanos"], "5000000000");
    assert_eq!(metrics["units_sold"], 1);
    assert_eq!(metrics["by_currency"][0]["net_amount_nanos"], "10000000000");
    let mut reversal = refund.clone();
    reversal["transaction_id"] = json!("reverse1");
    reversal["event_type"] = json!("REFUND_REVERSED");
    reversal["date"] = json!(now);
    assert_eq!(
        payment(&app, &key, reversal.clone()).await.0,
        StatusCode::OK
    );
    assert_eq!(
        payment(&app, &key, reversal.clone()).await.0,
        StatusCode::OK
    );
    let mut stale = refund.clone();
    stale["transaction_id"] = json!("stale");
    assert_eq!(payment(&app, &key, stale).await.0, StatusCode::OK);
    let metrics = purchase_lifecycle::revenue_metrics(
        &st,
        project,
        now - Duration::days(1),
        now + Duration::days(1),
        None,
    )
    .await
    .unwrap();
    assert_eq!(metrics["revenue_usd_nanos"], "10000000000");
    assert_eq!(metrics["units_sold"], 2);
    let snapshots: Vec<(Option<Uuid>, Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
        "SELECT link_id,attributed_link_id,inviter_id FROM purchase_ledger WHERE project_id=$1",
    )
    .bind(project)
    .fetch_all(&st.pg)
    .await
    .unwrap();
    assert_eq!(snapshots.len(), 3);
    assert!(
        snapshots
            .iter()
            .all(|r| *r == (None, Some(link), Some(inviter)))
    );
    let mut forged = buy.clone();
    forged["store"] = json!(true);
    forged["transaction_id"] = json!("fake-store");
    assert_eq!(payment(&app, &key, forged).await.0, StatusCode::BAD_REQUEST);
    let mut foreign = refund.clone();
    foreign["visitor_id"] = json!(Uuid::new_v4());
    assert_eq!(payment(&app, &key, foreign).await.0, StatusCode::CONFLICT);
    let id:Uuid=sqlx::query_scalar("INSERT INTO purchase_notifications(provider,external_id,instance_id,project_id,payload) VALUES('apple','invalid',$1,$2,'{}') RETURNING id").bind(instance).bind(project).fetch_one(&st.pg).await.unwrap();
    assert_eq!(
        purchase_lifecycle::process_pending(&st, 1).await.unwrap(),
        0
    );
    let retry:(i32,bool,bool)=sqlx::query_as("SELECT attempts,available_at>now(),processed_at IS NULL FROM purchase_notifications WHERE id=$1").bind(id).fetch_one(&st.pg).await.unwrap();
    assert_eq!(retry, (1, true, true));
    st.pg.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[test]
fn google_setup_renders_authenticated_push_and_quotes_operator_values() {
    let instance = Uuid::new_v4();
    let audience = "https://api.example.test/audience?name='$(printf injected)'";
    let script = purchase_lifecycle::google_setup_script(
        "https://api.example.test",
        instance,
        Some(audience),
        Some("trisixt-play-api@project-example.iam.gserviceaccount.com"),
    )
    .unwrap();
    assert!(script.contains(&format!(
        "PUSH_ENDPOINT='https://api.example.test/api/v1/iap/google/{instance}'"
    )));
    assert!(script.contains("--push-auth-token-audience=\"$PUSH_AUDIENCE\""));
    assert!(script.contains("--push-auth-service-account=\"$SA_EMAIL\""));
    assert!(script.contains("roles/iam.serviceAccountTokenCreator"));
    assert!(script.contains("google-play-developer-notifications@system.gserviceaccount.com"));
    assert!(!script.contains("@@"));
    assert!(!script.contains("gcloud config set"));
    let mut command = std::process::Command::new("bash")
        .args(["-n"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    command
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    assert!(command.wait().unwrap().success());
    // Evaluate only the assignment, proving command substitution remains inert data.
    let assignment = script
        .lines()
        .find(|line| line.starts_with("PUSH_AUDIENCE="))
        .unwrap();
    let output = std::process::Command::new("bash")
        .args([
            "-c",
            &format!("{assignment}\nprintf '%s' \"$PUSH_AUDIENCE\""),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), audience);
    for origin in [
        "http://api.example.test",
        "https://user:pass@api.example.test",
        "https://api.example.test/path",
        "https://api.example.test?x=y",
    ] {
        assert!(purchase_lifecycle::google_setup_script(origin, instance, None, None).is_err());
    }
    assert!(
        purchase_lifecycle::google_setup_script(
            "https://api.example.test",
            instance,
            None,
            Some("bad';echo injected")
        )
        .is_err()
    );
}

mod support;
#[tokio::test]
#[ignore = "requires PostgreSQL via TEST_DATABASE_URL; run scripts/integration.sh"]
async fn google_setup_download_requires_project_administrator() {
    let f = support::Fixture::new().await;
    let path = f.path("purchases/google_configuration_script");
    let (status, body, headers) = f.raw("GET", &path, Value::Null, &f.token, "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        headers["content-disposition"],
        "attachment; filename=\"trisixt_android_gcloud_setup.sh\""
    );
    assert!(
        body["raw"]
            .as_str()
            .unwrap()
            .contains(&format!("/api/v1/iap/google/{}", f.instance))
    );
    assert_eq!(
        f.raw("GET", &path, Value::Null, "", &f.key).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.call(
            "GET",
            &format!(
                "/api/v1/projects/{}/purchases/google_configuration_script",
                Uuid::new_v4()
            ),
            Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE instance_roles SET role='member' WHERE user_id=$1")
        .bind(f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.call("GET", &path, Value::Null).await.0,
        StatusCode::FORBIDDEN
    );
    f.close().await;
}
