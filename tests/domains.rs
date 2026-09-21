use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    routing::any,
};
use serde_json::{Value, json};
use std::{collections::VecDeque, sync::Arc};
use tokio::sync::Mutex;
use trisixt::domains::{Cloudflare, cloudflare_records, normalize_hostname, public_ip};
#[test]
fn hostname_and_network_proofs_reject_private_targets() {
    assert_eq!(
        normalize_hostname(" Links.Example.COM. ").unwrap(),
        "links.example.com"
    );
    for host in [
        "localhost",
        "127.0.0.1",
        "evil.com/path",
        "user@example.com",
        "bad..example.com",
        "-bad.example.com",
        "éxample.com",
    ] {
        assert!(normalize_hostname(host).is_err(), "{host}");
    }
    for ip in [
        "127.0.0.1",
        "0.0.0.0",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "::1",
        "fc00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
    ] {
        assert!(!public_ip(ip.parse().unwrap()), "{ip}");
    }
    assert!(public_ip("1.1.1.1".parse().unwrap()));
    assert!(public_ip("2606:4700:4700::1111".parse().unwrap()));
}
#[test]
fn all_pending_and_unknown_txt_records_are_preserved() {
    let v = json!({"ssl":{"validation_records":[{"txt_name":"_a.example.com","txt_value":"a","status":"pending"},{"txt_name":"_b.example.com","txt_value":"b"},{"txt_name":"_c.example.com","txt_value":"c","status":"valid"},{"http_url":"https://example.com/proof"}]}});
    let records = cloudflare_records(&v);
    assert_eq!(records.as_array().unwrap().len(), 2);
    assert_eq!(records[1]["name"], "_b.example.com");
}
type SeenRequests = Arc<Mutex<Vec<(Method, String, HeaderMap, Value)>>>;
#[derive(Clone)]
struct Mock {
    responses: Arc<Mutex<VecDeque<(StatusCode, Value)>>>,
    seen: SeenRequests,
}
async fn handler(
    State(m): State<Mock>,
    method: Method,
    uri: Uri,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    m.seen.lock().await.push((method, uri.to_string(), h, body));
    let (s, v) = m.responses.lock().await.pop_front().unwrap();
    (s, Json(v))
}
async fn fallback(
    State(m): State<Mock>,
    method: Method,
    uri: Uri,
    h: HeaderMap,
    body: axum::body::Bytes,
) -> (StatusCode, Json<Value>) {
    handler(
        State(m),
        method,
        uri,
        h,
        Json(serde_json::from_slice(&body).unwrap_or(Value::Null)),
    )
    .await
}
#[tokio::test]
async fn cloudflare_adopts_orphan_and_checks_body_success_before_deletion() {
    let m = Mock {
        responses: Arc::new(Mutex::new(VecDeque::from([
            (StatusCode::CONFLICT, json!({"success":false})),
            (
                StatusCode::OK,
                json!({"success":true,"result":[{"id":"cf123","hostname":"links.example.com","status":"pending"}]}),
            ),
            (
                StatusCode::OK,
                json!({"success":false,"errors":[{"code":1000}]}),
            ),
            (
                StatusCode::NOT_FOUND,
                json!({"success":false,"errors":[{"code":1436}]}),
            ),
        ]))),
        seen: Arc::new(Mutex::new(Vec::new())),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().fallback(any(fallback)).with_state(m.clone());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let cf = Cloudflare::new(url, "zone123".into(), "test-secret".into()).unwrap();
    let result = cf.create("links.example.com").await.unwrap();
    assert_eq!(result["id"], "cf123");
    assert!(cf.delete("cf123").await.is_err());
    assert!(cf.delete("cf123").await.is_ok());
    let seen = m.seen.lock().await;
    assert_eq!(seen.len(), 4);
    assert_eq!(seen[0].2["authorization"], "Bearer test-secret");
    assert_eq!(seen[0].3["ssl"], json!({"method":"txt","type":"dv"}));
    assert!(seen[1].1.contains("hostname=links.example.com"));
    task.abort();
}

use uuid::Uuid;
async fn state() -> (trisixt::state::AppState, sqlx::PgPool, String) {
    use std::sync::Arc;
    use trisixt::config::{AnalyticsBackend, Config, StorageBackend};
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL required");
    let admin = sqlx::PgPool::connect(&url).await.unwrap();
    let schema = format!("test_domains_{}", Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await
        .unwrap();
    let search = format!("SET search_path TO {schema},public");
    let pg = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .after_connect(move |c, _| {
            let s = search.clone();
            Box::pin(async move {
                sqlx::query(sqlx::AssertSqlSafe(s)).execute(c).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pg).await.unwrap();
    let config = Config {
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
    };
    (
        trisixt::state::AppState {
            config: Arc::new(config),
            pg,
        },
        admin,
        schema,
    )
}
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn domain_activation_isolated_branding_and_teardown_are_durable() {
    let (st, admin, schema) = state().await;
    let i =
        sqlx::query_scalar::<_, Uuid>("INSERT INTO instances(name)VALUES('Domains')RETURNING id")
            .fetch_one(&st.pg)
            .await
            .unwrap();
    let p=sqlx::query_scalar::<_,Uuid>("INSERT INTO projects(instance_id,environment,domain)VALUES($1,'production','native.example.test')RETURNING id").bind(i).fetch_one(&st.pg).await.unwrap();
    let primary=sqlx::query_scalar::<_,Uuid>("INSERT INTO custom_hostnames(project_id,hostname,purpose,source,mode,status)VALUES($1,'branded.example.com','primary','enterprise','manual','active')RETURNING id").bind(p).fetch_one(&st.pg).await.unwrap();
    let migration=sqlx::query_scalar::<_,Uuid>("INSERT INTO custom_hostnames(project_id,hostname,purpose,source,mode,status)VALUES($1,'old.example.com','migration','enterprise','manual','pending')RETURNING id").bind(p).fetch_one(&st.pg).await.unwrap();
    sqlx::query("INSERT INTO project_domains(project_id,active_custom_host)VALUES($1,'branded.example.com')").bind(p).execute(&st.pg).await.unwrap();
    assert_eq!(
        trisixt::domains::resolve_project(&st.pg, "branded.example.com")
            .await
            .unwrap(),
        Some(p)
    );
    assert_eq!(
        trisixt::domains::resolve_project(&st.pg, "old.example.com")
            .await
            .unwrap(),
        None
    );
    sqlx::query("UPDATE custom_hostnames SET status='active' WHERE id=$1")
        .bind(migration)
        .execute(&st.pg)
        .await
        .unwrap();
    assert_eq!(
        trisixt::domains::resolve_project(&st.pg, "old.example.com")
            .await
            .unwrap(),
        Some(p)
    );
    assert_eq!(
        trisixt::domains::display_host(&st.pg, p).await.unwrap(),
        "branded.example.com"
    );
    assert!(trisixt::domains::teardown(&st, primary).await.unwrap());
    assert_eq!(
        trisixt::domains::display_host(&st.pg, p).await.unwrap(),
        "native.example.test"
    );
    assert_eq!(
        trisixt::domains::resolve_project(&st.pg, "branded.example.com")
            .await
            .unwrap(),
        None
    );
    let source=sqlx::query_scalar::<_,Uuid>("INSERT INTO migration_sources(project_id,provider,old_host,provider_hosted,credentials_ciphertext)VALUES($1,'branch','old.example.com',false,'encrypted-test')RETURNING id").bind(p).fetch_one(&st.pg).await.unwrap();
    assert!(trisixt::domains::teardown(&st, migration).await.unwrap());
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM migration_sources WHERE id=$1)"
        )
        .bind(source)
        .fetch_one(&st.pg)
        .await
        .unwrap()
    );
    st.pg.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&admin)
        .await
        .unwrap();
}
#[test]
fn store_metadata_parsers_keep_app_identity_and_reject_arbitrary_artwork() {
    use trisixt::app_metadata::{artwork_url, parse_apple, parse_google};
    let apple=parse_apple(&json!({"results":[{"trackName":"Example App","trackId":123,"artworkUrl512":"https://is1-ssl.mzstatic.com/image/thumb/test.png"}]})).unwrap();
    assert_eq!(apple["store_url"], "https://apps.apple.com/app/id123");
    assert_eq!(apple["title"], "Example App");
    let html = r#"<html><head><meta property="og:image" content="https://play-lh.googleusercontent.com/test=w240-h480"></head><body><h1>Example <span>&amp; App</span></h1></body></html>"#;
    let google = parse_google(html, "com.example.app").unwrap();
    assert_eq!(google["title"], "Example & App");
    assert_eq!(
        google["store_url"],
        "https://play.google.com/store/apps/details?id=com.example.app"
    );
    for bad in [
        "http://is1.mzstatic.com/image",
        "https://mzstatic.com.evil.test/image",
        "https://127.0.0.1/image",
        "https://user:password@is1.mzstatic.com/image",
    ] {
        assert!(!artwork_url("ios", bad));
    }
    assert!(parse_google("<html>temporary error</html>", "com.example.app").is_err());
    assert_eq!(parse_apple(&json!({"results":[]})).unwrap()["found"], false);
}
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn store_metadata_refresh_keeps_stale_cache_on_provider_failure() {
    use trisixt::app_metadata::{self, StoreClient};
    let (st, admin, schema) = state().await;
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let recorded = seen.clone();
    let app = Router::new().fallback(any(move |uri: Uri| {
        let recorded = recorded.clone();
        async move {
            recorded.lock().await.push(uri.to_string());
            if uri.path() == "/apple" {
                (
                    StatusCode::OK,
                    [("content-type", "application/json")],
                    r#"{"results":[{"trackName":"Cached App","trackId":123}]}"#,
                )
            } else {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [("content-type", "text/html")],
                    "unavailable",
                )
            }
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = StoreClient::new(format!("{base}/apple"), format!("{base}/google")).unwrap();
    assert_eq!(
        app_metadata::get(&st, "ios", "com.example.app")
            .await
            .unwrap(),
        json!({})
    );
    assert_eq!(app_metadata::tick_with(&st, &client).await.unwrap(), 1);
    assert_eq!(
        app_metadata::get(&st, "ios", "com.example.app")
            .await
            .unwrap()["title"],
        "Cached App"
    );
    assert!(seen.lock().await[0].contains("bundleId=com.example.app"));
    sqlx::query("INSERT INTO app_store_metadata(platform,identifier,metadata,ready)VALUES('android','com.example.app','{\"title\":\"Stale App\"}',true)").execute(&st.pg).await.unwrap();
    assert_eq!(app_metadata::tick_with(&st, &client).await.unwrap(), 0);
    let row=sqlx::query_as::<_,(Value,i32,bool)>("SELECT metadata,attempts,available_at>now() FROM app_store_metadata WHERE platform='android'").fetch_one(&st.pg).await.unwrap();
    assert_eq!(row.0["title"], "Stale App");
    assert_eq!(row.1, 1);
    assert!(row.2);
    task.abort();
    st.pg.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&admin)
        .await
        .unwrap();
}
#[test]
fn apple_hardware_preserves_names_simulators_and_unknown_identifiers() {
    assert_eq!(trisixt::hardware::apple_name("iPhone17,3"), "iPhone 16");
    assert_eq!(trisixt::hardware::apple_name("iPad15,8"), "iPad (A16)");
    for raw in ["iPhone 16", "arm64", "SM-S928B", "iPhone99,99", ""] {
        assert_eq!(trisixt::hardware::apple_name(raw), raw);
    }
    assert!(
        trisixt::hardware::parse_android_csv(
            b"Retail Branding,Marketing Name,Device,Model\nSamsung,Galaxy,device,model\n"
        )
        .is_err()
    );
    assert!(trisixt::hardware::parse_android_csv(&[255, 254, 1]).is_err());
}
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn android_hardware_refresh_validates_then_atomically_preserves_last_good_table() {
    let (st, admin, schema) = state().await;
    let mut csv = String::from("Retail Branding,Marketing Name,Device,Model\n");
    for n in 0..40000 {
        csv.push_str(&format!("Maker,Phone {n},device,model-{}\n", n % 20000));
    }
    let mut utf16 = vec![255, 254];
    for word in csv.encode_utf16() {
        utf16.extend_from_slice(&word.to_le_bytes());
    }
    let parsed = trisixt::hardware::parse_android_csv(&utf16).unwrap();
    assert_eq!(parsed.len(), 20000);
    assert_eq!(parsed["model-0"], "Maker Phone 0");
    assert_eq!(
        trisixt::hardware::humanize(&st, "android", "model-0")
            .await
            .unwrap(),
        "model-0"
    );
    assert_eq!(
        trisixt::hardware::install_android(&st, csv.as_bytes())
            .await
            .unwrap(),
        20000
    );
    assert_eq!(
        trisixt::hardware::humanize(&st, "android", "model-0")
            .await
            .unwrap(),
        "Maker Phone 0"
    );
    assert!(
        trisixt::hardware::install_android(&st, b"bad truncated download")
            .await
            .is_err()
    );
    assert_eq!(
        trisixt::hardware::humanize(&st, "android", "model-0")
            .await
            .unwrap(),
        "Maker Phone 0"
    );
    st.pg.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&admin)
        .await
        .unwrap();
}
