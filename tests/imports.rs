use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    routing::any,
};
use serde_json::{Value, json};
use std::{collections::VecDeque, sync::Arc};
use tokio::sync::Mutex;
use trisixt::imports::{Lookup, ProviderClient, map_payload};
#[test]
fn branch_mapping_preserves_campaign_custom_data_and_safe_mobile_links() {
    let v=map_payload("branch",json!({"data":json!({"$ios_url":"myapp://product/123","$android_url":"javascript:alert(1)","$desktop_url":"https://shop.example/product","$og_title":"Product","~campaign":"spring","~channel":"social","~feature":"share","~stage":"new","~tags":["promo"],"sku":"123"}).to_string()})).unwrap();
    assert_eq!(v["ios_url"], "myapp://product/123");
    assert!(v["android_url"].is_null());
    assert_eq!(v["tracking_campaign"], "spring");
    assert_eq!(v["custom_data"], json!({"sku":"123"}));
    assert_eq!(v["tags"], json!(["promo"]));
}
#[test]
fn appsflyer_mapping_handles_fallback_and_unsafe_urls() {
    let v=map_payload("appsflyer",json!({"af_dp":"shop://product/1","af_web_dp":"data:text/html,bad","af_og_title":"Product","c":"spring","pid":"newsletter","extra":"preserved"})).unwrap();
    assert_eq!(v["ios_url"], "shop://product/1");
    assert_eq!(v["android_url"], "shop://product/1");
    assert!(v["desktop_url"].is_null());
    assert_eq!(v["tracking_source"], "newsletter");
    assert_eq!(v["custom_data"]["extra"], "preserved");
}
#[derive(Clone)]
struct Mock {
    responses: Arc<Mutex<VecDeque<(StatusCode, Value)>>>,
    seen: Arc<Mutex<Vec<(String, HeaderMap)>>>,
}
async fn handle(
    State(m): State<Mock>,
    uri: Uri,
    h: HeaderMap,
) -> (StatusCode, [(String, String); 1], Json<Value>) {
    m.seen.lock().await.push((uri.to_string(), h));
    let (s, v) = m.responses.lock().await.pop_front().unwrap();
    (s, [("retry-after".into(), "37".into())], Json(v))
}
#[tokio::test]
async fn branch_and_appsflyer_requests_distinguish_not_found_and_retryable_errors() {
    let m = Mock {
        responses: Arc::new(Mutex::new(VecDeque::from([
            (
                StatusCode::OK,
                json!({"data":{"$desktop_url":"https://shop.example/"}}),
            ),
            (StatusCode::NOT_FOUND, json!({})),
            (StatusCode::TOO_MANY_REQUESTS, json!({})),
            (StatusCode::UNAUTHORIZED, json!({})),
            (StatusCode::OK, json!({"af_dp":"shop://product"})),
        ]))),
        seen: Arc::new(Mutex::new(Vec::new())),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().fallback(any(handle)).with_state(m.clone());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let c = ProviderClient::new(format!("{base}/branch"), format!("{base}/shortlinks")).unwrap();
    let creds = json!({"branch_key":"branch-test","onelink_id":"app-id","api_token":"af-test"});
    assert!(matches!(
        c.fetch(
            "branch",
            "old.example.com",
            "old/path",
            "campaign=a&source=b",
            &creds
        )
        .await,
        Lookup::Found(_)
    ));
    assert_eq!(
        c.fetch("branch", "old.example.com", "missing", "", &creds)
            .await,
        Lookup::NotFound
    );
    assert_eq!(
        c.fetch("branch", "old.example.com", "busy", "", &creds)
            .await,
        Lookup::Transient {
            status: 429,
            retry_after: Some(37)
        }
    );
    assert!(matches!(
        c.fetch("appsflyer", "old.example.com", "prefix/code", "", &creds)
            .await,
        Lookup::Transient { status: 401, .. }
    ));
    assert!(matches!(
        c.fetch("appsflyer", "old.example.com", "prefix/code", "", &creds)
            .await,
        Lookup::Found(_)
    ));
    let seen = m.seen.lock().await;
    let parsed = url::Url::parse(&format!("{base}{}", seen[0].0)).unwrap();
    let query = parsed
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(
        query["url"],
        "https://old.example.com/old/path?campaign=a&source=b"
    );
    assert_eq!(query["branch_key"], "branch-test");
    assert_eq!(seen[3].0, "/shortlinks/app-id/code");
    assert_eq!(seen[3].1["authorization"], "Bearer af-test");
    task.abort();
}

use uuid::Uuid;
async fn state() -> (trisixt::state::AppState, sqlx::PgPool, String) {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    use std::sync::Arc;
    use trisixt::config::{AnalyticsBackend, Config, StorageBackend};
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL required");
    let admin = sqlx::PgPool::connect(&url).await.unwrap();
    let schema = format!("test_imports_{}", Uuid::new_v4().simple());
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
async fn cached_imports_stay_project_scoped_and_archived_links_drain_to_defaults() {
    let (st, admin, schema) = state().await;
    let i =
        sqlx::query_scalar::<_, Uuid>("INSERT INTO instances(name)VALUES('Imports')RETURNING id")
            .fetch_one(&st.pg)
            .await
            .unwrap();
    let p=sqlx::query_scalar::<_,Uuid>("INSERT INTO projects(instance_id,environment,domain)VALUES($1,'production','native.example.test')RETURNING id").bind(i).fetch_one(&st.pg).await.unwrap();
    let p2=sqlx::query_scalar::<_,Uuid>("INSERT INTO projects(instance_id,environment,domain)VALUES($1,'test','test.example.test')RETURNING id").bind(i).fetch_one(&st.pg).await.unwrap();
    let source=sqlx::query_scalar::<_,Uuid>("INSERT INTO migration_sources(project_id,provider,old_host,provider_hosted,credentials_ciphertext,enabled)VALUES($1,'branch','old.example.com',true,'no-decrypt-cache',false)RETURNING id").bind(p).fetch_one(&st.pg).await.unwrap();
    sqlx::query("INSERT INTO migration_hosts(hostname,source_id)VALUES('old.example.com',$1)")
        .bind(source)
        .execute(&st.pg)
        .await
        .unwrap();
    let link=sqlx::query_scalar::<_,Uuid>("INSERT INTO links(project_id,name,path,target_url)VALUES($1,'Imported','native','https://shop.example.com')RETURNING id").bind(p).fetch_one(&st.pg).await.unwrap();
    sqlx::query("INSERT INTO migrated_links(source_id,old_path,status,link_id)VALUES($1,'legacy','resolved',$2)").bind(source).bind(link).execute(&st.pg).await.unwrap();
    assert!(matches!(
        trisixt::imports::resolve(&st, p, "old.example.com", "legacy", "")
            .await
            .unwrap(),
        Some(trisixt::imports::ImportOutcome::Link(_))
    ));
    assert!(
        trisixt::imports::resolve(&st, p2, "old.example.com", "legacy", "")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        trisixt::imports::resolve(&st, p, "old.example.com", "uncached", "")
            .await
            .unwrap()
            .is_none()
    );
    sqlx::query("UPDATE links SET archived_at=now()WHERE id=$1")
        .bind(link)
        .execute(&st.pg)
        .await
        .unwrap();
    assert!(matches!(
        trisixt::imports::resolve(&st, p, "old.example.com", "legacy", "")
            .await
            .unwrap(),
        Some(trisixt::imports::ImportOutcome::Defaults)
    ));
    sqlx::query("UPDATE migration_sources SET auto_disabled_at=now()WHERE id=$1")
        .bind(source)
        .execute(&st.pg)
        .await
        .unwrap();
    assert!(matches!(
        trisixt::imports::resolve(&st, p, "old.example.com", "uncached", "")
            .await
            .unwrap(),
        Some(trisixt::imports::ImportOutcome::Defaults)
    ));
    st.pg.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&admin)
        .await
        .unwrap();
}
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn firebase_server_sdk_public_preview_and_clipboard_roundtrip() {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    use trisixt::auth::{AuthUser, InternalPrincipal};
    let (st, admin, schema) = state().await;
    let user = AuthUser {
        id: Uuid::new_v4(),
        email: "connectivity@example.test".into(),
    };
    sqlx::query("INSERT INTO users(id,email)VALUES($1,$2)")
        .bind(user.id)
        .bind(&user.email)
        .execute(&st.pg)
        .await
        .unwrap();
    let i = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO instances(name)VALUES('Connectivity')RETURNING id",
    )
    .fetch_one(&st.pg)
    .await
    .unwrap();
    sqlx::query("INSERT INTO instance_roles(user_id,instance_id,role)VALUES($1,$2,'owner')")
        .bind(user.id)
        .bind(i)
        .execute(&st.pg)
        .await
        .unwrap();
    let p=sqlx::query_scalar::<_,Uuid>("INSERT INTO projects(instance_id,environment,domain)VALUES($1,'production','native.example.test')RETURNING id").bind(i).fetch_one(&st.pg).await.unwrap();
    let p2=sqlx::query_scalar::<_,Uuid>("INSERT INTO projects(instance_id,environment,domain)VALUES($1,'test','test.example.test')RETURNING id").bind(i).fetch_one(&st.pg).await.unwrap();
    let app = trisixt::routes::router(st.clone());
    let csv = "name,short_link,link,utm_source\nImported,https://old.example/a,https://shop.example/product,newsletter\nDuplicate,https://old.example/a,https://shop.example/other,newsletter\n";
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/projects/{p}/migrations/firebase"))
        .header("content-type", "application/json")
        .extension(InternalPrincipal(user.clone()))
        .body(Body::from(
            json!({"csv":csv,"short_link_prefix":"https://old.example/"}).to_string(),
        ))
        .unwrap();
    let r = app.clone().oneshot(req).await.unwrap();
    let status = r.status();
    let b = axum::body::to_bytes(r.into_body(), 100000).await.unwrap();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
    let v: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["links"].as_array().unwrap().len(), 1);
    let configured=app.clone().oneshot(Request::builder().method("PUT").uri(format!("/api/v1/projects/{p}/configurations/redirect")).extension(InternalPrincipal(user.clone())).header("content-type","application/json").body(Body::from(json!({"show_preview_ios":true,"copy_to_clipboard_ios":true,"uri_scheme":"shop","ios_phone":{"fallback":"https://shop.example/fallback","enabled":true}}).to_string())).unwrap()).await.unwrap();
    assert_eq!(configured.status(), StatusCode::OK);
    for (tracking_id, status) in [
        (json!("G-TRISIXT123"), StatusCode::OK),
        (
            json!("G-\"><script>alert(1)</script>"),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/v1/projects/{p}/domain/google_tracking_id"))
                    .extension(InternalPrincipal(user.clone()))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"google_tracking_id":tracking_id}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status);
    }
    let visitor = Uuid::new_v4();
    let foreign = Uuid::new_v4();
    sqlx::query("INSERT INTO visitors(project_id,id)VALUES($1,$2),($3,$4)")
        .bind(p)
        .bind(visitor)
        .bind(p2)
        .bind(foreign)
        .execute(&st.pg)
        .await
        .unwrap();
    assert!(
        trisixt::automation::build_link(
            &st,
            p,
            json!({"visitor_id":foreign,"target_url":"https://shop.example/"})
        )
        .await
        .is_err()
    );
    let created=trisixt::automation::build_link(&st,p,json!({"path":"preview","title":"<script>alert(1)</script>","subtitle":"An escaped preview","target_url":"https://shop.example/fallback","ios_url":"shop://product/1","show_preview_ios":true,"copy_to_clipboard_ios":true,"visitor_id":visitor,"data":{"sku":"123"},"tracking_source":"email"})).await.unwrap();
    assert_eq!(created["data"]["metadata"]["data"]["sku"], "123");
    let req = Request::builder()
        .uri("/preview?campaign=summer")
        .header("host", "native.example.test")
        .header("user-agent", "iPhone Mobile Safari")
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("set-cookie"));
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();

    assert!(
        response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("nonce-")
    );
    let html = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 1000000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(html.contains("gtag/js?id=G-TRISIXT123"));
    assert!(html.contains("send_page_view:false"));
    let ct = html
        .split("?ct=")
        .nth(1)
        .unwrap()
        .chars()
        .take(64)
        .collect::<String>();
    assert_eq!(ct.len(), 64);
    let captured=app.clone().oneshot(Request::builder().method("POST").uri("/").header("host","native.example.test").header("cookie",&cookie).header("content-type","application/json").body(Body::from(json!({"screen_width":390,"screen_height":844,"timezone":"Asia/Jakarta","webgl_vendor":"WebKit","webgl_renderer":"test-gpu","language":"en"}).to_string())).unwrap()).await.unwrap();
    assert_eq!(captured.status(), StatusCode::NO_CONTENT);
    let width=sqlx::query_scalar::<_,i32>("SELECT d.screen_width FROM link_clicks c JOIN devices d ON d.id=c.device_id AND d.project_id=c.project_id WHERE c.project_id=$1").bind(p).fetch_one(&st.pg).await.unwrap();
    assert_eq!(width, 390);
    let denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/")
                .header("host", "test.example.test")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    let (key, hash) = trisixt::auth::new_token();
    sqlx::query("INSERT INTO project_api_keys(project_id,token_hash,name)VALUES($1,$2,'test')")
        .bind(p)
        .bind(hash)
        .execute(&st.pg)
        .await
        .unwrap();
    let receiver = Uuid::new_v4();
    sqlx::query("INSERT INTO visitors(project_id,id)VALUES($1,$2)")
        .bind(p)
        .bind(receiver)
        .execute(&st.pg)
        .await
        .unwrap();
    let replay_receiver = Uuid::new_v4();
    sqlx::query("INSERT INTO visitors(project_id,id)VALUES($1,$2)")
        .bind(p)
        .bind(replay_receiver)
        .execute(&st.pg)
        .await
        .unwrap();
    for (current, expected) in [
        (receiver, Some("preview")),
        (receiver, None),
        (replay_receiver, None),
    ] {
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/sdk/data_for_device")
            .header("x-project-key", &key)
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"visitor_id":current,"clipboard_token":ct}).to_string(),
            ))
            .unwrap();
        let r = app.clone().oneshot(req).await.unwrap();
        let status = r.status();
        let b = axum::body::to_bytes(r.into_body(), 100000).await.unwrap();
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let result: Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(result["link"].as_str(), expected);
    }
    let (server, hash) = trisixt::auth::new_token();
    sqlx::query("INSERT INTO instance_api_keys(instance_id,token_hash)VALUES($1,$2)")
        .bind(i)
        .bind(hash)
        .execute(&st.pg)
        .await
        .unwrap();
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/sdk/metrics_for_link/preview")
                .header("project-key", &server)
                .header("environment", "production")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = r.status();
    let b = axum::body::to_bytes(r.into_body(), 100000).await.unwrap();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
    let metrics: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(metrics["metrics"]["views"], 1);
    assert_eq!(metrics["metrics"]["opens"], 1);
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/create")
                .header("host", "go.example.test")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"desktop":"javascript:alert(1)"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    st.pg.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&admin)
        .await
        .unwrap();
}

#[test]
fn store_tracking_preserves_provider_install_attribution() {
    let meta =
        json!({"tracking_campaign":"summer","tracking_source":"source","tracking_medium":"email"});
    let canonical = "https://native.example/a";
    let apple = trisixt::public_links::store_tracking_url(
        "https://apps.apple.com/app/id123",
        "ios",
        &meta,
        canonical,
    )
    .unwrap();
    let a = url::Url::parse(&apple)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(a["ct"], "summer");
    assert_eq!(a["at"], "source");
    assert_eq!(a["pt"], "email");
    let play = trisixt::public_links::store_tracking_url(
        "https://play.google.com/store/apps/details?id=app.example",
        "android",
        &meta,
        canonical,
    )
    .unwrap();
    let p = url::Url::parse(&play)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(p["referrer"], canonical);
    assert_eq!(p["utm_campaign"], "summer");
    assert_eq!(p["id"], "app.example");
    assert!(
        trisixt::public_links::store_tracking_url("javascript:alert(1)", "ios", &meta, canonical)
            .is_err()
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn public_installed_selection_store_buttons_and_frozen_automation_metrics() {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    use uuid::Uuid;
    let (st, admin, schema) = state().await;
    let user = trisixt::auth::AuthUser {
        id: Uuid::new_v4(),
        email: "public@example.test".into(),
    };
    sqlx::query("INSERT INTO users(id,email)VALUES($1,$2)")
        .bind(user.id)
        .bind(&user.email)
        .execute(&st.pg)
        .await
        .unwrap();
    let provision = trisixt::provisioning::provision(&st, &user, "Public")
        .await
        .unwrap();
    let project: Uuid = provision["instance"]["projects"][0]["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let owner = Uuid::new_v4();
    sqlx::query("INSERT INTO visitors(project_id,id)VALUES($1,$2)")
        .bind(project)
        .bind(owner)
        .execute(&st.pg)
        .await
        .unwrap();
    sqlx::query("UPDATE project_configurations SET ios=$2,android=$3 WHERE project_id=$1")
        .bind(project)
        .bind(json!({"app_store_url":"https://apps.apple.com/app/id123"}))
        .bind(json!({"store_url":"https://play.google.com/store/apps/details?id=app.example"}))
        .execute(&st.pg)
        .await
        .unwrap();
    trisixt::automation::build_link(&st,project,json!({"path":"store","target_url":"https://web.example/fallback","visitor_id":owner,"tracking_campaign":"summer"})).await.unwrap();
    let link =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM links WHERE project_id=$1 AND path='store'")
            .bind(project)
            .fetch_one(&st.pg)
            .await
            .unwrap();
    let app = trisixt::routes::router(st.clone());
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/r/{project}/store"))
                .header("user-agent", "iPhone")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::TEMPORARY_REDIRECT);
    assert!(
        r.headers()["location"]
            .to_str()
            .unwrap()
            .contains("apps.apple.com/app/id123")
    );
    assert!(
        r.headers()["location"]
            .to_str()
            .unwrap()
            .contains("ct=summer")
    );
    let cookie = r.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let visitor=sqlx::query_scalar::<_,Uuid>("SELECT visitor_id FROM browser_sessions WHERE project_id=$1 ORDER BY expires_at DESC LIMIT 1").bind(project).fetch_one(&st.pg).await.unwrap();
    for kind in [
        "install",
        "reinstall",
        "reactivation",
        "app_open",
        "user_referred",
        "time_spent",
    ] {
        sqlx::query("INSERT INTO events(event_id,project_id,visitor_id,event_type,occurred_at,properties)VALUES($1,$2,$3,$4,now(),$5)").bind(Uuid::new_v4()).bind(project).bind(visitor).bind(kind).bind(json!({"platform":"ios","engagement_time":1500,"_attribution":{"link_id":link,"link_visitor_id":owner,"sdk_generated":true}})).execute(&st.pg).await.unwrap();
    }
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/r/{project}/store"))
                .header("user-agent", "iPhone")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let html = String::from_utf8(
        axum::body::to_bytes(r.into_body(), 1_000_000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains(&format!(
        "{}://store",
        provision["instance"]["uri_scheme"].as_str().unwrap()
    )));
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/r/{project}/store"))
                .header("user-agent", "Desktop")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let html = String::from_utf8(
        axum::body::to_bytes(r.into_body(), 1_000_000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains(">App Store</a>"));
    assert!(html.contains(">Google Play</a>"));
    assert!(html.contains("<svg"));
    let r=app.clone().oneshot(Request::builder().method("PUT").uri(format!("/api/v1/projects/{project}/configurations/redirect")).extension(trisixt::auth::InternalPrincipal(user.clone())).header("content-type","application/json").body(Body::from(json!({"ios_phone":{"enabled":true,"appstore":false,"fallback_url":"https://web.example/disabled-store"}}).to_string())).unwrap()).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/r/{project}/store"))
                .header("user-agent", "iPhone")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::TEMPORARY_REDIRECT);
    assert!(
        r.headers()["location"]
            .to_str()
            .unwrap()
            .starts_with("https://web.example/disabled-store")
    );
    let purchase=sqlx::query_scalar::<_,Uuid>("INSERT INTO verified_purchases(project_id,visitor_id,provider,application_id,environment,transaction_id,original_transaction_id,product_id,purchase_kind,currency,amount_nanos,quantity,purchased_at,link_id)VALUES($1,$2,'apple','app.example','production','tx','tx','product','one_time','USD',2000000000,1,now(),$3)RETURNING id").bind(project).bind(visitor).bind(link).fetch_one(&st.pg).await.unwrap();
    for (kind, amount) in [("BUY", 2000000000_i64), ("REFUND", -500000000)] {
        sqlx::query("INSERT INTO purchase_ledger(purchase_id,project_id,visitor_id,link_id,event_type,source_key,amount_nanos,quantity,currency,usd_nanos,occurred_at)VALUES($1,$2,$3,$4,$5,$5,$6,1,'USD',$6,now())").bind(purchase).bind(project).bind(visitor).bind(link).bind(kind).bind(amount).execute(&st.pg).await.unwrap();
    }
    sqlx::query("DELETE FROM links WHERE project_id=$1 AND id=$2")
        .bind(project)
        .bind(link)
        .execute(&st.pg)
        .await
        .unwrap();
    let metrics = trisixt::automation::metrics(&st, project, Some(link), Some(owner), true)
        .await
        .unwrap();
    assert_eq!(metrics["installs"], 1);
    assert_eq!(metrics["reinstalls"], 1);
    assert_eq!(metrics["reactivations"], 1);
    assert_eq!(metrics["app_opens"], 1);
    assert_eq!(metrics["user_referred"], 1);
    assert_eq!(metrics["time_spent"].as_f64(), Some(1500.));
    assert_eq!(metrics["total_revenue"], 150);
    assert_eq!(
        trisixt::automation::metrics(&st, project, Some(link), Some(Uuid::new_v4()), true)
            .await
            .unwrap()["revenue"],
        0
    );
    st.pg.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&admin)
        .await
        .unwrap();
}
