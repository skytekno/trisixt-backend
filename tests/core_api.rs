//! Run explicitly with TEST_DATABASE_URL=... cargo test --test core_api -- --ignored.
//! Missing infrastructure is a failure when this suite is requested, never a pass.
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;
use tower::ServiceExt;
use trisixt::{
    config::{AnalyticsBackend, Config, StorageBackend},
    state::AppState,
};
use uuid::Uuid;

// Fixture signup/login is setup, not an authentication load test. Serialize it
// across test cases while preserving concurrency inside event/ledger tests.
static SIGNUP_SETUP: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Fixture {
    app: Router,
    pool: PgPool,
    admin: PgPool,
    schema: String,
}
impl Fixture {
    async fn new() -> Self {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .with_test_writer()
            .try_init();
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for PostgreSQL integration tests");
        let admin = PgPool::connect(&url)
            .await
            .expect("connect integration database");
        let schema = format!("test_core_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        let search_path = format!("SET search_path TO {schema},public");
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .after_connect(move |conn, _| {
                let query = search_path.clone();
                Box::pin(async move {
                    sqlx::query(sqlx::AssertSqlSafe(query))
                        .execute(conn)
                        .await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let config = Config {
            env: "test".into(),
            host: "127.0.0.1".into(),
            port: 0,
            server_host: "example.test".into(),
            database_url: url,
            redis_url: "redis://127.0.0.1:56389".into(),
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
        let app = trisixt::routes::router(AppState {
            config: Arc::new(config),
            pg: pool.clone(),
        });
        Self {
            app,
            pool,
            admin,
            schema,
        }
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        auth: Option<&str>,
        key: Option<&str>,
        body: Value,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(token) = auth {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        if let Some(key) = key {
            request = request
                .header("x-project-key", key)
                .header("platform", "ios")
                .header("identifier", "com.example.app");
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap();
        let body = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body)
                .unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&body)}))
        };
        (status, body)
    }
    async fn user(&self, label: &str) -> (String, Uuid, String) {
        let _setup = SIGNUP_SETUP.lock().await;
        let email = format!("{label}@example.test");
        let credentials = json!({"email":email,"password":"correct horse battery staple"});
        let (status, user) = self
            .request("POST", "/auth/register", None, None, credentials.clone())
            .await;
        assert_eq!(status, StatusCode::CREATED, "{user}");
        let (status, session) = self
            .request("POST", "/auth/login", None, None, credentials)
            .await;
        assert_eq!(status, StatusCode::OK, "{session}");
        (
            session["token"].as_str().unwrap().into(),
            Uuid::parse_str(user["id"].as_str().unwrap()).unwrap(),
            email,
        )
    }
    async fn instance(&self, token: &str) -> Uuid {
        let (status, value) = self
            .request(
                "POST",
                "/api/v1/instances",
                Some(token),
                None,
                json!({"name":"Test tenant"}),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{value}");
        Uuid::parse_str(value["id"].as_str().unwrap()).unwrap()
    }
    async fn project(&self, token: &str, instance: Uuid) -> Uuid {
        let (status,value)=self.request("POST",&format!("/api/v1/instances/{instance}/projects"),Some(token),None,json!({"name":"Test project","environment":"production","domain":format!("{}.example.test",Uuid::new_v4().simple())})).await;
        assert_eq!(status, StatusCode::CREATED, "{value}");
        let project = Uuid::parse_str(value["id"].as_str().unwrap()).unwrap();
        sqlx::query("INSERT INTO project_configurations(project_id,ios) VALUES($1,$2)")
            .bind(project)
            .bind(json!({"enabled":true,"bundle_id":"com.example.app"}))
            .execute(&self.pool)
            .await
            .unwrap();
        project
    }
    async fn finish(self) {
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin)
        .await
        .unwrap();
        self.admin.close().await;
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL and PostgreSQL; included by scripts/integration.sh"]
async fn core_workflow_enforces_roles_deduplicates_and_revokes() {
    let f = Fixture::new().await;
    let (owner, owner_id, _) = f.user("owner").await;
    let (member, _, member_email) = f.user("member").await;
    let (other, _, _) = f.user("other").await;
    let tenant = f.instance(&owner).await;
    let project = f.project(&owner, tenant).await;
    let other_tenant = f.instance(&other).await;
    let other_project = f.project(&other, other_tenant).await;
    for path in [
        format!("/api/v1/instances/{tenant}"),
        format!("/api/v1/projects/{project}"),
        format!("/api/v1/projects/{project}/events"),
    ] {
        assert_eq!(
            f.request("GET", &path, Some(&other), None, Value::Null)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        f.request(
            "POST",
            &format!("/api/v1/instances/{tenant}/members"),
            Some(&owner),
            None,
            json!({"email":member_email,"role":"member"})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        f.request(
            "GET",
            &format!("/api/v1/projects/{project}"),
            Some(&member),
            None,
            Value::Null
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        f.request(
            "POST",
            &format!("/api/v1/projects/{project}/keys"),
            Some(&member),
            None,
            json!({"name":"forbidden"})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.request(
            "DELETE",
            &format!("/api/v1/instances/{tenant}/members/{owner_id}"),
            Some(&owner),
            None,
            Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (status, key) = f
        .request(
            "POST",
            &format!("/api/v1/projects/{project}/keys"),
            Some(&owner),
            None,
            json!({"name":"SDK key"}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{key}");
    let sdk_key = key["key"].as_str().unwrap();
    let stored: String =
        sqlx::query_scalar("SELECT token_hash FROM project_api_keys WHERE project_id=$1")
            .bind(project)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_ne!(sdk_key, stored);
    let (status, campaign) = f
        .request(
            "POST",
            &format!("/api/v1/projects/{project}/campaigns"),
            Some(&owner),
            None,
            json!({"name":"Launch"}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{campaign}");
    let input = json!({"name":"Launch link","path":"launch","target_url":"https://example.com/landing","ios_url":"https://example.com/ios","campaign_id":campaign["id"]});
    let (status, link) = f
        .request(
            "POST",
            &format!("/api/v1/projects/{project}/links"),
            Some(&owner),
            None,
            input.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{link}");
    assert_eq!(
        f.request(
            "POST",
            &format!("/api/v1/projects/{project}/links"),
            Some(&owner),
            None,
            input.clone()
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let mut alternate = input.clone();
    alternate["path"] = json!("alternate");
    let (status, alternate) = f
        .request(
            "POST",
            &format!("/api/v1/projects/{project}/links"),
            Some(&owner),
            None,
            alternate,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{alternate}");
    let alternate_path = format!(
        "/api/v1/projects/{project}/links/{}",
        alternate["id"].as_str().unwrap()
    );
    let (status, conflict) = f
        .request("PATCH", &alternate_path, Some(&owner), None, input.clone())
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
    assert!(!conflict.to_string().contains("links_project_id_path_key"));
    let (status, preserved) = f
        .request("GET", &alternate_path, Some(&owner), None, Value::Null)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(preserved["path"], "alternate");
    assert_eq!(
        f.request(
            "POST",
            &format!("/api/v1/projects/{other_project}/links"),
            Some(&other),
            None,
            input
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/r/{project}/launch"))
                .header("user-agent", "iPhone")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(response.headers()["location"], "https://example.com/ios");
    let visitor = Uuid::new_v4();
    let event_id = Uuid::new_v4();
    let event = json!({"event_id":event_id,"visitor_id":visitor,"event_type":"app.open","occurred_at":chrono::Utc::now(),"properties":{"version":"1.0"}});
    let batch = json!({"events":[event.clone(),event.clone()]});
    let (status, accepted) = f
        .request(
            "POST",
            "/api/v1/sdk/events",
            None,
            Some(sdk_key),
            batch.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{accepted}");
    assert_eq!(accepted, json!({"accepted":1,"duplicates":1}));
    assert_eq!(
        f.request("POST", "/api/v1/sdk/events", None, Some(sdk_key), batch)
            .await
            .1,
        json!({"accepted":0,"duplicates":2})
    );
    let events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM events WHERE project_id=$1 AND event_type='app.open'",
    )
    .bind(project)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(events, 1);
    let outbox: i64 =
        sqlx::query_scalar("SELECT count(*) FROM analytics_outbox WHERE project_id=$1 AND payload->>'event_type'='app.open'")
            .bind(project)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(outbox, 1);
    let payload: Value =
        sqlx::query_scalar("SELECT payload FROM analytics_outbox WHERE project_id=$1 AND payload->>'event_type'='app.open'")
            .bind(project)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(payload["event_id"], event_id.to_string());
    assert_eq!(payload["project_id"], project.to_string());
    // A later invalid event must reject the entire batch before anything persists.
    let mut valid = event.clone();
    valid["event_id"] = json!(Uuid::new_v4());
    let mut invalid = event;
    invalid["event_type"] = json!("has spaces");
    assert_eq!(
        f.request(
            "POST",
            "/api/v1/sdk/events",
            None,
            Some(sdk_key),
            json!({"events":[valid,invalid]})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM events WHERE project_id=$1 AND event_type='app.open'"
        )
        .bind(project)
        .fetch_one(&f.pool)
        .await
        .unwrap(),
        1
    );
    let (status, value) = f
        .request(
            "GET",
            &format!("/api/v1/projects/{other_project}/events"),
            Some(&other),
            None,
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["events"], json!([]));
    let path = format!(
        "/api/v1/projects/{project}/links/{}",
        link["id"].as_str().unwrap()
    );
    assert_eq!(
        f.request("DELETE", &path, Some(&owner), None, Value::Null)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.request(
            "GET",
            &format!("/r/{project}/launch"),
            None,
            None,
            Value::Null
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        f.request(
            "DELETE",
            &format!(
                "/api/v1/projects/{project}/keys/{}",
                key["id"].as_str().unwrap()
            ),
            Some(&owner),
            None,
            Value::Null
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.request(
            "POST",
            "/api/v1/sdk/visitors",
            None,
            Some(sdk_key),
            json!({"visitor_id":visitor})
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.request("POST", "/auth/logout", Some(&owner), None, Value::Null)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.request("GET", "/auth/me", Some(&owner), None, Value::Null)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL and PostgreSQL; included by scripts/integration.sh"]
async fn auth_expiry_rate_limits_and_database_constraints() {
    let f = Fixture::new().await;
    let (token, user, email) = f.user("security").await;
    assert_eq!(
        f.request(
            "POST",
            "/auth/register",
            None,
            None,
            json!({"email":email.to_ascii_uppercase(),"password":"correct horse battery staple"})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        f.request(
            "POST",
            "/auth/register",
            None,
            None,
            json!({"email":"invalid","password":"short"})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    sqlx::query("UPDATE access_tokens SET expires_at=now()-interval '1 second' WHERE user_id=$1")
        .bind(user)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        f.request("GET", "/auth/me", Some(&token), None, Value::Null)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let mut last = StatusCode::OK;
    for _ in 0..11 {
        last = f
            .request(
                "POST",
                "/auth/login",
                None,
                None,
                json!({"email":email,"password":"wrong password"}),
            )
            .await
            .0;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    // PostgreSQL itself rejects cross-project campaign references.
    let (owner, _, _) = f.user("constraint").await;
    let instance = f.instance(&owner).await;
    let project = f.project(&owner, instance).await;
    let (instance2, project2) = {
        let i = f.instance(&owner).await;
        (i, f.project(&owner, i).await)
    };
    assert_ne!(instance, instance2);
    let campaign: Uuid =
        sqlx::query_scalar("INSERT INTO campaigns(project_id,name) VALUES($1,'one') RETURNING id")
            .bind(project)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    let result=sqlx::query("INSERT INTO links(project_id,campaign_id,name,path,target_url) VALUES($1,$2,'bad','bad','https://example.com')").bind(project2).bind(campaign).execute(&f.pool).await;
    assert_eq!(
        result
            .unwrap_err()
            .as_database_error()
            .unwrap()
            .code()
            .as_deref(),
        Some("23503")
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL and PostgreSQL; included by scripts/integration.sh"]
async fn association_configs_and_concurrent_replays_are_scoped() {
    let f = Fixture::new().await;
    let (owner, _, _) = f.user("config-owner").await;
    let (other, _, _) = f.user("config-other").await;
    let instance = f.instance(&owner).await;
    let project = f.project(&owner, instance).await;
    let domain: String = sqlx::query_scalar("SELECT domain FROM projects WHERE id=$1")
        .bind(project)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    let path = format!("/api/v1/projects/{project}/configurations/ios");
    let config = json!({"enabled":true,"team_id":"ABCDEFGHIJ","bundle_id":"com.example.app","app_store_url":"https://apps.apple.com/app/example"});
    assert_eq!(
        f.request("PUT", &path, Some(&other), None, config.clone())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.request("PUT", &path, Some(&owner), None, config).await.0,
        StatusCode::OK
    );
    assert_eq!(
        f.request(
            "PUT",
            &path,
            Some(&owner),
            None,
            json!({"private_key":"must not be stored"})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/apple-app-site-association")
                .header("host", &domain)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 10000).await.unwrap()).unwrap();
    assert_eq!(
        payload["applinks"]["details"][0]["appIDs"][0],
        "ABCDEFGHIJ.com.example.app"
    );
    let fingerprint = std::iter::repeat_n("AB", 32).collect::<Vec<_>>().join(":");
    let path = format!("/api/v1/projects/{project}/configurations/android");
    assert_eq!(
        f.request(
            "PUT",
            &path,
            Some(&owner),
            None,
            json!({"package_name":"com.example.app","sha256_cert_fingerprints":[fingerprint]})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        f.request(
            "PUT",
            &path,
            Some(&owner),
            None,
            json!({"sha256_cert_fingerprints":["wrong"]})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/assetlinks.json")
                .header("host", &domain)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 10000).await.unwrap()).unwrap();
    assert_eq!(payload[0]["target"]["package_name"], "com.example.app");
    assert_eq!(
        f.request(
            "GET",
            "/.well-known/assetlinks.json",
            None,
            None,
            Value::Null
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let (_, key) = f
        .request(
            "POST",
            &format!("/api/v1/projects/{project}/keys"),
            Some(&owner),
            None,
            json!({"name":"SDK"}),
        )
        .await;
    let key = key["key"].as_str().unwrap();
    let id = Uuid::new_v4();
    let first = json!({"event_id":id,"visitor_id":Uuid::new_v4(),"event_type":"open","occurred_at":chrono::Utc::now()});
    let mut second = first.clone();
    second["visitor_id"] = json!(Uuid::new_v4());
    let (a, b) = tokio::join!(
        f.request("POST", "/api/v1/sdk/event", None, Some(key), first),
        f.request("POST", "/api/v1/sdk/event", None, Some(key), second)
    );
    assert_eq!(a.0, StatusCode::OK, "{}", a.1);
    assert_eq!(b.0, StatusCode::OK, "{}", b.1);
    assert_eq!(
        a.1["accepted"].as_i64().unwrap() + b.1["accepted"].as_i64().unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM visitors WHERE project_id=$1")
            .bind(project)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM analytics_outbox WHERE project_id=$1")
            .bind(project)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        1
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL and PostgreSQL; included by scripts/integration.sh"]
async fn overlapping_batches_lock_visitors_in_consistent_order() {
    let f = Fixture::new().await;
    let (owner, _, _) = f.user("lock-order").await;
    let instance = f.instance(&owner).await;
    let project = f.project(&owner, instance).await;
    let (_, key) = f
        .request(
            "POST",
            &format!("/api/v1/projects/{project}/keys"),
            Some(&owner),
            None,
            json!({"name":"SDK"}),
        )
        .await;
    let key = key["key"].as_str().unwrap();
    let visitor_x = Uuid::from_u128(100);
    let visitor_y = Uuid::from_u128(200);
    // Distinct event lock sets, reversed visitor order: the former implementation
    // acquired visitor X then Y in A, and Y then X in B and could deadlock.
    for round in 0..10_u128 {
        let event = |id: u128, visitor: Uuid| json!({"event_id":Uuid::from_u128(id),"visitor_id":visitor,"event_type":"lock.test","occurred_at":chrono::Utc::now()});
        let a = json!({"events":[event(1000+round*4,visitor_x),event(1001+round*4,visitor_y)]});
        let b = json!({"events":[event(1002+round*4,visitor_y),event(1003+round*4,visitor_x)]});
        let (a, b) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                f.request("POST", "/api/v1/sdk/events", None, Some(key), a),
                f.request("POST", "/api/v1/sdk/events", None, Some(key), b)
            )
        })
        .await
        .expect("concurrent batches deadlocked");
        assert_eq!(a.0, StatusCode::OK, "{}", a.1);
        assert_eq!(b.0, StatusCode::OK, "{}", b.1);
        assert_eq!(a.1["accepted"], 2);
        assert_eq!(b.1["accepted"], 2);
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM events WHERE project_id=$1")
            .bind(project)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        40
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL and PostgreSQL; included by scripts/integration.sh"]
async fn nil_sdk_ids_are_rejected_and_audit_and_fallback_settings_are_effective() {
    let f = Fixture::new().await;
    let (owner, owner_id, _) = f.user("validation").await;
    let instance = f.instance(&owner).await;
    let project = f.project(&owner, instance).await;
    let (_, key) = f
        .request(
            "POST",
            &format!("/api/v1/projects/{project}/keys"),
            Some(&owner),
            None,
            json!({"name":"SDK"}),
        )
        .await;
    let key = key["key"].as_str().unwrap();
    for (event_id, visitor_id) in [(Uuid::nil(), Uuid::new_v4()), (Uuid::new_v4(), Uuid::nil())] {
        let(status,body)=f.request("POST","/api/v1/sdk/event",None,Some(key),json!({"event_id":event_id,"visitor_id":visitor_id,"event_type":"open","occurred_at":chrono::Utc::now()})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
    assert_eq!(
        f.request(
            "POST",
            "/api/v1/sdk/visitors",
            None,
            Some(key),
            json!({"visitor_id":Uuid::nil()})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM analytics_outbox WHERE project_id=$1")
            .bind(project)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM visitors WHERE project_id=$1")
            .bind(project)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        0
    );
    let link = json!({"name":"Configured redirect","path":"fallback","target_url":"https://example.com/generic","ios_url":"https://example.com/link-ios"});
    assert_eq!(
        f.request(
            "POST",
            &format!("/api/v1/projects/{project}/links"),
            Some(&owner),
            None,
            link
        )
        .await
        .0,
        StatusCode::CREATED
    );
    assert_eq!(f.request("PUT",&format!("/api/v1/projects/{project}/configurations/redirect"),Some(&owner),None,json!({"ios_fallback":"https://example.com/project-ios","android_fallback":"https://example.com/project-android","default_fallback":"https://example.com/default"})).await.0,StatusCode::OK);
    for (ua, target) in [
        ("iPhone", "https://example.com/link-ios"),
        ("Android", "https://example.com/project-android"),
        ("Desktop", "https://example.com/default"),
    ] {
        let response = f
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/r/{project}/fallback"))
                    .header("user-agent", ua)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers()["location"], target);
    }
    assert_eq!(
        f.request(
            "PUT",
            &format!("/api/v1/projects/{project}/configurations/web"),
            Some(&owner),
            None,
            json!({"fallback_url":"https://example.com/web"})
        )
        .await
        .0,
        StatusCode::OK
    );
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/r/{project}/fallback"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()["location"], "https://example.com/web");
    let actors: Vec<Option<Uuid>> =
        sqlx::query_scalar("SELECT actor_id FROM audit_events WHERE instance_id=$1")
            .bind(instance)
            .fetch_all(&f.pool)
            .await
            .unwrap();
    assert!(actors.len() >= 4);
    assert!(
        actors.iter().all(|actor| *actor == Some(owner_id)),
        "{actors:?}"
    );
    f.finish().await;
}
