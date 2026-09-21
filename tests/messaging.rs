use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    routing::post,
};
use serde_json::{Value, json};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use std::sync::Arc;
use tower::ServiceExt;
use trisixt::{
    config::{AnalyticsBackend, Config, StorageBackend},
    messaging::{self, PushMessage, PushOutcome},
    state::AppState,
};
use uuid::Uuid;
struct Fixture {
    app: Router,
    st: AppState,
    admin: PgPool,
    schema: String,
    owner: String,
    project: Uuid,
    key: String,
}
impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL required");
        let admin = PgPool::connect(&url).await.unwrap();
        let schema = format!("test_messaging_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        let path = format!("SET search_path TO {schema},public");
        let pg = PgPoolOptions::new()
            .max_connections(5)
            .after_connect(move |c, _| {
                let q = path.clone();
                Box::pin(async move {
                    sqlx::query(sqlx::AssertSqlSafe(q)).execute(c).await?;
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
        let st = AppState {
            pg,
            config: Arc::new(config),
        };
        let user: Uuid = sqlx::query_scalar(
            "INSERT INTO users(email) VALUES('owner@example.test') RETURNING id",
        )
        .fetch_one(&st.pg)
        .await
        .unwrap();
        let instance: Uuid =
            sqlx::query_scalar("INSERT INTO instances(name) VALUES('Messaging') RETURNING id")
                .fetch_one(&st.pg)
                .await
                .unwrap();
        sqlx::query("INSERT INTO instance_roles(instance_id,user_id,role) VALUES($1,$2,'owner')")
            .bind(instance)
            .bind(user)
            .execute(&st.pg)
            .await
            .unwrap();
        let project=sqlx::query_scalar("INSERT INTO projects(instance_id,domain,environment) VALUES($1,'messages.example.test','production') RETURNING id").bind(instance).fetch_one(&st.pg).await.unwrap();
        let owner = trisixt::accounts::issue_session(&st, user).await.unwrap()["token"]
            .as_str()
            .unwrap()
            .to_string();
        let (key, hash) = trisixt::auth::new_token();
        sqlx::query("INSERT INTO project_api_keys(project_id,name,token_hash) VALUES($1,'SDK',$2)")
            .bind(project)
            .bind(hash)
            .execute(&st.pg)
            .await
            .unwrap();
        let app = trisixt::routes::router(st.clone());
        Self {
            app,
            st,
            admin,
            schema,
            owner,
            project,
            key,
        }
    }
    async fn req(
        &self,
        method: &str,
        path: &str,
        dashboard: bool,
        body: Value,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .header("host", "messages.example.test");
        if dashboard {
            builder = builder.header("authorization", format!("Bearer {}", self.owner))
        } else {
            builder = builder.header("x-project-key", &self.key)
        }
        let response = self
            .app
            .clone()
            .oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&body)
                .unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&body)})),
        )
    }
    async fn visitor(&self, platform: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO visitors(project_id,id) VALUES($1,$2)")
            .bind(self.project)
            .bind(id)
            .execute(&self.st.pg)
            .await
            .unwrap();
        sqlx::query("INSERT INTO devices(project_id,visitor_id,platform,push_token) VALUES($1,$2,$3,'deadbeef')").bind(self.project).bind(id).bind(platform).execute(&self.st.pg).await.unwrap();
        id
    }
    async fn notification(&self, body: Value) -> Uuid {
        let (status, result) = self
            .req(
                "POST",
                &format!("/api/v1/projects/{}/notifications", self.project),
                true,
                body,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        Uuid::parse_str(result["notification"]["id"].as_str().unwrap()).unwrap()
    }
    async fn finish(self) {
        self.st.pg.close().await;
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
#[ignore = "requires PostgreSQL"]
async fn messaging_targets_schedule_scope_reads_archive_and_retry() {
    let f = Fixture::new().await;
    let old = f.visitor("ios").await;
    let new_notification=f.notification(json!({"title":"Welcome","subtitle":"For new iOS visitors","html":"<h1>hello</h1><script>bad()</script>","new_users":true,"existing_users":false,"platforms":["ios"],"auto_display":true,"send_push":true})).await;
    let new = f.visitor("ios").await;
    let android = f.visitor("android").await;
    assert_eq!(messaging::fanout_once(&f.st).await.unwrap(), 1);
    assert_eq!(messaging::fanout_once(&f.st).await.unwrap(), 0);
    for (visitor, count) in [(old, 0), (new, 1), (android, 0)] {
        let (status, result) = f
            .req(
                "GET",
                &format!("/api/v1/sdk/number_of_unread_notifications?visitor_id={visitor}"),
                false,
                json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(result["number_of_unread_notifications"], count);
    }
    let (status, list) = f
        .req(
            "GET",
            &format!("/api/v1/sdk/notifications_to_display_automatically?visitor_id={new}"),
            false,
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let message = list["notifications"][0]["id"].as_str().unwrap();
    assert_eq!(
        f.req(
            "POST",
            "/api/v1/sdk/mark_notification_as_read",
            false,
            json!({"visitor_id":old,"id":message})
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        f.req(
            "POST",
            "/api/v1/sdk/mark_notification_as_read",
            false,
            json!({"visitor_id":new,"id":message})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(
        f.req(
            "GET",
            &format!("/api/v1/sdk/notifications_to_display_automatically?visitor_id={new}"),
            false,
            json!({})
        )
        .await
        .1["notifications"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let (status, html) = f
        .req("GET", &format!("/mm/{new_notification}"), false, json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{html}");
    assert!(html["raw"].as_str().unwrap().contains("<h1>hello</h1>"));
    assert!(!html["raw"].as_str().unwrap().contains("script"));
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/mm/{new_notification}"))
                .header("host", "another.example.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    // No configured provider is a durable failure; the worker must not mark the message delivered.
    assert!(messaging::dispatch_once(&f.st).await.is_err());
    let row = sqlx::query("SELECT attempts,sent_at,available_at>now() AS delayed FROM push_outbox")
        .fetch_one(&f.st.pg)
        .await
        .unwrap();
    assert_eq!(row.get::<i32, _>("attempts"), 1);
    assert!(
        row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("sent_at")
            .is_none()
    );
    assert!(row.get::<bool, _>("delayed"));
    let existing = f
        .notification(
            json!({"title":"Existing","new_users":false,"existing_users":true,"platforms":[]}),
        )
        .await;
    let future=f.notification(json!({"title":"Future","new_users":false,"existing_users":true,"platforms":[],"scheduled_at":chrono::Utc::now()+chrono::Duration::hours(1)})).await;
    assert_eq!(messaging::fanout_once(&f.st).await.unwrap(), 3);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM notification_messages WHERE notification_id=$1"
        )
        .bind(future)
        .fetch_one(&f.st.pg)
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        f.req(
            "DELETE",
            &format!("/api/v1/projects/{}/notifications/{existing}", f.project),
            true,
            json!({})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        f.req(
            "DELETE",
            &format!(
                "/api/v1/projects/{}/notifications/{new_notification}",
                f.project
            ),
            true,
            json!({})
        )
        .await
        .0,
        StatusCode::OK
    );
    let foreign = Uuid::new_v4();
    assert_eq!(
        f.req(
            "GET",
            &format!("/api/v1/sdk/notifications?visitor_id={foreign}"),
            false,
            json!({})
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        f.req(
            "POST",
            &format!("/api/v1/projects/{foreign}/notifications"),
            true,
            json!({"title":"bad","new_users":true,"existing_users":false})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    f.finish().await;
}

#[derive(Clone)]
struct Mock {
    received: Arc<tokio::sync::Mutex<Vec<(HeaderMap, Value)>>>,
    status: StatusCode,
    body: Value,
}
async fn receive(
    State(state): State<Mock>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    state.received.lock().await.push((headers, body));
    (state.status, Json(state.body))
}
async fn mock(status: StatusCode, body: Value) -> (String, Mock, tokio::task::JoinHandle<()>) {
    let state = Mock {
        received: Arc::new(tokio::sync::Mutex::new(vec![])),
        status,
        body,
    };
    let app = Router::new()
        .route("/{*path}", post(receive))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/push", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, state, task)
}
#[tokio::test]
async fn fcm_and_apns_send_authenticated_payloads_and_classify_token_errors() {
    let message = PushMessage {
        id: Uuid::new_v4(),
        device_token: "abcd".into(),
        title: "Hello".into(),
        subtitle: "World".into(),
        test_environment: true,
    };
    let client = reqwest::Client::new();
    let (url, mock, task) = mock(StatusCode::OK, json!({"name":"messages/one"})).await;
    assert_eq!(
        messaging::send_push_http(&client, &url, "oauth-token", None, &message)
            .await
            .unwrap(),
        PushOutcome::Delivered
    );
    let received = mock.received.lock().await;
    assert_eq!(received[0].0["authorization"], "Bearer oauth-token");
    assert_eq!(received[0].1["message"]["token"], "abcd");
    assert_eq!(received[0].1["message"]["notification"]["title"], "Hello");
    assert_eq!(
        received[0].1["message"]["data"]["notification_id"],
        message.id.to_string()
    );
    drop(received);
    task.abort();
    let (url, state, task) = self::mock(StatusCode::GONE, json!({"reason":"Unregistered"})).await;
    assert_eq!(
        messaging::send_push_http(
            &client,
            &url,
            "signed-apns-jwt",
            Some("app.example"),
            &message
        )
        .await
        .unwrap(),
        PushOutcome::InvalidToken
    );
    let received = state.received.lock().await;
    assert_eq!(received[0].0["authorization"], "Bearer signed-apns-jwt");
    assert_eq!(received[0].0["apns-topic"], "app.example");
    assert_eq!(received[0].0["apns-push-type"], "alert");
    assert_eq!(received[0].1["aps"]["alert"]["subtitle"], "World");
    drop(received);
    task.abort();
    let (url, _, task) = self::mock(
        StatusCode::NOT_FOUND,
        json!({"error":{"details":[{"errorCode":"UNREGISTERED"}]}}),
    )
    .await;
    assert_eq!(
        messaging::send_push_http(&client, &url, "token", None, &message)
            .await
            .unwrap(),
        PushOutcome::InvalidToken
    );
    task.abort();
    let (url, _, task) = self::mock(
        StatusCode::TOO_MANY_REQUESTS,
        json!({"error":{"message":"retry"}}),
    )
    .await;
    assert!(
        messaging::send_push_http(&client, &url, "token", None, &message)
            .await
            .is_err()
    );
    task.abort();
}
