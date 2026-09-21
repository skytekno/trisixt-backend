#![allow(dead_code)]
pub mod baseline;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode},
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
pub struct Fixture {
    pub app: Router,
    pub state: AppState,
    pub pool: PgPool,
    admin: PgPool,
    schema: String,
    pub user: Uuid,
    pub instance: Uuid,
    pub project: Uuid,
    pub token: String,
    pub key: String,
}
impl Fixture {
    pub async fn new() -> Self {
        Self::with_ids(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()).await
    }

    /// Explicit identities let shared contracts replay within isolated schemas.
    pub async fn with_ids(user: Uuid, instance: Uuid, project: Uuid) -> Self {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .with_test_writer()
            .try_init();
        let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL required");
        let admin = PgPool::connect(&url).await.unwrap();
        let schema = format!("test_parity_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        let path = format!("SET search_path TO {schema}");
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .after_connect(move |c, _| {
                let p = path.clone();
                Box::pin(async move {
                    sqlx::query(sqlx::AssertSqlSafe(p)).execute(c).await?;
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
        let state = AppState {
            config: Arc::new(config),
            pg: pool.clone(),
        };
        let app = trisixt::routes::router(state.clone());
        let user = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO users(id,email) VALUES($1,'owner@example.test') RETURNING id",
        )
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
        let instance = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO instances(id,name) VALUES($1,'Fixture') RETURNING id",
        )
        .bind(instance)
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO instance_roles(user_id,instance_id,role) VALUES($1,$2,'owner')")
            .bind(user)
            .bind(instance)
            .execute(&pool)
            .await
            .unwrap();
        let project=sqlx::query_scalar::<_,Uuid>("INSERT INTO projects(id,instance_id,environment,domain,name) VALUES($1,$2,'production','fixture.example.test','Fixture') RETURNING id").bind(project).bind(instance).fetch_one(&pool).await.unwrap();
        let (token, hash) = trisixt::auth::new_token();
        sqlx::query("INSERT INTO access_tokens(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '1 hour')").bind(user).bind(hash).execute(&pool).await.unwrap();
        let (key, hash) = trisixt::auth::new_token();
        sqlx::query(
            "INSERT INTO project_api_keys(project_id,name,token_hash) VALUES($1,'Fixture',$2)",
        )
        .bind(project)
        .bind(hash)
        .execute(&pool)
        .await
        .unwrap();
        Self {
            app,
            state,
            pool,
            admin,
            schema,
            user,
            instance,
            project,
            token,
            key,
        }
    }
    pub async fn call(&self, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
        let (s, v, _) = self.raw(method, path, body, &self.token, &self.key).await;
        (s, v)
    }
    pub async fn raw(
        &self,
        method: &str,
        path: &str,
        body: Value,
        token: &str,
        key: &str,
    ) -> (StatusCode, Value, HeaderMap) {
        let response=self.app.clone().oneshot(Request::builder().method(method).uri(path).header("authorization",format!("Bearer {token}")).header("x-project-key",key).header("content-type","application/json").header("host","fixture.example.test").header("user-agent","Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15").extension(axum::extract::ConnectInfo("127.0.0.1:55222".parse::<std::net::SocketAddr>().unwrap())).body(Body::from(body.to_string())).unwrap()).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 2_000_000).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&bytes)})),
            headers,
        )
    }
    pub fn path(&self, suffix: &str) -> String {
        format!("/api/v1/projects/{}/{suffix}", self.project)
    }
    pub async fn visitor(&self) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO visitors(project_id,id,attributes) VALUES($1,$2,'{\"plan\":\"pro\"}')",
        )
        .bind(self.project)
        .bind(id)
        .execute(&self.pool)
        .await
        .unwrap();
        id
    }
    pub async fn event(
        &self,
        visitor: Uuid,
        kind: &str,
        at: chrono::DateTime<chrono::Utc>,
        properties: Value,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let(s,b)=self.call("POST","/api/v1/sdk/event",json!({"event_id":id,"visitor_id":visitor,"event_type":kind,"occurred_at":at,"properties":properties})).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        id
    }
    pub async fn close(self) {
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
