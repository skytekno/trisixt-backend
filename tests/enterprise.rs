//! PostgreSQL-backed enterprise boundary tests; explicitly run with --ignored.
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
    auth::{new_token, token_hash},
    config::{AnalyticsBackend, Config, StorageBackend},
    state::AppState,
};
use uuid::Uuid;
struct Fixture {
    app: Router,
    pool: PgPool,
    admin: PgPool,
    schema: String,
    instance: Uuid,
    token: String,
    other_instance: Uuid,
    other_token: String,
}
impl Fixture {
    async fn new(enabled: bool) -> Self {
        let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL required");
        let admin = PgPool::connect(&url).await.unwrap();
        let schema = format!("test_enterprise_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        let path = format!("SET search_path TO {schema}");
        let pool = PgPoolOptions::new()
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
        let (instance, token) = Self::tenant(&pool, "owner@example.test").await;
        let (other_instance, other_token) = Self::tenant(&pool, "other@example.test").await;
        let config = Config {
            env: "test".into(),
            host: "127.0.0.1".into(),
            port: 0,
            server_host: "example.test".into(),
            database_url: url,
            redis_url: "redis://127.0.0.1:56386".into(),
            ee_enabled: enabled,
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
            instance,
            token,
            other_instance,
            other_token,
        }
    }
    async fn tenant(pool: &PgPool, email: &str) -> (Uuid, String) {
        let id: Uuid = sqlx::query_scalar("INSERT INTO users(email)VALUES($1)RETURNING id")
            .bind(email)
            .fetch_one(pool)
            .await
            .unwrap();
        let tenant: Uuid =
            sqlx::query_scalar("INSERT INTO instances(name)VALUES('Tenant')RETURNING id")
                .fetch_one(pool)
                .await
                .unwrap();
        sqlx::query("INSERT INTO instance_roles(user_id,instance_id,role)VALUES($1,$2,'owner')")
            .bind(id)
            .bind(tenant)
            .execute(pool)
            .await
            .unwrap();
        let (token, hash) = new_token();
        sqlx::query("INSERT INTO access_tokens(user_id,token_hash,expires_at)VALUES($1,$2,now()+interval '1 hour')").bind(id).bind(hash).execute(pool).await.unwrap();
        (tenant, token)
    }
    async fn call(
        &self,
        method: &str,
        path: &str,
        token: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
    async fn close(self) {
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
#[ignore = "requires PostgreSQL 18.6 via TEST_DATABASE_URL"]
async fn enterprise_enabled_audit_chained_and_tenant_scoped() {
    let f = Fixture::new(true).await;
    let (status, body) = f
        .call(
            "GET",
            &format!("/api/v1/instances/{}/enterprise", f.instance),
            &f.token,
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["enabled"], true);
    let (status, body) = f
        .call(
            "GET",
            &format!("/api/v1/instances/{}/audit-events", f.instance),
            &f.token,
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["events"].as_array().unwrap().len() >= 2);
    let events = body["events"].as_array().unwrap();
    assert_eq!(events[0]["previous_hash"], "0".repeat(64));
    assert_eq!(events[1]["previous_hash"], events[0]["hash"]);
    let valid:bool=sqlx::query_scalar("SELECT bool_and(hash=encode(sha256(convert_to(previous_hash||jsonb_build_object('instance_id',instance_id,'sequence',sequence,'actor_id',actor_id,'action',action,'target_id',target_id,'details',details,'occurred_at',occurred_at)::text,'UTF8')),'hex')) FROM audit_events WHERE instance_id=$1").bind(f.instance).fetch_one(&f.pool).await.unwrap();
    assert!(valid);
    assert_eq!(
        f.call(
            "GET",
            &format!("/api/v1/instances/{}/audit-events", f.instance),
            &f.other_token,
            Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert!(
        sqlx::query("UPDATE audit_events SET action='tampered' WHERE instance_id=$1")
            .bind(f.instance)
            .execute(&f.pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM audit_events WHERE instance_id=$1")
            .bind(f.instance)
            .execute(&f.pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("TRUNCATE audit_events")
            .execute(&f.pool)
            .await
            .is_err()
    );
    f.close().await;
}
#[tokio::test]
#[ignore = "requires PostgreSQL 18.6 via TEST_DATABASE_URL"]
async fn scim_provision_patch_revoke_and_prevent_account_takeover() {
    let f = Fixture::new(true).await;
    let token_path = format!("/api/v1/instances/{}/scim-token", f.instance);
    let (status, body) = f.call("POST", &token_path, &f.token, json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let token = body["token"].as_str().unwrap();
    let(status,body)=f.call("POST","/scim/v2/Users",token,json!({"userName":"managed@example.test","externalId":"managed-1","displayName":"Managed","active":true})).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = body["id"].as_str().unwrap();
    let path = format!("/scim/v2/Users/{id}");
    assert_eq!(
        f.call(
            "POST",
            "/scim/v2/Users",
            token,
            json!({"userName":"other@example.test"})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (_, second) = f
        .call(
            "POST",
            &format!("/api/v1/instances/{}/scim-token", f.other_instance),
            &f.other_token,
            json!({}),
        )
        .await;
    let other = second["token"].as_str().unwrap();
    assert_eq!(
        f.call("GET", &path, other, Value::Null).await.0,
        StatusCode::NOT_FOUND
    );
    let session = new_token().0;
    sqlx::query("INSERT INTO access_tokens(user_id,token_hash,expires_at)VALUES($1,$2,now()+interval '1 hour')").bind(Uuid::parse_str(id).unwrap()).bind(token_hash(&session)).execute(&f.pool).await.unwrap();
    let (status, body) = f
        .call(
            "PATCH",
            &path,
            token,
            json!({"Operations":[{"op":"replace","path":"active","value":false}]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["active"], false);
    assert_eq!(
        f.call("GET", "/auth/me", &session, Value::Null).await.0,
        StatusCode::UNAUTHORIZED
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM instance_roles WHERE instance_id=$1 AND user_id=$2",
    )
    .bind(f.instance)
    .bind(Uuid::parse_str(id).unwrap())
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(count, 0);
    let (status, body) = f
        .call(
            "PATCH",
            &path,
            token,
            json!({"Operations":[{"op":"replace","value":{"active":true}}]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["active"], true);
    let (status, _) = f.call("DELETE", &token_path, &f.token, Value::Null).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        f.call("GET", "/scim/v2/Users", token, Value::Null).await.0,
        StatusCode::UNAUTHORIZED
    );
    f.close().await;
}
#[tokio::test]
#[ignore = "requires PostgreSQL 18.6 via TEST_DATABASE_URL"]
async fn explicit_enterprise_opt_out_enforced() {
    let f = Fixture::new(false).await;
    assert_eq!(
        f.call(
            "POST",
            &format!("/api/v1/instances/{}/scim-token", f.instance),
            &f.token,
            json!({})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    f.close().await;
}
