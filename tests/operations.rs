mod support;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chrono::Utc;
use serde_json::{Value, json};
use support::Fixture;
use tower::ServiceExt;
use uuid::Uuid;

async fn operator(
    f: &Fixture,
    method: &str,
    path: &str,
    key: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {}", f.token))
        .header("content-type", "application/json");
    if let Some(key) = key {
        request = request.header("x-admin-key", key);
    }
    let response = f
        .app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1_000_000).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
#[ignore = "requires PostgreSQL via TEST_DATABASE_URL; run scripts/integration.sh"]
async fn operator_auth_project_requeue_and_retention_are_scoped_and_audited() {
    // Run in a child test process to configure operator credentials without
    // mutating this multithreaded test runner's environment.
    if std::env::var("TRISIXT_OPERATOR_TEST_CHILD").ok().as_deref() != Some("1") {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "operator_auth_project_requeue_and_retention_are_scoped_and_audited",
                "--ignored",
                "--nocapture",
            ])
            .env("TRISIXT_OPERATOR_TEST_CHILD", "1")
            .env("TRISIXT_ADMIN_KEY", "operator-regression-secret")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let f = Fixture::new().await;
    let visitor = f.visitor().await;
    let first = f.event(visitor, "open", Utc::now(), json!({})).await;
    let delivered = f.event(visitor, "open", Utc::now(), json!({})).await;
    let second:Uuid=sqlx::query_scalar("INSERT INTO projects(instance_id,environment,domain) VALUES($1,'test','other.example.test') RETURNING id").bind(f.instance).fetch_one(&f.pool).await.unwrap();
    let other_visitor = Uuid::new_v4();
    sqlx::query("INSERT INTO visitors(project_id,id) VALUES($1,$2)")
        .bind(second)
        .bind(other_visitor)
        .execute(&f.pool)
        .await
        .unwrap();
    let other:Uuid=sqlx::query_scalar("INSERT INTO events(project_id,event_id,visitor_id,event_type,occurred_at,properties) VALUES($1,$2,$3,'view',now(),'{}') RETURNING id").bind(second).bind(Uuid::new_v4()).bind(other_visitor).fetch_one(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO analytics_outbox(project_id,event_id,payload) VALUES($1,$2,'{}')")
        .bind(second)
        .bind(other)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE analytics_outbox SET available_at=now()+interval '1 day',attempts=3,last_error='retain retry history'").execute(&f.pool).await.unwrap();
    sqlx::query("UPDATE analytics_outbox SET processed_at=now() WHERE event_id=(SELECT id FROM events WHERE project_id=$1 AND event_id=$2)").bind(f.project).bind(delivered).execute(&f.pool).await.unwrap();
    for key in [None, Some("wrong"), Some("operator-regression-secreu")] {
        let (status, _) = operator(
            &f,
            "POST",
            "/api/v1/admin/flush_events",
            key,
            json!({"project_id":f.project}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let key = Some("operator-regression-secret");
    let (status, body) = operator(
        &f,
        "POST",
        "/api/v1/admin/flush_events",
        key,
        json!({"project_id":f.project}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["queued"], 1);
    let ready:bool=sqlx::query_scalar("SELECT o.available_at<=now() AND o.attempts=3 AND o.last_error='retain retry history' FROM analytics_outbox o JOIN events e ON e.id=o.event_id WHERE e.project_id=$1 AND e.event_id=$2").bind(f.project).bind(first).fetch_one(&f.pool).await.unwrap();
    assert!(ready);
    let untouched: i64 =
        sqlx::query_scalar("SELECT count(*) FROM analytics_outbox WHERE available_at>now()")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(untouched, 2);
    let audit: Value = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action='analytics.requeued' AND target_id=$1",
    )
    .bind(f.project)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(audit["queued"], 1);
    assert_eq!(
        operator(
            &f,
            "POST",
            "/api/v1/admin/flush_events",
            key,
            json!({"project_id":Uuid::new_v4()})
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let retention = "/api/v1/admin/instance_retention";
    assert_eq!(
        operator(
            &f,
            "PATCH",
            retention,
            key,
            json!({"instance_id":f.instance,"cold_storage_days":90,"delete_days":30})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (status, body) = operator(
        &f,
        "PATCH",
        retention,
        key,
        json!({"instance_id":f.instance,"cold_storage_days":30,"delete_days":180}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        operator(
            &f,
            "PATCH",
            retention,
            key,
            json!({"instance_id":Uuid::new_v4(),"cold_storage_days":30,"delete_days":180})
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let (status, body) = operator(
        &f,
        "GET",
        "/api/v1/diagnostics/health_metrics",
        key,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["queues"]["pending_events"], 2);
    let (status, body) = operator(
        &f,
        "GET",
        "/api/v1/diagnostics/test_exception",
        key,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!body.to_string().contains("operator-regression-secret"));
    f.close().await;
}
