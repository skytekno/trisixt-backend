mod support;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use support::Fixture;
use tower::ServiceExt;
use uuid::Uuid;

const IOS: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15";
const ANDROID: &str = "Mozilla/5.0 (Linux; Android 15; Pixel 9) Mobile";
const STATUS: &str = "/api/v1/sdk/clipboard_status";

async fn link(f: &Fixture, name: &str, metadata: Value) -> Uuid {
    let (status, body) = f
        .call(
            "POST",
            &f.path("links"),
            json!({"name":name,"path":name,"target_url":"https://example.test/landing","metadata":metadata}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["id"].as_str().unwrap().parse().unwrap()
}

async fn public(app: &Router, path: &str, host: &str, ua: &str) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("host", host)
                .header("user-agent", ua)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1_048_576).await.unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

async fn status(app: &Router, key: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(STATUS)
                .header("content-type", "application/json")
                .header("x-project-key", key)
                .header("x-sdk-platform", "ios")
                .header("x-sdk-identifier", "com.example.app")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1_048_576).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn active(f: &Fixture, expected: bool) {
    assert_eq!(
        status(&f.app, &f.key, json!({})).await,
        (StatusCode::OK, json!({"clipboard_active":expected}))
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run scripts/integration.sh"]
async fn tokenless_activity_follows_eligible_mobile_copy_rendering() {
    let f = Fixture::new().await;
    link(
        &f,
        "copy",
        json!({"show_preview_ios":true,"copy_to_clipboard_ios":true}),
    )
    .await;
    active(&f, false).await;
    let (s, html) = public(&f.app, "/copy", "fixture.example.test", IOS).await;
    assert_eq!(s, StatusCode::OK, "{html}");
    assert!(html.contains("?ct="));
    assert!(html.contains("navigator.clipboard.writeText(copy)"));
    active(&f, true).await;
    assert_eq!(
        status(&f.app, &f.key, json!({"clipboard_token":null})).await,
        (StatusCode::OK, json!({"clipboard_active":true}))
    );
    clear(&f).await;
    // The configured Android fallback is also honored without an iOS event.
    sqlx::query("UPDATE project_configurations SET redirect=$2 WHERE project_id=$1")
        .bind(f.project)
        .bind(json!({"show_preview_android":true,"copy_to_clipboard_android":true}))
        .execute(&f.pool)
        .await
        .unwrap();
    link(&f, "android", json!({})).await;
    let (s, html) = public(&f.app, "/android", "fixture.example.test", ANDROID).await;
    assert_eq!(s, StatusCode::OK);
    assert!(html.contains("?ct="));
    active(&f, true).await;
    f.close().await;
}

async fn clear(f: &Fixture) {
    sqlx::query("DELETE FROM project_clipboard_activity")
        .execute(&f.pool)
        .await
        .unwrap();
}

async fn marker(f: &Fixture) -> Option<chrono::DateTime<chrono::Utc>> {
    sqlx::query_scalar(
        "SELECT last_eligible_at FROM project_clipboard_activity WHERE project_id=$1",
    )
    .bind(f.project)
    .fetch_optional(&f.pool)
    .await
    .unwrap()
}

async fn other_project(f: &Fixture) -> (Uuid, String) {
    let instance: Uuid =
        sqlx::query_scalar("INSERT INTO instances(name) VALUES('Other owner') RETURNING id")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    let project: Uuid = sqlx::query_scalar("INSERT INTO projects(instance_id,environment,domain) VALUES($1,'production','other.example.test') RETURNING id")
        .bind(instance).fetch_one(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO project_configurations(project_id,ios) VALUES($1,$2)")
        .bind(project)
        .bind(json!({"enabled":true,"bundle_id":"com.example.app"}))
        .execute(&f.pool)
        .await
        .unwrap();
    let (key, hash) = trisixt::auth::new_token();
    sqlx::query("INSERT INTO project_api_keys(project_id,name,token_hash) VALUES($1,'Other',$2)")
        .bind(project)
        .bind(hash)
        .execute(&f.pool)
        .await
        .unwrap();
    (project, key)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run scripts/integration.sh"]
async fn ineligible_public_requests_do_not_activate_clipboard_activity() {
    let f = Fixture::new().await;
    for (name, metadata, ua, expected) in [
        (
            "no-copy",
            json!({"show_preview_ios":true}),
            IOS,
            StatusCode::OK,
        ),
        (
            "redirect",
            json!({"copy_to_clipboard_ios":true}),
            IOS,
            StatusCode::TEMPORARY_REDIRECT,
        ),
        (
            "desktop",
            json!({"show_preview_desktop":true,"copy_to_clipboard_desktop":true}),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X)",
            StatusCode::OK,
        ),
        (
            "disabled",
            json!({"show_preview_ios":true,"copy_to_clipboard_ios":true,"disable_ios":true}),
            IOS,
            StatusCode::OK,
        ),
        (
            "crawler",
            json!({"show_preview_ios":true,"copy_to_clipboard_ios":true}),
            "iPhone SearchBot",
            StatusCode::OK,
        ),
    ] {
        link(&f, name, metadata).await;
        assert_eq!(
            public(&f.app, &format!("/{name}"), "fixture.example.test", ua)
                .await
                .0,
            expected
        );
        active(&f, false).await;
        assert_eq!(marker(&f).await, None, "{name} must not stamp activity");
    }
    link(
        &f,
        "copy",
        json!({"show_preview_ios":true,"copy_to_clipboard_ios":true}),
    )
    .await;
    for (path, host) in [
        ("/copy?go_to_fallback=1", "fixture.example.test"),
        ("/copy?trisixt_redirect=1", "fixture.example.test"),
        (
            "/?url=https%3A%2F%2Ffixture.example.test%2Fcopy",
            "preview.example.test",
        ),
    ] {
        let (s, html) = public(&f.app, path, host, IOS).await;
        assert_eq!(s, StatusCode::OK, "{path}: {html}");
        assert!(!html.contains("?ct="));
        active(&f, false).await;
    }
    sqlx::query(
        "UPDATE project_configurations SET ios=ios||'{\"enabled\":false}' WHERE project_id=$1",
    )
    .bind(f.project)
    .execute(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        public(&f.app, "/copy", "fixture.example.test", IOS).await.0,
        StatusCode::OK
    );
    assert_eq!(marker(&f).await, None);
    sqlx::query("UPDATE links SET archived_at=now() WHERE path='copy'")
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        public(&f.app, "/copy", "fixture.example.test", IOS).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(marker(&f).await, None);
    // Several ineligible requests still produced ordinary clicks; those alone
    // must never be mistaken for clipboard eligibility.
    let clicks: i64 = sqlx::query_scalar("SELECT count(*) FROM link_clicks")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert!(clicks > 0);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run scripts/integration.sh"]
async fn activity_is_project_scoped_read_only_and_requires_a_configured_sdk() {
    let f = Fixture::new().await;
    let (other, other_key) = other_project(&f).await;
    link(
        &f,
        "copy",
        json!({"show_preview_ios":true,"copy_to_clipboard_ios":true}),
    )
    .await;
    assert_eq!(
        public(&f.app, "/copy", "fixture.example.test", IOS).await.0,
        StatusCode::OK
    );
    let before = marker(&f).await;
    active(&f, true).await;
    assert_eq!(
        status(&f.app, &other_key, json!({"project_id":f.project})).await,
        (StatusCode::OK, json!({"clipboard_active":false}))
    );
    assert_eq!(
        status(&f.app, &f.key, json!({"project_id":other})).await,
        (StatusCode::OK, json!({"clipboard_active":true}))
    );
    let snapshot = |table: &str| {
        format!(
            "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM {table} t"
        )
    };
    let tables = [
        "project_clipboard_activity",
        "visitors",
        "devices",
        "events",
        "link_clicks",
    ];
    let mut rows = vec![];
    for table in tables {
        rows.push(
            sqlx::query_scalar::<_, Value>(sqlx::AssertSqlSafe(snapshot(table)))
                .fetch_one(&f.pool)
                .await
                .unwrap(),
        );
    }
    for invalid in [
        json!([]),
        json!(true),
        json!(null),
        json!({"clipboard_token":17}),
        json!({"clipboard_token":"x".repeat(65)}),
    ] {
        assert_eq!(
            status(&f.app, &f.key, invalid).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    active(&f, true).await;
    assert_eq!(
        status(&f.app, &f.key, json!({"platform":"android"}))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(STATUS)
                .header("x-project-key", &f.key)
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        status(&f.app, "invalid", json!({})).await.0,
        StatusCode::UNAUTHORIZED
    );
    sqlx::query(
        "UPDATE project_configurations SET ios=ios||'{\"enabled\":false}' WHERE project_id=$1",
    )
    .bind(f.project)
    .execute(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        status(&f.app, &f.key, json!({})).await.0,
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE project_api_keys SET revoked_at=now() WHERE project_id=$1")
        .bind(f.project)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        status(&f.app, &f.key, json!({})).await.0,
        StatusCode::UNAUTHORIZED
    );
    for (table, expected) in tables.into_iter().zip(rows) {
        let actual: Value = sqlx::query_scalar(sqlx::AssertSqlSafe(snapshot(table)))
            .fetch_one(&f.pool)
            .await
            .unwrap();
        assert_eq!(actual, expected, "status must not mutate {table}");
    }
    assert_eq!(marker(&f).await, before);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run scripts/integration.sh"]
async fn activity_expires_refreshes_and_survives_fresh_database_connections() {
    let f = Fixture::new().await;
    link(
        &f,
        "copy",
        json!({"show_preview_ios":true,"copy_to_clipboard_ios":true}),
    )
    .await;
    assert_eq!(
        public(&f.app, "/copy", "fixture.example.test", IOS).await.0,
        StatusCode::OK
    );
    for (age, expected) in [(47, true), (49, false)] {
        sqlx::query("UPDATE project_clipboard_activity SET last_eligible_at=now()-make_interval(hours=>$2) WHERE project_id=$1")
            .bind(f.project).bind(age).execute(&f.pool).await.unwrap();
        active(&f, expected).await;
    }
    assert_eq!(
        public(&f.app, "/copy", "fixture.example.test", IOS).await.0,
        StatusCode::OK
    );
    active(&f, true).await;
    let before = marker(&f).await;
    // Recreate both the application router and its pool; no in-process or
    // Redis cache participates in this result.
    let schema: String = sqlx::query_scalar("SHOW search_path")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    f.pool.close().await;
    let fresh = PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |connection, _| {
            let query = format!("SET search_path TO {schema}");
            Box::pin(async move {
                sqlx::query(sqlx::AssertSqlSafe(query))
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&f.state.config.database_url)
        .await
        .unwrap();
    let app = trisixt::routes::router(trisixt::state::AppState {
        config: f.state.config.clone(),
        pg: fresh.clone(),
    });
    assert_eq!(
        status(&app, &f.key, json!({})).await,
        (StatusCode::OK, json!({"clipboard_active":true}))
    );
    let after: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT last_eligible_at FROM project_clipboard_activity WHERE project_id=$1",
    )
    .bind(f.project)
    .fetch_optional(&fresh)
    .await
    .unwrap();
    assert_eq!(after, before);
    sqlx::query("DELETE FROM links WHERE project_id=$1")
        .bind(f.project)
        .execute(&fresh)
        .await
        .unwrap();
    assert_eq!(
        status(&app, &f.key, json!({})).await,
        (StatusCode::OK, json!({"clipboard_active":true}))
    );
    sqlx::query("DELETE FROM projects WHERE id=$1")
        .bind(f.project)
        .execute(&fresh)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM project_clipboard_activity")
        .fetch_one(&fresh)
        .await
        .unwrap();
    assert_eq!(
        count, 0,
        "project deletion must cascade the activity marker"
    );
    fresh.close().await;
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run scripts/integration.sh"]
async fn concurrent_eligible_renders_preserve_the_newest_activity() {
    let f = Fixture::new().await;
    link(
        &f,
        "copy",
        json!({"show_preview_ios":true,"copy_to_clipboard_ios":true}),
    )
    .await;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let app = f.app.clone();
        tasks.spawn(async move { public(&app, "/copy", "fixture.example.test", IOS).await });
    }
    while let Some(result) = tasks.join_next().await {
        assert_eq!(result.unwrap().0, StatusCode::OK);
    }
    active(&f, true).await;
    let (count, newest): (i64, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as("SELECT count(*),max(created_at) FROM link_clicks")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(count, 8);
    assert!(marker(&f).await.unwrap() >= newest);
    // Simulate an already-committed later statement (or a clock rollback): an
    // older render must not replace the newer timestamp.
    sqlx::query("UPDATE project_clipboard_activity SET last_eligible_at=now()+interval '1 hour' WHERE project_id=$1")
        .bind(f.project).execute(&f.pool).await.unwrap();
    let newer = marker(&f).await;
    assert_eq!(
        public(&f.app, "/copy", "fixture.example.test", IOS).await.0,
        StatusCode::OK
    );
    assert_eq!(marker(&f).await, newer);
    active(&f, false).await; // Future-dated activity is not a valid current hint.
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run scripts/integration.sh"]
async fn explicit_token_availability_consumption_and_replay_remain_independent() {
    let f = Fixture::new().await;
    let (_, other_key) = other_project(&f).await;
    link(
        &f,
        "copy",
        json!({"show_preview_ios":true,"copy_to_clipboard_ios":true,"data":{"screen":"welcome"}}),
    )
    .await;
    let (s, html) = public(&f.app, "/copy", "fixture.example.test", IOS).await;
    assert_eq!(s, StatusCode::OK);
    let token = html
        .split("?ct=")
        .nth(1)
        .unwrap()
        .chars()
        .take(64)
        .collect::<String>();
    let args = json!({"clipboard_token":token});
    let before = marker(&f).await;
    for (key, body, expected) in [
        (&f.key, args.clone(), true),
        (&other_key, args.clone(), false),
        (&f.key, json!({"clipboard_token":"forged"}), false),
        (&f.key, json!({"clipboard_token":""}), false),
    ] {
        assert_eq!(
            status(&f.app, key, body).await,
            (StatusCode::OK, json!({"available":expected}))
        );
    }
    let visitor = f.visitor().await;
    for (current, first) in [
        (visitor, true),
        (visitor, false),
        (f.visitor().await, false),
    ] {
        let consume = json!({"visitor_id":current,"clipboard_token":token});
        let (s, body) = f.call("POST", "/api/v1/sdk/data_for_device", consume).await;
        assert_eq!(s, StatusCode::OK, "{body}");
        if first {
            assert_eq!(body["link"], "copy");
            assert_eq!(body["data"]["screen"], "welcome");
        } else {
            assert_eq!(body, json!({"data":null,"link":null,"tracking":null}));
        }
    }
    assert_eq!(
        status(&f.app, &f.key, args).await,
        (StatusCode::OK, json!({"available":false}))
    );
    active(&f, true).await;
    assert_eq!(
        marker(&f).await,
        before,
        "checks and consumption do not extend the activity TTL"
    );
    let opens: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE event_type='open'")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(opens, 1);
    let (_, html) = public(&f.app, "/copy", "fixture.example.test", IOS).await;
    let expired = html
        .split("?ct=")
        .nth(1)
        .unwrap()
        .chars()
        .take(64)
        .collect::<String>();
    sqlx::query(
        "UPDATE link_clicks SET created_at=now()-interval '49 hours' WHERE clipboard_hash=$1",
    )
    .bind(trisixt::auth::token_hash(&expired))
    .execute(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        status(&f.app, &f.key, json!({"clipboard_token":expired})).await,
        (StatusCode::OK, json!({"available":false}))
    );
    active(&f, true).await;
    f.close().await;
}
