mod support;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use support::Fixture;
use tower::ServiceExt;
use uuid::Uuid;

// Deliberately sends exactly the supplied declarations. Positive fixture
// defaults must never conceal a missing header in these regression tests.
async fn request(
    f: &Fixture,
    method: &str,
    path: &str,
    body: Value,
    key: Option<&str>,
    headers: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("user-agent", "SDK gate test");
    if let Some(key) = key {
        request = request.header("x-project-key", key);
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = f
        .app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2_000_000).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&bytes)})),
    )
}

// Compare full rows, including timestamps and ownership, so an unchanged count
// cannot hide an update, identity merge, quota debit, or queued delivery.
async fn side_effects(f: &Fixture) -> Value {
    let tables = [
        "visitors",
        "devices",
        "events",
        "analytics_outbox",
        "monthly_active_visitors",
        "billing_alerts",
        "links",
        "link_clicks",
        "visitor_aliases",
        "visitor_attributions",
        "browser_sessions",
        "screen_aliases",
        "notification_messages",
        "push_outbox",
        "verified_purchases",
        "purchase_ledger",
        "subscription_states",
        "purchase_reconciliation",
        "migration_jobs",
        "migration_alerts",
        "connectivity_rate_limits",
        "audit_events",
    ];
    let entries = tables
        .iter()
        .map(|table| {
            format!(
                "'{table}',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM {table} t)"
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT jsonb_build_object({entries})"
    )))
    .fetch_one(&f.pool)
    .await
    .unwrap()
}

fn ios_headers() -> [(&'static str, &'static str); 2] {
    [
        ("x-sdk-platform", "ios"),
        ("x-sdk-identifier", "com.example.app"),
    ]
}

fn event(visitor: Uuid, platform: &str) -> Value {
    json!({"event_id":Uuid::new_v4(),"visitor_id":visitor,"event_type":"gate_test","occurred_at":chrono::Utc::now(),"properties":{"platform":platform}})
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn missing_disabled_foreign_and_conflicting_sdk_declarations_have_no_side_effects() {
    let f = Fixture::new().await;
    let foreign: Uuid = sqlx::query_scalar("INSERT INTO projects(instance_id,environment,domain) VALUES($1,'test','foreign.example.test') RETURNING id")
        .bind(f.instance).fetch_one(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO project_configurations(project_id,ios) VALUES($1,$2)")
        .bind(foreign)
        .bind(json!({"enabled":true,"bundle_id":"com.example.app"}))
        .execute(&f.pool)
        .await
        .unwrap();
    let visitor = f.visitor().await;
    let (status, _) = f
        .call(
            "POST",
            "/api/v1/sdk/authenticate",
            json!({"visitor_id":visitor,"app_version":"1"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = f
        .call("POST", &f.path("notifications"), json!({"title":"Pending notification","html":"<p>Pending</p>","new_users":false,"existing_users":true,"send_push":true}))
        .await;
    assert_eq!(status, StatusCode::OK);
    let endpoints = vec![
        ("GET", "/api/v1/sdk/configurations".to_owned(), Value::Null),
        (
            "POST",
            "/api/v1/sdk/authenticate".to_owned(),
            json!({"visitor_id":visitor,"app_version":"2","push_token":"changed"}),
        ),
        (
            "POST",
            "/api/v1/sdk/visitors".to_owned(),
            json!({"visitor_id":visitor,"attributes":{"changed":true}}),
        ),
        (
            "POST",
            "/api/v1/sdk/visitor_attributes".to_owned(),
            json!({"visitor_id":visitor,"attributes":{"changed":true},"push_token":"changed"}),
        ),
        (
            "POST",
            "/api/v1/sdk/event".to_owned(),
            event(Uuid::new_v4(), "ios"),
        ),
        (
            "POST",
            "/api/v1/sdk/events".to_owned(),
            json!({"events":[event(Uuid::new_v4(),"ios")]}),
        ),
        (
            "POST",
            "/api/v1/sdk/events/batch".to_owned(),
            json!({"events":[event(Uuid::new_v4(),"ios")]}),
        ),
        (
            "POST",
            "/api/v1/sdk/event/custom".to_owned(),
            json!({"visitor_id":visitor,"event_name":"blocked"}),
        ),
        (
            "POST",
            "/api/v1/sdk/screen_aliases".to_owned(),
            json!({"screen_aliases":[{"identifier":"blocked","name":"Blocked"}]}),
        ),
        (
            "POST",
            "/api/v1/sdk/create_link".to_owned(),
            json!({"path":"blocked","visitor_id":visitor}),
        ),
        (
            "POST",
            "/api/v1/sdk/data_for_device".to_owned(),
            json!({"visitor_id":visitor}),
        ),
        (
            "POST",
            "/api/v1/sdk/data_for_device_and_url".to_owned(),
            json!({"visitor_id":visitor,"url":"https://old.example.test/import-me"}),
        ),
        (
            "POST",
            "/api/v1/sdk/data_for_device_and_path".to_owned(),
            json!({"visitor_id":visitor,"path":"blocked"}),
        ),
        (
            "POST",
            "/api/v1/sdk/add_payment_event".to_owned(),
            json!({"visitor_id":visitor,"transaction_id":"blocked","product_id":"item","currency":"USD","price_cents":100}),
        ),
        (
            "POST",
            "/api/v1/sdk/purchases/verify".to_owned(),
            json!({"visitor_id":visitor,"provider":"apple","transaction_id":"blocked","product_id":"item"}),
        ),
        (
            "GET",
            format!("/api/v1/sdk/notifications?visitor_id={visitor}"),
            Value::Null,
        ),
        (
            "POST",
            "/api/v1/sdk/notifications_for_device".to_owned(),
            json!({"visitor_id":visitor}),
        ),
        (
            "GET",
            format!("/api/v1/sdk/number_of_unread_notifications?visitor_id={visitor}"),
            Value::Null,
        ),
        (
            "GET",
            format!("/api/v1/sdk/notifications_to_display_automatically?visitor_id={visitor}"),
            Value::Null,
        ),
        (
            "POST",
            "/api/v1/sdk/mark_notification_as_read".to_owned(),
            json!({"visitor_id":visitor,"id":Uuid::new_v4()}),
        ),
    ];
    let configurations = [
        (
            "missing declarations",
            Some(json!({"enabled":true,"bundle_id":"com.example.app"})),
            vec![],
        ),
        (
            "identifier without platform",
            Some(json!({"enabled":true,"bundle_id":"com.example.app"})),
            vec![("identifier", "com.example.app")],
        ),
        ("unconfigured", None, ios_headers().to_vec()),
        (
            "disabled",
            Some(json!({"enabled":false,"bundle_id":"com.example.app"})),
            ios_headers().to_vec(),
        ),
        (
            "foreign app",
            Some(json!({"enabled":true,"bundle_id":"com.foreign.app"})),
            ios_headers().to_vec(),
        ),
    ];
    for (case, configuration, headers) in configurations {
        if let Some(configuration) = configuration {
            sqlx::query("INSERT INTO project_configurations(project_id,ios) VALUES($1,$2) ON CONFLICT(project_id) DO UPDATE SET ios=$2")
                .bind(f.project).bind(configuration).execute(&f.pool).await.unwrap();
        } else {
            sqlx::query("DELETE FROM project_configurations WHERE project_id=$1")
                .bind(f.project)
                .execute(&f.pool)
                .await
                .unwrap();
        }
        let before = side_effects(&f).await;
        for (method, path, body) in &endpoints {
            let (status, response) =
                request(&f, method, path, body.clone(), Some(&f.key), &headers).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{case}: {method} {path}: {response}"
            );
        }
        assert_eq!(side_effects(&f).await, before, "{case} changed stored data");
    }
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn platform_configuration_and_header_validation_fail_closed() {
    let f = Fixture::new().await;
    let path = "/api/v1/sdk/authenticate";
    let body = json!({"app_version":"1"});
    let invalid_configurations = [
        json!({}),
        json!({"bundle_id":"com.example.app"}),
        json!({"enabled":null,"bundle_id":"com.example.app"}),
        json!({"enabled":"true","bundle_id":"com.example.app"}),
        json!({"enabled":true}),
        json!({"enabled":true,"bundle_id":""}),
        json!({"enabled":true,"bundle_id":" "}),
    ];
    for configuration in invalid_configurations {
        sqlx::query("UPDATE project_configurations SET ios=$2 WHERE project_id=$1")
            .bind(f.project)
            .bind(&configuration)
            .execute(&f.pool)
            .await
            .unwrap();
        let before = side_effects(&f).await;
        let (status, response) =
            request(&f, "POST", path, body.clone(), Some(&f.key), &ios_headers()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{configuration}: {response}");
        assert_eq!(side_effects(&f).await, before);
    }
    sqlx::query("UPDATE project_configurations SET ios=$2,web=$3 WHERE project_id=$1")
        .bind(f.project)
        .bind(json!({"enabled":true,"bundle_id":"com.example.app"}))
        .bind(json!({"enabled":true,"domains":["fixture.example.test","second.example.test"]}))
        .execute(&f.pool)
        .await
        .unwrap();
    type HeaderCase<'a> = (&'a str, Vec<(&'a str, &'a str)>, StatusCode);
    let cases: Vec<HeaderCase<'_>> = vec![
        (
            "platform only",
            vec![("platform", "ios")],
            StatusCode::FORBIDDEN,
        ),
        (
            "foreign android",
            vec![("platform", "android"), ("identifier", "com.foreign.app")],
            StatusCode::FORBIDDEN,
        ),
        (
            "foreign web",
            vec![("platform", "web"), ("identifier", "foreign.example.test")],
            StatusCode::FORBIDDEN,
        ),
        (
            "foreign origin",
            vec![("origin", "https://foreign.example.test")],
            StatusCode::FORBIDDEN,
        ),
        (
            "null origin",
            vec![("origin", "null")],
            StatusCode::FORBIDDEN,
        ),
        (
            "bare origin",
            vec![("origin", "fixture.example.test")],
            StatusCode::FORBIDDEN,
        ),
        (
            "unsupported",
            vec![("platform", "server"), ("identifier", "com.example.app")],
            StatusCode::BAD_REQUEST,
        ),
        (
            "empty platform",
            vec![("platform", "")],
            StatusCode::BAD_REQUEST,
        ),
        (
            "platform aliases disagree",
            vec![
                ("platform", "ios"),
                ("x-sdk-platform", "android"),
                ("identifier", "com.example.app"),
            ],
            StatusCode::BAD_REQUEST,
        ),
        (
            "duplicate platform disagrees",
            vec![
                ("platform", "ios"),
                ("platform", "android"),
                ("identifier", "com.example.app"),
            ],
            StatusCode::BAD_REQUEST,
        ),
        (
            "identifier aliases disagree",
            vec![
                ("platform", "ios"),
                ("identifier", "com.example.app"),
                ("x-sdk-identifier", "com.other.app"),
            ],
            StatusCode::BAD_REQUEST,
        ),
        (
            "origin conflicts with mobile",
            vec![
                ("platform", "ios"),
                ("identifier", "com.example.app"),
                ("origin", "https://fixture.example.test"),
            ],
            StatusCode::FORBIDDEN,
        ),
        (
            "origin conflicts with desktop",
            vec![
                ("platform", "desktop"),
                ("origin", "https://fixture.example.test"),
            ],
            StatusCode::FORBIDDEN,
        ),
        (
            "two allowed web hosts conflict",
            vec![
                ("platform", "web"),
                ("identifier", "fixture.example.test"),
                ("origin", "https://second.example.test"),
            ],
            StatusCode::FORBIDDEN,
        ),
    ];
    let before = side_effects(&f).await;
    for (case, headers, expected) in cases {
        let (status, response) =
            request(&f, "POST", path, body.clone(), Some(&f.key), &headers).await;
        assert_eq!(status, expected, "{case}: {response}");
    }
    assert_eq!(side_effects(&f).await, before);
    for (platform, configuration, headers) in [
        (
            "android",
            json!({"enabled":true}),
            vec![("platform", "android"), ("identifier", "com.example.app")],
        ),
        (
            "web",
            json!({"enabled":true}),
            vec![("origin", "https://fixture.example.test")],
        ),
        (
            "web",
            json!({"enabled":true,"domains":[]}),
            vec![("platform", "web"), ("identifier", "fixture.example.test")],
        ),
        (
            "web",
            json!({"enabled":false,"domains":["fixture.example.test"]}),
            vec![("origin", "https://fixture.example.test")],
        ),
        ("desktop", json!({}), vec![("platform", "desktop")]),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE project_configurations SET {platform}=$2 WHERE project_id=$1"
        )))
        .bind(f.project)
        .bind(configuration)
        .execute(&f.pool)
        .await
        .unwrap();
        let (status, response) =
            request(&f, "POST", path, body.clone(), Some(&f.key), &headers).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{platform}: {response}");
        assert_eq!(side_effects(&f).await, before);
    }
    sqlx::query("UPDATE project_api_keys SET revoked_at=now() WHERE project_id=$1")
        .bind(f.project)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        request(&f, "POST", path, body.clone(), Some(&f.key), &ios_headers())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&f, "POST", path, body, None, &ios_headers())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(side_effects(&f).await, before);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn payload_platform_conflicts_are_rejected_before_ingestion_and_fanout() {
    let f = Fixture::new().await;
    let visitor = f.visitor().await;
    let cases = vec![
        (
            "POST",
            "/api/v1/sdk/authenticate".to_owned(),
            json!({"visitor_id":visitor,"app_version":"1","platform":"android"}),
        ),
        (
            "POST",
            "/api/v1/sdk/data_for_device_and_url".to_owned(),
            json!({"visitor_id":visitor,"url":"https://old.example.test/import-me","platform":"android"}),
        ),
        (
            "POST",
            "/api/v1/sdk/event".to_owned(),
            event(Uuid::new_v4(), "android"),
        ),
        (
            "POST",
            "/api/v1/sdk/events/batch".to_owned(),
            json!({"events":[event(Uuid::new_v4(),"ios"),event(Uuid::new_v4(),"android")]}),
        ),
        (
            "POST",
            "/api/v1/sdk/event/custom".to_owned(),
            json!({"visitor_id":visitor,"event_name":"conflicting","properties":{"platform":"android"}}),
        ),
        (
            "POST",
            "/api/v1/sdk/add_payment_event".to_owned(),
            json!({"visitor_id":visitor,"transaction_id":"conflicting","product_id":"item","currency":"USD","price_cents":100,"platform":"android"}),
        ),
        (
            "GET",
            format!("/api/v1/sdk/notifications?visitor_id={visitor}&platform=android"),
            Value::Null,
        ),
        (
            "POST",
            "/api/v1/sdk/notifications_for_device".to_owned(),
            json!({"visitor_id":visitor,"platform":"android"}),
        ),
    ];
    let before = side_effects(&f).await;
    for (method, path, body) in cases {
        let (status, response) =
            request(&f, method, &path, body, Some(&f.key), &ios_headers()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {response}");
        assert_eq!(
            side_effects(&f).await,
            before,
            "{method} {path} changed data"
        );
    }
    for (method, path, body) in [
        (
            "GET",
            format!("/api/v1/sdk/notifications?visitor_id={visitor}&identifier=com.foreign.app"),
            Value::Null,
        ),
        (
            "POST",
            "/api/v1/sdk/notifications_for_device".to_owned(),
            json!({"visitor_id":visitor,"identifier":"com.foreign.app"}),
        ),
    ] {
        let (status, response) =
            request(&f, method, &path, body, Some(&f.key), &ios_headers()).await;
        let expected = if method == "GET" {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::UNPROCESSABLE_ENTITY
        };
        assert_eq!(status, expected, "{method} {path}: {response}");
        assert_eq!(side_effects(&f).await, before);
    }
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn configured_mobile_web_and_desktop_clients_authenticate_and_ingest() {
    let f = Fixture::new().await;
    let cases: Vec<(&str, Vec<(&str, &str)>)> = vec![
        ("ios", ios_headers().to_vec()),
        (
            "android",
            vec![("platform", "android"), ("identifier", "com.example.app")],
        ),
        (
            "web",
            vec![("platform", "web"), ("identifier", "Fixture.Example.Test.")],
        ),
        ("web", vec![("origin", "https://fixture.example.test")]),
        (
            "web",
            vec![
                ("x-sdk-platform", "WEB"),
                ("identifier", "fixture.example.test"),
                ("origin", "https://Fixture.Example.Test:443"),
            ],
        ),
        ("desktop", vec![("platform", "desktop")]),
        ("mac", vec![("platform", "mac")]),
        ("windows", vec![("platform", "windows")]),
        ("linux", vec![("platform", "linux")]),
    ];
    for (platform, headers) in cases {
        let (status, body) = request(
            &f,
            "POST",
            "/api/v1/sdk/authenticate",
            json!({"app_version":"1"}),
            Some(&f.key),
            &headers,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{platform}: {body}");
        let visitor = body["visitor_id"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            body["device"]["platform"],
            if matches!(platform, "mac" | "windows" | "linux") {
                "desktop"
            } else {
                platform
            }
        );
        let (status, body) = request(
            &f,
            "POST",
            "/api/v1/sdk/event",
            event(visitor, platform),
            Some(&f.key),
            &headers,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{platform}: {body}");
        assert_eq!(body["accepted"], 1);
    }
    for (platform, flag) in [("mac", "mac_enabled"), ("windows", "windows_enabled")] {
        sqlx::query("UPDATE project_configurations SET desktop=$2 WHERE project_id=$1")
            .bind(f.project)
            .bind(json!({"enabled":true,flag:false}))
            .execute(&f.pool)
            .await
            .unwrap();
        let before = side_effects(&f).await;
        assert_eq!(
            request(
                &f,
                "POST",
                "/api/v1/sdk/authenticate",
                json!({"app_version":"1"}),
                Some(&f.key),
                &[("platform", platform)]
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(side_effects(&f).await, before);
        assert_eq!(
            request(
                &f,
                "POST",
                "/api/v1/sdk/authenticate",
                json!({"app_version":"1","platform":platform}),
                Some(&f.key),
                &[("platform", "desktop")]
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(side_effects(&f).await, before);
    }
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn event_platform_defaults_to_authenticated_client_instead_of_a_different_device() {
    let f = Fixture::new().await;
    let visitor = f.visitor().await;
    let (status, body) = request(
        &f,
        "POST",
        "/api/v1/sdk/authenticate",
        json!({"visitor_id":visitor,"app_version":"1"}),
        Some(&f.key),
        &[("platform", "android"), ("identifier", "com.example.app")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut input = event(visitor, "ios");
    input["properties"] = json!({"source":"ios-client"});
    let id = input["event_id"].as_str().unwrap().parse::<Uuid>().unwrap();
    let (status, body) = request(
        &f,
        "POST",
        "/api/v1/sdk/event",
        input,
        Some(&f.key),
        &ios_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let platform: String = sqlx::query_scalar(
        "SELECT properties->>'platform' FROM events WHERE project_id=$1 AND event_id=$2",
    )
    .bind(f.project)
    .bind(id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(platform, "ios");
    let payload: Value = sqlx::query_scalar(
        "SELECT o.payload FROM analytics_outbox o JOIN events e ON e.id=o.event_id AND e.project_id=o.project_id WHERE e.project_id=$1 AND e.event_id=$2",
    )
    .bind(f.project)
    .bind(id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(payload["properties"]["platform"], "ios");
    let (status, body) = f
        .call(
            "POST",
            &f.path("notifications"),
            json!({"title":"Android only","existing_users":true,"new_users":false,"platforms":["android"]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for (headers, count) in [
        (ios_headers().to_vec(), 0),
        (
            vec![("platform", "android"), ("identifier", "com.example.app")],
            1,
        ),
    ] {
        let (status, body) = request(
            &f,
            "GET",
            &format!("/api/v1/sdk/notifications?visitor_id={visitor}"),
            Value::Null,
            Some(&f.key),
            &headers,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["notifications"].as_array().unwrap().len(), count);
    }
    let (status, body) = request(
        &f,
        "POST",
        "/api/v1/sdk/add_payment_event",
        json!({"visitor_id":visitor,"transaction_id":"default-platform","product_id":"item","currency":"USD","price_cents":100}),
        Some(&f.key),
        &ios_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let purchase_platform: String = sqlx::query_scalar(
        "SELECT platform FROM verified_purchases WHERE project_id=$1 AND transaction_id='default-platform'",
    )
    .bind(f.project)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(purchase_platform, "ios");
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn server_sdk_and_trusted_internal_calls_keep_their_own_authentication_contracts() {
    let f = Fixture::new().await;
    sqlx::query("DELETE FROM project_configurations WHERE project_id=$1")
        .bind(f.project)
        .execute(&f.pool)
        .await
        .unwrap();
    let (key, hash) = trisixt::auth::new_token();
    sqlx::query("INSERT INTO instance_api_keys(instance_id,token_hash,name) VALUES($1,$2,'Server gate regression')")
        .bind(f.instance).bind(hash).execute(&f.pool).await.unwrap();
    let (status, body) = request(
        &f,
        "POST",
        "/api/v1/sdk/generate_link",
        json!({"path":"server-sdk","target_url":"https://example.test/"}),
        Some(&key),
        &[("environment", "production")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = request(
        &f,
        "GET",
        "/api/v1/sdk/link/server-sdk",
        Value::Null,
        Some(&key),
        &[("environment", "production")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["link"]["path"], "server-sdk");
    let (status, _) = request(
        &f,
        "POST",
        "/api/v1/sdk/authenticate",
        json!({"app_version":"1"}),
        Some(&key),
        &ios_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let visitor = Uuid::new_v4();
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/sdk/visitors")
                .extension(trisixt::auth::InternalSdkProject(f.project))
                .header("content-type", "application/json")
                .body(Body::from(json!({"visitor_id":visitor}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM visitors WHERE project_id=$1 AND id=$2)"
        )
        .bind(f.project)
        .bind(visitor)
        .fetch_one(&f.pool)
        .await
        .unwrap()
    );
    f.close().await;
}
