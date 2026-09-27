mod support;

use axum::http::{HeaderMap, StatusCode};
use serde_json::{Value, json};
use support::Fixture;
use uuid::Uuid;

const RESOLVE: &str = "/api/v1/sdk/data_for_device_and_url";

fn referrer(url: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("utm_source", "play")
        .append_pair("~referring_link", url)
        .finish()
}

async fn link(f: &Fixture, path: &str) -> Value {
    let (status, body) = f
        .call(
            "POST",
            &f.path("links"),
            json!({
                "name":path,"path":path,"target_url":"https://shop.example/product",
                "data":{"screen":path},"tracking_campaign":"launch",
                "tracking_source":"newsletter","tracking_medium":"email"
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body
}

async fn source(f: &Fixture, host: &str, provider_hosted: bool) -> Uuid {
    let id = sqlx::query_scalar("INSERT INTO migration_sources(project_id,provider,old_host,provider_hosted,credentials_ciphertext,enabled) VALUES($1,'branch',$2,$3,'cached-only',false) RETURNING id")
        .bind(f.project).bind(host).bind(provider_hosted).fetch_one(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO migration_hosts(hostname,source_id) VALUES($1,$2)")
        .bind(host)
        .bind(id)
        .execute(&f.pool)
        .await
        .unwrap();
    id
}

async fn cached(f: &Fixture, source: Uuid, path: &str, link: &Value) {
    sqlx::query(
        "INSERT INTO migrated_links(source_id,old_path,status,link_id) VALUES($1,$2,'resolved',$3)",
    )
    .bind(source)
    .bind(path)
    .bind(link["id"].as_str().unwrap().parse::<Uuid>().unwrap())
    .execute(&f.pool)
    .await
    .unwrap();
}

async fn resolve(f: &Fixture, visitor: Uuid, url: &str) -> (StatusCode, Value) {
    f.call(
        "POST",
        RESOLVE,
        json!({"visitor_id":visitor,"url":url,"platform":"android"}),
    )
    .await
}

async fn assert_link(f: &Fixture, visitor: Uuid, input: &str, expected: &Value) {
    let (status, body) = resolve(f, visitor, input).await;
    assert_eq!(status, StatusCode::OK, "{input}: {body}");
    assert_eq!(
        body,
        json!({
            "data":expected["metadata"]["data"],"link":expected["path"],"link_id":expected["id"],
            "tracking":{"campaign":expected["metadata"]["tracking_campaign"],
                "source":expected["metadata"]["tracking_source"],"medium":expected["metadata"]["tracking_medium"]}
        }),
        "{input}"
    );
    let attribution: (Uuid, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT link_id,source,medium FROM visitor_attributions WHERE project_id=$1 AND visitor_id=$2")
        .bind(f.project).bind(visitor).fetch_one(&f.pool).await.unwrap();
    assert_eq!(
        attribution,
        (
            expected["id"].as_str().unwrap().parse().unwrap(),
            expected["metadata"]["tracking_source"]
                .as_str()
                .map(str::to_owned),
            expected["metadata"]["tracking_medium"]
                .as_str()
                .map(str::to_owned)
        ),
        "{input}"
    );
}

async fn assert_defaults(f: &Fixture, visitor: Uuid, input: &str) {
    let (status, body) = resolve(f, visitor, input).await;
    assert_eq!(status, StatusCode::OK, "{input}: {body}");
    assert_eq!(
        body,
        json!({"data":null,"link":null,"tracking":null}),
        "{input}"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run scripts/integration.sh"]
async fn routed_sdk_accepts_referrers_slugs_and_custom_schemes_with_exact_attribution() {
    let f = Fixture::new().await;
    let native = link(&f, "offer").await;
    let imported = link(&f, "imported").await;
    let source = source(&f, "old.example.test", true).await;
    cached(&f, source, "offer", &imported).await;
    cached(&f, source, "prefix/offer", &imported).await;
    for input in [
        "https://old.example.test/offer?utm_campaign=launch".into(),
        referrer("https://old.example.test/offer?utm_source=mail&campaign=summer%20sale"),
        "offer".into(),
        "offer?utm_source=mail".into(),
        "demoapp://offer".into(),
        "demoapp://prefix/offer?utm_source=mail".into(),
        "demoapp:///offer".into(),
    ] {
        assert_link(&f, f.visitor().await, &input, &imported).await;
    }
    // Native ownership takes precedence over a colliding old migration slug.
    for input in [
        "https://fixture.example.test/l/offer",
        "demoapp://fixture.example.test/l/offer",
        "https://FIXTURE.EXAMPLE.TEST./l/offer",
    ] {
        assert_link(&f, f.visitor().await, input, &native).await;
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM links")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        count, 2,
        "cached inputs must not materialize duplicate links"
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run scripts/integration.sh"]
async fn malformed_migration_inputs_cannot_claim_a_fingerprint_match() {
    let f = Fixture::new().await;
    let native = link(&f, "offer").await;
    let context = trisixt::sdk::ClientContext {
        ip: Some("127.0.0.1".parse().unwrap()),
        user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15"
            .into(),
    };
    trisixt::sdk::record_click(
        &f.state,
        f.project,
        native["id"].as_str().unwrap().parse().unwrap(),
        &HeaderMap::new(),
        &context,
    )
    .await
    .unwrap();
    let visitor = f.visitor().await;
    let before = effect_snapshot(&f).await;
    let invalid = [
        "",
        "   ",
        "broken input",
        "http:/old.example.test/offer",
        "https://",
        "javascript:alert(1)",
        "javascript://old.example.test/offer",
        "file://old.example.test/offer",
        "data:text/plain,offer",
        "ftp://old.example.test/offer",
        "mailto:offer@example.test",
        "https://user:password@old.example.test/offer",
        "demoapp://user:password@offer",
        "unknown=offer",
        "~referring_link=",
        "~referring_link=%GG",
        "~referring_link=offer",
        "~referring_link=https%3A%2F%2F",
        "~referring_link=demoapp%3A%2F%2Foffer",
        "~referring_link=javascript%3A%2F%2Fold.example.test%2Foffer",
        "~referring_link=https%3A%2F%2Fold.example.test%2Foffer&~referring_link=https%3A%2F%2Fold.example.test%2Fother",
        "~referring_link=~referring_link%3Dhttps%253A%252F%252Fold.example.test%252Foffer",
        "../offer",
        "prefix//offer",
        "//foreign.example.test/offer",
        "offer%ZZ",
        "offer\\other",
        "offer\nother",
    ];
    for input in invalid
        .iter()
        .map(|s| s.to_string())
        .chain(["x".repeat(8193)])
    {
        let (status, body) = resolve(&f, visitor, &input).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{input:?}: {body}");
    }
    assert_defaults(&f, visitor, "https://unconfigured.example.test/offer").await;
    assert_defaults(&f, visitor, "offer").await; // No migration source configured.
    assert_eq!(effect_snapshot(&f).await, before);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run scripts/integration.sh"]
async fn migration_custom_hosts_and_cache_rows_stay_project_scoped() {
    let f = Fixture::new().await;
    let native = link(&f, "offer").await;
    let imported = link(&f, "imported").await;
    let source = source(&f, "old.example.test", false).await;
    cached(&f, source, "offer", &imported).await;
    let visitor = f.visitor().await;
    assert_defaults(&f, visitor, "https://old.example.test/offer").await;
    sqlx::query("INSERT INTO custom_hostnames(project_id,hostname,purpose,source,mode,status) VALUES($1,'old.example.test','migration','enterprise','manual','active')")
        .bind(f.project).execute(&f.pool).await.unwrap();
    assert_link(&f, visitor, "https://old.example.test/offer", &imported).await;
    sqlx::query("INSERT INTO custom_hostnames(project_id,hostname,purpose,source,mode,status) VALUES($1,'primary.example.test','primary','enterprise','manual','active')")
        .bind(f.project).execute(&f.pool).await.unwrap();
    assert_link(
        &f,
        f.visitor().await,
        "https://primary.example.test/l/offer",
        &native,
    )
    .await;
    sqlx::query("UPDATE custom_hostnames SET status='suspended' WHERE purpose='migration'")
        .execute(&f.pool)
        .await
        .unwrap();
    assert_defaults(&f, f.visitor().await, "offer").await;

    let foreign: Uuid = sqlx::query_scalar("INSERT INTO projects(instance_id,environment,domain) VALUES($1,'test','foreign.example.test') RETURNING id")
        .bind(f.instance).fetch_one(&f.pool).await.unwrap();
    let other_source: Uuid = sqlx::query_scalar("INSERT INTO migration_sources(project_id,provider,old_host,provider_hosted,credentials_ciphertext,enabled) VALUES($1,'branch','foreign-old.example.test',true,'cached-only',false) RETURNING id")
        .bind(foreign).fetch_one(&f.pool).await.unwrap();
    sqlx::query(
        "INSERT INTO migration_hosts(hostname,source_id) VALUES('foreign-old.example.test',$1)",
    )
    .bind(other_source)
    .execute(&f.pool)
    .await
    .unwrap();
    let other_link: Uuid = sqlx::query_scalar("INSERT INTO links(project_id,name,path,target_url,metadata) VALUES($1,'Foreign','secret','https://example.test','{\"data\":{\"private\":true}}') RETURNING id")
        .bind(foreign).fetch_one(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO migrated_links(source_id,old_path,status,link_id) VALUES($1,'offer','resolved',$2)").bind(other_source).bind(other_link).execute(&f.pool).await.unwrap();
    for input in [
        "https://foreign.example.test/secret".into(),
        "https://foreign-old.example.test/offer".into(),
        referrer("https://foreign-old.example.test/offer"),
    ] {
        assert_defaults(&f, f.visitor().await, &input).await;
    }
    // Even a corrupt cache row cannot expose another project's link.
    sqlx::query("UPDATE custom_hostnames SET status='active' WHERE purpose='migration'")
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE migrated_links SET link_id=$2 WHERE source_id=$1")
        .bind(source)
        .bind(other_link)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_defaults(&f, f.visitor().await, "offer").await;
    let foreign_effects: i64 =
        sqlx::query_scalar("SELECT count(*) FROM visitor_attributions WHERE project_id=$1")
            .bind(foreign)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(foreign_effects, 0);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run scripts/integration.sh"]
async fn disabled_missing_archived_and_deleted_migrations_return_defaults() {
    let f = Fixture::new().await;
    let imported = link(&f, "imported").await;
    let source = source(&f, "old.example.test", true).await;
    cached(&f, source, "offer", &imported).await;
    let visitor = f.visitor().await;
    assert_defaults(&f, visitor, "uncached").await;
    assert_link(&f, visitor, "offer", &imported).await; // Manually disabled cache still resolves.
    sqlx::query("UPDATE migration_sources SET auto_disabled_at=now() WHERE id=$1")
        .bind(source)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_defaults(&f, f.visitor().await, "uncached").await;
    assert_link(&f, f.visitor().await, "offer", &imported).await;
    sqlx::query("UPDATE links SET archived_at=now() WHERE id=$1")
        .bind(imported["id"].as_str().unwrap().parse::<Uuid>().unwrap())
        .execute(&f.pool)
        .await
        .unwrap();
    assert_defaults(&f, f.visitor().await, "offer").await;
    sqlx::query("DELETE FROM links WHERE id=$1")
        .bind(imported["id"].as_str().unwrap().parse::<Uuid>().unwrap())
        .execute(&f.pool)
        .await
        .unwrap();
    assert_defaults(&f, f.visitor().await, "offer").await;
    for status in ["not_found", "transient_error"] {
        sqlx::query("INSERT INTO migrated_links(source_id,old_path,status,cached_until) VALUES($1,$2,$2,now()+interval '1 hour')").bind(source).bind(status).execute(&f.pool).await.unwrap();
        assert_defaults(&f, f.visitor().await, status).await;
    }
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run scripts/integration.sh"]
async fn referrer_clipboard_replay_preserves_single_open_and_identity_claim() {
    let f = Fixture::new().await;
    let imported = link(&f, "imported").await;
    let source = source(&f, "old.example.test", true).await;
    cached(&f, source, "offer", &imported).await;
    let click = trisixt::sdk::record_click(
        &f.state,
        f.project,
        imported["id"].as_str().unwrap().parse().unwrap(),
        &HeaderMap::new(),
        &trisixt::sdk::ClientContext::default(),
    )
    .await
    .unwrap();
    let visitor = f.visitor().await;
    let input = referrer(&format!(
        "https://old.example.test/offer?ct={}",
        click.clipboard
    ));
    assert_link(&f, visitor, &input, &imported).await;
    assert_link(&f, visitor, &input, &imported).await;
    assert_eq!(
        trisixt::sdk::canonical(&f.state, f.project, click.visitor)
            .await
            .unwrap(),
        visitor
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE event_type='open'")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run scripts/integration.sh"]
async fn routed_provider_resolution_preserves_queries_and_caches_failures() {
    // Configure only a child process: mutating process-global environment during
    // parallel Rust tests is unsafe and can send another test to the wrong host.
    const CHILD: &str = "TRISIXT_MIGRATION_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        provider_resolution_case().await;
        return;
    }
    use axum::{Json, Router, extract::State, http::Uri, routing::get};
    use std::sync::Arc;
    use tokio::sync::Mutex;
    type Seen = Arc<Mutex<Vec<String>>>;
    async fn provider(State(seen): State<Seen>, uri: Uri) -> (StatusCode, Json<Value>) {
        let query = url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes())
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(query["branch_key"], "test-branch-key");
        let old = url::Url::parse(&query["url"]).unwrap();
        seen.lock().await.push(old.to_string());
        match old.path() {
            "/fresh" | "/bare" | "/prefix/custom" => (
                StatusCode::OK,
                Json(json!({"data":{
                    "$desktop_url":"https://shop.example/product","sku":"exact-product",
                    "~campaign":"summer","~channel":"play","~feature":"install"
                }})),
            ),
            "/busy" => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({}))),
            _ => (StatusCode::NOT_FOUND, Json(json!({}))),
        }
    }
    let seen = Seen::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/branch", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/branch", get(provider))
        .with_state(seen.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let output = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "routed_provider_resolution_preserves_queries_and_caches_failures",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("BRANCH_API_ENDPOINT", endpoint)
        .env(
            "MIGRATION_ENCRYPTION_KEY",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .output()
        .await
        .unwrap();
    server.abort();
    assert!(
        output.status.success(),
        "child test failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let seen = seen.lock().await;
    for expected in [
        "https://old.example.test/fresh?campaign=summer%20sale&source=play",
        "https://old.example.test/bare?utm_source=mail",
        "https://old.example.test/prefix/custom?utm_source=custom",
        "https://old.example.test/missing",
        "https://old.example.test/busy",
    ] {
        assert_eq!(
            seen.iter().filter(|url| *url == expected).count(),
            1,
            "{seen:?}"
        );
    }
    assert_eq!(
        seen.len(),
        6,
        "five lookups and one setup credential probe; retries use cache"
    );
}

async fn provider_resolution_case() {
    let f = Fixture::new().await;
    let (status, source) = f
        .call(
            "POST",
            &f.path("migrations"),
            json!({
                "provider":"branch","hostname":"old.example.test","provider_hosted":true,
                "credentials":{"branch_key":"test-branch-key"}
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{source}");
    for input in [
        referrer("https://old.example.test/fresh?campaign=summer%20sale&source=play"),
        "bare?utm_source=mail".into(),
        "demoapp://prefix/custom?utm_source=custom".into(),
    ] {
        let visitor = f.visitor().await;
        let (status, first) = resolve(&f, visitor, &input).await;
        assert_eq!(status, StatusCode::OK, "{input}: {first}");
        assert_eq!(first["data"], json!({"sku":"exact-product"}));
        assert_eq!(
            first["tracking"],
            json!({"campaign":"summer","source":"play","medium":"install"})
        );
        let id: Uuid = first["link_id"].as_str().unwrap().parse().unwrap();
        let expected: Value = sqlx::query_scalar("SELECT to_jsonb(l) FROM links l WHERE id=$1")
            .bind(id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
        assert_eq!(expected["project_id"], f.project.to_string());
        assert_link(&f, visitor, &input, &expected).await;
    }
    for input in ["https://old.example.test/missing", "busy"] {
        let visitor = f.visitor().await;
        assert_defaults(&f, visitor, input).await;
        assert_defaults(&f, visitor, input).await;
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM visitor_attributions WHERE visitor_id=$1")
                .bind(visitor)
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert_eq!(count, 0);
    }
    let caches: Vec<(String, String)> =
        sqlx::query_as("SELECT old_path,status FROM migrated_links ORDER BY old_path")
            .fetch_all(&f.pool)
            .await
            .unwrap();
    assert_eq!(
        caches,
        vec![
            ("bare".into(), "resolved".into()),
            ("busy".into(), "transient_error".into()),
            ("fresh".into(), "resolved".into()),
            ("missing".into(), "not_found".into()),
            ("prefix/custom".into(), "resolved".into()),
        ]
    );
    let links: i64 = sqlx::query_scalar("SELECT count(*) FROM links")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(links, 3);
    f.close().await;
}

async fn effect_snapshot(f: &Fixture) -> Value {
    let mut snapshot = serde_json::Map::new();
    for table in [
        "visitors",
        "visitor_attributions",
        "visitor_aliases",
        "link_clicks",
        "events",
        "links",
        "migration_sources",
        "migrated_links",
    ] {
        let rows: Value = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text), '[]') FROM {table} t"
        ))).fetch_one(&f.pool).await.unwrap();
        snapshot.insert(table.into(), rows);
    }
    Value::Object(snapshot)
}
