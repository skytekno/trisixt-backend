use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use trisixt::{
    auth::{AuthUser, InternalPrincipal},
    mcp::{validate_redirect, verify_pkce},
};
use uuid::Uuid;
#[test]
fn oauth_redirects_and_pkce_reject_substitution() {
    for good in [
        "https://client.example/callback",
        "http://127.0.0.1:3001/callback",
        "http://localhost/cb",
    ] {
        assert!(validate_redirect(good).is_ok());
    }
    for bad in [
        "http://attacker.example/callback",
        "javascript:alert(1)",
        "https://user:password@example.com/cb",
        "https://example.com/cb#token",
        "/relative",
    ] {
        assert!(validate_redirect(bad).is_err());
    }
    let verifier = "a".repeat(43);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    assert!(verify_pkce(&verifier, &challenge));
    assert!(!verify_pkce(&"b".repeat(43), &challenge));
    assert!(!verify_pkce("short", &challenge));
}
async fn request(
    app: axum::Router,
    path: &str,
    body: Value,
    user: Option<AuthUser>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(u) = user {
        req = req
            .extension(InternalPrincipal(u))
            .header("authorization", format!("Bearer {}", "d".repeat(64)));
    }
    let response = app
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
async fn form(app: axum::Router, values: &[(&str, String)]) -> (StatusCode, Value) {
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(values.iter().map(|(k, v)| (*k, v)))
        .finish();
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(encoded))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let b = axum::body::to_bytes(res.into_body(), 100000).await.unwrap();
    (status, serde_json::from_slice(&b).unwrap())
}
async fn state() -> (trisixt::state::AppState, sqlx::PgPool, String) {
    use std::sync::Arc;
    use trisixt::config::{AnalyticsBackend, Config, StorageBackend};
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL required");
    let admin = sqlx::PgPool::connect(&url).await.unwrap();
    let schema = format!("test_mcp_{}", Uuid::new_v4().simple());
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
async fn codes_pkce_resource_scopes_and_refresh_replay_are_enforced() {
    let (st, admin, schema) = state().await;
    let app = trisixt::mcp::router().with_state(st.clone());
    let user = AuthUser {
        id: Uuid::new_v4(),
        email: "mcp@example.test".into(),
    };
    sqlx::query("INSERT INTO users(id,email)VALUES($1,$2)")
        .bind(user.id)
        .bind(&user.email)
        .execute(&st.pg)
        .await
        .unwrap();
    sqlx::query("INSERT INTO access_tokens(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '1 hour')").bind(user.id).bind(trisixt::auth::token_hash(&"d".repeat(64))).execute(&st.pg).await.unwrap();
    let instance =
        sqlx::query_scalar::<_, Uuid>("INSERT INTO instances(name)VALUES('MCP') RETURNING id")
            .fetch_one(&st.pg)
            .await
            .unwrap();
    sqlx::query("INSERT INTO instance_roles(user_id,instance_id,role)VALUES($1,$2,'owner')")
        .bind(user.id)
        .bind(instance)
        .execute(&st.pg)
        .await
        .unwrap();
    let project=sqlx::query_scalar::<_,Uuid>("INSERT INTO projects(instance_id,environment,domain)VALUES($1,'production','mcp.example.test')RETURNING id").bind(instance).fetch_one(&st.pg).await.unwrap();
    let (s, client) = request(
        app.clone(),
        "/register",
        json!({"client_name":"Test client","redirect_uris":["https://client.example/callback"]}),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{client}");
    let client = client["client_id"].as_str().unwrap().to_owned();
    let verifier = "x".repeat(43);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let resource = "https://example.test/api/v1/mcp";
    let auth = json!({"client_id":client,"redirect_uri":"https://client.example/callback","code_challenge":challenge,"code_challenge_method":"S256","resource":resource,"scope":"mcp:read","project_ids":[project]});
    let mut attack = auth.clone();
    attack["project_ids"] = json!([Uuid::new_v4()]);
    assert_eq!(
        request(
            app.clone(),
            "/api/v1/mcp/approve_consent",
            attack,
            Some(user.clone())
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (s, approved) = request(app.clone(), "/api/v1/mcp/approve_consent", auth, Some(user)).await;
    assert_eq!(s, StatusCode::OK, "{approved}");
    let code = approved["code"].as_str().unwrap().to_owned();
    let fields = vec![
        ("grant_type", "authorization_code".into()),
        ("client_id", client.clone()),
        ("code", code),
        ("redirect_uri", "https://client.example/callback".into()),
        ("code_verifier", verifier),
        ("resource", resource.into()),
    ];
    let mut bad = fields.clone();
    bad[4].1 = "y".repeat(43);
    assert_eq!(form(app.clone(), &bad).await.1["error"], "invalid_grant");
    bad = fields.clone();
    bad[5].1 = "https://other.example/api/v1/mcp".into();
    assert_eq!(form(app.clone(), &bad).await.1["error"], "invalid_target");
    let (s, tokens) = form(app.clone(), &fields).await;
    assert_eq!(s, StatusCode::OK, "{tokens}");
    assert_eq!(form(app.clone(), &fields).await.1["error"], "invalid_grant");
    let access = tokens["access_token"].as_str().unwrap();
    for (method, params) in [
        (
            "initialize",
            json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}),
        ),
        ("tools/list", json!({})),
        (
            "tools/call",
            json!({"name":"search_links","arguments":{"project_id":project}}),
        ),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/mcp")
            .header("authorization", format!("Bearer {access}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string(),
            ))
            .unwrap();
        let r = app.clone().oneshot(request).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(r.into_body(), 1_000_000)
            .await
            .unwrap();
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(result["error"].is_null(), "{result}");
        if method == "tools/list" {
            assert_eq!(result["result"]["tools"].as_array().unwrap().len(), 14)
        }
        if method == "tools/call" {
            assert_eq!(result["result"]["isError"], false, "{result}");
        }
    }

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/mcp/links")
        .header("authorization", format!("Bearer {access}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"project_id":project,"name":"must not create"}).to_string(),
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let refresh = vec![
        ("grant_type", "refresh_token".into()),
        ("client_id", client),
        (
            "refresh_token",
            tokens["refresh_token"].as_str().unwrap().into(),
        ),
        ("resource", resource.into()),
    ];
    let (s, rotated) = form(app.clone(), &refresh).await;
    assert_eq!(s, StatusCode::OK, "{rotated}");
    assert_eq!(
        form(app.clone(), &refresh).await.1["error"],
        "invalid_grant"
    );
    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/mcp/status")
                .header(
                    "authorization",
                    format!("Bearer {}", rotated["access_token"].as_str().unwrap()),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert!(
        res.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("resource_metadata")
    );
    st.pg.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&admin)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn provisioning_creates_atomic_pair_and_one_time_hashed_credentials() {
    let (st, admin, schema) = state().await;
    let user = AuthUser {
        id: Uuid::new_v4(),
        email: "provision@example.test".into(),
    };
    sqlx::query("INSERT INTO users(id,email)VALUES($1,$2)")
        .bind(user.id)
        .bind(&user.email)
        .execute(&st.pg)
        .await
        .unwrap();
    let app = trisixt::routes::router(st.clone());
    let (status, result) = request(
        app,
        "/api/v1/instances/provision",
        json!({"name":"Pair"}),
        Some(user.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    let projects = result["instance"]["projects"].as_array().unwrap();
    assert_eq!(projects.len(), 2);
    assert_ne!(projects[0]["domain"], projects[1]["domain"]);
    let server = result["server_key"].as_str().unwrap();
    for project in projects {
        let p: Uuid = project["id"].as_str().unwrap().parse().unwrap();
        let hash = sqlx::query_scalar::<_, String>(
            "SELECT token_hash FROM project_api_keys WHERE project_id=$1",
        )
        .bind(p)
        .fetch_one(&st.pg)
        .await
        .unwrap();
        assert_eq!(
            hash,
            trisixt::auth::token_hash(project["sdk_key"].as_str().unwrap())
        );
        let environment = project["environment"].as_str().unwrap();
        assert_eq!(
            trisixt::automation::authenticate_key(&st, server, environment)
                .await
                .unwrap(),
            p
        );
        let config = sqlx::query_scalar::<_, Value>(
            "SELECT redirect FROM project_configurations WHERE project_id=$1",
        )
        .bind(p)
        .fetch_one(&st.pg)
        .await
        .unwrap();
        assert_eq!(config["uri_scheme"], result["instance"]["uri_scheme"]);
    }
    let count = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM instances")
        .fetch_one(&st.pg)
        .await
        .unwrap();
    assert!(
        trisixt::provisioning::provision(&st, &user, "")
            .await
            .is_err()
    );
    assert_eq!(
        count,
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM instances")
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

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn redirect_configuration_accepts_safe_custom_fallbacks_and_rejects_scripts() {
    let (st, admin, schema) = state().await;
    let user = AuthUser {
        id: Uuid::new_v4(),
        email: "redirects@example.test".into(),
    };
    sqlx::query("INSERT INTO users(id,email)VALUES($1,$2)")
        .bind(user.id)
        .bind(&user.email)
        .execute(&st.pg)
        .await
        .unwrap();
    let pair = trisixt::provisioning::provision(&st, &user, "Redirect")
        .await
        .unwrap();
    let project: Uuid = pair["instance"]["projects"][0]["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let client=sqlx::query_scalar::<_,Uuid>("INSERT INTO mcp_clients(name,redirect_uris)VALUES('Redirects','[\"https://client.example/cb\"]')RETURNING id").fetch_one(&st.pg).await.unwrap();
    let (access, hash) = trisixt::auth::new_token();
    let (_, refresh) = trisixt::auth::new_token();
    sqlx::query("INSERT INTO mcp_tokens(family_id,client_id,user_id,access_hash,refresh_hash,scope,issuer,audience,project_ids,expires_at,refresh_expires_at)VALUES($1,$2,$3,$4,$5,'mcp:write','https://example.test','https://example.test/api/v1/mcp',$6,now()+interval '1 hour',now()+interval '1 day')").bind(Uuid::new_v4()).bind(client).bind(user.id).bind(hash).bind(refresh).bind(vec![project]).execute(&st.pg).await.unwrap();
    let app = trisixt::routes::router(st.clone());
    for (fallback, appstore, status) in [
        ("custom-app://product/42", json!(false), StatusCode::OK),
        ("javascript:alert(1)", json!(false), StatusCode::BAD_REQUEST),
        ("https://example.com", json!(17), StatusCode::BAD_REQUEST),
    ] {
        let response=app.clone().oneshot(Request::builder().method("PUT").uri("/api/v1/mcp/redirects").header("authorization",format!("Bearer {access}")).header("content-type","application/json").body(Body::from(json!({"project_id":project,"platforms":{"ios":{"variation":"phone","fallback_url":fallback,"appstore":appstore}}}).to_string())).unwrap()).await.unwrap();
        assert_eq!(response.status(), status);
    }
    let config = sqlx::query_scalar::<_, Value>(
        "SELECT redirect FROM project_configurations WHERE project_id=$1",
    )
    .bind(project)
    .fetch_one(&st.pg)
    .await
    .unwrap();
    assert_eq!(config["ios_phone"]["fallback"], "custom-app://product/42");
    assert_eq!(config["ios_phone"]["appstore"], false);
    st.pg.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&admin)
        .await
        .unwrap();
}
