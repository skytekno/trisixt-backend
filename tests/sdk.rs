mod support;
use axum::http::{HeaderMap, StatusCode};
use serde_json::{Value, json};
use support::Fixture;
use uuid::Uuid;
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn device_identity_vendor_scope_attributes_and_screen_aliases() {
    let f = Fixture::new().await;
    let payload = json!({"vendor":"phone-one","app_version":"2.1","platform":"ios","push_token":"test-token","model":"iPhone"});
    let (s, b) = f
        .call("POST", "/api/v1/sdk/authenticate", payload.clone())
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let visitor = b["visitor_id"].as_str().unwrap();
    let (s, again) = f.call("POST", "/api/v1/sdk/authenticate", payload).await;
    assert_eq!(s, StatusCode::OK, "{again}");
    assert_eq!(again["visitor_id"], visitor);
    assert_eq!(again["device_id"], b["device_id"]);
    let(s,b)=f.call("POST","/api/v1/sdk/visitor_attributes",json!({"visitor_id":visitor,"sdk_identifier":"account-42","attributes":{"plan":"paid"}})).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let (s, b) = f
        .call(
            "GET",
            &format!("/api/v1/sdk/visitor_attributes?visitor_id={visitor}"),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["attributes"]["plan"], "paid");
    let(s,b)=f.call("POST","/api/v1/sdk/screen_aliases",json!({"screen_aliases":[{"identifier":"home","name":"First"},{"identifier":"home","name":"Home"},{"identifier":" ","name":"Ignored"}]})).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["saved"], 1);
    let name =
        sqlx::query_scalar::<_, String>("SELECT name FROM screen_aliases WHERE project_id=$1")
            .bind(f.project)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(name, "Home");
    let (s, b) = f
        .call(
            "GET",
            "/api/v1/sdk/device_for_vendor_id?vendor_id=phone-one",
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["visitor_id"], visitor);
    let (s, b) = f
        .call(
            "GET",
            "/api/v1/sdk/device_for_vendor_id?vendor_id=",
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(b.is_null());
    f.close().await;
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn clipboard_deferred_link_consumption_merges_identity_once() {
    let f = Fixture::new().await;
    let(s,l)=f.call("POST",&f.path("links"),json!({"name":"Welcome","path":"welcome","target_url":"https://example.com","data":{"screen":"welcome"},"tracking_campaign":"launch","custom_redirects":{"ios":{"url":"demoapp://welcome","open_app":true}}})).await;
    assert_eq!(s, StatusCode::CREATED, "{l}");
    let link = l["id"].as_str().unwrap().parse::<Uuid>().unwrap();
    let context = trisixt::sdk::ClientContext {
        ip: Some("127.0.0.1".parse().unwrap()),
        user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15"
            .into(),
    };
    let click = trisixt::sdk::record_click(&f.state, f.project, link, &HeaderMap::new(), &context)
        .await
        .unwrap();
    let visitor = f.visitor().await;
    let body = json!({"visitor_id":visitor,"clipboard_token":click.clipboard,"platform":"ios"});
    let (s, b) = f
        .call("POST", "/api/v1/sdk/data_for_device", body.clone())
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["data"]["screen"], "welcome");
    let (s, b) = f
        .call(
            "POST",
            "/api/v1/sdk/clipboard_status",
            json!({"clipboard_token":click.clipboard}),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["available"], false);
    let (s, b) = f.call("POST", "/api/v1/sdk/data_for_device", body).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let opens = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM events WHERE project_id=$1 AND event_type='open'",
    )
    .bind(f.project)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(opens, 1);
    assert_eq!(
        trisixt::sdk::canonical(&f.state, f.project, click.visitor)
            .await
            .unwrap(),
        visitor
    );
    let (s, b) = f
        .call(
            "PATCH",
            &f.path(&format!("links/{link}")),
            json!({"title":"Updated","show_preview_ios":true}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["path"], "welcome");
    assert_eq!(b["metadata"]["data"]["screen"], "welcome");
    f.close().await;
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn forged_clipboard_foreign_urls_and_unsafe_deep_links_do_not_claim_identity() {
    let f = Fixture::new().await;
    let visitor = f.visitor().await;
    let (s, b) = f
        .call(
            "POST",
            "/api/v1/sdk/data_for_device_and_url",
            json!({"visitor_id":visitor,"url":"https://foreign.example/welcome?ct=forged"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(b["data"].is_null());
    for url in [
        "javascript:alert(1)",
        "data:text/html,test",
        "https://user:pass@example.com",
    ] {
        let (s, b) = f
            .call(
                "POST",
                &f.path("links"),
                json!({"name":"Unsafe","ios_url":url}),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    }
    let (s, b) = f
        .call(
            "POST",
            "/api/v1/sdk/data_for_device",
            json!({"visitor_id":Uuid::new_v4(),"clipboard_token":"forged"}),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{b}");
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL via TEST_DATABASE_URL; run scripts/integration.sh"]
async fn failed_deferred_delivery_resumes_same_claim_without_duplicate_open() {
    let f = Fixture::new().await;
    let(s,link)=f.call("POST",&f.path("links"),json!({"name":"Retry","path":"retry","target_url":"https://example.com","data":{"retry":true}})).await;
    assert_eq!(s, StatusCode::CREATED, "{link}");
    let link: Uuid = link["id"].as_str().unwrap().parse().unwrap();
    let visitor = f.visitor().await;
    let context = trisixt::sdk::ClientContext {
        ip: Some("127.0.0.1".parse().unwrap()),
        user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15"
            .into(),
    };
    let click = trisixt::sdk::record_click(&f.state, f.project, link, &HeaderMap::new(), &context)
        .await
        .unwrap();
    sqlx::query("CREATE FUNCTION test_fail_open() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='open' THEN RAISE EXCEPTION 'temporary test failure'; END IF; RETURN NEW; END $$").execute(&f.pool).await.unwrap();
    sqlx::query("CREATE TRIGGER test_open_failure BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION test_fail_open()").execute(&f.pool).await.unwrap();
    let body = json!({"visitor_id":visitor,"clipboard_token":click.clipboard});
    let (s, _) = f
        .call("POST", "/api/v1/sdk/data_for_device", body.clone())
        .await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
    let claim: (Uuid, bool) =
        sqlx::query_as("SELECT claimed_by,handled_at IS NULL FROM link_clicks WHERE project_id=$1")
            .bind(f.project)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(claim, (visitor, true));
    let other = f.visitor().await;
    let (s, data) = f
        .call(
            "POST",
            "/api/v1/sdk/data_for_device",
            json!({"visitor_id":other,"clipboard_token":click.clipboard}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{data}");
    assert!(data["data"].is_null());
    sqlx::query("DROP TRIGGER test_open_failure ON events")
        .execute(&f.pool)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        f.call("POST", "/api/v1/sdk/data_for_device", body.clone()),
        f.call("POST", "/api/v1/sdk/data_for_device", body)
    );
    assert_eq!(a.0, StatusCode::OK, "{:?}", a);
    assert_eq!(b.0, StatusCode::OK, "{:?}", b);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM events WHERE project_id=$1 AND event_type='open'")
            .bind(f.project)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    let handled: bool =
        sqlx::query_scalar("SELECT handled_at IS NOT NULL FROM link_clicks WHERE project_id=$1")
            .bind(f.project)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert!(handled);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL via TEST_DATABASE_URL; run scripts/integration.sh"]
async fn identity_merge_preserves_revenue_billing_and_pending_notifications() {
    let f = Fixture::new().await;
    let from = f.visitor().await;
    let to = f.visitor().await;
    f.event(from, "view", chrono::Utc::now(), json!({})).await;
    f.event(to, "view", chrono::Utc::now(), json!({})).await;
    for (visitor, transaction) in [(from, "source"), (to, "target")] {
        let(s,b)=f.call("POST","/api/v1/sdk/add_payment_event",json!({"visitor_id":visitor,"transaction_id":transaction,"original_transaction_id":transaction,"product_id":"plan","purchase_kind":"subscription","currency":"USD","price_cents":1000})).await;
        assert_eq!(s, StatusCode::OK, "{b}");
    }
    let device:Uuid=sqlx::query_scalar("INSERT INTO devices(project_id,visitor_id,user_agent,app_version,platform) VALUES($1,$2,'Test','1','ios') RETURNING id").bind(f.project).bind(from).fetch_one(&f.pool).await.unwrap();
    let notification:Uuid=sqlx::query_scalar("INSERT INTO notifications(project_id,title,new_users,existing_users) VALUES($1,'Notice',false,true) RETURNING id").bind(f.project).fetch_one(&f.pool).await.unwrap();
    for visitor in [from, to] {
        let message:Uuid=sqlx::query_scalar("INSERT INTO notification_messages(project_id,visitor_id,notification_id) VALUES($1,$2,$3) RETURNING id").bind(f.project).bind(visitor).bind(notification).fetch_one(&f.pool).await.unwrap();
        sqlx::query("INSERT INTO push_outbox(project_id,message_id,device_id) VALUES($1,$2,$3)")
            .bind(f.project)
            .bind(message)
            .bind(device)
            .execute(&f.pool)
            .await
            .unwrap();
    }
    trisixt::sdk::merge_visitors(&f.state, f.project, from, to)
        .await
        .unwrap();
    let totals:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM monthly_active_visitors WHERE instance_id=$1),(SELECT count(DISTINCT visitor_id) FROM purchase_ledger WHERE project_id=$2),(SELECT count(*) FROM push_outbox WHERE project_id=$2 AND sent_at IS NULL)").bind(f.instance).bind(f.project).fetch_one(&f.pool).await.unwrap();
    assert_eq!(totals, (1, 1, 1));
    let owners:Vec<Uuid>=sqlx::query_scalar("SELECT visitor_id FROM verified_purchases WHERE project_id=$1 UNION SELECT visitor_id FROM subscription_states WHERE project_id=$1 UNION SELECT visitor_id FROM notification_messages WHERE project_id=$1").bind(f.project).fetch_all(&f.pool).await.unwrap();
    assert_eq!(owners, vec![to]);
    let(s,b)=f.call("POST","/api/v1/sdk/add_payment_event",json!({"visitor_id":from,"transaction_id":"source","product_id":"plan","purchase_kind":"subscription","currency":"USD","price_cents":1000})).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["duplicate"], true);
    f.event(from, "app_open", chrono::Utc::now(), json!({}))
        .await;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM monthly_active_visitors WHERE instance_id=$1")
            .bind(f.instance)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn linked_web_domains_and_declared_app_identifiers_are_enforced() {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    let f = Fixture::new().await;
    let (s, b) = f
        .call(
            "PUT",
            &f.path("configurations/web"),
            json!({"enabled":true,"domains":["Web.Example.test","https://other.example.test"]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    for (platform, identifier, origin, expected) in [
        (Some("web"), Some("web.example.test"), None, StatusCode::OK),
        (
            Some("web"),
            Some("evil.example.test"),
            None,
            StatusCode::FORBIDDEN,
        ),
        (Some("web"), None, None, StatusCode::FORBIDDEN),
        (
            None,
            None,
            Some("https://other.example.test"),
            StatusCode::OK,
        ),
        (
            None,
            None,
            Some("https://evil.example.test"),
            StatusCode::FORBIDDEN,
        ),
        (
            Some("web"),
            Some("web.example.test"),
            Some("https://evil.example.test"),
            StatusCode::FORBIDDEN,
        ),
    ] {
        let mut request = Request::builder()
            .uri("/api/v1/sdk/configurations")
            .header("project-key", &f.key);
        if let Some(value) = platform {
            request = request.header("platform", value);
        }
        if let Some(value) = identifier {
            request = request.header("identifier", value);
        }
        if let Some(value) = origin {
            request = request.header("origin", value);
        }
        let response = f
            .app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            expected,
            "{platform:?} {identifier:?} {origin:?}"
        );
    }
    for domains in [
        json!(["https://user:pass@example.test"]),
        json!(["*.example.test"]),
        json!(["https://example.test/path"]),
        json!("example.test"),
    ] {
        let (s, b) = f
            .call(
                "PUT",
                &f.path("configurations/web"),
                json!({"domains":domains}),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    }
    let (s, b) = f
        .call(
            "PUT",
            &f.path("configurations/ios"),
            json!({"bundle_id":"com.example.app","enabled":true}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    for (identifier, expected) in [
        ("com.example.app", StatusCode::OK),
        ("com.other.app", StatusCode::FORBIDDEN),
    ] {
        let response = f
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/sdk/configurations")
                    .header("x-project-key", &f.key)
                    .header("platform", "ios")
                    .header("identifier", identifier)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    let (s, b) = f
        .call("DELETE", &f.path("configurations/web"), Value::Null)
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["web"], json!({}));
    f.close().await;
}
