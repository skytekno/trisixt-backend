mod support;
use axum::http::StatusCode;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use support::Fixture;
use uuid::Uuid;
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn explorer_filters_timezone_sort_cursor_fields_and_tenant_isolation() {
    let f = Fixture::new().await;
    let v = f.visitor().await;
    let at = Utc::now() - Duration::hours(1);
    let id=f.event(v,"view",at,json!({"platform":"ios","app_version":"2.0","event_name":"Home","country":"US","score":5})).await;
    f.event(
        v,
        "open",
        at + Duration::seconds(1),
        json!({"platform":"android","app_version":"3.0","event_name":"Cart","score":2}),
    )
    .await;
    let (s, b) = f
        .call(
            "GET",
            &f.path("analytics/events?limit=1&include_count=true"),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["count"], 2);
    let cursor = b["next_cursor"].as_str().unwrap();
    let (s, b) = f
        .call(
            "GET",
            &f.path(&format!("analytics/events?limit=1&cursor={cursor}")),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["data"][0]["event_id"], id.to_string());
    assert!(b["next_cursor"].is_null());
    for (field, op, value, count) in [
        ("platform", "is", json!("ios"), 1),
        ("event_name", "contains", json!("ho"), 1),
        ("user.plan", "eq", json!("pro"), 2),
        ("properties.score", "gt", json!(3), 1),
        ("country", "is_not_set", Value::Null, 0),
    ] {
        let filters = json!([{"field":field,"operator":op,"value":value}]).to_string();
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("filters", &filters)
            .finish();
        let (s, b) = f
            .call(
                "GET",
                &f.path(&format!("analytics/events?{query}")),
                Value::Null,
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{field}: {b}");
        assert_eq!(b["data"].as_array().unwrap().len(), count, "{field}: {b}");
    }
    for suffix in [
        "analytics/events/fields",
        "analytics/events/field-values?field=platform",
        "analytics/events/volume?timezone=Asia%2FJakarta",
        "analytics/overview/versions",
        "analytics/overview/versions/distribution",
        "analytics/overview/trends/users",
        "analytics/overview/sources/breakdown",
    ] {
        let (s, b) = f.call("GET", &f.path(suffix), Value::Null).await;
        assert_eq!(s, StatusCode::OK, "{suffix}: {b}");
    }
    let (s, _) = f
        .call(
            "GET",
            &format!("/api/v1/projects/{}/analytics/events", Uuid::new_v4()),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    for suffix in [
        "analytics/events?timezone=Wrong",
        "analytics/events?cursor=garbage",
        "analytics/events?limit=201",
        "analytics/events?sort_by=password_hash",
        "analytics/events/field-values?field=password_hash",
        "analytics/events?start_date=2000-01-01",
    ] {
        let (s, b) = f.call("GET", &f.path(suffix), Value::Null).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{suffix}: {b}");
    }
    f.close().await;
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn sessions_are_isolated_by_project_visitor_and_day() {
    let f = Fixture::new().await;
    let a = f.visitor().await;
    let b = f.visitor().await;
    let at = Utc::now() - Duration::days(1);
    for (v, t) in [
        (a, at),
        (a, at + Duration::seconds(12)),
        (b, at),
        (a, at - Duration::days(1)),
    ] {
        f.event(
            v,
            "view",
            t,
            json!({"session_id":"shared/id:with?bytes","platform":"ios"}),
        )
        .await;
    }
    let (s, rows) = f
        .call("GET", &f.path("analytics/sessions"), Value::Null)
        .await;
    assert_eq!(s, StatusCode::OK, "{rows}");
    assert_eq!(rows["data"].as_array().unwrap().len(), 3);
    let key = rows["data"][0]["id"].as_str().unwrap();
    let (s, detail) = f
        .call(
            "GET",
            &f.path(&format!("analytics/sessions/{key}")),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{detail}");
    let events = detail["events"].as_array().unwrap();
    assert_eq!(
        events.len(),
        detail["session"]["event_count"].as_u64().unwrap() as usize
    );
    assert!(
        events
            .iter()
            .all(|e| e["visitor_id"] == detail["session"]["visitor_id"])
    );
    f.close().await;
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn attribution_is_frozen_and_metrics_series_zero_fill() {
    let f = Fixture::new().await;
    let v = f.visitor().await;
    let (s, link) = f
        .call(
            "POST",
            &f.path("links"),
            json!({"name":"Promo","path":"promo","target_url":"https://example.com","metadata":{}}),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{link}");
    let link_id = link["id"].as_str().unwrap();
    let at = Utc::now() - Duration::days(1);
    f.event(v, "view", at, json!({"link_id":link_id,"platform":"ios"}))
        .await;
    let campaign = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO campaigns(project_id,name) VALUES($1,'Later') RETURNING id",
    )
    .bind(f.project)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    sqlx::query("UPDATE links SET campaign_id=$2 WHERE id=$1")
        .bind(link_id.parse::<Uuid>().unwrap())
        .bind(campaign)
        .execute(&f.pool)
        .await
        .unwrap();
    let (s, b) = f
        .call(
            "GET",
            &f.path("analytics/overview/sources/breakdown"),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["data"][0]["source"], "links");
    let (s, b) = f
        .call(
            "GET",
            &f.path("analytics/overview/key-metrics"),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["metrics"]["views"], 1);
    assert_eq!(b["metrics"]["link_views"], 1);
    sqlx::query("DELETE FROM links WHERE id=$1")
        .bind(link_id.parse::<Uuid>().unwrap())
        .execute(&f.pool)
        .await
        .unwrap();
    let (s, after_delete) = f
        .call(
            "GET",
            &f.path("analytics/overview/sources/breakdown"),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{after_delete}");
    assert_eq!(after_delete["data"][0]["source"], "links");
    assert_eq!(after_delete["data"][0]["metrics"]["link_views"], 1);
    let from = (Utc::now() - Duration::days(2)).date_naive();
    let to = Utc::now().date_naive();
    let (s, b) = f
        .call(
            "GET",
            &f.path(&format!(
                "analytics/overview/key-metrics/series?metric=views&start_date={from}&end_date={to}"
            )),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        b["points"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["value"].as_i64().unwrap())
            .collect::<Vec<_>>(),
        vec![0, 1, 0]
    );
    f.close().await;
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn retention_uses_mature_cohorts_and_does_not_count_null_left_join() {
    let f = Fixture::new().await;
    let (s, b) = f
        .call("GET", &f.path("analytics/retention/summary"), Value::Null)
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(b["day_1"].is_null(), "{b}");
    let a = f.visitor().await;
    let b = f.visitor().await;
    let at = Utc::now() - Duration::days(10);
    f.event(a, "install", at, json!({"platform":"ios"})).await;
    f.event(b, "install", at, json!({"platform":"ios"})).await;
    f.event(a, "open", at + Duration::days(7), json!({"platform":"ios"}))
        .await;
    let (s, b) = f
        .call("GET", &f.path("analytics/retention/summary"), Value::Null)
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["day_1"], 50.0);
    assert_eq!(b["day_7"], 50.0);
    assert!(b["day_30"].is_null(), "{b}");
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn golden_countable_users_install_requirement_platform_history_and_trends() {
    let f = Fixture::new().await;
    let cross = f.visitor().await;
    let new = f.visitor().await;
    let view = f.visitor().await;
    let custom = f.visitor().await;
    let referral = f.visitor().await;
    let today = Utc::now().date_naive();
    let at = (today - Duration::days(1))
        .and_hms_opt(12, 0, 0)
        .unwrap()
        .and_utc();
    f.event(
        cross,
        "app_open",
        at - Duration::days(60),
        json!({"platform":"android"}),
    )
    .await;
    f.event(cross, "install", at, json!({"platform":"ios"}))
        .await;
    f.event(new, "view", at, json!({"platform":"ios"})).await;
    f.event(
        new,
        "install",
        today.and_hms_opt(1, 0, 0).unwrap().and_utc(),
        json!({"platform":"ios"}),
    )
    .await;
    f.event(view, "view", at, json!({"platform":"ios"})).await;
    f.event(custom, "custom_only", at, json!({"platform":"ios"}))
        .await;
    for n in 0..2 {
        f.event(
            referral,
            "user_referred",
            at + Duration::seconds(n),
            json!({"platform":"ios"}),
        )
        .await;
    }
    let start = today - Duration::days(2);
    let range = format!("start_date={start}&end_date={today}");
    let (s, result) = f
        .call(
            "GET",
            &f.path(&format!("analytics/overview/key-metrics?{range}")),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{result}");
    let m = &result["metrics"];
    assert_eq!(m["total_users"], 4);
    assert_eq!(m["new_users"], 1);
    assert_eq!(m["returning_users"], 1);
    assert_eq!(m["returning_rate"], 0.25);
    assert_eq!(m["referred_users"], 2);
    assert_eq!(m["installs"], 2);
    let (s, ios) = f
        .call(
            "GET",
            &f.path(&format!(
                "analytics/overview/key-metrics?{range}&platform=ios"
            )),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{ios}");
    assert_eq!(ios["metrics"]["new_users"], 2);
    assert_eq!(ios["metrics"]["returning_users"], 0);
    let (s, series) = f
        .call(
            "GET",
            &f.path(&format!(
                "analytics/overview/key-metrics/series?{range}&metric=new_users"
            )),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{series}");
    assert_eq!(
        series["points"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["value"].as_i64().unwrap())
            .collect::<Vec<_>>(),
        vec![0, 1, 0],
        "first activity day, not later install day"
    );
    let (s, trends) = f
        .call(
            "GET",
            &f.path(&format!("analytics/overview/trends/users?{range}")),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{trends}");
    assert_eq!(trends["points"][1]["new_users"], 1);
    assert_eq!(trends["points"].as_array().unwrap().len(), 3);
    assert!(
        trends["points"][0]
            .get("previous_revenue_usd_cents")
            .is_some()
    );
    f.close().await;
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn golden_retention_uses_event_days_timezone_and_lifetime_filter_membership() {
    let f = Fixture::new().await;
    let a = f.visitor().await;
    let b = f.visitor().await;
    let day = Utc::now().date_naive() - Duration::days(10);
    let at = day.and_hms_opt(16, 30, 0).unwrap().and_utc();
    for v in [a, b] {
        f.event(
            v,
            "install",
            at,
            json!({"platform":"ios","event_name":"First"}),
        )
        .await;
    }
    f.event(
        a,
        "custom_return",
        at + Duration::hours(1),
        json!({"platform":"ios","event_name":"Later"}),
    )
    .await;
    let range = format!("start_date={day}&end_date={day}");
    let (s, utc) = f
        .call(
            "GET",
            &f.path(&format!("analytics/retention/summary?{range}")),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{utc}");
    assert_eq!(utc["day_1"], 0.0, "same UTC day is not a day-one return");
    let (s, local) = f
        .call(
            "GET",
            &f.path(&format!(
                "analytics/retention/summary?{range}&timezone=Asia%2FJakarta"
            )),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{local}");
    assert_eq!(local["day_1"], 50.0);
    assert_eq!(
        local["sparkline"][0]["rate"], 50.0,
        "profile last_seen_at is now for both visitors, but only one returned"
    );
    assert_eq!(local["median_churn_day"], 3);
    assert!(local["day_30"].is_null());
    let filters = json!([{"field":"event_name","operator":"is","value":"Later"}]).to_string();
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("filters", &filters)
        .finish();
    let (s, filtered) = f
        .call(
            "GET",
            &f.path(&format!(
                "analytics/retention/summary?{range}&timezone=Asia%2FJakarta&{query}"
            )),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{filtered}");
    assert_eq!(
        filtered["day_1"], 100.0,
        "matching return lies after cohort date range but must select its visitor"
    );
    f.close().await;
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn golden_sessions_stitch_blank_events_filter_summaries_and_join_real_purchases() {
    let f = Fixture::new().await;
    let a = f.visitor().await;
    let b = f.visitor().await;
    let day = Utc::now().date_naive() - Duration::days(1);
    let at = day.and_hms_opt(12, 0, 0).unwrap().and_utc();
    f.event(
        a,
        "view",
        at,
        json!({"platform":"ios","app_version":"1.0","country":"US","screen_name":"Home"}),
    )
    .await;
    f.event(
        a,
        "open",
        at + Duration::minutes(5),
        json!({"platform":"ios","app_version":"2.0","country":"US","session_id":"native-session"}),
    )
    .await;
    f.event(
        a,
        "time_spent",
        at + Duration::minutes(10),
        json!({"platform":"ios","app_version":"2.0","country":"DE","session_id":"native-session"}),
    )
    .await;
    f.event(
        a,
        "view",
        at + Duration::minutes(50),
        json!({"platform":"ios"}),
    )
    .await;
    f.event(
        b,
        "install",
        at,
        json!({"platform":"mac","session_id":"no-purchase"}),
    )
    .await;
    let(s,purchase)=f.call("POST","/api/v1/sdk/add_payment_event",json!({"visitor_id":a,"transaction_id":"session-order","product_id":"item","currency":"USD","price_cents":500,"date":at+Duration::minutes(7),"session_id":"native-session","platform":"ios"})).await;
    assert_eq!(s, StatusCode::OK, "{purchase}");
    let filters=json!([{"field":"country","operator":"is","value":"DE"},{"field":"has_conversion","operator":"is","value":"true"}]).to_string();
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("filters", &filters)
        .finish();
    let (s, rows) = f
        .call(
            "GET",
            &f.path(&format!("analytics/sessions?{query}")),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{rows}");
    assert_eq!(rows["data"].as_array().unwrap().len(), 1);
    let session = &rows["data"][0];
    assert_eq!(
        session["event_count"], 3,
        "filtering a summary must preserve its earlier events"
    );
    assert_eq!(session["duration_ms"], 600000.0);
    assert_eq!(session["revenue_usd_cents"], 500);
    assert_eq!(session["app_version"], "2.0");
    let (s, detail) = f
        .call(
            "GET",
            &f.path(&format!(
                "analytics/sessions/{}",
                session["id"].as_str().unwrap()
            )),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{detail}");
    assert_eq!(detail["events"].as_array().unwrap().len(), 3);
    assert!(
        detail["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["session_id"] == "native-session")
    );
    let (s, web) = f
        .call(
            "GET",
            &f.path("analytics/sessions?platform=web"),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{web}");
    assert_eq!(web["data"].as_array().unwrap().len(), 1);
    assert_eq!(
        web["data"][0]["has_conversion"], false,
        "install alone is not a monetary conversion"
    );
    let (s, all) = f
        .call("GET", &f.path("analytics/sessions"), Value::Null)
        .await;
    assert_eq!(s, StatusCode::OK, "{all}");
    assert_eq!(all["data"].as_array().unwrap().len(), 3);
    assert!(
        all["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["session_id"].as_str().unwrap().starts_with("synth_"))
    );
    f.close().await;
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn golden_event_snapshots_legacy_filters_volume_picker_and_revenue_buckets() {
    let f = Fixture::new().await;
    let v = f.visitor().await;
    let day = Utc::now().date_naive() - Duration::days(2);
    let at = day.and_hms_opt(23, 30, 0).unwrap().and_utc();
    f.event(
        v,
        "view",
        at,
        json!({"platform":"ios","event_name":"Home","score":5,"app_version":"2.0","basket":{"amount":12},"ads_platform":"search"}),
    )
    .await;
    sqlx::query(
        "UPDATE visitors SET attributes='{\"plan\":\"enterprise\"}' WHERE project_id=$1 AND id=$2",
    )
    .bind(f.project)
    .bind(v)
    .execute(&f.pool)
    .await
    .unwrap();
    f.event(
        v,
        "open",
        at + Duration::hours(1),
        json!({"platform":"android","event_name":"Basket","score":6,"app_version":"3.0"}),
    )
    .await;
    for (field, value, expected) in [
        ("user.plan", json!("pro"), "Home"),
        ("score", json!("5"), "Home"),
        ("basket.amount", json!("12"), "Home"),
        ("ads_platform", json!("search"), "Home"),
        ("platform", json!(["android"]), "Basket"),
    ] {
        let (s, result) = f
            .call(
                "POST",
                &f.path("events/search"),
                json!({"filters":[{"field":field,"operator":"is","value":value}]}),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{result}");
        assert_eq!(result["events"].as_array().unwrap().len(), 1);
        assert_eq!(result["events"][0]["event_name"], expected);
        assert!(result["events"][0]["properties"].is_null());
    }
    for filters in [
        json!({"f":"basket.amount","o":"is","v":"12"}),
        json!({"basket.amount":"12"}),
    ] {
        let (s, result) = f
            .call("POST", &f.path("events/search"), json!({"filters":filters}))
            .await;
        assert_eq!(s, StatusCode::OK, "{result}");
        assert_eq!(result["events"].as_array().unwrap().len(), 1);
    }
    let (s, fields) = f
        .call("GET", &f.path("analytics/events/fields"), Value::Null)
        .await;
    assert_eq!(s, StatusCode::OK, "{fields}");
    assert!(
        fields["fields"]
            .as_array()
            .unwrap()
            .contains(&json!({"name":"basket.amount","type":"property"}))
    );
    assert!(
        !fields["names"]
            .as_array()
            .unwrap()
            .contains(&json!("_attribution.source"))
    );
    let (s, nested) = f
        .call(
            "GET",
            &f.path("analytics/events/field-values?field=basket.amount"),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{nested}");
    assert_eq!(nested["values"], json!(["12"]));
    let (s, picker) = f
        .call(
            "GET",
            &f.path("analytics/events/field-values?field=app_version&limit=1"),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{picker}");
    assert_eq!(picker["values"][0], "2.0");
    let cursor = picker["next_cursor"].as_str().unwrap();
    let (s, next) = f
        .call(
            "GET",
            &f.path(&format!(
                "analytics/events/field-values?field=app_version&limit=1&cursor={cursor}"
            )),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{next}");
    assert_eq!(next["values"][0], "3.0");
    let range = format!("start_date={day}&end_date={}", day + Duration::days(1));
    let (s, buckets) = f
        .call(
            "GET",
            &f.path(&format!(
                "analytics/events/volume?{range}&bucket=hour&timezone=Asia%2FJakarta&search=home"
            )),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{buckets}");
    assert_eq!(buckets["buckets"].as_array().unwrap().len(), 1);
    assert_eq!(
        buckets["buckets"][0]["bucket"],
        format!("{} 06:00:00", day + Duration::days(1))
    );
    let(s,purchase)=f.call("POST","/api/v1/sdk/add_payment_event",json!({"visitor_id":v,"transaction_id":"timezone-order","product_id":"item","currency":"USD","price_cents":1234,"date":at,"platform":"ios"})).await;
    assert_eq!(s, StatusCode::OK, "{purchase}");
    let(s,series)=f.call("GET",&f.path(&format!("analytics/overview/key-metrics/series?{range}&metric=revenue&timezone=Asia%2FJakarta&platform=ios")),Value::Null).await;
    assert_eq!(s, StatusCode::OK, "{series}");
    assert_eq!(series["points"][0]["value"], 0);
    assert_eq!(series["points"][1]["value"], 1234);
    let (s, versions) = f
        .call(
            "GET",
            &f.path("analytics/overview/versions/distribution"),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{versions}");
    assert!(versions["entries"][0]["release_date"].is_string());
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn link_engagement_uses_canonical_engaged_sessions_and_mcp_excludes_bounces() {
    let f = Fixture::new().await;
    let link=sqlx::query_scalar::<_,Uuid>("INSERT INTO links(project_id,name,path,target_url)VALUES($1,'Engaged','engaged','https://example.com')RETURNING id").bind(f.project).fetch_one(&f.pool).await.unwrap();
    let bounce_link=sqlx::query_scalar::<_,Uuid>("INSERT INTO links(project_id,name,path,target_url)VALUES($1,'Bounce','bounce','https://example.com')RETURNING id").bind(f.project).fetch_one(&f.pool).await.unwrap();
    let at = (Utc::now().date_naive() - Duration::days(1))
        .and_hms_opt(12, 0, 0)
        .unwrap()
        .and_utc();
    for (index, seconds) in [(0, 10), (1, 30), (2, 0)] {
        let visitor = f.visitor().await;
        let props =
            json!({"link_id":link,"platform":"ios","session_id":format!("session-{index}")});
        f.event(visitor, "view", at, props.clone()).await;
        if seconds > 0 {
            f.event(visitor, "open", at + Duration::seconds(seconds), props)
                .await;
        }
    }
    let visitor = f.visitor().await;
    f.event(
        visitor,
        "view",
        at,
        json!({"link_id":bounce_link,"platform":"ios","session_id":"bounce-only"}),
    )
    .await;
    let (s, body) = f.call("GET", &f.path("analytics/links"), Value::Null).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let rows = body["links"].as_array().unwrap();
    assert_eq!(
        rows.iter()
            .find(|r| r["link_id"] == link.to_string())
            .unwrap()["metrics"]["avg_engagement_time"]
            .as_f64(),
        Some(20.0)
    );
    assert_eq!(
        rows.iter()
            .find(|r| r["link_id"] == bounce_link.to_string())
            .unwrap()["metrics"]["avg_engagement_time"]
            .as_f64(),
        Some(0.0)
    );
    let (s, body) = f
        .call(
            "GET",
            &f.path("analytics/links?platform=android"),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert!(body["links"].as_array().unwrap().is_empty());
    let client=sqlx::query_scalar::<_,Uuid>("INSERT INTO mcp_clients(name,redirect_uris)VALUES('Analytics','[\"https://client.example/cb\"]')RETURNING id").fetch_one(&f.pool).await.unwrap();
    let (access, hash) = trisixt::auth::new_token();
    let (_, refresh) = trisixt::auth::new_token();
    sqlx::query("INSERT INTO mcp_tokens(family_id,client_id,user_id,access_hash,refresh_hash,scope,issuer,audience,project_ids,expires_at,refresh_expires_at)VALUES($1,$2,$3,$4,$5,'mcp:read','https://example.test','https://example.test/api/v1/mcp',$6,now()+interval '1 hour',now()+interval '1 day')").bind(Uuid::new_v4()).bind(client).bind(f.user).bind(hash).bind(refresh).bind(vec![f.project]).execute(&f.pool).await.unwrap();
    let (s, body, _) = f
        .raw(
            "POST",
            "/api/v1/mcp/analytics/link",
            json!({"project_id":f.project,"path":"engaged"}),
            &access,
            "",
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["links"].as_array().unwrap().len(), 1);
    assert_eq!(
        body["links"][0]["metrics"]["avg_engagement_time"].as_f64(),
        Some(20.0)
    );
    let (s, _, _) = f
        .raw(
            "POST",
            "/api/v1/mcp/analytics/link",
            json!({"project_id":Uuid::new_v4(),"path":"engaged"}),
            &access,
            "",
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, defaults) = f.call("GET", &f.path("domain/defaults"), Value::Null).await;
    assert_eq!(s, StatusCode::OK, "{defaults}");
    assert!(!defaults["generic_title"].as_str().unwrap().is_empty());
    assert!(defaults["generic_subtitle"].is_string());
    assert!(defaults.get("generic_image_url").is_some());
    let (s, _) = f
        .call(
            "GET",
            &format!("/api/v1/projects/{}/domain/defaults", Uuid::new_v4()),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    f.close().await;
}
