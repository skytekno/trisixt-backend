mod support;
use axum::http::StatusCode;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use support::Fixture;
use uuid::Uuid;
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn management_statistics_sort_search_and_paginate_without_losing_zero_activity() {
    let f = Fixture::new().await;
    let visitor = f.visitor().await;
    let (status, campaign) = f
        .call("POST", &f.path("campaigns"), json!({"name":"Summer"}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{campaign}");
    let mut links = vec![];
    for (name, path) in [
        ("A zero", "zero"),
        ("B small", "small"),
        ("C large", "large"),
    ] {
        let(s,l)=f.call("POST",&f.path("links"),json!({"name":name,"path":path,"campaign_id":campaign["id"],"title":"Promotion","tags":["Summer","Mobile"],"ads_platform":"google"})).await;
        assert_eq!(s, StatusCode::CREATED, "{l}");
        links.push(l);
    }
    for (i, n) in [(1, 1), (2, 3)] {
        for _ in 0..n {
            f.event(
                visitor,
                "view",
                Utc::now() - Duration::hours(1),
                json!({"link_id":links[i]["id"],"platform":"ios"}),
            )
            .await;
        }
    }
    f.event(
        visitor,
        "time_spent",
        Utc::now() - Duration::hours(1),
        json!({"link_id":links[2]["id"],"platform":"ios","engagement_time":1200}),
    )
    .await;
    for (ascending, expected) in [(false, vec![2, 1, 0]), (true, vec![1, 2, 0])] {
        let (s, b) = f
            .call(
                "POST",
                &f.path("links/search_v2"),
                json!({"sort_by":"views","ascending":ascending}),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["meta"]["total_entries"], 3);
        for (i, j) in expected.into_iter().enumerate() {
            assert_eq!(b["links"][i]["id"], links[j]["id"]);
        }
    }
    let(s,b)=f.call("POST",&f.path("links/search_v2"),json!({"term":"mobile","tags":["Summer"],"sort_by":"time_spent","per_page":1,"ads_platform":"google"})).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["links"][0]["total_time_spent"], 1200.0);
    assert_eq!(b["next_offset"], 1);
    assert_eq!(b["meta"]["total_pages"], 3);
    let (s, b) = f
        .call(
            "POST",
            &f.path("campaigns/search_v2"),
            json!({"sort_by":"views"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["campaigns"][0]["total_views"], 4);
    let (s, b) = f
        .call(
            "POST",
            &f.path("links/search"),
            json!({"platform":"android"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(
        b["links"]
            .as_array()
            .unwrap()
            .iter()
            .all(|l| l["total_views"] == 0)
    );
    for payload in [
        json!({"sort_by":"name;DROP TABLE links"}),
        json!({"sort_order":"x"}),
        json!({"page":0}),
        json!({"limit":1001}),
        json!({"start_date":"2000-01-01"}),
    ] {
        let (s, b) = f.call("POST", &f.path("links/search"), payload).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    }
    let (s, _) = f
        .call(
            "POST",
            &format!("/api/v1/projects/{}/links/search", Uuid::new_v4()),
            json!({}),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    f.close().await;
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn onboarding_is_idempotent_and_retention_is_owner_only() {
    let f = Fixture::new().await;
    let path = format!("/api/v1/instances/{}/setup_progress", f.instance);
    let (s, first) = f
        .call(
            "POST",
            &format!("{path}/complete"),
            json!({"category":"sdk","step_identifier":"install"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{first}");
    let (_, again) = f
        .call(
            "POST",
            &format!("{path}/complete"),
            json!({"category":"sdk","step_identifier":"install"}),
        )
        .await;
    assert_eq!(first, again);
    let (_, b) = f
        .call("GET", &format!("{path}?category=sdk"), Value::Null)
        .await;
    assert_eq!(b["steps"].as_array().unwrap().len(), 1);
    let path = format!("/api/v1/instances/{}/retention", f.instance);
    let (s, b) = f
        .call(
            "PUT",
            &path,
            json!({"cold_storage_days":365,"delete_days":180}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    sqlx::query("UPDATE instance_roles SET role='admin' WHERE user_id=$1")
        .bind(f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    let (s, b) = f
        .call(
            "PUT",
            &path,
            json!({"cold_storage_days":365,"delete_days":730}),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{b}");
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn concurrent_partial_link_edits_preserve_metadata_and_archive_can_be_reversed() {
    let f = Fixture::new().await;
    let (_, campaign) = f
        .call("POST", &f.path("campaigns"), json!({"name":"Keep"}))
        .await;
    let(s,link)=f.call("POST",&f.path("links"),json!({"name":"Partial","path":"partial","campaign_id":campaign["id"],"metadata":{"keep":true}})).await;
    assert_eq!(s, StatusCode::CREATED, "{link}");
    let path = f.path(&format!("links/{}", link["id"].as_str().unwrap()));
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..10 {
        let app = f.app.clone();
        let token = f.token.clone();
        let path = path.clone();
        tasks.spawn(async move {
            use tower::ServiceExt;
            let response = app
                .oneshot(
                    axum::http::Request::builder()
                        .method("PATCH")
                        .uri(path)
                        .header("authorization", format!("Bearer {token}"))
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(
                            json!({"metadata":{format!("field_{i}"):i}}).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    let (s, b) = f.call("GET", &path, Value::Null).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["metadata"].as_object().unwrap().len(), 11);
    for active in [false, true] {
        let (s, b) = f.call("PATCH", &path, json!({"active":active})).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["archived_at"].is_null(), active);
        assert_eq!(b["metadata"]["keep"], true);
    }
    let (s, b) = f
        .call(
            "PATCH",
            &f.path(&format!("campaigns/{}", campaign["id"].as_str().unwrap())),
            json!({"metadata":{"color":"red"}}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["name"], "Keep");
    f.close().await;
}
