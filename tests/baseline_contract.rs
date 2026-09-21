mod support;

use axum::http::StatusCode;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path};
use support::baseline::{Baseline, Contract};
use uuid::Uuid;

#[test]
fn deterministic_contract_has_stable_ids_isolated_runs_and_intact_assets() {
    let anchor = "2026-09-18T00:00:00Z".parse().unwrap();
    let contract = Contract::load("man5-reference", anchor);
    assert_eq!(
        contract.id("project_a").to_string(),
        "5bb1d807-da0c-8766-98d9-3a64712bae02"
    );
    assert_eq!(
        contract.id("event_a_view_alias").to_string(),
        "3b9e3080-6f5a-8d8d-b7e7-236acb486c2f"
    );
    let same = Contract::load("man5-reference", anchor);
    assert_eq!(contract.ids, same.ids);
    let other = Contract::load("man5-other", anchor);
    let first_ids: BTreeSet<_> = contract.ids.values().collect();
    assert_eq!(first_ids.len(), contract.ids.len());
    assert!(other.ids.values().all(|id| !first_ids.contains(id)));

    let combinations: BTreeSet<_> = contract.data["provider_matrix"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["ANALYTICS_BACKEND"].as_str().unwrap(),
                p["STORAGE_BACKEND"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        combinations,
        BTreeSet::from([
            ("clickhouse", "s3"),
            ("clickhouse", "gcs"),
            ("bigquery", "s3"),
            ("bigquery", "gcs")
        ])
    );
    for asset in contract.data["assets"].as_array().unwrap() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/baseline")
            .join(asset["file"].as_str().unwrap());
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(bytes.len() as u64, asset["bytes"].as_u64().unwrap());
        assert_eq!(hex::encode(Sha256::digest(&bytes)), asset["sha256"]);
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via scripts/integration.sh"]
async fn shared_contract_replays_isolates_tenants_and_preserves_numeric_oracles() {
    let run_id = format!("native-{}", Uuid::new_v4().simple());
    let anchor = (Utc::now() - Duration::days(1))
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .and_utc();
    let baseline = Baseline::new(&run_id, anchor).await;
    let contract = &baseline.contract;
    let a = contract.id("project_a");
    let b = contract.id("project_b");
    let pool = &baseline.fixture.pool;
    let data = &contract.data;

    // Repeat migration must preserve the seeded two-owner fixture.
    sqlx::migrate!("./migrations").run(pool).await.unwrap();
    let owner_count: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(owner_count, 2);

    let auth = &data["sdk_authentication"];
    let (status, authenticated) = baseline
        .call(
            a,
            "POST",
            auth["path"].as_str().unwrap(),
            auth["request"].clone(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{authenticated}");
    assert_eq!(authenticated["visitor_id"], auth["expected"]["visitor_id"]);
    assert_eq!(authenticated["uri_scheme"], auth["expected"]["uri_scheme"]);
    let device_id: Uuid = authenticated["device_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(!device_id.is_nil());
    let (repeat_status, repeated) = baseline
        .call(
            a,
            "POST",
            auth["path"].as_str().unwrap(),
            auth["request"].clone(),
        )
        .await;
    assert_eq!(repeat_status, StatusCode::OK, "{repeated}");
    assert_eq!(repeated["device_id"], authenticated["device_id"]);

    for (key, project) in [("project_a", a), ("project_b", b)] {
        let events: Vec<_> = data["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["project_id"] == project.to_string())
            .map(|e| e["request"].clone())
            .collect();
        let (status, actual) = baseline
            .call(
                project,
                "POST",
                "/api/v1/sdk/events",
                json!({"events":events}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{actual}");
        assert_eq!(actual, data["expected"]["initial_ingestion"][key]);
        let (status, actual) = baseline
            .call(project, "POST", "/api/v1/sdk/event", events[0].clone())
            .await;
        assert_eq!(status, StatusCode::OK, "{actual}");
        assert_eq!(actual, json!({"accepted":0,"duplicates":1}));
        let counts: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM events WHERE project_id=$1),(SELECT count(*) FROM analytics_outbox WHERE project_id=$1),(SELECT count(DISTINCT visitor_id) FROM events WHERE project_id=$1)")
            .bind(project).fetch_one(pool).await.unwrap();
        let expected = &data["expected"]["event_ledgers"][key];
        assert_eq!(
            counts,
            (
                expected["events"].as_i64().unwrap(),
                expected["outbox_rows"].as_i64().unwrap(),
                expected["raw_distinct_visitors"].as_i64().unwrap()
            )
        );
    }

    for (method, path, body) in [
        ("GET", format!("/api/v1/projects/{a}/events"), Value::Null),
        (
            "PUT",
            format!("/api/v1/projects/{a}/configurations/ios"),
            json!({"enabled":false}),
        ),
        (
            "GET",
            format!("/api/v1/projects/{a}/objects/baseline/private.svg"),
            Value::Null,
        ),
    ] {
        assert_eq!(
            baseline.call(b, method, &path, body).await.0,
            StatusCode::FORBIDDEN
        );
    }
    let mut foreign_link = data["events"][4]["request"].clone();
    foreign_link["event_id"] = json!(Uuid::new_v4());
    foreign_link["properties"]["link_id"] = json!(contract.id("link_a"));
    assert_eq!(
        baseline
            .call(b, "POST", "/api/v1/sdk/event", foreign_link)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );

    trisixt::sdk::merge_visitors(
        &baseline.fixture.state,
        a,
        contract.id("visitor_a_alias"),
        contract.id("visitor_a_customer"),
    )
    .await
    .unwrap();
    // The raw outbox is still immutable, even after canonical identity changes.
    let counts: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(DISTINCT visitor_id) FROM analytics_event_facts WHERE project_id=$1),(SELECT count(DISTINCT payload->>'visitor_id') FROM analytics_outbox WHERE project_id=$1),(SELECT count(*) FROM visitor_aliases WHERE project_id=$1)")
        .bind(a).fetch_one(pool).await.unwrap();
    let merged = &data["expected"]["after_alias_merge"]["project_a"];
    assert_eq!(
        counts,
        (
            merged["canonical_distinct_visitors"].as_i64().unwrap(),
            merged["raw_distinct_visitors"].as_i64().unwrap(),
            merged["alias_rows"].as_i64().unwrap()
        )
    );
    let (status, replayed) = baseline
        .call(
            a,
            "POST",
            "/api/v1/sdk/event",
            data["events"][0]["request"].clone(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{replayed}");
    assert_eq!(replayed, json!({"accepted":0,"duplicates":1}));
    for (key, project) in [("project_a", a), ("project_b", b)] {
        let counts: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM events WHERE project_id=$1),(SELECT count(*) FROM analytics_outbox WHERE project_id=$1),(SELECT count(*) FROM visitor_aliases WHERE project_id=$1)")
            .bind(project).fetch_one(pool).await.unwrap();
        let expected = &data["expected"]["after_alias_merge"][key];
        assert_eq!(
            counts,
            (
                expected["events"].as_i64().unwrap(),
                expected["outbox_rows"].as_i64().unwrap(),
                expected["alias_rows"].as_i64().unwrap()
            )
        );
    }

    for payment in data["payments"].as_array().unwrap() {
        let project: Uuid = payment["project_id"].as_str().unwrap().parse().unwrap();
        let mut purchase_id = Value::Null;
        for attempt in 0..2 {
            let (status, actual) = baseline
                .call(
                    project,
                    "POST",
                    "/api/v1/sdk/add_payment_event",
                    payment["request"].clone(),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{actual}");
            if payment["request"]["event_type"] == "BUY" {
                assert_eq!(actual["verified"], false);
                assert_eq!(actual["source"], "sdk_reported");
                let id: Uuid = actual["id"].as_str().unwrap().parse().unwrap();
                assert!(!id.is_nil());
                if attempt == 0 {
                    purchase_id = actual["id"].clone();
                } else {
                    assert_eq!(actual["id"], purchase_id);
                    assert_eq!(actual["duplicate"], true);
                }
            }
        }
        let expected = if project == a {
            data["expected"]["money_stages_a"]
                .as_array()
                .unwrap()
                .iter()
                .find(|stage| stage["after"] == payment["key"])
                .unwrap()
        } else {
            &data["expected"]["money_final_b"]
        };
        let ledger: (i64, String, i64) = sqlx::query_as("SELECT count(*),coalesce(sum(usd_nanos),0)::text,(SELECT count(*) FROM verified_purchases WHERE project_id=$1) FROM purchase_ledger WHERE project_id=$1")
            .bind(project).fetch_one(pool).await.unwrap();
        assert_eq!(ledger.0, expected["signed_ledger_rows"].as_i64().unwrap());
        assert_eq!(ledger.1, expected["net_usd_nanos"].as_str().unwrap());
        assert_eq!(ledger.2, expected["verified_purchases"].as_i64().unwrap());
    }

    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("timezone", "UTC")
        .append_pair("from", data["run_contract"]["query_from"].as_str().unwrap())
        .append_pair(
            "to",
            data["run_contract"]["query_to_exclusive"].as_str().unwrap(),
        )
        .finish();
    for (key, project) in [("project_a", a), ("project_b", b)] {
        let (status, actual) = baseline
            .call(
                project,
                "GET",
                &format!("/api/v1/projects/{project}/analytics/overview/key-metrics?{query}"),
                Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{actual}");
        for (metric, expected) in data["expected"]["overview_after_merge_and_payments"][key]
            .as_object()
            .unwrap()
        {
            assert_eq!(&actual["metrics"][metric], expected, "{key}/{metric}");
        }
    }
    baseline.fixture.close().await;
}
