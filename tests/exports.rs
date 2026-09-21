mod support;
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::sync::Arc;
use support::Fixture;
use trisixt::providers::Storage;
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn export_pages_exactly_once_escapes_cells_expires_and_checks_membership() {
    let f = Fixture::new().await;
    sqlx::query("INSERT INTO links(project_id,name,path,target_url) SELECT $1,CASE WHEN n=1 THEN '=SUM(1,2)' ELSE 'Link '||n END,'path-'||n,'https://example.com' FROM generate_series(1,205) n").bind(f.project).execute(&f.pool).await.unwrap();
    let (s, b) = f
        .call("POST", &f.path("exports/links"), json!({"active":true}))
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    let id = b["id"].as_str().unwrap();
    let storage = Storage::new(Arc::new(object_store::memory::InMemory::new()));
    for _ in 0..3 {
        assert_eq!(
            trisixt::exports::dispatch_with(&f.state, &storage)
                .await
                .unwrap(),
            1
        );
    }
    let (s, b) = f
        .call(
            "GET",
            &format!("/api/v1/instances/{}/exports/{id}", f.instance),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["state"], "ready");
    assert_eq!(b["row_count"], 205);
    assert_eq!(b["parts"].as_array().unwrap().len(), 3);
    let mut total = 0;
    let mut formula = false;
    for key in b["parts"].as_array().unwrap() {
        let bytes = storage.get(f.project, key.as_str().unwrap()).await.unwrap();
        let mut reader = csv::Reader::from_reader(bytes.as_slice());
        for row in reader.records() {
            let row = row.unwrap();
            total += 1;
            formula |= &row[1] == "'=SUM(1,2)";
        }
    }
    assert_eq!(total, 205);
    assert!(formula);
    sqlx::query("UPDATE export_jobs SET expires_at=now()-interval '1 second' WHERE id=$1")
        .bind(id.parse::<uuid::Uuid>().unwrap())
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        trisixt::exports::expire(&f.state, &storage).await.unwrap(),
        1
    );
    for key in b["parts"].as_array().unwrap() {
        assert!(storage.get(f.project, key.as_str().unwrap()).await.is_err());
    }
    let (s, b) = f.call("POST", &f.path("exports/links"), json!({})).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    let id = b["id"].as_str().unwrap();
    sqlx::query("DELETE FROM instance_roles WHERE instance_id=$1 AND user_id=$2")
        .bind(f.instance)
        .bind(f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    trisixt::exports::dispatch_with(&f.state, &storage)
        .await
        .unwrap();
    let state = sqlx::query_scalar::<_, String>("SELECT state FROM export_jobs WHERE id=$1")
        .bind(id.parse::<uuid::Uuid>().unwrap())
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(state, "failed");
    f.close().await;
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn usage_export_uses_durable_billable_uniques_and_rejects_foreign_campaign() {
    let f = Fixture::new().await;
    sqlx::query("INSERT INTO monthly_active_visitors(instance_id,month,visitor_id) VALUES($1,date_trunc('month',now())::date,gen_random_uuid()),($1,date_trunc('month',now())::date,gen_random_uuid())").bind(f.instance).execute(&f.pool).await.unwrap();
    let (s, b) = f
        .call(
            "POST",
            &format!("/api/v1/instances/{}/exports/usage", f.instance),
            json!({}),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    let id = b["id"].as_str().unwrap();
    let storage = Storage::new(Arc::new(object_store::memory::InMemory::new()));
    trisixt::exports::dispatch_with(&f.state, &storage)
        .await
        .unwrap();
    let (s, b) = f
        .call(
            "GET",
            &format!("/api/v1/instances/{}/exports/{id}", f.instance),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let bytes = storage
        .get(f.instance, b["parts"][0].as_str().unwrap())
        .await
        .unwrap();
    assert!(String::from_utf8(bytes).unwrap().contains(",2"));
    let (s, _) = f
        .call(
            "POST",
            &f.path("exports/links"),
            json!({"campaign_id":uuid::Uuid::new_v4()}),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL via TEST_DATABASE_URL; run scripts/integration.sh"]
async fn usage_exports_recheck_privileges_and_expiry_removes_crash_orphan() {
    let f = Fixture::new().await;
    let storage = Storage::new(Arc::new(object_store::memory::InMemory::new()));
    let (s, b) = f
        .call(
            "POST",
            &format!("/api/v1/instances/{}/exports/usage", f.instance),
            json!({}),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    let id = b["id"].as_str().unwrap().parse::<uuid::Uuid>().unwrap();
    trisixt::exports::dispatch_with(&f.state, &storage)
        .await
        .unwrap();
    sqlx::query("UPDATE instance_roles SET role='member' WHERE instance_id=$1 AND user_id=$2")
        .bind(f.instance)
        .bind(f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    for path in [
        format!("/api/v1/instances/{}/exports/{id}", f.instance),
        format!("/api/v1/instances/{}/exports/{id}/parts/0", f.instance),
    ] {
        let (s, b) = f.call("GET", &path, Value::Null).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{b}");
    }
    let orphan = format!("exports/{id}/part-1.csv");
    storage
        .put(f.instance, &orphan, b"orphan".to_vec())
        .await
        .unwrap();
    sqlx::query("UPDATE export_jobs SET expires_at=now()-interval '1 second' WHERE id=$1")
        .bind(id)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        trisixt::exports::expire(&f.state, &storage).await.unwrap(),
        1
    );
    assert!(storage.get(f.instance, &orphan).await.is_err());
    sqlx::query("UPDATE instance_roles SET role='owner' WHERE instance_id=$1 AND user_id=$2")
        .bind(f.instance)
        .bind(f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    let (s, b) = f
        .call(
            "POST",
            &format!("/api/v1/instances/{}/exports/usage", f.instance),
            json!({}),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{b}");
    let id = b["id"].as_str().unwrap().parse::<uuid::Uuid>().unwrap();
    sqlx::query("UPDATE instance_roles SET role='member' WHERE instance_id=$1 AND user_id=$2")
        .bind(f.instance)
        .bind(f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    trisixt::exports::dispatch_with(&f.state, &storage)
        .await
        .unwrap();
    let state: String = sqlx::query_scalar("SELECT state FROM export_jobs WHERE id=$1")
        .bind(id)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(state, "failed");
    f.close().await;
}
