mod support;
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{StatusCode, Uri},
    response::IntoResponse,
};
use bytes::Bytes as ObjectBytes;
use object_store::{ObjectStoreExt, memory::InMemory, path::Path};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Mutex;
use trisixt::{
    cleanup,
    providers::{Analytics, ClickHouseConfig, Storage},
};
use uuid::Uuid;

#[tokio::test]
async fn storage_cleanup_is_bounded_and_respects_exact_namespace_boundary() {
    let store = Arc::new(InMemory::new());
    let storage = Storage::new(store.clone());
    let project = Uuid::new_v4();
    let other = Uuid::new_v4();
    for key in ["asset.png", "exports/a/part-0.csv", "exports/a/part-1.csv"] {
        storage.put(project, key, vec![1]).await.unwrap();
    }
    storage.put(other, "asset.png", vec![2]).await.unwrap();
    let similar = Path::from(format!("projects/{project}-other/asset.png"));
    store
        .put(&similar, ObjectBytes::from_static(b"other").into())
        .await
        .unwrap();
    assert_eq!(
        storage.delete_namespace_batch(project, 2).await.unwrap(),
        (2, false)
    );
    assert_eq!(
        storage.delete_namespace_batch(project, 2).await.unwrap(),
        (1, true)
    );
    assert_eq!(
        storage.delete_namespace_batch(project, 2).await.unwrap(),
        (0, true)
    );
    assert_eq!(storage.get(other, "asset.png").await.unwrap(), vec![2]);
    assert!(store.get(&similar).await.is_ok());
    assert!(
        storage
            .delete_namespace_batch(Uuid::nil(), 10)
            .await
            .is_err()
    );
    assert!(storage.delete_namespace_batch(project, 0).await.is_err());
}
#[derive(Default)]
struct Warehouse {
    fail: AtomicBool,
    deleted: Mutex<Vec<String>>,
}
async fn warehouse(State(st): State<Arc<Warehouse>>, uri: Uri, body: Bytes) -> impl IntoResponse {
    if st.fail.load(Ordering::SeqCst) {
        return (StatusCode::UNAUTHORIZED, "denied".to_string());
    }
    let query = String::from_utf8(body.to_vec()).unwrap();
    if query.contains("system.mutations") {
        return (StatusCode::OK, r#"{"data":[{"pending":0}]}"#.into());
    }
    assert!(query.contains("DELETE WHERE project_id"));
    assert!(!query.contains("occurred_at"));
    let params: std::collections::HashMap<_, _> =
        url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes())
            .into_owned()
            .collect();
    st.deleted
        .lock()
        .await
        .push(params["param_project"].clone());
    (StatusCode::OK, String::new())
}
async fn analytics() -> (Analytics, Arc<Warehouse>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let state = Arc::new(Warehouse::default());
    let a = Analytics::clickhouse(ClickHouseConfig {
        url: format!("http://{}", listener.local_addr().unwrap()),
        database: "trisixt".into(),
        table: "events".into(),
        username: "default".into(),
        password: String::new(),
    })
    .unwrap();
    let app = Router::new().fallback(warehouse).with_state(state.clone());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (a, state, task)
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn deleted_project_retries_providers_and_reconciles_late_arrivals() {
    let f = support::Fixture::new().await;
    let (a, mock, task) = analytics().await;
    let storage = Storage::new(Arc::new(InMemory::new()));
    let other = Uuid::new_v4();
    storage.put(f.project, "asset.png", vec![1]).await.unwrap();
    storage.put(other, "asset.png", vec![2]).await.unwrap();
    let mut rollback = f.pool.begin().await.unwrap();
    sqlx::query("DELETE FROM projects WHERE id=$1")
        .bind(f.project)
        .execute(&mut *rollback)
        .await
        .unwrap();
    rollback.rollback().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM deleted_namespaces")
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        0
    );
    sqlx::query("DELETE FROM projects WHERE id=$1")
        .bind(f.project)
        .execute(&f.pool)
        .await
        .unwrap();
    mock.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        cleanup::dispatch_with(&f.state, &a, &storage)
            .await
            .unwrap(),
        1
    );
    assert!(
        storage
            .get(f.project, "asset.png")
            .await
            .unwrap_err()
            .is_not_found()
    );
    assert!(sqlx::query_scalar::<_,bool>("SELECT last_error IS NOT NULL AND storage_cleaned_at IS NOT NULL AND warehouse_cleaned_at IS NULL FROM deleted_namespaces WHERE namespace_id=$1").bind(f.project).fetch_one(&f.pool).await.unwrap());
    mock.fail.store(false, Ordering::SeqCst);
    sqlx::query("UPDATE deleted_namespaces SET available_at=now() WHERE namespace_id=$1")
        .bind(f.project)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        cleanup::dispatch_with(&f.state, &a, &storage)
            .await
            .unwrap(),
        1
    );
    assert!(sqlx::query_scalar::<_,bool>("SELECT last_error IS NULL AND last_success_at IS NOT NULL AND warehouse_cleaned_at IS NOT NULL AND available_at>now() FROM deleted_namespaces WHERE namespace_id=$1").bind(f.project).fetch_one(&f.pool).await.unwrap());
    assert_eq!(storage.get(other, "asset.png").await.unwrap(), vec![2]);
    // A late asynchronous export/previously accepted write is removed next pass.
    storage.put(f.project, "late.csv", vec![3]).await.unwrap();
    sqlx::query("UPDATE deleted_namespaces SET available_at=now() WHERE namespace_id=$1")
        .bind(f.project)
        .execute(&f.pool)
        .await
        .unwrap();
    cleanup::dispatch_with(&f.state, &a, &storage)
        .await
        .unwrap();
    assert!(
        storage
            .get(f.project, "late.csv")
            .await
            .unwrap_err()
            .is_not_found()
    );
    assert_eq!(
        mock.deleted.lock().await.as_slice(),
        [f.project.to_string(), f.project.to_string()]
    );
    assert!(sqlx::query("INSERT INTO projects(id,instance_id,environment,domain,name) VALUES($1,$2,'production','reused.example.test','Reused')").bind(f.project).bind(f.instance).execute(&f.pool).await.is_err());
    task.abort();
    f.close().await;
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn instance_cascade_cleans_usage_namespace_and_project_after_writer_commits() {
    let f = support::Fixture::new().await;
    let (a, mock, task) = analytics().await;
    let storage = Storage::new(Arc::new(InMemory::new()));
    storage
        .put(f.instance, "exports/usage/part-0.csv", vec![1])
        .await
        .unwrap();
    let mut writer = f.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM projects WHERE id=$1 FOR SHARE")
        .bind(f.project)
        .execute(&mut *writer)
        .await
        .unwrap();
    let pool = f.pool.clone();
    let instance = f.instance;
    let mut deletion = tokio::spawn(async move {
        sqlx::query("DELETE FROM instances WHERE id=$1")
            .bind(instance)
            .execute(&pool)
            .await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(150), &mut deletion)
            .await
            .is_err()
    );
    storage
        .put(f.project, "last-in-flight.png", vec![2])
        .await
        .unwrap();
    writer.commit().await.unwrap();
    deletion.await.unwrap().unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM deleted_namespaces")
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        cleanup::dispatch_with(&f.state, &a, &storage)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        cleanup::dispatch_with(&f.state, &a, &storage)
            .await
            .unwrap(),
        1
    );
    assert!(
        storage
            .get(f.instance, "exports/usage/part-0.csv")
            .await
            .unwrap_err()
            .is_not_found()
    );
    assert!(
        storage
            .get(f.project, "last-in-flight.png")
            .await
            .unwrap_err()
            .is_not_found()
    );
    assert_eq!(
        mock.deleted.lock().await.as_slice(),
        [f.project.to_string()]
    );
    assert!(sqlx::query_scalar::<_,bool>("SELECT warehouse_cleaned_at IS NULL AND storage_cleaned_at IS NOT NULL FROM deleted_namespaces WHERE namespace_id=$1").bind(f.instance).fetch_one(&f.pool).await.unwrap());
    task.abort();
    f.close().await;
}
