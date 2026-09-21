//! Durable cleanup after project/instance cascades. Tombstones are deliberately
//! retained: Pub/Sub may export an already-acknowledged event after the first
//! BigQuery deletion, so warehouse and object namespaces are reconciled again.
use crate::{
    error::AppError,
    providers::{Analytics, Storage},
    state::AppState,
};
use sqlx::Row;
use std::time::Duration;
use uuid::Uuid;

pub async fn dispatch_once(st: &AppState, analytics: &Analytics) -> Result<usize, AppError> {
    let due = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM deleted_namespaces WHERE available_at<=now())",
    )
    .fetch_one(&st.pg)
    .await?;
    if !due {
        return Ok(0);
    }
    let storage = Storage::from_env(&st.config)
        .map_err(|_| AppError::Config("storage required for deleted namespace cleanup".into()))?;
    dispatch_with(st, analytics, &storage).await
}
/// Injectable providers keep cleanup retries and tenant boundaries testable.
pub async fn dispatch_with(
    st: &AppState,
    analytics: &Analytics,
    storage: &Storage,
) -> Result<usize, AppError> {
    let mut tx = st.pg.begin().await?;
    let row=sqlx::query("SELECT namespace_id,kind,attempts FROM deleted_namespaces WHERE available_at<=now() ORDER BY available_at,namespace_id FOR UPDATE SKIP LOCKED LIMIT 1").fetch_optional(&mut *tx).await?;
    let Some(row) = row else {
        return Ok(0);
    };
    let namespace: Uuid = row.get("namespace_id");
    let project = row.get::<String, _>("kind") == "project";
    let attempts: i64 = row.get("attempts");
    let warehouse = if project {
        match tokio::time::timeout(Duration::from_secs(60), analytics.purge_project(namespace))
            .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err("warehouse deletion failed"),
            Err(_) => Err("warehouse deletion timed out"),
        }
    } else {
        Ok(())
    };
    // Storage deletion remains independent: a warehouse outage must not prevent
    // private exports/assets from being removed.
    let objects = match tokio::time::timeout(
        Duration::from_secs(60),
        storage.delete_namespace_batch(namespace, 250),
    )
    .await
    {
        Ok(Ok((_, complete))) => Ok(complete),
        Ok(Err(_)) => Err("object deletion failed"),
        Err(_) => Err("object deletion timed out"),
    };
    let error = warehouse.as_ref().err().or(objects.as_ref().err()).copied();
    let complete = warehouse.is_ok() && objects == Ok(true);
    let delay = if error.is_some() {
        2_i32.saturating_pow(attempts.clamp(0, 11) as u32).min(3600)
    } else if complete {
        3600
    } else {
        0
    };
    sqlx::query("UPDATE deleted_namespaces SET attempts=attempts+1,available_at=now()+make_interval(secs=>$2::double precision),warehouse_cleaned_at=CASE WHEN $3 THEN now() ELSE warehouse_cleaned_at END,storage_cleaned_at=CASE WHEN $4 THEN now() ELSE storage_cleaned_at END,last_success_at=CASE WHEN $5 THEN now() ELSE last_success_at END,last_error=$6 WHERE namespace_id=$1")
        .bind(namespace).bind(f64::from(delay)).bind(project&&warehouse.is_ok()).bind(objects==Ok(true)).bind(complete).bind(error).execute(&mut *tx).await?;
    tx.commit().await?;
    if let Some(error) = error {
        tracing::warn!(%namespace,error,"deleted namespace retained for retry");
    }
    Ok(1)
}
