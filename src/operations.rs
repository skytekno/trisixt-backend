//! Operator-only diagnostics and explicit repair triggers.
use crate::{error::AppError, state::AppState};
use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use uuid::Uuid;
fn admin(headers: &HeaderMap) -> Result<(), AppError> {
    let secret = std::env::var("TRISIXT_ADMIN_KEY")
        .or_else(|_| std::env::var("ADMIN_API_KEY"))
        .unwrap_or_default();
    let supplied = headers
        .get("x-admin-key")
        .or_else(|| headers.get("x-auth"))
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    check_secret(&secret, supplied)
}
fn check_secret(secret: &str, supplied: &str) -> Result<(), AppError> {
    if secret.is_empty() || supplied.is_empty() {
        return Err(AppError::Forbidden);
    }
    let mut expected =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| AppError::Internal)?;
    expected.update(b"trisixt-operator");
    let mut actual =
        Hmac::<Sha256>::new_from_slice(supplied.as_bytes()).map_err(|_| AppError::Internal)?;
    actual.update(b"trisixt-operator");
    expected
        .verify_slice(&actual.finalize().into_bytes())
        .map_err(|_| AppError::Forbidden)
}
async fn health(State(st): State<AppState>, headers: HeaderMap) -> Result<Json<Value>, AppError> {
    admin(&headers)?;
    let db=sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('pending_events',(SELECT count(*) FROM analytics_outbox WHERE processed_at IS NULL),'retrying_events',(SELECT count(*) FROM analytics_outbox WHERE processed_at IS NULL AND attempts>0),'pending_mail',(SELECT count(*) FROM mail_outbox WHERE sent_at IS NULL),'pending_purchases',(SELECT count(*) FROM purchase_notifications WHERE processed_at IS NULL),'pending_exports',(SELECT count(*) FROM export_jobs WHERE state IN('queued','running')))").fetch_one(&st.pg).await?;
    let jobs =
        sqlx::query_scalar::<_, Value>("SELECT to_jsonb(h) FROM worker_job_health h ORDER BY name")
            .fetch_all(&st.pg)
            .await?;
    Ok(Json(json!({"service":"trisixt","queues":db,"jobs":jobs})))
}
#[derive(Deserialize)]
struct Repair {
    project_id: Uuid,
    from: chrono::DateTime<chrono::Utc>,
    to: chrono::DateTime<chrono::Utc>,
}
async fn repair(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Repair>,
) -> Result<Json<Value>, AppError> {
    admin(&headers)?;
    Ok(Json(
        crate::maintenance::reconcile_range(&st, body.project_id, body.from, body.to).await?,
    ))
}
#[derive(Deserialize)]
struct Flush {
    project_id: Uuid,
}
async fn flush(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Flush>,
) -> Result<Json<Value>, AppError> {
    admin(&headers)?;
    let mut tx = st.pg.begin().await?;
    let instance: Uuid =
        sqlx::query_scalar("SELECT instance_id FROM projects WHERE id=$1 FOR SHARE")
            .bind(body.project_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(AppError::NotFound)?;
    let affected=sqlx::query("UPDATE analytics_outbox SET available_at=now() WHERE project_id=$1 AND processed_at IS NULL").bind(body.project_id).execute(&mut *tx).await?.rows_affected();
    sqlx::query("SELECT trisixt_audit($1,NULL,'analytics.requeued',$2,$3)")
        .bind(instance)
        .bind(body.project_id)
        .bind(json!({"queued":affected}))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({"queued":affected})))
}
#[derive(Deserialize)]
struct Retention {
    instance_id: Uuid,
    cold_storage_days: i32,
    delete_days: i32,
}
async fn retention(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Retention>,
) -> Result<Json<Value>, AppError> {
    admin(&headers)?;
    if body.cold_storage_days < 1
        || body.delete_days < body.cold_storage_days
        || body.delete_days > 3650
    {
        return Err(AppError::BadRequest("invalid retention days".into()));
    }
    let mut tx = st.pg.begin().await?;
    let n = sqlx::query("UPDATE instances SET cold_storage_days=$2,delete_days=$3 WHERE id=$1")
        .bind(body.instance_id)
        .bind(body.cold_storage_days)
        .bind(body.delete_days)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(AppError::NotFound);
    }
    sqlx::query("SELECT trisixt_audit($1,NULL,'instance.retention.updated',$1,$2)")
        .bind(body.instance_id)
        .bind(json!({"cold_storage_days":body.cold_storage_days,"delete_days":body.delete_days}))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({"updated":true})))
}
async fn log_test(headers: HeaderMap) -> Result<Json<Value>, AppError> {
    admin(&headers)?;
    let correlation = Uuid::new_v4();
    tracing::info!(%correlation,"operator diagnostics log test");
    tracing::warn!(%correlation,"operator diagnostics warning test");
    Ok(Json(json!({"correlation_id":correlation,"logged":true})))
}
async fn exception(headers: HeaderMap) -> Result<Json<Value>, AppError> {
    admin(&headers)?;
    tracing::error!("operator diagnostics exception test");
    Err(AppError::Internal)
}
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/flush_events", post(flush))
        .route("/api/v1/admin/reconcile_analytics", post(repair))
        .route(
            "/api/v1/admin/instance_retention",
            axum::routing::patch(retention),
        )
        .route("/api/v1/diagnostics/health_metrics", get(health))
        .route(
            "/api/v1/diagnostics/test_diagnostics",
            get(health).post(health),
        )
        .route(
            "/api/v1/diagnostics/test_logs",
            get(log_test).post(log_test),
        )
        .route(
            "/api/v1/diagnostics/test_exception",
            get(exception).post(exception),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn operator_secret_requires_exact_nonempty_match() {
        assert!(check_secret("operator-secret", "operator-secret").is_ok());
        for (expected, supplied) in [
            ("", ""),
            ("operator-secret", ""),
            ("", "operator-secret"),
            ("operator-secret", "operator-secret-extra"),
            ("operator-secret", "operator-secreu"),
        ] {
            assert!(matches!(
                check_secret(expected, supplied),
                Err(AppError::Forbidden)
            ));
        }
    }
}
