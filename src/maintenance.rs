//! Durable maintenance for the canonical PostgreSQL analytics design. Warehouse
//! retention completes before PostgreSQL deletion; pending delivery is preserved.
use crate::{error::AppError, providers::Analytics, state::AppState};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

#[derive(Debug, Default, Serialize)]
pub struct MaintenanceReport {
    pub projects_completed: u64,
    pub projects_failed: u64,
    pub events_deleted: u64,
    pub expired_records_deleted: u64,
}

/// Called by the worker; per-project row locks permit safe concurrent workers.
pub async fn tick(st: &AppState, analytics: &Analytics) -> Result<MaintenanceReport, AppError> {
    let cleaned = cleanup_expired(st).await?;
    let mut report = process_due(st, analytics, 25).await?;
    report.expired_records_deleted = cleaned;
    Ok(report)
}

pub async fn process_due(
    st: &AppState,
    analytics: &Analytics,
    limit: i64,
) -> Result<MaintenanceReport, AppError> {
    sqlx::query(
        "INSERT INTO retention_jobs(project_id) SELECT id FROM projects ON CONFLICT DO NOTHING",
    )
    .execute(&st.pg)
    .await?;
    let mut report = MaintenanceReport::default();
    for _ in 0..limit.clamp(1, 100) {
        let mut tx = st.pg.begin().await?;
        let row=sqlx::query("SELECT j.project_id,p.instance_id,i.delete_days FROM retention_jobs j JOIN projects p ON p.id=j.project_id JOIN instances i ON i.id=p.instance_id WHERE j.available_at<=now() ORDER BY j.available_at,j.project_id FOR UPDATE OF j SKIP LOCKED LIMIT 1").fetch_optional(&mut *tx).await?;
        let Some(row) = row else { break };
        let project: Uuid = row.get("project_id");
        let instance: Uuid = row.get("instance_id");
        // Hold a shared lock so a concurrent retention-policy extension cannot
        // race an in-flight destructive request using the former shorter policy.
        let days: i32 =
            sqlx::query_scalar("SELECT delete_days FROM instances WHERE id=$1 FOR SHARE")
                .bind(instance)
                .fetch_one(&mut *tx)
                .await?;
        let cutoff = Utc::now()
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .ok_or(AppError::Internal)?
            .and_utc()
            - chrono::Duration::days(i64::from(days));
        let pending:Option<DateTime<Utc>>=sqlx::query_scalar("SELECT min(e.occurred_at) FROM events e JOIN analytics_outbox o ON o.event_id=e.id WHERE e.project_id=$1 AND o.processed_at IS NULL AND e.occurred_at<$2").bind(project).bind(cutoff).fetch_one(&mut *tx).await?;
        let warehouse_cutoff = pending.map_or(cutoff, |at| at.min(cutoff));
        match analytics.purge_before(project, warehouse_cutoff).await {
            Ok(()) => {
                let result=sqlx::query("DELETE FROM events e WHERE e.project_id=$1 AND e.occurred_at<$2 AND NOT EXISTS(SELECT 1 FROM analytics_outbox o WHERE o.event_id=e.id AND o.processed_at IS NULL)").bind(project).bind(warehouse_cutoff).execute(&mut *tx).await?;
                let deleted = result.rows_affected();
                // Visitor identities, purchases, subscription state and monthly
                // billing snapshots deliberately outlive event retention.
                sqlx::query("DELETE FROM link_clicks WHERE project_id=$1 AND created_at<$2 AND handled_at IS NOT NULL").bind(project).bind(warehouse_cutoff).execute(&mut *tx).await?;
                sqlx::query("UPDATE retention_jobs SET available_at=now()+interval '1 day',attempts=0,last_completed_at=now(),cutoff=$2,deleted_events=$3,last_error=NULL WHERE project_id=$1").bind(project).bind(warehouse_cutoff).bind(deleted as i64).execute(&mut *tx).await?;
                sqlx::query("SELECT trisixt_audit($1,NULL,'retention.deletion_ran',$2,$3)").bind(instance).bind(project).bind(json!({"cutoff":warehouse_cutoff,"delete_days":days,"deleted_events":deleted,"pending_delivery_limited_cutoff":pending.is_some()})).execute(&mut *tx).await?;
                report.projects_completed += 1;
                report.events_deleted += deleted;
            }
            Err(error) => {
                tracing::warn!(project_id=%project,error=%error,"warehouse retention failed; PostgreSQL preserved");
                sqlx::query("UPDATE retention_jobs SET attempts=attempts+1,available_at=now()+make_interval(secs=>least(86400,60*power(2,least(attempts,10)))::int),last_error='warehouse retention failed; local data preserved' WHERE project_id=$1").bind(project).execute(&mut *tx).await?;
                report.projects_failed += 1;
            }
        }
        tx.commit().await?;
    }
    Ok(report)
}

/// Cleanup is limited to expired authentication material and delivered jobs.
/// Reuse-detection records survive until their whole refresh family expires.
pub async fn cleanup_expired(st: &AppState) -> Result<u64, AppError> {
    let mut tx = st.pg.begin().await?;
    let due:Option<String>=sqlx::query_scalar("SELECT name FROM maintenance_schedules WHERE name='expired_records' AND available_at<=now() FOR UPDATE SKIP LOCKED").fetch_optional(&mut *tx).await?;
    if due.is_none() {
        return Ok(0);
    }
    let mut deleted = 0;
    for statement in [
        "DELETE FROM browser_sessions WHERE expires_at<now()-interval '1 day'",
        "DELETE FROM oidc_transactions WHERE expires_at<now()-interval '1 day'",
        "DELETE FROM mcp_authorization_codes WHERE expires_at<now()-interval '1 day'",
        "DELETE FROM mcp_tokens t WHERE refresh_expires_at<now()-interval '1 day' AND NOT EXISTS(SELECT 1 FROM mcp_tokens live WHERE live.family_id=t.family_id AND live.refresh_expires_at>=now()-interval '1 day')",
        "DELETE FROM refresh_sessions r WHERE expires_at<now()-interval '1 day' AND NOT EXISTS(SELECT 1 FROM refresh_sessions live WHERE live.family_id=r.family_id AND live.expires_at>=now()-interval '1 day')",
        "DELETE FROM access_tokens WHERE expires_at<now()-interval '1 day'",
        "DELETE FROM account_tokens WHERE expires_at<now()-interval '1 day'",
        "DELETE FROM auth_attempts WHERE window_start<now()-interval '1 day'",
        "DELETE FROM mail_outbox WHERE sent_at<now()-interval '30 days'",
        "DELETE FROM push_outbox WHERE sent_at<now()-interval '30 days' OR invalidated_at<now()-interval '30 days'",
        "DELETE FROM purchase_notifications WHERE processed_at<now()-interval '90 days'",
        "DELETE FROM billing_webhooks WHERE processed_at<now()-interval '90 days'",
    ] {
        deleted += sqlx::query(statement)
            .execute(&mut *tx)
            .await?
            .rows_affected();
    }
    sqlx::query("UPDATE maintenance_schedules SET available_at=now()+interval '1 hour',last_completed_at=now(),result=$1 WHERE name='expired_records'").bind(json!({"deleted":deleted})).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(deleted)
}

/// Rebuild delivery and billable counts for a bounded retained interval. Native
/// analytics aggregate the canonical view directly, so link/campaign edits and
/// visitor identity merges cannot leave stale materialized rollup dimensions.
pub async fn reconcile_range(
    st: &AppState,
    project: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Value, AppError> {
    if project.is_nil() || from >= to || to - from > chrono::Duration::days(366) {
        return Err(AppError::BadRequest(
            "reconciliation requires a project and at most 366 days".into(),
        ));
    }
    let mut tx = st.pg.begin().await?;
    let instance: Uuid = sqlx::query_scalar("SELECT instance_id FROM projects WHERE id=$1")
        .bind(project)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("billing:{instance}"))
        .execute(&mut *tx)
        .await?;
    let outbox=sqlx::query("INSERT INTO analytics_outbox(project_id,event_id,payload) SELECT e.project_id,e.id,jsonb_build_object('id',e.id,'event_id',e.event_id,'project_id',e.project_id,'visitor_id',e.visitor_id,'event_type',e.event_type,'occurred_at',e.occurred_at,'properties',e.properties) FROM events e WHERE e.project_id=$1 AND e.occurred_at>=$2 AND e.occurred_at<$3 ON CONFLICT(event_id) DO NOTHING").bind(project).bind(from).bind(to).execute(&mut *tx).await?.rows_affected();
    let users=sqlx::query("INSERT INTO monthly_active_visitors(instance_id,month,visitor_id) SELECT $4,date_trunc('month',e.occurred_at AT TIME ZONE 'UTC')::date,e.visitor_id FROM analytics_event_facts e WHERE e.project_id=$1 AND e.occurred_at>=$2 AND e.occurred_at<$3 AND lower(e.event_type) IN ('view','open','install','reinstall','time_spent','reactivation','app_open','user_referred') GROUP BY 1,2,3 ON CONFLICT DO NOTHING").bind(project).bind(from).bind(to).bind(instance).execute(&mut *tx).await?.rows_affected();
    sqlx::query("SELECT trisixt_audit($1,NULL,'analytics.reconciled',$2,$3)")
        .bind(instance)
        .bind(project)
        .bind(json!({"from":from,"to":to,"outbox_repaired":outbox,"monthly_users_repaired":users}))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(json!({"outbox_repaired":outbox,"monthly_users_repaired":users}))
}
