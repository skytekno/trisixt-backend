//! Durable event delivery. PostgreSQL owns the queue; Redis is a disposable heartbeat.
//! Delivery is at least once; warehouse queries deduplicate the immutable event id.
use crate::{
    error::AppError,
    providers::{Analytics, AnalyticsEvent},
    state::AppState,
};
use sqlx::Row;
use std::time::Duration;
use tokio::sync::watch;

pub async fn dispatch_once(state: &AppState, analytics: &Analytics) -> Result<usize, AppError> {
    let mut tx = state.pg.begin().await?;
    let row=sqlx::query("SELECT id,payload,attempts FROM analytics_outbox WHERE processed_at IS NULL AND available_at<=now() ORDER BY available_at,created_at FOR UPDATE SKIP LOCKED LIMIT 1").fetch_optional(&mut *tx).await?;
    let Some(row) = row else { return Ok(0) };
    let id: uuid::Uuid = row.get("id");
    let payload: serde_json::Value = row.get("payload");
    let attempts: i32 = row.get("attempts");
    let result = match serde_json::from_value::<AnalyticsEvent>(payload) {
        Ok(event) => {
            match tokio::time::timeout(Duration::from_secs(45), analytics.publish(&[event])).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => {
                    tracing::warn!(outbox_id=%id,error=%error,"analytics delivery failed");
                    Err("provider delivery failed")
                }
                Err(_) => Err("provider delivery timed out"),
            }
        }
        Err(_) => Err("invalid stored event payload"),
    };
    match result {
        Ok(()) => {
            sqlx::query("UPDATE analytics_outbox SET processed_at=now(),attempts=attempts+1,last_error=NULL WHERE id=$1").bind(id).execute(&mut *tx).await?;
        }
        Err(message) => {
            let delay = 2_i32.saturating_pow(attempts.clamp(0, 11) as u32).min(3600);
            sqlx::query("UPDATE analytics_outbox SET attempts=attempts+1,last_error=$2,available_at=now()+make_interval(secs=>$3::double precision) WHERE id=$1").bind(id).bind(message).bind(f64::from(delay)).execute(&mut *tx).await?;
        }
    }
    tx.commit().await?;
    Ok(1)
}
async fn heartbeat(client: Option<redis::Client>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {changed=shutdown.changed()=>{if changed.is_err()||*shutdown.borrow(){break}},_=interval.tick()=>{
            if let Some(client)=&client{
                let ping=async{let mut conn=client.get_multiplexed_async_connection().await?;
                    redis::cmd("SET").arg("trisixt:worker:heartbeat").arg(chrono::Utc::now().timestamp()).arg("EX").arg(45).query_async::<()>(&mut conn).await};
                if !matches!(tokio::time::timeout(Duration::from_secs(2),ping).await,Ok(Ok(()))){tracing::warn!("redis heartbeat unavailable; events remain durable in PostgreSQL");}
            }
        }}
    }
}
pub async fn run(state: AppState, mut shutdown: watch::Receiver<bool>) {
    let analytics = match Analytics::from_env(&state.config) {
        Ok(a) => a,
        Err(error) => {
            tracing::error!(%error,"analytics worker configuration invalid; events remain queued");
            return;
        }
    };
    let heartbeat_task = tokio::spawn(heartbeat(
        redis::Client::open(state.config.redis_url.as_str()).ok(),
        shutdown.clone(),
    ));
    let mut background = tokio::task::JoinSet::new();
    for (name, seconds) in [
        ("billing", 2),
        ("purchases", 2),
        ("mail", 2),
        ("push", 1),
        ("domains", 60),
        ("imports", 2),
        ("exports", 2),
        ("quota", 600),
        ("reconcile", 60),
        ("fx", 3600),
        ("maintenance", 60),
        ("app_metadata", 10),
        ("hardware", 3600),
        ("cleanup", 2),
    ] {
        background.spawn(periodic(
            name,
            state.clone(),
            analytics.clone(),
            shutdown.clone(),
            Duration::from_secs(seconds),
        ));
    }
    loop {
        // Only shutdown can cancel delivery. Heartbeat ticks must not roll back
        // an in-flight transaction or repeatedly cancel a slow cloud request.
        tokio::select! {
            changed=shutdown.changed()=>{if changed.is_err()||*shutdown.borrow(){break}},
            completed=background.join_next()=>{
                if !*shutdown.borrow() {
                    tracing::error!(result=?completed,"background worker exited unexpectedly; stopping for supervisor restart");
                }
                break;
            },
            result=dispatch_once(&state,&analytics)=>match result{
                Ok(0)=>tokio::time::sleep(Duration::from_millis(500)).await,
                Ok(_)=>{},
                Err(error)=>{tracing::error!(%error,"outbox worker failed");tokio::time::sleep(Duration::from_secs(1)).await;}
            }
        }
    }
    background.abort_all();
    while background.join_next().await.is_some() {}
    heartbeat_task.abort();
    let _ = heartbeat_task.await;
}

async fn periodic(
    name: &'static str,
    st: AppState,
    analytics: Analytics,
    mut shutdown: watch::Receiver<bool>,
    period: Duration,
) {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {changed=shutdown.changed()=>{if changed.is_err()||*shutdown.borrow(){break;}},_=interval.tick()=>{}}
        if *shutdown.borrow() {
            break;
        }
        let result = tokio::select! {changed=shutdown.changed()=>{if changed.is_err()||*shutdown.borrow(){break;}else{continue;}},result=background_job(name,&st,&analytics)=>result};
        let error = result.err();
        if let Some(error) = &error {
            tracing::warn!(job=name,error=%error,"background job failed; durable work retained");
        }
        let _=sqlx::query("INSERT INTO worker_job_health(name,last_attempt_at,last_success_at,last_error) VALUES($1,now(),CASE WHEN $2::text IS NULL THEN now() END,$2) ON CONFLICT(name) DO UPDATE SET last_attempt_at=now(),last_success_at=CASE WHEN $2::text IS NULL THEN now() ELSE worker_job_health.last_success_at END,last_error=$2").bind(name).bind(error.map(|_|"job failed; inspect server logs")).execute(&st.pg).await;
    }
}
async fn background_job(name: &str, st: &AppState, analytics: &Analytics) -> Result<(), AppError> {
    match name {
        "billing" => {
            crate::billing::process_pending(st, 5).await?;
        }
        "purchases" => {
            crate::purchase_lifecycle::process_pending(st, 5).await?;
        }
        "mail" => {
            if std::env::var("SMTP_HOST").is_ok() {
                crate::accounts::enqueue_alerts(st).await?;
                crate::accounts::dispatch_mail_once(st).await?;
            } else if sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mail_outbox WHERE sent_at IS NULL) OR EXISTS(SELECT 1 FROM billing_alerts WHERE delivered_at IS NULL) OR EXISTS(SELECT 1 FROM migration_alerts WHERE delivered_at IS NULL)").fetch_one(&st.pg).await? {
                return Err(AppError::Config("SMTP_HOST required for pending mail delivery".into()));
            }
        }
        "push" => {
            crate::messaging::dispatch_once(st).await?;
        }
        "domains" => {
            crate::domains::tick(st).await?;
        }
        "imports" => {
            crate::imports::tick(st).await?;
        }
        "app_metadata" => {
            crate::app_metadata::tick(st).await?;
        }
        "hardware" => {
            crate::hardware::tick(st).await?;
        }
        "cleanup" => {
            crate::cleanup::dispatch_once(st, analytics).await?;
        }
        "exports" => {
            crate::exports::dispatch_once(st).await?;
        }
        "quota" => {
            crate::billing::report_usage(st).await?;
        }
        "reconcile" => {
            crate::purchase_lifecycle::reconcile_due(st, 5).await?;
        }
        "fx" => {
            let needed = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM purchase_ledger WHERE currency<>'USD')",
            )
            .fetch_one(&st.pg)
            .await?;
            if needed {
                crate::purchase_lifecycle::refresh_fx(st).await?;
            }
        }
        "maintenance" => {
            crate::maintenance::tick(st, analytics).await?;
            let expired=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM export_jobs WHERE expires_at<=now() AND state<>'expired')").fetch_one(&st.pg).await?;
            if expired {
                let storage = crate::providers::Storage::from_env(&st.config)
                    .map_err(|_| AppError::Upstream)?;
                crate::exports::expire(st, &storage).await?;
            }
        }
        _ => return Err(AppError::Internal),
    };
    Ok(())
}
