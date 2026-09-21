//! Durable paginated exports. Each bounded CSV part is uploaded to the selected
//! S3/GCS backend before the cursor advances; retrying never skips a page.
use crate::{
    accounts::{Mail, enqueue_mail},
    auth::{AuthUser, authorize_instance, authorize_project},
    error::AppError,
    providers::Storage,
    state::AppState,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;
fn bad(s: &str) -> AppError {
    AppError::BadRequest(s.into())
}
#[derive(Default, Deserialize)]
struct ExportInput {
    start_date: Option<chrono::NaiveDate>,
    end_date: Option<chrono::NaiveDate>,
    campaign_id: Option<Uuid>,
    active: Option<bool>,
    sdk: Option<bool>,
}
async fn queue(
    st: &AppState,
    user: &AuthUser,
    instance: Uuid,
    project: Option<Uuid>,
    kind: &str,
    q: ExportInput,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let today = Utc::now().date_naive();
    let from = q.start_date.unwrap_or(today - Duration::days(29));
    let to = q.end_date.unwrap_or(today);
    if from > to || to - from > Duration::days(366) {
        return Err(bad("export range must be 1 to 367 days"));
    }
    if let Some(project) = project {
        let days=sqlx::query_scalar::<_,i32>("SELECT CASE WHEN $2 OR EXISTS(SELECT 1 FROM billing_subscriptions b WHERE b.instance_id=i.id AND b.status NOT IN ('canceled','incomplete_expired')) OR EXISTS(SELECT 1 FROM enterprise_subscriptions e WHERE e.instance_id=i.id AND e.active AND e.start_date<=now() AND e.end_date>=now()) THEN delete_days ELSE cold_storage_days END FROM instances i WHERE id=$1").bind(instance).bind(crate::billing::self_hosted()).fetch_one(&st.pg).await?;
        if from < today - Duration::days(i64::from(days)) {
            return Err(bad("export range exceeds retention window"));
        }
        if let Some(campaign) = q.campaign_id {
            let own = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM campaigns WHERE project_id=$1 AND id=$2)",
            )
            .bind(project)
            .bind(campaign)
            .fetch_one(&st.pg)
            .await?;
            if !own {
                return Err(AppError::NotFound);
            }
        }
    }
    let params = json!({"from":from.and_hms_opt(0,0,0).unwrap().and_utc(),"to":to.succ_opt().ok_or_else(||bad("invalid end date"))?.and_hms_opt(0,0,0).unwrap().and_utc(),"campaign_id":q.campaign_id,"active":q.active,"sdk":q.sdk});
    let mut tx = st.pg.begin().await?;
    let id=sqlx::query_scalar::<_,Uuid>("INSERT INTO export_jobs(instance_id,project_id,user_id,kind,parameters) VALUES($1,$2,$3,$4,$5) RETURNING id").bind(instance).bind(project).bind(user.id).bind(kind).bind(params).fetch_one(&mut *tx).await?;
    sqlx::query("SELECT trisixt_audit($1,$2,'export.queued',$3,$4)")
        .bind(instance)
        .bind(user.id)
        .bind(id)
        .bind(json!({"kind":kind}))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(
            json!({"id":id,"state":"queued","status_url":format!("/api/v1/instances/{instance}/exports/{id}")}),
        ),
    ))
}
async fn links(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Json(body): Json<ExportInput>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let instance = authorize_project(&st, &user, project, false).await?;
    queue(&st, &user, instance, Some(project), "links", body).await
}
async fn usage(
    State(st): State<AppState>,
    user: AuthUser,
    Path(instance): Path<Uuid>,
    Json(body): Json<ExportInput>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    authorize_instance(&st, &user, instance, true).await?;
    queue(&st, &user, instance, None, "usage", body).await
}
async fn status(
    State(st): State<AppState>,
    user: AuthUser,
    Path((instance, id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Value>, AppError> {
    let role = authorize_instance(&st, &user, instance, false).await?;
    let row=sqlx::query_scalar::<_,Value>("SELECT to_jsonb(j)-'lease_id'-'lease_until' FROM export_jobs j WHERE instance_id=$1 AND id=$2").bind(instance).bind(id).fetch_optional(&st.pg).await?.ok_or(AppError::NotFound)?;
    if row["kind"] == "usage" && !matches!(role.as_str(), "owner" | "admin") {
        return Err(AppError::Forbidden);
    }
    Ok(Json(row))
}
async fn download(
    State(st): State<AppState>,
    user: AuthUser,
    Path((instance, id, part)): Path<(Uuid, Uuid, usize)>,
) -> Result<Response, AppError> {
    let role = authorize_instance(&st, &user, instance, false).await?;
    let row=sqlx::query("SELECT coalesce(project_id,instance_id) scope,parts,kind FROM export_jobs WHERE instance_id=$1 AND id=$2 AND state='ready' AND expires_at>now()").bind(instance).bind(id).fetch_optional(&st.pg).await?.ok_or(AppError::NotFound)?;
    if row.get::<String, _>("kind") == "usage" && !matches!(role.as_str(), "owner" | "admin") {
        return Err(AppError::Forbidden);
    }
    let parts: Value = row.get("parts");
    let key = parts
        .get(part)
        .and_then(Value::as_str)
        .ok_or(AppError::NotFound)?;
    let bytes = Storage::from_env(&st.config)
        .map_err(|_| AppError::Upstream)?
        .get(row.get("scope"), key)
        .await
        .map_err(|_| AppError::Upstream)?;
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (header::CONTENT_DISPOSITION, "attachment"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CACHE_CONTROL, "private, no-store"),
        ],
        bytes,
    )
        .into_response())
}
fn csv_cell(value: &Value) -> String {
    let s = match value {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        v => v.to_string(),
    };
    if s.trim_start().starts_with(['=', '+', '-', '@']) || s.starts_with(['\t', '\r', '\n']) {
        format!("'{s}")
    } else {
        s
    }
}
fn csv(rows: &[Value], columns: &[&str]) -> Result<Vec<u8>, AppError> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer
        .write_record(columns)
        .map_err(|_| AppError::Internal)?;
    for row in rows {
        writer
            .write_record(columns.iter().map(|c| csv_cell(&row[*c])))
            .map_err(|_| AppError::Internal)?;
    }
    writer.into_inner().map_err(|_| AppError::Internal)
}
pub async fn dispatch_once(st: &AppState) -> Result<usize, AppError> {
    let pending=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM export_jobs WHERE state IN('queued','running') AND available_at<=now() AND expires_at>now() AND (lease_until IS NULL OR lease_until<now()))").fetch_one(&st.pg).await?;
    if !pending {
        return Ok(0);
    }
    let storage = Storage::from_env(&st.config).map_err(|_| AppError::Upstream)?;
    dispatch_with(st, &storage).await
}
pub async fn dispatch_with(st: &AppState, storage: &Storage) -> Result<usize, AppError> {
    let lease = Uuid::new_v4();
    let job=sqlx::query("WITH pending AS(SELECT id FROM export_jobs WHERE state IN('queued','running') AND available_at<=now() AND expires_at>now() AND (lease_until IS NULL OR lease_until<now()) ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE export_jobs j SET state='running',lease_id=$1,lease_until=now()+interval '2 minutes' FROM pending WHERE j.id=pending.id RETURNING j.*").bind(lease).fetch_optional(&st.pg).await?;
    let Some(job) = job else {
        return Ok(0);
    };
    let id: Uuid = job.get("id");
    let instance: Uuid = job.get("instance_id");
    let project: Option<Uuid> = job.get("project_id");
    let scope = project.unwrap_or(instance);
    let user: Option<Uuid> = job.get("user_id");
    let kind: String = job.get("kind");
    let permitted = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM instance_roles WHERE instance_id=$1 AND user_id=$2 AND ($3<>'usage' OR role IN ('owner','admin')))",
    )
    .bind(instance)
    .bind(user)
    .bind(&kind)
    .fetch_one(&st.pg)
    .await?;
    if !permitted {
        sqlx::query("UPDATE export_jobs SET state='failed',last_error='requester no longer has access',lease_id=NULL,lease_until=NULL WHERE id=$1 AND lease_id=$2").bind(id).bind(lease).execute(&st.pg).await?;
        return Ok(1);
    }
    let result=async {
    let params: Value = job.get("parameters");
    let parts: Value = job.get("parts");
    let part = parts.as_array().ok_or(AppError::Internal)?.len();
    let from: DateTime<Utc> = params["from"]
        .as_str()
        .ok_or(AppError::Internal)?
        .parse()
        .map_err(|_| AppError::Internal)?;
    let to: DateTime<Utc> = params["to"]
        .as_str()
        .ok_or(AppError::Internal)?
        .parse()
        .map_err(|_| AppError::Internal)?;
  let rows=if kind=="links"{sqlx::query_scalar::<_,Value>("SELECT to_jsonb(l)||jsonb_build_object('views',(SELECT count(*) FROM analytics_event_facts e WHERE e.project_id=l.project_id AND e.link_id=l.id AND lower(e.event_type)='view' AND e.occurred_at>=$3 AND e.occurred_at<$4),'opens',(SELECT count(*) FROM analytics_event_facts e WHERE e.project_id=l.project_id AND e.link_id=l.id AND lower(e.event_type)='open' AND e.occurred_at>=$3 AND e.occurred_at<$4),'installs',(SELECT count(*) FROM analytics_event_facts e WHERE e.project_id=l.project_id AND e.link_id=l.id AND lower(e.event_type)='install' AND e.occurred_at>=$3 AND e.occurred_at<$4),'revenue_usd_nanos',(SELECT coalesce(sum(usd_nanos),0)::text FROM purchase_ledger p WHERE p.project_id=l.project_id AND p.link_id=l.id AND p.occurred_at>=$3 AND p.occurred_at<$4)) FROM links l WHERE project_id=$1 AND ($2::uuid IS NULL OR id>$2) AND created_at<=$5 AND ($6::uuid IS NULL OR campaign_id=$6) AND ($7::bool IS NULL OR (archived_at IS NULL)=$7) AND ($8::bool IS NULL OR coalesce(metadata->>'sdk_generated','false')=$8::text) ORDER BY id LIMIT 100").bind(project).bind(job.get::<Option<Uuid>,_>("cursor_id")).bind(from).bind(to).bind(job.get::<DateTime<Utc>,_>("created_at")).bind(params["campaign_id"].as_str().and_then(|s|s.parse::<Uuid>().ok())).bind(params["active"].as_bool()).bind(params["sdk"].as_bool()).fetch_all(&st.pg).await?}
  else{sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('month',month,'monthly_active_users',count(*)) FROM monthly_active_visitors WHERE instance_id=$1 AND month>=date_trunc('month',$2::timestamptz)::date AND month<$3::timestamptz::date GROUP BY month ORDER BY month").bind(instance).bind(from).bind(to).fetch_all(&st.pg).await?};
  let columns:&[&str]=if kind=="links"{&["id","name","path","target_url","campaign_id","views","opens","installs","revenue_usd_nanos","metadata"]}else{&["month","monthly_active_users"]};
  let key=format!("exports/{id}/part-{part}.csv");
  let bytes=csv(&rows,columns)?;
  let mut tx=st.pg.begin().await?;
  let owned:Option<Uuid>=sqlx::query_scalar("SELECT id FROM export_jobs WHERE id=$1 AND lease_id=$2 AND state='running' AND expires_at>now() FOR UPDATE").bind(id).bind(lease).fetch_optional(&mut *tx).await?;
  if owned.is_none(){return Ok(());}
  // Hold the job row across upload and commit. An expired lease cannot publish
  // a later overwrite, and expiration cannot delete a part during its upload.
  storage.put(scope,&key,bytes).await.map_err(|_|AppError::Upstream)?;
  let ready=kind=="usage"||rows.len()<100;let cursor=rows.last().and_then(|r|r["id"].as_str()).and_then(|s|s.parse::<Uuid>().ok());
  let updated=sqlx::query("UPDATE export_jobs SET state=$3,cursor_id=$4,row_count=row_count+$5,parts=parts||jsonb_build_array($6::text),lease_id=NULL,lease_until=NULL,last_error=NULL WHERE id=$1 AND lease_id=$2").bind(id).bind(lease).bind(if ready{"ready"}else{"queued"}).bind(cursor).bind(rows.len() as i64).bind(&key).execute(&mut *tx).await?.rows_affected();
  if updated==1&&ready&&std::env::var("SMTP_HOST").is_ok(){let email=sqlx::query_scalar::<_,String>("SELECT email FROM users WHERE id=$1").bind(user).fetch_optional(&mut *tx).await?;if let Some(email)=email{let public=std::env::var("PUBLIC_URL").unwrap_or_else(|_|format!("https://{}",st.config.server_host));enqueue_mail(&mut tx,&Mail{to:email,subject:"Your Trisixt export is ready".into(),text:format!("Your {kind} export is ready and expires in 24 hours. Sign in to download: {public}/api/v1/instances/{instance}/exports/{id}")},Some(&format!("export:{id}"))).await?;}}
  tx.commit().await?;Ok::<_,AppError>(())
 }.await;
    if let Err(error) = result {
        tracing::warn!(export_id=%id,error=%error,"export part failed");
        sqlx::query("UPDATE export_jobs SET state=CASE WHEN attempts>=9 THEN 'failed' ELSE 'queued' END,attempts=attempts+1,available_at=now()+make_interval(secs=>least(3600,power(2,least(attempts,11)))::int),lease_id=NULL,lease_until=NULL,last_error='export generation or storage failed' WHERE id=$1 AND lease_id=$2").bind(id).bind(lease).execute(&st.pg).await?;
    }
    Ok(1)
}
pub async fn expire(st: &AppState, storage: &Storage) -> Result<usize, AppError> {
    let mut count = 0;
    for _ in 0..20 {
        let mut tx = st.pg.begin().await?;
        let job=sqlx::query("SELECT id,coalesce(project_id,instance_id) scope,parts FROM export_jobs WHERE expires_at<=now() AND state<>'expired' ORDER BY expires_at FOR UPDATE SKIP LOCKED LIMIT 1").fetch_optional(&mut *tx).await?;
        let Some(job) = job else { break };
        let id: Uuid = job.get("id");
        let scope: Uuid = job.get("scope");
        let parts: Value = job.get("parts");
        let parts = parts.as_array().ok_or(AppError::Internal)?;
        let mut keys: Vec<String> = parts
            .iter()
            .map(|key| key.as_str().map(str::to_owned).ok_or(AppError::Internal))
            .collect::<Result<_, _>>()?;
        // Upload may have succeeded just before a process crash rolled back its cursor.
        keys.push(format!("exports/{id}/part-{}.csv", parts.len()));
        for key in keys {
            match storage.delete(scope, &key).await {
                Ok(()) => {}
                Err(error) if error.is_not_found() => {}
                Err(_) => return Err(AppError::Upstream),
            }
        }
        sqlx::query("UPDATE export_jobs SET state='expired',parts='[]',lease_id=NULL,lease_until=NULL WHERE id=$1").bind(id).execute(&mut *tx).await?;
        tx.commit().await?;
        count += 1;
    }
    Ok(count)
}
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/projects/{id}/exports/links", post(links))
        .route("/api/v1/instances/{id}/exports/usage", post(usage))
        .route("/api/v1/instances/{id}/exports/{export}", get(status))
        .route(
            "/api/v1/instances/{id}/exports/{export}/parts/{part}",
            get(download),
        )
}
