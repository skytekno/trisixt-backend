//! Search, statistics, onboarding and instance configuration operations.
use crate::{
    auth::{AuthUser, authorize_instance, authorize_project},
    error::AppError,
    state::AppState,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;
type Api = Result<Json<Value>, AppError>;
fn bad(s: &str) -> AppError {
    AppError::BadRequest(s.into())
}
#[derive(Default, Deserialize)]
struct Search {
    query: Option<String>,
    search: Option<String>,
    term: Option<String>,
    campaign_id: Option<Uuid>,
    link_id: Option<Uuid>,
    active: Option<bool>,
    archived: Option<bool>,
    sdk: Option<bool>,
    ads_platform: Option<String>,
    tags: Option<Vec<String>>,
    limit: Option<i64>,
    per_page: Option<i64>,
    offset: Option<i64>,
    page: Option<i64>,
    ids: Option<Vec<Uuid>>,
    sort_by: Option<String>,
    sort_order: Option<String>,
    #[serde(alias = "ascending", alias = "ascendent")]
    asc: Option<bool>,
    start_date: Option<String>,
    end_date: Option<String>,
    from: Option<String>,
    to: Option<String>,
    timezone: Option<String>,
    platform: Option<String>,
    #[serde(default)]
    all: bool,
}
impl Search {
    fn term(&self) -> Option<&str> {
        self.query
            .as_deref()
            .or(self.search.as_deref())
            .or(self.term.as_deref())
    }
    fn limit(&self) -> i64 {
        self.limit
            .or(self.per_page)
            .unwrap_or(if self.all { 1000 } else { 50 })
    }
    fn offset(&self) -> i64 {
        self.offset
            .unwrap_or((self.page.unwrap_or(1) - 1).saturating_mul(self.limit()))
    }
    fn validate(&self) -> Result<(), AppError> {
        if self.term().is_some_and(|s| s.len() > 255)
            || self.ids.as_ref().is_some_and(|v| v.len() > 200)
            || !(1..=1000).contains(&self.limit())
            || !(1..=100001).contains(&self.page.unwrap_or(1))
            || !(0..=100000).contains(&self.offset())
            || self.ads_platform.as_ref().is_some_and(|v| v.len() > 100)
            || self
                .tags
                .as_ref()
                .is_some_and(|v| v.len() > 100 || v.iter().any(|s| s.len() > 255))
        {
            return Err(bad("invalid search parameters"));
        }
        if self
            .sort_order
            .as_ref()
            .is_some_and(|s| !matches!(s.as_str(), "asc" | "desc"))
        {
            return Err(bad("sort_order must be asc or desc"));
        }
        Ok(())
    }
}
async fn search_links(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Json(q): Json<Search>,
) -> Api {
    authorize_project(&st, &user, project, false).await?;
    search_entities(&st, project, q, false).await
}
async fn search_campaigns(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Json(q): Json<Search>,
) -> Api {
    authorize_project(&st, &user, project, false).await?;
    search_entities(&st, project, q, true).await
}
async fn search_entities(st: &AppState, project: Uuid, q: Search, campaign: bool) -> Api {
    q.validate()?;
    let range = crate::analytics_api::Range::new(
        st,
        project,
        &crate::analytics_api::AnalyticsQuery {
            start_date: q.start_date.clone(),
            end_date: q.end_date.clone(),
            from: q.from.clone(),
            to: q.to.clone(),
            timezone: q.timezone.clone(),
            platform: q.platform.clone(),
            ..Default::default()
        },
        true,
    )
    .await?;
    // Every interpolated SQL fragment below is a closed, server-owned identifier
    // or expression. User values are bound through the params CTE.
    let (table, key) = if campaign {
        ("campaigns", "campaign_id")
    } else {
        ("links", "link_id")
    };
    let sort = match q.sort_by.as_deref().unwrap_or("created_at") {
        "name" => "lower(e.name)",
        "created_at" => "e.created_at",
        "updated_at" => "e.updated_at",
        "title" if !campaign => "lower(e.metadata->>'title')",
        "path" if !campaign => "e.path",
        "tags" if !campaign => "e.metadata->'tags'",
        "active" => "(e.archived_at IS NULL)",
        "sdk_generated" if !campaign => "(e.metadata->>'sdk_generated')",
        "campaign_id" if !campaign => "e.campaign_id",
        "ads_platform" if !campaign => "e.metadata->>'ads_platform'",
        "views" => "nullif(m.views,0)",
        "opens" => "nullif(m.opens,0)",
        "installs" => "nullif(m.installs,0)",
        "reinstalls" => "nullif(m.reinstalls,0)",
        "time_spent" => "nullif(m.time_spent,0)",
        "reactivations" => "nullif(m.reactivations,0)",
        "app_opens" => "nullif(m.app_opens,0)",
        "user_referred" => "nullif(m.user_referred,0)",
        "revenue" => "nullif(r.revenue,0)",
        _ => return Err(bad("unsupported sort field")),
    };
    let direction = q
        .sort_order
        .as_deref()
        .unwrap_or(if q.asc.unwrap_or(false) {
            "asc"
        } else {
            "desc"
        });
    let restrictions = if campaign {
        ""
    } else {
        " AND (p.q->>'campaign_id' IS NULL OR e.campaign_id=(p.q->>'campaign_id')::uuid) AND (p.q->>'link_id' IS NULL OR e.id=(p.q->>'link_id')::uuid) AND (p.q->>'sdk' IS NULL OR coalesce(e.metadata->>'sdk_generated','false')=p.q->>'sdk') AND (p.q->>'ads_platform' IS NULL OR e.metadata->>'ads_platform'=p.q->>'ads_platform') AND (p.q->'tags'='null'::jsonb OR coalesce(e.metadata->'tags','[]'::jsonb) @> (p.q->'tags'))"
    };
    let search = if campaign {
        "strpos(lower(e.name),lower(p.q->>'term'))>0"
    } else {
        "strpos(lower(concat_ws(' ',e.name,e.path,e.metadata->>'title',e.metadata->>'subtitle',e.metadata->>'tags')),lower(p.q->>'term'))>0"
    };
    let revenue_key = if campaign {
        "l.campaign_id"
    } else {
        "pl.link_id"
    };
    let sql = format!(
        r#"WITH params AS(SELECT $1::uuid project,$2::timestamptz lower,$3::timestamptz upper,$4::text platform,$5::jsonb q),
 eligible AS(SELECT e.* FROM {table} e,params p WHERE e.project_id=p.project AND(p.q->>'term' IS NULL OR {search}) AND(p.q->>'active' IS NULL OR(e.archived_at IS NULL)=(p.q->>'active')::bool) AND(p.q->'ids'='null'::jsonb OR p.q->'ids' @> to_jsonb(e.id::text)){restrictions}),
 metrics AS(SELECT f.{key} id,count(*) FILTER(WHERE lower(event_type)='view') views,count(*) FILTER(WHERE lower(event_type)='open') opens,count(*) FILTER(WHERE lower(event_type)='install') installs,count(*) FILTER(WHERE lower(event_type)='reinstall') reinstalls,coalesce(sum(engagement_time) FILTER(WHERE lower(event_type)='time_spent'),0) time_spent,count(*) FILTER(WHERE lower(event_type)='reactivation') reactivations,count(*) FILTER(WHERE lower(event_type)='app_open') app_opens,count(*) FILTER(WHERE lower(event_type)='user_referred') user_referred FROM analytics_event_facts f,params p WHERE f.project_id=p.project AND f.occurred_at>=p.lower AND f.occurred_at<p.upper AND(p.platform IS NULL OR f.platform=p.platform) AND f.{key} IN(SELECT id FROM eligible) GROUP BY f.{key}),
 revenue AS(SELECT {revenue_key} id,sum(pl.usd_nanos)/10000000 revenue,count(*) FILTER(WHERE pl.usd_nanos IS NULL) unpriced FROM purchase_ledger pl JOIN verified_purchases vp ON vp.id=pl.purchase_id LEFT JOIN links l ON l.id=pl.link_id AND l.project_id=pl.project_id,params p WHERE pl.project_id=p.project AND pl.occurred_at>=p.lower AND pl.occurred_at<p.upper AND(p.platform IS NULL OR vp.platform=p.platform) AND {revenue_key} IN(SELECT id FROM eligible) GROUP BY {revenue_key}),
 page AS(SELECT to_jsonb(e)||jsonb_build_object('active',e.archived_at IS NULL,'total_views',coalesce(m.views,0),'total_opens',coalesce(m.opens,0),'total_installs',coalesce(m.installs,0),'total_reinstalls',coalesce(m.reinstalls,0),'total_time_spent',coalesce(m.time_spent,0),'total_reactivations',coalesce(m.reactivations,0),'total_app_opens',coalesce(m.app_opens,0),'total_user_referred',coalesce(m.user_referred,0),'total_revenue',coalesce(r.revenue,0),'unpriced_purchases',coalesce(r.unpriced,0)) value FROM eligible e LEFT JOIN metrics m ON m.id=e.id LEFT JOIN revenue r ON r.id=e.id ORDER BY {sort} {direction} NULLS LAST,e.id LIMIT $6 OFFSET $7)
 SELECT jsonb_build_object('{table}',coalesce((SELECT jsonb_agg(value) FROM page),'[]'::jsonb),'meta',jsonb_build_object('page',($7::bigint/$6::bigint)+1,'per_page',$6::bigint,'total_entries',(SELECT count(*) FROM eligible),'total_pages',ceil((SELECT count(*) FROM eligible)::numeric/$6::bigint)),'next_offset',CASE WHEN $7::bigint+$6::bigint<(SELECT count(*) FROM eligible) THEN $7::bigint+$6::bigint END)"#
    );
    let options = json!({"term":q.term(),"campaign_id":q.campaign_id,"link_id":q.link_id,"active":q.active.or(q.archived.map(|v|!v)),"sdk":q.sdk,"ads_platform":q.ads_platform,"tags":q.tags,"ids":q.ids});
    let mut tx = st.pg.begin().await?;
    sqlx::query("SET LOCAL statement_timeout=\'15s\'")
        .execute(&mut *tx)
        .await?;
    let data = sqlx::query_scalar::<_, Value>(sqlx::AssertSqlSafe(sql))
        .bind(project)
        .bind(range.from)
        .bind(range.to)
        .bind(range.platform)
        .bind(options)
        .bind(q.limit())
        .bind(q.offset())
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(data))
}
async fn search_visitors(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Json(q): Json<Search>,
) -> Api {
    authorize_project(&st, &user, project, false).await?;
    q.validate()?;
    let rows=sqlx::query_scalar::<_,Value>("SELECT to_jsonb(v) FROM visitors v WHERE project_id=$1 AND NOT EXISTS(SELECT 1 FROM visitor_aliases a WHERE a.project_id=v.project_id AND a.alias_id=v.id) AND ($2::text IS NULL OR strpos(lower(coalesce(external_id,'')),lower($2))>0 OR id::text=$2) AND ($3::uuid[] IS NULL OR id=ANY($3)) ORDER BY last_seen_at DESC,id LIMIT $4 OFFSET $5").bind(project).bind(q.term()).bind(&q.ids).bind(q.limit()).bind(q.offset()).fetch_all(&st.pg).await?;
    Ok(Json(json!({"visitors":rows})))
}
#[derive(Deserialize)]
struct LinkPath {
    path: String,
}
async fn available(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Json(body): Json<LinkPath>,
) -> Api {
    authorize_project(&st, &user, project, true).await?;
    if body.path.is_empty()
        || body.path.len() > 100
        || !body
            .path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(bad("invalid path"));
    }
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM links WHERE project_id=$1 AND path=$2)",
    )
    .bind(project)
    .bind(body.path)
    .fetch_one(&st.pg)
    .await?;
    Ok(Json(json!({"available":!exists})))
}
async fn random_path(State(st): State<AppState>, user: AuthUser, Path(project): Path<Uuid>) -> Api {
    authorize_project(&st, &user, project, true).await?;
    Ok(Json(json!({"path":Uuid::new_v4().simple().to_string()})))
}
#[derive(Deserialize)]
struct ProgressQuery {
    category: Option<String>,
}
async fn progress(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Query(q): Query<ProgressQuery>,
) -> Api {
    authorize_instance(&st, &user, id, false).await?;
    let data = sqlx::query_scalar::<_, Value>("SELECT setup_progress FROM instances WHERE id=$1")
        .bind(id)
        .fetch_one(&st.pg)
        .await?;
    let steps: Vec<Value> = data
        .as_object()
        .into_iter()
        .flat_map(|o| o.values())
        .filter(|v| {
            q.category
                .as_ref()
                .is_none_or(|c| v["category"] == c.as_str())
        })
        .cloned()
        .collect();
    Ok(Json(json!({"steps":steps})))
}
#[derive(Deserialize)]
struct Step {
    category: String,
    step_identifier: String,
}
async fn complete(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<Step>,
) -> Api {
    authorize_instance(&st, &user, id, true).await?;
    if [&body.category, &body.step_identifier].iter().any(|s| {
        s.is_empty()
            || s.len() > 100
            || !s
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    }) {
        return Err(bad("invalid setup step"));
    }
    let key = format!("{}:{}", body.category, body.step_identifier);
    let step = json!({"category":body.category,"step_identifier":body.step_identifier,"completed_at":chrono::Utc::now()});
    let row=sqlx::query_scalar::<_,Value>("UPDATE instances SET setup_progress=CASE WHEN setup_progress ? $2 THEN setup_progress ELSE setup_progress||jsonb_build_object($2,$3::jsonb) END WHERE id=$1 RETURNING setup_progress->$2").bind(id).bind(key).bind(step).fetch_one(&st.pg).await?;
    Ok(Json(json!({"step":row})))
}
async fn dismiss(State(st): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Api {
    authorize_instance(&st, &user, id, true).await?;
    sqlx::query("UPDATE instances SET setup_progress=setup_progress||jsonb_build_object('get_started_dismissed',jsonb_build_object('completed_at',now())) WHERE id=$1").bind(id).execute(&st.pg).await?;
    Ok(Json(json!({"dismissed":true})))
}
async fn role(State(st): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Api {
    let role = authorize_instance(&st, &user, id, false).await?;
    Ok(Json(json!({"role":role})))
}
#[derive(Deserialize)]
struct Retention {
    cold_storage_days: i32,
    delete_days: i32,
}
async fn retention(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<Retention>,
) -> Api {
    if authorize_instance(&st, &user, id, true).await? != "owner" {
        return Err(AppError::Forbidden);
    }
    if !(1..=3650).contains(&body.cold_storage_days)
        || body.delete_days < body.cold_storage_days
        || body.delete_days > 3650
    {
        return Err(bad(
            "retention must satisfy 1 <= hot days <= delete days <= 3650",
        ));
    }
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT set_config('trisixt.actor_id',$1,true)")
        .bind(user.id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE instances SET cold_storage_days=$2,delete_days=$3 WHERE id=$1")
        .bind(id)
        .bind(body.cold_storage_days)
        .bind(body.delete_days)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"cold_storage_days":body.cold_storage_days,"delete_days":body.delete_days}),
    ))
}
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/projects/{id}/links/search", post(search_links))
        .route("/api/v1/projects/{id}/links/search_v2", post(search_links))
        .route("/api/v1/projects/{id}/links/by_ids", post(search_links))
        .route("/api/v1/projects/{id}/links/check_path", post(available))
        .route("/api/v1/projects/{id}/links/random_path", get(random_path))
        .route(
            "/api/v1/projects/{id}/campaigns/search",
            post(search_campaigns),
        )
        .route(
            "/api/v1/projects/{id}/campaigns/search_v2",
            post(search_campaigns),
        )
        .route(
            "/api/v1/projects/{id}/campaigns/by_ids",
            post(search_campaigns),
        )
        .route(
            "/api/v1/projects/{id}/visitors/search",
            post(search_visitors),
        )
        .route("/api/v1/instances/{id}/setup_progress", get(progress))
        .route(
            "/api/v1/instances/{id}/setup_progress/complete",
            post(complete),
        )
        .route("/api/v1/instances/{id}/dismiss_get_started", post(dismiss))
        .route("/api/v1/instances/{id}/role", get(role))
        .route(
            "/api/v1/instances/{id}/retention",
            axum::routing::put(retention),
        )
}
