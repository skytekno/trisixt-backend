//! Canonical analytics over the durable, tenant-scoped event ledger. Both
//! warehouse adapters receive the same events; explorer reads never mistake a
//! delayed warehouse delivery for an empty dataset.
use crate::{
    auth::{AuthUser, authorize_project},
    error::AppError,
    state::AppState,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;
type Api = Result<Json<Value>, AppError>;
const FIELDS: &[&str] = &[
    "event_id",
    "event_type",
    "event_name",
    "screen_name",
    "platform",
    "app_version",
    "country",
    "city",
    "device_model",
    "os",
    "os_version",
    "campaign_id",
    "link_id",
    "session_id",
    "visitor_id",
    "sdk_identifier",
    "tracking_source",
    "tracking_medium",
    "tracking_campaign",
    "ads_platform",
    "source",
    "has_conversion",
];
const COUNTABLE: &str =
    "('view','open','install','reinstall','time_spent','reactivation','app_open','user_referred')";
const BASE: &str = "WITH params AS (SELECT $1::uuid AS project,$2::timestamptz AS lower,$3::timestamptz AS upper,$4::text AS platform,$5::jsonb AS filters,$6::text AS timezone,$7::jsonb AS options),range_facts AS (SELECT f.* FROM analytics_event_facts f,params p WHERE f.project_id=p.project AND f.occurred_at>=p.lower AND f.occurred_at<p.upper AND (p.platform IS NULL OR f.platform=p.platform) AND trisixt_matches_filters(to_jsonb(f),p.filters) AND (p.options->>'search' IS NULL OR strpos(lower(f.event_name),lower(p.options->>'search'))>0 OR strpos(lower(f.screen_name),lower(p.options->>'search'))>0 OR strpos(lower(f.event_type),lower(p.options->>'search'))>0)),countable_history AS (SELECT h.visitor_id,min(h.occurred_at) first_countable FROM analytics_event_facts h,params p WHERE h.project_id=p.project AND (p.platform IS NULL OR h.platform=p.platform) AND lower(h.event_type) IN ('view','open','install','reinstall','time_spent','reactivation','app_open','user_referred') AND h.visitor_id IN(SELECT visitor_id FROM range_facts) GROUP BY h.visitor_id),filtered AS (SELECT f.*,h.first_countable FROM range_facts f LEFT JOIN countable_history h USING(visitor_id)) ";
fn bad(s: &str) -> AppError {
    AppError::BadRequest(s.into())
}
async fn bounded_read(
    st: &AppState,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, AppError> {
    let mut tx = st.pg.begin().await?;
    sqlx::query("SET LOCAL statement_timeout='15s'")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}
#[derive(Default, Deserialize)]
pub struct AnalyticsQuery {
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub timezone: Option<String>,
    pub platform: Option<String>,
    #[serde(default, deserialize_with = "filter_input")]
    pub filters: Option<String>,
    pub source: Option<String>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
    pub include_count: Option<bool>,
    pub field: Option<String>,
    #[serde(alias = "q")]
    pub query: Option<String>,
    pub search: Option<String>,
    pub bucket: Option<String>,
    pub metric: Option<String>,
    pub granularity: Option<String>,
    pub path: Option<String>,
    pub visitor_id: Option<Uuid>,
    pub campaign_id: Option<Uuid>,
    pub referrals: Option<bool>,
}
pub(crate) struct Range {
    pub(crate) from: DateTime<Utc>,
    pub(crate) to: DateTime<Utc>,
    pub(crate) timezone: String,
    pub(crate) platform: Option<String>,
    pub(crate) filters: Value,
    pub(crate) options: Value,
    cutoff: DateTime<Utc>,
}
fn filter_input<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let value = Option::<Value>::deserialize(deserializer)?;
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(v @ (Value::Array(_) | Value::Object(_))) => Ok(Some(v.to_string())),
        _ => Err(serde::de::Error::custom(
            "filters must be a JSON array, object or JSON string",
        )),
    }
}
fn property_key(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && !s
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '`' | '\\'))
        && !matches!(
            s.split('.').next().unwrap_or(s),
            "password_hash"
                | "token_hash"
                | "_attribution"
                | "_user_attributes"
                | "_sdk_identifier"
        )
}
fn field_name(field: &str) -> Result<String, AppError> {
    let field = match field {
        "campaign" => "campaign_id",
        "link" => "link_id",
        "visitor" => "visitor_id",
        x => x,
    };
    if FIELDS.contains(&field) {
        return Ok(field.into());
    }
    for prefix in ["user.", "properties."] {
        if let Some(key) = field.strip_prefix(prefix) {
            return if property_key(key) {
                Ok(field.into())
            } else {
                Err(bad("unsupported filter field"))
            };
        }
    }
    if property_key(field) {
        Ok(format!("properties.{field}"))
    } else {
        Err(bad("unsupported filter field"))
    }
}
fn valid_field(field: &str) -> bool {
    field_name(field).is_ok()
}
fn normalized_platform(s: &str) -> &str {
    match s {
        "desktop" | "mac" | "windows" | "linux" => "web",
        x => x,
    }
}

fn filters(raw: Option<&str>) -> Result<Value, AppError> {
    let mut value: Value = match raw {
        Some(s) if s.len() <= 16384 => {
            serde_json::from_str(s).map_err(|_| bad("filters must be JSON"))?
        }
        Some(_) => return Err(bad("filters too large")),
        None => json!([]),
    };
    if let Value::Object(object) = &value {
        value = if object.contains_key("field") || object.contains_key("f") {
            json!([value])
        } else {
            Value::Array(
                object
                    .iter()
                    .map(|(field, value)| json!({"field":field,"operator":"is","value":value}))
                    .collect(),
            )
        };
    }
    let list = value
        .as_array_mut()
        .filter(|v| v.len() <= 25)
        .ok_or_else(|| bad("at most 25 filters required"))?;
    for filter in list {
        if !filter.is_object() {
            return Err(bad("filter must be an object"));
        }
        for (long, short) in [("field", "f"), ("operator", "o"), ("value", "v")] {
            if filter.get(long).is_none() {
                filter[long] = filter[short].clone();
            }
        }
        let field = filter["field"]
            .as_str()
            .ok_or_else(|| bad("filter field required"))?;
        let field = field_name(field)?;
        filter["field"] = json!(field);
        if field == "platform" {
            if let Some(values) = filter["value"].as_array_mut() {
                for value in values {
                    if let Some(text) = value.as_str() {
                        *value = json!(normalized_platform(text));
                    }
                }
            } else if let Some(value) = filter["value"].as_str() {
                filter["value"] = json!(normalized_platform(value));
            }
        }
        if field == "has_conversion" {
            filter["value"] = json!(match &filter["value"] {
                Value::Bool(b) => *b,
                Value::Number(n) => n.as_i64() == Some(1),
                Value::String(s) => s == "1" || s.eq_ignore_ascii_case("true"),
                _ => return Err(bad("boolean filter requires true or false")),
            });
        }
        let op = filter["operator"]
            .as_str()
            .or(filter["op"].as_str())
            .ok_or_else(|| bad("filter operator required"))?;
        let op = match op {
            "is" | "equals" if filter["value"].is_array() => "in",
            "is_not" | "not_equals" if filter["value"].is_array() => "not_in",
            "is" | "equals" => "eq",
            "is_not" | "not_equals" => "neq",
            "greater_than" => "gt",
            "less_than" => "lt",
            x => x,
        };
        if ![
            "eq",
            "neq",
            "in",
            "not_in",
            "contains",
            "not_contains",
            "starts_with",
            "is_set",
            "is_not_set",
            "gt",
            "gte",
            "lt",
            "lte",
        ]
        .contains(&op)
        {
            return Err(bad("unsupported filter operator"));
        }
        if ["in", "not_in"].contains(&op)
            && !filter["value"].as_array().is_some_and(|a| a.len() <= 100)
        {
            return Err(bad(
                "filter membership value must be an array of at most 100 items",
            ));
        }
        if ["contains", "not_contains", "starts_with"].contains(&op) && !filter["value"].is_string()
        {
            return Err(bad("text filter requires text"));
        }
        let op = op.to_owned();
        filter["operator"] = json!(op);
    }
    Ok(value)
}
fn decode(raw: &str) -> Result<Value, AppError> {
    if raw.len() > 2048 {
        return Err(bad("invalid cursor"));
    }
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(raw)
            .map_err(|_| bad("invalid cursor"))?,
    )
    .map_err(|_| bad("invalid cursor"))
}
fn encode(v: &Value) -> String {
    URL_SAFE_NO_PAD.encode(v.to_string())
}
impl Range {
    pub(crate) async fn new(
        st: &AppState,
        project: Uuid,
        q: &AnalyticsQuery,
        aggregate: bool,
    ) -> Result<Self, AppError> {
        let timezone = q.timezone.as_deref().unwrap_or("UTC");
        let tz: chrono_tz::Tz = timezone.parse().map_err(|_| bad("invalid timezone"))?;
        let today = Utc::now().with_timezone(&tz).date_naive();
        let date = |s: &str| {
            NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|_| bad("date must be YYYY-MM-DD"))
        };
        let instant = |s: &str| {
            DateTime::parse_from_rfc3339(s)
                .map(|d| d.with_timezone(&Utc))
                .map_err(|_| bad("timestamp must have a UTC offset"))
        };
        let midnight = |d: NaiveDate| {
            tz.from_local_datetime(&d.and_hms_opt(0, 0, 0).unwrap())
                .earliest()
                .map(|d| d.with_timezone(&Utc))
                .ok_or_else(|| bad("nonexistent local date boundary"))
        };
        let start = q
            .start_date
            .as_deref()
            .map(date)
            .transpose()?
            .unwrap_or(today - Duration::days(30));
        let end = q
            .end_date
            .as_deref()
            .map(date)
            .transpose()?
            .unwrap_or(today);
        let from = q
            .from
            .as_deref()
            .map(instant)
            .transpose()?
            .unwrap_or(midnight(start)?);
        let to =
            q.to.as_deref()
                .map(instant)
                .transpose()?
                .unwrap_or(midnight(
                    end.succ_opt().ok_or_else(|| bad("date out of range"))?,
                )?);
        if from >= to || to - from > Duration::days(3651) {
            return Err(bad("invalid date range"));
        }
        if aggregate
            && (to.with_timezone(&tz).date_naive() - from.with_timezone(&tz).date_naive())
                .num_days()
                > 90
        {
            return Err(bad("aggregate queries are limited to 90 calendar days"));
        }
        let policy=sqlx::query("SELECT i.cold_storage_days,i.delete_days,EXISTS(SELECT 1 FROM billing_subscriptions b WHERE b.instance_id=i.id AND b.status NOT IN ('canceled','incomplete_expired')) OR EXISTS(SELECT 1 FROM enterprise_subscriptions e WHERE e.instance_id=i.id AND e.active AND e.start_date<=now() AND e.end_date>=now()) AS paid FROM projects p JOIN instances i ON i.id=p.instance_id WHERE p.id=$1").bind(project).fetch_one(&st.pg).await?;
        let cold: i32 = policy.get("cold_storage_days");
        let days: i32 = if crate::billing::self_hosted() || policy.get::<bool, _>("paid") {
            policy.get("delete_days")
        } else {
            cold
        };
        if from.with_timezone(&tz).date_naive() < today - Duration::days(i64::from(days)) {
            return Err(bad("requested range exceeds the instance retention window"));
        }
        let mut filter = filters(q.filters.as_deref())?;
        if let Some(visitor) = q.visitor_id {
            filter
                .as_array_mut()
                .unwrap()
                .push(json!({"field":"visitor_id","operator":"eq","value":visitor}));
        }
        if let Some(campaign) = q.campaign_id {
            filter
                .as_array_mut()
                .unwrap()
                .push(json!({"field":"campaign_id","operator":"eq","value":campaign}));
        }
        if let Some(path) = &q.path {
            let link = sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM links WHERE project_id=$1 AND path=$2",
            )
            .bind(project)
            .bind(path)
            .fetch_optional(&st.pg)
            .await?
            .ok_or(AppError::NotFound)?;
            filter
                .as_array_mut()
                .unwrap()
                .push(json!({"field":"link_id","operator":"eq","value":link}));
        }
        if let Some(source) = &q.source {
            if !["campaigns", "referrals", "api_links", "links", "organic"]
                .contains(&source.as_str())
            {
                return Err(bad("invalid source category"));
            }
            filter
                .as_array_mut()
                .unwrap()
                .push(json!({"field":"source","operator":"eq","value":source}));
        }
        if from.with_timezone(&tz).date_naive() < today - Duration::days(i64::from(cold))
            && filter.as_array().unwrap().iter().any(|f| {
                ["contains", "not_contains", "neq", "not_in"]
                    .contains(&f["operator"].as_str().unwrap_or(""))
            })
        {
            return Err(bad(
                "substring and exclusion filters are unavailable outside the hot window",
            ));
        }
        let limit = q.limit.unwrap_or(50);
        if !(1..=200).contains(&limit) {
            return Err(bad("limit must be between 1 and 200"));
        }
        if q.platform.as_ref().is_some_and(|p| {
            ![
                "ios", "android", "web", "desktop", "mac", "windows", "linux", "other",
            ]
            .contains(&p.as_str())
        }) {
            return Err(bad("invalid platform"));
        }
        let cursor = q.cursor.as_deref().map(decode).transpose()?;
        Ok(Self {
            from,
            to,
            timezone: timezone.into(),
            platform: q
                .platform
                .as_deref()
                .map(normalized_platform)
                .map(str::to_string),
            filters: filter,
            options: json!({"limit":limit,"cursor":cursor,"field":q.field,"query":q.query,"search":q.search}),
            cutoff: midnight(today - Duration::days(i64::from(days)))?,
        })
    }
    fn fingerprint(&self) -> String {
        crate::auth::token_hash(&json!({"from":self.from,"to":self.to,"timezone":self.timezone,"platform":self.platform,"filters":self.filters,"search":self.options["search"],"session_filters":self.options["session_filters"]}).to_string())
    }
    async fn rows(
        &self,
        st: &AppState,
        project: Uuid,
        suffix: &str,
    ) -> Result<Vec<Value>, AppError> {
        // suffix is assembled only from static SQL and whitelisted identifiers.
        let sql = format!("{BASE}{suffix}");
        let mut tx = bounded_read(st).await?;
        let result = sqlx::query_scalar::<_, Value>(sqlx::AssertSqlSafe(sql))
            .bind(project)
            .bind(self.from)
            .bind(self.to)
            .bind(&self.platform)
            .bind(&self.filters)
            .bind(&self.timezone)
            .bind(&self.options)
            .fetch_all(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(result)
    }
}
pub async fn explorer(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Query(q): Query<AnalyticsQuery>,
) -> Api {
    authorize_project(&st, &user, project, false).await?;
    let r = Range::new(&st, project, &q, false).await?;
    let sort = match q.sort_by.as_deref().unwrap_or("occurred_at") {
        "created_at" | "occurred_at" => "occurred_at",
        "event_type" => "event_type",
        "event_name" => "event_name",
        "platform" => "platform",
        "app_version" => "app_version",
        _ => return Err(bad("unsupported sort field")),
    };
    let (order, op) = match q.sort_order.as_deref().unwrap_or("desc") {
        "desc" => ("DESC", "<"),
        "asc" => ("ASC", ">"),
        _ => return Err(bad("sort_order must be asc or desc")),
    };
    let cast = if sort == "occurred_at" {
        "timestamptz"
    } else {
        "text"
    };
    if let Some(c) = r.options.get("cursor").filter(|c| !c.is_null()) {
        if c["sort"] != sort
            || c["order"] != order
            || c["project"] != project.to_string()
            || c["query"] != r.fingerprint()
            || c["id"]
                .as_str()
                .and_then(|s| s.parse::<Uuid>().ok())
                .is_none()
            || c["value"].as_str().is_none()
        {
            return Err(bad("cursor does not match this query"));
        }
        if sort == "occurred_at"
            && DateTime::parse_from_rfc3339(c["value"].as_str().unwrap()).is_err()
        {
            return Err(bad("invalid cursor timestamp"));
        }
    }
    let suffix = format!(
        "SELECT (to_jsonb(f)-'user_attributes'-'first_countable'-'original_visitor_id')||jsonb_build_object('properties',NULL) FROM filtered f,params p WHERE p.options->'cursor'='null'::jsonb OR (f.{sort},f.id) {op} ((p.options#>>'{{cursor,value}}')::{cast},(p.options#>>'{{cursor,id}}')::uuid) ORDER BY f.{sort} {order},f.id {order} LIMIT (SELECT (options->>'limit')::int+1 FROM params)"
    );
    let mut rows = r.rows(&st, project, &suffix).await?;
    let limit = q.limit.unwrap_or(50) as usize;
    let more = rows.len() > limit;
    rows.truncate(limit);
    let next = if more {
        rows.last().map(|v| {
            encode(
                &json!({"sort":sort,"order":order,"project":project,"query":r.fingerprint(),"value":v[sort],"id":v["id"]}),
            )
        })
    } else {
        None
    };
    let count = if q.include_count.unwrap_or(false) && r.to - r.from <= Duration::days(90) {
        r.rows(&st, project, "SELECT to_jsonb(count(*)) FROM filtered")
            .await?
            .first()
            .cloned()
    } else {
        None
    };
    Ok(Json(
        json!({"data":rows,"events":rows,"next_cursor":next,"count":count,"total_count":count}),
    ))
}
async fn event(
    State(st): State<AppState>,
    user: AuthUser,
    Path((project, id)): Path<(Uuid, Uuid)>,
) -> Api {
    authorize_project(&st, &user, project, false).await?;
    let mut tx = bounded_read(&st).await?;
    let event=sqlx::query_scalar::<_,Value>("SELECT to_jsonb(f) FROM analytics_event_facts f WHERE project_id=$1 AND (event_id=$2 OR id=$2)").bind(project).bind(id).fetch_optional(&mut *tx).await?.ok_or(AppError::NotFound)?;
    tx.commit().await?;
    let at = event["occurred_at"].as_str().ok_or(AppError::Internal)?;
    let time = DateTime::parse_from_rfc3339(at).map_err(|_| AppError::Internal)?;
    Range::new(
        &st,
        project,
        &AnalyticsQuery {
            from: Some(time.to_rfc3339()),
            to: Some((time + Duration::seconds(1)).to_rfc3339()),
            ..Default::default()
        },
        false,
    )
    .await?;
    Ok(Json(event))
}
async fn fields(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Query(q): Query<AnalyticsQuery>,
) -> Api {
    authorize_project(&st, &user, project, false).await?;
    let r = Range::new(&st, project, &q, false).await?;
    let mut tx = bounded_read(&st).await?;
    let discovered = sqlx::query_scalar::<_,Value>("WITH RECURSIVE paths(kind,path,value) AS (SELECT x.kind,e.key,e.value FROM analytics_event_facts f CROSS JOIN LATERAL (VALUES('property'::text,f.properties),('user_attribute'::text,f.user_attributes)) x(kind,obj) CROSS JOIN LATERAL jsonb_each(x.obj) e WHERE f.project_id=$1 AND f.occurred_at>=$2 AND f.occurred_at<$3 UNION ALL SELECT p.kind,p.path||'.'||e.key,e.value FROM paths p CROSS JOIN LATERAL jsonb_each(CASE WHEN jsonb_typeof(p.value)='object' THEN p.value ELSE '{}'::jsonb END) e WHERE length(p.path)<256),names AS(SELECT DISTINCT kind,path FROM paths WHERE jsonb_typeof(value)<>'object'),ranked AS(SELECT *,row_number() OVER(PARTITION BY kind ORDER BY path) n FROM names) SELECT jsonb_build_object('name',CASE WHEN kind='user_attribute' THEN 'user.'||path ELSE path END,'type',kind) FROM ranked WHERE n<=100 ORDER BY kind,path").bind(project).bind(r.from).bind(r.to).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    let mut fields: Vec<Value> = FIELDS
        .iter()
        .filter(|f| **f != "has_conversion")
        .map(|name| json!({"name":name,"type":"attribute"}))
        .collect();
    fields.extend(discovered.into_iter().filter(|f| {
        f["name"]
            .as_str()
            .is_some_and(|s| valid_field(s) && !FIELDS.contains(&s))
    }));
    let names: Vec<_> = fields.iter().map(|f| f["name"].clone()).collect();
    Ok(Json(json!({"fields":fields,"names":names})))
}
async fn field_values(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Query(q): Query<AnalyticsQuery>,
) -> Api {
    authorize_project(&st, &user, project, false).await?;
    let field = field_name(q.field.as_deref().ok_or_else(|| bad("field required"))?)?;
    let mut r = Range::new(&st, project, &q, true).await?;
    r.options["field"] = json!(field);
    let cursor = &r.options["cursor"];
    if !cursor.is_null()
        && (cursor["project"] != project.to_string()
            || cursor["field"] != field
            || cursor["value"].as_str().is_none()
            || cursor["query"] != r.fingerprint())
    {
        return Err(bad("field cursor does not match this query"));
    }
    let mut rows=r.rows(&st,project,",field_values AS(SELECT CASE WHEN starts_with(p.options->>'field','user.') THEN coalesce(f.user_attributes->substring(p.options->>'field' FROM 6),f.user_attributes#>string_to_array(substring(p.options->>'field' FROM 6),'.')) WHEN starts_with(p.options->>'field','properties.') THEN coalesce(f.properties->substring(p.options->>'field' FROM 12),f.properties#>string_to_array(substring(p.options->>'field' FROM 12),'.')) ELSE to_jsonb(f)->(p.options->>'field') END val FROM filtered f,params p) SELECT jsonb_build_object('value',val#>>'{}','count',count(*),'name',CASE WHEN p.options->>'field'='link_id' THEN(SELECT name FROM links WHERE project_id=p.project AND id::text=val#>>'{}') WHEN p.options->>'field'='campaign_id' THEN(SELECT name FROM campaigns WHERE project_id=p.project AND id::text=val#>>'{}') WHEN p.options->>'field'='visitor_id' THEN(SELECT coalesce(external_id,id::text) FROM visitors WHERE project_id=p.project AND id::text=val#>>'{}') END) FROM field_values,params p WHERE val IS NOT NULL AND val<>'null'::jsonb AND val#>>'{}'<>'' AND (p.options->>'query' IS NULL OR strpos(lower(val#>>'{}'),lower(p.options->>'query'))>0) AND (p.options->'cursor'='null'::jsonb OR val#>>'{}'>p.options#>>'{cursor,value}') GROUP BY val,p.project,p.options ORDER BY val#>>'{}' LIMIT(SELECT (options->>'limit')::int+1 FROM params)").await?;
    let limit = q.limit.unwrap_or(50) as usize;
    let more = rows.len() > limit;
    rows.truncate(limit);
    let next = if more {
        rows.last().map(|r0|encode(&json!({"project":project,"field":field,"value":r0["value"],"query":r.fingerprint()})))
    } else {
        None
    };
    let values: Vec<Value> = rows
        .iter()
        .map(|r| {
            if ["link_id", "campaign_id", "visitor_id"].contains(&field.as_str()) {
                json!({"id":r["value"],"name":r["name"]})
            } else {
                r["value"].clone()
            }
        })
        .collect();
    Ok(Json(
        json!({"data":rows,"values":values,"next_cursor":next}),
    ))
}
async fn volume(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Query(q): Query<AnalyticsQuery>,
) -> Api {
    authorize_project(&st, &user, project, false).await?;
    let r = Range::new(&st, project, &q, true).await?;
    let days = (r.to - r.from).num_days();
    let bucket = q.bucket.as_deref().unwrap_or(if days <= 3 {
        "hour"
    } else if days <= 31 {
        "day"
    } else {
        "week"
    });
    let expr = match bucket {
        "hour" => {
            "to_char(date_trunc('hour',occurred_at AT TIME ZONE (SELECT timezone FROM params)),'YYYY-MM-DD HH24:00:00')"
        }
        "day" => "((occurred_at AT TIME ZONE (SELECT timezone FROM params))::date)::text",
        "week" => {
            "((occurred_at AT TIME ZONE (SELECT timezone FROM params))::date-extract(dow FROM occurred_at AT TIME ZONE (SELECT timezone FROM params))::int)::text"
        }
        "month" => {
            "date_trunc('month',occurred_at AT TIME ZONE (SELECT timezone FROM params))::date::text"
        }
        _ => return Err(bad("bucket must be hour, day, week or month")),
    };
    let buckets=r.rows(&st,project,&format!("SELECT jsonb_build_object('bucket',{expr},'count',count(*)) FROM filtered GROUP BY {expr} ORDER BY {expr}")).await?;
    Ok(Json(json!({"buckets":buckets})))
}

const METRICS: &str = "jsonb_build_object('views',count(*) FILTER(WHERE upper(event_type)='VIEW'),'link_views',count(*) FILTER(WHERE upper(event_type)='VIEW' AND link_id IS NOT NULL),'opens',count(*) FILTER(WHERE upper(event_type)='OPEN'),'installs',count(*) FILTER(WHERE upper(event_type)='INSTALL'),'link_driven_installs',count(*) FILTER(WHERE upper(event_type)='INSTALL' AND link_id IS NOT NULL),'organic_installs',count(*) FILTER(WHERE upper(event_type)='INSTALL' AND link_id IS NULL),'reinstalls',count(*) FILTER(WHERE upper(event_type)='REINSTALL'),'app_opens',count(*) FILTER(WHERE upper(event_type)='APP_OPEN'),'time_spent',coalesce(sum(engagement_time) FILTER(WHERE upper(event_type)='TIME_SPENT'),0),'reactivations',count(*) FILTER(WHERE upper(event_type)='REACTIVATION'),'user_referred',count(*) FILTER(WHERE upper(event_type)='USER_REFERRED'),'referred_users',count(*) FILTER(WHERE upper(event_type)='USER_REFERRED'),'total_users',count(DISTINCT visitor_id) FILTER(WHERE lower(event_type) IN ('view','open','install','reinstall','time_spent','reactivation','app_open','user_referred')),'new_users',count(DISTINCT visitor_id) FILTER(WHERE first_countable>=(SELECT lower FROM params) AND lower(event_type)='install'),'returning_users',count(DISTINCT visitor_id) FILTER(WHERE first_countable<(SELECT lower FROM params) AND lower(event_type) IN ('view','open','install','reinstall','time_spent','reactivation','app_open','user_referred')),'events',count(*))";
async fn overview(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Query(q): Query<AnalyticsQuery>,
) -> Api {
    authorize_project(&st, &user, project, false).await?;
    let r = Range::new(&st, project, &q, true).await?;
    let mut metrics = r
        .rows(&st, project, &format!("SELECT {METRICS} FROM filtered"))
        .await?
        .remove(0);
    let revenue = crate::purchase_lifecycle::revenue_metrics(
        &st,
        project,
        r.from,
        r.to,
        r.platform.as_deref(),
    )
    .await?;
    let revenue_cents = revenue["revenue_usd_nanos"]
        .as_str()
        .and_then(|s| s.parse::<i128>().ok())
        .unwrap_or(0)
        / 10_000_000;
    for (key, value) in revenue.as_object().unwrap() {
        if key != "daily_series" {
            metrics[key] = value.clone();
        }
    }
    metrics["revenue"] = json!(i64::try_from(revenue_cents).map_err(|_| AppError::Internal)?);
    let users = metrics["total_users"].as_f64().unwrap_or(0.);
    let returning = metrics["returning_users"].as_f64().unwrap_or(0.);
    metrics["returning_rate"] = json!(if users > 0. {
        (returning / users * 10000.).round() / 10000.
    } else {
        0.
    });
    let revenue_value = revenue_cents as f64;
    let payers = metrics["paying_users"].as_f64().unwrap_or(0.);
    metrics["arpu"] = json!(if users > 0. {
        (revenue_value / users * 100.).round() / 100.
    } else {
        0.
    });
    metrics["arppu"] = json!(if payers > 0. {
        (revenue_value / payers * 100.).round() / 100.
    } else {
        0.
    });
    Ok(Json(json!({"metrics":metrics})))
}
fn metric_expression(metric: &str) -> Result<&'static str, AppError> {
    Ok(match metric {
        "views" => "count(*) FILTER(WHERE upper(event_type)='VIEW')",
        "link_views" => "count(*) FILTER(WHERE upper(event_type)='VIEW' AND link_id IS NOT NULL)",
        "opens" => "count(*) FILTER(WHERE upper(event_type)='OPEN')",
        "installs" => "count(*) FILTER(WHERE upper(event_type)='INSTALL')",
        "link_driven_installs" => {
            "count(*) FILTER(WHERE upper(event_type)='INSTALL' AND link_id IS NOT NULL)"
        }
        "organic_installs" => {
            "count(*) FILTER(WHERE upper(event_type)='INSTALL' AND link_id IS NULL)"
        }
        "reinstalls" => "count(*) FILTER(WHERE upper(event_type)='REINSTALL')",
        "time_spent" => {
            "coalesce(sum(engagement_time) FILTER(WHERE upper(event_type)='TIME_SPENT'),0)"
        }
        "reactivations" => "count(*) FILTER(WHERE upper(event_type)='REACTIVATION')",
        "user_referred" => "count(*) FILTER(WHERE upper(event_type)='USER_REFERRED')",
        "app_opens" => "count(*) FILTER(WHERE upper(event_type)='APP_OPEN')",
        "referred_users" => "count(*) FILTER(WHERE upper(event_type)='USER_REFERRED')",
        "total_users" => {
            "count(DISTINCT visitor_id) FILTER(WHERE lower(event_type) IN ('view','open','install','reinstall','time_spent','reactivation','app_open','user_referred'))"
        }
        "new_users" => {
            "count(DISTINCT visitor_id) FILTER(WHERE first_countable>=(SELECT lower FROM params) AND lower(event_type)='install')"
        }
        "returning_users" => {
            "count(DISTINCT visitor_id) FILTER(WHERE first_countable<(SELECT lower FROM params) AND lower(event_type) IN ('view','open','install','reinstall','time_spent','reactivation','app_open','user_referred'))"
        }
        "events" => "count(*)",
        _ => return Err(bad("unsupported metric")),
    })
}
async fn series(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Query(q): Query<AnalyticsQuery>,
) -> Api {
    authorize_project(&st, &user, project, false).await?;
    let r = Range::new(&st, project, &q, true).await?;
    let metric = q.metric.as_deref().unwrap_or("events");
    let rows = if metric == "new_users" {
        new_user_days(&st, project, &r).await?
    } else if [
        "revenue",
        "units_sold",
        "cancellations",
        "paying_users",
        "first_time_purchases",
    ]
    .contains(&metric)
    {
        revenue_days(&st, project, &r, metric).await?
    } else {
        let expression = if metric == "returning_users" {
            "count(DISTINCT visitor_id) FILTER(WHERE lower(event_type) IN ('view','open','install','reinstall','time_spent','reactivation','app_open','user_referred') AND (first_countable AT TIME ZONE (SELECT timezone FROM params))::date<(occurred_at AT TIME ZONE (SELECT timezone FROM params))::date)"
        } else {
            metric_expression(metric)?
        };
        r.rows(&st,project,&format!("SELECT jsonb_build_object('date',(occurred_at AT TIME ZONE (SELECT timezone FROM params))::date,'value',{expression}) FROM filtered GROUP BY (occurred_at AT TIME ZONE (SELECT timezone FROM params))::date ORDER BY 1")).await?
    };
    let map = day_map(rows);
    let tz: chrono_tz::Tz = r.timezone.parse().map_err(|_| AppError::Internal)?;
    let start = r.from.with_timezone(&tz).date_naive();
    let end = (r.to - Duration::microseconds(1))
        .with_timezone(&tz)
        .date_naive();
    let points: Vec<Value> = (0..=(end - start).num_days())
        .map(|n| {
            let date = (start + Duration::days(n)).to_string();
            json!({"date":date,"value":map.get(&date).cloned().unwrap_or(json!(0))})
        })
        .collect();
    Ok(Json(json!({"metric":metric,"points":points})))
}
async fn versions(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Query(q): Query<AnalyticsQuery>,
) -> Api {
    authorize_project(&st, &user, project, false).await?;
    let r = Range::new(&st, project, &q, true).await?;
    let rows=r.rows(&st,project,",counts AS(SELECT coalesce(nullif(app_version,''),'Unknown') version,platform,count(DISTINCT visitor_id) users,count(*) events FROM filtered GROUP BY 1,2),ranked AS(SELECT *,row_number() OVER(PARTITION BY platform ORDER BY users DESC,version) rank FROM counts) SELECT to_jsonb(r)-'rank' FROM ranked r WHERE rank<=10 ORDER BY platform,users DESC,version").await?;
    let mut platforms = serde_json::Map::new();
    for row in &rows {
        let key = row["platform"].as_str().unwrap_or("other");
        platforms
            .entry(key.to_owned())
            .or_insert(json!([]))
            .as_array_mut()
            .unwrap()
            .push(row.clone());
    }
    for entries in platforms.values_mut() {
        let total: i64 = entries
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|r| r["users"].as_i64())
            .sum();
        for row in entries.as_array_mut().unwrap() {
            let n = row["users"].as_i64().unwrap_or(0);
            row["percent"] = json!(if total > 0 {
                (n as f64 / total as f64 * 1000.).round() / 10.
            } else {
                0.
            });
        }
    }
    Ok(Json(
        json!({"data":rows,"versions":rows,"platforms":platforms}),
    ))
}
async fn version_distribution(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Query(mut q): Query<AnalyticsQuery>,
) -> Api {
    authorize_project(&st, &user, project, false).await?;
    q.limit = Some(q.limit.unwrap_or(10));
    let r = Range::new(&st, project, &q, true).await?;
    let data=r.rows(&st,project,",top_versions AS(SELECT coalesce(nullif(app_version,''),'Unknown') version,count(DISTINCT visitor_id) users FROM filtered GROUP BY 1 ORDER BY users DESC,version LIMIT(SELECT (options->>'limit')::int FROM params)),counts AS(SELECT coalesce(nullif(app_version,''),'Unknown') version,platform,count(DISTINCT visitor_id) users FROM filtered GROUP BY 1,2) SELECT jsonb_build_object('version',c.version,'total',sum(c.users),'platforms',jsonb_object_agg(c.platform,c.users),'release_date',(SELECT min((f.occurred_at AT TIME ZONE p.timezone)::date) FROM analytics_event_facts f,params p WHERE f.project_id=p.project AND coalesce(nullif(f.app_version,''),'Unknown')=c.version)) FROM counts c JOIN top_versions t USING(version) GROUP BY c.version ORDER BY sum(c.users) DESC,c.version").await?;
    Ok(Json(json!({"entries":data,"data":data})))
}
async fn sources(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Query(q): Query<AnalyticsQuery>,
) -> Api {
    authorize_project(&st, &user, project, false).await?;
    let r = Range::new(&st, project, &q, true).await?;
    let data=r.rows(&st,project,&format!("SELECT jsonb_build_object('source',source,'visitors',count(DISTINCT visitor_id),'metrics',{METRICS}) FROM filtered GROUP BY source ORDER BY count(DISTINCT visitor_id) DESC,source")).await?;
    let sources:Vec<Value>=data.iter().map(|r|json!({"name":match r["source"].as_str().unwrap_or(""){"campaigns"=>"Campaigns","referrals"=>"Referrals","api_links"=>"API Links","links"=>"Links",_=>"Organic"},"value":r["visitors"]})).collect();
    let total: i64 = data.iter().filter_map(|r| r["visitors"].as_i64()).sum();
    Ok(Json(json!({"data":data,"sources":sources,"total":total})))
}
async fn new_user_days(st: &AppState, project: Uuid, r: &Range) -> Result<Vec<Value>, AppError> {
    r.rows(st,project,&format!(",new_people AS(SELECT visitor_id,min(first_countable) first_date FROM filtered WHERE lower(event_type) IN {COUNTABLE} GROUP BY visitor_id HAVING min(first_countable)>=(SELECT lower FROM params) AND bool_or(lower(event_type)='install')) SELECT jsonb_build_object('date',(first_date AT TIME ZONE (SELECT timezone FROM params))::date,'value',count(*)) FROM new_people GROUP BY (first_date AT TIME ZONE (SELECT timezone FROM params))::date ORDER BY 1")).await
}
async fn revenue_days(
    st: &AppState,
    project: Uuid,
    r: &Range,
    metric: &str,
) -> Result<Vec<Value>, AppError> {
    let expression = match metric {
        "revenue" => "trunc(coalesce(sum(l.usd_nanos),0)/10000000)::bigint",
        "units_sold" => {
            "coalesce(sum(l.quantity) FILTER(WHERE l.event_type IN('BUY','REFUND','REFUND_REVERSED')),0)"
        }
        "cancellations" => "count(*) FILTER(WHERE l.event_type='CANCEL')",
        "paying_users" => {
            "count(DISTINCT l.visitor_id) FILTER(WHERE l.event_type IN('BUY','REFUND_REVERSED'))"
        }
        "first_time_purchases" => {
            "count(DISTINCT l.visitor_id) FILTER(WHERE l.event_type='BUY' AND NOT EXISTS(SELECT 1 FROM purchase_ledger prev WHERE prev.project_id=l.project_id AND prev.visitor_id=l.visitor_id AND prev.event_type='BUY' AND (prev.occurred_at,prev.id)<(l.occurred_at,l.id)))"
        }
        _ => return Err(bad("unsupported revenue metric")),
    };
    let query = format!(
        "SELECT jsonb_build_object('date',(l.occurred_at AT TIME ZONE $5)::date,'value',{expression}) FROM purchase_ledger l JOIN verified_purchases p ON p.id=l.purchase_id WHERE l.project_id=$1 AND l.occurred_at>=$2 AND l.occurred_at<$3 AND ($4::text IS NULL OR p.platform=$4) GROUP BY (l.occurred_at AT TIME ZONE $5)::date ORDER BY 1"
    );
    let mut tx = bounded_read(st).await?;
    let rows = sqlx::query_scalar::<_, Value>(sqlx::AssertSqlSafe(query))
        .bind(project)
        .bind(r.from)
        .bind(r.to)
        .bind(&r.platform)
        .bind(&r.timezone)
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(rows)
}
fn day_map(rows: Vec<Value>) -> std::collections::BTreeMap<String, Value> {
    rows.into_iter()
        .filter_map(|r| Some((r["date"].as_str()?.to_string(), r["value"].clone())))
        .collect()
}
async fn trends(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Query(q): Query<AnalyticsQuery>,
) -> Api {
    authorize_project(&st, &user, project, false).await?;
    let mut r = Range::new(&st, project, &q, true).await?;
    let tz: chrono_tz::Tz = r.timezone.parse().map_err(|_| AppError::Internal)?;
    let start = r.from.with_timezone(&tz).date_naive();
    let end = (r.to - Duration::microseconds(1))
        .with_timezone(&tz)
        .date_naive();
    let length = (end - start).num_days() + 1;
    let users = day_map(new_user_days(&st, project, &r).await?);
    let revenue = day_map(revenue_days(&st, project, &r, "revenue").await?);
    let previous_start = start - Duration::days(length);
    let old_from = r.from;
    r.to = old_from;
    r.from = tz
        .from_local_datetime(&previous_start.and_hms_opt(0, 0, 0).unwrap())
        .earliest()
        .ok_or_else(|| bad("nonexistent local date boundary"))?
        .with_timezone(&Utc)
        .max(r.cutoff);
    let (previous_users, previous_revenue) = if r.from < r.to {
        (
            day_map(new_user_days(&st, project, &r).await?),
            day_map(revenue_days(&st, project, &r, "revenue").await?),
        )
    } else {
        (Default::default(), Default::default())
    };
    let points:Vec<Value>=(0..length).map(|i|{let date=(start+Duration::days(i)).to_string();let previous=(previous_start+Duration::days(i)).to_string();let users=users.get(&date).cloned().unwrap_or(json!(0));let prev=previous_users.get(&previous).cloned().unwrap_or(json!(0));json!({"date":date,"new_users":users,"previous_new_users":prev,"users":users,"previous_users":prev,"revenue_usd_cents":revenue.get(&date).cloned().unwrap_or(json!(0)),"previous_revenue_usd_cents":previous_revenue.get(&previous).cloned().unwrap_or(json!(0))})}).collect();
    Ok(Json(json!({"points":points,"data":points})))
}

const COHORT_CTE: &str = ",cohort_candidates AS (SELECT v.id,CASE WHEN p.platform IS NULL THEN v.first_seen_at ELSE (SELECT min(f.occurred_at) FROM analytics_event_facts f WHERE f.project_id=p.project AND f.visitor_id=v.id AND f.platform=p.platform) END first_seen_at,(SELECT max(f.occurred_at) FROM analytics_event_facts f WHERE f.project_id=p.project AND f.visitor_id=v.id AND (p.platform IS NULL OR f.platform=p.platform)) last_seen FROM visitors v,params p WHERE v.project_id=p.project AND NOT EXISTS(SELECT 1 FROM visitor_aliases a WHERE a.project_id=v.project_id AND a.alias_id=v.id) AND (p.filters='[]' OR EXISTS(SELECT 1 FROM analytics_event_facts f WHERE f.project_id=p.project AND f.visitor_id=v.id AND trisixt_matches_filters(to_jsonb(f),p.filters)))),cohorts AS (SELECT c.*,(c.first_seen_at AT TIME ZONE p.timezone)::date cohort_date,(c.last_seen AT TIME ZONE p.timezone)::date last_event_date FROM cohort_candidates c,params p WHERE c.first_seen_at>=p.lower AND c.first_seen_at<p.upper)";
async fn retention(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Query(q): Query<AnalyticsQuery>,
) -> Api {
    authorize_project(&st, &user, project, false).await?;
    let r = Range::new(&st, project, &q, true).await?;
    if !["weekly", "monthly", "daily"].contains(&q.granularity.as_deref().unwrap_or("weekly")) {
        return Err(bad("invalid granularity"));
    }
    let rates=r.rows(&st,project,&format!("{COHORT_CTE} SELECT jsonb_build_object('day',d,'rate',round(100.0*count(c.id) FILTER(WHERE last_event_date>=cohort_date+d)/nullif(count(c.id),0),1)) FROM unnest(ARRAY[1,3,7,14,30,60,90]) d LEFT JOIN cohorts c ON c.first_seen_at<=now()-make_interval(days=>d) GROUP BY d ORDER BY d")).await?;
    let rate = |d: i64| {
        rates
            .iter()
            .find(|r| r["day"] == d)
            .map(|r| r["rate"].clone())
            .unwrap_or(Value::Null)
    };
    let median = rates
        .iter()
        .find(|r| r["rate"].as_f64().is_some_and(|n| n < 50.))
        .map(|r| r["day"].clone());
    let spark=r.rows(&st,project,&format!("{COHORT_CTE} SELECT jsonb_build_object('date',cohort_date,'total',count(*),'rate',round(100.0*count(*) FILTER(WHERE last_event_date>=cohort_date+1)/nullif(count(*),0),1)) FROM cohorts WHERE first_seen_at<=now()-interval '1 day' GROUP BY cohort_date ORDER BY cohort_date")).await?;
    Ok(Json(
        json!({"day_1":rate(1),"day_7":rate(7),"day_30":rate(30),"sparkline":spark,"median_churn_day":median}),
    ))
}
const SESSION_CTE: &str = r#",session_ordered AS (
 SELECT f.*,(f.occurred_at AT TIME ZONE 'UTC')::date event_date,left(f.session_id,256) raw_session_id,
 lag(f.occurred_at) OVER(PARTITION BY visitor_id,(f.occurred_at AT TIME ZONE 'UTC')::date ORDER BY occurred_at,id) previous_ts,
 row_number() OVER(PARTITION BY visitor_id,(f.occurred_at AT TIME ZONE 'UTC')::date ORDER BY occurred_at,id) row_no
 FROM analytics_event_facts f,params p WHERE f.project_id=p.project AND f.occurred_at>=date_trunc('day',p.lower AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AND f.occurred_at<(date_trunc('day',(p.upper-interval '1 microsecond') AT TIME ZONE 'UTC')+interval '1 day') AT TIME ZONE 'UTC'
),session_chunks AS (
 SELECT *,sum(CASE WHEN previous_ts IS NULL OR occurred_at-previous_ts>interval '30 minutes' THEN 1 ELSE 0 END) OVER(PARTITION BY visitor_id,event_date ORDER BY occurred_at,id) chunk FROM session_ordered
),session_future AS (
 SELECT *,min(row_no) FILTER(WHERE raw_session_id<>'') OVER(PARTITION BY visitor_id,event_date,chunk ORDER BY occurred_at,id ROWS BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING) next_real,
 first_value(id::text) OVER(PARTITION BY visitor_id,event_date,chunk ORDER BY occurred_at,id) chunk_id FROM session_chunks
),sessionized AS (
 SELECT f.*,coalesce(nullif(f.raw_session_id,''),n.raw_session_id,'synth_'||f.visitor_id::text||'_'||f.chunk_id) resolved_session FROM session_future f LEFT JOIN session_ordered n ON n.visitor_id=f.visitor_id AND n.event_date=f.event_date AND n.row_no=f.next_real
),session_agg AS (
 SELECT resolved_session AS session_id,visitor_id,event_date,min(occurred_at) started_at,max(occurred_at) ended_at,extract(epoch FROM max(occurred_at)-min(occurred_at))*1000 duration_ms,count(*) event_count,
 (array_agg(platform ORDER BY occurred_at DESC,id DESC))[1] platform,(array_agg(app_version ORDER BY occurred_at DESC,id DESC))[1] app_version,(array_agg(country ORDER BY occurred_at DESC,id DESC))[1] country,(array_agg(device_model ORDER BY occurred_at DESC,id DESC))[1] device_model,
 (array_agg(link_id ORDER BY occurred_at,id))[1] link_id,(array_agg(campaign_id ORDER BY occurred_at,id))[1] campaign_id,(array_agg(source ORDER BY occurred_at,id))[1] source,(array_agg(tracking_source ORDER BY occurred_at,id))[1] tracking_source,
 count(*) FILTER(WHERE screen_name<>'') screen_count,(array_agg(screen_name ORDER BY occurred_at,id) FILTER(WHERE screen_name<>''))[1] first_screen,(array_agg(screen_name ORDER BY occurred_at DESC,id DESC) FILTER(WHERE screen_name<>''))[1] last_screen
 FROM sessionized GROUP BY resolved_session,visitor_id,event_date
),sessions AS (
 SELECT a.*,payment.has_conversion,payment.revenue_usd_cents FROM session_agg a LEFT JOIN LATERAL(
 SELECT count(*)>0 has_conversion,trunc(coalesce(sum(l.usd_nanos),0)/10000000)::bigint revenue_usd_cents FROM purchase_ledger l JOIN verified_purchases v ON v.id=l.purchase_id,params p
 WHERE l.project_id=p.project AND coalesce((SELECT visitor_id FROM visitor_aliases WHERE project_id=p.project AND alias_id=l.visitor_id),l.visitor_id)=a.visitor_id AND l.event_type='BUY'
 AND ((v.session_id=a.session_id AND (l.occurred_at AT TIME ZONE 'UTC')::date=a.event_date) OR ((nullif(v.session_id,'') IS NULL OR NOT EXISTS(SELECT 1 FROM session_agg existing WHERE existing.visitor_id=a.visitor_id AND existing.event_date=a.event_date AND existing.session_id=v.session_id)) AND l.occurred_at BETWEEN a.started_at AND a.ended_at))
 ) payment ON true
) "#;
async fn sessions(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Query(q): Query<AnalyticsQuery>,
) -> Api {
    authorize_project(&st, &user, project, false).await?;
    let mut r = Range::new(&st, project, &q, false).await?;
    for filter in r.filters.as_array().unwrap() {
        if ![
            "platform",
            "country",
            "link_id",
            "campaign_id",
            "has_conversion",
            "app_version",
            "source",
            "visitor_id",
        ]
        .contains(&filter["field"].as_str().unwrap_or(""))
        {
            return Err(bad("unsupported session filter"));
        }
    }
    let mut session_filters = r.filters.clone();
    if let Some(platform) = r.platform.take() {
        session_filters
            .as_array_mut()
            .unwrap()
            .push(json!({"field":"platform","operator":"eq","value":platform}));
    }
    r.options["session_filters"] = session_filters;
    r.filters = json!([]);
    let cursor = r.options["cursor"].clone();
    if !cursor.is_null()
        && (cursor["p"] != project.to_string()
            || cursor["query"] != r.fingerprint()
            || cursor["s"].as_str().is_none()
            || cursor["v"]
                .as_str()
                .and_then(|s| s.parse::<Uuid>().ok())
                .is_none()
            || cursor["t"]
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .is_none())
    {
        return Err(bad("invalid session cursor"));
    }
    r.options["cursor"] = cursor;
    let suffix = format!(
        "{SESSION_CTE} SELECT to_jsonb(s) FROM sessions s,params p WHERE s.ended_at>=p.lower AND s.started_at<p.upper AND trisixt_matches_filters(to_jsonb(s),p.options->'session_filters') AND (p.options->'cursor'='null'::jsonb OR (s.started_at,s.session_id,s.visitor_id)<((p.options#>>'{{cursor,t}}')::timestamptz,p.options#>>'{{cursor,s}}',(p.options#>>'{{cursor,v}}')::uuid)) ORDER BY started_at DESC,session_id DESC,visitor_id DESC LIMIT (SELECT (options->>'limit')::int+1 FROM params)"
    );
    let mut data = r.rows(&st, project, &suffix).await?;
    let limit = q.limit.unwrap_or(50) as usize;
    let more = data.len() > limit;
    data.truncate(limit);
    let cursor = if more {
        data.last().map(|v| {
            encode(
                &json!({"p":project,"query":r.fingerprint(),"t":v["started_at"],"s":v["session_id"],"v":v["visitor_id"]}),
            )
        })
    } else {
        None
    };
    for row in &mut data {
        row["id"] = json!(encode(
            &json!({"s":row["session_id"],"v":row["visitor_id"],"d":row["event_date"]})
        ));
    }
    Ok(Json(json!({"data":data,"next_cursor":cursor})))
}
async fn session(
    State(st): State<AppState>,
    user: AuthUser,
    Path((project, key)): Path<(Uuid, String)>,
) -> Api {
    authorize_project(&st, &user, project, false).await?;
    let key = decode(&key)?;
    let sid = key["s"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .ok_or_else(|| bad("invalid session key"))?;
    let visitor = key["v"]
        .as_str()
        .and_then(|s| s.parse::<Uuid>().ok())
        .ok_or_else(|| bad("invalid session visitor"))?;
    let day = key["d"]
        .as_str()
        .ok_or_else(|| bad("invalid session day"))?;
    let q = AnalyticsQuery {
        start_date: Some(day.into()),
        end_date: Some(day.into()),
        ..Default::default()
    };
    let mut r = Range::new(&st, project, &q, false).await?;
    r.options["detail"] = json!({"session":sid,"visitor":visitor});
    let sessions=r.rows(&st,project,&format!("{SESSION_CTE} SELECT to_jsonb(s) FROM sessions s,params p WHERE s.session_id=p.options#>>'{{detail,session}}' AND s.visitor_id=(p.options#>>'{{detail,visitor}}')::uuid")).await?;
    let session = sessions.first().ok_or(AppError::NotFound)?;
    let events=r.rows(&st,project,&format!("{SESSION_CTE} SELECT (to_jsonb(f)-'previous_ts'-'row_no'-'chunk'-'next_real'-'chunk_id'-'resolved_session'-'raw_session_id')||jsonb_build_object('session_id',f.resolved_session) FROM sessionized f,params p WHERE f.resolved_session=p.options#>>'{{detail,session}}' AND f.visitor_id=(p.options#>>'{{detail,visitor}}')::uuid ORDER BY occurred_at,id LIMIT 10001")).await?;
    if events.len() > 10000 {
        return Err(bad(
            "session exceeds 10000 events; use event explorer to paginate",
        ));
    }
    Ok(Json(json!({"session":session,"events":events})))
}

pub async fn link_summary(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Query(q): Query<AnalyticsQuery>,
) -> Api {
    authorize_project(&st, &user, project, false).await?;
    let r = Range::new(&st, project, &q, true).await?;
    // The original link_session_daily rollup excludes zero-duration bounces and
    // divides total engaged duration by engaged-session count exactly once.
    // Reuse the canonical stitching/day/visitor rules from the sessions API.
    let data=r.rows(&st,project,&format!("{SESSION_CTE},link_metrics AS (SELECT link_id,campaign_id,{METRICS} metrics,count(*) events FROM filtered WHERE link_id IS NOT NULL GROUP BY link_id,campaign_id),link_session_metrics AS (SELECT s.link_id,round(sum(s.duration_ms)/count(*)/1000,2) avg_seconds FROM session_agg s,params p WHERE s.duration_ms>0 AND s.link_id IS NOT NULL AND s.ended_at>=p.lower AND s.started_at<p.upper AND (p.platform IS NULL OR s.platform=p.platform) AND EXISTS(SELECT 1 FROM filtered f WHERE f.link_id=s.link_id AND f.visitor_id=s.visitor_id AND (f.occurred_at AT TIME ZONE 'UTC')::date=s.event_date) GROUP BY s.link_id) SELECT jsonb_build_object('link_id',l.link_id,'campaign_id',l.campaign_id,'metrics',l.metrics||jsonb_build_object('avg_engagement_time',coalesce(s.avg_seconds,0))) FROM link_metrics l LEFT JOIN link_session_metrics s ON s.link_id=l.link_id ORDER BY l.events DESC,l.link_id LIMIT (SELECT (options->>'limit')::int FROM params)")).await?;
    Ok(Json(json!({"data":data,"links":data})))
}
async fn campaign_summary(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Query(q): Query<AnalyticsQuery>,
) -> Api {
    authorize_project(&st, &user, project, false).await?;
    let r = Range::new(&st, project, &q, true).await?;
    let data=r.rows(&st,project,&format!("SELECT jsonb_build_object('campaign_id',campaign_id,'metrics',{METRICS}) FROM filtered WHERE campaign_id IS NOT NULL GROUP BY campaign_id ORDER BY count(*) DESC,campaign_id LIMIT (SELECT (options->>'limit')::int FROM params)")).await?;
    Ok(Json(json!({"data":data,"campaigns":data})))
}
async fn visitor_metrics(
    State(st): State<AppState>,
    user: AuthUser,
    Path(project): Path<Uuid>,
    Query(q): Query<AnalyticsQuery>,
) -> Api {
    authorize_project(&st, &user, project, false).await?;
    let r = Range::new(&st, project, &q, true).await?;
    let data=r.rows(&st,project,&format!("SELECT jsonb_build_object('visitor_id',visitor_id,'metrics',{METRICS},'last_seen_at',max(occurred_at)) FROM filtered GROUP BY visitor_id ORDER BY max(occurred_at) DESC,visitor_id LIMIT (SELECT (options->>'limit')::int FROM params)")).await?;
    Ok(Json(json!({"data":data,"visitors":data})))
}
async fn links_post(
    s: State<AppState>,
    u: AuthUser,
    p: Path<Uuid>,
    Json(q): Json<AnalyticsQuery>,
) -> Api {
    link_summary(s, u, p, Query(q)).await
}
async fn visitors_post(
    s: State<AppState>,
    u: AuthUser,
    p: Path<Uuid>,
    Json(q): Json<AnalyticsQuery>,
) -> Api {
    visitor_metrics(s, u, p, Query(q)).await
}
async fn overview_post(
    s: State<AppState>,
    u: AuthUser,
    p: Path<Uuid>,
    Json(q): Json<AnalyticsQuery>,
) -> Api {
    overview(s, u, p, Query(q)).await
}
async fn explorer_post(
    s: State<AppState>,
    u: AuthUser,
    p: Path<Uuid>,
    Json(q): Json<AnalyticsQuery>,
) -> Api {
    explorer(s, u, p, Query(q)).await
}
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/projects/{id}/analytics/links", get(link_summary))
        .route(
            "/api/v1/projects/{id}/analytics/campaigns",
            get(campaign_summary),
        )
        .route(
            "/api/v1/projects/{id}/analytics/visitors",
            get(visitor_metrics),
        )
        .route(
            "/api/v1/projects/{id}/dashboard/top_links",
            axum::routing::post(links_post),
        )
        .route(
            "/api/v1/projects/{id}/dashboard/links_views",
            axum::routing::post(links_post),
        )
        .route(
            "/api/v1/projects/{id}/dashboard/metrics_overview",
            axum::routing::post(overview_post),
        )
        .route(
            "/api/v1/projects/{id}/events/search",
            axum::routing::post(explorer_post),
        )
        .route(
            "/api/v1/projects/{id}/events/sorted",
            axum::routing::post(explorer_post),
        )
        .route(
            "/api/v1/projects/{id}/events/overview",
            axum::routing::post(overview_post),
        )
        .route("/api/v1/projects/{id}/events/metric_values", get(fields))
        .route(
            "/api/v1/projects/{id}/visitors/aggregated",
            axum::routing::post(visitors_post),
        )
        .route(
            "/api/v1/projects/{id}/visitors/aggregated_metrics",
            axum::routing::post(visitors_post),
        )
        .route(
            "/api/v1/projects/{id}/visitors/metrics",
            axum::routing::post(visitors_post),
        )
        .route("/api/v1/projects/{id}/analytics/events", get(explorer))
        .route("/api/v1/projects/{id}/analytics/events/fields", get(fields))
        .route(
            "/api/v1/projects/{id}/analytics/events/field-values",
            get(field_values),
        )
        .route("/api/v1/projects/{id}/analytics/events/volume", get(volume))
        .route(
            "/api/v1/projects/{id}/analytics/events/{event_id}",
            get(event),
        )
        .route(
            "/api/v1/projects/{id}/analytics/overview/key-metrics",
            get(overview),
        )
        .route(
            "/api/v1/projects/{id}/analytics/overview/key-metrics/series",
            get(series),
        )
        .route(
            "/api/v1/projects/{id}/analytics/overview/versions",
            get(versions),
        )
        .route(
            "/api/v1/projects/{id}/analytics/overview/versions/distribution",
            get(version_distribution),
        )
        .route(
            "/api/v1/projects/{id}/analytics/overview/trends/users",
            get(trends),
        )
        .route(
            "/api/v1/projects/{id}/analytics/overview/sources/breakdown",
            get(sources),
        )
        .route(
            "/api/v1/projects/{id}/analytics/retention/summary",
            get(retention),
        )
        .route("/api/v1/projects/{id}/analytics/sessions", get(sessions))
        .route(
            "/api/v1/projects/{id}/analytics/sessions/{key}",
            get(session),
        )
}
/// Server-SDK/automation aggregates over the same retained, frozen event facts
/// as dashboard analytics. Callers authenticate the project before this helper.
pub async fn metrics_for_scope(
    st: &AppState,
    project: Uuid,
    link: Option<Uuid>,
    visitor: Option<Uuid>,
    referrals: bool,
) -> Result<Value, AppError> {
    let query = AnalyticsQuery {
        start_date: Some(Utc::now().date_naive().to_string()),
        ..Default::default()
    };
    let mut range = Range::new(st, project, &query, false).await?;
    range.from = range.cutoff;
    range.options["link"] = json!(link);
    range.options["visitor"] = json!(visitor);
    range.options["referrals"] = json!(referrals);
    let suffix = format!(
        "SELECT {METRICS} FROM filtered f,params p WHERE (p.options->>'link' IS NULL OR f.link_id=(p.options->>'link')::uuid) AND (p.options->>'visitor' IS NULL OR CASE WHEN (p.options->>'referrals')::bool THEN coalesce((SELECT visitor_id FROM visitor_aliases WHERE project_id=p.project AND alias_id=trisixt_uuid(f.properties#>>'{{_attribution,link_visitor_id}}')),trisixt_uuid(f.properties#>>'{{_attribution,link_visitor_id}}'))=(p.options->>'visitor')::uuid ELSE f.visitor_id=(p.options->>'visitor')::uuid END)"
    );
    let mut result = range.rows(st, project, &suffix).await?.remove(0);
    let mut tx = bounded_read(st).await?;
    let revenue=sqlx::query_scalar::<_,i64>("SELECT trunc(coalesce(sum(usd_nanos),0)/10000000)::bigint FROM purchase_ledger l WHERE project_id=$1 AND occurred_at>=$2 AND occurred_at<$3 AND($4::uuid IS NULL OR attributed_link_id=$4) AND($5::uuid IS NULL OR coalesce((SELECT visitor_id FROM visitor_aliases WHERE project_id=l.project_id AND alias_id=CASE WHEN $6 THEN l.inviter_id ELSE l.visitor_id END),CASE WHEN $6 THEN l.inviter_id ELSE l.visitor_id END)=$5)").bind(project).bind(range.from).bind(range.to).bind(link).bind(visitor).bind(referrals).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    result["revenue"] = json!(revenue);
    result["revenue_usd_cents"] = json!(revenue);
    result["unique_visitors"] = result["total_users"].clone();
    for key in [
        "views",
        "opens",
        "installs",
        "reinstalls",
        "time_spent",
        "reactivations",
        "app_opens",
        "user_referred",
        "revenue",
    ] {
        result[format!("total_{key}")] = result[key].clone();
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_filter_operators_and_cursors() {
        assert!(
            filters(Some(
                r#"[{"field":"platform","operator":"is","value":"ios"}]"#
            ))
            .is_ok()
        );
        assert!(
            filters(Some(
                r#"[{"field":"password_hash","operator":"eq","value":"x"}]"#
            ))
            .is_err()
        );
        assert!(
            filters(Some(
                r#"[{"field":"platform","operator":"in","value":"ios"}]"#
            ))
            .is_err()
        );
        assert!(decode("invalid!").is_err());
        assert_eq!(decode(&encode(&json!({"x":1}))).unwrap(), json!({"x":1}));
    }
}
