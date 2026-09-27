//! Device identity, deferred links, attribution and SDK utilities.
use crate::{
    auth::{self, SdkProject},
    core_api::{EventInput, persist_events},
    error::AppError,
    state::AppState,
};
use axum::{
    Json, Router,
    extract::{ConnectInfo, FromRequestParts, Query, State},
    http::{HeaderMap, request::Parts},
    routing::{get, post},
};
use chrono::Utc;
use serde_json::{Value, json};
use sqlx::Row;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};
use uuid::Uuid;
type Api = Result<Json<Value>, AppError>;
fn bad(s: &str) -> AppError {
    AppError::BadRequest(s.into())
}
#[derive(Clone, Default)]
pub struct ClientContext {
    pub ip: Option<IpAddr>,
    pub user_agent: String,
}
impl FromRequestParts<AppState> for ClientContext {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, _: &AppState) -> Result<Self, AppError> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|p| p.0.ip());
        let trusted: Vec<IpAddr> = std::env::var("TRUSTED_PROXY_IPS")
            .unwrap_or_default()
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        let ip = forwarded_ip(
            peer,
            parts
                .headers
                .get("x-forwarded-for")
                .and_then(|h| h.to_str().ok()),
            &trusted,
        );
        Ok(Self {
            ip,
            user_agent: parts
                .headers
                .get("user-agent")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .chars()
                .take(2048)
                .collect(),
        })
    }
}
fn forwarded_ip(
    peer: Option<IpAddr>,
    forwarded: Option<&str>,
    trusted: &[IpAddr],
) -> Option<IpAddr> {
    let peer = peer?;
    if !trusted.contains(&peer) {
        return Some(peer);
    }
    let chain = forwarded.and_then(|s| {
        s.split(',')
            .map(|ip| ip.trim().parse::<IpAddr>())
            .collect::<Result<Vec<_>, _>>()
            .ok()
    });
    chain
        .and_then(|chain| chain.into_iter().rev().find(|ip| !trusted.contains(ip)))
        .or(Some(peer))
}
fn platform(ua: &str) -> &'static str {
    let ua = ua.to_lowercase();
    if ua.contains("iphone") || ua.contains("ipad") {
        "ios"
    } else if ua.contains("android") {
        "android"
    } else if ua.contains("windows") || ua.contains("macintosh") {
        "desktop"
    } else {
        "web"
    }
}
fn fingerprint(ctx: &ClientContext, ua: &str) -> Option<String> {
    let ip = ctx.ip?;
    if ua.is_empty() {
        return None;
    }
    let lower = ua.to_lowercase();
    let version = |prefixes: &[&str]| {
        prefixes
            .iter()
            .find_map(|p| {
                lower.split(p).nth(1).map(|s| {
                    s.chars()
                        .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '_')
                        .collect::<String>()
                        .replace('_', ".")
                })
            })
            .unwrap_or_default()
    };
    let (os, os_version) = if lower.contains("iphone") || lower.contains("ipad") {
        ("ios", version(&["iphone os ", "cpu os "]))
    } else if lower.contains("android") {
        ("android", version(&["android "]))
    } else if lower.contains("mac os x") {
        ("mac", version(&["mac os x "]))
    } else if lower.contains("windows nt") {
        ("windows", version(&["windows nt "]))
    } else {
        ("other", lower.clone())
    };
    let engine = if matches!(os, "ios" | "mac") {
        version(&["applewebkit/"])
    } else {
        version(&["chrome/", "firefox/", "version/"])
    };
    Some(auth::token_hash(&format!(
        "{ip}|{os}|{os_version}|{engine}"
    )))
}
fn text<'a>(body: &'a Value, key: &str, max: usize) -> Result<Option<&'a str>, AppError> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.len() <= max => Ok(Some(s)),
        _ => Err(bad("invalid or oversized text field")),
    }
}
fn object(v: &Value) -> Result<(), AppError> {
    if !v.is_object() || v.to_string().len() > 32768 {
        return Err(bad("attributes must be an object of at most 32 KiB"));
    }
    Ok(())
}
fn visitor_id(body: &Value, headers: &HeaderMap) -> Result<Uuid, AppError> {
    body.get("visitor_id")
        .and_then(Value::as_str)
        .or_else(|| headers.get("x-visitor-id").and_then(|h| h.to_str().ok()))
        .and_then(|s| s.parse::<Uuid>().ok())
        .filter(|u| !u.is_nil())
        .ok_or_else(|| bad("visitor_id required"))
}
pub async fn canonical(st: &AppState, project: Uuid, id: Uuid) -> Result<Uuid, AppError> {
    Ok(sqlx::query_scalar::<_,Uuid>("SELECT coalesce((SELECT visitor_id FROM visitor_aliases WHERE project_id=$1 AND alias_id=$2),$2)").bind(project).bind(id).fetch_one(&st.pg).await?)
}
async fn authenticate(
    State(st): State<AppState>,
    sdk: SdkProject,
    ctx: ClientContext,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Api {
    let project = sdk.id;
    sdk.check_body(&body)?;
    object(&body)?;
    let ua = text(&body, "user_agent", 2048)?.unwrap_or(&ctx.user_agent);
    let version = text(&body, "app_version", 100)?.ok_or_else(|| bad("app_version required"))?;
    if ua.is_empty() {
        return Err(bad("user_agent required"));
    }
    let vendor = text(&body, "vendor", 255)?
        .or(text(&body, "vendor_id", 255)?)
        .filter(|v| !v.trim().is_empty());
    let supplied = body
        .get("visitor_id")
        .and_then(Value::as_str)
        .or_else(|| headers.get("x-visitor-id").and_then(|h| h.to_str().ok()))
        .map(str::parse::<Uuid>)
        .transpose()
        .map_err(|_| bad("invalid visitor_id"))?;
    let id = supplied.unwrap_or_else(Uuid::new_v4);
    if id.is_nil() {
        return Err(bad("invalid visitor_id"));
    }
    let p = sdk.platform(text(&body, "platform", 20)?, platform(ua))?;
    if !["ios", "android", "web", "desktop", "other"].contains(&p) {
        return Err(bad("invalid platform"));
    }
    let model = crate::hardware::humanize(
        &st,
        p,
        text(&body, "model", 255)?
            .or(text(&body, "device", 255)?)
            .unwrap_or(""),
    )
    .await?;
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,42))")
        .bind(project.to_string())
        .execute(&mut *tx)
        .await?;
    let supplied=match supplied{Some(id)=>Some(sqlx::query_scalar::<_,Uuid>("SELECT coalesce((SELECT visitor_id FROM visitor_aliases WHERE project_id=$1 AND alias_id=$2),$2)").bind(project).bind(id).fetch_one(&mut *tx).await?),None=>None};
    if let Some(vendor) = vendor {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,41))")
            .bind(format!("{project}:{vendor}"))
            .execute(&mut *tx)
            .await?;
    }
    let found=sqlx::query("SELECT id,visitor_id FROM devices WHERE project_id=$1 AND (($2::text IS NOT NULL AND vendor_id=$2) OR ($3::uuid IS NOT NULL AND visitor_id=$3)) ORDER BY (vendor_id=$2) DESC NULLS LAST,updated_at DESC LIMIT 1 FOR UPDATE").bind(project).bind(vendor).bind(supplied).fetch_optional(&mut *tx).await?;
    let device = found
        .as_ref()
        .map(|r| r.get::<Uuid, _>("id"))
        .unwrap_or_else(Uuid::new_v4);
    let visitor = found.map(|r| r.get::<Uuid, _>("visitor_id")).unwrap_or(id);
    let visitor=sqlx::query_scalar::<_,Uuid>("SELECT coalesce((SELECT visitor_id FROM visitor_aliases WHERE project_id=$1 AND alias_id=$2),$2)").bind(project).bind(visitor).fetch_one(&mut *tx).await?;
    sqlx::query("INSERT INTO visitors(project_id,id) VALUES($1,$2) ON CONFLICT(project_id,id) DO UPDATE SET last_seen_at=now()").bind(project).bind(visitor).execute(&mut *tx).await?;
    let environment = text(&body, "push_environment", 20)?.unwrap_or("production");
    if !["test", "production"].contains(&environment) {
        return Err(bad("invalid push environment"));
    }
    let timezone = text(&body, "timezone", 100)?.unwrap_or("UTC");
    if timezone.parse::<chrono_tz::Tz>().is_err() {
        return Err(bad("invalid timezone"));
    }
    for key in ["screen_height", "screen_width"] {
        if body.get(key).is_some() && !body[key].as_i64().is_some_and(|v| (1..=32768).contains(&v))
        {
            return Err(bad("invalid screen dimensions"));
        }
    }
    let row=sqlx::query_scalar::<_,Value>("INSERT INTO devices(id,project_id,visitor_id,vendor_id,user_agent,app_version,build,model,platform,push_token,push_environment,language,timezone,screen_height,screen_width,webgl_vendor,webgl_renderer,ip) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18::text::inet) ON CONFLICT(id) DO UPDATE SET visitor_id=excluded.visitor_id,vendor_id=coalesce(excluded.vendor_id,devices.vendor_id),user_agent=excluded.user_agent,app_version=excluded.app_version,build=excluded.build,model=excluded.model,platform=excluded.platform,push_token=coalesce(excluded.push_token,devices.push_token),push_environment=excluded.push_environment,language=excluded.language,timezone=excluded.timezone,screen_height=excluded.screen_height,screen_width=excluded.screen_width,webgl_vendor=excluded.webgl_vendor,webgl_renderer=excluded.webgl_renderer,ip=excluded.ip,updated_at=now() RETURNING to_jsonb(devices)-'ip'")
 .bind(device).bind(project).bind(visitor).bind(vendor).bind(ua).bind(version).bind(text(&body,"build",100)?.unwrap_or("")).bind(&model).bind(p).bind(text(&body,"push_token",4096)?).bind(environment).bind(text(&body,"language",100)?.unwrap_or("")).bind(timezone).bind(body["screen_height"].as_i64().map(|v|v as i32)).bind(body["screen_width"].as_i64().map(|v|v as i32)).bind(text(&body,"webgl_vendor",255)?).bind(text(&body,"webgl_renderer",255)?).bind(ctx.ip.map(|v|v.to_string())).fetch_one(&mut *tx).await?;
    sqlx::query("UPDATE link_clicks SET device_id=$3 WHERE project_id=$1 AND visitor_id=$2 AND device_id IS NULL AND handled_at IS NULL AND created_at>now()-interval '5 minutes'").bind(project).bind(visitor).bind(device).execute(&mut *tx).await?;
    crate::billing::enforce_project_quota(&st, project, visitor).await?;
    tx.commit().await?;
    let profile=sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('sdk_identifier',external_id,'sdk_attributes',attributes) FROM visitors WHERE project_id=$1 AND id=$2").bind(project).bind(visitor).fetch_one(&st.pg).await?;
    let uri_scheme: Option<String> = sqlx::query_scalar(
        "SELECT to_jsonb(c)->$2->>'uri_scheme' FROM project_configurations c WHERE project_id=$1",
    )
    .bind(project)
    .bind(p)
    .fetch_optional(&st.pg)
    .await?
    .flatten();
    Ok(Json(
        json!({"uri_scheme":uri_scheme,"visitor_id":visitor,"device_id":device,"linksquared":visitor,"device":row,"sdk_identifier":profile["sdk_identifier"],"sdk_attributes":profile["sdk_attributes"],"push_token":row["push_token"]}),
    ))
}
async fn vendor(
    State(st): State<AppState>,
    sdk: SdkProject,
    Query(q): Query<HashMap<String, String>>,
) -> Api {
    let project = sdk.id;
    let vendor = q
        .get("vendor_id")
        .or(q.get("vendor"))
        .filter(|s| !s.trim().is_empty());
    let Some(vendor) = vendor else {
        return Ok(Json(Value::Null));
    };
    let row=sqlx::query_scalar::<_,Value>("SELECT (to_jsonb(d)-'ip')||jsonb_build_object('last_seen',(SELECT max(e.occurred_at) FROM events e WHERE e.project_id=d.project_id AND e.properties->>'_device_id'=d.id::text)) FROM devices d WHERE project_id=$1 AND vendor_id=$2 ORDER BY updated_at DESC LIMIT 1").bind(project).bind(vendor).fetch_optional(&st.pg).await?;
    Ok(Json(row.unwrap_or(Value::Null)))
}
async fn get_attributes(
    State(st): State<AppState>,
    sdk: SdkProject,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Api {
    let project = sdk.id;
    let id = visitor_id(&json!({"visitor_id":q.get("visitor_id")}), &headers)?;
    let id = canonical(&st, project, id).await?;
    let row=sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('visitor_id',id,'sdk_identifier',external_id,'attributes',attributes) FROM visitors WHERE project_id=$1 AND id=$2").bind(project).bind(id).fetch_optional(&st.pg).await?.ok_or(AppError::NotFound)?;
    Ok(Json(row))
}
async fn set_attributes(
    State(st): State<AppState>,
    sdk: SdkProject,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Api {
    let project = sdk.id;
    sdk.check_body(&body)?;
    object(&body)?;
    let requested = visitor_id(&body, &headers)?;
    let attrs = body
        .get("attributes")
        .or(body.get("sdk_attributes"))
        .cloned();
    let attrs = attrs.map(|v| if v.is_null() { json!({}) } else { v });
    if let Some(attrs) = &attrs {
        object(attrs)?;
    }
    let external = text(&body, "sdk_identifier", 254)?
        .or(text(&body, "external_id", 254)?)
        .filter(|s| !s.trim().is_empty());
    let replace_external =
        body.get("sdk_identifier").is_some() || body.get("external_id").is_some();
    let push = text(&body, "push_token", 4096)?;
    let change_push = body.get("push_token").is_some();
    let device = text(&body, "device_id", 36)?
        .map(str::parse::<Uuid>)
        .transpose()
        .map_err(|_| bad("invalid device id"))?;
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,42))")
        .bind(project.to_string())
        .execute(&mut *tx)
        .await?;
    let id=sqlx::query_scalar::<_,Uuid>("SELECT coalesce((SELECT visitor_id FROM visitor_aliases WHERE project_id=$1 AND alias_id=$2),$2)").bind(project).bind(requested).fetch_one(&mut *tx).await?;
    let row=sqlx::query_scalar::<_,Value>("UPDATE visitors SET attributes=coalesce($3::jsonb,attributes),external_id=CASE WHEN $5 THEN $4 ELSE external_id END,last_seen_at=now() WHERE project_id=$1 AND id=$2 RETURNING jsonb_build_object('visitor_id',id,'attributes',attributes,'sdk_identifier',external_id)").bind(project).bind(id).bind(attrs).bind(external).bind(replace_external).fetch_optional(&mut *tx).await?.ok_or(AppError::NotFound)?;
    if change_push {
        let updated=sqlx::query("UPDATE devices SET push_token=$3,updated_at=now() WHERE id=(SELECT id FROM devices WHERE project_id=$1 AND visitor_id=$2 AND ($4::uuid IS NULL OR id=$4) ORDER BY updated_at DESC LIMIT 1)").bind(project).bind(id).bind(push.filter(|s|!s.is_empty())).bind(device).execute(&mut *tx).await?.rows_affected();
        if updated != 1 {
            return Err(AppError::NotFound);
        }
    }
    tx.commit().await?;
    Ok(Json(row))
}
async fn screens(State(st): State<AppState>, sdk: SdkProject, Json(body): Json<Value>) -> Api {
    let project = sdk.id;
    sdk.check_body(&body)?;
    let entries = body["screen_aliases"]
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= 200)
        .ok_or_else(|| bad("screen_aliases must contain 1 to 200 entries"))?;
    let mut final_entries = std::collections::BTreeMap::new();
    for entry in entries {
        let id = text(entry, "identifier", 255)?.unwrap_or("").trim();
        let name = text(entry, "name", 255)?
            .or(text(entry, "alias", 255)?)
            .unwrap_or("")
            .trim();
        if !id.is_empty() && !name.is_empty() {
            final_entries.insert(id, name);
        }
    }
    let mut tx = st.pg.begin().await?;
    for (id, name) in &final_entries {
        sqlx::query("INSERT INTO screen_aliases(project_id,identifier,name) VALUES($1,$2,$3) ON CONFLICT(project_id,identifier) DO UPDATE SET name=excluded.name,updated_at=now()").bind(project).bind(id).bind(name).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(Json(json!({"saved":final_entries.len()})))
}
/// Flatten aliases under a project lock. Events remain immutable; reads resolve
/// their identity through aliases so retries cannot reintroduce a split visitor.
pub async fn merge_visitors(
    st: &AppState,
    project: Uuid,
    from: Uuid,
    to: Uuid,
) -> Result<(), AppError> {
    if from == to {
        return Ok(());
    }
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,42))")
        .bind(project.to_string())
        .execute(&mut *tx)
        .await?;
    let from=sqlx::query_scalar::<_,Uuid>("SELECT coalesce((SELECT visitor_id FROM visitor_aliases WHERE project_id=$1 AND alias_id=$2),$2)").bind(project).bind(from).fetch_one(&mut *tx).await?;
    let to=sqlx::query_scalar::<_,Uuid>("SELECT coalesce((SELECT visitor_id FROM visitor_aliases WHERE project_id=$1 AND alias_id=$2),$2)").bind(project).bind(to).fetch_one(&mut *tx).await?;
    if from == to {
        return Ok(());
    }
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM visitors WHERE project_id=$1 AND id IN($2,$3)",
    )
    .bind(project)
    .bind(from)
    .bind(to)
    .fetch_one(&mut *tx)
    .await?;
    if exists != 2 {
        return Err(AppError::NotFound);
    }
    let from_ids:Vec<Uuid>=sqlx::query_scalar("SELECT alias_id FROM visitor_aliases WHERE project_id=$1 AND visitor_id=$2 UNION SELECT $2").bind(project).bind(from).fetch_all(&mut *tx).await?;
    // Match event ingestion's visitor-before-billing lock order.
    sqlx::query(
        "SELECT id FROM visitors WHERE project_id=$1 AND id=ANY($2) ORDER BY id FOR UPDATE",
    )
    .bind(project)
    .bind(vec![from, to])
    .fetch_all(&mut *tx)
    .await?;
    let instance: Uuid = sqlx::query_scalar("SELECT instance_id FROM projects WHERE id=$1")
        .bind(project)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("billing:{instance}"))
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO monthly_active_visitors(instance_id,month,visitor_id) SELECT instance_id,month,$3 FROM monthly_active_visitors WHERE instance_id=$1 AND visitor_id=ANY($2) GROUP BY instance_id,month ON CONFLICT DO NOTHING").bind(instance).bind(&from_ids).bind(to).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM monthly_active_visitors WHERE instance_id=$1 AND visitor_id=ANY($2)")
        .bind(instance)
        .bind(&from_ids)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE verified_purchases SET visitor_id=$3 WHERE project_id=$1 AND visitor_id=ANY($2)",
    )
    .bind(project)
    .bind(&from_ids)
    .bind(to)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE purchase_ledger SET visitor_id=$3 WHERE project_id=$1 AND visitor_id=ANY($2)",
    )
    .bind(project)
    .bind(&from_ids)
    .bind(to)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE subscription_states SET visitor_id=$3 WHERE project_id=$1 AND visitor_id=ANY($2)",
    )
    .bind(project)
    .bind(&from_ids)
    .bind(to)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE browser_sessions SET visitor_id=$3 WHERE project_id=$1 AND visitor_id=ANY($2)",
    )
    .bind(project)
    .bind(&from_ids)
    .bind(to)
    .execute(&mut *tx)
    .await?;
    // Preserve notification delivery/read state when both identities received the
    // same campaign. Pending pushes move before duplicate message deletion.
    sqlx::query("INSERT INTO notification_messages(project_id,visitor_id,notification_id,read,created_at,updated_at) SELECT project_id,$3,notification_id,bool_or(read),min(created_at),max(updated_at) FROM notification_messages WHERE project_id=$1 AND visitor_id=ANY($2) GROUP BY project_id,notification_id ON CONFLICT(notification_id,visitor_id) DO UPDATE SET read=notification_messages.read OR excluded.read").bind(project).bind(&from_ids).bind(to).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO push_outbox(project_id,message_id,device_id,attempts,available_at,sent_at,invalidated_at,last_error) SELECT DISTINCT ON(target.id,p.device_id) p.project_id,target.id,p.device_id,p.attempts,p.available_at,p.sent_at,p.invalidated_at,p.last_error FROM notification_messages source JOIN notification_messages target ON target.project_id=source.project_id AND target.notification_id=source.notification_id AND target.visitor_id=$3 JOIN push_outbox p ON p.message_id=source.id WHERE source.project_id=$1 AND source.visitor_id=ANY($2) ORDER BY target.id,p.device_id,p.sent_at DESC NULLS LAST,p.invalidated_at DESC NULLS LAST ON CONFLICT(message_id,device_id) DO UPDATE SET sent_at=coalesce(push_outbox.sent_at,excluded.sent_at),invalidated_at=coalesce(push_outbox.invalidated_at,excluded.invalidated_at)").bind(project).bind(&from_ids).bind(to).execute(&mut *tx).await?;
    sqlx::query("UPDATE notification_messages target SET read=target.read OR source.read FROM notification_messages source WHERE target.project_id=$1 AND source.project_id=$1 AND source.visitor_id=ANY($2) AND target.visitor_id=$3 AND source.notification_id=target.notification_id").bind(project).bind(&from_ids).bind(to).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM notification_messages source USING notification_messages target WHERE source.project_id=$1 AND target.project_id=$1 AND source.visitor_id=ANY($2) AND target.visitor_id=$3 AND source.notification_id=target.notification_id").bind(project).bind(&from_ids).bind(to).execute(&mut *tx).await?;
    sqlx::query(
        "UPDATE notification_messages SET visitor_id=$3 WHERE project_id=$1 AND visitor_id=ANY($2)",
    )
    .bind(project)
    .bind(&from_ids)
    .bind(to)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE visitors target SET first_seen_at=least(target.first_seen_at,source.first_seen_at),last_seen_at=greatest(target.last_seen_at,source.last_seen_at),attributes=source.attributes||target.attributes,external_id=coalesce(target.external_id,source.external_id) FROM visitors source WHERE target.project_id=$1 AND source.project_id=$1 AND target.id=$2 AND source.id=$3").bind(project).bind(to).bind(from).execute(&mut *tx).await?;
    sqlx::query("UPDATE visitor_aliases SET visitor_id=$3 WHERE project_id=$1 AND visitor_id=$2")
        .bind(project)
        .bind(from)
        .bind(to)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO visitor_aliases(project_id,alias_id,visitor_id) VALUES($1,$2,$3)")
        .bind(project)
        .bind(from)
        .bind(to)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE devices SET visitor_id=$3 WHERE project_id=$1 AND visitor_id=$2")
        .bind(project)
        .bind(from)
        .bind(to)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO visitor_attributions(project_id,visitor_id,link_id,campaign_id,source,medium,attributed_at,method,metadata) SELECT project_id,$3,link_id,campaign_id,source,medium,attributed_at,method,metadata FROM visitor_attributions WHERE project_id=$1 AND visitor_id=$2 ON CONFLICT DO NOTHING").bind(project).bind(from).bind(to).execute(&mut *tx).await?;
    sqlx::query("UPDATE link_clicks SET claimed_by=$3 WHERE project_id=$1 AND claimed_by=ANY($2)")
        .bind(project)
        .bind(&from_ids)
        .bind(to)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    crate::purchase_lifecycle::backfill_attribution(st, project, to).await?;
    Ok(())
}
pub async fn attribute(
    st: &AppState,
    project: Uuid,
    visitor: Uuid,
    link: Uuid,
    method: &str,
) -> Result<(), AppError> {
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,42))")
        .bind(project.to_string())
        .execute(&mut *tx)
        .await?;
    let visitor=sqlx::query_scalar::<_,Uuid>("SELECT coalesce((SELECT visitor_id FROM visitor_aliases WHERE project_id=$1 AND alias_id=$2),$2)").bind(project).bind(visitor).fetch_one(&mut *tx).await?;
    sqlx::query("INSERT INTO visitor_attributions(project_id,visitor_id,link_id,campaign_id,source,medium,method) SELECT l.project_id,$2,l.id,l.campaign_id,l.metadata->>'tracking_source',l.metadata->>'tracking_medium',$4 FROM links l WHERE l.project_id=$1 AND l.id=$3 ON CONFLICT(project_id,visitor_id) DO UPDATE SET link_id=excluded.link_id,campaign_id=excluded.campaign_id,source=excluded.source,medium=excluded.medium,method=excluded.method,attributed_at=now()").bind(project).bind(visitor).bind(link).bind(method).execute(&mut *tx).await?;
    tx.commit().await?;
    crate::purchase_lifecycle::backfill_attribution(st, project, visitor).await?;
    Ok(())
}
pub struct Click {
    pub cookie: String,
    pub clipboard: String,
    pub visitor: Uuid,
}
pub async fn record_click(
    st: &AppState,
    project: Uuid,
    link: Uuid,
    headers: &HeaderMap,
    ctx: &ClientContext,
) -> Result<Click, AppError> {
    let existing = headers
        .get("cookie")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| {
            s.split(';')
                .filter_map(|part| part.trim().split_once('='))
                .find(|(k, _)| *k == "trisixt_visitor")
                .map(|(_, v)| v)
        });
    let existing_hash = existing.map(auth::token_hash);
    let found=sqlx::query_scalar::<_,Uuid>("SELECT visitor_id FROM browser_sessions WHERE project_id=$1 AND token_hash=$2 AND expires_at>now()").bind(project).bind(existing_hash).fetch_optional(&st.pg).await?;
    let visitor = found.unwrap_or_else(Uuid::new_v4);
    let (cookie, hash) = auth::new_token();
    let (clipboard, clipboard_hash) = auth::new_token();
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,42))")
        .bind(project.to_string())
        .execute(&mut *tx)
        .await?;
    let visitor=sqlx::query_scalar::<_,Uuid>("SELECT coalesce((SELECT visitor_id FROM visitor_aliases WHERE project_id=$1 AND alias_id=$2),$2)").bind(project).bind(visitor).fetch_one(&mut *tx).await?;

    sqlx::query("INSERT INTO visitors(project_id,id) VALUES($1,$2) ON CONFLICT(project_id,id) DO UPDATE SET last_seen_at=now()").bind(project).bind(visitor).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO browser_sessions(project_id,visitor_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '30 days')").bind(project).bind(visitor).bind(hash).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO link_clicks(project_id,link_id,visitor_id,fingerprint,clipboard_hash,platform) VALUES($1,$2,$3,$4,$5,$6)").bind(project).bind(link).bind(visitor).bind(fingerprint(ctx,&ctx.user_agent)).bind(clipboard_hash).bind(platform(&ctx.user_agent)).execute(&mut *tx).await?;
    tx.commit().await?;
    attribute(st, project, visitor, link, "click").await?;
    let _ = persist_events(
        st,
        project,
        vec![EventInput {
            event_id: Uuid::new_v4(),
            visitor_id: visitor,
            event_type: "view".into(),
            occurred_at: Utc::now(),
            properties: json!({"link_id":link,"platform":platform(&ctx.user_agent)}),
        }],
    )
    .await?;
    Ok(Click {
        cookie,
        clipboard,
        visitor,
    })
}
async fn resolve(
    State(st): State<AppState>,
    sdk: SdkProject,
    ctx: ClientContext,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Api {
    let project = sdk.id;
    sdk.check_body(&body)?;
    let p = sdk.platform(text(&body, "platform", 20)?, platform(&ctx.user_agent))?;
    object(&body)?;
    let visitor = canonical(&st, project, visitor_id(&body, &headers)?).await?;
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM visitors WHERE project_id=$1 AND id=$2)",
    )
    .bind(project)
    .bind(visitor)
    .fetch_one(&st.pg)
    .await?;
    if !exists {
        return Err(AppError::NotFound);
    }
    let session = text(&body, "session_id", 200)?;
    let raw = text(&body, "url", 8192)?;
    let input = raw.map(crate::imports::SdkLinkInput::parse).transpose()?;
    let parsed = input.as_ref().and_then(crate::imports::SdkLinkInput::url);
    let clipboard = parsed
        .and_then(|url| {
            url.query_pairs()
                .find(|(k, _)| k == "ct")
                .map(|(_, v)| v.into_owned())
        })
        .or_else(|| body["clipboard_token"].as_str().map(str::to_owned));
    let path =
        text(&body, "path", 100)?.or_else(|| parsed.map(|u| u.path().trim_start_matches('/')));
    let mut explicit = None;
    if let Some(input) = &input {
        let native_host = if let Some(host) = parsed
            .and_then(url::Url::host_str)
            .and_then(|host| crate::domains::normalize_hostname(host).ok())
        {
            // Migration custom hosts must use their old-path mapping even when
            // a native link happens to have the same path.
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1 AND lower(domain)=$2) OR EXISTS(SELECT 1 FROM custom_hostnames WHERE project_id=$1 AND hostname=$2 AND purpose='primary' AND status='active')",
            )
            .bind(project)
            .bind(host)
            .fetch_one(&st.pg)
            .await?
        } else {
            false
        };
        if !native_host {
            match crate::imports::resolve_sdk_input(&st, project, input).await? {
                Some(crate::imports::ImportOutcome::Link(link)) => explicit = Some(link),
                Some(crate::imports::ImportOutcome::Defaults) | None => {
                    return Ok(Json(json!({"data":null,"link":null,"tracking":null})));
                }
            }
        }
    }
    if explicit.is_none()
        && let Some(path) = path
    {
        explicit=sqlx::query_scalar::<_,Value>("SELECT to_jsonb(l) FROM links l WHERE project_id=$1 AND path=$2 AND archived_at IS NULL").bind(project).bind(path.trim_start_matches("l/")).fetch_optional(&st.pg).await?;
    }
    let explicit_id = explicit
        .as_ref()
        .and_then(|l| l["id"].as_str())
        .and_then(|id| id.parse::<Uuid>().ok());
    let fp = fingerprint(
        &ctx,
        text(&body, "user_agent", 2048)?.unwrap_or(&ctx.user_agent),
    );
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,42))")
        .bind(project.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,43))")
        .bind(project.to_string())
        .execute(&mut *tx)
        .await?;
    let visitor=sqlx::query_scalar::<_,Uuid>("SELECT coalesce((SELECT visitor_id FROM visitor_aliases WHERE project_id=$1 AND alias_id=$2),$2)").bind(project).bind(visitor).fetch_one(&mut *tx).await?;

    let mut matches=sqlx::query("SELECT c.id,c.link_id,c.visitor_id,c.handled_at,to_jsonb(d) device FROM link_clicks c LEFT JOIN devices d ON d.project_id=c.project_id AND d.id=c.device_id WHERE c.project_id=$1 AND (c.claimed_by IS NULL OR c.claimed_by=$5) AND ($3::text IS NOT NULL OR c.handled_at IS NULL) AND ($2::uuid IS NULL OR c.link_id=$2) AND ((c.clipboard_hash=$3 AND c.created_at>now()-interval '48 hours') OR ($3::text IS NULL AND c.fingerprint=$4 AND c.created_at>now()-interval '5 minutes')) ORDER BY c.created_at DESC LIMIT 20 FOR UPDATE OF c").bind(project).bind(explicit_id).bind(clipboard.as_deref().map(auth::token_hash)).bind(fp).bind(visitor).fetch_all(&mut *tx).await?;
    if clipboard.is_none()
        && matches
            .iter()
            .map(|r| r.get::<Uuid, _>("visitor_id"))
            .collect::<std::collections::HashSet<_>>()
            .len()
            > 1
    {
        let current=sqlx::query_scalar::<_,Value>("SELECT to_jsonb(d) FROM devices d WHERE project_id=$1 AND visitor_id=$2 ORDER BY updated_at DESC LIMIT 1").bind(project).bind(visitor).fetch_optional(&mut *tx).await?.unwrap_or(json!({}));
        matches.retain(|r| {
            let candidate: Option<Value> = r.get("device");
            candidate.is_some_and(|candidate| {
                [
                    "screen_width",
                    "screen_height",
                    "timezone",
                    "webgl_vendor",
                    "webgl_renderer",
                    "language",
                ]
                .iter()
                .all(|key| {
                    let expected = body.get(*key).unwrap_or(&current[*key]);
                    !expected.is_null() && expected != &json!("") && candidate[*key] == *expected
                })
            })
        });
    }
    let distinct = matches
        .iter()
        .map(|r| r.get::<Uuid, _>("visitor_id"))
        .collect::<std::collections::HashSet<_>>();
    let matched = if distinct.len() == 1 {
        Some(matches.remove(0))
    } else {
        None
    };
    let already_handled = matched.as_ref().is_some_and(|r| {
        r.get::<Option<chrono::DateTime<Utc>>, _>("handled_at")
            .is_some()
    });
    if already_handled {
        let owner = canonical(&st, project, matched.as_ref().unwrap().get("visitor_id")).await?;
        if explicit_id.is_none() || owner != visitor {
            return Ok(Json(json!({"data":null,"link":null,"tracking":null})));
        }
    }
    let link_id = explicit_id.or_else(|| matched.as_ref().map(|r| r.get::<Uuid, _>("link_id")));
    let Some(link_id) = link_id else {
        return Ok(Json(json!({"data":null,"link":null,"tracking":null})));
    };
    let link = match explicit {
        Some(link) => link,
        None => sqlx::query_scalar::<_, Value>(
            "SELECT to_jsonb(l) FROM links l WHERE project_id=$1 AND id=$2 AND archived_at IS NULL",
        )
        .bind(project)
        .bind(link_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AppError::NotFound)?,
    };
    if !matches!(p, "ios" | "android" | "web" | "desktop" | "other") {
        return Err(bad("invalid platform"));
    }
    if link["metadata"][format!("disable_{p}")] == true {
        return Ok(Json(json!({"data":null,"link":null,"tracking":null})));
    }
    if let Some(m) = &matched {
        sqlx::query("UPDATE link_clicks SET claimed_by=$4 WHERE project_id=$1 AND visitor_id=$2 AND created_at<=(SELECT created_at FROM link_clicks WHERE id=$3) AND (claimed_by IS NULL OR claimed_by=$4)").bind(project).bind(m.get::<Uuid,_>("visitor_id")).bind(m.get::<Uuid,_>("id")).bind(visitor).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    if let Some(m) = &matched {
        merge_visitors(&st, project, m.get("visitor_id"), visitor).await?;
    }
    attribute(
        &st,
        project,
        visitor,
        link_id,
        if clipboard.is_some() {
            "clipboard"
        } else if explicit_id.is_some() {
            "direct"
        } else {
            "fingerprint"
        },
    )
    .await?;
    if !already_handled {
        let _ = persist_events(
            &st,
            project,
            vec![EventInput {
                event_id: matched
                    .as_ref()
                    .map(|m| m.get::<Uuid, _>("id"))
                    .unwrap_or_else(Uuid::new_v4),
                visitor_id: visitor,
                event_type: "open".into(),
                occurred_at: Utc::now(),
                properties: json!({"link_id":link_id,"platform":p,"session_id":session}),
            }],
        )
        .await?;
    }
    if let Some(m) = &matched {
        sqlx::query("UPDATE link_clicks SET handled_at=coalesce(handled_at,now()) WHERE project_id=$1 AND visitor_id=$2 AND claimed_by=$4 AND created_at<=(SELECT created_at FROM link_clicks WHERE id=$3)").bind(project).bind(m.get::<Uuid,_>("visitor_id")).bind(m.get::<Uuid,_>("id")).bind(visitor).execute(&st.pg).await?;
    }
    Ok(Json(
        json!({"data":link["metadata"]["data"],"link":link["path"],"tracking":{"campaign":link["metadata"]["tracking_campaign"],"source":link["metadata"]["tracking_source"],"medium":link["metadata"]["tracking_medium"]},"link_id":link_id}),
    ))
}
async fn clipboard_status(
    State(st): State<AppState>,
    sdk: SdkProject,
    Json(body): Json<Value>,
) -> Api {
    let project = sdk.id;
    sdk.check_body(&body)?;
    if !body.is_object() {
        return Err(bad("JSON object required"));
    }
    if let Some(token) = text(&body, "clipboard_token", 64)? {
        let available=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM link_clicks WHERE project_id=$1 AND clipboard_hash=$2 AND handled_at IS NULL AND created_at>now()-interval '48 hours')").bind(project).bind(auth::token_hash(token)).fetch_one(&st.pg).await?;
        return Ok(Json(json!({"available":available})));
    }
    // Use the same database clock as the public renderer; application-server
    // clock skew must not extend or prematurely expire the activity window.
    let activity = sqlx::query_as::<_, (chrono::DateTime<Utc>, chrono::DateTime<Utc>)>(
        "SELECT last_eligible_at,now() FROM project_clipboard_activity WHERE project_id=$1",
    )
    .bind(project)
    .fetch_optional(&st.pg)
    .await?;
    let active = activity.is_some_and(|(last, now)| clipboard_activity_active(last, now));
    Ok(Json(json!({"clipboard_active":active})))
}
fn clipboard_activity_active(last: chrono::DateTime<Utc>, now: chrono::DateTime<Utc>) -> bool {
    last <= now && last > now - chrono::Duration::hours(48)
}
async fn custom_event(
    State(st): State<AppState>,
    sdk: SdkProject,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Api {
    let project = sdk.id;
    sdk.check_body(&body)?;
    let visitor = canonical(&st, project, visitor_id(&body, &headers)?).await?;
    let name = text(&body, "event_name", 100)?
        .or(text(&body, "name", 100)?)
        .ok_or_else(|| bad("event_name required"))?;
    let mut props = body
        .get("properties")
        .or(body.get("data"))
        .cloned()
        .unwrap_or(json!({}));
    object(&props)?;
    sdk.bind_event_platform(&mut props)?;
    props["event_name"] = json!(name);
    let id = body
        .get("event_id")
        .and_then(Value::as_str)
        .map(str::parse::<Uuid>)
        .transpose()
        .map_err(|_| bad("invalid event_id"))?
        .unwrap_or_else(Uuid::new_v4);
    persist_events(
        &st,
        project,
        vec![EventInput {
            event_id: id,
            visitor_id: visitor,
            event_type: "custom".into(),
            occurred_at: Utc::now(),
            properties: props,
        }],
    )
    .await
}
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/sdk/authenticate", post(authenticate))
        .route("/api/v1/sdk/device_for_vendor_id", get(vendor))
        .route(
            "/api/v1/sdk/visitor_attributes",
            get(get_attributes).post(set_attributes),
        )
        .route("/api/v1/sdk/screen_aliases", post(screens))
        .route("/api/v1/sdk/data_for_device", post(resolve))
        .route("/api/v1/sdk/data_for_device_and_url", post(resolve))
        .route("/api/v1/sdk/data_for_device_and_path", post(resolve))
        .route("/api/v1/sdk/clipboard_status", post(clipboard_status))
        .route("/api/v1/sdk/event/custom", post(custom_event))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clipboard_activity_expires_at_exactly_48_hours() {
        let now = "2026-09-27T12:00:00Z"
            .parse::<chrono::DateTime<Utc>>()
            .unwrap();
        let boundary = now - chrono::Duration::hours(48);
        assert!(clipboard_activity_active(now, now));
        assert!(clipboard_activity_active(
            boundary + chrono::Duration::microseconds(1),
            now
        ));
        assert!(!clipboard_activity_active(boundary, now));
        assert!(!clipboard_activity_active(
            boundary - chrono::Duration::microseconds(1),
            now
        ));
        assert!(!clipboard_activity_active(
            now + chrono::Duration::microseconds(1),
            now
        ));
    }
    #[test]
    fn trusted_proxy_uses_nearest_untrusted_hop_and_ignores_forged_prefix() {
        let proxy: IpAddr = "10.0.0.1".parse().unwrap();
        let client: IpAddr = "198.51.100.2".parse().unwrap();
        assert_eq!(
            forwarded_ip(Some(proxy), Some("203.0.113.8, 198.51.100.2"), &[proxy]),
            Some(client)
        );
        assert_eq!(
            forwarded_ip(Some(client), Some("203.0.113.8"), &[proxy]),
            Some(client)
        );
        assert_eq!(
            forwarded_ip(Some(proxy), Some("malformed"), &[proxy]),
            Some(proxy)
        );
    }
}
