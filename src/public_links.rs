//! Public link rendering, preview handoff and standalone quick links.
use crate::{
    domains,
    error::AppError,
    imports::{self, ImportOutcome},
    sdk::ClientContext,
    state::AppState,
};
use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
use serde_json::{Value, json};
use std::collections::HashMap;
use uuid::Uuid;
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn js(s: &str) -> String {
    json!(s)
        .to_string()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}
fn host(h: &HeaderMap) -> Result<String, AppError> {
    domains::normalize_hostname(
        h.get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or(""),
    )
}
pub async fn project_for_host(st: &AppState, h: &str) -> Result<Option<Uuid>, AppError> {
    let native = sqlx::query_scalar("SELECT id FROM projects WHERE lower(domain)=$1")
        .bind(h)
        .fetch_optional(&st.pg)
        .await?;
    if native.is_some() {
        Ok(native)
    } else {
        domains::resolve_project(&st.pg, h).await
    }
}
fn navigable(s: &str) -> bool {
    url::Url::parse(s).is_ok_and(|u| {
        !u.scheme().is_empty()
            && !matches!(
                u.scheme(),
                "javascript" | "data" | "file" | "vbscript" | "blob" | "about"
            )
            && u.username().is_empty()
            && u.password().is_none()
    })
}
fn redirect(url: &str, status: StatusCode) -> Result<Response, AppError> {
    if !navigable(url) {
        return Err(AppError::BadRequest("invalid link destination".into()));
    }
    let mut r = status.into_response();
    r.headers_mut().insert(
        "location",
        url.parse()
            .map_err(|_| AppError::BadRequest("invalid link destination".into()))?,
    );
    Ok(r)
}
pub fn tracking_url(target: &str, metadata: &Value, query: &str) -> Result<String, AppError> {
    if !navigable(target) {
        return Err(AppError::BadRequest("invalid link destination".into()));
    }
    let mut u = url::Url::parse(target).map_err(|_| AppError::Internal)?;
    let existing = u
        .query_pairs()
        .map(|(k, _)| k.into_owned())
        .collect::<Vec<_>>();
    for (key, val) in url::form_urlencoded::parse(query.as_bytes()) {
        if ![
            "go_to_fallback",
            "trisixt_redirect",
            "url",
            "ct",
            "clipboard_token",
        ]
        .contains(&key.as_ref())
            && !existing.iter().any(|k| k == key.as_ref())
        {
            u.query_pairs_mut().append_pair(&key, &val);
        }
    }
    for (key, field) in [
        ("utm_campaign", "tracking_campaign"),
        ("utm_source", "tracking_source"),
        ("utm_medium", "tracking_medium"),
    ] {
        if let Some(s) = metadata[field].as_str()
            && !u.query_pairs().any(|(k, _)| k == key)
        {
            u.query_pairs_mut().append_pair(key, s);
        }
    }
    Ok(u.into())
}
/// Store attribution preserves the provider-specific install referrer contract.
pub fn store_tracking_url(
    target: &str,
    platform: &str,
    metadata: &Value,
    canonical: &str,
) -> Result<String, AppError> {
    let mut u =
        url::Url::parse(target).map_err(|_| AppError::BadRequest("invalid store URL".into()))?;
    if !matches!(u.scheme(), "http" | "https") || !navigable(target) {
        return Err(AppError::BadRequest("invalid store URL".into()));
    }
    for (key, field) in if platform == "ios" {
        [
            ("ct", "tracking_campaign"),
            ("at", "tracking_source"),
            ("pt", "tracking_medium"),
        ]
    } else {
        [
            ("utm_campaign", "tracking_campaign"),
            ("utm_source", "tracking_source"),
            ("utm_medium", "tracking_medium"),
        ]
    } {
        if let Some(value) = metadata[field].as_str()
            && !u.query_pairs().any(|(k, _)| k == key)
        {
            u.query_pairs_mut().append_pair(key, value);
        }
    }
    if platform == "android" && !u.query_pairs().any(|(k, _)| k == "referrer") {
        u.query_pairs_mut().append_pair("referrer", canonical);
    }
    Ok(u.into())
}
async fn known_install(
    st: &AppState,
    project: Uuid,
    platform: &str,
    headers: &HeaderMap,
) -> Result<bool, AppError> {
    let cookie = headers
        .get("cookie")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| {
            s.split(';')
                .filter_map(|p| p.trim().split_once('='))
                .find(|(k, _)| *k == "trisixt_visitor")
                .map(|(_, v)| v)
        });
    let Some(cookie) = cookie else {
        return Ok(false);
    };
    let hash = crate::auth::token_hash(cookie);
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM browser_sessions b JOIN analytics_event_facts f ON f.project_id=b.project_id AND f.visitor_id=coalesce((SELECT visitor_id FROM visitor_aliases WHERE project_id=b.project_id AND alias_id=b.visitor_id),b.visitor_id) WHERE b.project_id=$1 AND b.token_hash=$2 AND b.expires_at>now() AND lower(f.event_type) IN ('install','reinstall','open','app_open') AND f.platform=$3)").bind(project).bind(hash).bind(platform).fetch_one(&st.pg).await?)
}
fn platform(ua: &str) -> (&'static str, &'static str) {
    let u = ua.to_ascii_lowercase();
    if u.contains("ipad") {
        ("ios", "tablet")
    } else if u.contains("iphone") {
        ("ios", "phone")
    } else if u.contains("android") {
        (
            "android",
            if u.contains("mobile") {
                "phone"
            } else {
                "tablet"
            },
        )
    } else {
        (
            "desktop",
            if u.contains("macintosh") {
                "mac"
            } else if u.contains("windows") {
                "windows"
            } else {
                "linux"
            },
        )
    }
}
fn bot(ua: &str) -> bool {
    let u = ua.to_ascii_lowercase();
    [
        "bot",
        "crawler",
        "spider",
        "facebookexternalhit",
        "slackbot",
        "twitterbot",
        "whatsapp",
        "telegram",
    ]
    .iter()
    .any(|s| u.contains(s))
}
struct Page<'a> {
    title: &'a str,
    subtitle: &'a str,
    image: &'a str,
    canonical: &'a str,
    target: &'a str,
    fallback: &'a str,
    clipboard: &'a str,
    auto: bool,
    qr: bool,
    capture: bool,
    google_tag: Option<&'a str>,
    tracking: Option<&'a Value>,
    stores: &'a [(String, String)],
}
fn page(
    Page {
        title,
        subtitle,
        image,
        canonical,
        target,
        fallback,
        clipboard,
        auto,
        qr,
        capture,
        google_tag,
        tracking,
        stores,
    }: Page<'_>,
) -> Response {
    let nonce = Uuid::new_v4().simple().to_string();
    let qr = if qr {
        qrcode::QrCode::new(canonical.as_bytes())
            .map(|q| {
                q.render::<qrcode::render::svg::Color>()
                    .min_dimensions(180, 180)
                    .build()
            })
            .unwrap_or_default()
    } else {
        String::new()
    };
    let picture = if image.is_empty() {
        String::new()
    } else {
        format!(
            "<img src=\"{}\" alt=\"\" width=\"96\" height=\"96\">",
            escape(image)
        )
    };
    let google_tag =
        google_tag.filter(|s| !s.is_empty() && domains::validate_tracking_id(&json!(s)).is_ok());
    let google = google_tag.map(|tag| {
        let traffic=json!({"utm_source":tracking.and_then(|m|m["tracking_source"].as_str()),"utm_medium":tracking.and_then(|m|m["tracking_medium"].as_str()),"utm_campaign":tracking.and_then(|m|m["tracking_campaign"].as_str())});
        let traffic=traffic.to_string().replace('<',"\\u003c").replace('>',"\\u003e").replace('&',"\\u0026");
        format!(r#"<script nonce="{nonce}" async src="https://www.googletagmanager.com/gtag/js?id={tag}"></script><script nonce="{nonce}">window.dataLayer=window.dataLayer||[];function gtag(){{dataLayer.push(arguments)}}gtag('js',new Date());const trafficFallback={traffic},trafficQuery=new URLSearchParams(location.search),traffic={{}};for(const [key,field] of Object.entries({{utm_source:'source',utm_medium:'medium',utm_campaign:'campaign',utm_term:'term',utm_content:'content'}})){{const value=trafficQuery.get(key)||trafficFallback[key];if(value)traffic[field]=value;}}gtag('config',{tag_js},{{send_page_view:false,page_location:location.href,linker:{{domains:[location.hostname]}},...traffic}});gtag('event','page_view',{{page_location:location.href}});</script>"#,tag_js=js(tag))
    }).unwrap_or_default();
    let store_buttons = stores
        .iter()
        .map(|(label, target)| {
            format!(
                "<p><a href=\"{}\">{}</a></p>",
                escape(target),
                escape(label)
            )
        })
        .collect::<String>();
    let html = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title><meta name="description" content="{subtitle}"><meta property="og:title" content="{title}"><meta property="og:description" content="{subtitle}"><meta property="og:image" content="{image}"><meta property="og:url" content="{canonical}"><meta name="twitter:card" content="summary_large_image"><link rel="canonical" href="{canonical}">{google}<style nonce="{nonce}">body{{font:16px system-ui;background:#f6f7fb;color:#182330;display:grid;min-height:95vh;place-items:center}}main{{max-width:440px;padding:36px;text-align:center;background:white;border-radius:18px}}a,button{{display:inline-block;background:#184fe4;color:white;padding:12px 24px;border:0;border-radius:8px;font:inherit;cursor:pointer}}svg{{display:block;margin:24px auto}}p{{line-height:1.6}}</style></head><body><main>{picture}<h1>{title}</h1><p>{subtitle}</p><a id="open" href="{target}">Open</a>{qr}{store_buttons}<p id="status" aria-live="polite"></p><noscript><p><a href="{fallback}">Continue</a></p></noscript></main><script nonce="{nonce}">const destination={target_js},fallback={fallback_js},copy={clipboard_js};let hidden=false;document.addEventListener('visibilitychange',()=>{{if(document.hidden)hidden=true;}});async function openLink(event){{if(event)event.preventDefault();if(copy&&navigator.clipboard){{try{{await navigator.clipboard.writeText(copy)}}catch(_){{}}}}window.location.href=destination;if(fallback&&fallback!==destination)setTimeout(()=>{{if(!hidden)window.location.href=fallback}},1400);}}document.getElementById('open').addEventListener('click',openLink);if({capture})try{{const canvas=document.createElement('canvas'),gl=canvas.getContext('webgl'),debug=gl&&gl.getExtension('WEBGL_debug_renderer_info');fetch('/',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify({{screen_width:screen.width,screen_height:screen.height,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,language:navigator.language,webgl_vendor:debug?gl.getParameter(debug.UNMASKED_VENDOR_WEBGL):'',webgl_renderer:debug?gl.getParameter(debug.UNMASKED_RENDERER_WEBGL):''}}),keepalive:true}}).catch(()=>{{}})}}catch(_){{}}if({auto})openLink();</script></body></html>"#,
        title = escape(title),
        subtitle = escape(subtitle),
        image = escape(image),
        canonical = escape(canonical),
        target = escape(target),
        fallback = escape(fallback),
        target_js = js(target),
        fallback_js = js(fallback),
        clipboard_js = js(clipboard)
    );
    let mut r = Html(html).into_response();
    let google_connect = if google_tag.is_some() {
        " https://*.google-analytics.com https://*.analytics.google.com https://*.googletagmanager.com"
    } else {
        ""
    };
    r.headers_mut().insert("content-security-policy",format!("default-src 'none'; connect-src 'self'{google_connect}; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; img-src https: data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'").parse().unwrap());
    r.headers_mut().insert(
        "referrer-policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    r.headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    r
}
pub async fn render(
    st: &AppState,
    project: Uuid,
    path: &str,
    headers: &HeaderMap,
    ctx: &ClientContext,
    query: &str,
    preview: bool,
) -> Result<Response, AppError> {
    let hostname = match host(headers) {
        Ok(h) => h,
        Err(_) => {
            sqlx::query_scalar::<_, String>("SELECT domain FROM projects WHERE id=$1")
                .bind(project)
                .fetch_one(&st.pg)
                .await?
        }
    };
    let link = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(l) FROM links l WHERE project_id=$1 AND path=$2 AND archived_at IS NULL",
    )
    .bind(project)
    .bind(path)
    .fetch_optional(&st.pg)
    .await?;
    let Some(link) = link else {
        match imports::resolve(st, project, &hostname, path, query).await? {
            Some(ImportOutcome::Link(link)) => {
                let path = link["path"].as_str().ok_or(AppError::Internal)?;
                let target = format!(
                    "https://{}/{path}{}{}",
                    domains::display_host(&st.pg, project).await?,
                    if query.is_empty() { "" } else { "?" },
                    query
                );
                return redirect(&target, StatusCode::MOVED_PERMANENTLY);
            }
            Some(ImportOutcome::Defaults) => {
                let fallback:Option<String>=sqlx::query_scalar("SELECT redirect->>'default_fallback' FROM project_configurations WHERE project_id=$1").bind(project).fetch_optional(&st.pg).await?.flatten();
                return redirect(
                    fallback.as_deref().ok_or(AppError::NotFound)?,
                    StatusCode::FOUND,
                );
            }
            None => return Err(AppError::NotFound),
        }
    };
    let meta = &link["metadata"];
    let id: Uuid = link["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or(AppError::Internal)?;
    crate::billing::enforce_project_quota(st, project, Uuid::nil()).await?;
    let config = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(c) FROM project_configurations c WHERE project_id=$1",
    )
    .bind(project)
    .fetch_optional(&st.pg)
    .await?
    .unwrap_or(json!({}));
    let brand = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(d) FROM project_domains d WHERE project_id=$1",
    )
    .bind(project)
    .fetch_optional(&st.pg)
    .await?
    .unwrap_or(json!({}));
    let (p, variation) = platform(&ctx.user_agent);
    let ios_meta = if let Some(id) = config["ios"]["bundle_id"].as_str() {
        crate::app_metadata::get(st, "ios", id).await?
    } else {
        json!({})
    };
    let android_meta = if let Some(id) = config["android"]["package_name"].as_str() {
        crate::app_metadata::get(st, "android", id).await?
    } else {
        json!({})
    };
    let store_meta = if p == "android" || ios_meta["found"] != true {
        &android_meta
    } else {
        &ios_meta
    };

    let options: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    let fallback_only = options
        .get("go_to_fallback")
        .is_some_and(|v| v == "true" || v == "1");
    let canonical = format!(
        "https://{}/{path}",
        domains::display_host(&st.pg, project).await?
    );
    let nested = if p == "desktop" && meta["custom_redirects"][p].is_null() {
        &meta["custom_redirects"]["web"]
    } else {
        &meta["custom_redirects"][p]
    };
    let preferred = &config["redirect"][format!("{p}_{variation}")];
    let platform_redirect = if preferred.is_null() {
        &config["redirect"][format!("{p}_{}", if p == "desktop" { "all" } else { "phone" })]
    } else {
        preferred
    };
    let target = nested
        .as_str()
        .or(nested["url"].as_str())
        .or(link[format!("{p}_url")].as_str())
        .or(platform_redirect.as_str())
        .or(platform_redirect["url"].as_str())
        .or(platform_redirect["fallback"].as_str())
        .or(platform_redirect["fallback_url"].as_str())
        .or(config["redirect"][format!("{p}_fallback")].as_str())
        .or(config[p]["fallback_url"].as_str())
        .or(if p == "desktop" {
            config["web"]["fallback_url"].as_str()
        } else {
            None
        })
        .or(config["redirect"]["default_fallback"].as_str())
        .or(link["target_url"].as_str())
        .ok_or(AppError::NotFound)?;
    let configured_store = platform_redirect["appstore"]
        .as_str()
        .or(config[p]["app_store_url"].as_str())
        .or(config[p]["store_url"].as_str())
        .or(if p == "ios" {
            ios_meta["store_url"].as_str()
        } else if p == "android" {
            android_meta["store_url"].as_str()
        } else {
            None
        });
    let store = if platform_redirect["appstore"] == false || !nested.is_null() {
        None
    } else {
        configured_store
            .map(|url| store_tracking_url(url, p, meta, &canonical))
            .transpose()?
    };
    let store = store.as_deref();
    let installed = known_install(st, project, p, headers).await?;
    let open_app = nested["open_app"]
        .as_bool()
        .or(nested["open_app_if_installed"].as_bool())
        .unwrap_or(true);
    let scheme = config[p]["uri_scheme"]
        .as_str()
        .or(config["redirect"]["uri_scheme"].as_str());
    let deep = if open_app && (p == "desktop" || installed) {
        platform_redirect["uri"]
            .as_str()
            .map(str::to_owned)
            .or_else(|| {
                if p == "desktop"
                    && config[p][format!("{variation}_enabled")]
                        .as_bool()
                        .unwrap_or(true)
                {
                    config[p][format!("{variation}_uri")]
                        .as_str()
                        .map(str::to_owned)
                } else {
                    None
                }
            })
            .or_else(|| scheme.map(|s| format!("{}://{path}", s.trim_end_matches("://"))))
    } else {
        None
    };
    let disabled = meta[format!("disable_{p}")] == true
        || config[p]["enabled"] == false
        || platform_redirect["enabled"] == false
        || (variation == "tablet" && config[p]["tablet_enabled"] == false);
    let store = if disabled { None } else { store };
    let fallback = if disabled {
        config["redirect"]["default_fallback"]
            .as_str()
            .or(link["target_url"].as_str())
            .unwrap_or(target)
    } else if fallback_only || (store.is_some() && !installed) {
        store.unwrap_or(target)
    } else {
        target
    };
    let fallback = tracking_url(fallback, meta, query)?;
    let target = tracking_url(
        if !disabled && !fallback_only {
            deep.as_deref().unwrap_or(&fallback)
        } else {
            &fallback
        },
        meta,
        query,
    )?;
    let title = meta["title"]
        .as_str()
        .or(meta["og_title"].as_str())
        .or(brand["generic_title"].as_str())
        .or(store_meta["title"].as_str())
        .unwrap_or("Trisixt");
    let subtitle = meta["subtitle"]
        .as_str()
        .or(meta["og_description"].as_str())
        .or(brand["generic_subtitle"].as_str())
        .unwrap_or("Open this link on your device.");
    let image = meta["image_url"]
        .as_str()
        .or(meta["og_image_url"].as_str())
        .or(brand["generic_image_url"].as_str())
        .or(store_meta["image_url"].as_str())
        .unwrap_or("");
    let crawler = bot(&ctx.user_agent);
    let click =
        if !preview && !crawler && !fallback_only && !options.contains_key("trisixt_redirect") {
            Some(crate::sdk::record_click(st, project, id, headers, ctx).await?)
        } else {
            None
        };
    let show = meta[format!("show_preview_{p}")]
        .as_bool()
        .or(meta["show_preview"].as_bool())
        .or(nested["show_preview"].as_bool())
        .or(platform_redirect["show_preview"].as_bool())
        .or(config["redirect"][format!("show_preview_{p}")].as_bool())
        .or(config["redirect"]["show_preview"].as_bool())
        .unwrap_or(false);
    let copy = meta[format!("copy_to_clipboard_{p}")]
        .as_bool()
        .or(nested["copy_to_clipboard"].as_bool())
        .or(platform_redirect["copy_to_clipboard"].as_bool())
        .or(config["redirect"][format!("copy_to_clipboard_{p}")].as_bool())
        .or(config["redirect"]["copy_to_clipboard"].as_bool())
        .unwrap_or(false);
    let clipboard = if copy {
        click
            .as_ref()
            .map(|c| format!("{canonical}?ct={}", c.clipboard))
            .unwrap_or_default()
    } else {
        String::new()
    };
    let generated = p == "desktop" && config["desktop"]["generated_page"] == true;
    let mut stores = Vec::new();
    if generated {
        for (platform, label, metadata) in [
            ("ios", "App Store", &ios_meta),
            ("android", "Google Play", &android_meta),
        ] {
            if let Some(url) = config[platform]["app_store_url"]
                .as_str()
                .or(config[platform]["store_url"].as_str())
                .or(metadata["store_url"].as_str())
            {
                stores.push((
                    label.to_owned(),
                    store_tracking_url(url, platform, meta, &canonical)?,
                ));
            }
        }
    }
    let mut response = if crawler || preview || show || generated || deep.is_some() {
        page(Page {
            title,
            subtitle,
            image,
            canonical: &canonical,
            target: &target,
            fallback: store.unwrap_or(&fallback),
            clipboard: &clipboard,
            auto: !crawler && !preview && !show && !generated,
            qr: generated,
            capture: click.is_some(),
            google_tag: brand["google_tracking_id"].as_str(),
            tracking: Some(meta),
            stores: &stores,
        })
    } else {
        redirect(&target, StatusCode::TEMPORARY_REDIRECT)?
    };
    if let Some(click) = click {
        response.headers_mut().insert(
            "set-cookie",
            format!(
                "trisixt_visitor={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000",
                click.cookie
            )
            .parse()
            .map_err(|_| AppError::Internal)?,
        );
    }
    Ok(response)
}
async fn quick(st: &AppState, path: &str, ctx: &ClientContext) -> Result<Response, AppError> {
    let v = sqlx::query_scalar::<_, Value>("SELECT metadata FROM quick_links WHERE path=$1")
        .bind(path)
        .fetch_optional(&st.pg)
        .await?
        .ok_or(AppError::NotFound)?;
    let (p, variant) = platform(&ctx.user_agent);
    let target = v[format!("{p}_{variant}")]
        .as_str()
        .or(v[p].as_str())
        .or(v["desktop"].as_str())
        .ok_or(AppError::NotFound)?;
    let canonical = format!("https://go.{}/{path}", st.config.server_host);
    Ok(page(Page {
        title: v["title"].as_str().unwrap_or("Trisixt"),
        subtitle: v["subtitle"]
            .as_str()
            .unwrap_or("Open this link on your device."),
        image: v["image_url"].as_str().unwrap_or(""),
        canonical: &canonical,
        target,
        fallback: target,
        clipboard: "",
        auto: !bot(&ctx.user_agent),
        qr: false,
        capture: false,
        google_tag: None,
        tracking: None,
        stores: &[],
    }))
}
async fn create_quick(st: &AppState, request: Request) -> Result<Response, AppError> {
    domains::rate_limit(&st.pg, "quick:public:create", 60).await?;
    let b = axum::body::to_bytes(request.into_body(), 32768)
        .await
        .map_err(|_| AppError::BadRequest("quick link exceeds 32 KiB".into()))?;
    let mut v: Value =
        serde_json::from_slice(&b).map_err(|_| AppError::BadRequest("JSON required".into()))?;
    if !v.is_object() {
        return Err(AppError::BadRequest("object required".into()));
    }
    for key in [
        "ios_phone",
        "ios_tablet",
        "android_phone",
        "android_tablet",
        "desktop",
        "desktop_linux",
        "desktop_mac",
        "desktop_windows",
    ] {
        if let Some(s) = v[key].as_str() {
            let s = s.trim();
            let normalized = if !s.contains(':') && s.contains('.') && !s.contains(' ') {
                format!("https://{s}")
            } else {
                s.to_owned()
            };
            if !navigable(&normalized) {
                return Err(AppError::BadRequest(format!("invalid {key} URL")));
            }
            v[key] = json!(normalized)
        }
    }
    if let Some(image) = v["image_url"].as_str() {
        let parsed =
            url::Url::parse(image).map_err(|_| AppError::BadRequest("invalid image URL".into()))?;
        if parsed.scheme() != "https" {
            return Err(AppError::BadRequest("image requires HTTPS".into()));
        }
    }
    let path = Uuid::new_v4().simple().to_string();
    sqlx::query("INSERT INTO quick_links(path,metadata)VALUES($1,$2)")
        .bind(&path)
        .bind(&v)
        .execute(&st.pg)
        .await?;
    Ok(Json(json!({"link":{"path":path,"url":format!("https://go.{}/{path}",st.config.server_host),"metadata":v}})).into_response())
}
async fn browser_data(
    st: &AppState,
    project: Uuid,
    ctx: &ClientContext,
    request: Request,
) -> Result<Response, AppError> {
    let token = request
        .headers()
        .get("cookie")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| {
            s.split(';')
                .filter_map(|p| p.trim().split_once('='))
                .find(|(k, _)| *k == "trisixt_visitor")
                .map(|(_, v)| v.to_owned())
        })
        .ok_or(AppError::Unauthorized)?;
    let visitor=sqlx::query_scalar::<_,Uuid>("SELECT visitor_id FROM browser_sessions WHERE project_id=$1 AND token_hash=$2 AND expires_at>now()").bind(project).bind(crate::auth::token_hash(&token)).fetch_optional(&st.pg).await?.ok_or(AppError::Unauthorized)?;
    let visitor = crate::sdk::canonical(st, project, visitor).await?;
    domains::rate_limit(&st.pg, &format!("browser-data:{project}:{visitor}"), 20).await?;
    let bytes = axum::body::to_bytes(request.into_body(), 16384)
        .await
        .map_err(|_| AppError::BadRequest("browser data exceeds 16 KiB".into()))?;
    let v: Value = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::BadRequest("browser JSON required".into()))?;
    for key in ["screen_width", "screen_height"] {
        if v.get(key).is_some() && !v[key].as_i64().is_some_and(|x| (1..=32768).contains(&x)) {
            return Err(AppError::BadRequest("invalid screen dimensions".into()));
        }
    }
    let timezone = v["timezone"].as_str().unwrap_or("UTC");
    if timezone.parse::<chrono_tz::Tz>().is_err() {
        return Err(AppError::BadRequest("invalid timezone".into()));
    }
    for key in ["language", "webgl_vendor", "webgl_renderer"] {
        if v.get(key).is_some() && !v[key].as_str().is_some_and(|s| s.len() <= 255) {
            return Err(AppError::BadRequest("invalid browser attribute".into()));
        }
    }
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,42))")
        .bind(project.to_string())
        .execute(&mut *tx)
        .await?;
    let visitor = sqlx::query_scalar::<_,Uuid>("SELECT coalesce((SELECT visitor_id FROM visitor_aliases WHERE project_id=$1 AND alias_id=$2),$2)").bind(project).bind(visitor).fetch_one(&mut *tx).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,32))")
        .bind(format!("{project}:{visitor}"))
        .execute(&mut *tx)
        .await?;
    let existing=sqlx::query_scalar::<_,Uuid>("SELECT id FROM devices WHERE project_id=$1 AND visitor_id=$2 AND vendor_id IS NULL ORDER BY updated_at DESC LIMIT 1").bind(project).bind(visitor).fetch_optional(&mut *tx).await?;
    let device = existing.unwrap_or_else(Uuid::new_v4);
    sqlx::query("INSERT INTO devices(id,project_id,visitor_id,platform,user_agent,screen_width,screen_height,timezone,language,webgl_vendor,webgl_renderer,ip)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::text::inet)ON CONFLICT(id)DO UPDATE SET screen_width=excluded.screen_width,screen_height=excluded.screen_height,timezone=excluded.timezone,language=excluded.language,webgl_vendor=excluded.webgl_vendor,webgl_renderer=excluded.webgl_renderer,updated_at=now()").bind(device).bind(project).bind(visitor).bind(platform(&ctx.user_agent).0).bind(&ctx.user_agent).bind(v["screen_width"].as_i64().map(|x|x as i32)).bind(v["screen_height"].as_i64().map(|x|x as i32)).bind(timezone).bind(v["language"].as_str().unwrap_or("")).bind(v["webgl_vendor"].as_str()).bind(v["webgl_renderer"].as_str()).bind(ctx.ip.map(|p|p.to_string())).execute(&mut *tx).await?;
    sqlx::query("UPDATE link_clicks SET device_id=$3 WHERE project_id=$1 AND visitor_id=$2 AND created_at>now()-interval '48 hours'").bind(project).bind(visitor).bind(device).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
pub async fn fallback(
    State(st): State<AppState>,
    ctx: ClientContext,
    request: Request,
) -> Result<Response, AppError> {
    let h = host(request.headers())?;
    let path = request.uri().path().trim_start_matches('/').to_owned();
    if path == "favicon.ico" {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    if h == format!("go.{}", st.config.server_host) {
        if request.method() == axum::http::Method::POST && path == "create" {
            return create_quick(&st, request).await;
        }
        if request.method() == axum::http::Method::GET {
            return quick(&st, &path, &ctx).await;
        }
        return Err(AppError::NotFound);
    }
    if request.method() == axum::http::Method::POST && path.is_empty() {
        let project = project_for_host(&st, &h).await?.ok_or(AppError::NotFound)?;
        return browser_data(&st, project, &ctx, request).await;
    }
    if request.method() != axum::http::Method::GET {
        return Err(AppError::NotFound);
    }
    let query = request.uri().query().unwrap_or("");
    if h == format!("preview.{}", st.config.server_host) {
        let url = url::form_urlencoded::parse(query.as_bytes())
            .find(|(k, _)| k == "url")
            .map(|(_, v)| v.into_owned())
            .ok_or(AppError::NotFound)?;
        let parsed = url::Url::parse(&url).map_err(|_| AppError::NotFound)?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(AppError::NotFound);
        }
        let host = parsed.host_str().ok_or(AppError::NotFound)?;
        let project = project_for_host(&st, host)
            .await?
            .ok_or(AppError::NotFound)?;
        let mut headers = request.headers().clone();
        headers.insert("host", host.parse().map_err(|_| AppError::NotFound)?);
        return render(
            &st,
            project,
            parsed.path().trim_start_matches('/'),
            &headers,
            &ctx,
            parsed.query().unwrap_or(""),
            true,
        )
        .await;
    }
    let project = project_for_host(&st, &h).await?.ok_or(AppError::NotFound)?;
    render(&st, project, &path, request.headers(), &ctx, query, false).await
}
