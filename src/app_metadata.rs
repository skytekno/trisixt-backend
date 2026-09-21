//! Bounded App Store / Google Play discovery. Requests never target tenant URLs.
use crate::{domains::bounded_json, error::AppError, state::AppState};
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get as route_get,
};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use std::time::Duration;
fn identifier(platform: &str, id: &str) -> Result<(), AppError> {
    if !["ios", "android"].contains(&platform)
        || id.is_empty()
        || id.len() > 255
        || !id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-_".contains(&c))
    {
        Err(AppError::BadRequest("invalid store identifier".into()))
    } else {
        Ok(())
    }
}
pub fn artwork_url(platform: &str, value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|u| {
        let host = u.host_str().unwrap_or("");
        u.scheme() == "https"
            && u.port_or_known_default() == Some(443)
            && u.username().is_empty()
            && u.password().is_none()
            && match platform {
                "ios" => host.ends_with(".mzstatic.com"),
                "android" => host.ends_with(".googleusercontent.com"),
                _ => false,
            }
    })
}
pub fn parse_apple(v: &Value) -> Result<Value, AppError> {
    let Some(results) = v["results"].as_array() else {
        return Err(AppError::Upstream);
    };
    let Some(app) = results.first() else {
        return Ok(json!({"found":false}));
    };
    let name = app["trackName"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or(AppError::Upstream)?;
    let id = app["trackId"].as_u64().ok_or(AppError::Upstream)?;
    let image = app["artworkUrl512"]
        .as_str()
        .or(app["artworkUrl100"].as_str())
        .filter(|s| artwork_url("ios", s));
    Ok(
        json!({"found":true,"title":name.chars().take(300).collect::<String>(),"image_url":image,"appstore_id":id,"store_url":format!("https://apps.apple.com/app/id{id}")}),
    )
}
pub fn parse_google(html: &str, identifier: &str) -> Result<Value, AppError> {
    let document = Html::parse_document(html);
    let h1 = Selector::parse("h1").map_err(|_| AppError::Internal)?;
    let meta = Selector::parse("meta").map_err(|_| AppError::Internal)?;
    let img = Selector::parse("img").map_err(|_| AppError::Internal)?;
    let title = document
        .select(&h1)
        .next()
        .map(|n| n.text().collect::<String>())
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            document
                .select(&meta)
                .find(|m| m.value().attr("property") == Some("og:title"))
                .and_then(|m| m.value().attr("content"))
                .map(str::to_owned)
        })
        .ok_or(AppError::Upstream)?;
    let image = document
        .select(&meta)
        .find(|m| m.value().attr("property") == Some("og:image"))
        .and_then(|m| m.value().attr("content"))
        .filter(|s| artwork_url("android", s))
        .or_else(|| {
            document
                .select(&img)
                .filter_map(|i| i.value().attr("src"))
                .find(|s| s.ends_with("w240-h480") && artwork_url("android", s))
        });
    let mut store = url::Url::parse("https://play.google.com/store/apps/details")
        .map_err(|_| AppError::Internal)?;
    store.query_pairs_mut().append_pair("id", identifier);
    Ok(
        json!({"found":true,"title":title.trim().chars().take(300).collect::<String>(),"image_url":image,"store_url":store.as_str()}),
    )
}
#[derive(Clone)]
pub struct StoreClient {
    client: reqwest::Client,
    apple: String,
    google: String,
}
impl StoreClient {
    pub fn new(apple: String, google: String) -> Result<Self, AppError> {
        for raw in [&apple, &google] {
            let u = url::Url::parse(raw)
                .map_err(|_| AppError::Config("invalid store endpoint".into()))?;
            if u.scheme() != "https" && !(u.scheme() == "http" && u.host_str() == Some("127.0.0.1"))
            {
                return Err(AppError::Config("store endpoint requires HTTPS".into()));
            }
        }
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .user_agent("Trisixt/1.0 store metadata")
                .build()
                .map_err(|_| AppError::Internal)?,
            apple,
            google,
        })
    }
    fn production() -> Result<Self, AppError> {
        Self::new(
            "https://itunes.apple.com/lookup".into(),
            "https://play.google.com/store/apps/details".into(),
        )
    }
    pub async fn fetch(&self, platform: &str, id: &str) -> Result<Value, AppError> {
        identifier(platform, id)?;
        let response = if platform == "ios" {
            self.client.get(&self.apple).query(&[("bundleId", id)])
        } else {
            self.client
                .get(&self.google)
                .query(&[("id", id), ("hl", "en"), ("gl", "US")])
        }
        .send()
        .await
        .map_err(|_| AppError::Upstream)?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(json!({"found":false}));
        }
        if !response.status().is_success() {
            return Err(AppError::Upstream);
        }
        if platform == "ios" {
            parse_apple(&bounded_json(response, 1048576).await?)
        } else {
            let bytes = bounded_bytes(response, 4 * 1048576).await?;
            let html = String::from_utf8(bytes).map_err(|_| AppError::Upstream)?;
            parse_google(&html, id)
        }
    }
    async fn image(&self, platform: &str, url: &str) -> Result<(Vec<u8>, &'static str), AppError> {
        if !artwork_url(platform, url) {
            return Err(AppError::Upstream);
        }
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| AppError::Upstream)?;
        if !response.status().is_success() {
            return Err(AppError::Upstream);
        }
        let bytes = bounded_bytes(response, 5 * 1048576).await?;
        let kind = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            "image/png"
        } else if bytes.starts_with(b"\xff\xd8\xff") {
            "image/jpeg"
        } else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
            "image/webp"
        } else {
            return Err(AppError::Upstream);
        };
        Ok((bytes, kind))
    }
}
async fn bounded_bytes(mut response: reqwest::Response, max: usize) -> Result<Vec<u8>, AppError> {
    if response.content_length().is_some_and(|n| n > max as u64) {
        return Err(AppError::Upstream);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| AppError::Upstream)? {
        if bytes.len() + chunk.len() > max {
            return Err(AppError::Upstream);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
pub async fn get(st: &AppState, platform: &str, id: &str) -> Result<Value, AppError> {
    identifier(platform, id)?;
    sqlx::query(
        "INSERT INTO app_store_metadata(platform,identifier)VALUES($1,$2)ON CONFLICT DO NOTHING",
    )
    .bind(platform)
    .bind(id)
    .execute(&st.pg)
    .await?;
    let result=sqlx::query_as::<_,(Value,bool)>("SELECT metadata,artwork IS NOT NULL FROM app_store_metadata WHERE platform=$1 AND identifier=$2").bind(platform).bind(id).fetch_one(&st.pg).await?;
    let mut value = result.0;
    if result.1 {
        value["image_url"] = json!(format!(
            "https://{}/api/v1/app-store/{platform}/{id}/artwork",
            st.config.server_host
        ))
    }
    Ok(value)
}
pub async fn tick(st: &AppState) -> Result<usize, AppError> {
    tick_with(st, &StoreClient::production()?).await
}
pub async fn tick_with(st: &AppState, client: &StoreClient) -> Result<usize, AppError> {
    let rows=sqlx::query_as::<_,(String,String)>("WITH due AS(SELECT platform,identifier FROM app_store_metadata WHERE expires_at<=now() AND available_at<=now() ORDER BY available_at FOR UPDATE SKIP LOCKED LIMIT 3)UPDATE app_store_metadata m SET available_at=now()+interval '2 minutes' FROM due WHERE m.platform=due.platform AND m.identifier=due.identifier RETURNING m.platform,m.identifier").fetch_all(&st.pg).await?;
    let mut completed = 0;
    for (platform, id) in rows {
        let result = async {
            let value = client.fetch(&platform, &id).await?;
            let image = if let Some(url) = value["image_url"].as_str() {
                Some(client.image(&platform, url).await?)
            } else {
                None
            };
            Ok::<_, AppError>((value, image))
        }
        .await;
        match result {
            Ok((value, image)) => {
                sqlx::query("UPDATE app_store_metadata SET metadata=$3,artwork=$4,content_type=$5,ready=true,expires_at=now()+interval '24 hours',available_at=now()+interval '24 hours',attempts=0,last_error=NULL,updated_at=now()WHERE platform=$1 AND identifier=$2").bind(&platform).bind(&id).bind(value).bind(image.as_ref().map(|x|&x.0)).bind(image.as_ref().map(|x|x.1)).execute(&st.pg).await?;
                completed += 1;
            }
            Err(_) => {
                sqlx::query("UPDATE app_store_metadata SET attempts=attempts+1,last_error='store metadata refresh failed',available_at=now()+make_interval(secs=>least(3600,300*greatest(attempts,1))),updated_at=now()WHERE platform=$1 AND identifier=$2").bind(&platform).bind(&id).execute(&st.pg).await?;
            }
        }
    }
    Ok(completed)
}
async fn artwork(
    State(st): State<AppState>,
    Path((platform, id)): Path<(String, String)>,
) -> Result<Response, AppError> {
    identifier(&platform, &id)?;
    let row=sqlx::query_as::<_,(Vec<u8>,String)>("SELECT artwork,content_type FROM app_store_metadata WHERE platform=$1 AND identifier=$2 AND artwork IS NOT NULL").bind(platform).bind(id).fetch_optional(&st.pg).await?.ok_or(AppError::NotFound)?;
    Ok((
        StatusCode::OK,
        [
            ("content-type", row.1),
            ("cache-control", "public, max-age=3600".into()),
            ("x-content-type-options", "nosniff".into()),
        ],
        row.0,
    )
        .into_response())
}
pub fn router() -> Router<AppState> {
    Router::new().route(
        "/api/v1/app-store/{platform}/{identifier}/artwork",
        route_get(artwork),
    )
}
