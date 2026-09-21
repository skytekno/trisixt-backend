use crate::{error::AppError, state::AppState};
use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use serde_json::{Value, json};
async fn up() -> &'static str {
    "ok"
}
async fn ready(State(st): State<AppState>) -> Result<(StatusCode, Json<Value>), AppError> {
    sqlx::query("SELECT 1").execute(&st.pg).await?;
    Ok((
        StatusCode::OK,
        Json(json!({"status":"ready","service":"trisixt"})),
    ))
}
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/up", get(up))
        .route("/ready", get(ready))
        .merge(crate::core_api::router())
        .merge(crate::provisioning::router())
        .merge(crate::accounts::router())
        .merge(crate::app_metadata::router())
        .merge(crate::domains::router())
        .merge(crate::imports::router())
        .merge(crate::messaging::router())
        .merge(crate::purchase_lifecycle::router())
        .merge(crate::sdk::router())
        .merge(crate::mcp::router())
        .merge(crate::automation::router())
        .merge(crate::management::router())
        .merge(crate::exports::router())
        .merge(crate::operations::router())
        .merge(crate::analytics_api::router())
        .merge(crate::billing::router())
        .merge(crate::enterprise::router())
        .merge(crate::enterprise_admin::router())
        .merge(crate::integrations::router())
        .merge(crate::purchases::router())
        .merge(crate::oidc::router())
        .layer(tower_http::trace::TraceLayer::new_for_http().make_span_with(
            |request: &axum::http::Request<axum::body::Body>| {
                // OAuth codes and state live in query parameters; never log them.
                tracing::info_span!("http", method = %request.method(), path = %request.uri().path())
            },
        ))
        .fallback(crate::public_links::fallback)
        .layer(browser_cors())
        .with_state(state)
}

fn browser_cors() -> tower_http::cors::CorsLayer {
    let origins = std::env::var("CORS_ALLOWED_ORIGINS")
        .or_else(|_| std::env::var("ACCOUNT_FRONTEND_URL"))
        .ok();
    cors_for(origins.as_deref())
}
fn cors_for(origins: Option<&str>) -> tower_http::cors::CorsLayer {
    use axum::http::{HeaderValue, Method};
    use tower_http::cors::{AllowHeaders, Any, CorsLayer};
    let layer = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::HEAD,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(AllowHeaders::mirror_request())
        .expose_headers([axum::http::header::CONTENT_DISPOSITION])
        .max_age(std::time::Duration::from_secs(600));
    match origins {
        Some(origins) => {
            let origins: Vec<HeaderValue> = origins
                .split(',')
                .filter_map(|raw| {
                    let url = url::Url::parse(raw.trim()).ok()?;
                    if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
                        return None;
                    }
                    url.origin().ascii_serialization().parse().ok()
                })
                .collect();
            layer.allow_origin(origins).allow_credentials(true)
        }
        // Preserve bearer-token SDK access from arbitrary origins by default.
        // Browser cookies are allowed only for the explicit frontend origins.
        None => layer.allow_origin(Any),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    #[tokio::test]
    async fn browser_preflight_supports_bearer_and_limits_cookies_to_configured_origins() {
        for (configured, origin, allowed, credentials) in [
            (None, "https://sdk.example", "*", false),
            (
                Some("https://app.example/path"),
                "https://app.example",
                "https://app.example",
                true,
            ),
            (
                Some("https://app.example"),
                "https://untrusted.example",
                "",
                true,
            ),
            (Some("invalid"), "https://untrusted.example", "", true),
        ] {
            let app = Router::new()
                .route("/", get(|| async { "ok" }))
                .layer(cors_for(configured));
            let response = app
                .oneshot(
                    Request::builder()
                        .method("OPTIONS")
                        .uri("/")
                        .header("origin", origin)
                        .header("access-control-request-method", "POST")
                        .header(
                            "access-control-request-headers",
                            "authorization,content-type,x-project-key",
                        )
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(response.status().is_success());
            assert_eq!(
                response
                    .headers()
                    .get("access-control-allow-origin")
                    .map(|v| v.to_str().unwrap())
                    .unwrap_or(""),
                allowed
            );
            assert_eq!(
                response
                    .headers()
                    .contains_key("access-control-allow-credentials"),
                credentials
            );
            assert_eq!(
                response.headers()["access-control-allow-headers"],
                "authorization,content-type,x-project-key"
            );
        }
    }
}
