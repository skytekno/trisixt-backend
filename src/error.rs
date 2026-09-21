use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("config: {0}")]
    Config(String),
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Conflict(String),
    #[error("internal service error")]
    Internal,
    #[error("upstream service unavailable")]
    Upstream,
    #[error("too many requests")]
    TooManyRequests,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Db(sqlx::Error::Database(error))
                if error.code().as_deref() == Some("57014") =>
            {
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "query exceeded its execution budget; narrow the date range or filters"
                        .to_owned(),
                )
            }
            AppError::Db(
                sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_),
            ) => {
                tracing::error!(error = %self, "database unavailable");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "data service temporarily unavailable".to_owned(),
                )
            }
            AppError::Db(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                (StatusCode::CONFLICT, "resource already exists".to_owned())
            }
            AppError::Db(sqlx::Error::Database(error))
                if error.is_foreign_key_violation() || error.is_check_violation() =>
            {
                (
                    StatusCode::BAD_REQUEST,
                    "invalid resource relationship or value".to_owned(),
                )
            }
            AppError::Config(_) | AppError::Db(_) | AppError::Internal => {
                tracing::error!(error = %self, "request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal service error".to_owned(),
                )
            }
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, self.to_string()),
            AppError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::Conflict(_) => (StatusCode::CONFLICT, self.to_string()),
            AppError::Upstream => (StatusCode::BAD_GATEWAY, self.to_string()),
            AppError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
        };
        (status, axum::Json(serde_json::json!({"error": message}))).into_response()
    }
}
