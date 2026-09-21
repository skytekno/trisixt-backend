use crate::{
    auth::{AuthUser, authorize_project},
    error::AppError,
    providers::{Analytics, Dashboard, ProviderError, Storage},
    state::AppState,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/projects/{id}/analytics", get(dashboard))
        .route(
            "/api/v1/projects/{id}/objects/{*key}",
            get(get_object)
                .put(put_object)
                .delete(delete_object)
                .layer(DefaultBodyLimit::max(16 * 1024 * 1024)),
        )
}
#[derive(Deserialize)]
struct Range {
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
}
async fn dashboard(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Query(range): Query<Range>,
) -> Result<Json<Dashboard>, AppError> {
    authorize_project(&st, &user, id, false).await?;
    let to = range.to.unwrap_or_else(Utc::now);
    let from = range
        .from
        .unwrap_or_else(|| to - chrono::Duration::days(30));
    if from >= to || to - from > chrono::Duration::days(366) {
        return Err(AppError::BadRequest(
            "analytics range must be positive and at most 366 days".into(),
        ));
    }
    let analytics = Analytics::from_env(&st.config).map_err(provider_error)?;
    Ok(Json(
        analytics
            .dashboard(id, from, to)
            .await
            .map_err(provider_error)?,
    ))
}
fn provider_error(error: ProviderError) -> AppError {
    match error {
        ProviderError::NotFound => AppError::NotFound,
        ProviderError::InvalidInput(message) => AppError::BadRequest(message.into()),
        error => {
            tracing::error!(%error,"provider request failed");
            AppError::Upstream
        }
    }
}
async fn put_object(
    State(st): State<AppState>,
    user: AuthUser,
    Path((id, key)): Path<(Uuid, String)>,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    authorize_project(&st, &user, id, true).await?;
    let mut tx = st.pg.begin().await?;
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM projects WHERE id=$1 FOR SHARE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AppError::NotFound)?;
    let storage = Storage::from_env(&st.config).map_err(provider_error)?;
    storage
        .put(id, &key, body.to_vec())
        .await
        .map_err(provider_error)?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn get_object(
    State(st): State<AppState>,
    user: AuthUser,
    Path((id, key)): Path<(Uuid, String)>,
) -> Result<Response, AppError> {
    authorize_project(&st, &user, id, false).await?;
    let storage = Storage::from_env(&st.config).map_err(provider_error)?;
    let body = storage.get(id, &key).await.map_err(provider_error)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CONTENT_DISPOSITION, "attachment"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        body,
    )
        .into_response())
}
async fn delete_object(
    State(st): State<AppState>,
    user: AuthUser,
    Path((id, key)): Path<(Uuid, String)>,
) -> Result<StatusCode, AppError> {
    authorize_project(&st, &user, id, true).await?;
    Storage::from_env(&st.config)
        .map_err(provider_error)?
        .delete(id, &key)
        .await
        .map_err(provider_error)?;
    Ok(StatusCode::NO_CONTENT)
}
