//! Atomic instance onboarding retains the production/test pair and credentials.
use crate::{
    auth::{AuthUser, new_token},
    error::AppError,
    state::AppState,
};
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    name: String,
}
pub fn router() -> Router<AppState> {
    Router::new().route("/api/v1/instances/provision", post(create))
}
async fn create(
    State(st): State<AppState>,
    user: AuthUser,
    Json(input): Json<Input>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    Ok((
        StatusCode::CREATED,
        Json(provision(&st, &user, &input.name).await?),
    ))
}
pub async fn provision(st: &AppState, user: &AuthUser, name: &str) -> Result<Value, AppError> {
    let name = name.trim();
    if name.is_empty() || name.len() > 200 || name.chars().any(char::is_control) {
        return Err(AppError::BadRequest(
            "name must be 1 to 200 characters".into(),
        ));
    }
    crate::domains::rate_limit(&st.pg, &format!("provision:{}", user.id), 20).await?;
    let id = Uuid::new_v4();
    let suffix = id.simple().to_string();
    let slug = format!("p{}", &suffix[..16]);
    let scheme = format!("trisixt{}", &suffix[..16]);
    let (server_key, server_hash) = new_token();
    let mut tx = st.pg.begin().await?;
    sqlx::query("SELECT set_config('trisixt.actor_id',$1,true)")
        .bind(user.id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO instances(id,name)VALUES($1,$2)")
        .bind(id)
        .bind(name)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO instance_roles(instance_id,user_id,role)VALUES($1,$2,'owner')")
        .bind(id)
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO instance_api_keys(instance_id,name,token_hash)VALUES($1,'Initial Server SDK',$2)").bind(id).bind(server_hash).execute(&mut *tx).await?;
    let mut projects = Vec::new();
    for env in ["production", "test"] {
        let project = Uuid::new_v4();
        let project_name = if env == "test" {
            format!("{name}-test")
        } else {
            name.to_owned()
        };
        let domain = if env == "test" {
            format!("{slug}-test.{}", st.config.server_host)
        } else {
            format!("{slug}.{}", st.config.server_host)
        };
        crate::domains::normalize_hostname(&domain)?;
        let (sdk_key, sdk_hash) = new_token();
        sqlx::query(
            "INSERT INTO projects(id,instance_id,name,environment,domain)VALUES($1,$2,$3,$4,$5)",
        )
        .bind(project)
        .bind(id)
        .bind(&project_name)
        .bind(env)
        .bind(&domain)
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO project_domains(project_id,generic_title)VALUES($1,$2)")
            .bind(project)
            .bind(&project_name)
            .execute(&mut *tx)
            .await?;
        let redirect = json!({"uri_scheme":scheme,"ios_phone":{"enabled":true,"appstore":true},"android_phone":{"enabled":true,"appstore":true}});
        sqlx::query("INSERT INTO project_configurations(project_id,redirect,desktop)VALUES($1,$2,'{\"generated_page\":true}'::jsonb)").bind(project).bind(redirect).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO project_api_keys(project_id,name,token_hash)VALUES($1,'Initial Mobile SDK',$2)").bind(project).bind(sdk_hash).execute(&mut *tx).await?;
        projects.push(json!({"id":project,"instance_id":id,"name":project_name,"environment":env,"domain":domain,"sdk_key":sdk_key}));
    }
    sqlx::query("SELECT trisixt_audit($1,$2,'instance.provisioned',$1,$3)")
        .bind(id)
        .bind(user.id)
        .bind(json!({"environments":["production","test"]}))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(
        json!({"instance":{"id":id,"name":name,"role":"owner","uri_scheme":scheme,"projects":projects},"server_key":server_key,"credentials_returned_once":true}),
    )
}
