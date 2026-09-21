use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use axum::extract::FromRequestParts;
use axum::http::{header::AUTHORIZATION, request::Parts};
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};
use uuid::Uuid;

use crate::{error::AppError, state::AppState};

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|h| {
            Argon2::default()
                .verify_password(password.as_bytes(), &h)
                .is_ok()
        })
        .unwrap_or(false)
}

// Argon2 uses substantial memory. Bound in-flight jobs rather than allowing the
// Tokio blocking pool to launch hundreds of independent unauthenticated jobs.
fn password_slots() -> &'static Arc<tokio::sync::Semaphore> {
    static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(4)))
}

pub async fn hash_password_async(password: String) -> Result<String, AppError> {
    let permit = password_slots()
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::TooManyRequests)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hash_password(&password).map_err(|_| AppError::Internal)
    })
    .await
    .map_err(|_| AppError::Internal)?
}

pub async fn verify_password_async(
    password: String,
    hash: Option<String>,
) -> Result<bool, AppError> {
    let permit = password_slots()
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::TooManyRequests)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        match hash {
            Some(hash) => verify_password(&password, &hash),
            None => {
                let _ = hash_password(&password);
                false
            }
        }
    })
    .await
    .map_err(|_| AppError::Internal)
}

pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// A 244-bit random bearer credential, returned once and only stored hashed.
pub fn new_token() -> (String, String) {
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let hash = token_hash(&token);
    (token, hash)
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct AuthUser {
    pub id: Uuid,
    pub email: String,
}

/// Trusted in-process delegation, set only after an OAuth grant has been
/// authenticated and its scopes checked. No HTTP header creates this value.
#[derive(Clone)]
pub struct InternalPrincipal(pub AuthUser);

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        if let Some(principal) = parts.extensions.get::<InternalPrincipal>() {
            return Ok(principal.0.clone());
        }
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .filter(|v| v.len() == 64)
            .ok_or(AppError::Unauthorized)?;
        sqlx::query_as::<_, AuthUser>(
            "SELECT u.id,u.email FROM users u JOIN access_tokens t ON t.user_id=u.id \
             WHERE t.token_hash=$1 AND t.expires_at>now()",
        )
        .bind(token_hash(token))
        .fetch_optional(&state.pg)
        .await?
        .ok_or(AppError::Unauthorized)
    }
}

/// Instance roles are the sole dashboard authorization boundary. Members read;
/// owners/admins write. Ownership-changing operations require an owner separately.
pub async fn authorize_instance(
    st: &AppState,
    user: &AuthUser,
    id: Uuid,
    write: bool,
) -> Result<String, AppError> {
    let role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM instance_roles WHERE user_id=$1 AND instance_id=$2",
    )
    .bind(user.id)
    .bind(id)
    .fetch_optional(&st.pg)
    .await?
    .ok_or(AppError::Forbidden)?;
    if write && role != "owner" && role != "admin" {
        return Err(AppError::Forbidden);
    }
    Ok(role)
}

pub async fn authorize_project(
    st: &AppState,
    user: &AuthUser,
    id: Uuid,
    write: bool,
) -> Result<Uuid, AppError> {
    let instance = sqlx::query_scalar::<_, Uuid>(
        "SELECT p.instance_id FROM projects p JOIN instance_roles r ON r.instance_id=p.instance_id \
         WHERE p.id=$1 AND r.user_id=$2 AND (NOT $3 OR r.role IN ('owner','admin'))",
    )
    .bind(id)
    .bind(user.id)
    .bind(write)
    .fetch_optional(&st.pg)
    .await?
    .ok_or(AppError::Forbidden)?;
    Ok(instance)
}

#[derive(Debug, Clone)]
pub struct SdkProject(pub Uuid);
#[derive(Clone)]
pub struct InternalSdkProject(pub SdkProject);
impl FromRequestParts<AppState> for SdkProject {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        if let Some(principal) = parts.extensions.get::<InternalSdkProject>() {
            return Ok(principal.0.clone());
        }

        let key = parts
            .headers
            .get("x-project-key")
            .or_else(|| parts.headers.get("project-key"))
            .and_then(|v| v.to_str().ok())
            .filter(|v| v.len() == 64)
            .ok_or(AppError::Unauthorized)?;
        let id = sqlx::query_scalar::<_, Uuid>(
            "SELECT project_id FROM project_api_keys WHERE token_hash=$1 AND revoked_at IS NULL",
        )
        .bind(token_hash(key))
        .fetch_optional(&state.pg)
        .await?
        .ok_or(AppError::Unauthorized)?;
        let platform = parts
            .headers
            .get("x-sdk-platform")
            .or_else(|| parts.headers.get("platform"))
            .and_then(|h| h.to_str().ok());
        let identifier = parts
            .headers
            .get("x-sdk-identifier")
            .or_else(|| parts.headers.get("identifier"))
            .and_then(|h| h.to_str().ok());
        let origin = parts.headers.get("origin").and_then(|h| h.to_str().ok());
        if platform.is_some() || origin.is_some() {
            let configuration = sqlx::query_scalar::<_, serde_json::Value>(
                "SELECT to_jsonb(c) FROM project_configurations c WHERE project_id=$1",
            )
            .bind(id)
            .fetch_optional(&state.pg)
            .await?
            .unwrap_or_else(|| serde_json::json!({}));
            if let Some(platform) = platform {
                let platform = match platform.to_ascii_lowercase().as_str() {
                    "ios" => "ios",
                    "android" => "android",
                    "web" => "web",
                    "desktop" | "mac" | "windows" | "linux" => "desktop",
                    _ => return Err(AppError::BadRequest("unsupported SDK platform".into())),
                };
                if configuration[platform]["enabled"] == false {
                    return Err(AppError::Forbidden);
                }
                let expected = match platform {
                    "ios" => configuration[platform]["bundle_id"].as_str(),
                    "android" => configuration[platform]["package_name"].as_str(),
                    _ => None,
                };
                if expected.is_some() && identifier != expected {
                    return Err(AppError::Forbidden);
                }
                if platform == "web"
                    && let Some(domains) = configuration["web"]["domains"].as_array()
                {
                    let claimed = identifier.or(origin).ok_or(AppError::Forbidden)?;
                    if !web_domain_allowed(domains, claimed) {
                        return Err(AppError::Forbidden);
                    }
                }
            }
            if let Some(origin) = origin
                && let Some(domains) = configuration["web"]["domains"].as_array()
                && (configuration["web"]["enabled"] == false
                    || !web_domain_allowed(domains, origin))
            {
                return Err(AppError::Forbidden);
            }
        }
        Ok(Self(id))
    }
}

/// Linked web domains are hostnames, not arbitrary URLs or wildcard patterns.
pub(crate) fn web_identifier(value: &str) -> Result<String, AppError> {
    let input = if value.contains("://") {
        value.to_owned()
    } else {
        format!("https://{value}")
    };
    let url = url::Url::parse(&input)
        .map_err(|_| AppError::BadRequest("invalid linked web domain".into()))?;
    if value.len() > 512
        || value != value.trim()
        || value.chars().any(char::is_control)
        || !matches!(url.scheme(), "https" | "http")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AppError::BadRequest("invalid linked web domain".into()));
    }
    url.host_str()
        .filter(|h| !h.contains('*'))
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
        .ok_or_else(|| AppError::BadRequest("invalid linked web domain".into()))
}
fn web_domain_allowed(domains: &[serde_json::Value], identifier: &str) -> bool {
    let Ok(identifier) = web_identifier(identifier) else {
        return false;
    };
    domains
        .iter()
        .filter_map(|v| v.as_str())
        .any(|v| web_identifier(v).is_ok_and(|domain| domain == identifier))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn password_work_rejects_overload_without_spawning_more_jobs() {
        let permit = password_slots()
            .clone()
            .acquire_many_owned(4)
            .await
            .unwrap();
        assert!(matches!(
            hash_password_async("overloaded".into()).await,
            Err(AppError::TooManyRequests)
        ));
        assert!(matches!(
            verify_password_async("overloaded".into(), None).await,
            Err(AppError::TooManyRequests)
        ));
        drop(permit);
    }
    #[test]
    fn password_roundtrip_and_malformed_hash() {
        let hash = hash_password("secure password!").unwrap();
        assert!(verify_password("secure password!", &hash));
        assert!(!verify_password("wrong", &hash));
        assert!(!verify_password("secure password!", "not a hash"));
    }
    #[test]
    fn random_credentials_only_hashes_persist() {
        let (a, h) = new_token();
        let (b, _) = new_token();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert_ne!(a, h);
        assert_eq!(h, token_hash(&a));
    }
}
