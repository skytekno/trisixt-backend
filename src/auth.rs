use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use axum::extract::FromRequestParts;
use axum::http::{HeaderMap, header::AUTHORIZATION, request::Parts};
use serde_json::Value;
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
pub struct SdkProject {
    pub id: Uuid,
    declaration: Option<SdkDeclaration>,
}

#[derive(Debug, Clone)]
struct SdkDeclaration {
    platform: String,
    identifier: Option<String>,
    disabled_desktop_platforms: Vec<&'static str>,
}

/// Trusted in-process delegation. HTTP headers cannot create this extension.
#[derive(Clone)]
pub struct InternalSdkProject(pub Uuid);

fn sdk_platform(value: &str) -> Result<&'static str, AppError> {
    match value.to_ascii_lowercase().as_str() {
        "ios" => Ok("ios"),
        "android" => Ok("android"),
        "web" => Ok("web"),
        "desktop" | "mac" | "windows" | "linux" => Ok("desktop"),
        _ => Err(AppError::BadRequest("unsupported SDK platform".into())),
    }
}

/// Reject ambiguous aliases and repeated headers instead of trusting the first.
fn sdk_header<'a>(headers: &'a HeaderMap, names: &[&str]) -> Result<Option<&'a str>, AppError> {
    let mut selected = None;
    for name in names {
        for value in headers.get_all(*name) {
            let value = value
                .to_str()
                .ok()
                .filter(|v| !v.is_empty() && *v == v.trim())
                .ok_or_else(|| AppError::BadRequest("invalid SDK declaration header".into()))?;
            if selected.is_some_and(|previous| previous != value) {
                return Err(AppError::BadRequest(
                    "conflicting SDK declaration headers".into(),
                ));
            }
            selected = Some(value);
        }
    }
    Ok(selected)
}

impl SdkProject {
    /// The authenticated declaration, rather than the user agent, owns the
    /// platform. Internal callers retain their existing platform fallback.
    pub(crate) fn platform<'a>(
        &'a self,
        supplied: Option<&'a str>,
        fallback: &'a str,
    ) -> Result<&'a str, AppError> {
        self.check_platform(supplied)?;
        match &self.declaration {
            Some(declaration) => sdk_platform(&declaration.platform),
            None => Ok(supplied.unwrap_or(fallback)),
        }
    }

    pub(crate) fn check_platform(&self, supplied: Option<&str>) -> Result<(), AppError> {
        if let (Some(declaration), Some(supplied)) = (&self.declaration, supplied) {
            if sdk_platform(supplied)? != sdk_platform(&declaration.platform)? {
                return Err(AppError::Forbidden);
            }
            if declaration
                .disabled_desktop_platforms
                .contains(&supplied.to_ascii_lowercase().as_str())
            {
                return Err(AppError::Forbidden);
            }
            // A specific desktop client must not claim a different OS.
            if matches!(declaration.platform.as_str(), "mac" | "windows" | "linux")
                && supplied.to_ascii_lowercase() != declaration.platform
                && !supplied.eq_ignore_ascii_case("desktop")
            {
                return Err(AppError::Forbidden);
            }
        }
        Ok(())
    }

    pub(crate) fn check_body(&self, body: &Value) -> Result<(), AppError> {
        let Some(declaration) = &self.declaration else {
            return Ok(());
        };
        if let Some(platform) = body.get("platform") {
            self.check_platform(Some(
                platform
                    .as_str()
                    .ok_or_else(|| AppError::BadRequest("invalid SDK platform".into()))?,
            ))?;
        }
        // sdk_identifier is a visitor's external identity, not an app ID.
        for field in ["identifier", "bundle_id", "package_name", "origin"] {
            if let Some(value) = body.get(field) {
                let value = value.as_str().ok_or(AppError::Forbidden)?;
                let matches = if declaration.platform == "web" {
                    web_identifier(value).ok().as_ref() == declaration.identifier.as_ref()
                } else {
                    field != "origin" && declaration.identifier.as_deref() == Some(value)
                };
                if !matches {
                    return Err(AppError::Forbidden);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn declared_platform(&self) -> Option<&str> {
        self.declaration.as_ref().map(|d| d.platform.as_str())
    }

    pub(crate) fn bind_event_platform(&self, properties: &mut Value) -> Result<(), AppError> {
        if let Some(platform) = properties.get("platform") {
            self.check_platform(Some(
                platform
                    .as_str()
                    .ok_or_else(|| AppError::BadRequest("invalid event platform".into()))?,
            ))?;
        } else if let Some(platform) = self.declared_platform() {
            if !properties.is_object() {
                return Err(AppError::BadRequest(
                    "event properties must be an object".into(),
                ));
            }
            properties["platform"] = Value::String(platform.to_owned());
        }
        Ok(())
    }
}
impl FromRequestParts<AppState> for SdkProject {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        if let Some(principal) = parts.extensions.get::<InternalSdkProject>() {
            return Ok(Self {
                id: principal.0,
                declaration: None,
            });
        }

        let key = sdk_header(&parts.headers, &["x-project-key", "project-key"])?
            .filter(|v| v.len() == 64)
            .ok_or(AppError::Unauthorized)?;
        let id = sqlx::query_scalar::<_, Uuid>(
            "SELECT project_id FROM project_api_keys WHERE token_hash=$1 AND revoked_at IS NULL",
        )
        .bind(token_hash(key))
        .fetch_optional(&state.pg)
        .await?
        .ok_or(AppError::Unauthorized)?;
        let platform = sdk_header(&parts.headers, &["x-sdk-platform", "platform"])?;
        let identifier = sdk_header(&parts.headers, &["x-sdk-identifier", "identifier"])?;
        let origin = sdk_header(&parts.headers, &["origin"])?;
        if origin.is_some_and(|value| !value.contains("://") || web_identifier(value).is_err()) {
            return Err(AppError::Forbidden);
        }
        // A browser Origin is an unambiguous web declaration; a bare key or
        // identifier is not enough to choose an app.
        let platform = platform
            .or(origin.map(|_| "web"))
            .ok_or(AppError::Forbidden)?;
        let family = sdk_platform(platform)?;
        let configuration = sqlx::query_scalar::<_, Value>(
            "SELECT to_jsonb(c) FROM project_configurations c WHERE project_id=$1",
        )
        .bind(id)
        .fetch_optional(&state.pg)
        .await?
        .ok_or(AppError::Forbidden)?;
        let app = &configuration[family];
        if app["enabled"] != true || (origin.is_some() && family != "web") {
            return Err(AppError::Forbidden);
        }
        let identifier = match family {
            "ios" | "android" => {
                let field = if family == "ios" {
                    "bundle_id"
                } else {
                    "package_name"
                };
                let expected = app[field]
                    .as_str()
                    .filter(|s| !s.trim().is_empty())
                    .ok_or(AppError::Forbidden)?;
                if identifier != Some(expected) {
                    return Err(AppError::Forbidden);
                }
                Some(expected.to_owned())
            }
            "web" => {
                let domains = app["domains"].as_array().ok_or(AppError::Forbidden)?;
                let claimed = identifier.or(origin).ok_or(AppError::Forbidden)?;
                if !web_domain_allowed(domains, claimed) {
                    return Err(AppError::Forbidden);
                }
                let claimed = web_identifier(claimed).map_err(|_| AppError::Forbidden)?;
                if let Some(origin) = origin
                    && (!web_domain_allowed(domains, origin)
                        || web_identifier(origin).ok().as_ref() != Some(&claimed))
                {
                    return Err(AppError::Forbidden);
                }
                Some(claimed)
            }
            _ => {
                let platform = platform.to_ascii_lowercase();
                if matches!(platform.as_str(), "mac" | "windows")
                    && app[format!("{platform}_enabled")] == false
                {
                    return Err(AppError::Forbidden);
                }
                if identifier.is_some() {
                    return Err(AppError::Forbidden);
                }
                None
            }
        };
        Ok(Self {
            id,
            declaration: Some(SdkDeclaration {
                platform: platform.to_ascii_lowercase(),
                identifier,
                disabled_desktop_platforms: ["mac", "windows"]
                    .into_iter()
                    .filter(|os| app[format!("{os}_enabled")] == false)
                    .collect(),
            }),
        })
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
