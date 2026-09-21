//! External analytics and object storage. Provider failures are never acknowledged as success.
mod analytics;
mod storage;

pub use analytics::{
    Analytics, AnalyticsEvent, BigQueryConfig, ClickHouseConfig, Dashboard, EventCount, GoogleAuth,
};
pub use storage::Storage;

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("provider configuration: {0}")]
    Configuration(String),
    #[error("invalid provider input: {0}")]
    InvalidInput(&'static str),
    #[error("provider authentication failed")]
    Authentication,
    #[error("provider returned HTTP {0}")]
    Http(u16),
    #[error("provider transport failed")]
    Transport,
    #[error("invalid provider response")]
    Response,
    #[error("provider operation timed out")]
    Timeout,
    #[error("object not found")]
    NotFound,
    #[error("object storage operation failed")]
    Storage,
}

impl ProviderError {
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound)
    }
}

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.trim().is_empty())
}

fn env_default(key: &str, default: &str) -> String {
    env_opt(key).unwrap_or_else(|| default.to_owned())
}
