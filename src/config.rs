use std::env;
use std::str::FromStr;

use crate::error::AppError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalyticsBackend {
    ClickHouse,
    BigQuery,
}

impl FromStr for AnalyticsBackend {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "clickhouse" => Ok(Self::ClickHouse),
            "bigquery" => Ok(Self::BigQuery),
            other => Err(AppError::Config(format!(
                "unknown analytics backend: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageBackend {
    S3,
    Gcs,
}

impl FromStr for StorageBackend {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "s3" => Ok(Self::S3),
            "gcs" => Ok(Self::Gcs),
            other => Err(AppError::Config(format!(
                "unknown storage backend: {other}"
            ))),
        }
    }
}

#[derive(Clone)]
pub struct Config {
    pub env: String,
    pub host: String,
    pub port: u16,
    /// Bare domain (e.g. `links.example.com`); reserved subdomains derive from it.
    pub server_host: String,
    pub database_url: String,
    pub redis_url: String,
    /// Enterprise features on by default. Kept as a switch for explicit opt-out.
    pub ee_enabled: bool,
    pub analytics_backend: AnalyticsBackend,
    pub storage_backend: StorageBackend,
    pub storage_region: Option<String>,
    pub storage_bucket: Option<String>,
    pub clickhouse_url: Option<String>,
    pub pubsub_topic: Option<String>,
    pub bigquery_dataset: Option<String>,
    pub gcs_credentials: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, AppError> {
        Ok(Self {
            env: env("APP_ENV", "development"),
            host: env("HOST", "0.0.0.0"),
            port: env_parse("PORT", 3000_u16)?,
            server_host: env("SERVER_HOST", "localhost"),
            database_url: env_required("DATABASE_URL")?,
            redis_url: env("REDIS_URL", "redis://127.0.0.1:6379"),
            ee_enabled: env_bool("TRISIXT_EE", true)?,
            analytics_backend: env_parse("ANALYTICS_BACKEND", AnalyticsBackend::ClickHouse)?,
            storage_backend: env_parse("STORAGE_BACKEND", StorageBackend::S3)?,
            storage_region: env_opt("STORAGE_REGION"),
            storage_bucket: env_opt("STORAGE_BUCKET"),
            clickhouse_url: env_opt("CLICKHOUSE_URL"),
            pubsub_topic: env_opt("PUBSUB_TOPIC"),
            bigquery_dataset: env_opt("BIGQUERY_DATASET"),
            gcs_credentials: env_opt("GCS_CREDENTIALS"),
        })
    }
}

fn env(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_opt(key: &str) -> Option<String> {
    env::var(key).ok().filter(|v| !v.is_empty())
}

fn env_required(key: &str) -> Result<String, AppError> {
    env_opt(key).ok_or_else(|| AppError::Config(format!("{key} is required")))
}

fn env_parse<T: FromStr>(key: &str, default: T) -> Result<T, AppError>
where
    T::Err: std::fmt::Display,
{
    match env::var(key) {
        Ok(v) => v
            .parse()
            .map_err(|e| AppError::Config(format!("{key}: {e}"))),
        Err(_) => Ok(default),
    }
}

fn env_bool(key: &str, default: bool) -> Result<bool, AppError> {
    match env::var(key) {
        Ok(v) => parse_bool(key, &v),
        Err(_) => Ok(default),
    }
}

fn parse_bool(key: &str, value: &str) -> Result<bool, AppError> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(AppError::Config(format!("{key} must be a boolean"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_selection_is_explicit() {
        assert_eq!(
            "bigquery".parse::<AnalyticsBackend>().unwrap(),
            AnalyticsBackend::BigQuery
        );
        assert_eq!(
            "gcs".parse::<StorageBackend>().unwrap(),
            StorageBackend::Gcs
        );
        assert!("other".parse::<StorageBackend>().is_err());
        assert!("other".parse::<AnalyticsBackend>().is_err());
    }

    #[test]
    fn invalid_boolean_cannot_silently_disable_enterprise() {
        assert!(parse_bool("TRISIXT_EE", "tru").is_err());
        assert!(parse_bool("TRISIXT_EE", "true").unwrap());
        assert!(!parse_bool("TRISIXT_EE", "false").unwrap());
    }
}
