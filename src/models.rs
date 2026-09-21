use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Instance {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Project {
    pub id: Uuid,
    pub instance_id: Uuid,
    pub environment: String,
    pub domain: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct InstanceRole {
    pub id: Uuid,
    pub user_id: Uuid,
    pub instance_id: Uuid,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

/// Minimal projection used by list endpoints.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct InstanceRef {
    pub id: Uuid,
    pub name: String,
}
