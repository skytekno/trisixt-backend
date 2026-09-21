use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use object_store::{
    ObjectStore, ObjectStoreExt, RetryConfig, aws::AmazonS3Builder, gcp::GoogleCloudStorageBuilder,
    path::Path,
};
use uuid::Uuid;

use super::ProviderError;
use crate::config::{Config, StorageBackend};

pub const MAX_OBJECT_BYTES: usize = 20 * 1024 * 1024;

#[derive(Clone)]
pub struct Storage {
    store: Arc<dyn ObjectStore>,
}

impl Storage {
    pub fn from_env(config: &Config) -> Result<Self, ProviderError> {
        let bucket = config
            .storage_bucket
            .as_deref()
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| ProviderError::Configuration("STORAGE_BUCKET is required".into()))?;
        let retry = RetryConfig {
            max_retries: 3,
            retry_timeout: Duration::from_secs(30),
            ..Default::default()
        };
        let store: Arc<dyn ObjectStore> = match config.storage_backend {
            StorageBackend::S3 => Arc::new(
                AmazonS3Builder::from_env()
                    .with_bucket_name(bucket)
                    .with_region(config.storage_region.as_deref().unwrap_or("us-east-1"))
                    .with_retry(retry)
                    .build()
                    .map_err(|_| ProviderError::Configuration("invalid S3 configuration".into()))?,
            ),
            StorageBackend::Gcs => {
                let mut builder = GoogleCloudStorageBuilder::from_env()
                    .with_bucket_name(bucket)
                    .with_retry(retry);
                if let Some(path) = &config.gcs_credentials {
                    // An explicit credential file must take precedence over a
                    // developer's unrelated gcloud ADC file as well.
                    builder = builder.with_application_credentials(path);
                }
                Arc::new(builder.build().map_err(|_| {
                    ProviderError::Configuration("invalid GCS configuration".into())
                })?)
            }
        };
        Ok(Self { store })
    }

    /// Supports injecting an ObjectStore implementation for local contract tests.
    pub fn new(store: Arc<dyn ObjectStore>) -> Self {
        Self { store }
    }

    pub async fn put(
        &self,
        project_id: Uuid,
        key: &str,
        bytes: Vec<u8>,
    ) -> Result<(), ProviderError> {
        if bytes.len() > MAX_OBJECT_BYTES {
            return Err(ProviderError::InvalidInput("object exceeds 20 MiB"));
        }
        let path = scoped_path(project_id, key)?;
        self.store
            .put(&path, Bytes::from(bytes).into())
            .await
            .map_err(storage_error)?;
        Ok(())
    }

    pub async fn get(&self, project_id: Uuid, key: &str) -> Result<Vec<u8>, ProviderError> {
        let path = scoped_path(project_id, key)?;
        let result = self.store.get(&path).await.map_err(storage_error)?;
        if result.meta.size > MAX_OBJECT_BYTES as u64 {
            return Err(ProviderError::InvalidInput("object exceeds 20 MiB"));
        }
        let bytes = result.bytes().await.map_err(storage_error)?;
        if bytes.len() > MAX_OBJECT_BYTES {
            return Err(ProviderError::InvalidInput("object exceeds 20 MiB"));
        }
        Ok(bytes.to_vec())
    }

    /// Delete one bounded batch from exactly this project/instance namespace.
    /// A false completion flag requests another durable cleanup pass.
    pub async fn delete_namespace_batch(
        &self,
        namespace: Uuid,
        limit: usize,
    ) -> Result<(usize, bool), ProviderError> {
        if namespace.is_nil() || !(1..=1000).contains(&limit) {
            return Err(ProviderError::InvalidInput(
                "invalid cleanup namespace or limit",
            ));
        }
        let prefix = Path::from(format!("projects/{namespace}"));
        let boundary = format!("projects/{namespace}/");
        let mut objects = self.store.list(Some(&prefix));
        let mut deleted = 0;
        while let Some(item) = std::future::poll_fn(|cx| objects.as_mut().poll_next(cx)).await {
            let item = item.map_err(storage_error)?;
            if !item.location.as_ref().starts_with(&boundary) {
                continue;
            }
            if deleted == limit {
                return Ok((deleted, false));
            }
            match self.store.delete(&item.location).await {
                Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
                Err(error) => return Err(storage_error(error)),
            }
            deleted += 1;
        }
        Ok((deleted, true))
    }

    pub async fn delete(&self, project_id: Uuid, key: &str) -> Result<(), ProviderError> {
        let path = scoped_path(project_id, key)?;
        self.store.delete(&path).await.map_err(storage_error)
    }
}

fn scoped_path(project_id: Uuid, key: &str) -> Result<Path, ProviderError> {
    if project_id.is_nil()
        || key.is_empty()
        || key.len() > 512
        || key.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || !part
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        })
    {
        return Err(ProviderError::InvalidInput("invalid object key"));
    }
    Ok(Path::from(format!("projects/{project_id}/{key}")))
}

fn storage_error(error: object_store::Error) -> ProviderError {
    match error {
        object_store::Error::NotFound { .. } => ProviderError::NotFound,
        object_store::Error::PermissionDenied { .. }
        | object_store::Error::Unauthenticated { .. } => ProviderError::Authentication,
        _ => ProviderError::Storage,
    }
}
