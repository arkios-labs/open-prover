use crate::{
    storage::{Storage, StorageType},
    uri::{ResourceMetadata, Result, UriError},
};
use std::sync::Arc;
use url::Url;

use super::{data_uri, http_uri, storage_uri};

#[derive(Clone)]
pub struct UriResolver {
    storage: Arc<dyn Storage>,
    storage_scheme: String,
    http_client: reqwest::Client,
}

impl UriResolver {
    pub fn new(storage: Arc<dyn Storage>, http_client: reqwest::Client) -> Self {
        let storage_scheme = storage.get_type().to_scheme();
        Self { storage, storage_scheme, http_client }
    }

    pub async fn read(&self, uri: &str) -> Result<Vec<u8>> {
        let url = Url::parse(uri)?;

        match url.scheme() {
            "data" => data_uri::read(&url).await,
            "http" | "https" => http_uri::read(&self.http_client, &url).await,
            scheme if scheme == self.storage_scheme => {
                storage_uri::read(&self.storage.clone(), &url).await
            }
            scheme => Err(UriError::UnsupportedScheme(scheme.to_string())),
        }
    }

    pub async fn write(
        &self,
        storage_type: StorageType,
        path: &str,
        content: &[u8],
    ) -> Result<ResourceMetadata> {
        match storage_type {
            StorageType::EFS => storage_uri::write(&self.storage, path, content).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::fs_storage::FileSystemStorage;
    use tempfile::TempDir;

    async fn create_test_resolver() -> (UriResolver, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let fs_storage = FileSystemStorage::new(temp_dir.path()).await.unwrap();
        let resolver = UriResolver::new(Arc::new(fs_storage), reqwest::Client::new());
        (resolver, temp_dir)
    }

    #[tokio::test]
    async fn test_read_unsupported_scheme() {
        let (resolver, _temp_dir) = create_test_resolver().await;
        let uri = "ftp://example.com/file.txt";
        let result = resolver.read(uri).await;
        match result {
            Err(UriError::UnsupportedScheme(scheme)) => {
                assert_eq!(scheme, "ftp");
            }
            _ => panic!("Expected UnsupportedScheme error"),
        }
    }
}
