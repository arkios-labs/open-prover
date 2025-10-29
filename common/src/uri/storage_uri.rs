use crate::{
    storage::{Storage, StorageError},
    uri::{ResourceMetadata, UriError},
};
use std::sync::Arc;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum StorageUriError {
    #[error("Invalid {scheme}:// URI: path cannot be empty")]
    EmptyPath { scheme: String },

    #[error("Failed to read from storage: {0}")]
    StorageReadError(#[source] StorageError),

    #[error("Failed to write to storage: {0}")]
    StorageWriteError(#[source] StorageError),
}

pub(super) async fn read(storage: &Arc<dyn Storage>, url: &Url) -> Result<Vec<u8>, UriError> {
    let path = _extract_path(url);

    if path.is_empty() {
        return Err(UriError::Storage(StorageUriError::EmptyPath {
            scheme: storage.get_type().to_scheme(),
        }));
    }

    storage.get(path).await.map_err(|e| UriError::Storage(StorageUriError::StorageReadError(e)))
}

pub(super) async fn write(
    storage: &Arc<dyn Storage>,
    path: &str,
    content: &[u8],
) -> Result<ResourceMetadata, UriError> {
    let clean_path = _sanitize_path(path);

    if clean_path.is_empty() {
        return Err(UriError::Storage(StorageUriError::EmptyPath {
            scheme: storage.get_type().to_scheme(),
        }));
    }

    storage
        .put(clean_path, content)
        .await
        .map_err(|e| UriError::Storage(StorageUriError::StorageWriteError(e)))?;

    Ok(ResourceMetadata {
        uri: format!("{}:///{}", storage.get_type().to_scheme(), clean_path),
        size: content.len() as u64,
    })
}

fn _extract_path(url: &Url) -> &str {
    _sanitize_path(url.path())
}

fn _sanitize_path(path: &str) -> &str {
    path.trim_start_matches('/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::fs_storage::FileSystemStorage;
    use tempfile::TempDir;

    async fn create_test_storage() -> (Arc<dyn Storage>, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let fs_storage = FileSystemStorage::new(temp_dir.path()).await.unwrap();
        (Arc::new(fs_storage), temp_dir)
    }

    #[tokio::test]
    async fn test_efs_read_write() {
        let (storage, _temp_dir) = create_test_storage().await;

        let test_data = b"Hello, EFS!";
        let path = "test/sample.txt";

        let metadata = write(&storage, path, test_data).await.unwrap();
        assert_eq!(metadata.size, test_data.len() as u64);
        assert_eq!(metadata.uri, "efs:///test/sample.txt");

        let url = Url::parse(&metadata.uri).unwrap();
        let content = read(&storage, &url).await.unwrap();
        assert_eq!(content, test_data);
    }

    #[tokio::test]
    async fn test_efs_nested_path() {
        let (storage, _temp_dir) = create_test_storage().await;

        let test_data = b"Nested file";
        let path = "deep/nested/path/file.bin";

        let metadata = write(&storage, path, test_data).await.unwrap();
        assert_eq!(metadata.uri, "efs:///deep/nested/path/file.bin");

        // Read using URI
        let url = Url::parse(&metadata.uri).unwrap();
        let content = read(&storage, &url).await.unwrap();
        assert_eq!(content, test_data);
    }
}
