use async_trait::async_trait;
use thiserror::Error;

pub mod fs_storage;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("File not found: {path}")]
    NotFound { path: String },

    #[error("Permission denied: {path}")]
    PermissionDenied { path: String },

    #[error("Unknown error: {0}")]
    Unknown(String),
}

#[async_trait]
pub trait Storage {
    async fn get(&self, file_path: &str) -> Result<Vec<u8>, StorageError>;
    async fn put(&self, file_path: &str, data: &[u8]) -> Result<(), StorageError>;
    async fn delete(&self, file_path: &str) -> Result<(), StorageError>;
}
