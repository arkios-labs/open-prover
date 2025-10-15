use anyhow::Error;
use async_trait::async_trait;

#[async_trait]
pub trait Storage {
    async fn get(&self, file_path: &str) -> Result<Vec<u8>, Error>;
    async fn put(&self, file_path: &str, data: &[u8]) -> Result<(), Error>;
    async fn delete(&self, file_path: &str) -> Result<(), Error>;
}
