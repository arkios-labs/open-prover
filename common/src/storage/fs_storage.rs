use crate::storage::Storage;
use anyhow::{Context, Error};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use tokio::fs;

pub struct FileSystemStorage {
    root_path: PathBuf,
}

impl FileSystemStorage {
    pub async fn new(root: impl AsRef<Path>) -> Result<Self, Error> {
        let root_path = root.as_ref().to_path_buf();

        if !root_path.exists() {
            fs::create_dir_all(&root_path).await.with_context(|| format!("Failed to create root directory: {:?}", root_path))?;
        }

        Ok(Self { root_path })
    }
}

#[async_trait]
impl Storage for FileSystemStorage {
    async fn get(&self, file_path: &str) -> Result<Vec<u8>, Error> {
        let path = self.root_path.join(file_path);
        let data = fs::read(path).await?;
        Ok(data)
    }

    async fn put(&self, file_path: &str, data: &[u8]) -> Result<(), Error> {
        let path = self.root_path.join(file_path);
        if let Some(parent) = path.parent() && !parent.exists() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(path, data).await?;
        Ok(())
    }

    async fn delete(&self, file_path: &str) -> Result<(), Error> {
        let path = self.root_path.join(file_path);
        fs::remove_file(path).await?;
        Ok(())
    }
}
