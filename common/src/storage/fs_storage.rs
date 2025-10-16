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
            fs::create_dir_all(&root_path)
                .await
                .with_context(|| format!("Failed to create root directory: {:?}", root_path))?;
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
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn create_test_storage() -> (FileSystemStorage, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let storage = FileSystemStorage::new(temp_dir.path()).await.unwrap();
        (storage, temp_dir)
    }

    #[tokio::test]
    async fn test_basic_put_get() {
        let (storage, temp_dir) = create_test_storage().await;

        let test_data = b"Hello, World!".to_vec();
        let file_path = "test_basic.txt";

        storage.put(file_path, &test_data).await.unwrap();
        let retrieved_data = storage.get(file_path).await.unwrap();

        assert_eq!(test_data, retrieved_data);

        temp_dir.close().unwrap();
    }

    #[tokio::test]
    async fn test_data_integrity() {
        let (storage, temp_dir) = create_test_storage().await;

        let empty_data = Vec::new();
        let file_path = "empty_test.txt";

        storage.put(file_path, &empty_data).await.unwrap();
        let retrieved_data = storage.get(file_path).await.unwrap();

        assert_eq!(empty_data, retrieved_data);
        assert!(retrieved_data.is_empty());

        let binary_data: Vec<u8> = (0..=255).collect();
        let binary_file_path = "binary_test.bin";

        storage.put(binary_file_path, &binary_data).await.unwrap();
        let retrieved_binary = storage.get(binary_file_path).await.unwrap();

        assert_eq!(binary_data, retrieved_binary);

        let large_data = vec![b'A'; 1024 * 1024];
        let large_file_path = "large_test.txt";

        storage.put(large_file_path, &large_data).await.unwrap();
        let retrieved_large = storage.get(large_file_path).await.unwrap();

        assert_eq!(large_data.len(), retrieved_large.len());
        assert_eq!(large_data, retrieved_large);

        temp_dir.close().unwrap();
    }

    #[tokio::test]
    async fn test_overwrite_behavior() {
        let (storage, temp_dir) = create_test_storage().await;

        let file_path = "overwrite_test.txt";
        let original_data = b"Original content".to_vec();
        let new_data = b"New content".to_vec();

        storage.put(file_path, &original_data).await.unwrap();

        storage.put(file_path, &new_data).await.unwrap();

        let retrieved_data = storage.get(file_path).await.unwrap();
        assert_eq!(new_data, retrieved_data);

        temp_dir.close().unwrap();
    }

    #[tokio::test]
    async fn test_delete_functionality() {
        let (storage, temp_dir) = create_test_storage().await;

        let test_data = b"To be deleted".to_vec();
        let file_path = "delete_test.txt";

        storage.put(file_path, &test_data).await.unwrap();

        assert!(storage.get(file_path).await.is_ok());

        storage.delete(file_path).await.unwrap();

        assert!(storage.get(file_path).await.is_err());

        temp_dir.close().unwrap();
    }

    #[tokio::test]
    async fn test_nested_directories() {
        let (storage, temp_dir) = create_test_storage().await;

        let test_data = b"Nested file content".to_vec();
        let file_path = "nested/dir/structure/file.txt";

        storage.put(file_path, &test_data).await.unwrap();
        let retrieved_data = storage.get(file_path).await.unwrap();

        assert_eq!(test_data, retrieved_data);

        temp_dir.close().unwrap();
    }

    #[tokio::test]
    async fn test_filesystem_permissions() {
        let (storage, temp_dir) = create_test_storage().await;

        let file_path = "permission_test.txt";
        let test_data = b"Permission test".to_vec();

        storage.put(file_path, &test_data).await.unwrap();

        let file_path = temp_dir.path().join(file_path);
        let metadata = std::fs::metadata(&file_path).unwrap();

        assert!(metadata.is_file());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = metadata.permissions();
            let mode = permissions.mode();

            assert!((mode & 0o600) == 0o600, "File should be readable and writable by owner");
        }

        temp_dir.close().unwrap();
    }
}
