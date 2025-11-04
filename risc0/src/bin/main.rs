use anyhow::Result;
use common::storage::fs_storage::FileSystemStorage;
use risc0::server::grpc_server;
use std::sync::Arc;
use std::{env, io};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).with_writer(io::stderr).init();

    let storage_path = env::var("STORAGE_PATH").unwrap_or("efs".to_string());

    let storage = FileSystemStorage::new(&storage_path).await?;

    let addr = env::var("GRPC_ADDR").unwrap_or("0.0.0.0:50051".to_string());

    grpc_server::run(&addr, Arc::new(storage)).await?;

    Ok(())
}
