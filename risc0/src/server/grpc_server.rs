use anyhow::{Context, Result};
use common::{storage::Storage, uri::UriResolver};
use std::sync::Arc;
use tonic::transport::Server;
use tracing::info;

use crate::{
    proto::risc0_service_server::Risc0ServiceServer, server::grpc_service::Risc0ServiceImpl,
};

pub async fn run(addr: &str, storage: Arc<dyn Storage>) -> Result<()> {
    info!("Starting gRPC server on {}", addr);

    let uri_resolver = UriResolver::new(storage, reqwest::Client::new());

    let service = Risc0ServiceImpl::new(uri_resolver);
    let addr = addr.parse().context("Invalid gRPC address")?;

    Server::builder()
        .add_service(Risc0ServiceServer::new(service))
        .serve(addr)
        .await
        .context("gRPC server failed")?;

    Ok(())
}
