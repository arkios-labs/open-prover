use std::{path::PathBuf, pin::Pin};

use common::{storage::StorageType, uri::UriResolver};
use tokio::sync::mpsc;
use tokio_stream::{Stream, wrappers::ReceiverStream};
use tonic::Status;
use tracing::info;

use crate::{
    proto::{risc0_service_server::Risc0Service, *},
    server::path::{STORAGE_ROOT_DIR, journal_path, keccak_path, segment_path},
    tasks::{
        execute::{self, ExecuteMessage},
        serialize_obj,
    },
};

const KECCAK_DEFAULT_PO2: u32 = 17;

pub struct Risc0ServiceImpl {
    uri_resolver: UriResolver,
}

impl Risc0ServiceImpl {
    pub fn new(uri_resolver: UriResolver) -> Self {
        Self { uri_resolver }
    }
}

#[tonic::async_trait]
impl Risc0Service for Risc0ServiceImpl {
    type ExecuteStream =
        Pin<Box<dyn Stream<Item = std::result::Result<Risc0ExecuteResponse, Status>> + Send>>;

    async fn execute(
        &self,
        request: tonic::Request<Risc0ExecuteRequest>,
    ) -> std::result::Result<tonic::Response<Self::ExecuteStream>, Status> {
        let request = request.into_inner();
        let (tx, mut rx) = mpsc::channel(10);

        info!("Executing job: {}", request.job_id);

        let elf_bytes = self
            .uri_resolver
            .read(&request.elf_uri)
            .await
            .map_err(|e| Status::internal(format!("Failed to read ELF: {e}")))?;
        let input_bytes = self
            .uri_resolver
            .read(&request.stdin_uri)
            .await
            .map_err(|e| Status::internal(format!("Failed to read input: {e}")))?;

        let (message_tx, message_rx) = mpsc::channel(10);
        let uri_resolver = self.uri_resolver.clone();

        tokio::spawn(async move {
            let execute_handle = tokio::task::spawn_blocking(move || {
                execute::execute(
                    tx,
                    request.segment_po2,
                    KECCAK_DEFAULT_PO2,
                    elf_bytes,
                    input_bytes,
                );
            });

            let mut sequence = 0;

            while let Some(message) = rx.recv().await {
                sequence += 1;
                info!("Received message: {:?}", sequence);

                let result: std::result::Result<Risc0ExecuteResponse, Status> = match message {
                    ExecuteMessage::Segment(segment) => {
                        info!("Writing segment: {}", segment.index);

                        let path_buf = PathBuf::from(STORAGE_ROOT_DIR)
                            .join(segment_path(&request.job_id, segment.index));
                        let path_str = path_buf
                            .to_str()
                            .ok_or(Status::internal("Failed to convert segment path to string"))
                            .unwrap();

                        let segment_bytes = serialize_obj(&segment)
                            .map_err(|e| {
                                Status::internal(format!("Failed to serialize segment: {e}"))
                            })
                            .unwrap();

                        let metadata = uri_resolver
                            .write(StorageType::EFS, path_str, &segment_bytes)
                            .await
                            .map_err(|e| Status::internal(format!("Failed to write segment: {e}")))
                            .unwrap();

                        Ok(Risc0ExecuteResponse {
                            sequence: sequence as u64,
                            payload: Some(risc0_execute_response::Payload::Segment(
                                Risc0FileMetadata {
                                    file_uri: metadata.uri,
                                    file_size: metadata.size,
                                },
                            )),
                        })
                    }
                    ExecuteMessage::Keccak(message) => {
                        info!("Writing keccak: {}", message.index);

                        let keccak_path_buf = PathBuf::from(STORAGE_ROOT_DIR)
                            .join(keccak_path(&request.job_id, message.index));
                        let keccak_path_str = keccak_path_buf
                            .to_str()
                            .ok_or(Status::internal("Failed to convert keccak path to string"))
                            .unwrap();
                        let keccak_bytes = serialize_obj(&message.request)
                            .map_err(|e| {
                                Status::internal(format!("Failed to serialize keccak: {e}"))
                            })
                            .unwrap();
                        let metadata = uri_resolver
                            .write(StorageType::EFS, keccak_path_str, &keccak_bytes)
                            .await
                            .map_err(|e| Status::internal(format!("Failed to write keccak: {e}")))
                            .unwrap();
                        Ok(Risc0ExecuteResponse {
                            sequence: message.index as u64,
                            payload: Some(risc0_execute_response::Payload::Keccak(
                                Risc0FileMetadata {
                                    file_uri: metadata.uri,
                                    file_size: metadata.size,
                                },
                            )),
                        })
                    }
                    ExecuteMessage::Result(result) => {
                        let journal_path_buf =
                            PathBuf::from(STORAGE_ROOT_DIR).join(journal_path(&request.job_id));
                        let journal_path_str = journal_path_buf
                            .to_str()
                            .ok_or_else(|| {
                                Status::internal("Failed to convert journal path to string")
                            })
                            .unwrap();
                        let journal_bytes = serialize_obj(&result.journal)
                            .map_err(|e| {
                                Status::internal(format!("Failed to serialize journal: {e}"))
                            })
                            .unwrap();
                        let journal_metadata = uri_resolver
                            .write(StorageType::EFS, journal_path_str, &journal_bytes)
                            .await
                            .map_err(|e| Status::internal(format!("Failed to write journal: {e}")))
                            .unwrap();
                        Ok(Risc0ExecuteResponse {
                            sequence: sequence as u64,
                            payload: Some(risc0_execute_response::Payload::Result(
                                Risc0ExecuteResult {
                                    total_cycles: result.total_cycles,
                                    segment_count: result.segment_count as u64,
                                    keccak_count: result.keccak_count as u64,
                                    journal: Some(Risc0FileMetadata {
                                        file_uri: journal_metadata.uri,
                                        file_size: journal_metadata.size,
                                    }),
                                    receipt: None,
                                },
                            )),
                        })
                    }
                    ExecuteMessage::Fault => Err(Status::internal("Execution failed with fault!")),
                };

                if let Err(e) = message_tx.send(result).await {
                    info!("Failed to send message: {:?}", e);
                    break;
                }
            }

            if let Err(e) = execute_handle.await {
                info!("Execute task failed: {:?}", e);
            }

            info!("Execution completed for job: {}", request.job_id);
        });

        Ok(tonic::Response::new(Box::pin(ReceiverStream::new(message_rx)) as Self::ExecuteStream))
    }

    async fn prove_segment(
        &self,
        _request: tonic::Request<Risc0ProveSegmentRequest>,
    ) -> std::result::Result<tonic::Response<Risc0ProveSegmentResponse>, Status> {
        Ok(tonic::Response::new(Risc0ProveSegmentResponse::default()))
    }

    async fn prove_keccak(
        &self,
        _request: tonic::Request<Risc0ProveKeccakRequest>,
    ) -> std::result::Result<tonic::Response<Risc0ProveKeccakResponse>, Status> {
        Ok(tonic::Response::new(Risc0ProveKeccakResponse::default()))
    }

    async fn join(
        &self,
        _request: tonic::Request<Risc0JoinRequest>,
    ) -> std::result::Result<tonic::Response<Risc0JoinResponse>, Status> {
        Ok(tonic::Response::new(Risc0JoinResponse::default()))
    }

    async fn union(
        &self,
        _request: tonic::Request<Risc0UnionRequest>,
    ) -> std::result::Result<tonic::Response<Risc0UnionResponse>, Status> {
        Ok(tonic::Response::new(Risc0UnionResponse::default()))
    }

    async fn resolve(
        &self,
        _request: tonic::Request<Risc0ResolveRequest>,
    ) -> std::result::Result<tonic::Response<Risc0ResolveResponse>, Status> {
        Ok(tonic::Response::new(Risc0ResolveResponse::default()))
    }

    async fn finalize(
        &self,
        _request: tonic::Request<Risc0FinalizeRequest>,
    ) -> std::result::Result<tonic::Response<Risc0FinalizeResponse>, Status> {
        Ok(tonic::Response::new(Risc0FinalizeResponse::default()))
    }

    async fn stark2_snark(
        &self,
        _request: tonic::Request<Risc0Stark2SnarkRequest>,
    ) -> std::result::Result<tonic::Response<Risc0Stark2SnarkResponse>, Status> {
        Ok(tonic::Response::new(Risc0Stark2SnarkResponse::default()))
    }
}
