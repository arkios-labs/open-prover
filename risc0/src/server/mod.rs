pub mod grpc_server;
pub mod grpc_service;

mod path;

pub enum ProverRequest {
    ProveSegment,
    ProveKeccak,
    Join,
    Union,
    Resolve,
    Finalize,
    Stark2Snark,
}

pub enum ExecutorRequest {
    Execute,
}
