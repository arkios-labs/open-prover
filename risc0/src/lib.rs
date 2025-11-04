pub mod command;
pub mod server;
pub mod tasks;

pub mod proto {
    tonic::include_proto!("a41.zkrabbit.agent.v0");
}
