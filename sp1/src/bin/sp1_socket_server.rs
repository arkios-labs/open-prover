use anyhow::{Context, Result};
use common::io::socket::{TaskRequest, TaskResponse, UnixSocketServer};
use sp1::command::registry::Command;
use sp1::tasks::Sp1Agent;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tokio;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let socket_base_path = env::var("SUCCINCT_SOCKET_BASE_PATH")
        .context("SUCCINCT_SOCKET_BASE_PATH environment variable is not set")?;

    info!("Starting SP1 server with base path: {socket_base_path}");

    let sp1_agent = Arc::new(Sp1Agent::new().context("Failed to initialize agent")?);

    let socket_paths = vec![
        PathBuf::from(&socket_base_path).join("hifi_gpu.sock"),
        PathBuf::from(&socket_base_path).join("lofi_gpu.sock"),
        PathBuf::from(&socket_base_path).join("hifi_cpu.sock"),
        PathBuf::from(&socket_base_path).join("lofi_cpu.sock"),
    ];

    info!("Creating servers for sockets:");
    for (index, path) in socket_paths.iter().enumerate() {
        info!("  {index}: {path}", path = path.display());
    }

    let mut handles = Vec::new();

    for socket_path in socket_paths {
        let agent = Arc::clone(&sp1_agent);
        let handle = tokio::spawn(async move { run_server(socket_path, agent).await });
        handles.push(handle);
    }

    for (index, handle) in handles.into_iter().enumerate() {
        if let Err(error) = handle.await {
            error!("Server {index} failed: {error}");
        }
    }

    Ok(())
}

async fn run_server(socket_path: PathBuf, agent: Arc<Sp1Agent>) -> Result<()> {
    let socket_name = socket_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_string();

    info!(
        "Starting server for socket: {socket_path}",
        socket_path = socket_path.display()
    );

    let mut server =
        UnixSocketServer::new(socket_path).context("Failed to create socket server")?;
    server.bind().context("Failed to bind socket")?;

    info!("SP1 Server for {socket_name} is ready to accept requests...");

    loop {
        server
            .handle_connection(|request| {
                Ok(process_request(&agent, request)
                    .map(TaskResponse::success)
                    .unwrap_or_else(|e| {
                        error!("Error processing request on {socket_name}: {e}");
                        TaskResponse::error(e)
                    }))
            })
            .context("Failed to handle connection")?;
    }
}

fn process_request(agent: &Sp1Agent, request: TaskRequest) -> Result<Vec<u8>> {
    let task_type: Command = request.task_type.parse().context("Invalid task type")?;
    info!("Processing task: {task_type:?}");

    task_type.apply(agent, request.data.into_vec())
}
