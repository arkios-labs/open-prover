use crate::serialization::{Format, recv, send};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::io::{BufReader, BufWriter, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use tracing::{error, info, warn};

#[derive(Debug, Serialize, Deserialize)]
pub struct TaskResponse {
    pub success: bool,

    /// We use `ByteBuf` instead of `Vec<u8>` because, when sending data to Python,
    /// `Vec<u8>` gets deserialized as a tuple (i.e., a list of integers),
    /// which cannot be directly used as a byte stream (e.g., writing to a file).
    /// `ByteBuf`, on the other hand, is serialized in a way that allows Python
    /// to deserialize it directly into a `bytes` object, making it easy to use
    /// as raw binary data.
    pub data: ByteBuf,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TaskRequest {
    pub task_type: String,

    /// Same reason as above — use `ByteBuf` to ensure Python receives a `bytes` object.
    pub data: ByteBuf,
}

pub struct UnixSocketServer {
    pub socket_path: PathBuf,
    pub listener: Option<UnixListener>,
}

impl TaskResponse {
    pub fn success(data: Vec<u8>) -> Self {
        Self { success: true, data: ByteBuf::from(data), error: None }
    }

    pub fn error<E: ToString>(err: E) -> Self {
        Self { success: false, data: ByteBuf::from(vec![]), error: Some(err.to_string()) }
    }
}

impl UnixSocketServer {
    pub fn new(socket_path: impl Into<PathBuf>) -> Result<Self> {
        let socket_path = socket_path.into();
        if socket_path.exists() {
            std::fs::remove_file(&socket_path).context("Failed to remove existing socket file")?;
        }

        Ok(Self { socket_path, listener: None })
    }

    pub fn bind(&mut self) -> Result<()> {
        let listener =
            UnixListener::bind(&self.socket_path).context("Failed to bind Unix socket")?;

        self.listener = Some(listener);
        info!(
            "Unix socket server bound to: {socket_path}",
            socket_path = self.socket_path.display()
        );

        Ok(())
    }

    pub fn handle_connection<F>(&mut self, handler: F) -> anyhow::Result<()>
    where
        F: Fn(TaskRequest) -> anyhow::Result<TaskResponse>,
    {
        let listener = self.listener.as_ref().context("Server not bound")?;
        let (stream, addr) = listener.accept().context("Failed to accept connection")?;

        info!("Accepted connection from: {addr:?}");

        let mut reader = BufReader::new(&stream);
        let mut writer = BufWriter::new(&stream);

        loop {
            let request = match recv::<_, TaskRequest>(&mut reader, Format::Msgpack) {
                Ok(request) => request,
                Err(e) => {
                    warn!("Client disconnected or error reading request: {}", e);
                    break;
                }
            };

            info!("Received request: task_type={}", request.task_type);

            let response = handler(request).unwrap_or_else(|err| {
                let msg = err.to_string();
                error!("Handler error: {msg}");
                TaskResponse { success: false, data: Vec::new().into(), error: Some(msg) }
            });

            info!(
                "Sending response: success={success}, data_size={data_size}, error={error:?}",
                success = response.success,
                data_size = response.data.len(),
                error = response.error
            );

            if let Err(e) = send(&mut writer, &response, Format::Msgpack) {
                error!("Failed to send response: {}", e);
                break;
            }
        }

        writer.flush().context("Failed to flush writer")?;
        Ok(())
    }
}

pub struct UnixSocketClient {
    pub socket_path: PathBuf,
}

impl UnixSocketClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self { socket_path: socket_path.into() }
    }

    pub fn connect(&self) -> Result<UnixStream> {
        let stream =
            UnixStream::connect(&self.socket_path).context("Failed to connect to Unix socket")?;

        info!("Connected to Unix socket: {socket_path}", socket_path = self.socket_path.display());
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;
    use tempfile::tempdir;

    #[test]
    fn test_socket_basic() -> Result<()> {
        let dir = tempdir().expect("Failed to create temporary directory");
        let socket_path = dir.path().join("test_socket");

        let mut server = UnixSocketServer::new(socket_path.clone())
            .expect("Failed to create Unix socket server");
        server.bind().expect("Failed to bind Unix socket");

        let client = UnixSocketClient::new(socket_path);

        let client_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));

            let request =
                TaskRequest { task_type: "echo".to_string(), data: vec![1, 2, 3, 4].into() };

            let mut stream = client.connect().expect("Failed to connect to Unix socket");
            send(&mut stream, &request, Format::Msgpack).expect("Failed to send request");

            let response = recv::<_, TaskResponse>(&mut stream, Format::Msgpack)
                .expect("Failed to receive response");
            assert_eq!(response.success, true);
            assert_eq!(response.data, vec![1, 2, 3, 4]);
        });

        server
            .handle_connection(|request| {
                assert_eq!(request.task_type, "echo");
                assert_eq!(request.data, vec![1, 2, 3, 4]);

                Ok(TaskResponse::success(request.data.into_vec()))
            })
            .expect("Failed to handle connection");

        client_thread.join().unwrap();
        Ok(())
    }

    #[test]
    fn test_socket_error_handling() -> Result<()> {
        let dir = tempdir().expect("Failed to create temporary directory");
        let socket_path = dir.path().join("error_socket");

        let mut server = UnixSocketServer::new(socket_path.clone())
            .expect("Failed to create Unix socket server");
        server.bind().expect("Failed to bind Unix socket");

        let client = UnixSocketClient::new(socket_path);

        let client_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));

            let request =
                TaskRequest { task_type: "invalid_task".to_string(), data: vec![1, 2, 3].into() };

            let mut stream = client.connect().expect("Failed to connect to Unix socket");
            send(&mut stream, &request, Format::Msgpack).expect("Failed to send request");

            let response = recv::<_, TaskResponse>(&mut stream, Format::Msgpack)
                .expect("Failed to receive response");
            assert_eq!(response.success, false);
            assert!(response.error.is_some());
        });

        server
            .handle_connection(|request| {
                assert_eq!(request.task_type, "invalid_task");
                assert_eq!(request.data, vec![1, 2, 3]);

                Ok(TaskResponse::error("Invalid task type"))
            })
            .expect("Failed to handle connection");

        client_thread.join().unwrap();
        Ok(())
    }

    #[test]
    fn test_socket_large_data() -> Result<()> {
        let dir = tempdir().expect("Failed to create temporary directory");
        let socket_path = dir.path().join("large_data_socket");

        let mut server = UnixSocketServer::new(socket_path.clone())
            .expect("Failed to create Unix socket server");
        server.bind().expect("Failed to bind Unix socket");

        let client = UnixSocketClient::new(socket_path);

        let client_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));

            let large_data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();

            let request = TaskRequest {
                task_type: "large_data".to_string(),
                data: large_data.clone().into(),
            };

            let mut stream = client.connect().expect("Failed to connect to Unix socket");
            send(&mut stream, &request, Format::Msgpack).expect("Failed to send request");

            let response = recv::<_, TaskResponse>(&mut stream, Format::Msgpack)
                .expect("Failed to receive response");
            assert_eq!(response.success, true);
            assert_eq!(response.data, large_data);
        });

        server
            .handle_connection(|request| {
                assert_eq!(request.task_type, "large_data");
                assert_eq!(request.data.len(), 1024);

                Ok(TaskResponse::success(request.data.into_vec()))
            })
            .expect("Failed to handle connection");

        client_thread.join().unwrap();
        Ok(())
    }
}
