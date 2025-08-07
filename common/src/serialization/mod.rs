use crate::serialization::bincode::{deserialize_from_bincode_bytes, serialize_to_bincode_bytes};
use crate::serialization::mpk::{deserialize_from_msgpack_bytes, serialize_to_msgpack_bytes};
use anyhow::{anyhow, bail, Context};
use std::io::{Read, Write};

pub mod bincode;
pub mod json_bytes;
pub mod mpk;

#[derive(Clone, Copy)]
pub enum Format {
    Msgpack,
    Bincode,
}

const MAX_READ_SIZE: usize = 500 * 1024 * 1024;

pub fn recv<R: Read, T: serde::de::DeserializeOwned>(
    reader: &mut R,
    format: Format,
) -> anyhow::Result<T> {
    let mut size_buf = [0u8; 8];
    if let Err(e) = reader.read_exact(&mut size_buf) {
        return if e.kind() == std::io::ErrorKind::UnexpectedEof {
            tracing::info!("Client disconnected after previous request");
            Err(anyhow!("Client disconnected"))
        } else {
            Err(e).context("Failed to read length prefix")
        };
    }
    let size = u64::from_le_bytes(size_buf) as usize;

    if size == 0 {
        return Err(anyhow::anyhow!("Received empty payload"));
    }

    if size > MAX_READ_SIZE {
        bail!("Payload size too large: {size} bytes");
    }

    let mut buf = vec![0u8; size];
    reader
        .read_exact(&mut buf)
        .context("Failed to read payload")?;

    let value = match format {
        Format::Msgpack => deserialize_from_msgpack_bytes(&buf),
        Format::Bincode => deserialize_from_bincode_bytes(&buf),
    }
    .context("Failed to deserialize payload")?;

    Ok(value)
}

pub fn send<W: Write, T: serde::Serialize>(
    writer: &mut W,
    response: &T,
    format: Format,
) -> anyhow::Result<()> {
    let data = match format {
        Format::Msgpack => serialize_to_msgpack_bytes(response),
        Format::Bincode => serialize_to_bincode_bytes(response),
    }
    .context("Failed to serialize value")?;

    let size = data.len();

    if size > MAX_READ_SIZE {
        bail!("Payload size too large: {size} bytes");
    }

    writer
        .write_all(&size.to_le_bytes())
        .context("Failed to write size header")?;
    writer
        .write_all(&data)
        .context("Failed to write serialized payload")?;
    writer.flush().context("Failed to flush writer")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::io::Cursor;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestData {
        id: u32,
        name: String,
        active: bool,
    }

    fn run_roundtrip_test(format: Format) {
        let original = TestData {
            id: 42,
            name: "hello".to_string(),
            active: true,
        };

        let mut buffer = Cursor::new(Vec::new());
        send(&mut buffer, &original, format).expect("send failed");

        buffer.set_position(0);

        let result: TestData = recv(&mut buffer, format).expect("recv failed");

        assert_eq!(original, result);
    }

    #[test]
    fn test_roundtrip_msgpack() {
        run_roundtrip_test(Format::Msgpack);
    }

    #[test]
    fn test_roundtrip_bincode() {
        run_roundtrip_test(Format::Bincode);
    }

    #[test]
    fn test_empty_payload_returns_error() {
        let mut buffer = Cursor::new(0u64.to_le_bytes().to_vec());
        let result: anyhow::Result<TestData> = recv(&mut buffer, Format::Msgpack);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty payload"));
    }

    #[test]
    fn test_invalid_data_fails_gracefully() {
        let mut buffer = Cursor::new(vec![0xFF; 20]); // invalid size header
        let result: anyhow::Result<TestData> = recv(&mut buffer, Format::Msgpack);
        assert!(result.is_err());
    }
}
