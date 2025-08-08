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

/// Trait for deserializing a single value from raw bytes.
pub trait FromBytes: Sized {
    fn from_bytes(input: &[u8]) -> anyhow::Result<Self>;
}

/// Trait for constructing structured data from `Vec<Vec<u8>>`,
/// typically deserialized from a Msgpack payload.
pub trait FromVecBytes: Sized {
    fn from_vec_bytes(inputs: &[Vec<u8>]) -> anyhow::Result<Self>;
}

impl FromVecBytes for () {
    fn from_vec_bytes(_: &[Vec<u8>]) -> anyhow::Result<Self> {
        Ok(())
    }
}

impl<Head, Tail> FromVecBytes for (Head, Tail)
where
    Head: FromBytes,
    Tail: FromVecBytes,
{
    fn from_vec_bytes(inputs: &[Vec<u8>]) -> anyhow::Result<Self> {
        if inputs.is_empty() {
            bail!("Not enough inputs");
        }
        let head = Head::from_bytes(&inputs[0]).context("Failed to deserialize head")?;
        let tail = Tail::from_vec_bytes(&inputs[1..]).context("Failed to deserialize tail")?;
        Ok((head, tail))
    }
}

/// Entrypoint for parsing Msgpack-encoded `Vec<Vec<u8>>` into structured types.
pub trait FromInputBytes: Sized {
    fn from_input_bytes(input: &[u8]) -> anyhow::Result<Self>;
}

impl<T> FromInputBytes for T
where
    T: FromVecBytes,
{
    fn from_input_bytes(input: &[u8]) -> anyhow::Result<Self> {
        if input.is_empty() {
            bail!("input is empty");
        }

        let chunks: Vec<Vec<u8>> = deserialize_from_msgpack_bytes(input)
            .context("Failed to parse input as Vec<Vec<u8>>")?;

        T::from_vec_bytes(&chunks)
    }
}

/// For types that can be deserialized from a single binary blob
/// using a specific serialization format.
pub trait FormatDeserialize: Sized {
    fn deserialize(input: &[u8]) -> anyhow::Result<Self>;
}

/// Parses a single binary payload using a format-aware wrapper type (e.g., Msgpack<T>, Bincode<T>).
///
/// Use this when the input is a single serialized value.
pub fn parse_single_input<T>(input: &[u8]) -> anyhow::Result<T>
where
    T: FormatDeserialize,
{
    if input.is_empty() {
        bail!("input is empty");
    }

    T::deserialize(input).context("Failed to deserialize input")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialization::bincode::Bincode;
    use crate::serialization::mpk::Msgpack;
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

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct SerializationTestData {
        id: u32,
        name: String,
    }

    #[test]
    fn test_parse_input_msgpack_and_bincode() {
        let data = SerializationTestData {
            id: 7,
            name: "sp1".to_string(),
        };

        let msgpack_bytes = serialize_to_msgpack_bytes(&data).unwrap();
        let Msgpack(parsed): Msgpack<SerializationTestData> =
            parse_single_input(&msgpack_bytes).unwrap();
        assert_eq!(parsed, data);

        let bincode_bytes = serialize_to_bincode_bytes(&data).unwrap();
        let Bincode(parsed): Bincode<SerializationTestData> =
            parse_single_input(&bincode_bytes).unwrap();
        assert_eq!(parsed, data);
    }

    #[test]
    fn test_from_vec_bytes_single() {
        let val = SerializationTestData {
            id: 1,
            name: "msgpack".into(),
        };

        let msgpack_bytes = serialize_to_msgpack_bytes(&val).unwrap();
        let wrapper =
            Msgpack::<SerializationTestData>::from_vec_bytes(&[msgpack_bytes.clone()]).unwrap();
        assert_eq!(wrapper.0, val);

        let bincode_bytes = serialize_to_bincode_bytes(&val).unwrap();
        let wrapper =
            Bincode::<SerializationTestData>::from_vec_bytes(&[bincode_bytes.clone()]).unwrap();
        assert_eq!(wrapper.0, val);
    }

    #[test]
    fn test_from_vec_bytes_tuple() {
        let val1 = SerializationTestData {
            id: 11,
            name: "a".into(),
        };
        let val2 = SerializationTestData {
            id: 22,
            name: "b".into(),
        };

        let a = serialize_to_msgpack_bytes(&val1).unwrap();
        let b = serialize_to_bincode_bytes(&val2).unwrap();
        let input = vec![a, b];

        let (Msgpack(v1), Bincode(v2)): (
            Msgpack<SerializationTestData>,
            Bincode<SerializationTestData>,
        ) = FromVecBytes::from_vec_bytes(&input).unwrap();

        assert_eq!(v1, val1);
        assert_eq!(v2, val2);
    }

    #[test]
    fn test_from_input_bytes_nested_tuple() {
        let val1 = SerializationTestData {
            id: 100,
            name: "left".into(),
        };
        let val2 = SerializationTestData {
            id: 200,
            name: "right".into(),
        };
        let flag = true;

        let chunk1 = serialize_to_bincode_bytes(&val1).unwrap();
        let chunk2 = serialize_to_bincode_bytes(&val2).unwrap();
        let chunk3 = serialize_to_msgpack_bytes(&flag).unwrap();

        let input_chunks = vec![chunk1, chunk2, chunk3];
        let packed_input = serialize_to_msgpack_bytes(&input_chunks).unwrap();

        let (Bincode(left), (Bincode(right), Msgpack(is_set))): (
            Bincode<SerializationTestData>,
            (Bincode<SerializationTestData>, Msgpack<bool>),
        ) = FromInputBytes::from_input_bytes(&packed_input).unwrap();

        assert_eq!(left, val1);
        assert_eq!(right, val2);
        assert!(is_set);
    }

    #[test]
    fn test_from_structured_input_invalid_format() {
        let not_nested_vec = serialize_to_msgpack_bytes(&"not nested array").unwrap();

        let result: anyhow::Result<(
            Msgpack<SerializationTestData>,
            Bincode<SerializationTestData>,
        )> = FromInputBytes::from_input_bytes(&not_nested_vec);

        assert!(result.is_err());

        let err = result.unwrap_err().to_string();
        assert!(err.contains("Failed to parse input as Vec<Vec<u8>>"));
    }

    #[test]
    fn test_from_vec_bytes_empty_input() {
        let result: anyhow::Result<(
            Msgpack<SerializationTestData>,
            Bincode<SerializationTestData>,
        )> = FromVecBytes::from_vec_bytes(&[]);
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("Not enough inputs"));
    }

    #[test]
    fn test_empty_input_returns_error() {
        let result: anyhow::Result<Msgpack<SerializationTestData>> = parse_single_input(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("input is empty"));
    }
}
