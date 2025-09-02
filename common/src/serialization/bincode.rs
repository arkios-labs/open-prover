use crate::serialization::mpk::{deserialize_from_msgpack_bytes, serialize_to_msgpack_bytes};
use crate::serialization::{ArgBytes, NestedArgBytes};
use anyhow::{Context, Result, bail};
use serde::{Serialize, de::DeserializeOwned};

pub fn serialize_to_bincode_bytes<T: Serialize>(item: &T) -> Result<Vec<u8>> {
    let encoded = bincode::serialize(item).context("Failed to serialize to bincode")?;
    Ok(encoded)
}

pub fn deserialize_from_bincode_bytes<T: DeserializeOwned>(encoded: &[u8]) -> Result<T> {
    let decoded = bincode::deserialize(encoded).context("Failed to deserialize from bincode")?;
    Ok(decoded)
}

#[derive(Debug)]
pub struct Bincode<T>(pub T);

impl<T> ArgBytes for Bincode<T>
where
    T: DeserializeOwned + Serialize,
{
    fn from_arg_bytes(bytes: &[u8]) -> Result<Self> {
        let v =
            deserialize_from_bincode_bytes(bytes).context("Failed to deserialize from bincode")?;
        Ok(Self(v))
    }
    fn to_arg_bytes(&self) -> Result<Vec<u8>> {
        serialize_to_bincode_bytes(&self.0)
    }
}

impl<T> NestedArgBytes for Bincode<T>
where
    T: DeserializeOwned + Serialize,
{
    fn from_nested_arg_bytes(input: &[u8]) -> Result<Self> {
        let chunks: Vec<Vec<u8>> =
            deserialize_from_msgpack_bytes(input).context("Failed to deserialize from msgpack")?;
        if chunks.len() != 1 {
            bail!("Expected exactly one input chunk");
        }
        Self::from_arg_bytes(&chunks[0])
    }

    fn to_nested_arg_bytes(&self) -> Result<Vec<u8>> {
        let one = vec![self.to_arg_bytes().context("Failed to get arg")?];
        serialize_to_msgpack_bytes(&one)
    }
}
