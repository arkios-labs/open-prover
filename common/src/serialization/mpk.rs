use crate::serialization::{ArgBytes, NestedArgBytes};
use anyhow::Context;
use anyhow::{Result, bail};
use serde::Serialize;
use serde::de::DeserializeOwned;

pub fn serialize_to_msgpack_bytes<T: Serialize + ?Sized>(item: &T) -> Result<Vec<u8>> {
    let buf = rmp_serde::to_vec_named(item).context("Failed to serialize to msgpack")?;
    Ok(buf)
}

pub fn deserialize_from_msgpack_bytes<T: DeserializeOwned>(encoded: &[u8]) -> Result<T> {
    let decoded = rmp_serde::from_slice(encoded).context("Failed to deserialize from msgpack")?;
    Ok(decoded)
}

#[derive(Debug)]
pub struct Msgpack<T>(pub T);

impl<T> ArgBytes for Msgpack<T>
where
    T: DeserializeOwned + Serialize,
{
    fn from_arg_bytes(bytes: &[u8]) -> Result<Self> {
        let v =
            deserialize_from_msgpack_bytes(bytes).context("Failed to deserialize from msgpack")?;
        Ok(Self(v))
    }
    fn to_arg_bytes(&self) -> Result<Vec<u8>> {
        serialize_to_msgpack_bytes(&self.0)
    }
}

impl<T> NestedArgBytes for Msgpack<T>
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
