use crate::serialization::{FormatDeserialize, FromBytes, FromVecBytes};
use anyhow::Context;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub fn serialize_to_msgpack_bytes<T: Serialize>(item: &T) -> anyhow::Result<Vec<u8>> {
    let buf = rmp_serde::to_vec_named(item).context("failed to serialize to msgpack")?;
    Ok(buf)
}

pub fn deserialize_from_msgpack_bytes<T: DeserializeOwned>(encoded: &[u8]) -> anyhow::Result<T> {
    let decoded = rmp_serde::from_slice(encoded).context("failed to deserialize from msgpack")?;
    Ok(decoded)
}

#[derive(Debug)]
pub struct Msgpack<T>(pub T);

impl<T> FormatDeserialize for Msgpack<T>
where
    T: serde::de::DeserializeOwned,
{
    fn deserialize(input: &[u8]) -> anyhow::Result<Self> {
        let t = deserialize_from_msgpack_bytes(input)?;
        Ok(Msgpack(t))
    }
}

impl<T> FromBytes for Msgpack<T>
where
    T: serde::de::DeserializeOwned,
{
    fn from_bytes(input: &[u8]) -> anyhow::Result<Self> {
        let value = deserialize_from_msgpack_bytes(input)?;
        Ok(Msgpack(value))
    }
}

impl<T> FromVecBytes for Msgpack<T>
where
    T: serde::de::DeserializeOwned,
{
    fn from_vec_bytes(inputs: &[Vec<u8>]) -> anyhow::Result<Self> {
        if inputs.len() != 1 {
            return Err(anyhow::anyhow!("Expected exactly 1 input for Msgpack<T>"));
        }
        let value = deserialize_from_msgpack_bytes(&inputs[0])?;
        Ok(Msgpack(value))
    }
}
