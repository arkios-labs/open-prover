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
