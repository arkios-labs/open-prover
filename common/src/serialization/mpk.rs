use anyhow::Context;
use anyhow::Result;
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
