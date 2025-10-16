use anyhow::{Context, Result};
use serde::{Serialize, de::DeserializeOwned};

pub fn serialize_to_bincode_bytes<T: Serialize>(item: &T) -> Result<Vec<u8>> {
    let encoded = bincode::serialize(item).context("Failed to serialize to bincode")?;
    Ok(encoded)
}

pub fn deserialize_from_bincode_bytes<T: DeserializeOwned>(encoded: &[u8]) -> Result<T> {
    let decoded = bincode::deserialize(encoded).context("Failed to deserialize from bincode")?;
    Ok(decoded)
}
