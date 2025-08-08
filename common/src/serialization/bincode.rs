use anyhow::Result;
use serde::{de::DeserializeOwned, Serialize};

pub fn serialize_to_bincode_bytes<T: Serialize>(item: &T) -> Result<Vec<u8>> {
    let encoded = bincode::serialize(item)?;
    Ok(encoded)
}

pub fn deserialize_from_bincode_bytes<T: DeserializeOwned>(encoded: &[u8]) -> Result<T> {
    let decoded = bincode::deserialize(encoded)?;
    Ok(decoded)
}
