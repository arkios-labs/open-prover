use anyhow::Result;
use serde::Serialize;
use serde::de::DeserializeOwned;

pub fn serialize_to_json_bytes<T: Serialize>(item: &T) -> Result<Vec<u8>> {
    let json_str = serde_json::to_string(item)?;
    Ok(json_str.into_bytes())
}

pub fn deserialize_from_json_bytes<T: DeserializeOwned>(encoded: &[u8]) -> Result<T> {
    let json_str = std::str::from_utf8(encoded)?;
    let decoded = serde_json::from_str(json_str)?;
    Ok(decoded)
}
