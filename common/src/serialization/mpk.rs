use rmp_serde::encode;
use serde::Serialize;
use serde::de::DeserializeOwned;

pub fn serialize_to_msgpack_bytes<T: Serialize>(item: &T) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    encode::write(&mut buf, item)?;
    Ok(buf)
}

pub fn deserialize_from_msgpack_bytes<T: DeserializeOwned>(encoded: &[u8]) -> anyhow::Result<T> {
    let decoded = rmp_serde::from_slice(encoded)?;
    Ok(decoded)
}
