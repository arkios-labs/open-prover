use crate::serialization::{FormatDeserialize, FromBytes, FromVecBytes};
use anyhow::{Context, Result, anyhow};
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

impl<T> FormatDeserialize for Bincode<T>
where
    T: serde::de::DeserializeOwned,
{
    fn deserialize(input: &[u8]) -> Result<Self> {
        let t =
            deserialize_from_bincode_bytes(input).context("Failed to deserialize from bincode")?;
        Ok(Bincode(t))
    }
}

impl<T> FromBytes for Bincode<T>
where
    T: serde::de::DeserializeOwned,
{
    fn from_bytes(input: &[u8]) -> Result<Self> {
        let value =
            deserialize_from_bincode_bytes(input).context("Failed to deserialize from bincode")?;
        Ok(Bincode(value))
    }
}

impl<T> FromVecBytes for Bincode<T>
where
    T: serde::de::DeserializeOwned,
{
    fn from_vec_bytes(inputs: &[Vec<u8>]) -> Result<Self> {
        if inputs.len() != 1 {
            return Err(anyhow!("Expected exactly 1 input for Bincode<T>"));
        }
        let value = deserialize_from_bincode_bytes(&inputs[0])
            .context("Failed to deserialize from bincode")?;
        Ok(Bincode(value))
    }
}
