use crate::serialization::{FormatDeserialize, FromBytes, FromVecBytes};
use anyhow::Result;
use serde::{Serialize, de::DeserializeOwned};

pub fn serialize_to_bincode_bytes<T: Serialize>(item: &T) -> Result<Vec<u8>> {
    let encoded = bincode::serialize(item)?;
    Ok(encoded)
}

pub fn deserialize_from_bincode_bytes<T: DeserializeOwned>(encoded: &[u8]) -> Result<T> {
    let decoded = bincode::deserialize(encoded)?;
    Ok(decoded)
}

#[derive(Debug)]
pub struct Bincode<T>(pub T);

impl<T> FormatDeserialize for Bincode<T>
where
    T: serde::de::DeserializeOwned,
{
    fn deserialize(input: &[u8]) -> anyhow::Result<Self> {
        let t = deserialize_from_bincode_bytes(input)?;
        Ok(Bincode(t))
    }
}

impl<T> FromBytes for Bincode<T>
where
    T: serde::de::DeserializeOwned,
{
    fn from_bytes(input: &[u8]) -> anyhow::Result<Self> {
        let value = deserialize_from_bincode_bytes(input)?;
        Ok(Bincode(value))
    }
}

impl<T> FromVecBytes for Bincode<T>
where
    T: serde::de::DeserializeOwned,
{
    fn from_vec_bytes(inputs: &[Vec<u8>]) -> anyhow::Result<Self> {
        if inputs.len() != 1 {
            return Err(anyhow::anyhow!("Expected exactly 1 input for Bincode<T>"));
        }
        let value = deserialize_from_bincode_bytes(&inputs[0])?;
        Ok(Bincode(value))
    }
}
