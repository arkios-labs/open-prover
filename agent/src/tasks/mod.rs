pub mod factory;
pub mod r0;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub trait Agent {
    fn execute(&self, data: Vec<u8>) -> Result<()>;
    fn prove(&self, data: Vec<u8>) -> Result<()>;
    fn join(&self, left: Vec<u8>, right: Vec<u8>) -> Result<()>;
    fn keccak(&self, data: Vec<u8>) -> Result<()>;
    fn union(&self, data: Vec<u8>) -> Result<()>;
    fn finalize(&self, data: Vec<u8>) -> Result<()>;
    fn stark2snark(&self, data: Vec<u8>) -> Result<()>;
    fn resolve(&self, data: Vec<u8>) -> Result<()>;
}

pub(crate) fn deserialize_obj<T: for<'de> Deserialize<'de>>(encoded: &[u8]) -> Result<T> {
    let decoded = bincode::deserialize(encoded)?;
    Ok(decoded)
}

pub(crate) fn serialize_obj<T: Serialize>(item: &T) -> Result<Vec<u8>> {
    bincode::serialize(item).map_err(anyhow::Error::new)
}
