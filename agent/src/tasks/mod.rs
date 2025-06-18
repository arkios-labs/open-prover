pub mod factory;
pub mod r0;

use anyhow::{Context, Result};
use bincode::de;
use risc0_zkvm::{Digest, ProveKeccakRequest};
use serde::de::{DeserializeOwned, Error, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::fmt::Write;

pub trait Agent {
    fn execute(&self, data: Vec<u8>) -> Result<()>;
    fn prove(&self, data: Vec<u8>) -> Result<Vec<u8>>;
    fn join(&self, left: Vec<u8>, right: Vec<u8>) -> Result<Vec<u8>>;
    fn keccak(&self, prove_keccak_request: Vec<u8>) -> Result<Vec<u8>>;
    fn union(&self, left: Vec<u8>, right: Vec<u8>) -> Result<Vec<u8>>;
    fn finalize(&self, data: Vec<u8>) -> Result<()>;
    fn stark2snark(&self, data: Vec<u8>) -> Result<()>;
    fn resolve(&self, data: Vec<u8>) -> Result<Vec<u8>>;
}

pub(crate) fn deserialize_obj<T: DeserializeOwned>(encoded: &[u8]) -> Result<T> {
    let json_str = std::str::from_utf8(encoded)?;
    let decoded = serde_json::from_str(json_str)?;
    Ok(decoded)
}

pub(crate) fn serialize_obj<T: Serialize>(item: &T) -> Result<Vec<u8>> {
    let json_str = serde_json::to_string(item)?;
    Ok(json_str.into_bytes())
}

pub type KeccakState = [u64; 25];

#[derive(Deserialize)]
struct ProveKeccakRequestLocal {
    claim_digest: [u8; 32],
    po2: usize,
    control_root: [u8; 32],
    input: Vec<KeccakState>,
}

fn convert(local: ProveKeccakRequestLocal) -> ProveKeccakRequest {
    ProveKeccakRequest {
        claim_digest: Digest::from(local.claim_digest),
        po2: local.po2,
        control_root: Digest::from(local.control_root),
        input: local.input,
    }
}
