pub mod factory;
pub mod r0;

use anyhow::Result;
use risc0_zkvm::{
    Assumption, AssumptionReceipt, Digest, Journal, ProveKeccakRequest, ReceiptClaim, Segment,
    SuccinctReceipt, Unknown,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub type KeccakState = [u64; 25];

#[derive(Deserialize, Serialize)]
pub struct ProveKeccakRequestLocal {
    pub claim_digest: Digest,
    pub po2: usize,
    pub control_root: Digest,
    pub input: Vec<KeccakState>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SerializableKeccakRequest {
    /// The digest of the claim that this keccak input is expected to produce.
    pub claim_digest: Digest,

    /// The requested size of the keccak proof, in powers of 2.
    pub po2: usize,

    /// The control root which identifies a particular keccak circuit revision.
    pub control_root: Digest,

    /// Input transcript to provide to the keccak circuit.
    pub input: Vec<KeccakState>,
}

#[derive(Serialize, Deserialize)]
pub struct SerializableZkrRequest {
    pub claim_digest: String,
    pub control_id: String,
    pub input_len: usize,
}
#[derive(Serialize, Deserialize)]
pub struct SerializableSession {
    pub segments: Vec<Segment>,
    pub journal: Option<Journal>,
    pub assumptions: Vec<(Assumption, AssumptionReceipt)>,
    pub pending_zkrs: Vec<SerializableZkrRequest>,
    pub pending_keccaks: Vec<SerializableKeccakRequest>,
}

#[derive(Serialize, Deserialize)]
pub struct ResolveInput {
    pub(crate) root: SuccinctReceipt<ReceiptClaim>,
    pub(crate) union: Option<SuccinctReceipt<Unknown>>,
    pub(crate) assumptions: Vec<(Assumption, AssumptionReceipt)>,
}

#[derive(Serialize, Deserialize)]
pub struct FinalizeInput {
    pub(crate) root: SuccinctReceipt<ReceiptClaim>,
    pub(crate) journal: Vec<u8>,
    pub(crate) image_id: String,
}

#[async_trait::async_trait(?Send)]
pub trait Agent {
    fn execute(&self, data: Vec<u8>) -> Result<Vec<u8>>;
    fn prove(&self, data: Vec<u8>) -> Result<Vec<u8>>;
    fn join(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn keccak(&self, prove_keccak_request: Vec<u8>) -> Result<Vec<u8>>;
    fn union(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn resolve(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn finalize(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn prepare_snark(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn get_snark_receipt(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    async fn snark(&self, data: Vec<u8>) -> Result<Vec<u8>>;
}

pub fn deserialize_obj<T: DeserializeOwned>(encoded: &[u8]) -> Result<T> {
    let json_str = std::str::from_utf8(encoded)?;
    let decoded = serde_json::from_str(json_str)?;
    Ok(decoded)
}

pub fn serialize_obj<T: Serialize>(item: &T) -> Result<Vec<u8>> {
    let json_str = serde_json::to_string(item)?;
    Ok(json_str.into_bytes())
}

fn convert(local: ProveKeccakRequestLocal) -> ProveKeccakRequest {
    ProveKeccakRequest {
        claim_digest: Digest::from(local.claim_digest),
        po2: local.po2,
        control_root: Digest::from(local.control_root),
        input: local.input,
    }
}
