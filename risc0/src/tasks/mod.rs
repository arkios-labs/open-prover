pub mod r0;

use anyhow::{Context, Result};
use risc0_zkvm::{
    Assumption, AssumptionReceipt, Digest, Journal, ProveKeccakRequest, ProverOpts, ProverServer,
    ReceiptClaim, Segment, SuccinctReceipt, Unknown, VerifierContext, get_prover_server,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::rc::Rc;

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

pub struct Risc0Agent {
    pub prover: Rc<dyn ProverServer>,
    pub verifier_ctx: VerifierContext,
}

impl Risc0Agent {
    pub fn new() -> Result<Self> {
        let verifier_ctx = VerifierContext::default();

        let opts = ProverOpts::default().with_segment_po2_max(25);
        let prover = get_prover_server(&opts).context("Failed to initialize prover server")?;

        Ok(Self { prover, verifier_ctx })
    }
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
        claim_digest: local.claim_digest,
        po2: local.po2,
        control_root: local.control_root,
        input: local.input,
    }
}

pub fn setup_agent_and_metadata_dir() -> Result<(PathBuf, Risc0Agent)> {
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init();

    let metadata_dir = PathBuf::from("metadata");

    let agent = Risc0Agent::new().context("Failed to create agent")?;

    Ok((metadata_dir, agent))
}
