pub mod execute;
mod finalize;
mod join;
mod keccak;
mod prove;
mod resolve;
mod stark2snark;
mod union;

use anyhow::{Context, Result};
use risc0_zkvm::{
    Assumption, AssumptionReceipt, Digest, Journal, ProveKeccakRequest, ProverOpts, ProverServer,
    ReceiptClaim, Segment, SuccinctReceipt, Unknown, VerifierContext, get_prover_server,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
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

    let metadata_dir = PathBuf::from(test_constants::METADATA_PATH);

    let agent = Risc0Agent::new().context("Failed to create agent")?;

    Ok((metadata_dir, agent))
}

pub fn compress_binary_tree<F>(func: F, receipts: VecDeque<Vec<u8>>) -> Result<Vec<u8>>
where
    F: Fn(Vec<u8>, Vec<u8>) -> Result<Vec<u8>>,
{
    let mut queue = receipts;
    while queue.len() > 1 {
        let mut next_level = VecDeque::with_capacity((queue.len() + 1) / 2);
        while let Some(left) = queue.pop_front() {
            if let Some(right) = queue.pop_front() {
                let joined = func(left, right).context("Failed to join receipts")?;
                next_level.push_back(joined);
            } else {
                next_level.push_back(left);
                break;
            }
        }
        queue = next_level;
    }
    Ok(queue.pop_front().unwrap())
}

pub mod test_constants {
    pub const FIXTURES_IMAGE_ID: &str =
        "8edff446235f5e628e89a627661ec2d1c13c4467beb0a7c669709ea36b5c9a1a"; // MultiTestSpec::KeccakUnion(1)
    pub const METADATA_PATH: &str = "metadata";
    pub const ELF_DATA_PATH: &str = "elf_data.bin";
    pub const INPUT_DATA_PATH: &str = "input_data.bin";
    pub const SEGMENTS_PATH: &str = "session/segments.bin";
    pub const KECCAKS_PATH: &str = "session/keccaks.bin";
    pub const JOURNAL_PATH: &str = "session/journal.bin";
    pub const ASSUMPTIONS_PATH: &str = "session/assumptions.bin";
    pub const SEGMENT_LIFTED_RECEIPTS_PATH: &str = "receipt/segment_lifted_receipts.bin";
    pub const KECCAK_RECEIPTS_PATH: &str = "receipt/keccak_receipts.bin";
    pub const JOIN_ROOT_RECEIPT_PATH: &str = "receipt/join_root_receipt.bin";
    pub const UNION_ROOT_RECEIPT_PATH: &str = "receipt/union_root_receipt.bin";
    pub const RESOLVED_RECEIPT_PATH: &str = "receipt/resolved_receipt.bin";
    pub const FINAL_RECEIPT_PATH: &str = "receipt/final_receipt.bin";
}
