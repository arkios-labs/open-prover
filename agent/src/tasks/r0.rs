use crate::io::input::env::EnvProvider;
use crate::tasks::factory::get_agent;
use crate::tasks::{
    Agent, ProveKeccakRequestLocal, SerializableSession, convert, deserialize_obj, serialize_obj,
};
use anyhow::{Context, bail};
use anyhow::{Result, anyhow};
use hex::FromHex;
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{
    AssumptionReceipt, Digest, InnerAssumptionReceipt, InnerReceipt, ProverOpts, ProverServer,
    Receipt, ReceiptClaim, SuccinctReceipt, Unknown, VerifierContext, get_prover_server,
};
use std::collections::HashMap;
use std::time::Instant;
use std::{env, fs, rc::Rc};
use tracing::info;

pub struct RiscZeroAgent {
    pub prover: Option<Rc<dyn ProverServer>>,
    pub verifier_ctx: VerifierContext,
}

impl RiscZeroAgent {
    pub fn new() -> Result<Self> {
        let verifier_ctx = VerifierContext::default();

        let opts = ProverOpts::default();
        let prover = get_prover_server(&opts).context("Failed to initialize prover server")?;

        Ok(Self {
            prover: Some(prover),
            verifier_ctx,
        })
    }
}

impl Agent for RiscZeroAgent {
    fn execute(&self, _data: Vec<u8>) -> Result<()> {
        bail!("RiscZeroTask::execute is not supported in this context");
    }

    fn prove(&self, segment_bytes: Vec<u8>) -> Result<Vec<u8>> {
        let segment = deserialize_obj(&segment_bytes).context("Failed to deserialize segment")?;

        let segment_receipt = self
            .prover
            .as_ref()
            .context("Missing prover")?
            .prove_segment(&self.verifier_ctx, &segment)
            .context("Failed to prove segment")?;

        info!("segment_receipt: {:?}", &segment_receipt);
        let lift_receipt = self
            .prover
            .as_ref()
            .context("Missing prover")?
            .lift(&segment_receipt)
            .with_context(|| "Failed to lift".to_string())?;

        let serialized = serialize_obj(&lift_receipt).expect("Failed to serialize");

        Ok(serialized)
    }

    fn join(&self, left_receipt_bytes: Vec<u8>, right_receipt_bytes: Vec<u8>) -> Result<Vec<u8>> {
        info!("RiscZeroTask::join()");
        let left_receipt =
            deserialize_obj(&left_receipt_bytes).context("Failed to deserialize left receipt")?;
        let right_receipt =
            deserialize_obj(&right_receipt_bytes).context("Failed to deserialize right receipt")?;

        let joined = self
            .prover
            .as_ref()
            .context("Missing prover from join task")?
            .join(&left_receipt, &right_receipt)?;

        let serialized = serialize_obj(&joined).expect("Failed to serialize");

        Ok(serialized)
    }

    fn keccak(&self, pending_keccak_bytes: Vec<u8>) -> Result<Vec<u8>> {
        info!("RiscZeroTask::keccak()");

        let prove_keccak_request_local: ProveKeccakRequestLocal =
            deserialize_obj(&pending_keccak_bytes)
                .context("Failed to deserialize keccak request")?;

        // Conversion is required because the library's `ProveKeccakRequest` type doesn't support deserialization
        let prove_keccak_request = convert(prove_keccak_request_local);

        let keccak_receipt = self
            .prover
            .as_ref()
            .context("Mssing prover from keccak task")?
            .prove_keccak(&prove_keccak_request);

        let serialized = serialize_obj(&keccak_receipt?).expect("Failed to serialize");
        Ok(serialized)
    }

    fn union(&self, left_receipt_bytes: Vec<u8>, right_receipt_bytes: Vec<u8>) -> Result<Vec<u8>> {
        info!("RiscZeroTask::union()");

        let left_receipt =
            deserialize_obj(&left_receipt_bytes).context("Failed to deserialize left receipt")?;

        let right_receipt =
            deserialize_obj(&right_receipt_bytes).context("Failed to deserialize right receipt")?;

        let unioned = self
            .prover
            .as_ref()
            .context("Missing prover from union prove task")?
            .union(&left_receipt, &right_receipt)
            .context("Failed to union on left/right receipt")?
            .into_unknown();

        let serialized = serialize_obj(&unioned).context("Failed to serialize union receipt")?;

        Ok(serialized)
    }

    fn finalize(&self, root_receipt: Vec<u8>, journal: Vec<u8>, image_id: Digest) -> Result<()> {
        info!("RiscZeroTask::finalize()");
        let root_receipt = deserialize_obj(&root_receipt).context("Failed to deserialize root")?;
        let journal: Vec<u8> = match deserialize_obj(&journal) {
            Ok(data) => data,
            Err(_e) if journal.is_empty() => {
                tracing::warn!("Journal was empty, using default empty Vec");
                vec![]
            }
            Err(e) => return Err(e).context("could not deserialize the journal"),
        };
        let rollup_receipt = Receipt::new(InnerReceipt::Succinct(root_receipt), journal);

        rollup_receipt
            .verify(image_id)
            .context("Receipt verification failed")?;

        Ok(())
    }

    fn stark2snark(&self, _data: Vec<u8>) -> Result<()> {
        info!("RiscZeroTask::stark2snark()");
        Ok(())
    }

    fn resolve(
        &self,
        assumptions_bytes: Vec<u8>,
        root_receipt_bytes: Vec<u8>,
        union_root_receipt_bytes: Vec<u8>,
    ) -> Result<Vec<u8>> {
        info!("RiscZeroTask::resolve()");
        let mut conditional_receipt: SuccinctReceipt<ReceiptClaim> =
            deserialize_obj(&root_receipt_bytes).context("Failed to deserialize root receipt")?;

        let assumption_receipts: Vec<SuccinctReceipt<Unknown>> =
            deserialize_obj(&assumptions_bytes).context("Failed to deserialize assumptions")?;

        let mut assumption_receipt_map = HashMap::new();

        for receipt in assumption_receipts {
            let digest_str = receipt.claim.digest().to_string();
            assumption_receipt_map.insert(digest_str, receipt);
        }

        let mut assumptions_len: u64 = 0;

        if conditional_receipt
            .claim
            .clone()
            .as_value()?
            .output
            .is_some()
        {
            if let Some(guest_output) = conditional_receipt
                .claim
                .clone()
                .as_value()?
                .output
                .as_value()?
            {
                if !guest_output.assumptions.is_empty() {
                    let assumptions = guest_output
                        .assumptions
                        .as_value()
                        .context("Failed unwrap the assumptions of the guest output")?
                        .iter();

                    info!("Resolving {} assumption(s)", assumptions.len());
                    assumptions_len = assumptions
                        .len()
                        .try_into()
                        .context("Failed to convert to u64")?;

                    let mut union_claim = String::new();
                    if !union_root_receipt_bytes.is_empty() {
                        let union_receipt: SuccinctReceipt<Unknown> = deserialize_obj(
                            &union_root_receipt_bytes,
                        )
                        .context("Failed to deserialize to SuccinctReceipt<Unknown> type")?;
                        union_claim = union_receipt.claim.digest().to_string();

                        info!("Resolving union claim digest: {union_claim}");
                        conditional_receipt = self
                            .prover
                            .as_ref()
                            .context("Missing prover from resolve task")?
                            .resolve(&conditional_receipt, &union_receipt)
                            .context("Failed to resolve the union receipt")?;
                    }

                    for assumption in assumptions {
                        let assumption_claim = assumption.as_value()?.claim.to_string();
                        if assumption_claim.eq(&union_claim) {
                            info!("Skipping already resolved union claim: {union_claim}");
                            continue;
                        }

                        let assumption_receipt = assumption_receipt_map
                            .get(assumption_claim.as_str())
                            .with_context(|| {
                                format!("corroborating receipt not found: key {}", assumption_claim)
                            })?;

                        conditional_receipt = self
                            .prover
                            .as_ref()
                            .context("Missing prover from resolve task")?
                            .resolve(&conditional_receipt, &assumption_receipt)
                            .context("Failed to resolve the conditional receipt")?;
                    }
                    info!("Resolve complete");
                }
            }
        }
        info!(
            "Resolve operation completed successfully: {}",
            assumptions_len
        );

        let serialized = serialize_obj(&conditional_receipt)
            .context("Failed to serialize conditional receipt")?;

        Ok(serialized)
    }
}

#[test]
fn test_keccak_on_pending_keccaks() -> Result<()> {
    use anyhow::Context;
    use std::{env, fs, path::PathBuf, time::Instant};
    use tracing::info;

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    unsafe {
        env::set_var("AGENT_TYPE", "invalid");
    }

    let input = Box::new(EnvProvider {
        key: "AGENT_TYPE".to_string(),
    });
    let agent = get_agent(input)?;
    let agent_ref: &dyn Agent = agent.as_ref();

    let path = env::current_dir()?.join("metadata/session/session_4_segments.json");
    info!("Loading session from: {:?}", path);

    let json = fs::read_to_string(&path)?;
    let session: SerializableSession = serde_json::from_str(&json)?;

    let keccak_count = session.pending_keccaks.len();
    assert!(keccak_count > 0, "No pending keccaks found in session");

    info!("Found {} pending keccak inputs", keccak_count);

    let mut all_receipts = Vec::with_capacity(keccak_count);
    let start = Instant::now();

    for (i, keccak_req) in session.pending_keccaks.iter().enumerate() {
        let local_req = ProveKeccakRequestLocal {
            claim_digest: keccak_req
                .claim_digest
                .as_bytes()
                .try_into()
                .expect("claim_digest must be 32 bytes"),
            po2: keccak_req.po2,
            control_root: keccak_req
                .control_root
                .as_bytes()
                .try_into()
                .expect("control_root must be 32 bytes"),
            input: keccak_req.input.clone(),
        };

        let bytes = serialize_obj(&local_req)?;
        info!("Proving keccak [{} / {}]...", i + 1, keccak_count);

        let result = agent_ref.keccak(bytes)?;
        let receipt: SuccinctReceipt<Unknown> =
            deserialize_obj(&result).context("Failed to deserialize keccak receipt")?;

        info!("Keccak [{}] result size: {}", i, result.len());
        all_receipts.push(receipt);
    }

    let file_path = PathBuf::from("metadata/keccak/keccak_receipts.json");
    let receipts_json = serde_json::to_string_pretty(&all_receipts)?;
    fs::write(&file_path, receipts_json)
        .with_context(|| format!("Failed to write receipts to {:?}", file_path))?;

    info!(
        "All {} keccak receipts written to {:?} in {:?}",
        keccak_count,
        file_path,
        start.elapsed()
    );

    Ok(())
}

#[test]
fn test_union_on_keccaks_tree() -> Result<()> {
    use std::{collections::VecDeque, env, fs, time::Instant};
    use tracing::info;

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    unsafe {
        env::set_var("AGENT_TYPE", "invalid");
    }

    let input = Box::new(EnvProvider {
        key: "AGENT_TYPE".to_string(),
    });
    let agent = get_agent(input)?;
    let agent_ref: &dyn Agent = agent.as_ref();

    let path = env::current_dir()?.join("metadata/keccak/keccak_receipts.json");
    info!("Loading keccak receipts from: {:?}", path);

    let json = fs::read_to_string(&path)?;
    let keccak_receipts: Vec<SuccinctReceipt<Unknown>> = serde_json::from_str(&json)?;
    let receipt_count = keccak_receipts.len();
    info!("Loaded {} keccak receipts", receipt_count);

    let mut queue: Vec<Vec<Vec<u8>>> = keccak_receipts
        .into_iter()
        .map(|r| vec![serialize_obj(&r).expect("Failed to serialize receipt")])
        .collect();

    let start = Instant::now();

    while queue.len() > 1 {
        let mut next_level = Vec::with_capacity((queue.len() + 1) / 2);
        let mut i = 0;

        while i + 1 < queue.len() {
            let left = queue[i].clone();
            let right = queue[i + 1].clone();
            let left_serialized = left.last().unwrap();
            let right_serialized = right.last().unwrap();

            let union = agent_ref
                .union(left_serialized.clone(), right_serialized.clone())
                .expect("Union failed");

            let mut new_branch = left;
            new_branch.extend(right);
            new_branch.push(union.clone());

            info!("Union [{} + {}] size: {}", i, i + 1, union.len());
            next_level.push(new_branch);

            i += 2;
        }

        if i < queue.len() {
            next_level.push(queue[i].clone());
        }

        queue = next_level;
    }

    let final_branch = queue.pop().unwrap();
    let final_result = final_branch.last().unwrap();
    let elapsed = start.elapsed();

    info!(
        "Union complete: final result size: {}, elapsed: {:?}, total input receipts: {}",
        final_result.len(),
        elapsed,
        receipt_count
    );

    let union_receipt: SuccinctReceipt<Unknown> = deserialize_obj(final_result)?;
    let union_json = serde_json::to_string_pretty(&union_receipt)?;
    let output_path = env::current_dir()?.join("metadata/keccak/unioned_receipt.json");
    fs::write(&output_path, union_json)?;

    info!("Unioned receipt written to {:?}", output_path);

    Ok(())
}

#[test]
fn test_prove_all_segments() -> Result<()> {
    use anyhow::Context;
    use std::{env, fs, time::Instant};
    use tracing::info;

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    unsafe {
        env::set_var("AGENT_TYPE", "invalid");
    }

    let input = Box::new(EnvProvider {
        key: "AGENT_TYPE".to_string(),
    });
    let agent = get_agent(input)?;
    let agent_ref: &dyn Agent = agent.as_ref();

    let path = env::current_dir()?.join("metadata/session/session_4_segments.json");
    info!("Loading session from: {:?}", path);

    let json = fs::read_to_string(&path)?;
    let session: SerializableSession = serde_json::from_str(&json)?;
    let segment_count = session.segments.len();
    assert!(segment_count > 0, "No segments found in session");

    info!(
        "Found {} segments. Starting proof generation...",
        segment_count
    );
    let mut all_receipts = Vec::with_capacity(segment_count);
    let start = Instant::now();

    for (i, segment) in session.segments.iter().enumerate() {
        info!("Proving segment [{}/{}]", i + 1, segment_count);
        let bytes = serialize_obj(segment)?;
        let lifted_bytes = agent_ref.prove(bytes)?;

        info!("Segment [{}] proof size: {}", i, lifted_bytes.len());

        let lifted_receipt: SuccinctReceipt<ReceiptClaim> = deserialize_obj(&lifted_bytes)
            .context(format!("Failed to deserialize receipt for segment {}", i))?;

        all_receipts.push(lifted_receipt);
    }

    let output_path = env::current_dir()?.join("metadata/lifted_receipts.json");
    let output_json = serde_json::to_string_pretty(&all_receipts)?;
    fs::write(&output_path, output_json).context("Failed to write lifted receipts JSON")?;

    info!(
        "All {} segment receipts written to {:?} in {:?}",
        segment_count,
        output_path,
        start.elapsed()
    );

    Ok(())
}

#[test]
fn test_join_on_lifted_receipts() -> Result<()> {
    use std::{collections::VecDeque, env, fs, time::Instant};
    use tracing::info;

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    unsafe {
        env::set_var("AGENT_TYPE", "invalid");
    }

    let input = Box::new(EnvProvider {
        key: "AGENT_TYPE".to_string(),
    });
    let agent = get_agent(input)?;
    let agent_ref: &dyn Agent = agent.as_ref();

    let path = env::current_dir()?.join("metadata/lifted_receipts.json");
    info!("Loading lifted receipts from: {:?}", path);
    let json = fs::read_to_string(&path)?;

    let lifted_receipts: Vec<SuccinctReceipt<ReceiptClaim>> = serde_json::from_str(&json)?;
    let receipt_count = lifted_receipts.len();
    info!("Loaded {} lifted receipts", receipt_count);

    let serialized_receipts: Vec<Vec<u8>> = lifted_receipts
        .into_iter()
        .map(|r| serialize_obj(&r).unwrap())
        .collect();

    let mut queue: VecDeque<Vec<u8>> = VecDeque::from(serialized_receipts);
    let start = Instant::now();

    while queue.len() > 1 {
        let left = queue.pop_front().unwrap();
        let right = queue.pop_front().unwrap();

        let joined = agent_ref.join(left, right).expect("Join failed");
        info!(
            "Join successful (size: {}) | Remaining queue: {}",
            joined.len(),
            queue.len()
        );
        queue.push_back(joined);
    }

    let final_result = queue.pop_front().unwrap();
    let elapsed = start.elapsed();

    info!(
        "Join complete in {:?} | Final joined result size: {} | Total input receipts: {}",
        elapsed,
        final_result.len(),
        receipt_count
    );

    let root_receipt: SuccinctReceipt<ReceiptClaim> = deserialize_obj(&final_result)?;
    let root_json = serde_json::to_string_pretty(&root_receipt)?;
    fs::write("metadata/root_receipt.json", root_json)?;
    info!("Root receipt written to metadata/root_receipt.json");

    Ok(())
}

#[test]
fn test_resolve_on_session() -> Result<()> {
    use std::time::Instant;
    use std::{env, fs};
    use tracing::info;

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    unsafe {
        env::set_var("AGENT_TYPE", "invalid");
    }

    let input = Box::new(EnvProvider {
        key: "AGENT_TYPE".to_string(),
    });
    let agent = get_agent(input)?;
    let agent_ref: &dyn Agent = agent.as_ref();

    let session_path = env::current_dir()?.join("metadata/session/session_4_segments.json");
    info!("Loading session from: {:?}", session_path);
    let session_json = fs::read_to_string(&session_path)?;
    let session: SerializableSession = serde_json::from_str(&session_json)?;

    let assumption_receipts: Vec<SuccinctReceipt<Unknown>> = session
        .assumptions
        .iter()
        .filter_map(|(_, receipt)| match receipt {
            AssumptionReceipt::Proven(InnerAssumptionReceipt::Succinct(r)) => Some(r.clone()),
            _ => None,
        })
        .collect();
    info!("Loaded {} assumption receipts", assumption_receipts.len());

    let assumptions_bytes = serialize_obj(&assumption_receipts)?;
    info!(
        "Serialized assumption receipts, size: {}",
        assumptions_bytes.len()
    );

    let root_path = env::current_dir()?.join("metadata/root_receipt.json");
    info!("Loading root receipt from: {:?}", root_path);
    let root_json = fs::read_to_string(&root_path)?;
    let root_receipt: SuccinctReceipt<ReceiptClaim> = serde_json::from_str(&root_json)?;
    let root_receipt_bytes = serialize_obj(&root_receipt)?;
    info!(
        "Root receipt serialized, size: {}",
        root_receipt_bytes.len()
    );

    let union_path = env::current_dir()?.join("metadata/keccak/unioned_receipt.json");
    info!("Loading unioned receipt from: {:?}", union_path);
    let union_json = fs::read_to_string(&union_path)?;
    let union_receipt: SuccinctReceipt<Unknown> = serde_json::from_str(&union_json)?;
    let union_root_receipt_bytes = serialize_obj(&union_receipt)?;
    info!(
        "Unioned receipt serialized, size: {}",
        union_root_receipt_bytes.len()
    );

    info!("Calling resolve()...");
    let start_resolve = Instant::now();
    let resolved = agent_ref.resolve(
        assumptions_bytes,
        root_receipt_bytes,
        union_root_receipt_bytes,
    )?;
    info!("Resolve completed in {:?}", start_resolve.elapsed());

    let resolved_receipt: SuccinctReceipt<ReceiptClaim> = deserialize_obj(&resolved)?;
    let resolved_json = serde_json::to_string_pretty(&resolved_receipt)?;
    fs::write("metadata/resolved_receipt.json", resolved_json)?;
    info!("Resolved receipt written to metadata/resolved_receipt.json");

    Ok(())
}

#[test]
fn test_finalize_on_session() -> Result<()> {
    use std::time::Instant;
    use std::{env, fs};
    use tracing::info;

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let input = Box::new(EnvProvider {
        key: "AGENT_TYPE".to_string(),
    });
    let agent = get_agent(input)?;
    let agent_ref: &dyn Agent = agent.as_ref();

    let root_path = env::current_dir()?.join("metadata/resolved_receipt.json");
    info!("Loading resolved receipt from: {:?}", root_path);
    let root_json = fs::read_to_string(&root_path)?;
    let root_receipt: SuccinctReceipt<ReceiptClaim> = serde_json::from_str(&root_json)?;
    let root_receipt_bytes = serialize_obj(&root_receipt)?;
    info!(
        "Resolved receipt loaded and serialized, size: {}",
        root_receipt_bytes.len()
    );

    let session_path = env::current_dir()?.join("metadata/session/session_4_segments.json");
    info!("Loading session from: {:?}", session_path);
    let session_json = fs::read_to_string(&session_path)?;
    let session: SerializableSession = serde_json::from_str(&session_json)?;

    let journal_bytes = session
        .journal
        .as_ref()
        .map(|j| j.bytes.clone())
        .ok_or_else(|| anyhow!("journal is missing"))?;
    info!("Journal loaded, size: {}", journal_bytes.len());

    let image_id =
        read_image_id("3fe354c3604a1b33f44a76bde3ee677e0f68a1777b0f74f7658c87b49e4c4c8a")?;
    info!("Image ID loaded: {}", image_id.to_string());

    let start_finalize = Instant::now();
    agent_ref.finalize(root_receipt_bytes, journal_bytes, image_id)?;
    info!("Finalize succeeded in {:?}", start_finalize.elapsed());

    Ok(())
}

pub(crate) fn read_image_id(image_id: &str) -> Result<Digest> {
    Digest::from_hex(image_id).context("Failed to convert imageId file to digest from_hex")
}
