use crate::io::input::env::EnvProvider;
use crate::tasks::factory::get_agent;
use crate::tasks::{
    convert, deserialize_obj, serialize_obj, Agent, ProveKeccakRequestLocal, SerializableSession,
};
use anyhow::{anyhow, Result};
use anyhow::{bail, Context};
use hex::FromHex;
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{
    get_prover_server, AssumptionReceipt, Digest, InnerAssumptionReceipt, InnerReceipt, ProverOpts,
    ProverServer, Receipt, ReceiptClaim, SuccinctReceipt, Unknown, VerifierContext,
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

    info!("path: {:?}", path);
    let json = fs::read_to_string(&path)?;
    let session: SerializableSession = serde_json::from_str(&json)?;

    assert!(
        !session.pending_keccaks.is_empty(),
        "No pending keccaks found in session"
    );

    let mut all_receipts = Vec::new();

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
        info!("Keccak test [{}] start", i);
        let result = agent_ref.keccak(bytes)?;

        let keccak_receipt: SuccinctReceipt<Unknown> =
            deserialize_obj(&result).context("Failed to deserialize keccak")?;

        all_receipts.push(keccak_receipt);

        info!("Keccak test [{}] result len: {}", i, result.len());
    }

    let receipts_json = serde_json::to_string_pretty(&all_receipts)?;
    let file_path = std::path::PathBuf::from("metadata/keccak/keccak_receipts.json");
    fs::write(&file_path, receipts_json)
        .with_context(|| format!("Failed to write receipts to {:?}", file_path))?;

    Ok(())
}

#[test]
fn test_union_on_keccaks_ordered() -> Result<()> {
    use std::env;
    use std::fs;
    use std::time::Instant;
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
    info!("path: {:?}", path);
    let json = fs::read_to_string(&path)?;
    let keccak_receipts: Vec<SuccinctReceipt<Unknown>> = serde_json::from_str(&json)?;

    let serialized = |i: usize| serialize_obj(&keccak_receipts[i]).expect("Serialize failed");

    let start = Instant::now();

    let union1 = agent_ref
        .union(serialized(0), serialized(1))
        .expect("Union 0-1 failed");
    let union2 = agent_ref
        .union(serialized(2), serialized(3))
        .expect("Union 2-3 failed");
    let union3 = agent_ref
        .union(union1.clone(), union2.clone())
        .expect("Union1-2 failed");
    let final_union = agent_ref
        .union(union3.clone(), serialized(4))
        .expect("Final union failed");

    let elapsed = start.elapsed();

    info!("Final unioned result size: {}", final_union.len());
    info!("Union elapsed: {:?} with receipts count: 6", elapsed);

    let union_receipt: SuccinctReceipt<Unknown> = deserialize_obj(&final_union)?;
    let union_json = serde_json::to_string_pretty(&union_receipt)?;
    fs::write("metadata/keccak/unioned_receipt.json", union_json)?;

    Ok(())
}

#[test]
fn test_union_on_keccaks() -> Result<()> {
    use std::collections::VecDeque;

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
    info!("path: {:?}", path);
    let json = fs::read_to_string(&path)?;

    let keccak_receipts: Vec<SuccinctReceipt<Unknown>> = serde_json::from_str(&json)?;
    let keccak_receipts_count = keccak_receipts.len();

    let serialized_receipts: Vec<Vec<u8>> = keccak_receipts
        .into_iter()
        .map(|r| serialize_obj(&r).unwrap())
        .collect();

    let mut queue: VecDeque<Vec<u8>> = VecDeque::from(serialized_receipts);
    let start = Instant::now();

    while queue.len() > 1 {
        let left = queue.pop_front().unwrap();
        let right = queue.pop_front().unwrap();

        let union = agent_ref.union(left, right).expect("Union failed");

        info!("Union successful, resulting size: {}", union.len());
        queue.push_back(union);
    }

    let final_result = queue.pop_front().unwrap();
    let elapsed = start.elapsed();

    info!("Final unioned result size: {}", final_result.len());
    info!(
        "Union elapsed: {:?} with receipts count: {:?}",
        elapsed, keccak_receipts_count
    );
    let union_receipt: SuccinctReceipt<Unknown> = deserialize_obj(&final_result)?;

    let union_receipt = serde_json::to_string_pretty(&union_receipt)?;
    fs::write("metadata/keccak/unioned_receipt.json", union_receipt)?;

    Ok(())
}

#[test]
fn test_prove_all_segments() -> Result<()> {
    use anyhow::Context;
    use std::env;
    use std::fs;
    use std::time::Instant;
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
    info!("path: {:?}", path);

    let json = fs::read_to_string(&path)?;
    let session: SerializableSession = serde_json::from_str(&json)?;

    assert!(!session.segments.is_empty(), "No segments found in session");

    let mut all_receipts = Vec::new();
    let start = Instant::now();

    for (i, segment) in session.segments.iter().enumerate() {
        info!("Proving segment [{}]", i);
        let bytes = serialize_obj(segment)?;
        let lifted_bytes = agent_ref.prove(bytes)?;

        info!("Lifted segment [{}] result size: {}", i, lifted_bytes.len());

        let lifted_receipt: SuccinctReceipt<ReceiptClaim> = deserialize_obj(&lifted_bytes)
            .context(format!("Failed to deserialize receipt for segment {}", i))?;

        all_receipts.push(lifted_receipt);
    }

    let output_json = serde_json::to_string_pretty(&all_receipts)?;
    fs::write("metadata/lifted_receipts.json", output_json)
        .context("Failed to write lifted receipts JSON")?;

    info!(
        "All segment receipts written successfully in {:?}",
        start.elapsed()
    );

    Ok(())
}

#[test]
fn test_join_on_lifted_receipts() -> Result<()> {
    use std::collections::VecDeque;

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
    info!("path: {:?}", path);
    let json = fs::read_to_string(&path)?;

    let lifted_receipts: Vec<SuccinctReceipt<ReceiptClaim>> = serde_json::from_str(&json)?;
    let lifted_receipts_count = lifted_receipts.len();

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

        info!("Join successful, resulting size: {}", joined.len());
        queue.push_back(joined);
    }

    let final_result = queue.pop_front().unwrap();
    let elapsed = start.elapsed();

    info!("Final joined result size: {}", final_result.len());
    info!(
        "Join elapsed: {:?} with receipts count: {:?}",
        elapsed, lifted_receipts_count
    );
    let root_receipt: SuccinctReceipt<ReceiptClaim> = deserialize_obj(&final_result)?;

    let root_receipt = serde_json::to_string_pretty(&root_receipt)?;
    fs::write("metadata/root_receipt.json", root_receipt)?;

    Ok(())
}

#[test]
fn test_resolve_on_session() -> Result<()> {
    use std::env;
    use std::fs;
    use std::time::Instant;
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
    info!("Reading session from {:?}", session_path);
    let session_json = fs::read_to_string(&session_path)?;
    let session: SerializableSession = serde_json::from_str(&session_json)?;

    let assumption_receipts: Vec<SuccinctReceipt<Unknown>> = session
        .assumptions
        .iter()
        .filter_map(|(_, assumption_receipt)| match assumption_receipt {
            AssumptionReceipt::Proven(InnerAssumptionReceipt::Succinct(receipt)) => {
                Some(receipt.clone())
            }
            _ => None,
        })
        .collect();
    let assumptions_bytes = serialize_obj(&assumption_receipts)?;

    let root_path = env::current_dir()?.join("metadata/root_receipt.json");
    let root_json = fs::read_to_string(&root_path)?;
    let root_receipt: SuccinctReceipt<ReceiptClaim> = serde_json::from_str(&root_json)?;
    let root_receipt_bytes = serialize_obj(&root_receipt)?;

    let union_path = env::current_dir()?.join("metadata/keccak/unioned_receipt.json");
    let union_json = fs::read_to_string(&union_path)?;
    let union_receipt: SuccinctReceipt<Unknown> = serde_json::from_str(&union_json)?;
    let union_root_receipt_bytes = serialize_obj(&union_receipt)?;

    let start = Instant::now();

    let resolved = agent_ref.resolve(
        assumptions_bytes,
        root_receipt_bytes,
        union_root_receipt_bytes,
    )?;
    info!("Resolve time elapsed: {:?}", start.elapsed());

    let resolved_receipt: SuccinctReceipt<ReceiptClaim> = deserialize_obj(&resolved)?;

    let resolved_receipt = serde_json::to_string_pretty(&resolved_receipt)?;
    fs::write("metadata/resolved_receipt.json", resolved_receipt)?;

    Ok(())
}

#[test]
fn test_finalize_on_session() -> Result<()> {
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

    let root_path = env::current_dir()?.join("metadata/resolved_receipt.json");
    let root_json = fs::read_to_string(&root_path)?;
    let root_receipt: SuccinctReceipt<ReceiptClaim> = serde_json::from_str(&root_json)?;
    let root_receipt_bytes = serialize_obj(&root_receipt)?;

    let session_path = env::current_dir()?.join("metadata/session/session_4_segments.json");
    let session_json = fs::read_to_string(&session_path)?;
    let session: SerializableSession = serde_json::from_str(&session_json)?;

    let journal_bytes = session
        .journal
        .as_ref()
        .map(|j| j.bytes.clone())
        .ok_or_else(|| anyhow!("journal is missing"))?;

    let image_id =
        read_image_id("3fe354c3604a1b33f44a76bde3ee677e0f68a1777b0f74f7658c87b49e4c4c8a");

    info!("Calling finalize()...");
    agent_ref.finalize(root_receipt_bytes, journal_bytes, image_id?)?;

    info!("Finalize succeeded.");
    Ok(())
}

pub(crate) fn read_image_id(image_id: &str) -> Result<Digest> {
    Digest::from_hex(image_id).context("Failed to convert imageId file to digest from_hex")
}
