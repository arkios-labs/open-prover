use crate::io::input::env::EnvProvider;
use crate::tasks::factory::get_agent;
use crate::tasks::{
    Agent, FinalizeInput, ProveKeccakRequestLocal, ResolveInput, SerializableSession, convert,
    deserialize_obj, serialize_obj,
};
use anyhow::{Context, bail};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use hex::FromHex;
use nix::{sys::stat, unistd};
use risc0_zkvm::recursion::identity_p254;
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{
    AssumptionReceipt, Digest, Groth16ProofJson, Groth16Receipt, Groth16ReceiptVerifierParameters,
    Groth16Seal, InnerAssumptionReceipt, InnerReceipt, ProverOpts, ProverServer, Receipt,
    ReceiptClaim, SuccinctReceipt, Unknown, VerifierContext, get_prover_server, seal_to_json,
};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::{env, fs, rc::Rc};
use tempfile::tempdir;
use tokio::process::Command;
use tracing::{info, warn};

const APP_DIR: &str = "";
const WITNESS_FILE: &str = "output.wtns";
const PROOF_FILE: &str = "proof.json";
const IDENT_FILE: &str = "ident.json";
const STARK_VERIFY_BIN: &str = "stark_verify";
const PROVER_BIN: &str = "prover";
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

#[async_trait::async_trait(?Send)]
impl Agent for RiscZeroAgent {
    fn execute(&self, _data: Vec<u8>) -> Result<Vec<u8>> {
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

    fn join(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("RiscZeroTask::join()");

        let receipts: Vec<Vec<u8>> =
            serde_json::from_slice(&input).context("Failed to parse input as Vec<Vec<u8>>")?;

        if receipts.len() != 2 {
            bail!(
                "Expected exactly two receipts for join, got {}",
                receipts.len()
            );
        }

        let left_receipt =
            deserialize_obj(&receipts[0]).context("Failed to deserialize left receipt")?;
        let right_receipt =
            deserialize_obj(&receipts[1]).context("Failed to deserialize right receipt")?;

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

    fn union(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("RiscZeroTask::union()");

        let receipts: Vec<Vec<u8>> = serde_json::from_slice(&input)
            .context("Failed to parse input as Vec<Vec<u8>> for union")?;

        if receipts.len() != 2 {
            bail!(
                "Expected exactly two receipts for union, got {}",
                receipts.len()
            );
        }

        let left_receipt =
            deserialize_obj(&receipts[0]).context("Failed to deserialize left receipt")?;
        let right_receipt =
            deserialize_obj(&receipts[1]).context("Failed to deserialize right receipt")?;

        let unioned = self
            .prover
            .as_ref()
            .context("Missing prover from union task")?
            .union(&left_receipt, &right_receipt)
            .context("Failed to union on left/right receipt")?
            .into_unknown();

        let serialized = serialize_obj(&unioned).context("Failed to serialize union receipt")?;

        Ok(serialized)
    }

    fn resolve(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("RiscZeroTask::resolve()");

        let ResolveInput {
            mut root,
            union,
            assumptions,
        } = serde_json::from_slice(&input).context("Failed to parse ResolveInput JSON")?;

        let mut assumption_receipt_map = HashMap::new();

        let assumption_receipts: Vec<SuccinctReceipt<Unknown>> = assumptions
            .iter()
            .filter_map(|(_, receipt)| match receipt {
                AssumptionReceipt::Proven(InnerAssumptionReceipt::Succinct(r)) => Some(r.clone()),
                _ => None,
            })
            .collect();
        info!("Loaded {} assumption receipts", assumption_receipts.len());

        for receipt in assumption_receipts {
            let digest_str = receipt.claim.digest().to_string();
            assumption_receipt_map.insert(digest_str, receipt);
        }

        let mut assumptions_len: u64 = 0;

        if root.claim.clone().as_value()?.output.is_some() {
            if let Some(guest_output) = root.claim.clone().as_value()?.output.as_value()? {
                if !guest_output.assumptions.is_empty() {
                    let assumptions_list = guest_output
                        .assumptions
                        .as_value()
                        .context("Failed to unwrap assumptions of guest output")?;

                    assumptions_len = assumptions_list
                        .len()
                        .try_into()
                        .context("Failed to convert assumption length")?;

                    let mut union_claim = String::new();
                    if let Some(union_receipt) = union {
                        union_claim = union_receipt.claim.digest().to_string();
                        info!("Resolving union claim digest: {union_claim}");

                        root = self
                            .prover
                            .as_ref()
                            .context("Missing prover from resolve task")?
                            .resolve(&root, &union_receipt)
                            .context("Failed to resolve union receipt")?;
                    }

                    for assumption in &assumptions_list.0 {
                        let assumption_claim = assumption.as_value()?.claim.to_string();
                        if assumption_claim == union_claim {
                            info!("Skipping already resolved union claim: {union_claim}");
                            continue;
                        }

                        let assumption_receipt = assumption_receipt_map
                            .get(&assumption_claim)
                            .with_context(|| {
                                format!("Corroborating receipt not found: {}", assumption_claim)
                            })?;

                        root = self
                            .prover
                            .as_ref()
                            .context("Missing prover from resolve task")?
                            .resolve(&root, assumption_receipt)
                            .context("Failed to resolve assumption receipt")?;
                    }

                    info!("Resolve complete");
                }
            }
        }

        info!("Resolve operation completed successfully: {assumptions_len}");

        let serialized = serialize_obj(&root).context("Failed to serialize conditional receipt")?;
        Ok(serialized)
    }

    fn finalize(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("RiscZeroTask::finalize()");

        let FinalizeInput {
            root,
            journal,
            image_id,
        } = serde_json::from_slice(&input).context("Failed to parse FinalizeInput JSON")?;

        let journal: Vec<u8> = if journal.is_empty() {
            warn!("Journal was empty, using default empty Vec");
            vec![]
        } else {
            journal
        };

        let rollup_receipt = Receipt::new(InnerReceipt::Succinct(root), journal);

        let image_id = read_image_id(&*image_id)?;
        rollup_receipt
            .verify(image_id)
            .context("Receipt verification failed")?;

        serialize_obj(&rollup_receipt).context("Failed to serialize rollup receipt")
    }

    async fn stark2snark(&self, rollup_receipt: Vec<u8>) -> Result<Vec<u8>> {
        info!("RiscZeroTask::stark2snark()");

        let work_dir = tempdir().context("Failed to create tmpdir")?;

        // // 1. Deserialize rollup receipt
        let receipt: Receipt = deserialize_obj(&rollup_receipt)?;

        // // 2. Get succinct receipt
        let succinct_receipt = receipt.inner.succinct()?;

        // 3. generate identity predicate
        let receipt_ident = identity_p254(succinct_receipt).context("identity predicate failed")?;

        // 4. Convert seal to JSON
        let seal_bytes = receipt_ident.get_seal_bytes();
        info!("Running seal-to-json");

        let seal_path = work_dir.path().join("input.json");
        let seal_json = File::create(&seal_path)?;
        let mut seal_reader = Cursor::new(&seal_bytes);
        seal_to_json(&mut seal_reader, &seal_json)?;

        // 5. Prepare to run stark_verify
        let app_path = Path::new("./");
        if !app_path.exists() {
            bail!("Missing app path");
        }
        info!("Running stark_verify");
        let witness_file = work_dir.path().join(WITNESS_FILE);

        // Create a named pipe for the witness data so that the prover can start before
        // the witness generation is complete.

        unistd::mkfifo(&witness_file, stat::Mode::S_IRWXU).context("Failed to create fifo")?;

        // Spawn stark_verify process
        let mut wit_gen = Command::new(app_path.join(STARK_VERIFY_BIN))
            .arg(&seal_path)
            .arg(&witness_file)
            .spawn()?;

        info!("Running gnark");
        let cs_file = app_path.join("stark_verify.cs");
        let pk_file = app_path.join("stark_verify_final.pk.dmp");
        let proof_file = work_dir.path().join(PROOF_FILE);

        // Spawn prover process
        let mut prover = Command::new(app_path.join(PROVER_BIN))
            .arg(cs_file)
            .arg(pk_file)
            .arg(witness_file)
            .arg(&proof_file)
            .spawn()?;

        // Wait for stark_verify to complete
        info!("Running prover");
        match wit_gen.wait().await {
            // Make sure the prover is always killed, otherwise it will wait forever
            Err(err) => {
                prover.kill().await.expect("Failed to kill prover process");
                bail!(err);
            }
            Ok(status) if !status.success() => {
                prover.kill().await.expect("Failed to kill prover process");
                bail!("Failed to run stark_verify");
            }
            _ => {}
        }

        // stark_verify completed successfully, now wait for prover
        if !prover.wait().await?.success() {
            bail!("Failed to run gnark prover");
        }

        info!("Parsing proof");
        let mut proof = File::open(proof_file)?;
        let mut contents = String::new();
        proof.read_to_string(&mut contents)?;

        let proof_json: Groth16ProofJson = serde_json::from_str(&contents)?;
        let seal: Groth16Seal = proof_json.try_into()?;

        let snark_receipt = Groth16Receipt::new(
            seal.to_vec(),
            receipt.claim().context("Receipt missing claim")?.clone(),
            Groth16ReceiptVerifierParameters::default().digest(),
        );

        let snark_receipt =
            Receipt::new(InnerReceipt::Groth16(snark_receipt), receipt.journal.bytes);

        let serialized = serialize_obj(&snark_receipt).context("Failed to serialize receipt")?;

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

    let agent_type = env::var("AGENT_TYPE").unwrap_or_else(|_| "r0".to_string());

    let input = Box::new(EnvProvider { key: agent_type });
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
        assert!(
            !result.is_empty(),
            "Keccak result should not be empty for request {}",
            i
        );

        let receipt: SuccinctReceipt<Unknown> =
            deserialize_obj(&result).context("Failed to deserialize keccak receipt")?;

        assert!(
            receipt.claim.as_value().is_ok(),
            "Keccak receipt should have a claim"
        );

        info!("Keccak [{}] result size: {}", i, result.len());
        all_receipts.push(receipt);
    }

    assert_eq!(
        all_receipts.len(),
        keccak_count,
        "Number of receipts should match keccak count"
    );

    let file_path = PathBuf::from("metadata/keccak/keccak_receipts.json");
    let receipts_json = serde_json::to_string_pretty(&all_receipts)?;
    fs::write(&file_path, receipts_json)
        .with_context(|| format!("Failed to write receipts to {:?}", file_path))?;

    assert!(
        fs::metadata(&file_path).is_ok(),
        "Keccak receipts file should be created"
    );

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

    let agent_type = env::var("AGENT_TYPE").unwrap_or_else(|_| "r0".to_string());

    let input = Box::new(EnvProvider { key: agent_type });
    let agent = get_agent(input)?;
    let agent_ref: &dyn Agent = agent.as_ref();

    let path = env::current_dir()?.join("metadata/keccak/keccak_receipts.json");
    info!("Loading keccak receipts from: {:?}", path);

    let json = fs::read_to_string(&path)?;
    let keccak_receipts: Vec<SuccinctReceipt<Unknown>> = serde_json::from_str(&json)?;
    let receipt_count = keccak_receipts.len();
    assert!(receipt_count > 0, "No keccak receipts found");

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

            let input =
                serde_json::to_vec(&vec![left_serialized.clone(), right_serialized.clone()])
                    .expect("Failed to serialize union input");

            let union = agent_ref.union(input).expect("Union failed");
            assert!(!union.is_empty(), "Union result should not be empty");

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
    assert!(
        !final_result.is_empty(),
        "Final union result should not be empty"
    );

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

    assert!(
        fs::metadata(&output_path).is_ok(),
        "Unioned receipt file should be created"
    );

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

    let agent_type = env::var("AGENT_TYPE").unwrap_or_else(|_| "r0".to_string());

    let input = Box::new(EnvProvider { key: agent_type });
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

        assert!(
            !lifted_bytes.is_empty(),
            "Lifted bytes should not be empty for segment {}",
            i
        );

        info!("Segment [{}] proof size: {}", i, lifted_bytes.len());

        let lifted_receipt: SuccinctReceipt<ReceiptClaim> = deserialize_obj(&lifted_bytes)
            .context(format!("Failed to deserialize receipt for segment {}", i))?;

        assert!(
            lifted_receipt.claim.as_value().is_ok(),
            "Lifted receipt should have a claim"
        );

        all_receipts.push(lifted_receipt);
    }

    assert_eq!(
        all_receipts.len(),
        segment_count,
        "Number of receipts should match segment count"
    );

    let output_path = env::current_dir()?.join("metadata/lifted_receipts.json");
    let output_json = serde_json::to_string_pretty(&all_receipts)?;
    fs::write(&output_path, output_json).context("Failed to write lifted receipts JSON")?;

    assert!(
        fs::metadata(&output_path).is_ok(),
        "Lifted receipts file should be created"
    );

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

    let agent_type = env::var("AGENT_TYPE").unwrap_or_else(|_| "r0".to_string());

    let input = Box::new(EnvProvider { key: agent_type });
    let agent = get_agent(input)?;
    let agent_ref: &dyn Agent = agent.as_ref();

    let path = env::current_dir()?.join("metadata/lifted_receipts.json");
    info!("Loading lifted receipts from: {:?}", path);
    let json = fs::read_to_string(&path)?;

    let lifted_receipts: Vec<SuccinctReceipt<ReceiptClaim>> = serde_json::from_str(&json)?;
    let receipt_count = lifted_receipts.len();
    assert!(receipt_count > 0, "No lifted receipts found");

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

        let join_input = serde_json::to_vec(&vec![left.clone(), right.clone()])
            .expect("Failed to serialize join input");

        let joined = agent_ref.join(join_input).expect("Join failed");
        assert!(!joined.is_empty(), "Joined result should not be empty");
        assert!(
            joined.len() > left.len() || joined.len() > right.len(),
            "Joined result should be larger than individual receipts"
        );

        queue.push_back(joined);
        info!(
            "Join successful (size: {}) | Remaining queue: {}",
            queue.back().unwrap().len(),
            queue.len()
        );
    }

    let final_result = queue.pop_front().unwrap();
    assert!(
        !final_result.is_empty(),
        "Final joined result should not be empty"
    );

    let elapsed = start.elapsed();

    info!(
        "Join complete in {:?} | Final joined result size: {} | Total input receipts: {}",
        elapsed,
        final_result.len(),
        receipt_count
    );

    let root_receipt: SuccinctReceipt<ReceiptClaim> = deserialize_obj(&final_result)?;
    assert!(
        root_receipt.claim.as_value().is_ok(),
        "Root receipt should have a claim"
    );

    let root_json = serde_json::to_string_pretty(&root_receipt)?;
    fs::write("metadata/root_receipt.json", root_json)?;

    assert!(
        fs::metadata("metadata/root_receipt.json").is_ok(),
        "Root receipt file should be created"
    );

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

    let agent_type = env::var("AGENT_TYPE").unwrap_or_else(|_| "r0".to_string());

    let input = Box::new(EnvProvider { key: agent_type });
    let agent = get_agent(input)?;
    let agent_ref: &dyn Agent = agent.as_ref();

    let session_path = env::current_dir()?.join("metadata/session/session_4_segments.json");
    info!("Loading session from: {:?}", session_path);
    let session_json = fs::read_to_string(&session_path)?;
    let session: SerializableSession = serde_json::from_str(&session_json)?;

    let root_path = env::current_dir()?.join("metadata/root_receipt.json");
    info!("Loading root receipt from: {:?}", root_path);
    let root_json = fs::read_to_string(&root_path)?;
    let root_receipt: SuccinctReceipt<ReceiptClaim> = serde_json::from_str(&root_json)?;
    assert!(
        root_receipt.claim.as_value().is_ok(),
        "Root receipt should have a claim"
    );

    info!("Loaded root receipt");

    let union_path = env::current_dir()?.join("metadata/keccak/unioned_receipt.json");
    info!("Loading unioned receipt from: {:?}", union_path);
    let union_json = fs::read_to_string(&union_path)?;
    let union_receipt: SuccinctReceipt<Unknown> = serde_json::from_str(&union_json)?;

    info!("Loaded unioned receipt");

    let resolve_input = ResolveInput {
        root: root_receipt,
        union: Some(union_receipt),
        assumptions: session.assumptions,
    };

    let input_bytes = serde_json::to_vec(&resolve_input)?;
    info!("Serialized resolve input");

    info!("Calling resolve()...");
    let start_resolve = Instant::now();
    let resolved = agent_ref.resolve(input_bytes)?;
    assert!(!resolved.is_empty(), "Resolved result should not be empty");

    info!("Resolve completed in {:?}", start_resolve.elapsed());

    let resolved_receipt: SuccinctReceipt<ReceiptClaim> = deserialize_obj(&resolved)?;
    assert!(
        resolved_receipt.claim.as_value().is_ok(),
        "Resolved receipt should have a claim"
    );

    let resolved_json = serde_json::to_string_pretty(&resolved_receipt)?;
    fs::write("metadata/resolved_receipt.json", resolved_json)?;

    assert!(
        fs::metadata("metadata/resolved_receipt.json").is_ok(),
        "Resolved receipt file should be created"
    );

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

    let agent_type = env::var("AGENT_TYPE").unwrap_or_else(|_| "r0".to_string());

    let input = Box::new(EnvProvider { key: agent_type });

    let agent = get_agent(input)?;
    let agent_ref: &dyn Agent = agent.as_ref();

    let root_path = env::current_dir()?.join("metadata/resolved_receipt.json");
    info!("Loading resolved receipt from: {:?}", root_path);
    let root_json = fs::read_to_string(&root_path)?;
    let root_receipt: SuccinctReceipt<ReceiptClaim> = serde_json::from_str(&root_json)?;
    assert!(
        root_receipt.claim.as_value().is_ok(),
        "Root receipt should have a claim"
    );

    info!("Resolved receipt loaded");

    let session_path = env::current_dir()?.join("metadata/session/session_4_segments.json");
    info!("Loading session from: {:?}", session_path);
    let session_json = fs::read_to_string(&session_path)?;
    let session: SerializableSession = serde_json::from_str(&session_json)?;

    let journal_bytes = session
        .journal
        .as_ref()
        .map(|j| j.bytes.clone())
        .ok_or_else(|| anyhow!("journal is missing"))?;
    assert!(!journal_bytes.is_empty(), "Journal should not be empty");

    info!("Journal loaded, size: {}", journal_bytes.len());

    let image_id = "3fe354c3604a1b33f44a76bde3ee677e0f68a1777b0f74f7658c87b49e4c4c8a";

    let finalize_input = FinalizeInput {
        root: root_receipt,
        journal: journal_bytes,
        image_id: image_id.to_string(),
    };
    info!("Image ID loaded: {}", image_id.to_string());

    let input_bytes = serde_json::to_vec(&finalize_input)?;
    info!("Finalize input serialized");

    let stark_finalize = Instant::now();
    let stark_receipt = agent_ref.finalize(input_bytes)?;
    assert!(
        !stark_receipt.is_empty(),
        "Stark receipt should not be empty"
    );

    info!("Finalize succeeded in {:?}", stark_finalize.elapsed());

    let finalized_receipt: Receipt = deserialize_obj(&stark_receipt)?;
    assert!(
        finalized_receipt.claim().is_ok(),
        "Finalized receipt should have a claim"
    );

    let finalized_json = serde_json::to_string_pretty(&finalized_receipt)?;
    fs::write("metadata/result/finalized_receipt.json", finalized_json)?;

    assert!(
        fs::metadata("metadata/result/finalized_receipt.json").is_ok(),
        "Finalized receipt file should be created"
    );

    info!("Final STARK receipt written to metadata/result/stark.json");

    Ok(())
}

#[tokio::test]
async fn test_stark2snark() -> Result<()> {
    use std::time::Instant;
    use std::{env, fs};
    use tracing::info;

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let agent_type = env::var("AGENT_TYPE").unwrap_or_else(|_| "r0".to_string());

    let input = Box::new(EnvProvider { key: agent_type });

    let agent = get_agent(input)?;
    let agent_ref: &dyn Agent = agent.as_ref();

    let stark_path = env::current_dir()?.join("metadata/result/finalized_receipt.json");
    info!("Loading stark receipt from: {:?}", stark_path);

    let stark_receipt_bytes = fs::read(&stark_path)?;
    assert!(
        !stark_receipt_bytes.is_empty(),
        "Stark receipt bytes should not be empty"
    );

    let groth16_receipt = agent_ref
        .stark2snark(stark_receipt_bytes)
        .await
        .expect("stark2snark conversion failed: could not convert stark receipt to snark");

    assert!(
        !groth16_receipt.is_empty(),
        "Groth16 receipt should not be empty"
    );

    let groth16_receipt: Receipt = deserialize_obj(&groth16_receipt)?;
    assert!(
        groth16_receipt.claim().is_ok(),
        "Groth16 receipt should have a claim"
    );

    let groth16_json = serde_json::to_string_pretty(&groth16_receipt)?;
    fs::write("metadata/result/groth16.json", groth16_json)?;

    assert!(
        fs::metadata("metadata/result/groth16.json").is_ok(),
        "Groth16 receipt file should be created"
    );

    Ok(())
}
pub(crate) fn read_image_id(image_id: &str) -> Result<Digest> {
    Digest::from_hex(image_id).context("Failed to convert imageId file to digest from_hex")
}
