use crate::tasks::{convert, deserialize_obj, serialize_obj, Agent, ProveKeccakRequestLocal};
use anyhow::{bail, Context, Result};
use hex::FromHex;
use risc0_zkvm::recursion::identity_p254;
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{
    get_prover_server, seal_to_json, Assumption, AssumptionReceipt, Digest,
    Groth16ProofJson, Groth16Receipt, Groth16ReceiptVerifierParameters, Groth16Seal, InnerReceipt, ProverOpts,
    ProverServer, Receipt, ReceiptClaim, SuccinctReceipt, Unknown, VerifierContext,
};
use std::collections::HashMap;
use std::fs::File;
use std::io::Cursor;
use std::rc::Rc;
use tempfile::tempdir;
use tracing::info;

pub struct RiscZeroAgent {
    pub prover: Option<Rc<dyn ProverServer>>,
    pub verifier_ctx: VerifierContext,
}

impl RiscZeroAgent {
    pub fn new() -> Result<Self> {
        let verifier_ctx = VerifierContext::default();

        let opts = ProverOpts::default().with_segment_po2_max(25);
        let prover = get_prover_server(&opts).context("Failed to initialize prover server")?;

        Ok(Self {
            prover: Some(prover),
            verifier_ctx,
        })
    }
}

impl Agent for RiscZeroAgent {
    fn execute(&self, _data: Vec<u8>) -> Result<Vec<u8>> {
        bail!("RiscZeroTask::execute is not supported in this context");
    }

    fn prove(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        if input.is_empty() {
            bail!("prove input is empty");
        }

        let segment = deserialize_obj(&input).context("Failed to deserialize segment")?;

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

        if input.is_empty() {
            bail!("join input is empty");
        }

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

    fn keccak(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("RiscZeroTask::keccak()");

        if input.is_empty() {
            bail!("keccak input is empty");
        }

        let prove_keccak_request_local: ProveKeccakRequestLocal =
            deserialize_obj(&input).context("Failed to deserialize keccak request")?;

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

        if input.is_empty() {
            bail!("union input is empty");
        }

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

        if input.is_empty() {
            bail!("resolve input is empty");
        }

        let inputs: Vec<Vec<u8>> = serde_json::from_slice(&input)
            .context("Failed to parse input as Vec<Vec<u8>> for resolve")?;

        if inputs.len() != 3 {
            bail!(
                "Expected exactly three inputs for resolve, got {}",
                inputs.len()
            )
        }

        let mut root: SuccinctReceipt<ReceiptClaim> =
            deserialize_obj(&inputs[0]).context("Failed to deserialize root receipt")?;

        let union: Option<SuccinctReceipt<Unknown>> =
            deserialize_obj(&inputs[1]).context("Failed to deserialize union receipt")?;

        let pairs: Vec<(Assumption, AssumptionReceipt)> =
            deserialize_obj(&inputs[2]).context("Failed to deserialize assumptions")?;

        let (_, session_assumption_receipts): (Vec<Assumption>, Vec<AssumptionReceipt>) =
            pairs.into_iter().unzip();

        let assumption_receipt_map: HashMap<String, SuccinctReceipt<Unknown>> = HashMap::new();

        info!(
            "Loaded {} assumption receipts",
            session_assumption_receipts.len()
        );

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

        if input.is_empty() {
            bail!("finalize input is empty");
        }

        let inputs: Vec<Vec<u8>> = serde_json::from_slice(&input)
            .context("Failed to parse input as Vec<Vec<u8>> for finalize")?;

        if inputs.len() != 3 {
            bail!(
                "Expected exactly three inputs for finalize, got {}",
                inputs.len()
            )
        }

        let root: SuccinctReceipt<ReceiptClaim> =
            deserialize_obj(&inputs[0]).context("Failed to deserialize root receipt")?;
        let journal: Vec<u8> = inputs[1].clone();
        let image_id: String =
            deserialize_obj(&inputs[2]).context("Failed to deserialize image_id")?;

        let rollup_receipt = Receipt::new(InnerReceipt::Succinct(root), journal);

        let image_id = read_image_id(&*image_id)?;
        rollup_receipt
            .verify(image_id)
            .context("Receipt verification failed")?;

        serialize_obj(&rollup_receipt).context("Failed to serialize rollup receipt")
    }

    fn prepare_snark(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("RiscZeroTask::prepare_snark()");

        if input.is_empty() {
            bail!("prepare_snark input is empty");
        }

        let work_dir = tempdir()?.keep();

        let receipt: Receipt = deserialize_obj(&input)?;

        let succinct_receipt = receipt.inner.succinct()?;

        info!("start identity_p254");
        let receipt_ident = identity_p254(succinct_receipt).context("identity predicate failed")?;

        let seal_bytes = receipt_ident.get_seal_bytes();
        info!("Running seal-to-json");

        let seal_path = work_dir.join("input.json");
        let seal_json = File::create(&seal_path)?;
        let mut seal_reader = Cursor::new(&seal_bytes);
        seal_to_json(&mut seal_reader, &seal_json)?;

        let result_bytes = serialize_obj(&seal_path.to_string_lossy().to_string())?;

        info!("Seal file created at: {:?}", seal_path);
        info!("prepare_snark completed successfully");

        Ok(result_bytes)
    }

    fn get_snark_receipt(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("RiscZeroTask::get_snark_receipt()");

        if input.is_empty() {
            bail!("get_snark_receipt input is empty");
        }

        let inputs: Vec<Vec<u8>> =
            serde_json::from_slice(&input).context("Failed to parse input as Vec<Vec<u8>>")?;

        if inputs.len() != 2 {
            bail!(
                "Expected exactly two inputs for snark, got {}",
                inputs.len()
            );
        }

        let stark_receipt: Receipt =
            deserialize_obj(&inputs[0]).context("Failed to parse stark_receipt")?;

        let proof_json: Groth16ProofJson =
            deserialize_obj(&inputs[1]).context("Failed to parse input JSON")?;

        let seal: Groth16Seal = proof_json
            .try_into()
            .context("Failed to convert proof JSON to Groth16Seal")?;

        let snark_receipt = Groth16Receipt::new(
            seal.to_vec(),
            stark_receipt.claim()?,
            Groth16ReceiptVerifierParameters::default().digest(),
        );

        let snark_receipt = Receipt::new(
            InnerReceipt::Groth16(snark_receipt),
            stark_receipt.journal.bytes,
        );

        let serialized =
            serialize_obj(&snark_receipt).context("Failed to serialize SNARK receipt")?;

        info!(
            "SNARK receipt created successfully ({} bytes)",
            serialized.len()
        );

        Ok(serialized)
    }
}
#[cfg(test)]
mod tests {
    use crate::tasks::{
        deserialize_obj, serialize_obj, setup_agent_and_metadata_dir, Agent, FinalizeInput,
        ProveKeccakRequestLocal, ResolveInput, SerializableSession,
    };
    use anyhow::Context;
    use anyhow::{anyhow, Result};
    use risc0_zkvm::{Receipt, ReceiptClaim, SuccinctReceipt, Unknown};
    use std::{collections::VecDeque, fs, time::Instant};
    use tracing::info;

    #[test]
    fn test_keccak_on_pending_keccaks() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let path = metadata_dir.join("session/session_4_segments.json");
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

            let result = agent.keccak(bytes)?;
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

        let file_path = metadata_dir.join("keccak/keccak_receipts.json");
        let receipts_json = serde_json::to_string_pretty(&all_receipts)?;

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
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let path = metadata_dir.join("keccak/keccak_receipts.json");
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

                let union = agent.union(input).expect("Union failed");
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

        Ok(())
    }

    #[test]
    fn test_prove_all_segments() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let path = metadata_dir.join("session/session_4_segments.json");
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
            let lifted_bytes = agent.prove(bytes)?;

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

        info!(
            "All {} segment receipts generated in {:?}",
            segment_count,
            start.elapsed()
        );

        Ok(())
    }

    #[test]
    fn test_join_on_lifted_receipts() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let path = metadata_dir.join("lifted_receipts.json");
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

            let joined = agent.join(join_input).expect("Join failed");
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

        info!("Root receipt written to metadata/root_receipt.json");

        Ok(())
    }

    #[test]
    fn test_resolve_on_session() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let session_path = metadata_dir.join("session/session_4_segments.json");
        info!("Loading session from: {:?}", session_path);
        let session_json = fs::read_to_string(&session_path)?;
        let session: SerializableSession = serde_json::from_str(&session_json)?;

        let root_path = metadata_dir.join("root_receipt.json");
        info!("Loading root receipt from: {:?}", root_path);
        let root_json = fs::read_to_string(&root_path)?;
        let root_receipt: SuccinctReceipt<ReceiptClaim> = serde_json::from_str(&root_json)?;
        assert!(
            root_receipt.claim.as_value().is_ok(),
            "Root receipt should have a claim"
        );

        info!("Loaded root receipt");

        let union_path = metadata_dir.join("keccak/unioned_receipt.json");
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
        let resolved = agent.resolve(input_bytes)?;
        assert!(!resolved.is_empty(), "Resolved result should not be empty");

        info!("Resolve completed in {:?}", start_resolve.elapsed());

        let resolved_receipt: SuccinctReceipt<ReceiptClaim> = deserialize_obj(&resolved)?;
        assert!(
            resolved_receipt.claim.as_value().is_ok(),
            "Resolved receipt should have a claim"
        );

        let resolved_json = serde_json::to_string_pretty(&resolved_receipt)?;

        info!("Resolved receipt written to metadata/resolved_receipt.json");

        Ok(())
    }

    #[test]
    fn test_finalize_on_session() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let root_path = metadata_dir.join("resolved_receipt.json");
        info!("Loading resolved receipt from: {:?}", root_path);
        let root_json = fs::read_to_string(&root_path)?;
        let root_receipt: SuccinctReceipt<ReceiptClaim> = serde_json::from_str(&root_json)?;
        assert!(
            root_receipt.claim.as_value().is_ok(),
            "Root receipt should have a claim"
        );

        info!("Resolved receipt loaded");

        let session_path = metadata_dir.join("session/session_4_segments.json");
        info!("Loading session from: {:?}", session_path);
        let session_json = fs::read_to_string(&session_path)?;
        let session: SerializableSession = serde_json::from_str(&session_json)?;

        let journal_bytes = session
            .journal
            .as_ref()
            .map(|j| j.bytes.clone())
            .ok_or_else(|| anyhow!("journal is missing"))?;

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
        let stark_receipt = agent.finalize(input_bytes)?;
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

        info!("Final STARK receipt written to metadata/result/stark.json");

        Ok(())
    }

    #[tokio::test]
    async fn test_stark2snark() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let stark_path = metadata_dir.join("result/finalized_receipt.json");
        info!("Loading stark receipt from: {:?}", stark_path);

        let stark_receipt_bytes = fs::read(&stark_path)?;
        assert!(
            !stark_receipt_bytes.is_empty(),
            "Stark receipt bytes should not be empty"
        );

        let groth16_receipt = agent
            .get_snark_receipt(stark_receipt_bytes)
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

        Ok(())
    }

    #[test]
    fn test_prepare_snark() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let stark_path = metadata_dir.join("result/finalized_receipt.json");
        info!("Loading STARK receipt from: {:?}", stark_path);

        let stark_json = fs::read_to_string(&stark_path)?;
        let stark_receipt: Receipt = serde_json::from_str(&stark_json)?;
        assert!(
            stark_receipt.claim().is_ok(),
            "STARK receipt should have a claim"
        );

        info!("STARK receipt loaded successfully");

        let stark_receipt_bytes = serialize_obj(&stark_receipt)?;
        assert!(
            !stark_receipt_bytes.is_empty(),
            "STARK receipt bytes should not be empty"
        );

        info!(
            "STARK receipt serialized, size: {} bytes",
            stark_receipt_bytes.len()
        );

        let start_prepare = Instant::now();
        let prepare_result = agent.prepare_snark(stark_receipt_bytes)?;
        assert!(
            !prepare_result.is_empty(),
            "prepare_snark result should not be empty"
        );

        info!("prepare_snark completed in {:?}", start_prepare.elapsed());

        let prepare_result_str = String::from_utf8(prepare_result.clone())?;
        let prepare_json: serde_json::Value = serde_json::from_str(&prepare_result_str)?;

        assert!(
            prepare_json.get("seal_path").is_some(),
            "prepare_snark result should contain seal_path"
        );
        assert!(
            prepare_json.get("receipt_claim").is_some(),
            "prepare_snark result should contain receipt_claim"
        );
        assert!(
            prepare_json.get("journal_bytes").is_some(),
            "prepare_snark result should contain journal_bytes"
        );

        let seal_path = prepare_json["seal_path"].as_str().unwrap();
        assert!(
            fs::metadata(seal_path).is_ok(),
            "Seal file should exist at: {}",
            seal_path
        );

        let seal_content = fs::read_to_string(seal_path)?;
        assert!(!seal_content.is_empty(), "Seal file should not be empty");

        let journal_bytes = prepare_json["journal_bytes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect::<Vec<u8>>();

        assert_eq!(
            journal_bytes, stark_receipt.journal.bytes,
            "Journal bytes should match original STARK receipt"
        );

        info!("prepare_snark test completed successfully");
        info!("Seal file created at: {}", seal_path);
        info!("Seal file size: {} bytes", seal_content.len());

        Ok(())
    }
}

pub(crate) fn read_image_id(image_id: &str) -> Result<Digest> {
    Digest::from_hex(image_id).context("Failed to convert imageId file to digest from_hex")
}
