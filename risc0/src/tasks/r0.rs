use crate::tasks::{Agent, ProveKeccakRequestLocal, convert, deserialize_obj, serialize_obj};
use anyhow::{Context, Result, bail};
use hex::FromHex;
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{
    Assumption, AssumptionReceipt, Digest, InnerReceipt, ProverOpts, ProverServer, Receipt,
    ReceiptClaim, SuccinctReceipt, Unknown, VerifierContext, get_prover_server,
};
use std::collections::HashMap;
use std::rc::Rc;
use std::time::Instant;
use tracing::info;

pub struct RiscZeroAgent {
    pub prover: Rc<dyn ProverServer>,
    pub verifier_ctx: VerifierContext,
}

impl RiscZeroAgent {
    pub fn new() -> Result<Self> {
        let verifier_ctx = VerifierContext::default();

        let opts = ProverOpts::default().with_segment_po2_max(25);
        let prover = get_prover_server(&opts).context("Failed to initialize prover server")?;

        Ok(Self { prover, verifier_ctx })
    }
}

impl Agent for RiscZeroAgent {
    fn prove(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::prove()");
        let start_time = Instant::now();

        if input.is_empty() {
            bail!("prove input is empty");
        }

        let segment = deserialize_obj(&input).context("Failed to deserialize segment")?;

        let segment_receipt = self
            .prover
            .prove_segment(&self.verifier_ctx, &segment)
            .context("Failed to prove segment")?;

        let lift_receipt =
            self.prover.lift(&segment_receipt).with_context(|| "Failed to lift".to_string())?;

        let serialized = serialize_obj(&lift_receipt).context("Failed to serialize")?;
        let elapsed = start_time.elapsed();
        info!("Agent::prove() took {elapsed:?}");
        Ok(serialized)
    }

    fn join(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::join()");
        let start_time = Instant::now();

        if input.is_empty() {
            bail!("join input is empty");
        }

        let receipts: Vec<Vec<u8>> =
            serde_json::from_slice(&input).context("Failed to parse input as Vec<Vec<u8>>")?;

        if receipts.len() != 2 {
            bail!("Expected exactly two receipts for join, got {}", receipts.len());
        }

        let left_receipt =
            deserialize_obj(&receipts[0]).context("Failed to deserialize left receipt")?;
        let right_receipt =
            deserialize_obj(&receipts[1]).context("Failed to deserialize right receipt")?;

        let joined = self.prover.join(&left_receipt, &right_receipt)?;

        let serialized = serialize_obj(&joined).context("Failed to serialize")?;
        let elapsed = start_time.elapsed();
        info!("Agent::join() took {elapsed:?}");
        Ok(serialized)
    }

    fn keccak(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::keccak()");
        let start_time = Instant::now();

        if input.is_empty() {
            bail!("keccak input is empty");
        }

        let prove_keccak_request_local: ProveKeccakRequestLocal =
            deserialize_obj(&input).context("Failed to deserialize keccak request")?;

        // Conversion is required because the library's `ProveKeccakRequest` type doesn't support deserialization
        let prove_keccak_request = convert(prove_keccak_request_local);

        let keccak_receipt = self.prover.prove_keccak(&prove_keccak_request);

        let serialized = serialize_obj(&keccak_receipt?).context("Failed to serialize")?;
        let elapsed = start_time.elapsed();
        info!("Agent::keccak() took {elapsed:?}");
        Ok(serialized)
    }

    fn union(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::union()");
        let start_time = Instant::now();

        if input.is_empty() {
            bail!("union input is empty");
        }

        let receipts: Vec<Vec<u8>> = serde_json::from_slice(&input)
            .context("Failed to parse input as Vec<Vec<u8>> for union")?;

        if receipts.len() != 2 {
            bail!("Expected exactly two receipts for union, got {}", receipts.len());
        }

        let left_receipt =
            deserialize_obj(&receipts[0]).context("Failed to deserialize left receipt")?;
        let right_receipt =
            deserialize_obj(&receipts[1]).context("Failed to deserialize right receipt")?;

        let unioned = self
            .prover
            .union(&left_receipt, &right_receipt)
            .context("Failed to union on left/right receipt")?
            .into_unknown();

        let serialized = serialize_obj(&unioned).context("Failed to serialize union receipt")?;
        let elapsed = start_time.elapsed();
        info!("Agent::union() took {elapsed:?}");
        Ok(serialized)
    }

    fn resolve(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::resolve()");
        let start_time = Instant::now();

        if input.is_empty() {
            bail!("resolve input is empty");
        }

        let inputs: Vec<Vec<u8>> = serde_json::from_slice(&input)
            .context("Failed to parse input as Vec<Vec<u8>> for resolve")?;

        if inputs.len() != 3 {
            bail!("Expected exactly three inputs for resolve, got {}", inputs.len())
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

        info!("Loaded {} assumption receipts", session_assumption_receipts.len());

        let mut assumptions_len: u64 = 0;

        if root.claim.clone().as_value()?.output.is_some()
            && let Some(guest_output) = root.claim.clone().as_value()?.output.as_value()?
            && !guest_output.assumptions.is_empty()
        {
            let assumptions_list = guest_output
                .assumptions
                .as_value()
                .context("Failed to unwrap assumptions of guest output")?;

            assumptions_len =
                assumptions_list.len().try_into().context("Failed to convert assumption length")?;

            let mut union_claim = String::new();
            if let Some(union_receipt) = union {
                union_claim = union_receipt.claim.digest().to_string();
                info!("Resolving union claim digest: {union_claim}");

                root = self
                    .prover
                    .resolve(&root, &union_receipt)
                    .context("Failed to resolve union receipt")?;
            }

            for assumption in &assumptions_list.0 {
                let assumption_claim = assumption.as_value()?.claim.to_string();
                if assumption_claim == union_claim {
                    info!("Skipping already resolved union claim: {union_claim}");
                    continue;
                }

                let assumption_receipt =
                    assumption_receipt_map.get(&assumption_claim).with_context(|| {
                        format!("Corroborating receipt not found: {}", assumption_claim)
                    })?;

                root = self
                    .prover
                    .resolve(&root, assumption_receipt)
                    .context("Failed to resolve assumption receipt")?;
            }

            info!("Resolve complete");
        }

        info!("Resolve operation completed successfully: {assumptions_len}");

        let serialized = serialize_obj(&root).context("Failed to serialize conditional receipt")?;
        let elapsed = start_time.elapsed();
        info!("Agent::resolve() took {elapsed:?}");
        Ok(serialized)
    }

    fn finalize(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::finalize()");
        let start_time = Instant::now();

        if input.is_empty() {
            bail!("finalize input is empty");
        }

        let inputs: Vec<Vec<u8>> = serde_json::from_slice(&input)
            .context("Failed to parse input as Vec<Vec<u8>> for finalize")?;

        if inputs.len() != 3 {
            bail!("Expected exactly three inputs for finalize, got {}", inputs.len())
        }

        let root: SuccinctReceipt<ReceiptClaim> =
            deserialize_obj(&inputs[0]).context("Failed to deserialize root receipt")?;
        let journal: Vec<u8> = inputs[1].clone();
        let image_id: String =
            deserialize_obj(&inputs[2]).context("Failed to deserialize image_id")?;

        let rollup_receipt = Receipt::new(InnerReceipt::Succinct(root), journal);

        let image_id = read_image_id(&image_id)?;
        rollup_receipt.verify(image_id).context("Receipt verification failed")?;

        let elapsed = start_time.elapsed();
        info!("Agent::finalize() took {elapsed:?}");
        let serialized = serialize_obj(&rollup_receipt).context("Failed to serialize receipt")?;
        Ok(serialized)
    }

    fn stark2snark(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::stark2snark()");
        let start_time = Instant::now();

        if input.is_empty() {
            bail!("get_snark_receipt input is empty");
        }

        let stark_receipt: Receipt =
            deserialize_obj(&input).context("Failed to parse stark_receipt")?;

        let opts = ProverOpts::groth16();
        // Implemented based on newly introduced logic in Bento.
        // (Ref: https://github.com/risc0/risc0/blob/b5b16f6/bento/crates/workflow/src/tasks/snark.rs#L29-L34)
        let snark_receipt = self
            .prover
            .compress(&opts, &stark_receipt)
            .context("Failed to compress stark receipt")?;

        let serialized =
            serialize_obj(&snark_receipt).context("Failed to serialize SNARK receipt")?;
        let elapsed = start_time.elapsed();
        info!("Agent::stark2snark() took {elapsed:?}");
        Ok(serialized)
    }
}
#[cfg(test)]
mod tests {
    use crate::tasks::{
        Agent, ProveKeccakRequestLocal, SerializableSession, deserialize_obj, serialize_obj,
        setup_agent_and_metadata_dir,
    };
    use anyhow::Context;
    use anyhow::{Result, anyhow};
    use common::serialization::bincode::{
        deserialize_from_bincode_bytes, serialize_to_bincode_bytes,
    };
    use risc0_zkvm::{Receipt, ReceiptClaim, SuccinctReceipt, Unknown};
    use std::{collections::VecDeque, fs};
    use tracing::info;

    #[test]
    fn test_prove_all_segments() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let session_path = metadata_dir.join("session/po2_19_segment_3_keccak_2_cycle_1420941.bin");
        info!("Loading session from: {session_path:?}");

        let session_serialized = fs::read(&session_path).context("Failed to read session file")?;
        let session: SerializableSession = deserialize_from_bincode_bytes(&session_serialized)
            .context("Failed to deserialize session")?;
        let segment_count = session.segments.len();
        assert!(segment_count > 0, "No segments found in session");

        info!("Found {segment_count} segments. Starting proof generation...",);
        let mut all_receipts = Vec::with_capacity(segment_count);

        for (i, segment) in session.segments.iter().enumerate() {
            let current_index = i + 1;
            info!("Proving segment [{current_index}/{segment_count}]");
            let bytes = serialize_obj(segment)?;
            let lifted_bytes = agent.prove(bytes)?;

            assert!(
                !lifted_bytes.is_empty(),
                "Lifted bytes should not be empty for segment {current_index}"
            );

            info!(
                "Segment [{current_index}] proof size: {proof_size}",
                proof_size = lifted_bytes.len()
            );

            let lifted_receipt: SuccinctReceipt<ReceiptClaim> = deserialize_obj(&lifted_bytes)
                .context(format!("Failed to deserialize receipt for segment {current_index}"))?;

            assert!(lifted_receipt.claim.as_value().is_ok(), "Lifted receipt should have a claim");

            all_receipts.push(lifted_receipt);
        }

        let receipts_serialized = serialize_to_bincode_bytes(&all_receipts)?;

        info!("prove result: ({size} bytes)", size = receipts_serialized.len());

        Ok(())
    }

    #[test]
    fn test_join_on_lifted_receipts() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let proof_path =
            metadata_dir.join("receipt/po2_19_segment_3_keccak_2_cycle_1420941_lifted_receipt.bin");
        info!("Loading lifted proof from: {proof_path:?}");
        let lifted_receipts = fs::read(&proof_path).context("Failed to read receipt file")?;

        let lifted_receipts: Vec<SuccinctReceipt<ReceiptClaim>> =
            deserialize_from_bincode_bytes(&lifted_receipts).context("Failed to deserialize")?;
        let receipt_count = lifted_receipts.len();
        assert!(receipt_count > 0, "No lifted receipts found");

        info!("Loaded {receipt_count} lifted receipts");

        let serialized_receipts: Vec<Vec<u8>> =
            lifted_receipts.into_iter().map(|r| serialize_obj(&r).unwrap()).collect();

        let mut queue: VecDeque<Vec<u8>> = VecDeque::from(serialized_receipts);

        while queue.len() > 1 {
            let mut next_level: VecDeque<Vec<u8>> = VecDeque::with_capacity((queue.len() + 1) / 2);

            while let Some(left) = queue.pop_front() {
                if let Some(right) = queue.pop_front() {
                    let join_input =
                        serde_json::to_vec(&vec![left, right]).context("serialize failed")?;
                    let joined = agent.join(join_input).context("Union failed")?;
                    assert!(!joined.is_empty(), "Joined result should not be empty");
                    next_level.push_back(joined);
                } else {
                    next_level.push_back(left);
                    break;
                }
            }

            info!(
                "Level complete | produced {} nodes (from {} inputs)",
                next_level.len(),
                receipt_count
            );
            queue = next_level;
        }

        let final_result = queue.pop_front().unwrap();

        info!("join result: ({size} bytes)", size = final_result.len());

        Ok(())
    }

    #[test]
    fn test_keccak_on_pending_keccaks() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let session_path = metadata_dir.join("session/po2_19_segment_3_keccak_2_cycle_1420941.bin");
        info!("Loading session from: {session_path:?}");

        let session_serialized = fs::read(&session_path)?;
        let session: SerializableSession = deserialize_from_bincode_bytes(&session_serialized)?;

        let keccak_count = session.pending_keccaks.len();
        assert!(keccak_count > 0, "No pending keccaks found in session");

        info!("Found {keccak_count} pending keccak inputs");

        let mut all_receipts = Vec::with_capacity(keccak_count);

        for (i, keccak_req) in session.pending_keccaks.iter().enumerate() {
            let current_index = i + 1;
            let local_req = ProveKeccakRequestLocal {
                claim_digest: keccak_req
                    .claim_digest
                    .as_bytes()
                    .try_into()
                    .context("claim_digest must be 32 bytes")?,
                po2: keccak_req.po2,
                control_root: keccak_req
                    .control_root
                    .as_bytes()
                    .try_into()
                    .context("control_root must be 32 bytes")?,
                input: keccak_req.input.clone(),
            };

            let bytes = serialize_obj(&local_req)?;
            info!("Proving keccak [{current_index} / {keccak_count}]...");

            let result = agent.keccak(bytes)?;
            assert!(
                !result.is_empty(),
                "Keccak result should not be empty for request {current_index}"
            );

            let receipt: SuccinctReceipt<Unknown> =
                deserialize_obj(&result).context("Failed to deserialize keccak receipt")?;

            info!(
                "Keccak [{current_index}] result size: {result_size}",
                result_size = result.len()
            );
            all_receipts.push(receipt);
        }

        assert_eq!(
            all_receipts.len(),
            keccak_count,
            "Number of receipts should match keccak count"
        );

        let receipts_serialized = serialize_to_bincode_bytes(&all_receipts)?;

        info!("keccak result: ({size} bytes)", size = receipts_serialized.len());

        Ok(())
    }

    #[test]
    fn test_union_on_keccaks_tree() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let keccak_receipt_path =
            metadata_dir.join("receipt/po2_19_segment_3_keccak_2_cycle_1420941_keccak_receipt.bin");
        info!("Loading keccak receipts from: {:?}", keccak_receipt_path);

        let keccak_receipt_serialized =
            fs::read(&keccak_receipt_path).context("Failed to read file")?;
        let keccak_receipts: Vec<SuccinctReceipt<Unknown>> =
            deserialize_from_bincode_bytes(&keccak_receipt_serialized)
                .context("Failed to deserialize")?;
        let receipt_count = keccak_receipts.len();
        assert!(receipt_count > 0, "No keccak receipts found");

        info!("Loaded {receipt_count} keccak receipts");

        let keccak_receipts_serialized: Vec<Vec<u8>> = keccak_receipts
            .into_iter()
            .map(|r| serialize_obj(&r).context("Failed to serialize receipt"))
            .collect::<Result<_, _>>()?;

        let mut queue: VecDeque<Vec<u8>> = VecDeque::from(keccak_receipts_serialized.clone());

        while queue.len() > 1 {
            let mut next_level: VecDeque<Vec<u8>> = VecDeque::with_capacity((queue.len() + 1) / 2);

            while let Some(left) = queue.pop_front() {
                if let Some(right) = queue.pop_front() {
                    let union_input =
                        serde_json::to_vec(&vec![left, right]).context("serialize failed")?;
                    let joined = agent.union(union_input).context("Union failed")?;
                    assert!(!joined.is_empty(), "Joined result should not be empty");
                    next_level.push_back(joined);
                } else {
                    next_level.push_back(left);
                    break;
                }
            }

            info!(
                "Level complete | produced {} nodes (from {} inputs)",
                next_level.len(),
                receipt_count
            );
            queue = next_level;
        }

        let final_result = queue.pop_front().unwrap();

        info!("union result: ({size} bytes)", size = final_result.len());

        Ok(())
    }

    #[test]
    fn test_resolve_on_session() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let session_path = metadata_dir.join("session/po2_19_segment_3_keccak_2_cycle_1420941.bin");
        info!("Loading session from: {:?}", session_path);
        let session_serialized = fs::read(&session_path).context("Failed to read session file")?;
        let session: SerializableSession = deserialize_from_bincode_bytes(&session_serialized)
            .context("Failed to deserialize session")?;

        let join_root_path = metadata_dir
            .join("receipt/po2_19_segment_3_keccak_2_cycle_1420941_join_root_receipt.bin");
        info!("Loading root receipt from: {:?}", join_root_path);
        let join_root_serialized = fs::read(&join_root_path).context("Failed to read file")?;
        let join_root_receipt: SuccinctReceipt<ReceiptClaim> =
            deserialize_from_bincode_bytes(&join_root_serialized)
                .context("Failed to deserialize")?;

        let union_root_path = metadata_dir
            .join("receipt/po2_19_segment_3_keccak_2_cycle_1420941_union_root_receipt.bin");
        info!("Loading unioned receipt from: {:?}", union_root_path);
        let union_root_serialized = fs::read(&union_root_path).context("Failed to read file")?;
        let union_root_receipt: SuccinctReceipt<Unknown> =
            deserialize_from_bincode_bytes(&union_root_serialized)
                .context("Failed to deserialize")?;

        let join_root_serialized = serialize_obj(&join_root_receipt)?;
        let union_root_serialized = serialize_obj(&union_root_receipt)?;
        let assumptions_serialized = serialize_obj(&session.assumptions)?;

        let resolve_input = serde_json::to_vec(&vec![
            join_root_serialized,
            union_root_serialized,
            assumptions_serialized,
        ])
        .context("Failed to serialize join input")?;

        let resolved_receipt = agent.resolve(resolve_input)?;

        info!("resolve result: ({size} bytes)", size = resolved_receipt.len());

        Ok(())
    }

    #[test]
    fn test_finalize_on_session() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let resolved_receipt_path = metadata_dir
            .join("receipt/po2_19_segment_3_keccak_2_cycle_1420941_resolved_receipt.bin");
        info!("Loading resolved receipt from: {:?}", resolved_receipt_path);
        let resolved_receipt = fs::read(&resolved_receipt_path).context("Failed to read file")?;
        let resolved_receipt: SuccinctReceipt<ReceiptClaim> =
            deserialize_from_bincode_bytes(&resolved_receipt).context("Failed to deserialize")?;
        assert!(resolved_receipt.claim.as_value().is_ok(), "Root receipt should have a claim");

        let session_path = metadata_dir.join("session/po2_19_segment_3_keccak_2_cycle_1420941.bin");
        info!("Loading session from: {:?}", session_path);
        let session_serialized = fs::read(&session_path).context("Failed to read session file")?;
        let session: SerializableSession = deserialize_from_bincode_bytes(&session_serialized)
            .context("Failed to deserialize session")?;

        let journal_bytes = session
            .journal
            .as_ref()
            .map(|j| j.bytes.clone())
            .ok_or_else(|| anyhow!("journal is missing"))?;

        info!("Journal loaded, size: {}", journal_bytes.len());

        let image_id = "3fe354c3604a1b33f44a76bde3ee677e0f68a1777b0f74f7658c87b49e4c4c8a";

        let resolved_receipt_serialized =
            serialize_obj(&resolved_receipt).context("Failed to serialize")?;
        let image_id_serialized = serialize_obj(&image_id).context("Failed to serialize")?;

        let finalize_input = serde_json::to_vec(&vec![
            resolved_receipt_serialized,
            journal_bytes,
            image_id_serialized,
        ])
        .context("Failed to serialize finalize input")?;

        let stark_receipt = agent.finalize(finalize_input).context("Failed to finalize")?;

        info!("finalize result: ({size} bytes)", size = stark_receipt.len());

        Ok(())
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_stark2snark() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let stark_path =
            metadata_dir.join("receipt/po2_19_segment_3_keccak_2_cycle_1420941_stark_receipt.bin");
        info!("Loading stark receipt from: {stark_path:?}");

        let stark_receipt_serialized = fs::read(&stark_path).context("Failed to read file")?;

        assert!(!stark_receipt_serialized.is_empty(), "Stark receipt bytes should not be empty");
        let stark_receipt: Receipt = deserialize_from_bincode_bytes(&stark_receipt_serialized)
            .context("Failed to deserialize")?;

        let stark_receipt_serialized =
            serialize_obj(&stark_receipt).context("Failed to serialize")?;

        let snark_receipt = agent
            .stark2snark(stark_receipt_serialized)
            .context("stark2snark conversion failed: could not convert stark receipt to snark")?;

        info!("stark2snark result: ({size} bytes)", size = snark_receipt.len());
        Ok(())
    }
}

pub(crate) fn read_image_id(image_id: &str) -> Result<Digest> {
    Digest::from_hex(image_id).context("Failed to convert imageId file to digest from_hex")
}
