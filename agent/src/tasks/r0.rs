use crate::tasks::{Agent, ProveKeccakRequestLocal, convert, deserialize_obj, serialize_obj, SerializableSession};
use anyhow::{bail, Context};
use anyhow::Result;
use risc0_zkvm::{
    ProverOpts, ProverServer, ReceiptClaim, Segment,
    SuccinctReceipt, Unknown, VerifierContext, get_prover_server,
};
use std::{env, fs, rc::Rc, sync::atomic::{AtomicBool, Ordering}};
use std::time::Instant;
use tracing::info;
use crate::io::input::env::EnvProvider;
use crate::tasks::factory::get_agent;

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
    fn execute(&self, data: Vec<u8>) -> Result<()> {
        bail!("RiscZeroTask::execute is not supported in this context");
    }

    fn prove(&self, segment_bytes: Vec<u8>) -> Result<Vec<u8>> {
        let segment = deserialize_obj(&segment_bytes).context("Failed to deserialize segment")?;
        let json = serde_json::to_string_pretty(&segment)?;
        fs::write("segment.json", json)?;

        let segment_receipt = self
            .prover
            .as_ref()
            .context("Missing prover")?
            .prove_segment(&self.verifier_ctx, &segment)
            .context("Failed to prove segment")?;

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

    fn finalize(&self, data: Vec<u8>) -> Result<()> {
        info!("RiscZeroTask::finalize()");
        // TODO:
        // 1. Get root_receipt
        // 2. Make rollup_receipt with journal
        // 3. Verify rollup_receipt with image_id
        // 4. Delete intermediate data used during the above operations
        Ok(())
    }

    fn stark2snark(&self, data: Vec<u8>) -> Result<()> {
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
        
        Ok(Vec::from(assumptions_bytes))
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

    let mut path = env::current_dir()?;
    path.push("session_1_segments.json");
    let json = fs::read_to_string(&path)?;
    let session: SerializableSession = serde_json::from_str(&json)?;

    assert!(
        !session.pending_keccaks.is_empty(),
        "No pending keccaks found in session"
    );

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
        info!("Keccak test start");
        let result = agent_ref.keccak(bytes)?;

        info!("Keccak test [{}] result len: {}", i, result.len());
    }

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

    let mut path = env::current_dir()?;
    path.push("pending_keccaks.json");
    let json = fs::read_to_string(&path)?;

    let keccak_receipts: Vec<SuccinctReceipt<Unknown>> = serde_json::from_str(&json)?;
    let keccak_receipts_count = keccak_receipts.len();

    let serialized_receipts: Vec<Vec<u8>> = keccak_receipts
        .into_iter()
        .map(|r| serialize_obj(&r).unwrap())
        .collect();

    let start = Instant::now();
    let mut queue: VecDeque<Vec<u8>> = VecDeque::from(serialized_receipts);

    while queue.len() > 1 {
        let left = queue.pop_front().unwrap();
        let right = queue.pop_front().unwrap();

        let unioned = agent_ref
            .union(left, right)
            .expect("Union failed");

        info!("Union successful, resulting size: {}", unioned.len());
        queue.push_back(unioned);
    }

    let final_result = queue.pop_front().unwrap();
    let elapsed = start.elapsed();

    info!("Final unioned result size: {}", final_result.len());
    info!("Union elapsed: {:?} with receipts count: {:?}", elapsed, keccak_receipts_count);

    Ok(())
}