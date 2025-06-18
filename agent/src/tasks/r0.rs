use crate::tasks::{Agent, ProveKeccakRequestLocal, convert, deserialize_obj, serialize_obj};
use anyhow::Context;
use anyhow::Result;
use risc0_zkvm::{
    ExecutorImpl, ProveKeccakRequest, ProverOpts, ProverServer, Segment, VerifierContext,
    get_prover_server,
};
use std::{
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
};
use tracing::info;

pub struct RiscZeroAgent {
    pub prover: Option<Rc<dyn ProverServer>>,
    pub verifier_ctx: VerifierContext,
}

impl RiscZeroAgent {
    pub fn new() -> anyhow::Result<Self> {
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
    fn execute(&self, data: Vec<u8>) -> anyhow::Result<()> {
        info!("RiscZeroTask::execute()");
        Ok(())
    }

    fn prove(&self, segment_bytes: Vec<u8>) -> Result<Vec<u8>> {
        let segment = deserialize_obj(&segment_bytes).context("Failed to deserialize segment")?;
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

    fn keccak(&self, keccak_request: Vec<u8>) -> Result<Vec<u8>> {
        info!("RiscZeroTask::keccak()");

        let prove_keccak_request_local: ProveKeccakRequestLocal =
            deserialize_obj(&keccak_request).context("Failed to deserialize keccak request")?;

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

    fn union(&self, left_receipt_bytes: Vec<u8>, right_receipt_bytes: Vec<u8>) ->Result<Vec<u8>> {
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
        Ok(())
    }

    fn stark2snark(&self, data: Vec<u8>) -> Result<()> {
        info!("RiscZeroTask::stark2snark()");
        Ok(())
    }

    fn resolve(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        info!("RiscZeroTask::resolve()");
        Ok(())
    }
}
