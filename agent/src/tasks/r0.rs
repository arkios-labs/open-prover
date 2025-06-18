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

    fn prove(&self, segment_vec: Vec<u8>) -> Result<()> {
        let segment = deserialize_obj(&segment_vec).context("Failed to deserialize segment")?;
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

        let _serialized = serialize_obj(&lift_receipt).expect("Failed to serialize");

        Ok(())
    }

    fn join(&self, left: Vec<u8>, right: Vec<u8>) -> Result<()> {
        info!("RiscZeroTask::join()");
        let left_receipt = deserialize_obj(&left).context("Failed to deserialize left receipt")?;
        let right_receipt =
            deserialize_obj(&right).context("Failed to deserialize right receipt")?;

        let joined = self
            .prover
            .as_ref()
            .context("Missing prover from join task")?
            .join(&left_receipt, &right_receipt)?;

        let join_result = serialize_obj(&joined).expect("Failed to serialize the segment");

        Ok(())
    }

    fn keccak(&self, keccak_request: Vec<u8>) -> Result<()> {
        info!("RiscZeroTask::keccak()");

        let prove_keccak_request_local: ProveKeccakRequestLocal =
            deserialize_obj(&keccak_request).context("Failed to deserialize keccak request")?;

        let prove_keccak_request = convert(prove_keccak_request_local);

        let keccak_receipt = self
            .prover
            .as_ref()
            .context("Mssing prover from keccak task")?
            .prove_keccak(&prove_keccak_request);

        Ok(())
    }

    fn union(&self, data: Vec<u8>) -> anyhow::Result<()> {
        info!("RiscZeroTask::union()");
        Ok(())
    }

    fn finalize(&self, data: Vec<u8>) -> anyhow::Result<()> {
        info!("RiscZeroTask::finalize()");
        Ok(())
    }

    fn stark2snark(&self, data: Vec<u8>) -> anyhow::Result<()> {
        info!("RiscZeroTask::stark2snark()");
        Ok(())
    }

    fn resolve(&self, data: Vec<u8>) -> anyhow::Result<()> {
        info!("RiscZeroTask::resolve()");
        Ok(())
    }
}
