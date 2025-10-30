use std::time::Instant;

use anyhow::{Context, Result};
use risc0_zkvm::{ReceiptClaim, Segment, SuccinctReceipt};
use tracing::info;

use crate::tasks::Risc0Agent;

impl Risc0Agent {
    pub fn prove(&self, segment: Segment) -> Result<SuccinctReceipt<ReceiptClaim>> {
        info!("Agent::prove()");
        let start_time = Instant::now();

        let segment_receipt = self
            .prover
            .prove_segment(&self.verifier_ctx, &segment)
            .context("Failed to prove segment")?;

        let lift_receipt =
            self.prover.lift(&segment_receipt).with_context(|| "Failed to lift".to_string())?;

        let elapsed = start_time.elapsed();
        info!("Agent::prove() took {elapsed:?}");
        Ok(lift_receipt)
    }
}

#[cfg(test)]
mod tests {
    use crate::tasks::setup_agent_and_metadata_dir;
    use crate::tasks::test_constants;
    use anyhow::Context;
    use anyhow::Result;
    use common::serialization::bincode::{
        deserialize_from_bincode_bytes, serialize_to_bincode_bytes,
    };
    use risc0_zkvm::Segment;
    use std::fs;
    use tracing::info;

    #[test]
    fn test_prove_all_segments() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let segments_path = metadata_dir.join(test_constants::SEGMENTS_PATH);
        info!("Loading segments from: {segments_path:?}");
        let segments = fs::read(&segments_path).context("Failed to read segments file")?;
        let segments: Vec<Segment> =
            deserialize_from_bincode_bytes(&segments).context("Failed to deserialize segments")?;
        let segment_count = segments.len();
        assert!(segment_count > 0, "No segments found");

        info!("Found {segment_count} segments. Starting proof generation...",);
        let mut all_receipts = Vec::with_capacity(segment_count);

        for (i, segment) in segments.iter().enumerate() {
            let current_index = i + 1;
            info!("Proving segment [{current_index}/{segment_count}]");
            let lift_receipt = agent.prove(segment.clone())?;

            assert!(
                !lift_receipt.get_seal_bytes().is_empty(),
                "Lifted bytes should not be empty for segment {current_index}"
            );

            info!(
                "Segment [{current_index}] proof size: {proof_size}",
                proof_size = lift_receipt.seal_size()
            );

            all_receipts.push(lift_receipt);
        }

        let receipts_serialized = serialize_to_bincode_bytes(&all_receipts)?;

        info!("prove result: ({size} bytes)", size = receipts_serialized.len());

        Ok(())
    }
}
