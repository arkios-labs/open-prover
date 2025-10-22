use std::time::Instant;

use anyhow::{Context, Result, bail};
use tracing::info;

use crate::tasks::{Risc0Agent, deserialize_obj, serialize_obj};

impl Risc0Agent {
    pub fn prove(&self, input: Vec<u8>) -> Result<Vec<u8>> {
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
}

#[cfg(test)]
mod tests {
    use crate::tasks::{
        SerializableSession, deserialize_obj, serialize_obj, setup_agent_and_metadata_dir,
    };
    use anyhow::Context;
    use anyhow::Result;
    use common::serialization::bincode::{
        deserialize_from_bincode_bytes, serialize_to_bincode_bytes,
    };
    use risc0_zkvm::{ReceiptClaim, SuccinctReceipt};
    use std::fs;
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
}
