use crate::tasks::Risc0Agent;
use anyhow::{Context, Result};
use risc0_zkvm::{ProverOpts, Receipt};
use std::time::Instant;
use tracing::info;

impl Risc0Agent {
    pub fn stark2snark(&self, stark_receipt: Receipt) -> Result<Receipt> {
        info!("Agent::stark2snark()");
        let start_time = Instant::now();

        let opts = ProverOpts::groth16();
        // Implemented based on newly introduced logic in Bento.
        // (Ref: https://github.com/risc0/risc0/blob/b5b16f6/bento/crates/workflow/src/tasks/snark.rs#L29-L34)
        let snark_receipt = self
            .prover
            .compress(&opts, &stark_receipt)
            .context("Failed to compress stark receipt")?;

        let elapsed = start_time.elapsed();
        info!("Agent::stark2snark() took {elapsed:?}");
        Ok(snark_receipt)
    }
}

#[cfg(test)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod tests {
    use crate::tasks::{setup_agent_and_metadata_dir, test_constants};
    use anyhow::Context;
    use anyhow::Result;
    use common::serialization::bincode::deserialize_from_bincode_bytes;
    use risc0_zkvm::Receipt;
    use std::fs;
    use tracing::info;

    #[test]
    fn test_stark2snark() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let stark_path = metadata_dir.join(test_constants::FINAL_RECEIPT_PATH);
        info!("Loading stark receipt from: {stark_path:?}");

        let stark_receipt_serialized = fs::read(&stark_path).context("Failed to read file")?;

        assert!(!stark_receipt_serialized.is_empty(), "Stark receipt bytes should not be empty");
        let stark_receipt: Receipt = deserialize_from_bincode_bytes(&stark_receipt_serialized)
            .context("Failed to deserialize")?;

        let snark_receipt = agent
            .stark2snark(stark_receipt)
            .context("stark2snark conversion failed: could not convert stark receipt to snark")?;

        info!("stark2snark result: ({size} bytes)", size = snark_receipt.seal_size());
        Ok(())
    }
}
