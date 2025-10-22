use crate::tasks::{Risc0Agent, deserialize_obj, serialize_obj};
use anyhow::{Context, Result, bail};
use risc0_zkvm::{ProverOpts, Receipt};
use std::time::Instant;
use tracing::info;

impl Risc0Agent {
    pub fn stark2snark(&self, input: Vec<u8>) -> Result<Vec<u8>> {
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
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod tests {
    use crate::tasks::{serialize_obj, setup_agent_and_metadata_dir, test_constants};
    use anyhow::Context;
    use anyhow::Result;
    use common::serialization::bincode::deserialize_from_bincode_bytes;
    use risc0_zkvm::{Receipt, Unknown};
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

        let stark_receipt_serialized =
            serialize_obj(&stark_receipt).context("Failed to serialize")?;

        let snark_receipt = agent
            .stark2snark(stark_receipt_serialized)
            .context("stark2snark conversion failed: could not convert stark receipt to snark")?;

        info!("stark2snark result: ({size} bytes)", size = snark_receipt.len());
        Ok(())
    }
}
