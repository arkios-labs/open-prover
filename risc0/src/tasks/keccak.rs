use std::time::Instant;

use anyhow::Result;
use risc0_zkvm::{ProveKeccakRequest, SuccinctReceipt, Unknown};
use tracing::info;

use crate::tasks::Risc0Agent;

impl Risc0Agent {
    pub fn keccak(
        &self,
        prove_keccak_request: ProveKeccakRequest,
    ) -> Result<SuccinctReceipt<Unknown>> {
        info!("Agent::keccak()");
        let start_time = Instant::now();

        let keccak_receipt = self.prover.prove_keccak(&prove_keccak_request)?;

        let elapsed = start_time.elapsed();
        info!("Agent::keccak() took {elapsed:?}");

        Ok(keccak_receipt)
    }
}

#[cfg(test)]
mod tests {
    use crate::tasks::{ProveKeccakRequestLocal, setup_agent_and_metadata_dir};
    use crate::tasks::{convert, test_constants};
    use anyhow::Context;
    use anyhow::Result;
    use common::serialization::bincode::{
        deserialize_from_bincode_bytes, serialize_to_bincode_bytes,
    };
    use risc0_zkvm::ProveKeccakRequest;
    use std::fs;
    use tracing::info;

    #[test]
    fn test_keccak_on_pending_keccaks() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let keccaks_path = metadata_dir.join(test_constants::KECCAKS_PATH);
        info!("Loading keccaks from: {keccaks_path:?}");

        let keccaks_serialized = fs::read(&keccaks_path)?;
        let keccaks: Vec<ProveKeccakRequest> = deserialize_from_bincode_bytes(&keccaks_serialized)?;

        let keccak_count = keccaks.len();
        assert!(keccak_count > 0, "No pending keccaks found in session");

        info!("Found {keccak_count} pending keccak inputs");

        let mut all_receipts = Vec::with_capacity(keccak_count);

        for (i, keccak_req) in keccaks.iter().enumerate() {
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

            info!("Proving keccak [{current_index} / {keccak_count}]...");

            let result = agent.keccak(convert(local_req))?;
            assert!(
                !result.get_seal_bytes().is_empty(),
                "Keccak result should not be empty for request {current_index}"
            );

            info!(
                "Keccak [{current_index}] result size: {result_size}",
                result_size = result.seal_size()
            );
            all_receipts.push(result);
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
}
