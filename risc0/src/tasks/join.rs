use std::time::Instant;

use anyhow::Result;
use risc0_zkvm::{ReceiptClaim, SuccinctReceipt};
use tracing::info;

use crate::tasks::Risc0Agent;

impl Risc0Agent {
    pub fn join(
        &self,
        left_receipt: SuccinctReceipt<ReceiptClaim>,
        right_receipt: SuccinctReceipt<ReceiptClaim>,
    ) -> Result<SuccinctReceipt<ReceiptClaim>> {
        info!("Agent::join()");
        let start_time = Instant::now();

        let joined = self.prover.join(&left_receipt, &right_receipt)?;

        let elapsed = start_time.elapsed();
        info!("Agent::join() took {elapsed:?}");

        Ok(joined)
    }
}

#[cfg(test)]
mod tests {
    use crate::tasks::{setup_agent_and_metadata_dir, test_constants};
    use anyhow::Context;
    use anyhow::Result;
    use common::serialization::bincode::deserialize_from_bincode_bytes;
    use risc0_zkvm::{ReceiptClaim, SuccinctReceipt};
    use std::{collections::VecDeque, fs};
    use tracing::info;

    #[test]
    fn test_join_on_lifted_receipts() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let proof_path = metadata_dir.join(test_constants::SEGMENT_LIFTED_RECEIPTS_PATH);
        info!("Loading lifted proof from: {proof_path:?}");
        let lifted_receipts = fs::read(&proof_path).context("Failed to read receipt file")?;

        let lifted_receipts: Vec<SuccinctReceipt<ReceiptClaim>> =
            deserialize_from_bincode_bytes(&lifted_receipts).context("Failed to deserialize")?;
        let receipt_count = lifted_receipts.len();
        assert!(receipt_count > 0, "No lifted receipts found");

        info!("Loaded {receipt_count} lifted receipts");

        let mut queue: VecDeque<SuccinctReceipt<ReceiptClaim>> = VecDeque::from(lifted_receipts);

        while queue.len() > 1 {
            let mut next_level: VecDeque<SuccinctReceipt<ReceiptClaim>> =
                VecDeque::with_capacity((queue.len() + 1) / 2);

            while let Some(left) = queue.pop_front() {
                if let Some(right) = queue.pop_front() {
                    let joined = agent.join(left, right)?;
                    assert!(
                        !joined.get_seal_bytes().is_empty(),
                        "Joined result should not be empty"
                    );
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

        info!("join result: ({size} bytes)", size = final_result.get_seal_bytes().len());

        Ok(())
    }
}
