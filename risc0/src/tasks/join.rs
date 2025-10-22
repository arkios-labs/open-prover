use std::time::Instant;

use anyhow::{Context, Result, bail};
use tracing::info;

use crate::tasks::{Risc0Agent, deserialize_obj, serialize_obj};

impl Risc0Agent {
    pub fn join(&self, input: Vec<u8>) -> Result<Vec<u8>> {
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
}

#[cfg(test)]
mod tests {
    use crate::tasks::{
        ProveKeccakRequestLocal, SerializableSession, deserialize_obj, serialize_obj,
        setup_agent_and_metadata_dir,
    };
    use anyhow::Context;
    use anyhow::{Result, anyhow};
    use common::serialization::bincode::{
        deserialize_from_bincode_bytes, serialize_to_bincode_bytes,
    };
    use risc0_zkvm::{ReceiptClaim, SuccinctReceipt, Unknown};
    use std::{collections::VecDeque, fs};
    use tracing::info;

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
}
