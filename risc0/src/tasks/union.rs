use std::time::Instant;

use anyhow::{Context, Result, bail};
use tracing::info;

use crate::tasks::{Risc0Agent, deserialize_obj, serialize_obj};

impl Risc0Agent {
    pub fn union(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::union()");
        let start_time = Instant::now();

        if input.is_empty() {
            bail!("union input is empty");
        }

        let receipts: Vec<Vec<u8>> = serde_json::from_slice(&input)
            .context("Failed to parse input as Vec<Vec<u8>> for union")?;

        if receipts.len() != 2 {
            bail!("Expected exactly two receipts for union, got {}", receipts.len());
        }

        let left_receipt =
            deserialize_obj(&receipts[0]).context("Failed to deserialize left receipt")?;
        let right_receipt =
            deserialize_obj(&receipts[1]).context("Failed to deserialize right receipt")?;

        let unioned = self
            .prover
            .union(&left_receipt, &right_receipt)
            .context("Failed to union on left/right receipt")?
            .into_unknown();

        let serialized = serialize_obj(&unioned).context("Failed to serialize union receipt")?;
        let elapsed = start_time.elapsed();
        info!("Agent::union() took {elapsed:?}");
        Ok(serialized)
    }
}

#[cfg(test)]
mod tests {
    use crate::tasks::test_constants;
    use crate::tasks::{serialize_obj, setup_agent_and_metadata_dir};
    use anyhow::Context;
    use anyhow::Result;
    use common::serialization::bincode::deserialize_from_bincode_bytes;
    use risc0_zkvm::{SuccinctReceipt, Unknown};
    use std::{collections::VecDeque, fs};
    use tracing::info;

    #[test]
    fn test_union_on_keccaks_tree() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let keccak_receipt_path = metadata_dir.join(test_constants::KECCAK_RECEIPTS_PATH);
        info!("Loading keccak receipts from: {:?}", keccak_receipt_path);

        let keccak_receipt_serialized =
            fs::read(&keccak_receipt_path).context("Failed to read file")?;
        let keccak_receipts: Vec<SuccinctReceipt<Unknown>> =
            deserialize_from_bincode_bytes(&keccak_receipt_serialized)
                .context("Failed to deserialize")?;
        let receipt_count = keccak_receipts.len();
        assert!(receipt_count > 0, "No keccak receipts found");

        info!("Loaded {receipt_count} keccak receipts");

        let keccak_receipts_serialized: Vec<Vec<u8>> = keccak_receipts
            .into_iter()
            .map(|r| serialize_obj(&r).context("Failed to serialize receipt"))
            .collect::<Result<_, _>>()?;

        let mut queue: VecDeque<Vec<u8>> = VecDeque::from(keccak_receipts_serialized.clone());

        while queue.len() > 1 {
            let mut next_level: VecDeque<Vec<u8>> = VecDeque::with_capacity((queue.len() + 1) / 2);

            while let Some(left) = queue.pop_front() {
                if let Some(right) = queue.pop_front() {
                    let union_input =
                        serde_json::to_vec(&vec![left, right]).context("serialize failed")?;
                    let joined = agent.union(union_input).context("Union failed")?;
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

        info!("union result: ({size} bytes)", size = final_result.len());

        Ok(())
    }
}
