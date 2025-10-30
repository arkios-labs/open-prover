use std::time::Instant;

use anyhow::{Context, Result};
use risc0_zkvm::{SuccinctReceipt, Unknown};
use tracing::info;

use crate::tasks::Risc0Agent;

impl Risc0Agent {
    pub fn union(
        &self,
        left_receipt: SuccinctReceipt<Unknown>,
        right_receipt: SuccinctReceipt<Unknown>,
    ) -> Result<SuccinctReceipt<Unknown>> {
        info!("Agent::union()");
        let start_time = Instant::now();

        let unioned = self
            .prover
            .union(&left_receipt, &right_receipt)
            .context("Failed to union on left/right receipt")?
            .into_unknown();

        let elapsed = start_time.elapsed();
        info!("Agent::union() took {elapsed:?}");
        Ok(unioned)
    }
}

#[cfg(test)]
mod tests {
    use crate::tasks::setup_agent_and_metadata_dir;
    use crate::tasks::test_constants;
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

        let mut queue: VecDeque<SuccinctReceipt<Unknown>> = VecDeque::from(keccak_receipts);

        while queue.len() > 1 {
            let mut next_level: VecDeque<SuccinctReceipt<Unknown>> =
                VecDeque::with_capacity((queue.len() + 1) / 2);

            while let Some(left) = queue.pop_front() {
                if let Some(right) = queue.pop_front() {
                    let joined = agent.union(left, right)?;
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

        info!("union result: ({size} bytes)", size = final_result.seal_size());

        Ok(())
    }
}
