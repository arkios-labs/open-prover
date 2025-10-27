use std::{collections::HashMap, time::Instant};

use anyhow::{Context, Result, bail};
use risc0_zkvm::{
    Assumption, AssumptionReceipt, ReceiptClaim, SuccinctReceipt, Unknown, sha::Digestible,
};
use tracing::info;

use crate::tasks::{Risc0Agent, deserialize_obj, serialize_obj};

impl Risc0Agent {
    pub fn resolve(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::resolve()");
        let start_time = Instant::now();

        if input.is_empty() {
            bail!("resolve input is empty");
        }

        let inputs: Vec<Vec<u8>> = serde_json::from_slice(&input)
            .context("Failed to parse input as Vec<Vec<u8>> for resolve")?;

        if inputs.len() != 3 {
            bail!("Expected exactly three inputs for resolve, got {}", inputs.len())
        }

        let mut root: SuccinctReceipt<ReceiptClaim> =
            deserialize_obj(&inputs[0]).context("Failed to deserialize root receipt")?;

        let union: Option<SuccinctReceipt<Unknown>> =
            deserialize_obj(&inputs[1]).context("Failed to deserialize union receipt")?;

        let pairs: Vec<(Assumption, AssumptionReceipt)> =
            deserialize_obj(&inputs[2]).context("Failed to deserialize assumptions")?;

        let (_, session_assumption_receipts): (Vec<Assumption>, Vec<AssumptionReceipt>) =
            pairs.into_iter().unzip();

        let assumption_receipt_map: HashMap<String, SuccinctReceipt<Unknown>> = HashMap::new();

        info!("Loaded {} assumption receipts", session_assumption_receipts.len());

        let mut assumptions_len: u64 = 0;

        if root.claim.clone().as_value()?.output.is_some()
            && let Some(guest_output) = root.claim.clone().as_value()?.output.as_value()?
            && !guest_output.assumptions.is_empty()
        {
            let assumptions_list = guest_output
                .assumptions
                .as_value()
                .context("Failed to unwrap assumptions of guest output")?;

            assumptions_len =
                assumptions_list.len().try_into().context("Failed to convert assumption length")?;

            let mut union_claim = String::new();
            if let Some(union_receipt) = union {
                union_claim = union_receipt.claim.digest().to_string();
                info!("Resolving union claim digest: {union_claim}");

                root = self
                    .prover
                    .resolve(&root, &union_receipt)
                    .context("Failed to resolve union receipt")?;
            }

            for assumption in &assumptions_list.0 {
                let assumption_claim = assumption.as_value()?.claim.to_string();
                if assumption_claim == union_claim {
                    info!("Skipping already resolved union claim: {union_claim}");
                    continue;
                }

                let assumption_receipt =
                    assumption_receipt_map.get(&assumption_claim).with_context(|| {
                        format!("Corroborating receipt not found: {assumption_claim}")
                    })?;

                root = self
                    .prover
                    .resolve(&root, assumption_receipt)
                    .context("Failed to resolve assumption receipt")?;
            }

            info!("Resolve complete");
        }

        info!("Resolve operation completed successfully: {assumptions_len}");

        let serialized = serialize_obj(&root).context("Failed to serialize conditional receipt")?;
        let elapsed = start_time.elapsed();
        info!("Agent::resolve() took {elapsed:?}");
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
    use risc0_zkvm::{Assumption, AssumptionReceipt, ReceiptClaim, SuccinctReceipt, Unknown};
    use std::fs;
    use tracing::info;

    #[test]
    fn test_resolve_on_session() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let assumptions_path = metadata_dir.join(test_constants::ASSUMPTIONS_PATH);
        info!("Loading assumptions from: {:?}", assumptions_path);
        let assumptions = fs::read(&assumptions_path).context("Failed to read assumptions file")?;
        let assumptions: Vec<(Assumption, AssumptionReceipt)> =
            deserialize_from_bincode_bytes(&assumptions)
                .context("Failed to deserialize assumptions")?;

        let join_root_path = metadata_dir.join(test_constants::JOIN_ROOT_RECEIPT_PATH);
        info!("Loading root receipt from: {:?}", join_root_path);
        let join_root_serialized = fs::read(&join_root_path).context("Failed to read file")?;
        let join_root_receipt: SuccinctReceipt<ReceiptClaim> =
            deserialize_from_bincode_bytes(&join_root_serialized)
                .context("Failed to deserialize")?;

        let union_root_path = metadata_dir.join(test_constants::UNION_ROOT_RECEIPT_PATH);
        info!("Loading unioned receipt from: {:?}", union_root_path);
        let union_root_serialized = fs::read(&union_root_path).context("Failed to read file")?;
        let union_root_receipt: SuccinctReceipt<Unknown> =
            deserialize_from_bincode_bytes(&union_root_serialized)
                .context("Failed to deserialize")?;

        let join_root_serialized = serialize_obj(&join_root_receipt)?;
        let union_root_serialized = serialize_obj(&union_root_receipt)?;
        let assumptions_serialized = serialize_obj(&assumptions)?;

        let resolve_input = serde_json::to_vec(&vec![
            join_root_serialized,
            union_root_serialized,
            assumptions_serialized,
        ])
        .context("Failed to serialize join input")?;

        let resolved_receipt = agent.resolve(resolve_input)?;

        info!("resolve result: ({size} bytes)", size = resolved_receipt.len());

        Ok(())
    }
}
