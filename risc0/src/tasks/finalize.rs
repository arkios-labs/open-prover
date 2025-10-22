use crate::tasks::{Risc0Agent, deserialize_obj, serialize_obj};
use anyhow::{Context, Result, bail};
use hex::FromHex;
use risc0_zkvm::{Digest, InnerReceipt, Receipt, ReceiptClaim, SuccinctReceipt};
use std::time::Instant;
use tracing::info;

impl Risc0Agent {
    pub fn finalize(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::finalize()");
        let start_time = Instant::now();

        if input.is_empty() {
            bail!("finalize input is empty");
        }

        let inputs: Vec<Vec<u8>> = serde_json::from_slice(&input)
            .context("Failed to parse input as Vec<Vec<u8>> for finalize")?;

        if inputs.len() != 3 {
            bail!("Expected exactly three inputs for finalize, got {}", inputs.len())
        }

        let root: SuccinctReceipt<ReceiptClaim> =
            deserialize_obj(&inputs[0]).context("Failed to deserialize root receipt")?;
        let journal: Vec<u8> = inputs[1].clone();
        let image_id: String =
            deserialize_obj(&inputs[2]).context("Failed to deserialize image_id")?;

        let rollup_receipt = Receipt::new(InnerReceipt::Succinct(root), journal);

        let image_id = read_image_id(&image_id)?;
        rollup_receipt.verify(image_id).context("Receipt verification failed")?;

        let elapsed = start_time.elapsed();
        info!("Agent::finalize() took {elapsed:?}");
        let serialized = serialize_obj(&rollup_receipt).context("Failed to serialize receipt")?;
        Ok(serialized)
    }
}

#[cfg(test)]
mod tests {
    use crate::tasks::{serialize_obj, setup_agent_and_metadata_dir, test_constants};
    use anyhow::Context;
    use anyhow::Result;
    use common::serialization::bincode::deserialize_from_bincode_bytes;
    use risc0_zkvm::{Journal, ReceiptClaim, SuccinctReceipt};
    use std::fs;
    use tracing::info;

    #[test]
    fn test_finalize_on_session() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let resolved_receipt_path = metadata_dir.join(test_constants::RESOLVED_RECEIPT_PATH);
        info!("Loading resolved receipt from: {:?}", resolved_receipt_path);
        let resolved_receipt = fs::read(&resolved_receipt_path).context("Failed to read file")?;
        let resolved_receipt: SuccinctReceipt<ReceiptClaim> =
            deserialize_from_bincode_bytes(&resolved_receipt).context("Failed to deserialize")?;
        assert!(resolved_receipt.claim.as_value().is_ok(), "Root receipt should have a claim");

        let journal_path = metadata_dir.join(test_constants::JOURNAL_PATH);
        info!("Loading journal from: {:?}", journal_path);
        let journal = fs::read(&journal_path).context("Failed to read journal file")?;
        let journal: Journal =
            deserialize_from_bincode_bytes(&journal).context("Failed to deserialize journal")?;

        let image_id = test_constants::FIXTURES_IMAGE_ID.to_string();

        let resolved_receipt_serialized =
            serialize_obj(&resolved_receipt).context("Failed to serialize")?;
        let image_id_serialized = serialize_obj(&image_id).context("Failed to serialize")?;

        let finalize_input = serde_json::to_vec(&vec![
            resolved_receipt_serialized,
            journal.bytes,
            image_id_serialized,
        ])
        .context("Failed to serialize finalize input")?;

        let stark_receipt = agent.finalize(finalize_input).context("Failed to finalize")?;

        info!("finalize result: ({size} bytes)", size = stark_receipt.len());

        Ok(())
    }
}

pub(crate) fn read_image_id(image_id: &str) -> Result<Digest> {
    Digest::from_hex(image_id).context("Failed to convert imageId file to digest from_hex")
}
