use crate::tasks::Risc0Agent;
use anyhow::{Context, Result};
use hex::FromHex;
use risc0_zkvm::{Digest, InnerReceipt, Journal, Receipt, ReceiptClaim, SuccinctReceipt};
use std::time::Instant;
use tracing::info;

impl Risc0Agent {
    pub fn finalize(
        &self,
        root: SuccinctReceipt<ReceiptClaim>,
        journal: Journal,
        image_id: String,
    ) -> Result<Receipt> {
        info!("Agent::finalize()");
        let start_time = Instant::now();

        let rollup_receipt = Receipt::new(InnerReceipt::Succinct(root), journal.bytes);

        let image_id = read_image_id(&image_id)?;
        rollup_receipt.verify(image_id).context("Receipt verification failed")?;

        let elapsed = start_time.elapsed();
        info!("Agent::finalize() took {elapsed:?}");

        Ok(rollup_receipt)
    }
}

#[cfg(test)]
mod tests {
    use crate::tasks::{setup_agent_and_metadata_dir, test_constants};
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

        let stark_receipt = agent.finalize(resolved_receipt, journal, image_id)?;

        info!("finalize result: ({size} bytes)", size = stark_receipt.seal_size());

        Ok(())
    }
}

pub(crate) fn read_image_id(image_id: &str) -> Result<Digest> {
    Digest::from_hex(image_id).context("Failed to convert imageId file to digest from_hex")
}
