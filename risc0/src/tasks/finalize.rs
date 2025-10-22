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
    use crate::tasks::{SerializableSession, serialize_obj, setup_agent_and_metadata_dir};
    use anyhow::Context;
    use anyhow::{Result, anyhow};
    use common::serialization::bincode::deserialize_from_bincode_bytes;
    use risc0_zkvm::{ReceiptClaim, SuccinctReceipt};
    use std::fs;
    use tracing::info;

    #[test]
    fn test_finalize_on_session() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let resolved_receipt_path = metadata_dir
            .join("receipt/po2_19_segment_3_keccak_2_cycle_1420941_resolved_receipt.bin");
        info!("Loading resolved receipt from: {:?}", resolved_receipt_path);
        let resolved_receipt = fs::read(&resolved_receipt_path).context("Failed to read file")?;
        let resolved_receipt: SuccinctReceipt<ReceiptClaim> =
            deserialize_from_bincode_bytes(&resolved_receipt).context("Failed to deserialize")?;
        assert!(resolved_receipt.claim.as_value().is_ok(), "Root receipt should have a claim");

        let session_path = metadata_dir.join("session/po2_19_segment_3_keccak_2_cycle_1420941.bin");
        info!("Loading session from: {:?}", session_path);
        let session_serialized = fs::read(&session_path).context("Failed to read session file")?;
        let session: SerializableSession = deserialize_from_bincode_bytes(&session_serialized)
            .context("Failed to deserialize session")?;

        let journal_bytes = session
            .journal
            .as_ref()
            .map(|j| j.bytes.clone())
            .ok_or_else(|| anyhow!("journal is missing"))?;

        info!("Journal loaded, size: {}", journal_bytes.len());

        let image_id = "3fe354c3604a1b33f44a76bde3ee677e0f68a1777b0f74f7658c87b49e4c4c8a";

        let resolved_receipt_serialized =
            serialize_obj(&resolved_receipt).context("Failed to serialize")?;
        let image_id_serialized = serialize_obj(&image_id).context("Failed to serialize")?;

        let finalize_input = serde_json::to_vec(&vec![
            resolved_receipt_serialized,
            journal_bytes,
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
