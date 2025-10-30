use crate::tasks::{ProveKeccakRequestLocal, Risc0Agent, convert, deserialize_obj, serialize_obj};
use anyhow::{Context, Result, anyhow, bail};
use risc0_zkvm::{
    Assumption, AssumptionReceipt, Journal, Receipt, ReceiptClaim, Segment, SuccinctReceipt,
    Unknown,
};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Command {
    Join,
    Prove,
    Finalize,
    Resolve,
    Union,
    Keccak,
    Snark,
}

impl FromStr for Command {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "JOIN" => Ok(Command::Join),
            "PROVE" => Ok(Command::Prove),
            "FINALIZE" => Ok(Command::Finalize),
            "RESOLVE" => Ok(Command::Resolve),
            "UNION" => Ok(Command::Union),
            "KECCAK" => Ok(Command::Keccak),
            "SNARK" => Ok(Command::Snark),
            _ => Err(anyhow!("Unknown command type: {}", s)),
        }
    }
}
impl Command {
    pub fn apply(self, agent: &Risc0Agent, input: Vec<u8>) -> Result<Vec<u8>> {
        match self {
            Command::Join => {
                if input.is_empty() {
                    bail!("join input is empty");
                }

                let receipts: Vec<Vec<u8>> = serde_json::from_slice(&input)
                    .context("Failed to parse input as Vec<Vec<u8>>")?;

                if receipts.len() != 2 {
                    bail!("Expected exactly two receipts for join, got {}", receipts.len());
                }

                let left_receipt =
                    deserialize_obj(&receipts[0]).context("Failed to deserialize left receipt")?;
                let right_receipt =
                    deserialize_obj(&receipts[1]).context("Failed to deserialize right receipt")?;

                let joined = agent.join(left_receipt, right_receipt)?;

                let serialized =
                    serialize_obj(&joined).context("Failed to serialize join receipt")?;

                Ok(serialized)
            }
            Command::Prove => {
                if input.is_empty() {
                    bail!("prove input is empty");
                }

                let segment: Segment =
                    deserialize_obj(&input).context("Failed to deserialize segment")?;

                let lift_receipt = agent.prove(segment)?;

                let serialized =
                    serialize_obj(&lift_receipt).context("Failed to serialize lift receipt")?;

                Ok(serialized)
            }
            Command::Finalize => {
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
                let journal: Journal =
                    deserialize_obj(&inputs[1]).context("Failed to deserialize journal")?;
                let image_id: String =
                    deserialize_obj(&inputs[2]).context("Failed to deserialize image_id")?;

                let finalized = agent.finalize(root, journal, image_id)?;

                let serialized =
                    serialize_obj(&finalized).context("Failed to serialize receipt")?;

                Ok(serialized)
            }
            Command::Resolve => {
                if input.is_empty() {
                    bail!("resolve input is empty");
                }

                let inputs: Vec<Vec<u8>> = serde_json::from_slice(&input)
                    .context("Failed to parse input as Vec<Vec<u8>> for resolve")?;

                if inputs.len() != 3 {
                    bail!("Expected exactly three inputs for resolve, got {}", inputs.len())
                }

                let root: SuccinctReceipt<ReceiptClaim> =
                    deserialize_obj(&inputs[0]).context("Failed to deserialize root receipt")?;

                let union: Option<SuccinctReceipt<Unknown>> =
                    deserialize_obj(&inputs[1]).context("Failed to deserialize union receipt")?;

                let pairs: Vec<(Assumption, AssumptionReceipt)> =
                    deserialize_obj(&inputs[2]).context("Failed to deserialize assumptions")?;

                let root = agent.resolve(root, union, pairs)?;

                let serialized =
                    serialize_obj(&root).context("Failed to serialize conditional receipt")?;

                Ok(serialized)
            }
            Command::Union => {
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

                let unioned = agent.union(left_receipt, right_receipt)?;

                let serialized =
                    serialize_obj(&unioned).context("Failed to serialize union receipt")?;

                Ok(serialized)
            }
            Command::Keccak => {
                if input.is_empty() {
                    bail!("keccak input is empty");
                }

                let prove_keccak_request_local: ProveKeccakRequestLocal =
                    deserialize_obj(&input).context("Failed to deserialize keccak request")?;

                // Conversion is required because the library's `ProveKeccakRequest` type doesn't support deserialization
                let prove_keccak_request = convert(prove_keccak_request_local);

                let keccak_receipt = agent.keccak(prove_keccak_request)?;

                let serialized =
                    serialize_obj(&keccak_receipt).context("Failed to serialize keccak receipt")?;

                Ok(serialized)
            }
            Command::Snark => {
                if input.is_empty() {
                    bail!("get_snark_receipt input is empty");
                }

                let stark_receipt: Receipt =
                    deserialize_obj(&input).context("Failed to parse stark_receipt")?;

                let snark_receipt = agent.stark2snark(stark_receipt)?;

                let serialized =
                    serialize_obj(&snark_receipt).context("Failed to serialize SNARK receipt")?;

                Ok(serialized)
            }
        }
    }
}
