use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use common::serialization::bincode::{deserialize_from_bincode_bytes, serialize_to_bincode_bytes};
use common::serialization::mpk::deserialize_from_msgpack_bytes;
use sp1_core_executor::SP1ReduceProof;
use sp1_prover::{CoreSC, InnerSC, SP1_CIRCUIT_VERSION};
use sp1_recursion_gnark_ffi::{Groth16Bn254Proof, PlonkBn254Proof};
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues, SP1PublicValues};
use sp1_stark::ShardProof;
use std::any::Any;
use std::fs;
use tracing::info;

pub(crate) mod cpu_agent;
pub mod factory;
pub(crate) mod gpu_agent;

const PROVE_INPUT_LEN: usize = 3;
const PROVE_LIFT_INPUT_LEN: usize = 3;
const COMPRESS_INPUT_LEN: usize = 3;
const GROTH16_INPUT_LEN: usize = 2;
const PLONK_INPUT_LEN: usize = 2;

#[async_trait]
pub trait Agent: Send + Sync {
    fn name(&self) -> &'static str;
    fn as_any(self: Box<Self>) -> Box<dyn Any>;
    fn setup(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn prove(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn prove_lift(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn compress(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn shrink(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn wrap(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn groth16(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn plonk(&self, input: Vec<u8>) -> Result<Vec<u8>>;

    fn wrap_compress(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::wrap_compress()");
        if input.is_empty() {
            bail!("wrap_compress input is empty");
        }

        let inputs: Vec<Vec<u8>> = deserialize_from_msgpack_bytes(&input)
            .context("Failed to parse input as Vec<Vec<u8>>")?;

        if inputs.len() != 2 {
            bail!("Expected 2 inputs for wrap_compress, got {}", inputs.len());
        }

        let public_values_path: String = deserialize_from_msgpack_bytes(&inputs[0])
            .context("Failed to deserialize record path")?;

        let compress_proof: SP1ReduceProof<InnerSC> = deserialize_from_bincode_bytes(&inputs[1])
            .context("Failed to deserialize compress proof")?;

        let public_values_vec = fs::read(&public_values_path)
            .with_context(|| format!("Failed to read record file at {}", public_values_path))?;

        let public_values: SP1PublicValues = deserialize_from_bincode_bytes(&public_values_vec)
            .context("Failed to deserialize public values")?;

        let compressed_proof_with_public_values: SP1ProofWithPublicValues =
            SP1ProofWithPublicValues {
                proof: SP1Proof::Compressed(Box::from(compress_proof)),
                public_values,
                sp1_version: SP1_CIRCUIT_VERSION.to_string(),
                tee_proof: None,
            };
        let serialized = serialize_to_bincode_bytes(&compressed_proof_with_public_values)
            .expect("Failed to serialize");
        Ok(serialized)
    }
}
