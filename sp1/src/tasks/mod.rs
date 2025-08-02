use crate::tasks::cpu_agent::CpuAgent;
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

#[async_trait]
pub trait Agent: Send + Sync {
    fn name(&self) -> &'static str;
    fn as_any(self: Box<Self>) -> Box<dyn Any>;
    fn setup(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        CpuAgent::new().setup(input)
    }
    fn prove(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        CpuAgent::new().prove(input)
    }

    fn prove_lift(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        CpuAgent::new().prove_lift(input)
    }

    fn compress(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        CpuAgent::new().compress(input)
    }

    fn shrink(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        CpuAgent::new().shrink(input)
    }

    fn wrap(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        CpuAgent::new().wrap(input)
    }

    fn groth16(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        CpuAgent::new().groth16(input)
    }

    fn plonk(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        CpuAgent::new().plonk(input)
    }

    fn wrap_core(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::wrap_core()");

        if input.is_empty() {
            bail!("wrap_core input is empty");
        }

        let inputs: Vec<Vec<u8>> = deserialize_from_msgpack_bytes(&input)
            .context("Failed to parse input as Vec<Vec<u8>>")?;

        if inputs.len() != 2 {
            bail!("Expected 2 inputs for wrap_core, got {}", inputs.len());
        }

        let public_values_path: String = deserialize_from_msgpack_bytes(&inputs[0])
            .context("Failed to deserialize public_values path")?;

        let shard_proofs: Vec<ShardProof<CoreSC>> = deserialize_from_msgpack_bytes(&inputs[1])
            .context("Failed to deserialize shard proofs")?;

        let public_values_vec = fs::read(&public_values_path)
            .with_context(|| format!("Failed to read record file at {}", public_values_path))?;

        let public_values: SP1PublicValues = deserialize_from_bincode_bytes(&public_values_vec)
            .context("Failed to deserialize public values")?;

        let core_proof_with_public_values: SP1ProofWithPublicValues = SP1ProofWithPublicValues {
            proof: SP1Proof::Core(shard_proofs),
            public_values,
            sp1_version: SP1_CIRCUIT_VERSION.to_string(),
            tee_proof: None,
        };
        let serialized = serialize_to_bincode_bytes(&core_proof_with_public_values)
            .expect("Failed to serialize");
        Ok(serialized)
    }

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

    fn wrap_groth16(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::wrap_groth16()");
        if input.is_empty() {
            bail!("core input is empty");
        }

        let inputs: Vec<Vec<u8>> = deserialize_from_msgpack_bytes(&input)
            .context("Failed to parse input as Vec<Vec<u8>>")?;

        if inputs.len() != 2 {
            bail!("Expected 2 inputs for wrap_groth16, got {}", inputs.len());
        }

        let public_values_path: String = deserialize_from_msgpack_bytes(&inputs[0])
            .context("Failed to deserialize record path")?;

        let groth16_proof: Groth16Bn254Proof = deserialize_from_bincode_bytes(&inputs[1])
            .context("Failed to deserialize groth16 proof")?;

        let public_values_vec = fs::read(&public_values_path)
            .with_context(|| format!("Failed to read record file at {}", public_values_path))?;

        let public_values: SP1PublicValues = deserialize_from_bincode_bytes(&public_values_vec)
            .context("Failed to deserialize public values")?;

        let groth16_proof_with_public_values: SP1ProofWithPublicValues = SP1ProofWithPublicValues {
            proof: SP1Proof::Groth16(groth16_proof),
            public_values,
            sp1_version: SP1_CIRCUIT_VERSION.to_string(),
            tee_proof: None,
        };
        let serialized = serialize_to_bincode_bytes(&groth16_proof_with_public_values)
            .expect("Failed to serialize");
        Ok(serialized)
    }

    fn wrap_plonk(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::wrap_plonk()");
        if input.is_empty() {
            bail!("core input is empty");
        }

        let inputs: Vec<Vec<u8>> = deserialize_from_msgpack_bytes(&input)
            .context("Failed to parse input as Vec<Vec<u8>>")?;

        if inputs.len() != 2 {
            bail!("Expected 2 inputs for wrap_plonk, got {}", inputs.len());
        }

        let public_values_path: String = deserialize_from_msgpack_bytes(&inputs[0])
            .context("Failed to deserialize record path")?;

        let plonk_proof: PlonkBn254Proof = deserialize_from_bincode_bytes(&inputs[1])
            .context("Failed to deserialize plonk proof")?;

        let public_values_vec = fs::read(&public_values_path)
            .with_context(|| format!("Failed to read record file at {}", public_values_path))?;

        let public_values: SP1PublicValues = deserialize_from_bincode_bytes(&public_values_vec)
            .context("Failed to deserialize public values")?;

        let plonk_proof_with_public_values: SP1ProofWithPublicValues = SP1ProofWithPublicValues {
            proof: SP1Proof::Plonk(plonk_proof),
            public_values,
            sp1_version: SP1_CIRCUIT_VERSION.to_string(),
            tee_proof: None,
        };

        let serialized = serialize_to_bincode_bytes(&plonk_proof_with_public_values)
            .expect("Failed to serialize");
        Ok(serialized)
    }
}
