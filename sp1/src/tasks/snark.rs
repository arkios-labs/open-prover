use crate::tasks::agent::Sp1Agent;
use crate::tasks::{Groth16Input, PlonkInput, VerifyGroth16Input, VerifyPlonkInput};
use anyhow::{Context, Result};
use common::serialization::NestedArgBytes;
use common::serialization::bincode::{
    Bincode, deserialize_from_bincode_bytes, serialize_to_bincode_bytes,
};
use common::serialization::mpk::Msgpack;
use sp1_prover::{SP1_CIRCUIT_VERSION, SP1PublicValues, SP1VerifyingKey};
use sp1_sdk::install::try_install_circuit_artifacts;
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues};
use std::fs;
use std::time::Instant;
use tracing::info;

impl Sp1Agent {
    pub fn groth16(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::groth16()");
        let start_time = Instant::now();

        let (Msgpack(public_values_path), Bincode(wrap_proof)): Groth16Input =
            NestedArgBytes::from_nested_arg_bytes(&input)
                .context("Failed to parse groth16 input")?;

        let public_values_vec = fs::read(&public_values_path)
            .with_context(|| format!("Failed to read record file at {}", public_values_path))?;
        let public_values: SP1PublicValues = deserialize_from_bincode_bytes(&public_values_vec)
            .context("Failed to deserialize public_values")?;

        let groth16_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
            sp1_prover::build::try_build_groth16_bn254_artifacts_dev(
                &wrap_proof.vk,
                &wrap_proof.proof,
            )
        } else {
            try_install_circuit_artifacts("groth16")
        };

        let groth16_proof = self.prover.wrap_groth16_bn254(wrap_proof, &groth16_bn254_artifacts);

        let groth16_proof_with_public_values: SP1ProofWithPublicValues = SP1ProofWithPublicValues {
            proof: SP1Proof::Groth16(groth16_proof),
            public_values,
            sp1_version: SP1_CIRCUIT_VERSION.to_string(),
            tee_proof: None,
        };

        let serialized = serialize_to_bincode_bytes(&groth16_proof_with_public_values)
            .context("Failed to serialize groth16_proof")?;
        let elapsed = start_time.elapsed();
        info!("Agent::groth16() took {:?}", elapsed);
        Ok(serialized)
    }

    pub fn plonk(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::plonk()");
        let start_time = Instant::now();

        let (Msgpack(public_values_path), Bincode(wrap_proof)): PlonkInput =
            NestedArgBytes::from_nested_arg_bytes(&input).context("Failed to parse plonk input")?;

        let public_values_vec = fs::read(&public_values_path)
            .with_context(|| format!("Failed to read record file at {}", public_values_path))?;
        let public_values: SP1PublicValues = deserialize_from_bincode_bytes(&public_values_vec)
            .context("Failed to deserialize public_values")?;

        let plonk_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
            sp1_prover::build::try_build_plonk_bn254_artifacts_dev(
                &wrap_proof.vk,
                &wrap_proof.proof,
            )
        } else {
            try_install_circuit_artifacts("plonk")
        };

        let plonk_proof = self.prover.wrap_plonk_bn254(wrap_proof, &plonk_bn254_artifacts);

        let plonk_proof_with_public_values: SP1ProofWithPublicValues = SP1ProofWithPublicValues {
            proof: SP1Proof::Plonk(plonk_proof),
            public_values,
            sp1_version: SP1_CIRCUIT_VERSION.to_string(),
            tee_proof: None,
        };

        let serialized = serialize_to_bincode_bytes(&plonk_proof_with_public_values)
            .context("Failed to serialize plonk_proof")?;
        let elapsed = start_time.elapsed();
        info!("Agent::plonk() took {:?}", elapsed);
        Ok(serialized)
    }

    pub fn verify_groth16(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::verify_groth16()");
        let start_time = Instant::now();

        let (Bincode(groth16_proof), (Bincode(vk), Msgpack(public_values_path))): VerifyGroth16Input =
            NestedArgBytes::from_nested_arg_bytes(&input).context("Failed to parse verify_groth16 input")?;

        let vk = SP1VerifyingKey { vk };

        let public_values_vec = fs::read(&public_values_path)
            .with_context(|| format!("Failed to read record file at {}", public_values_path))?;

        let public_values: SP1PublicValues = deserialize_from_bincode_bytes(&public_values_vec)
            .context("Failed to deserialize public_values")?;

        let groth16_bn254_artifacts = try_install_circuit_artifacts("groth16");

        self.prover
            .verify_groth16_bn254(
                &groth16_proof.proof.try_as_groth_16().unwrap(),
                &vk,
                &public_values,
                &groth16_bn254_artifacts,
            )
            .context("Groth16 proof verification failed")?;

        let result = serialize_to_bincode_bytes(&true).context("Failed to serialize result")?;
        let elapsed = start_time.elapsed();
        info!("Agent::verify_groth16() took {:?}", elapsed);
        Ok(result)
    }

    pub fn verify_plonk(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::verify_plonk()");
        let start_time = Instant::now();

        let (Bincode(plonk_proof), (Bincode(vk), Msgpack(public_values_path))): VerifyPlonkInput =
            NestedArgBytes::from_nested_arg_bytes(&input)
                .context("Failed to parse verify_plonk input")?;

        let vk = SP1VerifyingKey { vk };

        let public_values_vec = fs::read(&public_values_path)
            .with_context(|| format!("Failed to read record file at {}", public_values_path))?;

        let public_values: SP1PublicValues = deserialize_from_bincode_bytes(&public_values_vec)
            .context("Failed to deserialize public_values")?;

        let plonk_bn254_artifacts = try_install_circuit_artifacts("plonk");

        self.prover
            .verify_plonk_bn254(
                &plonk_proof.proof.try_as_plonk().unwrap(),
                &vk,
                &public_values,
                &plonk_bn254_artifacts,
            )
            .context("Plonk proof verification failed")?;

        let result = serialize_to_bincode_bytes(&true).context("Failed to serialize result")?;
        let elapsed = start_time.elapsed();
        info!("Agent::verify_plonk() took {:?}", elapsed);
        Ok(result)
    }
}
