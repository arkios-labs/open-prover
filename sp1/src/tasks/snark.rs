use crate::tasks::agent::Sp1Agent;
use crate::tasks::{
    Groth16Input, Groth16Output, PlonkInput, PlonkOutput, VerifyGroth16Input, VerifyPlonkInput,
};
use anyhow::{Context, Result};
use common::serialization::bincode::serialize_to_bincode_bytes;
use sp1_prover::SP1_CIRCUIT_VERSION;
use sp1_sdk::install::try_install_circuit_artifacts;
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues};
use std::time::Instant;
use tracing::info;

impl Sp1Agent {
    pub fn groth16(&self, groth16_input: Groth16Input) -> Result<Groth16Output> {
        info!("Agent::groth16()");
        let start_time = Instant::now();

        let wrap_proof = groth16_input.wrap_proof;

        let groth16_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
            sp1_prover::build::try_build_groth16_bn254_artifacts_dev(
                &wrap_proof.vk,
                &wrap_proof.proof,
            )
        } else {
            try_install_circuit_artifacts("groth16")
        };

        let groth16_proof = self.prover.wrap_groth16_bn254(wrap_proof, &groth16_bn254_artifacts);

        let groth16_proof: SP1ProofWithPublicValues = SP1ProofWithPublicValues {
            proof: SP1Proof::Groth16(groth16_proof),
            public_values: groth16_input.public_values,
            sp1_version: SP1_CIRCUIT_VERSION.to_string(),
            tee_proof: None,
        };

        let serialized = serialize_to_bincode_bytes(&groth16_proof)
            .context("Failed to serialize groth16_proof")?;
        let groth16_output = Groth16Output { groth16_proof: serialized };

        let elapsed = start_time.elapsed();
        info!("Agent::groth16() took {:?}", elapsed);
        Ok(groth16_output)
    }

    pub fn plonk(&self, plonk_input: PlonkInput) -> Result<PlonkOutput> {
        info!("Agent::plonk()");
        let start_time = Instant::now();

        let wrap_proof = plonk_input.wrap_proof;

        let plonk_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
            sp1_prover::build::try_build_plonk_bn254_artifacts_dev(
                &wrap_proof.vk,
                &wrap_proof.proof,
            )
        } else {
            try_install_circuit_artifacts("plonk")
        };

        let plonk_proof = self.prover.wrap_plonk_bn254(wrap_proof, &plonk_bn254_artifacts);

        let plonk_proof: SP1ProofWithPublicValues = SP1ProofWithPublicValues {
            proof: SP1Proof::Plonk(plonk_proof),
            public_values: plonk_input.public_values,
            sp1_version: SP1_CIRCUIT_VERSION.to_string(),
            tee_proof: None,
        };

        let plonk_proof =
            serialize_to_bincode_bytes(&plonk_proof).context("Failed to serialize plonk_proof")?;
        let plonk_output = PlonkOutput { plonk_proof };

        let elapsed = start_time.elapsed();
        info!("Agent::plonk() took {:?}", elapsed);
        Ok(plonk_output)
    }

    pub fn verify_groth16(&self, verify_groth16_input: VerifyGroth16Input) -> Result<()> {
        info!("Agent::verify_groth16()");
        let start_time = Instant::now();

        let groth16_bn254_artifacts = try_install_circuit_artifacts("groth16");

        self.prover
            .verify_groth16_bn254(
                &verify_groth16_input.groth16_proof.proof.try_as_groth_16().unwrap(),
                &verify_groth16_input.vk,
                &verify_groth16_input.public_values,
                &groth16_bn254_artifacts,
            )
            .context("Groth16 proof verification failed")?;

        let elapsed = start_time.elapsed();
        info!("Agent::verify_groth16() took {:?}", elapsed);
        Ok(())
    }

    pub fn verify_plonk(&self, verify_plonk_input: VerifyPlonkInput) -> Result<()> {
        info!("Agent::verify_plonk()");
        let start_time = Instant::now();

        let plonk_bn254_artifacts = try_install_circuit_artifacts("plonk");

        self.prover
            .verify_plonk_bn254(
                &verify_plonk_input.plonk_proof.proof.try_as_plonk().unwrap(),
                &verify_plonk_input.vk,
                &verify_plonk_input.public_values,
                &plonk_bn254_artifacts,
            )
            .context("Plonk proof verification failed")?;

        let elapsed = start_time.elapsed();
        info!("Agent::verify_plonk() took {:?}", elapsed);
        Ok(())
    }
}
