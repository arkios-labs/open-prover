#[cfg(test)]
mod tests {
    use crate::e2e::tests::{setup, setup_agent_and_metadata_dir};
    use crate::tasks::{PlonkInput, VerifyPlonkInput};
    use anyhow::{Context, Result};
    use common::serialization::bincode::deserialize_from_bincode_bytes;
    use sp1_prover::{SP1PublicValues, SP1VerifyingKey};
    use sp1_sdk::SP1ProofWithPublicValues;
    use sp1_sdk::install::plonk_circuit_artifacts_dir;
    use std::fs;

    #[test]
    fn test_e2e_plonk_proof_generation() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let pv_path = metadata_dir.join("public_value/fibonacci-elf_shardsize_14_pv.bin");
        let pv = fs::read(&pv_path).context("Failed to read public_values")?;
        let pv =
            deserialize_from_bincode_bytes(&pv).context("Failed to deserialize public_values")?;

        let wrap_proof =
            fs::read(metadata_dir.join("proof/fibonacci-elf_shard_size_14_wrap_proof.bin"))
                .context("Failed to read wrap_proof")?;
        let wrap_proof = deserialize_from_bincode_bytes(&wrap_proof)
            .context("Failed to deserialize wrap_proof")?;

        let plonk_input = PlonkInput { public_values: pv, wrap_proof };
        let plonk_output = agent.plonk(plonk_input).context("Failed to plonk")?;
        let plonk_proof: SP1ProofWithPublicValues =
            deserialize_from_bincode_bytes(&plonk_output.plonk_proof)
                .expect("Failed to deserialize proof");

        let elf_path = metadata_dir.join("elf/fibonacci-elf.bin");

        let stdin_path = metadata_dir.join("stdin/fibonacci-elf_shardsize_14_stdin.bin");
        let (_, vk, _, _, _) = setup(&agent, &elf_path, &stdin_path).context("Failed to setup")?;
        let vk = SP1VerifyingKey { vk };

        let pv = fs::read(&pv_path)?;
        let pv: SP1PublicValues =
            deserialize_from_bincode_bytes(&pv).context("Failed to deserialize public_values")?;

        let prover = &agent.prover;
        prover
            .verify_plonk_bn254(
                &plonk_proof.proof.try_as_plonk().unwrap(),
                &vk,
                &pv,
                &plonk_circuit_artifacts_dir(),
            )
            .expect("Core proof verification failed");
        Ok(())
    }

    #[test]
    fn test_verify_plonk_proof() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let elf_path = metadata_dir.join("elf/fibonacci-elf.bin");

        let stdin_path = metadata_dir.join("stdin/fibonacci-elf_shardsize_14_stdin.bin");
        let (_, vk, _, _, _) = setup(&agent, &elf_path, &stdin_path).context("Failed to setup")?;

        let plonk_proof_path =
            metadata_dir.join("proof/fibonacci-elf_shard_size_14_plonk_proof.bin");
        let plonk_proof = fs::read(&plonk_proof_path).context("Failed to read plonk proof")?;
        let plonk_proof = deserialize_from_bincode_bytes(&plonk_proof)
            .context("Failed to deserialize plonk_proof")?;

        let pv_path = metadata_dir.join("public_value/fibonacci-elf_shardsize_14_pv.bin");
        let pv = fs::read(&pv_path).context("Failed to read public_values")?;
        let pv =
            deserialize_from_bincode_bytes(&pv).context("Failed to deserialize public_values")?;

        let verify_groth16_input =
            VerifyPlonkInput { plonk_proof, vk: SP1VerifyingKey { vk }, public_values: pv };

        agent.verify_plonk(verify_groth16_input).context("Failed to verify plonk")?;
        Ok(())
    }
}
