#[cfg(test)]
mod tests {
    use crate::e2e::tests::{setup, setup_agent_and_metadata_dir};
    use crate::tasks::{Groth16Input, VerifyGroth16Input};
    use anyhow::{Context, Result};
    use common::serialization::bincode::deserialize_from_bincode_bytes;
    use sp1_prover::{SP1PublicValues, SP1VerifyingKey};
    use sp1_sdk::SP1ProofWithPublicValues;
    use sp1_sdk::install::groth16_circuit_artifacts_dir;
    use std::fs;

    #[test]
    fn test_e2e_groth16_proof_generation() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let pv_path = metadata_dir.join("public_value/fibonacci-elf_shardsize_14_pv.bin");
        let pv = fs::read(&pv_path).context("Failed to read public_values")?;
        let pv =
            deserialize_from_bincode_bytes(&pv).context("Failed to deserialize public_values")?;

        let wrap_proof =
            fs::read(metadata_dir.join("proof/fibonacci-elf_shard_size_14_wrap_proof.bin"))?;
        let wrap_proof = deserialize_from_bincode_bytes(&wrap_proof)
            .context("Failed to deserialize wrap_proof")?;

        let groth16_input = Groth16Input { public_values: pv, wrap_proof };

        let groth16_output = agent.groth16(groth16_input).context("Failed to generate proof")?;
        let groth16_proof: SP1ProofWithPublicValues =
            deserialize_from_bincode_bytes(&groth16_output.groth16_proof)
                .expect("Failed to deserialize proof");

        let prover = &agent.prover;
        let elf_path = metadata_dir.join("elf/fibonacci-elf.bin");

        let stdin_path = metadata_dir.join("stdin/fibonacci-elf_shardsize_14_stdin.bin");
        let (_, vk, _, _, _) = setup(&agent, &elf_path, &stdin_path).context("Failed to setup")?;

        let pv = fs::read(&pv_path)?;
        let pv: SP1PublicValues =
            deserialize_from_bincode_bytes(&pv).context("Failed to deserialize public_values")?;

        prover
            .verify_groth16_bn254(
                &groth16_proof.proof.try_as_groth_16().unwrap(),
                &SP1VerifyingKey { vk },
                &pv,
                &groth16_circuit_artifacts_dir(),
            )
            .expect("Core proof verification failed");

        Ok(())
    }

    #[test]
    fn test_verify_groth16_proof() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let elf_path = metadata_dir.join("elf/fibonacci-elf.bin");

        let stdin_path = metadata_dir.join("stdin/fibonacci-elf_shardsize_14_stdin.bin");
        let (_, vk, _, _, _) = setup(&agent, &elf_path, &stdin_path).context("Failed to setup")?;

        let groth16_proof_path =
            metadata_dir.join("proof/fibonacci-elf_shard_size_14_groth16_proof.bin");
        let groth16_proof =
            fs::read(&groth16_proof_path).context("Failed to read groth16 proof")?;
        let groth16_proof = deserialize_from_bincode_bytes(&groth16_proof)
            .context("Failed to deserialize groth16_proof")?;

        let pv_path = metadata_dir.join("public_value/fibonacci-elf_shardsize_14_pv.bin");
        let pv = fs::read(&pv_path).context("Failed to read public_values")?;
        let pv =
            deserialize_from_bincode_bytes(&pv).context("Failed to deserialize public_values")?;

        let verify_groth16_input =
            VerifyGroth16Input { groth16_proof, vk: SP1VerifyingKey { vk }, public_values: pv };

        agent.verify_groth16(verify_groth16_input).context("Failed to verify proof")?;

        Ok(())
    }
}
