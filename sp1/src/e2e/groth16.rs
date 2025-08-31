#[cfg(test)]
mod tests {
    use crate::e2e::tests::setup_agent_and_metadata_dir;
    use crate::tasks::Agent;
    use anyhow::Context;
    use common::serialization::bincode::deserialize_from_bincode_bytes;
    use common::serialization::mpk::serialize_to_msgpack_bytes;
    use sp1_prover::{CoreSC, SP1PublicValues, SP1VerifyingKey};
    use sp1_sdk::SP1ProofWithPublicValues;
    use sp1_sdk::install::groth16_circuit_artifacts_dir;
    use sp1_stark::StarkVerifyingKey;
    use std::fs;

    #[test]
    fn test_e2e_groth16_proof_generation() -> anyhow::Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let pv_path = metadata_dir.join("public_value/fibonacci-elf_shardsize_14_pv.bin");
        let pv_path_packed = serialize_to_msgpack_bytes(&pv_path)?;

        let wrap_proof =
            fs::read(metadata_dir.join("proof/fibonacci-elf_shard_size_14_wrap_proof.bin"))?;

        let inputs: Vec<Vec<u8>> = vec![pv_path_packed, wrap_proof];
        let inputs_packed =
            serialize_to_msgpack_bytes(&inputs).expect("Failed to serialize inputs");

        let groth16_proof_vec = agent.groth16(inputs_packed).expect("Failed to generate proof");
        let groth16_proof: SP1ProofWithPublicValues =
            deserialize_from_bincode_bytes(&groth16_proof_vec)
                .expect("Failed to deserialize proof");

        let prover = &agent.prover;
        let elf_path = metadata_dir.join("elf/fibonacci-elf");
        let elf_path_packed = serialize_to_msgpack_bytes(&elf_path)?;

        let vk = agent.setup(elf_path_packed)?;
        let vk: StarkVerifyingKey<CoreSC> = deserialize_from_bincode_bytes(&vk)?;
        let vk = SP1VerifyingKey { vk };

        let pv = fs::read(&pv_path)?;
        let pv: SP1PublicValues = deserialize_from_bincode_bytes(&pv)?;

        prover
            .verify_groth16_bn254(
                &groth16_proof.proof.try_as_groth_16().unwrap(),
                &vk,
                &pv,
                &groth16_circuit_artifacts_dir(),
            )
            .expect("Core proof verification failed");

        Ok(())
    }

    #[test]
    fn test_verify_groth16_proof() -> anyhow::Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let elf_path = metadata_dir.join("elf/fibonacci-elf");
        let elf_path_packed =
            serialize_to_msgpack_bytes(&elf_path).context("Failed to serialize")?;

        let vk = agent.setup(elf_path_packed).context("Failed to setup")?;

        let groth16_proof_path =
            metadata_dir.join("proof/fibonacci-elf_shard_size_14_groth16_proof.bin");
        let groth16_proof_file =
            fs::read(&groth16_proof_path).context("Failed to read groth16 proof")?;

        let pv_path = metadata_dir.join("public_value/fibonacci-elf_shardsize_14_pv.bin");
        let pv_path_packed =
            serialize_to_msgpack_bytes(&pv_path).context("Failed to serialize pv")?;

        let verify_inputs: Vec<Vec<u8>> = vec![groth16_proof_file, vk, pv_path_packed];
        let verify_inputs_packed =
            serialize_to_msgpack_bytes(&verify_inputs).context("Failed to serialize")?;

        let verify_result =
            agent.verify_groth16(verify_inputs_packed).context("Failed to verify")?;
        let verify_success: bool =
            deserialize_from_bincode_bytes(&verify_result).context("Failed to deserialize")?;
        assert!(verify_success, "Groth16 proof verification should succeed");

        Ok(())
    }
}
