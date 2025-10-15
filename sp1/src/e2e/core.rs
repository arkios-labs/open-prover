#[cfg(test)]
mod tests {
    use crate::e2e::tests::{setup, setup_agent_and_metadata_dir};
    use crate::tasks::ProveInput;
    use anyhow::{Context, Result};
    use common::serialization::bincode::deserialize_from_bincode_bytes;
    use sp1_core_machine::io::SP1Stdin;
    use sp1_prover::{CoreSC, SP1VerifyingKey};
    use sp1_prover::{SP1CoreProof, SP1CoreProofData, SP1PublicValues};
    use sp1_stark::ShardProof;
    use std::fs;
    use tracing::info;

    #[test]
    fn test_e2e_fibonacci_core_proof_generation() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let pv_path = metadata_dir.join("public_value/fibonacci-elf_shardsize_14_pv.bin");
        let pv = fs::read(&pv_path).context("Failed to read pv_path")?;
        let pv: SP1PublicValues =
            deserialize_from_bincode_bytes(&pv).context("Failed to deserialize public_values")?;

        let stdin_path = metadata_dir.join("stdin/fibonacci-elf_shardsize_14_stdin.bin");
        let stdin = fs::read(&stdin_path).context("Failed to read stdin_path")?;
        let stdin: SP1Stdin =
            deserialize_from_bincode_bytes(&stdin).context("Failed to deserialize stdin")?;

        let prover = &agent.prover;

        let mut proofs: Vec<ShardProof<CoreSC>> = vec![];
        let elf_path = metadata_dir.join("elf/fibonacci-elf");
        let (elf, vk, _, _, challenger) =
            setup(&agent, &elf_path, &stdin_path).context("Failed to setup")?;

        for i in 1..=3 {
            let record_path =
                metadata_dir.join(format!("record/fibonacci-elf_shardsize_14_record_{}.bin", i));
            let record = fs::read(&record_path).context("Failed to read record")?;
            let record =
                deserialize_from_bincode_bytes(&record).context("Failed to deserialize record")?;

            let prove_input =
                ProveInput { record, elf: &elf, vk: &vk, challenger: challenger.clone() };

            let prove_output = agent.prove(prove_input).context("Failed to prove")?;
            let shard_proof: ShardProof<CoreSC> =
                deserialize_from_bincode_bytes(&prove_output.shard_proof)
                    .context("Failed to deserialize shard_proof")?;
            proofs.push(shard_proof);
        }

        let core_proof = SP1CoreProof {
            proof: SP1CoreProofData(proofs),
            stdin: stdin.clone(),
            public_values: pv,
            cycles: 0,
        };

        let vk = SP1VerifyingKey { vk };

        prover.verify(&core_proof.proof, &vk).expect("Core proof verification failed");

        info!("Core proof verification succeeded.");

        Ok(())
    }

    #[test]
    fn test_e2e_keccak_core_proof_generation() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let pv_path = metadata_dir.join("public_value/keccak-elf_shardsize_14_pv.bin");
        let pv = fs::read(&pv_path).context("Failed to read pv_path")?;
        let pv: SP1PublicValues =
            deserialize_from_bincode_bytes(&pv).context("Failed to deserialize public_values")?;

        let stdin_path = metadata_dir.join("stdin/keccak-elf_shardsize_14_stdin.bin");
        let stdin = fs::read(&stdin_path).context("Failed to read stdin_path")?;
        let stdin: SP1Stdin =
            deserialize_from_bincode_bytes(&stdin).context("Failed to deserialize stdin")?;

        let prover = &agent.prover;

        let mut proofs: Vec<ShardProof<CoreSC>> = vec![];
        let elf_path = metadata_dir.join("elf/keccak-elf");
        let (elf, vk, _, _, challenger) =
            setup(&agent, &elf_path, &stdin_path).context("Failed to setup")?;

        for i in 1..=4 {
            let record_path =
                metadata_dir.join(format!("record/keccak-elf_shardsize_14_record_{}.bin", i));
            let record = fs::read(&record_path).context("Failed to read record")?;
            let record =
                deserialize_from_bincode_bytes(&record).context("Failed to deserialize record")?;

            let prove_input =
                ProveInput { record, elf: &elf, vk: &vk, challenger: challenger.clone() };

            let prove_output = agent.prove(prove_input).context("Failed to prove")?;
            let shard_proof: ShardProof<CoreSC> =
                deserialize_from_bincode_bytes(&prove_output.shard_proof)
                    .context("Failed to deserialize shard_proof")?;
            proofs.push(shard_proof);
        }

        let core_proof = SP1CoreProof {
            proof: SP1CoreProofData(proofs),
            stdin: stdin.clone(),
            public_values: pv,
            cycles: 0,
        };

        let vk = SP1VerifyingKey { vk };

        prover.verify(&core_proof.proof, &vk).expect("Core proof verification failed");

        info!("Core proof verification succeeded.");

        Ok(())
    }
}
