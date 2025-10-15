#[cfg(test)]
mod tests {
    use crate::e2e::tests::{setup, setup_agent_and_metadata_dir};
    use crate::tasks::ShrinkWrapInput;
    use anyhow::{Context, Result};
    use common::serialization::bincode::deserialize_from_bincode_bytes;
    use sp1_core_executor::SP1ReduceProof;
    use sp1_prover::{InnerSC, SP1VerifyingKey};
    use sp1_sdk::SP1ProofWithPublicValues;
    use std::fs;

    #[test]
    fn test_e2e_wrap_proof_generation() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let compressed_proof =
            fs::read(metadata_dir.join("proof/fibonacci-elf_shard_size_14_compressed_proof.bin"))
                .context("Failed to read compressed_proof")?;

        let compressed_proof: SP1ProofWithPublicValues =
            deserialize_from_bincode_bytes(&compressed_proof)
                .context("Failed to deserialize compressed_proof")?;
        let reduce_proof: SP1ReduceProof<InnerSC> =
            *compressed_proof.proof.try_as_compressed().unwrap();

        let shrink_wrap_input = ShrinkWrapInput { reduce_proof };
        let shrink_wrap_output =
            agent.shrink_wrap(shrink_wrap_input).context("Failed to shrink wrap")?;

        let wrap_proof = deserialize_from_bincode_bytes(&shrink_wrap_output.wrap_proof)
            .context("Failed to deserialize wrap_proof")?;

        let prover = &agent.prover;

        let elf_path = metadata_dir.join("elf/fibonacci-elf");

        let stdin_path = metadata_dir.join("stdin/fibonacci-elf_shardsize_14_stdin.bin");
        let (_, vk, _, _, _) = setup(&agent, &elf_path, &stdin_path).context("Failed to setup")?;
        let vk = SP1VerifyingKey { vk };

        prover.verify_wrap_bn254(&wrap_proof, &vk).expect("Wrap proof verification failed");

        Ok(())
    }
}
