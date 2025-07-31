#[cfg(test)]
mod tests {
    use crate::e2e::tests::setup_cpu_agent_and_metadata_dir;
    use crate::tasks::Agent;
    use anyhow::Context;
    use common::serialization::bincode::deserialize_from_bincode_bytes;
    use common::serialization::mpk::serialize_to_msgpack_bytes;
    use sp1_prover::{CoreSC, SP1VerifyingKey};
    use sp1_stark::StarkVerifyingKey;
    use std::fs;

    #[test]
    fn test_e2e_shrink_proof_generation() -> anyhow::Result<()> {
        let (metadata_dir, cpu_agent) =
            setup_cpu_agent_and_metadata_dir().context("Failed to setup")?;

        let compressed_proof = fs::read(
            metadata_dir
                .join("shard_size_18/fibonacci-elf_shard_size_18_cycles_1M_compressed_proof.bin"),
        )?;

        let shrink_proof_vec = cpu_agent.shrink(compressed_proof).unwrap();

        let shrink_proof = deserialize_from_bincode_bytes(&shrink_proof_vec).unwrap();

        let prover = &cpu_agent.prover;
        let elf_path = metadata_dir.join("elf/fibonacci-elf");
        let serialized_elf_path = serialize_to_msgpack_bytes(&elf_path)?;

        let vk = cpu_agent.setup(serialized_elf_path)?;
        let vk: StarkVerifyingKey<CoreSC> = deserialize_from_bincode_bytes(&vk)?;
        let vk = SP1VerifyingKey { vk };
        prover.verify_shrink(&shrink_proof, &vk).expect("Core proof verification failed");

        fs::write(
            metadata_dir
                .join("shard_size_18/fibonacci-elf_shard_size_18_cycles_1M_shrink_proof.bin"),
            shrink_proof_vec,
        )?;

        Ok(())
    }
}
