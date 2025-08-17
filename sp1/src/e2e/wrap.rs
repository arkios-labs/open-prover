#[cfg(test)]
mod tests {
    use crate::e2e::tests::setup_agent_and_metadata_dir;
    use crate::tasks::Agent;
    use anyhow::Context;
    use common::serialization::bincode::{
        deserialize_from_bincode_bytes, serialize_to_bincode_bytes,
    };
    use common::serialization::mpk::serialize_to_msgpack_bytes;
    use sp1_core_executor::SP1ReduceProof;
    use sp1_prover::{CoreSC, InnerSC, SP1VerifyingKey};
    use sp1_sdk::SP1ProofWithPublicValues;
    use sp1_stark::StarkVerifyingKey;
    use std::fs;

    #[test]
    fn test_e2e_wrap_proof_generation() -> anyhow::Result<()> {
        let (metadata_dir, cpu_agent) =
            setup_agent_and_metadata_dir().context("Failed to setup")?;

        let compressed_proof =
            fs::read(metadata_dir.join("proof/fibonacci-elf_shard_size_14_compressed_proof.bin"))?;

        let compressed_proof: SP1ProofWithPublicValues =
            deserialize_from_bincode_bytes(&compressed_proof)?;
        let compressed_proof: SP1ReduceProof<InnerSC> =
            *compressed_proof.proof.try_as_compressed().unwrap();
        let compressed_proof_serialized =
            serialize_to_bincode_bytes(&compressed_proof).expect("Failed to serialize");

        let wrap_proof_vec = cpu_agent.shrink_wrap(compressed_proof_serialized).unwrap();
        let wrap_proof = deserialize_from_bincode_bytes(&wrap_proof_vec).unwrap();

        let prover = &cpu_agent.prover;

        let elf_path = metadata_dir.join("elf/fibonacci-elf");
        let elf_path_packed = serialize_to_msgpack_bytes(&elf_path)?;

        let vk = cpu_agent.setup(elf_path_packed)?;
        let vk: StarkVerifyingKey<CoreSC> = deserialize_from_bincode_bytes(&vk)?;
        let vk = SP1VerifyingKey { vk };

        prover.verify_wrap_bn254(&wrap_proof, &vk).expect("Wrap proof verification failed");

        Ok(())
    }
}
