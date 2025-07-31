#[cfg(test)]
mod tests {
    use crate::e2e::tests::setup_cpu_agent_and_metadata_dir;
    use crate::tasks::Agent;
    use anyhow::Context;
    use common::serialization::bincode::deserialize_from_bincode_bytes;
    use common::serialization::mpk::serialize_to_msgpack_bytes;
    use sp1_prover::{CoreSC, SP1PublicValues, SP1VerifyingKey};
    use sp1_sdk::install::plonk_circuit_artifacts_dir;
    use sp1_stark::StarkVerifyingKey;
    use std::fs;

    #[test]
    fn test_e2e_plonk_proof_generation() -> anyhow::Result<()> {
        let (metadata_dir, cpu_agent) =
            setup_cpu_agent_and_metadata_dir().context("Failed to setup")?;

        let wrap_proof = fs::read(
            metadata_dir.join("shard_size_18/fibonacci-elf_shard_size_18_cycles_1M_wrap_proof.bin"),
        )?;

        let plonk_proof_vec = cpu_agent.plonk(wrap_proof).unwrap();

        let plonk_proof = deserialize_from_bincode_bytes(&plonk_proof_vec).unwrap();

        let prover = &cpu_agent.prover;
        let elf_path = metadata_dir.join("elf/fibonacci-elf");
        let serialized_elf_path = serialize_to_msgpack_bytes(&elf_path)?;

        let vk = cpu_agent.setup(serialized_elf_path)?;
        let vk: StarkVerifyingKey<CoreSC> = deserialize_from_bincode_bytes(&vk)?;
        let vk = SP1VerifyingKey { vk };

        let pv_path =
            metadata_dir.join("shard_size_18/fibonacci-elf_shardsize_18_cycles_1M_pv.bin");
        let pv = fs::read(&pv_path)?;
        let pv: SP1PublicValues = deserialize_from_bincode_bytes(&pv)?;

        prover
            .verify_plonk_bn254(&plonk_proof, &vk, &pv, &plonk_circuit_artifacts_dir())
            .expect("Core proof verification failed");

        fs::write(
            metadata_dir
                .join("shard_size_18/fibonacci-elf_shard_size_18_cycles_1M_plonk_proof.bin"),
            plonk_proof_vec,
        )?;

        Ok(())
    }

    #[test]
    fn test_wrap_plonk_proof() -> anyhow::Result<()> {
        let (metadata_dir, cpu_agent) =
            setup_cpu_agent_and_metadata_dir().context("Failed to setup")?;

        let pv_path =
            metadata_dir.join("shard_size_18/fibonacci-elf_shardsize_18_cycles_1M_pv.bin");

        let pv_path = serialize_to_msgpack_bytes(&pv_path)?;
        let plonk_proof_path = metadata_dir
            .join("shard_size_18/fibonacci-elf_shard_size_18_cycles_1M_plonk_proof.bin");
        let plonk_proof = fs::read(&plonk_proof_path).context("Failed to read plonk proof")?;

        let inputs: Vec<Vec<u8>> = vec![pv_path, plonk_proof];
        let packed = serialize_to_msgpack_bytes(&inputs).unwrap();

        let wrapped_plonk_proof = cpu_agent.wrap_plonk(packed)?;

        Ok(())
    }
}
