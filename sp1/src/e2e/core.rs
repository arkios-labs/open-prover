#[cfg(test)]
mod tests {
    use crate::e2e::tests::setup_cpu_agent_and_metadata_dir;
    use crate::tasks::Agent;
    use anyhow::Context;
    use common::serialization::bincode::{
        deserialize_from_bincode_bytes, serialize_to_bincode_bytes,
    };
    use common::serialization::mpk::serialize_to_msgpack_bytes;
    use sp1_core_machine::io::SP1Stdin;
    use sp1_prover::{CoreSC, SP1VerifyingKey};
    use sp1_prover::{SP1CoreProof, SP1CoreProofData, SP1PublicValues};
    use sp1_stark::{ShardProof, StarkVerifyingKey};
    use std::{env, fs};
    use tracing::info;

    #[test]
    fn test_e2e_fibonacci_core_proof_generation() -> anyhow::Result<()> {
        let (metadata_dir, cpu_agent) =
            setup_cpu_agent_and_metadata_dir().context("Failed to setup")?;

        let pv_path =
            metadata_dir.join("shard_size_18/fibonacci-elf_shardsize_18_cycles_1M_pv.bin");
        let pv = fs::read(&pv_path)?;
        let pv: SP1PublicValues = deserialize_from_bincode_bytes(&pv)?;

        let stdin_path =
            metadata_dir.join("shard_size_18/fibonacci-elf_shardsize_18_cycles_1M_stdin.bin");
        let stdin = fs::read(&stdin_path)?;
        let stdin: SP1Stdin = deserialize_from_bincode_bytes(&stdin)?;

        let prover = &cpu_agent.prover;

        let mut proofs: Vec<ShardProof<CoreSC>> = vec![];
        let elf_path = metadata_dir.join("elf/fibonacci-elf");
        let serialized_elf_path = serialize_to_msgpack_bytes(&elf_path)?;

        let vk = cpu_agent.setup(serialized_elf_path.clone())?;
        for i in 1..=7 {
            let record_path = metadata_dir.join(format!(
                "shard_size_18/fibonacci-elf_shardsize_18_cycles_1M_record_{}.bin",
                i
            ));
            let record_path_serialized = serialize_to_msgpack_bytes(&record_path)?;

            let elf_path = metadata_dir.join("elf/fibonacci-elf");
            let serialized_elf_path = serialize_to_msgpack_bytes(&elf_path)?;
            let inputs: Vec<Vec<u8>> =
                vec![record_path_serialized, serialized_elf_path, vk.clone()];
            let packed = serialize_to_msgpack_bytes(&inputs).unwrap();

            let shard_proof_serialized = cpu_agent.prove(packed).unwrap();
            let shard_proof: ShardProof<CoreSC> =
                deserialize_from_bincode_bytes(&shard_proof_serialized).unwrap();

            proofs.push(shard_proof);
        }

        let core_proof = SP1CoreProof {
            proof: SP1CoreProofData(proofs),
            stdin: stdin.clone(),
            public_values: pv,
            cycles: 0,
        };
        let core_proof_bytes = serialize_to_bincode_bytes(&core_proof).unwrap();
        fs::write(
            metadata_dir.join("shard_size_18/fibonacci-elf_shard_size_18_cycles_1M_core_proof.bin"),
            core_proof_bytes,
        )
        .unwrap();

        let vk = cpu_agent.setup(serialized_elf_path)?;
        let vk: StarkVerifyingKey<CoreSC> = deserialize_from_bincode_bytes(&vk)?;
        let vk = SP1VerifyingKey { vk };

        prover
            .verify(&core_proof.proof, &vk)
            .expect("Core proof verification failed");

        info!("Core proof verification succeeded.");

        Ok(())
    }

    #[tokio::test]
    async fn test_e2e_fibonacci_parallel_core_proof_generation() -> anyhow::Result<()> {
        let (metadata_dir, cpu_agent) =
            setup_cpu_agent_and_metadata_dir().context("Failed to setup")?;

        let pv_path =
            metadata_dir.join("shard_size_18/fibonacci-elf_shardsize_18_cycles_1M_pv.bin");
        let pv = fs::read(&pv_path)?;
        let pv: SP1PublicValues = deserialize_from_bincode_bytes(&pv)?;

        let stdin_path =
            metadata_dir.join("shard_size_18/fibonacci-elf_shardsize_18_cycles_1M_stdin.bin");
        let stdin = fs::read(&stdin_path)?;
        let stdin: SP1Stdin = deserialize_from_bincode_bytes(&stdin)?;

        let agent_type = env::var("AGENT_TYPE").unwrap_or_else(|_| "sp1-cpu".to_string());

        let prover = &cpu_agent.prover;

        let mut proofs: Vec<ShardProof<CoreSC>> = vec![];
        let elf_path = metadata_dir.join("elf/fibonacci-elf");
        let serialized_elf_path = serialize_to_msgpack_bytes(&elf_path)?;

        let vk = cpu_agent.setup(serialized_elf_path.clone())?;
        for i in 1..=7 {
            let record_path = metadata_dir.join(format!(
                "shard_size_18/fibonacci-elf_shardsize_18_cycles_1M_record_{}.bin",
                i
            ));
            let record_path_serialized = serialize_to_msgpack_bytes(&record_path)?;

            let elf_path = metadata_dir.join("elf/fibonacci-elf");
            let serialized_elf_path = serialize_to_msgpack_bytes(&elf_path)?;
            let inputs: Vec<Vec<u8>> =
                vec![record_path_serialized, serialized_elf_path, vk.clone()];
            let packed = serialize_to_msgpack_bytes(&inputs).unwrap();

            let shard_proof_serialized = cpu_agent.prove(packed).unwrap();
            let shard_proof: ShardProof<CoreSC> =
                deserialize_from_bincode_bytes(&shard_proof_serialized).unwrap();

            proofs.push(shard_proof);
        }

        let core_proof = SP1CoreProof {
            proof: SP1CoreProofData(proofs),
            stdin: stdin.clone(),
            public_values: pv,
            cycles: 0,
        };
        let core_proof_bytes = serialize_to_bincode_bytes(&core_proof).unwrap();
        fs::write(
            metadata_dir.join("shard_size_18/fibonacci-elf_shard_size_18_cycles_1M_core_proof.bin"),
            core_proof_bytes,
        )
        .unwrap();

        let vk = cpu_agent.setup(serialized_elf_path)?;
        let vk: StarkVerifyingKey<CoreSC> = deserialize_from_bincode_bytes(&vk)?;
        let vk = SP1VerifyingKey { vk };

        prover
            .verify(&core_proof.proof, &vk)
            .expect("Core proof verification failed");

        info!("Core proof verification succeeded.");

        Ok(())
    }

    #[tokio::test]
    async fn test_e2e_keccak_core_proof_generation() -> anyhow::Result<()> {
        let (metadata_dir, cpu_agent) =
            setup_cpu_agent_and_metadata_dir().context("Failed to setup")?;

        let pv_path = metadata_dir.join("shard_size_21/keccak-elf_shardsize_21_cycles_10M_pv.bin");
        let pv = fs::read(&pv_path)?;
        let pv: SP1PublicValues = deserialize_from_bincode_bytes(&pv)?;

        let stdin_path =
            metadata_dir.join("shard_size_21/keccak-elf_shardsize_21_cycles_10M_stdin.bin");
        let stdin = fs::read(&stdin_path)?;
        let stdin: SP1Stdin = deserialize_from_bincode_bytes(&stdin)?;

        let prover = &cpu_agent.prover;

        let mut proofs: Vec<ShardProof<CoreSC>> = vec![];
        let elf_path = metadata_dir.join("elf/keccak-elf");
        let serialized_elf_path = serialize_to_msgpack_bytes(&elf_path)?;

        let vk = cpu_agent.setup(serialized_elf_path.clone())?;
        for i in 1..=8 {
            let record_path = metadata_dir.join(format!(
                "shard_size_18/keccak-elf_shardsize_18_cycles_1M_record_{}.bin",
                i
            ));
            let record_path_serialized = serialize_to_msgpack_bytes(&record_path)?;

            let elf_path = metadata_dir.join("elf/keccak-elf");
            let serialized_elf_path = serialize_to_msgpack_bytes(&elf_path)?;
            let inputs: Vec<Vec<u8>> =
                vec![record_path_serialized, serialized_elf_path, vk.clone()];
            let packed = serialize_to_msgpack_bytes(&inputs).unwrap();

            let shard_proof_serialized = cpu_agent.prove(packed).unwrap();
            let shard_proof: ShardProof<CoreSC> =
                deserialize_from_bincode_bytes(&shard_proof_serialized).unwrap();

            proofs.push(shard_proof);
        }

        let core_proof = SP1CoreProof {
            proof: SP1CoreProofData(proofs),
            stdin: stdin.clone(),
            public_values: pv,
            cycles: 0,
        };
        let core_proof_bytes = serialize_to_bincode_bytes(&core_proof).unwrap();
        fs::write(
            metadata_dir.join("shard_size_18/keccak-elf_shard_size_18_cycles_1M_core_proof.bin"),
            core_proof_bytes,
        )
        .unwrap();

        let vk = cpu_agent.setup(serialized_elf_path)?;
        let vk: StarkVerifyingKey<CoreSC> = deserialize_from_bincode_bytes(&vk)?;
        let vk = SP1VerifyingKey { vk };

        prover
            .verify(&core_proof.proof, &vk)
            .expect("Core proof verification failed");

        info!("Core proof verification succeeded.");

        Ok(())
    }
}
