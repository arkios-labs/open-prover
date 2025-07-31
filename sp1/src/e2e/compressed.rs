#[cfg(test)]
mod tests {
    use crate::e2e::tests::setup_cpu_agent_and_metadata_dir;
    use crate::tasks::Agent;
    use anyhow::{anyhow, Context};
    use common::serialization::bincode::deserialize_from_bincode_bytes;
    use common::serialization::mpk::serialize_to_msgpack_bytes;
    use sp1_core_executor::SP1ReduceProof;
    use sp1_prover::InnerSC;
    use sp1_prover::{CoreSC, SP1VerifyingKey};
    use sp1_stark::StarkVerifyingKey;
    use std::fs;
    use tracing::info;

    #[tokio::test]
    async fn test_e2e_fibonacci_binary_tree_based_compressed_proof_generation() -> anyhow::Result<()>
    {
        let (metadata_dir, cpu_agent) =
            setup_cpu_agent_and_metadata_dir().context("Failed to setup")?;

        let prover = &cpu_agent.prover;

        let elf_path = metadata_dir.join("elf/fibonacci-elf");
        let serialized_elf_path = serialize_to_msgpack_bytes(&elf_path)?;

        let vk = cpu_agent.setup(serialized_elf_path.clone())?;
        let mut lifted_proofs = Vec::new();

        for i in 1..=7 {
            let record_path = metadata_dir.join(format!(
                "shard_size_18/fibonacci-elf_shardsize_18_cycles_1M_record_{}.bin",
                i
            ));
            let record_path_serialized = serialize_to_msgpack_bytes(&record_path)?;
            let elf_path_serialized = serialize_to_msgpack_bytes(&elf_path)?;
            let vk_clone = vk.clone();

            let inputs: Vec<Vec<u8>> = vec![record_path_serialized, elf_path_serialized, vk_clone];
            let packed = serialize_to_msgpack_bytes(&inputs)?;

            let proof = cpu_agent.prove_lift(packed)?;
            lifted_proofs.push(proof);
        }

        info!("lifted_proofs size: {}", lifted_proofs.len());
        let mut current_height = 0;
        let mut current_proofs = lifted_proofs.clone();

        while current_proofs.len() > 1 {
            info!(
                "Compressing {} proofs at height {} sequentially",
                current_proofs.len(),
                current_height
            );

            let mut next_level = Vec::new();
            let mut i = 0;

            while i + 1 < current_proofs.len() {
                let left = &current_proofs[i];
                let right = &current_proofs[i + 1];

                info!(
                    "Compressing pair [{}, {}] at height {}",
                    i,
                    i + 1,
                    current_height
                );

                let is_complete_bool = current_proofs.len() == 2 && i + 2 >= current_proofs.len();
                let is_complete = serialize_to_msgpack_bytes(&is_complete_bool)?;

                let inputs: Vec<Vec<u8>> = vec![left.clone(), right.clone(), is_complete];
                let packed = serialize_to_msgpack_bytes(&inputs)?;

                let result_bytes = cpu_agent.compress(packed)?;
                next_level.push(result_bytes);

                i += 2;
            }

            if i < current_proofs.len() {
                next_level.push(current_proofs[i].clone());
            }

            current_proofs = next_level;
            current_height += 1;

            info!(
                "Reduced to {} proofs at height {}",
                current_proofs.len(),
                current_height
            );
        }

        let final_proof_vec = current_proofs
            .pop()
            .ok_or_else(|| anyhow!("No final proof generated"))?;

        let final_proof: SP1ReduceProof<InnerSC> =
            deserialize_from_bincode_bytes(&final_proof_vec)?;

        let vk: StarkVerifyingKey<CoreSC> = deserialize_from_bincode_bytes(&vk)?;
        let vk = SP1VerifyingKey { vk };

        prover
            .verify_compressed(&final_proof, &vk)
            .expect("Compressed proof verification failed");

        fs::write(
            metadata_dir
                .join("shard_size_18/fibonacci-elf_shard_size_18_cycles_1M_compressed_proof.bin"),
            final_proof_vec,
        )?;

        Ok(())
    }

    #[test]
    fn test_wrap_compress_proof() -> anyhow::Result<()> {
        let (metadata_dir, cpu_agent) =
            setup_cpu_agent_and_metadata_dir().context("Failed to setup")?;

        let pv_path =
            metadata_dir.join("shard_size_18/fibonacci-elf_shardsize_18_cycles_1M_pv.bin");
        let pv_path = serialize_to_msgpack_bytes(&pv_path)?;
        let compressed_proof_path = metadata_dir
            .join("shard_size_18/fibonacci-elf_shard_size_18_cycles_1M_compressed_proof.bin");
        let compressed_proof =
            fs::read(&compressed_proof_path).context("Failed to read compressed proof")?;

        let inputs: Vec<Vec<u8>> = vec![pv_path, compressed_proof];
        let packed = serialize_to_msgpack_bytes(&inputs).unwrap();

        let wrapped_compress_proof = cpu_agent.wrap_compress(packed)?;

        Ok(())
    }
}
