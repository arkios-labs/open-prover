#[cfg(test)]
mod tests {
    use crate::e2e::tests::{setup, setup_agent_and_metadata_dir};
    use crate::tasks::agent::Sp1Agent;
    use anyhow::{Context, Result, anyhow};
    use common::serialization::bincode::{
        deserialize_from_bincode_bytes, serialize_to_bincode_bytes,
    };
    use common::serialization::mpk::serialize_to_msgpack_bytes;
    use std::fs;
    use std::path::{Path, PathBuf};
    use tracing::info;

    struct E2eCase<'a> {
        elf_path: &'a str,
        stdin_path: &'a str,
        record_glob_fmt: &'a str,
        record_len: usize,
    }

    fn compress_binary_tree(agent: &Sp1Agent, mut proofs: Vec<Vec<u8>>) -> Result<Vec<u8>> {
        let mut height = 0;
        let mut next = Vec::with_capacity(proofs.len());
        while proofs.len() > 1 {
            info!("Compressing {} proofs at height {}", proofs.len(), height);
            next.clear();

            {
                let mut iter = proofs.drain(..);

                while let Some(left) = iter.next() {
                    if let Some(right) = iter.next() {
                        let inputs = serialize_to_msgpack_bytes(&[&left, &right])
                            .context("Failed to pack")?;
                        let out = agent.compress(inputs).context("Failed to compress")?;
                        next.push(out);
                    } else {
                        next.push(left);
                    }
                }
            }

            proofs = std::mem::take(&mut next);
            height += 1;
            info!("Reduced to {} proofs at height {}", proofs.len(), height);
        }

        proofs.pop().ok_or_else(|| anyhow!("No final proof generated"))
    }

    fn run_e2e_case(agent: &Sp1Agent, metadata_dir: &Path, case: &E2eCase) -> Result<()> {
        let elf_path: PathBuf = metadata_dir.join(case.elf_path);
        let stdin_path: PathBuf = metadata_dir.join(case.stdin_path);

        let (vk, deferred_inputs, deferred_digest, challenger) =
            setup(agent, &elf_path, &stdin_path).context("Failed to setup")?;

        let mut lifted: Vec<Vec<u8>> = Vec::with_capacity(case.record_len + deferred_inputs.len());

        for deferred_input in &deferred_inputs {
            let deferred_input_packed = serialize_to_msgpack_bytes(deferred_input)
                .context("Failed to serialize deferred input")?;
            let lifted_proof = agent.lift_defer(deferred_input_packed).context("Failed to lift")?;
            lifted.push(lifted_proof);
        }

        let deferred_digest_serialized = serialize_to_bincode_bytes(&deferred_digest)
            .context("Failed to serialize deferred digest")?;
        let vk_serialized = serialize_to_bincode_bytes(&vk).context("Failed to serialize vk")?;
        let challenger_serialized =
            serialize_to_bincode_bytes(&challenger).context("Failed to serialize challenger")?;
        for i in 1..=case.record_len {
            let record_path = metadata_dir.join(case.record_glob_fmt.replace("{}", &i.to_string()));

            let record_path_packed =
                serialize_to_msgpack_bytes(&record_path).context("Failed to pack")?;
            let elf_path_packed =
                serialize_to_msgpack_bytes(&elf_path).context("Failed to pack")?;
            let inputs = serialize_to_msgpack_bytes(&[
                &record_path_packed,
                &elf_path_packed,
                &vk_serialized,
                &deferred_digest_serialized,
                &challenger_serialized,
            ])
            .context("Failed to pack")?;

            let proof = agent.prove_lift(inputs).context("Failed to prove lift")?;
            lifted.push(proof);
        }

        let final_proof = compress_binary_tree(agent, lifted).context("Failed to compress")?;

        let pv_path = metadata_dir.join("public_value/fibonacci-elf_shardsize_14_pv.bin");
        let pv_path_packed = serialize_to_msgpack_bytes(&pv_path).context("Failed to pack")?;

        let wrap_compress_inputs: Vec<u8> =
            serialize_to_msgpack_bytes(&[&pv_path_packed, &final_proof])
                .context("Failed to pack")?;
        let wrap_compressed_proof =
            agent.wrap_compress(wrap_compress_inputs).context("Failed to wrap compress")?;

        let wrap_compress_verify_inputs: Vec<u8> =
            serialize_to_msgpack_bytes(&[&wrap_compressed_proof, &vk_serialized])
                .context("Failed to pack")?;
        agent
            .verify_compress(wrap_compress_verify_inputs)
            .context("Compressed proof verification failed")?;
        Ok(())
    }

    #[test]
    fn test_e2e_binary_tree_variants() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        // Case 1: single record (without compress operation)
        let case_single = E2eCase {
            elf_path: "elf/single_record_elf.bin",
            stdin_path: "stdin/single_record_stdin.bin",
            record_glob_fmt: "record/single_record_{}.bin",
            record_len: 1,
        };

        // Case 2: three records (with compress operation)
        let case_multi = E2eCase {
            elf_path: "elf/fibonacci-elf",
            stdin_path: "stdin/fibonacci-elf_shardsize_14_stdin.bin",
            record_glob_fmt: "record/fibonacci-elf_shardsize_14_record_{}.bin",
            record_len: 3,
        };

        // Case 3: deferred proofs
        let case_deferred = E2eCase {
            elf_path: "elf/deferred_proof_elf.bin",
            stdin_path: "stdin/deferred_proof_stdin.bin",
            record_glob_fmt: "record/deferred_proof_record_{}.bin",
            record_len: 2,
        };

        for case in [&case_single, &case_multi, &case_deferred] {
            run_e2e_case(&agent, &metadata_dir, case)
                .with_context(|| format!("case failed: elf_rel={}", case.elf_path))?;
        }
        Ok(())
    }

    #[test]
    fn test_wrap_compress_proof() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let pv_path = metadata_dir.join("public_value/fibonacci-elf_shardsize_14_pv.bin");
        let pv_path_packed =
            serialize_to_msgpack_bytes(&pv_path).context("Failed to pack pv_path")?;
        let compressed_proof_path =
            metadata_dir.join("proof/fibonacci-elf_shard_size_14_raw_compressed_proof.bin");
        let compressed_proof =
            fs::read(&compressed_proof_path).context("Failed to read compressed proof")?;

        let inputs: Vec<Vec<u8>> = vec![pv_path_packed, compressed_proof];
        let inputs_packed =
            serialize_to_msgpack_bytes(&inputs).context("Failed to serialize inputs")?;

        let _wrapped_compress_proof =
            agent.wrap_compress(inputs_packed).context("Failed to wrap_compress")?;

        Ok(())
    }

    #[test]
    fn test_verify_compress_proof() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let elf_path = metadata_dir.join("elf/fibonacci-elf");

        let stdin_path = metadata_dir.join("stdin/keccak-elf_shardsize_14_stdin.bin");

        let (vk, _, _, _) = setup(&agent, &elf_path, &stdin_path).context("Failed to setup")?;

        let compressed_proof_path =
            metadata_dir.join("proof/fibonacci-elf_shard_size_14_compressed_proof.bin");
        let compressed_proof =
            fs::read(&compressed_proof_path).context("Failed to read compressed proof")?;
        let vk_serialized = serialize_to_bincode_bytes(&vk).context("Failed to serialize vk")?;

        let verify_inputs: Vec<Vec<u8>> = vec![compressed_proof, vk_serialized];
        let verify_inputs_packed =
            serialize_to_msgpack_bytes(&verify_inputs).context("Failed to pack verify_inputs")?;

        let verify_result =
            agent.verify_compress(verify_inputs_packed).context("Failed to verify_compress")?;
        let verify_success: bool = deserialize_from_bincode_bytes(&verify_result)
            .context("Failed to deserialize verify_result")?;
        assert!(verify_success, "Compressed proof verification should succeed");

        Ok(())
    }
}
