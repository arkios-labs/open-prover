#[cfg(test)]
mod tests {
    use crate::e2e::tests::{setup, setup_agent_and_metadata_dir};
    use crate::tasks::agent::Sp1Agent;
    use crate::tasks::{
        CompressInput, LiftDeferInput, ProveLiftInput, VerifyCompressInput, WrapCompressInput,
    };
    use anyhow::{Context, Result, anyhow};
    use common::serialization::bincode::deserialize_from_bincode_bytes;
    use sp1_core_executor::{ExecutionRecord, SP1ReduceProof};
    use sp1_prover::{InnerSC, SP1PublicValues, SP1VerifyingKey};
    use sp1_sdk::SP1ProofWithPublicValues;
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
                        let left_proof = deserialize_from_bincode_bytes(&left)
                            .context("Failed to deserialize left_proof")?;
                        let right_proof = deserialize_from_bincode_bytes(&right)
                            .context("Failed to deserialize right_proof")?;
                        let compress_input = CompressInput { left_proof, right_proof };

                        let compress_output =
                            agent.compress(compress_input).context("Failed to compress")?;

                        next.push(compress_output.reduce_proof);
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

        let (elf, vk, deferred_inputs, deferred_digest, challenger) =
            setup(agent, &elf_path, &stdin_path).context("Failed to setup")?;

        let mut lifted: Vec<Vec<u8>> = Vec::with_capacity(case.record_len + deferred_inputs.len());

        for deferred_input in deferred_inputs {
            let lift_defer_input = LiftDeferInput { deferred_input };

            let lift_defer_output =
                agent.lift_defer(lift_defer_input).context("Failed to lift_defer")?;

            lifted.push(lift_defer_output.reduce_proof);
        }

        for i in 1..=case.record_len {
            let record_path = metadata_dir.join(case.record_glob_fmt.replace("{}", &i.to_string()));
            let record = fs::read(&record_path).context("Failed to read shard_event")?;
            let record: ExecutionRecord = deserialize_from_bincode_bytes(&record)
                .context("Failed to deserialize shard_event")?;

            let prove_lift_input = ProveLiftInput {
                record,
                elf: elf.clone(),
                vk: vk.clone(),
                deferred_digest,
                challenger: challenger.clone(),
            };

            let proof = agent.prove_lift(prove_lift_input).context("Failed to prove lift")?;
            lifted.push(proof.reduce_proof);
        }

        let final_proof = compress_binary_tree(agent, lifted).context("Failed to compress")?;
        let final_proof = deserialize_from_bincode_bytes(&final_proof)
            .context("Failed to deserialize reduce_proof")?;

        let pv_path = metadata_dir.join("public_value/fibonacci-elf_shardsize_14_pv.bin");
        let pv = fs::read(&pv_path).context("Failed to read pv_path")?;
        let pv: SP1PublicValues =
            deserialize_from_bincode_bytes(&pv).context("Failed to deserialize public_values")?;

        let wrap_compress_input =
            WrapCompressInput { public_values: pv, reduce_proof: final_proof };

        let wrap_compress_output =
            agent.wrap_compress(wrap_compress_input).context("Failed to wrap compress")?;
        let compressed_proof: SP1ProofWithPublicValues =
            deserialize_from_bincode_bytes(&wrap_compress_output.compressed_proof)
                .context("Failed to deserialize compressed_proof")?;

        let verify_compress_input =
            VerifyCompressInput { compressed_proof, vk: SP1VerifyingKey { vk } };

        agent
            .verify_compress(verify_compress_input)
            .context("Compressed proof verification failed")?;
        Ok(())
    }

    #[test]
    fn test_compress_explorer_single_record() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let case_single = E2eCase {
            elf_path: "elf/single_record_elf.bin",
            stdin_path: "stdin/single_record_stdin.bin",
            record_glob_fmt: "record/single_record_{}.bin",
            record_len: 1,
        };

        run_e2e_case(&agent, &metadata_dir, &case_single)
            .context("Failed to run single record test")?;
        Ok(())
    }

    #[test]
    fn test_compress_fibonacci_three_records() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let case_multi = E2eCase {
            elf_path: "elf/fibonacci-elf.bin",
            stdin_path: "stdin/fibonacci-elf_shardsize_14_stdin.bin",
            record_glob_fmt: "record/fibonacci-elf_shardsize_14_record_{}.bin",
            record_len: 3,
        };

        run_e2e_case(&agent, &metadata_dir, &case_multi)
            .context("Failed to run multi record test")?;
        Ok(())
    }

    #[test]
    fn test_compress_deferred_proof_records() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let case_deferred = E2eCase {
            elf_path: "elf/deferred_proof_elf.bin",
            stdin_path: "stdin/deferred_proof_stdin.bin",
            record_glob_fmt: "record/deferred_proof_record_{}.bin",
            record_len: 2,
        };

        run_e2e_case(&agent, &metadata_dir, &case_deferred)
            .context("Failed to run deferred proof test")?;
        Ok(())
    }

    #[test]
    fn test_wrap_compress_proof() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let pv_path = metadata_dir.join("public_value/fibonacci-elf_shardsize_14_pv.bin");
        let pv = fs::read(&pv_path).context("Failed to read pv_path")?;
        let pv: SP1PublicValues =
            deserialize_from_bincode_bytes(&pv).context("Failed to deserialize public_values")?;

        let elf_path = metadata_dir.join("elf/fibonacci-elf.bin");

        let stdin_path = metadata_dir.join("stdin/keccak-elf_shardsize_14_stdin.bin");

        let (_, vk, _, _, _) = setup(&agent, &elf_path, &stdin_path).context("Failed to setup")?;
        let vk = SP1VerifyingKey { vk };

        let reduce_proof_path =
            metadata_dir.join("proof/fibonacci-elf_shard_size_14_raw_compressed_proof.bin");
        let reduce_proof =
            fs::read(&reduce_proof_path).context("Failed to read compressed proof")?;
        let reduce_proof: SP1ReduceProof<InnerSC> =
            deserialize_from_bincode_bytes(&reduce_proof)
                .context("Failed to deserialize compressed_proof")?;

        let wrap_compress_input = WrapCompressInput { public_values: pv, reduce_proof };

        let wrap_compress_output =
            agent.wrap_compress(wrap_compress_input).context("Failed to wrap compress")?;
        let compressed_proof: SP1ProofWithPublicValues =
            deserialize_from_bincode_bytes(&wrap_compress_output.compressed_proof)
                .context("Failed to deserialize compressed_proof")?;

        let verify_compress_input = VerifyCompressInput { compressed_proof, vk };

        agent
            .verify_compress(verify_compress_input)
            .context("Compressed proof verification failed")?;

        Ok(())
    }
}
