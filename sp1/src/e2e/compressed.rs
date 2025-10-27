#[cfg(test)]
mod tests {
    use crate::e2e::tests::{is_cpu_ryzen_9_9950x3d, setup, setup_agent_and_metadata_dir};
    use crate::tasks::agent::Sp1Agent;
    use crate::tasks::shards::{DeferredEvents, ShardEventData};
    use crate::tasks::{
        CompressInput, LiftDeferInput, ProveLiftDeferredEventsOutput, ProveLiftInput,
        VerifyCompressInput, WrapCompressInput,
    };
    use anyhow::{Context, Result, anyhow};
    use common::serialization::bincode::deserialize_from_bincode_bytes;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeField32;
    use sp1_core_executor::SP1ReduceProof;
    use sp1_prover::{CoreSC, InnerSC, SP1PublicValues, SP1VerifyingKey};
    use sp1_sdk::SP1ProofWithPublicValues;
    use sp1_stark::air::PublicValues;
    use sp1_stark::{Challenger, StarkVerifyingKey};
    use std::fs;
    use std::path::{Path, PathBuf};
    use tokio::sync::oneshot;
    use tracing::{debug, info};

    struct E2eCase<'a> {
        elf_path: &'a str,
        stdin_path: &'a str,
        checkpoint_glob_fmt: &'a str,
        checkpoint_len: usize,
        global_memory_glob_fmt: &'a str,
        global_memory_len: usize,
    }

    async fn compress_binary_tree(agent: &Sp1Agent, mut proofs: Vec<Vec<u8>>) -> Result<Vec<u8>> {
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
                            .context("Failed to deserialize_right_proof")?;
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

    async fn process_split_and_prove(
        agent: &Sp1Agent,
        deferred_events: &mut DeferredEvents,
        is_tail_split: bool,
        state: &mut PublicValues<u32, u32>,
        elf: &Vec<u8>,
        vk: &StarkVerifyingKey<CoreSC>,
        deferred_digest: [BabyBear; 8],
        challenger: &Challenger<CoreSC>,
        lifted: &mut Vec<Vec<u8>>,
    ) -> Result<()> {
        let split_deferred_events =
            deferred_events.split(is_tail_split, agent.prover_opts.core_opts.split_opts).await;

        for mut shard_event_data in split_deferred_events {
            state.shard += 1;
            shard_event_data.update_state(state);

            let prove_lift_input = ProveLiftInput {
                shard_event_data,
                elf: elf.clone(),
                vk: vk.clone(),
                deferred_digest,
                challenger: challenger.clone(),
            };

            let prove_lift_output = agent
                .prove_lift_precompile(prove_lift_input)
                .await
                .context("Failed to prove_lift_precompile")?;

            lifted.push(prove_lift_output.reduce_proof);
        }

        Ok(())
    }

    async fn run_e2e_case(agent: &Sp1Agent, metadata_dir: &Path, case: &E2eCase<'_>) -> Result<()> {
        let elf_path: PathBuf = metadata_dir.join(case.elf_path);

        let stdin_path: PathBuf = metadata_dir.join(case.stdin_path);

        let (elf, vk, deferred_inputs, deferred_digest, challenger) =
            setup(agent, &elf_path, &stdin_path).context("Failed to setup")?;

        let mut lifted: Vec<Vec<u8>> = Vec::with_capacity(
            case.checkpoint_len + case.global_memory_len + deferred_inputs.len(),
        );

        for deferred_input in deferred_inputs {
            let lift_defer_input = LiftDeferInput { deferred_input };

            let lift_defer_output =
                agent.lift_defer(lift_defer_input).context("Failed to lift_defer")?;

            lifted.push(lift_defer_output.reduce_proof);
        }

        let mut state = PublicValues::<u32, u32>::default().reset();
        state.start_pc = vk.pc_start.as_canonical_u32();

        info!("state.start_pc: {}", state.start_pc);
        let mut deferred_events = DeferredEvents::empty();
        for i in 1..=case.checkpoint_len {
            state.shard += 1;
            let shard_event_data_path =
                metadata_dir.join(case.checkpoint_glob_fmt.replace("{}", &i.to_string()));
            let shard_event_data =
                fs::read(&shard_event_data_path).context("Failed to read shard_event")?;
            let mut shard_event_data: ShardEventData =
                deserialize_from_bincode_bytes(&shard_event_data)
                    .context("Failed to deserialize shard_event")?;
            shard_event_data.update_state(&mut state);

            let (tx, rx) = oneshot::channel::<ProveLiftDeferredEventsOutput>();

            let prove_lift_input = ProveLiftInput {
                shard_event_data,
                elf: elf.clone(),
                vk: vk.clone(),
                deferred_digest,
                challenger: challenger.clone(),
            };

            let prove_lift_output =
                agent.prove_lift(prove_lift_input, tx).await.context("Failed to prove_lift")?;

            match rx.await {
                Ok(output) => {
                    let deferred_events_output: DeferredEvents =
                        deserialize_from_bincode_bytes(&output.deferred_events)
                            .context("Failed to deserialize deferred_events")?;
                    deferred_events.append(deferred_events_output).await;
                }
                Err(_) => {
                    debug!("No deferred events received for shard {}", i);
                }
            };

            lifted.push(prove_lift_output.reduce_proof);
        }

        process_split_and_prove(
            agent,
            &mut deferred_events,
            false,
            &mut state,
            &elf,
            &vk,
            deferred_digest,
            &challenger,
            &mut lifted,
        )
        .await?;

        process_split_and_prove(
            agent,
            &mut deferred_events,
            true,
            &mut state,
            &elf,
            &vk,
            deferred_digest,
            &challenger,
            &mut lifted,
        )
        .await?;

        for i in 1..=case.global_memory_len {
            state.shard += 1;

            let shard_event_data_path =
                metadata_dir.join(case.global_memory_glob_fmt.replace("{}", &i.to_string()));
            let shard_event_data =
                fs::read(&shard_event_data_path).context("Failed to read shard_event")?;
            let mut shard_event_data: ShardEventData =
                deserialize_from_bincode_bytes(&shard_event_data)
                    .context("Failed to deserialize shard_event")?;
            shard_event_data.update_state(&mut state);

            let prove_lift_input = ProveLiftInput {
                shard_event_data,
                elf: elf.clone(),
                vk: vk.clone(),
                deferred_digest,
                challenger: challenger.clone(),
            };

            let prove_lift_output = agent
                .prove_lift_precompile(prove_lift_input)
                .await
                .context("Failed to prove_lift_precompile")?;

            lifted.push(prove_lift_output.reduce_proof);
        }

        let final_proof =
            compress_binary_tree(agent, lifted).await.context("Failed to compress")?;
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

        agent.verify_compress(verify_compress_input).context("Failed to verify compress")?;
        Ok(())
    }

    #[tokio::test]
    async fn test_compress_explorer_single_checkpoint() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let case_single = E2eCase {
            elf_path: "elf/single_record_elf.bin",
            stdin_path: "stdin/single_record_stdin.bin",
            checkpoint_glob_fmt: "shard/checkpoint/single_checkpoint_{}.bin",
            checkpoint_len: 1,
            global_memory_glob_fmt: "shard/global_memory/single_checkpoint_global_memory_{}.bin",
            global_memory_len: 2,
        };

        run_e2e_case(&agent, &metadata_dir, &case_single)
            .await
            .context("Failed to run single checkpoint test")?;
        Ok(())
    }

    #[tokio::test]
    async fn test_compress_fibonacci_shard_event_data() -> Result<()> {
        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let case_multi = E2eCase {
            elf_path: "elf/fibonacci-elf.bin",
            stdin_path: "stdin/fibonacci-elf_shardsize_14_stdin.bin",
            checkpoint_glob_fmt: "shard/checkpoint/fibonacci-elf_shardsize_14_checkpoint_{}.bin",
            checkpoint_len: 1,
            global_memory_glob_fmt: "shard/global_memory/fibonacci-elf_shardsize_14_global_memory_{}.bin",
            global_memory_len: 1,
        };

        run_e2e_case(&agent, &metadata_dir, &case_multi)
            .await
            .context("Failed to run multi checkpoints test")?;
        Ok(())
    }

    #[tokio::test]
    async fn test_compress_deferred_proof_records() -> Result<()> {
        if is_cpu_ryzen_9_9950x3d() {
            eprintln!("Skipping test on AMD Ryzen 9 9950X3D CPU");
            return Ok(());
        }

        let (metadata_dir, agent) = setup_agent_and_metadata_dir().context("Failed to setup")?;

        let case_deferred = E2eCase {
            elf_path: "elf/deferred_proof_elf.bin",
            stdin_path: "stdin/deferred_proof_stdin.bin",
            checkpoint_glob_fmt: "shard/checkpoint/deferred_proof_checkpoint_{}.bin",
            checkpoint_len: 19,
            global_memory_glob_fmt: "shard/global_memory/deferred_proof_global_memory_{}.bin",
            global_memory_len: 2,
        };

        run_e2e_case(&agent, &metadata_dir, &case_deferred)
            .await
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
