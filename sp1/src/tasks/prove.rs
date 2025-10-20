use crate::tasks::agent::Sp1Agent;
use crate::tasks::shards::DeferredEvents;
use crate::tasks::{
    ProveInput, ProveLiftDeferredEventsOutput, ProveLiftInput, ProveLiftReduceProofOutput,
    ProveOutput,
};
use anyhow::{Context, Result, anyhow, bail};
use common::serialization::bincode::serialize_to_bincode_bytes;
use p3_baby_bear::BabyBear;
use p3_challenger::CanObserve;
use sp1_core_executor::{RiscvAirId, SP1ReduceProof};
use sp1_core_machine::shape::Shapeable;
use sp1_prover::shapes::SP1CompressProgramShape;
use sp1_prover::{CoreSC, HashableKey, SP1CircuitWitness};
use sp1_recursion_circuit::machine::{SP1RecursionShape, SP1RecursionWitnessValues};
use sp1_recursion_core::air::RecursionPublicValues;
use sp1_stark::air::MachineAir;
use sp1_stark::baby_bear_poseidon2::Val;
use sp1_stark::septic_digest::SepticDigest;
use sp1_stark::shape::OrderedShape;
use sp1_stark::{
    Challenger, MachineProof, MachineProver, ShardProof, StarkGenericConfig, StarkVerifyingKey,
    Verifier,
};
use std::borrow::Borrow;
use std::iter::once;
use std::slice::from_mut;
use std::str::FromStr;
use std::time::Instant;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{debug, error, info};

impl Sp1Agent {
    pub fn prove(&self, prove_input: ProveInput) -> Result<ProveOutput> {
        info!("Agent::prove()");
        let start_time = Instant::now();

        let mut record = prove_input.record;
        let elf = prove_input.elf;
        let vk = prove_input.vk;
        let mut challenger = prove_input.challenger;

        tracing::debug_span!("generate dependencies").in_scope(|| {
            self.prover.core_prover.machine().generate_dependencies(
                from_mut(&mut record),
                &self.prover_opts.core_opts,
                None,
            );
        });

        if let Some(shape_config) = &self.prover.core_shape_config {
            shape_config.fix_shape(&mut record).context("Failed to fix shape")?;
        }

        let program = self.prover.get_program(elf).expect("Failed to get program");

        let pkey = self.prover.core_prover.pk_from_vk(&program, vk);

        let traces = self.prover.core_prover.generate_traces(&record);

        let shard = record.shard();

        let main_data = tracing::debug_span!("commit", shard)
            .in_scope(|| self.prover.core_prover.commit(&record, traces));

        let shard_proof = tracing::debug_span!("opening", shard)
            .in_scope(|| self.prover.core_prover.open(&pkey, main_data, &mut challenger).unwrap());

        let shard_proof =
            serialize_to_bincode_bytes(&shard_proof).context("Failed to serialize shard_proof")?;
        let prove_output: ProveOutput = ProveOutput { shard_proof };

        let elapsed = start_time.elapsed();
        info!("Agent::prove() took {:?}", elapsed);
        Ok(prove_output)
    }

    pub async fn prove_lift(
        &self,
        prove_lift_input: ProveLiftInput,
        tx: oneshot::Sender<ProveLiftDeferredEventsOutput>,
    ) -> Result<ProveLiftReduceProofOutput> {
        info!("Agent::prove_lift()");
        let start_time = Instant::now();

        let vk = prove_lift_input.vk;
        let challenger = prove_lift_input.challenger.clone();

        let program = self
            .prover
            .get_program(&prove_lift_input.elf)
            .map_err(|e| anyhow::anyhow!("Failed to get program: {}", e))?;

        // Convert shard_event_data to execution record
        let (mut shard, deferred) = prove_lift_input
            .shard_event_data
            .into_record(self.prover.clone(), self.prover_opts, program.clone())
            .await
            .context("Failed to convert shard event data to record")?;

        self.prover.core_prover.machine().generate_dependencies(
            from_mut(&mut shard),
            &self.prover_opts.core_opts,
            None,
        );

        if let Some(shape_config) = &self.prover.core_shape_config {
            shape_config.fix_shape(&mut shard).context("Failed to fix shape")?;
        }

        let traces = self.prover.core_prover.generate_traces(&shard);

        let split_opts = self.prover_opts.core_opts.split_opts;

        let deferred_promise: JoinHandle<Result<(), anyhow::Error>> = tokio::spawn(async move {
            let deferred_data = deferred.context("Expected deferred data for non-precompile")?;

            let events = DeferredEvents::defer_record(deferred_data, split_opts).await?;
            info!("deferred_events: {:?}", events);

            let events_bytes = serialize_to_bincode_bytes(&events)
                .context("Failed to serialize deferred_result")?;

            let deferred_output = ProveLiftDeferredEventsOutput { deferred_events: events_bytes };

            tx.send(deferred_output).map_err(|_| anyhow!("Failed to send deferred response"))?;
            Ok(())
        });

        let pk = tracing::info_span!("pk_from_vk")
            .in_scope(|| self.prover.core_prover.pk_from_vk(&program, &vk));

        let data = tracing::info_span!("commit_main")
            .in_scope(|| self.prover.core_prover.commit(&shard, traces));

        let mut challenger_clone = challenger.clone();

        let shard_proof = tracing::info_span!("prove_shard")
            .in_scope(|| self.prover.core_prover.open(&pk, data, &mut challenger_clone).unwrap());

        let shard_number = shard.public_values.shard;

        let verify_future = self.spawn_verify_core_shard(
            vk.clone(),
            shard_proof.clone(),
            challenger.clone(),
            shard_number,
        );

        let is_first_shard = shard.public_values.shard == 1;

        let witness = SP1CircuitWitness::Core(SP1RecursionWitnessValues {
            vk,
            shard_proofs: vec![shard_proof],
            reconstruct_deferred_digest: prove_lift_input.deferred_digest,
            is_complete: false,
            is_first_shard,
            vk_root: self.prover.recursion_vk_root,
        });

        let proof_shape = {
            let chips = self.prover.core_prover.shard_chips(&shard).collect::<Vec<_>>();
            let shape = shard.shape.as_ref().context("shape not set")?;

            let mut heights = Vec::with_capacity(chips.len());
            for chip in chips.into_iter() {
                let id = RiscvAirId::from_str(&chip.name()).map_err(|e| {
                    anyhow::anyhow!("Failed to parse chip name as RiscvAirId: {}", e)
                })?;
                let height =
                    shape.log2_height(&id).context("Failed to get log2 height for chip")?;
                heights.push((chip.name(), height));
            }
            OrderedShape::from_log2_heights(&heights)
        };

        let compress_shape = SP1CompressProgramShape::Recursion(SP1RecursionShape {
            proof_shapes: vec![proof_shape],
            is_complete: false,
        });

        let program = self.prover.program_from_shape(compress_shape, None);

        let reduce_proof = self
            .full_recursion(program, witness, self.prover_opts, None)
            .context("Failed to reduce proof")?;

        let reduce_verify_future = self.spawn_verify_reduce_leaf(reduce_proof.clone());

        let expected_global_cumulative_sum = verify_future
            .await
            .unwrap()
            .map_err(|e| anyhow!("failed to verify shard proof: {}", e))?;

        let final_sum = reduce_verify_future
            .await
            .unwrap()
            .map_err(|e| anyhow!("failed to verify reduce proof: {}", e))?;
        if expected_global_cumulative_sum != final_sum {
            return Err(anyhow!(
                "expected global cumulative sum {:?} != final sum {:?}",
                expected_global_cumulative_sum,
                final_sum
            ));
        }

        let serialized = serialize_to_bincode_bytes(&reduce_proof)
            .context("Failed to serialize reduce_proof")?;

        let prove_lift_output = ProveLiftReduceProofOutput { reduce_proof: serialized };

        deferred_promise.await.context("Deferred task panicked")??;

        let elapsed = start_time.elapsed();
        info!("Agent::prove_lift() took {:?}", elapsed);

        Ok(prove_lift_output)
    }

    pub async fn prove_lift_precompile(
        &self,
        prove_lift_input: ProveLiftInput,
    ) -> Result<ProveLiftReduceProofOutput> {
        info!("Agent::prove_lift_precompile()");
        let start_time = Instant::now();

        let vk = prove_lift_input.vk;
        let challenger = prove_lift_input.challenger.clone();

        let program = self
            .prover
            .get_program(&prove_lift_input.elf)
            .map_err(|e| anyhow::anyhow!("Failed to get program: {}", e))?;

        // Convert shard_event_data to execution record
        let (mut shard, _deferred) = prove_lift_input
            .shard_event_data
            .into_record(self.prover.clone(), self.prover_opts, program.clone())
            .await
            .context("Failed to convert shard event data to record")?;

        self.prover.core_prover.machine().generate_dependencies(
            from_mut(&mut shard),
            &self.prover_opts.core_opts,
            None,
        );

        if let Some(shape_config) = &self.prover.core_shape_config {
            shape_config.fix_shape(&mut shard).context("Failed to fix shape")?;
        }

        let traces = self.prover.core_prover.generate_traces(&shard);

        let pk = tracing::info_span!("pk_from_vk")
            .in_scope(|| self.prover.core_prover.pk_from_vk(&program, &vk));

        let data = tracing::info_span!("commit_main")
            .in_scope(|| self.prover.core_prover.commit(&shard, traces));

        let mut challenger_clone = challenger.clone();

        let shard_proof = tracing::info_span!("prove_shard")
            .in_scope(|| self.prover.core_prover.open(&pk, data, &mut challenger_clone).unwrap());

        let shard_number = shard.public_values.shard;

        let verify_future = self.spawn_verify_core_shard(
            vk.clone(),
            shard_proof.clone(),
            challenger.clone(),
            shard_number,
        );

        let is_first_shard = shard.public_values.shard == 1;

        let witness = SP1CircuitWitness::Core(SP1RecursionWitnessValues {
            vk: vk.clone(),
            shard_proofs: vec![shard_proof],
            reconstruct_deferred_digest: prove_lift_input.deferred_digest,
            is_complete: false,
            is_first_shard,
            vk_root: self.prover.recursion_vk_root,
        });

        let proof_shape = {
            let chips = self.prover.core_prover.shard_chips(&shard).collect::<Vec<_>>();
            let shape = shard.shape.as_ref().context("shape not set")?;

            let mut heights = Vec::with_capacity(chips.len());
            for chip in chips.into_iter() {
                let id = RiscvAirId::from_str(&chip.name()).map_err(|e| {
                    anyhow::anyhow!("Failed to parse chip name as RiscvAirId: {}", e)
                })?;
                let height =
                    shape.log2_height(&id).context("Failed to get log2 height for chip")?;
                heights.push((chip.name(), height));
            }
            OrderedShape::from_log2_heights(&heights)
        };

        let compress_shape = SP1CompressProgramShape::Recursion(SP1RecursionShape {
            proof_shapes: vec![proof_shape],
            is_complete: false,
        });

        let program = self.prover.program_from_shape(compress_shape, None);

        let reduce_proof = self
            .full_recursion(program, witness, self.prover_opts, None)
            .context("Failed to reduce proof")?;

        let reduce_verify_future = self.spawn_verify_reduce_leaf(reduce_proof.clone());

        let expected_global_cumulative_sum = verify_future
            .await
            .unwrap()
            .map_err(|e| anyhow!("failed to verify shard proof: {}", e))?;

        let final_sum = reduce_verify_future
            .await
            .unwrap()
            .map_err(|e| anyhow!("failed to verify reduce proof: {}", e))?;
        if expected_global_cumulative_sum != final_sum {
            return Err(anyhow!(
                "expected global cumulative sum {:?} != final sum {:?}",
                expected_global_cumulative_sum,
                final_sum
            ));
        }

        let serialized = serialize_to_bincode_bytes(&reduce_proof)
            .context("Failed to serialize reduce_proof")?;

        let prove_lift_output = ProveLiftReduceProofOutput { reduce_proof: serialized };

        let elapsed = start_time.elapsed();
        info!("Agent::prove_lift_precompile() took {:?}", elapsed);

        Ok(prove_lift_output)
    }

    pub fn spawn_verify_core_shard(
        &self,
        vk: StarkVerifyingKey<CoreSC>,
        shard_proof: ShardProof<CoreSC>,
        mut challenger: Challenger<CoreSC>,
        shard_number: u32,
    ) -> JoinHandle<Result<SepticDigest<Val>>> {
        let prover_clone = self.prover.clone();

        tokio::task::spawn_blocking(move || {
            let machine = prover_clone.core_prover.machine();
            let chips = machine.shard_chips_ordered(&shard_proof.chip_ordering).collect::<Vec<_>>();
            challenger.observe_slice(
                &shard_proof.public_values[0..prover_clone.core_prover.num_pv_elts()],
            );

            let result = Verifier::verify_shard(
                machine.config(),
                &vk,
                &chips,
                &mut challenger,
                &shard_proof,
            );

            match &result {
                Ok(_) => {
                    debug!("Core shard proof verification succeeded");
                }
                Err(e) => {
                    error!("Core shard proof verification failed: {:?}", e);
                }
            }

            let mut expected = shard_proof.global_cumulative_sum();
            if shard_number == 1 {
                expected = once(expected).chain(once(vk.initial_global_cumulative_sum)).sum();
            }
            info!("Expected cumulative sum from core: {:?}", expected);

            result.map(|_| expected).map_err(|e| anyhow!(e))
        })
    }
    pub fn spawn_verify_reduce_leaf(
        &self,
        proof: SP1ReduceProof<CoreSC>,
    ) -> JoinHandle<Result<SepticDigest<BabyBear>>> {
        let prover_clone = self.prover.clone();

        tokio::task::spawn_blocking(move || {
            let compress_prover = &prover_clone.compress_prover;
            let machine = compress_prover.machine();
            let config = compress_prover.config();

            let SP1ReduceProof { vk, proof: shard_proof } = proof;
            let mut challenger = config.challenger();

            let machine_proof = MachineProof { shard_proofs: vec![shard_proof.clone()] };

            let pv: &RecursionPublicValues<BabyBear> =
                shard_proof.public_values.as_slice().borrow();

            let result = machine.verify(&vk, &machine_proof, &mut challenger);

            match &result {
                Ok(()) => {
                    debug!("Reduce leaf proof verification succeeded");
                    let vkey_hash = vk.hash_babybear();
                    if !prover_clone.recursion_vk_map.contains_key(&vkey_hash) {
                        error!("vkey {:?} not found in map", vkey_hash);
                        bail!("Invalid verification key");
                    }
                }
                Err(e) => {
                    error!("Reduce leaf proof verification failed: {:?}", e);
                }
            }

            result.map(|_| pv.global_cumulative_sum).map_err(|e| anyhow!(e))
        })
    }
}
