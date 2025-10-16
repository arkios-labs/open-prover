use crate::tasks::agent::Sp1Agent;
use crate::tasks::shards::DeferredEvents;
use crate::tasks::{
    ProveInput, ProveLiftDeferredEventsOutput, ProveLiftInput, ProveLiftReduceProofOutput,
    ProveOutput,
};
use anyhow::{Context, Result, anyhow};
use common::serialization::bincode::serialize_to_bincode_bytes;
use sp1_core_executor::RiscvAirId;
use sp1_core_machine::shape::Shapeable;
use sp1_prover::SP1CircuitWitness;
use sp1_prover::shapes::SP1CompressProgramShape;
use sp1_recursion_circuit::machine::{SP1RecursionShape, SP1RecursionWitnessValues};
use sp1_stark::MachineProver;
use sp1_stark::air::MachineAir;
use sp1_stark::shape::OrderedShape;
use std::slice::from_mut;
use std::str::FromStr;
use std::time::Instant;
use tokio::sync::oneshot;
use tracing::info;

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
        let mut challenger = prove_lift_input.challenger.clone();

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

        let split_opts = self.prover_opts.core_opts.split_opts.clone();
        let deferred_promise: tokio::task::JoinHandle<Result<(), anyhow::Error>> =
            tokio::spawn(async move {
                let deferred_data =
                    deferred.context("Expected deferred data for non-precompile")?;

                let events = DeferredEvents::defer_record(deferred_data, split_opts).await?;
                info!("deferred_events: {:?}", events);

                let events_bytes = serialize_to_bincode_bytes(&events)
                    .context("Failed to serialize deferred_result")?;

                let deferred_output =
                    ProveLiftDeferredEventsOutput { deferred_events: events_bytes };

                tx.send(deferred_output)
                    .map_err(|_| anyhow!("Failed to send deferred response"))?;

                Ok(())
            });

        let pk = tracing::info_span!("pk_from_vk")
            .in_scope(|| self.prover.core_prover.pk_from_vk(&program, &vk));

        let data = tracing::info_span!("commit_main")
            .in_scope(|| self.prover.core_prover.commit(&shard, traces));

        let shard_proof = tracing::info_span!("prove_shard")
            .in_scope(|| self.prover.core_prover.open(&pk, data, &mut challenger).unwrap());

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
        let mut challenger = prove_lift_input.challenger.clone();

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

        let shard_proof = tracing::info_span!("prove_shard")
            .in_scope(|| self.prover.core_prover.open(&pk, data, &mut challenger).unwrap());

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

        let serialized = serialize_to_bincode_bytes(&reduce_proof)
            .context("Failed to serialize reduce_proof")?;

        let prove_lift_output = ProveLiftReduceProofOutput { reduce_proof: serialized };

        let elapsed = start_time.elapsed();
        info!("Agent::prove_lift_precompile() took {:?}", elapsed);

        Ok(prove_lift_output)
    }
}
