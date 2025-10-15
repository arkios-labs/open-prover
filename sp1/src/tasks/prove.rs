use crate::tasks::agent::Sp1Agent;
use crate::tasks::{ProveInput, ProveLiftInput, ProveLiftOutput, ProveOutput};
use anyhow::{Context, Result};
use common::serialization::bincode::serialize_to_bincode_bytes;
use p3_field::AbstractField;
use sp1_core_executor::RiscvAirId;
use sp1_core_machine::shape::Shapeable;
use sp1_prover::shapes::SP1CompressProgramShape;
use sp1_prover::{CoreSC, SP1CircuitWitness};
use sp1_recursion_circuit::machine::{SP1RecursionShape, SP1RecursionWitnessValues};
use sp1_stark::air::MachineAir;
use sp1_stark::shape::OrderedShape;
use sp1_stark::{DIGEST_SIZE, MachineProver, Val};
use std::slice::from_mut;
use std::str::FromStr;
use std::time::Instant;
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

    pub fn prove_lift(&self, prove_lift_input: ProveLiftInput) -> Result<ProveLiftOutput> {
        info!("Agent::prove_lift()");
        let start_time = Instant::now();

        // Step 1: Load & process record
        let mut record = prove_lift_input.record;
        let elf = prove_lift_input.elf;
        let vk = prove_lift_input.vk;
        let mut challenger = prove_lift_input.challenger;
        let deferred_digest = prove_lift_input.deferred_digest;

        self.prover.core_prover.machine().generate_dependencies(
            from_mut(&mut record),
            &self.prover_opts.core_opts,
            None,
        );

        if let Some(shape_config) = &self.prover.core_shape_config {
            shape_config.fix_shape(&mut record).context("Failed to fix shape")?;
        }
        let traces = self.prover.core_prover.generate_traces(&record);

        // Step 2: Load ELF & generate PK, challenger
        let program = self.prover.get_program(&elf).expect("Failed to get program");

        let pk = self.prover.core_prover.pk_from_vk(&program, &vk);

        // Step 3: Commit and Open
        let main_data = tracing::debug_span!("commit")
            .in_scope(|| self.prover.core_prover.commit(&record, traces));

        let shard_proof = tracing::debug_span!("opening")
            .in_scope(|| self.prover.core_prover.open(&pk, main_data, &mut challenger).unwrap());

        // Step 4: Generate recursion witness
        let is_first_shard = record.public_values.shard == 1;
        let has_no_next_record = record.public_values.next_pc == 0;
        let has_no_deferred_proofs = deferred_digest == [Val::<CoreSC>::zero(); DIGEST_SIZE];

        // The proof request is complete if first shard, no next record, and no deferred proofs.
        let is_complete = is_first_shard && has_no_next_record && has_no_deferred_proofs;

        let witness = SP1CircuitWitness::Core(SP1RecursionWitnessValues {
            vk,
            shard_proofs: vec![shard_proof],
            reconstruct_deferred_digest: deferred_digest,
            is_complete,
            is_first_shard,
            vk_root: self.prover.recursion_vk_root,
        });

        let proof_shape = {
            let chips = self.prover.core_prover.shard_chips(&record).collect::<Vec<_>>();
            let shape = record.shape.as_ref().expect("shape not set");

            let mut heights = Vec::with_capacity(chips.len());
            for chip in chips.into_iter() {
                let id = RiscvAirId::from_str(&chip.name()).unwrap();
                let height = shape.log2_height(&id).unwrap();
                heights.push((chip.name(), height));
            }
            OrderedShape::from_log2_heights(&heights)
        };

        let compress_shape = SP1CompressProgramShape::Recursion(SP1RecursionShape {
            proof_shapes: vec![proof_shape],
            is_complete,
        });
        let program = self.prover.program_from_shape(compress_shape, None);

        let reduce_proof = self
            .full_recursion(program, witness, self.prover_opts, None)
            .context("Failed to reduce proof")?;

        let reduce_proof =
            serialize_to_bincode_bytes(&reduce_proof).context("Failed to serialize shard_proof")?;
        let prove_output = ProveLiftOutput { reduce_proof };

        let elapsed = start_time.elapsed();
        info!("Agent::prove_lift() took {:?}", elapsed);

        Ok(prove_output)
    }
}
