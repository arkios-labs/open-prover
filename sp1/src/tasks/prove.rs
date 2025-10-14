use crate::tasks::agent::Sp1Agent;
use crate::tasks::{ProveInput, ProveLiftInput};
use anyhow::{Context, Result};
use common::serialization::NestedArgBytes;
use common::serialization::bincode::{
    Bincode, deserialize_from_bincode_bytes, serialize_to_bincode_bytes,
};
use common::serialization::mpk::Msgpack;
use p3_field::AbstractField;
use sp1_core_executor::{ExecutionRecord, RiscvAirId};
use sp1_core_machine::shape::Shapeable;
use sp1_prover::shapes::SP1CompressProgramShape;
use sp1_prover::{CoreSC, SP1CircuitWitness};
use sp1_recursion_circuit::machine::{SP1RecursionShape, SP1RecursionWitnessValues};
use sp1_stark::air::MachineAir;
use sp1_stark::shape::OrderedShape;
use sp1_stark::{DIGEST_SIZE, MachineProver, StarkGenericConfig, Val};
use std::fs;
use std::slice::from_mut;
use std::str::FromStr;
use std::time::Instant;
use tracing::info;

impl Sp1Agent {
    pub fn prove(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::prove()");
        let start_time = Instant::now();

        let (Msgpack(record_path), (Msgpack(elf_path), Bincode(vk))): ProveInput =
            NestedArgBytes::from_nested_arg_bytes(&input).context("Failed to parse prove input")?;

        let record_bytes = fs::read(&record_path)
            .with_context(|| format!("Failed to read record file at {}", record_path))?;
        let elf_bytes = fs::read(&elf_path)
            .with_context(|| format!("Failed to read ELF file at {}", elf_path))?;
        let elf_deserialized: Vec<u8> =
            deserialize_from_bincode_bytes(&elf_bytes).context("Failed to deserialize ELF")?;

        let mut record: ExecutionRecord = deserialize_from_bincode_bytes(&record_bytes)
            .context("Failed to deserialize record")?;

        tracing::debug_span!("generate dependencies").in_scope(|| {
            self.prover.core_prover.machine().generate_dependencies(
                from_mut(&mut record),
                &self.prover_opts.core_opts,
                None,
            );
        });

        if let Some(shape_config) = &self.prover.core_shape_config {
            shape_config.fix_shape(&mut record).unwrap();
        }

        let program = self.prover.get_program(&elf_deserialized).expect("Failed to get program");

        let pkey = self.prover.core_prover.pk_from_vk(&program, &vk);

        let mut challenger = self.prover.core_prover.config().challenger();
        pkey.observe_into(&mut challenger);

        let traces = self.prover.core_prover.generate_traces(&record);

        let shard = record.shard();

        let main_data = tracing::debug_span!("commit", shard)
            .in_scope(|| self.prover.core_prover.commit(&record, traces));

        let shard_proof = tracing::debug_span!("opening", shard)
            .in_scope(|| self.prover.core_prover.open(&pkey, main_data, &mut challenger).unwrap());

        let serialized =
            serialize_to_bincode_bytes(&shard_proof).context("Failed to serialize shard_proof")?;
        let elapsed = start_time.elapsed();
        info!("Agent::prove() took {:?}", elapsed);
        Ok(serialized)
    }

    pub fn prove_lift(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::prove_lift()");
        let start_time = Instant::now();

        // Step 1: Load & process record
        let (Msgpack(record_path), (Msgpack(elf_path), (Bincode(vk), Bincode(deferred_digest)))): ProveLiftInput =
            NestedArgBytes::from_nested_arg_bytes(&input).context("Failed to parse prove_lift input")?;

        let record = fs::read(&record_path).context("Failed to read record file")?;
        let mut record = deserialize_from_bincode_bytes::<ExecutionRecord>(&record)
            .context("Failed to deserialize record")?;

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
        let elf_bytes = fs::read(&elf_path).context("Failed to read ELF file")?;
        let elf_deserialized: Vec<u8> =
            deserialize_from_bincode_bytes(&elf_bytes).context("Failed to deserialize ELF")?;
        let program = self.prover.get_program(&elf_deserialized).expect("Failed to get program");

        let pk = self.prover.core_prover.pk_from_vk(&program, &vk);
        let mut challenger = self.prover.core_prover.config().challenger();
        pk.observe_into(&mut challenger);

        // Step 3: Commit and Open
        let main_data = tracing::debug_span!("commit")
            .in_scope(|| self.prover.core_prover.commit(&record, traces));

        let shard_proof = tracing::debug_span!("opening").in_scope(|| {
            self.prover.core_prover.open(&pk, main_data, &mut challenger.clone()).unwrap()
        });

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

        let serialized = serialize_to_bincode_bytes(&reduce_proof)
            .context("Failed to serialize reduce_proof")?;

        let elapsed = start_time.elapsed();
        info!("Agent::prove_lift() took {:?}", elapsed);

        Ok(serialized)
    }
}
