use crate::tasks::agent::{ClusterProverComponents, Sp1Agent};
use crate::tasks::{CompressInput, LiftDeferInput, Traces, VerifyCompressInput, WrapCompressInput};
use anyhow::{Context, Error, Result};
use common::serialization::bincode::{
    Bincode, deserialize_from_bincode_bytes, serialize_to_bincode_bytes,
};
use common::serialization::mpk::Msgpack;
use common::serialization::{ArgBytes, NestedArgBytes};
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use sp1_core_executor::SP1ReduceProof;
use sp1_prover::{
    DeviceProvingKey, InnerSC, SP1_CIRCUIT_VERSION, SP1CircuitWitness, SP1PublicValues,
    SP1RecursionProverError, SP1VerifyingKey,
};
use sp1_recursion_circuit::machine::{
    SP1CompressWithVkeyShape, SP1CompressWitnessValues, SP1DeferredWitnessValues,
};
use sp1_recursion_circuit::witness::Witnessable;
use sp1_recursion_compiler::config::InnerConfig;
use sp1_recursion_core::ExecutionRecord as RecursionExecutionRecord;
use sp1_recursion_core::RecursionProgram;
use sp1_recursion_core::air::RecursionPublicValues;
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues};
use sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2;
use sp1_stark::septic_digest::SepticDigest;
use sp1_stark::{
    Challenge, DIGEST_SIZE, MachineProver, SP1ProverOpts, ShardProof, StarkGenericConfig,
    StarkVerifyingKey, Val,
};
use std::borrow::Borrow;
use std::fs;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info};

#[cfg(feature = "gpu")]
use sp1_stark::MachineProvingKey;

impl Sp1Agent {
    pub fn lift_defer(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::lift_defer()");
        let start_time = Instant::now();

        let Msgpack(deferred_input): LiftDeferInput =
            ArgBytes::from_arg_bytes(&input).context("Failed to parse lift_defer input")?;

        let reduce_proof = self
            .setup_and_prove_compress(SP1CircuitWitness::Deferred(deferred_input), self.prover_opts)
            .context("Failed to prove deferred")?;

        let serialized = serialize_to_bincode_bytes(&reduce_proof)
            .context("Failed to serialize reduce_proof")?;

        let elapsed = start_time.elapsed();
        info!("Agent::lift_defer() took {:?}", elapsed);
        Ok(serialized)
    }

    pub fn compress(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::compress()");
        let start_time = Instant::now();

        let (Bincode(left), Bincode(right)): CompressInput =
            NestedArgBytes::from_nested_arg_bytes(&input)
                .context("Failed to parse compress input")?;

        let first_pv: &RecursionPublicValues<BabyBear> =
            left.proof.public_values.as_slice().borrow();
        let last_pv: &RecursionPublicValues<BabyBear> =
            right.proof.public_values.as_slice().borrow();

        let zero_sum = [first_pv.global_cumulative_sum, last_pv.global_cumulative_sum]
            .into_iter()
            .sum::<SepticDigest<BabyBear>>()
            .is_zero();
        let is_complete = first_pv.start_shard == BabyBear::one()
            && last_pv.next_pc == BabyBear::zero()
            && first_pv.start_reconstruct_deferred_digest == [BabyBear::zero(); DIGEST_SIZE]
            && zero_sum;

        let witness = SP1CircuitWitness::Compress(SP1CompressWitnessValues {
            vks_and_proofs: vec![(left.vk, left.proof), (right.vk, right.proof)],
            is_complete,
        });

        let reduce_proof = self
            .setup_and_prove_compress(witness, self.prover_opts)
            .context("Failed to setup and prove compress")?;

        let serialized = serialize_to_bincode_bytes(&reduce_proof)
            .context("Failed to serialize reduce_proof")?;

        let elapsed = start_time.elapsed();
        info!("Agent::compress() took {:?}", elapsed);
        Ok(serialized)
    }

    pub fn wrap_compress(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::wrap_compress()");
        let start_time = Instant::now();

        let (Msgpack(public_values_path), Bincode(compress_proof)): WrapCompressInput =
            NestedArgBytes::from_nested_arg_bytes(&input)
                .context("Failed to parse wrap_compress input")?;

        let public_values_vec = fs::read(&public_values_path)
            .with_context(|| format!("Failed to read record file at {}", public_values_path))?;

        let public_values: SP1PublicValues = deserialize_from_bincode_bytes(&public_values_vec)
            .context("Failed to deserialize public_values")?;

        let compressed_proof_with_public_values: SP1ProofWithPublicValues =
            SP1ProofWithPublicValues {
                proof: SP1Proof::Compressed(Box::from(compress_proof)),
                public_values,
                sp1_version: SP1_CIRCUIT_VERSION.to_string(),
                tee_proof: None,
            };
        let serialized = serialize_to_bincode_bytes(&compressed_proof_with_public_values)
            .expect("Failed to serialize compressed_proof");
        let elapsed = start_time.elapsed();
        info!("Agent::wrap_compress() took {:?}", elapsed);
        Ok(serialized)
    }

    pub fn verify_compress(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::verify_compressed()");
        let start_time = Instant::now();

        let (Bincode(compressed_proof), Bincode(vk)): VerifyCompressInput =
            NestedArgBytes::from_nested_arg_bytes(&input)
                .context("Failed to parse verify_compress input")?;

        let vk = SP1VerifyingKey { vk };

        self.prover
            .verify_compressed(&compressed_proof.proof.try_as_compressed().unwrap(), &vk)
            .context("Compressed proof verification failed")?;

        let result = serialize_to_bincode_bytes(&true).context("Failed to serialize result")?;
        let elapsed = start_time.elapsed();
        info!("Agent::verify_compressed() took {:?}", elapsed);
        Ok(result)
    }

    fn setup_and_prove_compress(
        &self,
        input: SP1CircuitWitness,
        opts: SP1ProverOpts,
    ) -> Result<SP1ReduceProof<InnerSC>, Error> {
        let (program, input, cache_shape) = {
            match &input {
                SP1CircuitWitness::Core(input_core) => {
                    let program = self.prover.recursion_program(input_core);
                    (program, input, None)
                }
                SP1CircuitWitness::Deferred(input_def) => {
                    let program = self.prover.deferred_program(input_def);
                    (program, input, None)
                }
                SP1CircuitWitness::Compress(input_comp) => {
                    let input_with_merkle = self.prover.make_merkle_proofs(input_comp.clone());
                    let cache_shape = input_with_merkle.shape();
                    let program = self.prover.compress_program(&input_with_merkle);
                    (program, SP1CircuitWitness::Compress(input_comp.clone()), Some(cache_shape))
                }
            }
        };

        debug!("program shape: {:?}", program.shape);

        let reduce_proof = self
            .full_recursion(program, input, opts, cache_shape)
            .context("Failed to run full recursion")?;

        Ok(reduce_proof)
    }

    pub(crate) fn full_recursion(
        &self,
        program: Arc<RecursionProgram<Val<InnerSC>>>,
        input: SP1CircuitWitness,
        opts: SP1ProverOpts,
        cached_keys: Option<SP1CompressWithVkeyShape>,
    ) -> Result<SP1ReduceProof<InnerSC>, Error> {
        let program_clone = program.clone();
        let record =
            self.prepare_recursion(program_clone, input).context("Failed to prepare recursion")?;

        let mut records = vec![record];

        // Generate dependencies
        tracing::info_span!("generate dependencies").in_scope(|| {
            self.prover.compress_prover.machine().generate_dependencies(
                &mut records,
                &opts.recursion_opts,
                None,
            )
        });

        let record = records.into_iter().next().unwrap();

        let generated_traces = self.prover.compress_prover.generate_traces(&record);

        let record_and_traces = (record, generated_traces);

        let reduce_proof = self.prove_recursion(program, record_and_traces, cached_keys)?;

        Ok(reduce_proof)
    }

    fn prepare_recursion(
        &self,
        program: Arc<RecursionProgram<Val<InnerSC>>>,
        input: SP1CircuitWitness,
    ) -> Result<RecursionExecutionRecord<Val<InnerSC>>, Error> {
        let mut witness_stream = Vec::new();

        let witness_stream = tracing::info_span!("Get witness stream").in_scope(|| match input {
            SP1CircuitWitness::Core(input) => {
                Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
                witness_stream
            }
            SP1CircuitWitness::Deferred(input) => {
                Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
                witness_stream
            }
            SP1CircuitWitness::Compress(input) => {
                let input_with_merkle = self.prover.make_merkle_proofs(input);
                Witnessable::<InnerConfig>::write(&input_with_merkle, &mut witness_stream);
                witness_stream
            }
        });

        let mut runtime =
            sp1_recursion_core::runtime::Runtime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
                program,
                self.prover.compress_prover.config().perm.clone(),
            );
        runtime.witness_stream = witness_stream.into();
        runtime
            .run()
            .map_err(|e| SP1RecursionProverError::RuntimeError(e.to_string()))
            .context("Failed to run")?;

        Ok(runtime.record)
    }

    fn prove_recursion(
        &self,
        program: Arc<RecursionProgram<Val<InnerSC>>>,
        record_and_traces: (RecursionExecutionRecord<Val<InnerSC>>, Traces),
        cache_shape: Option<SP1CompressWithVkeyShape>,
    ) -> Result<SP1ReduceProof<InnerSC>, Error> {
        // Setup the program
        let (ref pk, ref vk) = *cache_shape
            .map(|shape| self.get_compress_keys(shape, program.clone()))
            .unwrap_or_else(|| {
                let (pk, vk) = tracing::info_span!("Setup compress program")
                    .in_scope(|| self.prover.compress_prover.setup(&program));
                Arc::new((pk, vk))
            });

        let mut challenger = self.prover.compress_prover.config().challenger();
        pk.observe_into(&mut challenger);

        let (record, traces) = record_and_traces;

        // Commit to the record and traces
        let data = tracing::info_span!("commit")
            .in_scope(|| self.prover.compress_prover.commit(&record, traces));

        drop(record);

        let proof = tracing::info_span!("open").in_scope(|| {
            self.prover
                .compress_prover
                .open(pk, data, &mut challenger)
                .map_err(|e| SP1RecursionProverError::RuntimeError(e.to_string()))
        })?;

        let reduce_proof = SP1ReduceProof { proof, vk: vk.clone() };
        Ok(reduce_proof)
    }

    fn get_compress_keys(
        &self,
        shape: SP1CompressWithVkeyShape,
        program: Arc<RecursionProgram<Val<InnerSC>>>,
    ) -> Arc<(DeviceProvingKey<ClusterProverComponents>, StarkVerifyingKey<InnerSC>)> {
        {
            let read = self.compress_keys.read().unwrap();
            if let Some(keys) = read.get(&shape) {
                return keys.clone();
            }
        }
        let mut write = self.compress_keys.write().unwrap();
        let keys = Arc::new(self.prover.compress_prover.setup(&program));
        write.insert(shape, keys.clone());
        keys
    }

    pub fn prove_deferred_leaves(
        &self,
        vk: &StarkVerifyingKey<InnerSC>,
        vks_and_proofs: Vec<(StarkVerifyingKey<BabyBearPoseidon2>, ShardProof<BabyBearPoseidon2>)>,
    ) -> Result<(Vec<SP1DeferredWitnessValues<InnerSC>>, [BabyBear; DIGEST_SIZE]), Error> {
        let reduce_proofs: Vec<SP1ReduceProof<BabyBearPoseidon2>> = vks_and_proofs
            .into_iter()
            .map(|(vk, shard_proof)| SP1ReduceProof { vk, proof: shard_proof })
            .collect();

        let (deferred_inputs, deferred_digest) =
            self.prover.get_recursion_deferred_inputs(vk, &reduce_proofs, 1);

        Ok((deferred_inputs, deferred_digest))
    }
}
