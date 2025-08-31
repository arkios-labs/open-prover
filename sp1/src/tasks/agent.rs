use crate::tasks::{
    Agent, ClusterProverComponents, CompressInput, Groth16Input, PlonkInput, ProveInput,
    ProveLiftInput, SetupInput, ShrinkWrapInput, Sp1Agent, Traces, VerifyCompressInput,
    VerifyGroth16Input, VerifyPlonkInput, WrapCompressInput,
};
use anyhow::{Context, Error, Result};
use cfg_if::cfg_if;
use common::serialization::bincode::{
    Bincode, deserialize_from_bincode_bytes, serialize_to_bincode_bytes,
};
use common::serialization::mpk::Msgpack;
use common::serialization::{ArgBytes, NestedArgBytes};
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use sp1_core_executor::{ExecutionRecord, RiscvAirId, SP1ReduceProof};
use sp1_core_machine::shape::Shapeable;
use sp1_prover::shapes::SP1CompressProgramShape;
use sp1_prover::{
    CoreSC, DeviceProvingKey, InnerSC, SP1_CIRCUIT_VERSION, SP1CircuitWitness, SP1PublicValues,
    SP1RecursionProverError, SP1VerifyingKey,
};
use sp1_recursion_circuit::machine::{
    SP1CompressWithVkeyShape, SP1CompressWitnessValues, SP1DeferredWitnessValues,
    SP1RecursionShape, SP1RecursionWitnessValues,
};
use sp1_recursion_circuit::witness::Witnessable;
use sp1_recursion_compiler::config::InnerConfig;
use sp1_recursion_core::ExecutionRecord as RecursionExecutionRecord;
use sp1_recursion_core::RecursionProgram;
use sp1_recursion_core::air::RecursionPublicValues;
use sp1_sdk::install::try_install_circuit_artifacts;
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues};
use sp1_stark::air::MachineAir;
use sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2;
use sp1_stark::septic_digest::SepticDigest;
use sp1_stark::{
    Challenge, DIGEST_SIZE, MachineProver, SP1ProverOpts, ShardProof, StarkGenericConfig,
    StarkVerifyingKey, Val,
};
use std::any::Any;
use std::borrow::Borrow;
use std::fs;
use std::slice::from_mut;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info};

#[cfg(feature = "gpu")]
use sp1_stark::MachineProvingKey;
use sp1_stark::shape::OrderedShape;

impl Sp1Agent {
    pub fn new() -> Result<Self> {
        cfg_if! {
            if #[cfg(feature = "gpu")] {
                let inner_prover = moongate_prover::SP1GpuProver::new();
            } else {
                let inner_prover = sp1_prover::SP1Prover::new();
            }
        }
        let prover = Arc::new(inner_prover);

        Ok(Self { prover, prover_opts: SP1ProverOpts::default() })
    }
}

impl Agent for Sp1Agent {
    fn name(&self) -> &'static str {
        cfg_if! {
            if #[cfg(feature = "gpu")] {
                "sp1-gpu"
            } else {
                "sp1-cpu"
            }
        }
    }

    fn as_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }

    fn setup(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::setup()");
        let start_time = Instant::now();

        let Msgpack(elf_path): SetupInput =
            ArgBytes::from_arg_bytes(&input).context("Failed to parse setup input")?;

        let elf_bytes = fs::read(&elf_path)
            .with_context(|| format!("Failed to read ELF file at {}", elf_path))?;

        let elf_deserialized: Vec<u8> =
            deserialize_from_bincode_bytes(&elf_bytes).context("Failed to deserialize ELF")?;

        let (_, _, _, vk) = self.prover.setup(&elf_deserialized);
        let vk = serialize_to_bincode_bytes(&vk).context("Failed to serialize vk")?;
        let elapsed = start_time.elapsed();
        info!("Agent::setup() took {:?}", elapsed);
        Ok(vk)
    }

    fn prove(&self, input: Vec<u8>) -> Result<Vec<u8>> {
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

    fn prove_lift(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::prove_lift()");
        let start_time = Instant::now();

        // Step 1: Load & process record
        let (Msgpack(record_path), (Msgpack(elf_path), Bincode(vk))): ProveLiftInput =
            NestedArgBytes::from_nested_arg_bytes(&input)
                .context("Failed to parse prove_lift input")?;

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

        // The proof request is complete if it consists of only this single record.
        let is_complete = is_first_shard && has_no_next_record;
        let deferred_digest = [Val::<CoreSC>::zero(); DIGEST_SIZE];

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

    fn compress(&self, input: Vec<u8>) -> Result<Vec<u8>> {
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

    fn shrink_wrap(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::shrink_wrap()");
        let start_time = Instant::now();

        let Bincode(reduce_proof): ShrinkWrapInput =
            ArgBytes::from_arg_bytes(&input).context("Failed to parse shrink_wrap input")?;

        let shrink_proof =
            self.prover.shrink(reduce_proof, self.prover_opts).context("Failed to shrink")?;

        let wrap_proof =
            self.prover.wrap_bn254(shrink_proof, self.prover_opts).context("Failed to wrap")?;

        let serialized =
            serialize_to_bincode_bytes(&wrap_proof).context("Failed to serialize wrap_proof")?;
        let elapsed = start_time.elapsed();
        info!("Agent::shrink_wrap() took {:?}", elapsed);
        Ok(serialized)
    }

    fn groth16(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::groth16()");
        let start_time = Instant::now();

        let (Msgpack(public_values_path), Bincode(wrap_proof)): Groth16Input =
            NestedArgBytes::from_nested_arg_bytes(&input)
                .context("Failed to parse groth16 input")?;

        let public_values_vec = fs::read(&public_values_path)
            .with_context(|| format!("Failed to read record file at {}", public_values_path))?;
        let public_values: SP1PublicValues = deserialize_from_bincode_bytes(&public_values_vec)
            .context("Failed to deserialize public_values")?;

        let groth16_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
            sp1_prover::build::try_build_groth16_bn254_artifacts_dev(
                &wrap_proof.vk,
                &wrap_proof.proof,
            )
        } else {
            try_install_circuit_artifacts("groth16")
        };

        let groth16_proof = self.prover.wrap_groth16_bn254(wrap_proof, &groth16_bn254_artifacts);

        let groth16_proof_with_public_values: SP1ProofWithPublicValues = SP1ProofWithPublicValues {
            proof: SP1Proof::Groth16(groth16_proof),
            public_values,
            sp1_version: SP1_CIRCUIT_VERSION.to_string(),
            tee_proof: None,
        };

        let serialized = serialize_to_bincode_bytes(&groth16_proof_with_public_values)
            .context("Failed to serialize groth16_proof")?;
        let elapsed = start_time.elapsed();
        info!("Agent::groth16() took {:?}", elapsed);
        Ok(serialized)
    }

    fn plonk(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::plonk()");
        let start_time = Instant::now();

        let (Msgpack(public_values_path), Bincode(wrap_proof)): PlonkInput =
            NestedArgBytes::from_nested_arg_bytes(&input).context("Failed to parse plonk input")?;

        let public_values_vec = fs::read(&public_values_path)
            .with_context(|| format!("Failed to read record file at {}", public_values_path))?;
        let public_values: SP1PublicValues = deserialize_from_bincode_bytes(&public_values_vec)
            .context("Failed to deserialize public_values")?;

        let plonk_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
            sp1_prover::build::try_build_plonk_bn254_artifacts_dev(
                &wrap_proof.vk,
                &wrap_proof.proof,
            )
        } else {
            try_install_circuit_artifacts("plonk")
        };

        let plonk_proof = self.prover.wrap_plonk_bn254(wrap_proof, &plonk_bn254_artifacts);

        let plonk_proof_with_public_values: SP1ProofWithPublicValues = SP1ProofWithPublicValues {
            proof: SP1Proof::Plonk(plonk_proof),
            public_values,
            sp1_version: SP1_CIRCUIT_VERSION.to_string(),
            tee_proof: None,
        };

        let serialized = serialize_to_bincode_bytes(&plonk_proof_with_public_values)
            .context("Failed to serialize plonk_proof")?;
        let elapsed = start_time.elapsed();
        info!("Agent::plonk() took {:?}", elapsed);
        Ok(serialized)
    }

    fn wrap_compress(&self, input: Vec<u8>) -> Result<Vec<u8>> {
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

    fn verify_compress(&self, input: Vec<u8>) -> Result<Vec<u8>> {
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

    fn verify_groth16(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::verify_groth16()");
        let start_time = Instant::now();

        let (Bincode(groth16_proof), (Bincode(vk), Msgpack(public_values_path))): VerifyGroth16Input =
            NestedArgBytes::from_nested_arg_bytes(&input).context("Failed to parse verify_groth16 input")?;

        let vk = SP1VerifyingKey { vk };

        let public_values_vec = fs::read(&public_values_path)
            .with_context(|| format!("Failed to read record file at {}", public_values_path))?;

        let public_values: SP1PublicValues = deserialize_from_bincode_bytes(&public_values_vec)
            .context("Failed to deserialize public_values")?;

        let groth16_bn254_artifacts = try_install_circuit_artifacts("groth16");

        self.prover
            .verify_groth16_bn254(
                &groth16_proof.proof.try_as_groth_16().unwrap(),
                &vk,
                &public_values,
                &groth16_bn254_artifacts,
            )
            .context("Groth16 proof verification failed")?;

        let result = serialize_to_bincode_bytes(&true).context("Failed to serialize result")?;
        let elapsed = start_time.elapsed();
        info!("Agent::verify_groth16() took {:?}", elapsed);
        Ok(result)
    }

    fn verify_plonk(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::verify_plonk()");
        let start_time = Instant::now();

        let (Bincode(plonk_proof), (Bincode(vk), Msgpack(public_values_path))): VerifyPlonkInput =
            NestedArgBytes::from_nested_arg_bytes(&input)
                .context("Failed to parse verify_plonk input")?;

        let vk = SP1VerifyingKey { vk };

        let public_values_vec = fs::read(&public_values_path)
            .with_context(|| format!("Failed to read record file at {}", public_values_path))?;

        let public_values: SP1PublicValues = deserialize_from_bincode_bytes(&public_values_vec)
            .context("Failed to deserialize public_values")?;

        let plonk_bn254_artifacts = try_install_circuit_artifacts("plonk");

        self.prover
            .verify_plonk_bn254(
                &plonk_proof.proof.try_as_plonk().unwrap(),
                &vk,
                &public_values,
                &plonk_bn254_artifacts,
            )
            .context("Plonk proof verification failed")?;

        let result = serialize_to_bincode_bytes(&true).context("Failed to serialize result")?;
        let elapsed = start_time.elapsed();
        info!("Agent::verify_plonk() took {:?}", elapsed);
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

    fn full_recursion(
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
        _shape: SP1CompressWithVkeyShape,
        program: Arc<RecursionProgram<Val<InnerSC>>>,
    ) -> Arc<(DeviceProvingKey<ClusterProverComponents>, StarkVerifyingKey<InnerSC>)> {
        Arc::from(self.prover.compress_prover.setup(&program))
    }

    fn prove_deferred_leaves(
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
