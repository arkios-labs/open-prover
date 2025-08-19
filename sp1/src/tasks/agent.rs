use crate::tasks::{
    Agent, CompressInput, Groth16Input, PlonkInput, ProveInput, ProveLiftInput, SetupInput,
    ShrinkWrapInput, Sp1Agent, VerifyCompressInput, VerifyGroth16Input, VerifyPlonkInput,
    WrapCompressInput,
};
use anyhow::Context;
use cfg_if::cfg_if;
use common::serialization::bincode::{
    Bincode, deserialize_from_bincode_bytes, serialize_to_bincode_bytes,
};
use common::serialization::mpk::Msgpack;
use common::serialization::{FromInputBytes, parse_single_input};
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use sp1_core_executor::{ExecutionRecord, SP1ReduceProof};
use sp1_core_machine::shape::Shapeable;
use sp1_prover::{
    CoreSC, InnerSC, SP1_CIRCUIT_VERSION, SP1CircuitWitness, SP1PublicValues,
    SP1RecursionProverError, SP1VerifyingKey,
};
use sp1_recursion_circuit::machine::{SP1CompressWitnessValues, SP1RecursionWitnessValues};
use sp1_recursion_circuit::witness::Witnessable;
use sp1_recursion_compiler::config::InnerConfig;
use sp1_recursion_core::air::RecursionPublicValues;
use sp1_sdk::install::try_install_circuit_artifacts;
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues};
use sp1_stark::septic_digest::SepticDigest;
use sp1_stark::{Challenge, DIGEST_SIZE, MachineProver, SP1ProverOpts, StarkGenericConfig, Val};
use std::any::Any;
use std::borrow::Borrow;
use std::fs;
use std::slice::from_mut;
use std::sync::Arc;
use std::time::Instant;
use tracing::info;

#[cfg(feature = "gpu")]
use sp1_stark::MachineProvingKey;

impl Sp1Agent {
    pub fn new() -> anyhow::Result<Self> {
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

    fn setup(&self, input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        info!("Agent::setup()");
        let start_time = Instant::now();

        let Msgpack(elf_path): SetupInput =
            parse_single_input(&input).context("Failed to parse input")?;

        let elf_bytes = fs::read(&elf_path)
            .with_context(|| format!("Failed to read ELF file at {}", elf_path))?;

        let elf_deserialized: Vec<u8> = deserialize_from_bincode_bytes(&elf_bytes)
            .context("Failed to bincode deserialize ELF")?;

        let (_, _pkey, _, vkey) = self.prover.setup(&elf_deserialized);
        let vkey = serialize_to_bincode_bytes(&vkey).context("Failed to serialize vkey")?;
        let elapsed = start_time.elapsed();
        info!("Agent::setup() took {:?}", elapsed);
        Ok(vkey)
    }

    fn prove(&self, input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        info!("Agent::prove()");
        let start_time = Instant::now();

        let (Msgpack(record_path), (Msgpack(elf_path), Bincode(vk))): ProveInput =
            FromInputBytes::from_input_bytes(&input).context("Failed to parse input")?;

        let record_bytes = fs::read(&record_path)
            .with_context(|| format!("Failed to read record file at {}", record_path))?;
        let elf_bytes = fs::read(&elf_path)
            .with_context(|| format!("Failed to read ELF file at {}", elf_path))?;
        let elf_deserialized: Vec<u8> = deserialize_from_bincode_bytes(&elf_bytes)
            .context("Failed to bincode deserialize ELF")?;

        let mut record: ExecutionRecord = deserialize_from_bincode_bytes(&record_bytes)
            .context("Failed to bincode deserialize record")?;

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

        let serialized = serialize_to_bincode_bytes(&shard_proof).context("Failed to serialize")?;
        let elapsed = start_time.elapsed();
        info!("Agent::prove() took {:?}", elapsed);
        Ok(serialized)
    }

    fn prove_lift(&self, input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        info!("Agent::prove_lift()");
        let start_time = Instant::now();

        // Step 1: Load & process record
        let (Msgpack(record_path), (Msgpack(elf_path), Bincode(vk))): ProveLiftInput =
            FromInputBytes::from_input_bytes(&input).context("Failed to parse input")?;

        let record = fs::read(&record_path).context("Failed to read record file")?;
        let mut record = deserialize_from_bincode_bytes::<ExecutionRecord>(&record)
            .context("Failed to bincode deserialize record")?;

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
        let elf_deserialized: Vec<u8> = deserialize_from_bincode_bytes(&elf_bytes)
            .context("Failed to bincode deserialize ELF")?;
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
        let is_complete = false;
        let deferred_digest = [Val::<CoreSC>::zero(); DIGEST_SIZE];

        let recursion_witness = SP1RecursionWitnessValues {
            vk,
            shard_proofs: vec![shard_proof],
            reconstruct_deferred_digest: deferred_digest,
            is_complete,
            is_first_shard,
            vk_root: self.prover.recursion_vk_root,
        };

        let witness = SP1CircuitWitness::Core(recursion_witness);

        let (program, witness_stream) = match witness {
            SP1CircuitWitness::Core(input) => {
                let mut witness_stream = Vec::new();
                Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
                (self.prover.recursion_program(&input), witness_stream)
            }
            SP1CircuitWitness::Deferred(input) => {
                let mut witness_stream = Vec::new();
                Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
                (self.prover.deferred_program(&input), witness_stream)
            }
            SP1CircuitWitness::Compress(input) => {
                let mut witness_stream = Vec::new();
                let input_with_merkle = self.prover.make_merkle_proofs(input);
                Witnessable::<InnerConfig>::write(&input_with_merkle, &mut witness_stream);
                (self.prover.compress_program(&input_with_merkle), witness_stream)
            }
        };

        // Step 5: Run recursive prover
        let mut runtime =
            sp1_recursion_core::runtime::Runtime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
                program.clone(),
                self.prover.compress_prover.config().perm.clone(),
            );
        runtime.witness_stream = witness_stream.into();
        runtime
            .run()
            .map_err(|e| SP1RecursionProverError::RuntimeError(e.to_string()))
            .context("Failed to run")?;

        let record = runtime.record;

        // Step 6: Compress proof
        let mut records = vec![record];
        self.prover.compress_prover.machine().generate_dependencies(
            &mut records,
            &self.prover_opts.recursion_opts,
            None,
        );
        let record = records.into_iter().next().unwrap();
        let traces = self.prover.compress_prover.generate_traces(&record);

        let (_, vk) = self.prover.compress_prover.setup(&program);
        let pk = self.prover.compress_prover.pk_from_vk(&program, &vk);
        let mut challenger = self.prover.compress_prover.config().challenger();
        pk.observe_into(&mut challenger);

        let data = self.prover.compress_prover.commit(&record, traces);
        let proof = self
            .prover
            .compress_prover
            .open(&pk, data, &mut challenger)
            .map_err(|e| SP1RecursionProverError::RuntimeError(e.to_string()))
            .context("Failed to open with compress_prover")?;

        let recursion_proof: SP1ReduceProof<InnerSC> = SP1ReduceProof { vk, proof };
        let serialized =
            serialize_to_bincode_bytes(&recursion_proof).context("Failed to serialize")?;

        let elapsed = start_time.elapsed();
        info!("Agent::prove_lift() took {:?}", elapsed);

        Ok(serialized)
    }

    fn compress(&self, input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        info!("Agent::compress()");
        let start_time = Instant::now();

        // TODO: We don’t need to pass 'is_complete' as an argument,
        //       since it can be derived directly from the proofs.
        let (Bincode(left), (Bincode(right), Msgpack(_is_complete))): CompressInput =
            FromInputBytes::from_input_bytes(&input).context("Failed to parse input")?;

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

        // Step 1: Prepare witness and program
        let compress_input = SP1CompressWitnessValues {
            vks_and_proofs: vec![(left.vk, left.proof), (right.vk, right.proof)],
            is_complete,
        };

        let witness = SP1CircuitWitness::Compress(compress_input);

        let mut witness_stream = Vec::new();
        let program = match witness {
            SP1CircuitWitness::Core(input) => {
                Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
                self.prover.recursion_program(&input)
            }
            SP1CircuitWitness::Deferred(input) => {
                Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
                self.prover.deferred_program(&input)
            }
            SP1CircuitWitness::Compress(input) => {
                let input_with_merkle = self.prover.make_merkle_proofs(input.clone());
                Witnessable::<InnerConfig>::write(&input_with_merkle, &mut witness_stream);
                self.prover.compress_program(&input_with_merkle)
            }
        };

        // Step 2: Setup
        let (pk, vk) = self.prover.compress_prover.setup(&program);
        let mut challenger = self.prover.compress_prover.config().challenger();
        pk.observe_into(&mut challenger);

        // Step 3: Run prover with witness stream
        let mut runtime =
            sp1_recursion_core::runtime::Runtime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
                program.clone(),
                self.prover.compress_prover.config().perm.clone(),
            );
        runtime.witness_stream = witness_stream.into();

        runtime
            .run()
            .map_err(|e| SP1RecursionProverError::RuntimeError(e.to_string()))
            .context("Failed to run")?;

        // Step 4: Post-processing
        let mut records = vec![runtime.record];
        self.prover.compress_prover.machine().generate_dependencies(
            &mut records,
            &self.prover_opts.recursion_opts,
            None,
        );
        let record = records.into_iter().next().unwrap();

        let traces = self.prover.compress_prover.generate_traces(&record);
        let data = self.prover.compress_prover.commit(&record, traces);

        let proof = self
            .prover
            .compress_prover
            .open(&pk, data, &mut challenger)
            .map_err(|e| SP1RecursionProverError::RuntimeError(e.to_string()))
            .context("Failed to open with compress_prover")?;

        // Step 5: Final serialization
        let sp1_reduce_proof = SP1ReduceProof { vk, proof };
        let serialized = serialize_to_bincode_bytes(&sp1_reduce_proof)
            .context("Failed to serialize compressed proof")?;

        let elapsed = start_time.elapsed();
        info!("Agent::compress() took {:?}", elapsed);
        Ok(serialized)
    }

    fn shrink_wrap(&self, input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        info!("Agent::shrink_wrap()");
        let start_time = Instant::now();

        let Bincode(reduce_proof): ShrinkWrapInput =
            parse_single_input(&input).context("Failed to parse input")?;

        let shrink_proof =
            self.prover.shrink(reduce_proof, self.prover_opts).context("Failed to shrink")?;

        let wrap_proof =
            self.prover.wrap_bn254(shrink_proof, self.prover_opts).context("Failed to wrap")?;

        let serialized = serialize_to_bincode_bytes(&wrap_proof).context("Failed to serialize")?;
        let elapsed = start_time.elapsed();
        info!("Agent::shrink_wrap() took {:?}", elapsed);
        Ok(serialized)
    }

    fn groth16(&self, input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        info!("Agent::groth16()");
        let start_time = Instant::now();

        let (Msgpack(public_values_path), Bincode(wrap_proof)): Groth16Input =
            FromInputBytes::from_input_bytes(&input).context("Failed to parse input")?;

        let public_values_vec = fs::read(&public_values_path)
            .with_context(|| format!("Failed to read record file at {}", public_values_path))?;
        let public_values: SP1PublicValues = deserialize_from_bincode_bytes(&public_values_vec)
            .context("Failed to deserialize public values")?;

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
            .context("Failed to serialize")?;
        let elapsed = start_time.elapsed();
        info!("Agent::groth16() took {:?}", elapsed);
        Ok(serialized)
    }

    fn plonk(&self, input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        info!("Agent::plonk()");
        let start_time = Instant::now();

        let (Msgpack(public_values_path), Bincode(wrap_proof)): PlonkInput =
            FromInputBytes::from_input_bytes(&input).context("Failed to parse input")?;

        let public_values_vec = fs::read(&public_values_path)
            .with_context(|| format!("Failed to read record file at {}", public_values_path))?;
        let public_values: SP1PublicValues = deserialize_from_bincode_bytes(&public_values_vec)
            .context("Failed to deserialize public values")?;

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
            .context("Failed to serialize")?;
        let elapsed = start_time.elapsed();
        info!("Agent::plonk() took {:?}", elapsed);
        Ok(serialized)
    }

    fn wrap_compress(&self, input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        info!("Agent::wrap_compress()");
        let start_time = Instant::now();

        let (Msgpack(public_values_path), Bincode(compress_proof)): WrapCompressInput =
            FromInputBytes::from_input_bytes(&input).context("Failed to parse input")?;

        let public_values_vec = fs::read(&public_values_path)
            .with_context(|| format!("Failed to read record file at {}", public_values_path))?;

        let public_values: SP1PublicValues = deserialize_from_bincode_bytes(&public_values_vec)
            .context("Failed to deserialize public values")?;

        let compressed_proof_with_public_values: SP1ProofWithPublicValues =
            SP1ProofWithPublicValues {
                proof: SP1Proof::Compressed(Box::from(compress_proof)),
                public_values,
                sp1_version: SP1_CIRCUIT_VERSION.to_string(),
                tee_proof: None,
            };
        let serialized = serialize_to_bincode_bytes(&compressed_proof_with_public_values)
            .expect("Failed to serialize");
        let elapsed = start_time.elapsed();
        info!("Agent::wrap_compress() took {:?}", elapsed);
        Ok(serialized)
    }

    fn verify_compress(&self, input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        info!("Agent::verify_compressed()");
        let start_time = Instant::now();

        let (Bincode(compressed_proof), Bincode(vk)): VerifyCompressInput =
            FromInputBytes::from_input_bytes(&input).context("Failed to parse input")?;

        let vk = SP1VerifyingKey { vk };

        self.prover
            .verify_compressed(&compressed_proof.proof.try_as_compressed().unwrap(), &vk)
            .context("Compressed proof verification failed")?;

        let result = serialize_to_bincode_bytes(&true).context("Failed to serialize result")?;
        let elapsed = start_time.elapsed();
        info!("Agent::verify_compressed() took {:?}", elapsed);
        Ok(result)
    }

    fn verify_groth16(&self, input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        info!("Agent::verify_groth16()");
        let start_time = Instant::now();

        let (Bincode(groth16_proof), (Bincode(vk), Msgpack(public_values_path))): VerifyGroth16Input = FromInputBytes::from_input_bytes(&input).context("Failed to parse input")?;

        let vk = SP1VerifyingKey { vk };

        let public_values_vec = fs::read(&public_values_path)
            .with_context(|| format!("Failed to read record file at {}", public_values_path))?;

        let public_values: SP1PublicValues = deserialize_from_bincode_bytes(&public_values_vec)
            .context("Failed to deserialize public values")?;

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

    fn verify_plonk(&self, input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        info!("Agent::verify_plonk()");
        let start_time = Instant::now();

        let (Bincode(plonk_proof), (Bincode(vk), Msgpack(public_values_path))): VerifyPlonkInput =
            FromInputBytes::from_input_bytes(&input).context("Failed to parse input")?;

        let vk = SP1VerifyingKey { vk };

        let public_values_vec = fs::read(&public_values_path)
            .with_context(|| format!("Failed to read record file at {}", public_values_path))?;

        let public_values: SP1PublicValues = deserialize_from_bincode_bytes(&public_values_vec)
            .context("Failed to deserialize public values")?;

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
}
