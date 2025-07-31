use crate::tasks::{Agent, COMPRESS_INPUT_LEN, PROVE_INPUT_LEN, PROVE_LIFT_INPUT_LEN};
use anyhow::{bail, Context};
use async_trait::async_trait;
use common::serialization::bincode::{deserialize_from_bincode_bytes, serialize_to_bincode_bytes};
use common::serialization::mpk::deserialize_from_msgpack_bytes;
use p3_field::AbstractField;
use sp1_core_executor::{ExecutionRecord, SP1ReduceProof};
use sp1_core_machine::shape::Shapeable;
use sp1_prover::{CoreSC, InnerSC, OuterSC, SP1CircuitWitness, SP1Prover, SP1RecursionProverError};
use sp1_recursion_circuit::machine::{SP1CompressWitnessValues, SP1RecursionWitnessValues};
use sp1_recursion_circuit::witness::Witnessable;
use sp1_recursion_compiler::config::InnerConfig;
use sp1_sdk::install::try_install_circuit_artifacts;
use sp1_stark::{
    Challenge, MachineProver, SP1ProverOpts, StarkGenericConfig, StarkVerifyingKey, Val,
    DIGEST_SIZE,
};
use std::any::Any;
use std::fs;
use std::slice::from_mut;
use std::sync::Arc;
use std::time::Instant;
use tracing::info;

pub struct CpuAgent {
    pub prover: Arc<SP1Prover>,
    pub prover_opts: SP1ProverOpts,
}

impl CpuAgent {
    pub fn new() -> Self {
        Self {
            prover: Arc::new(SP1Prover::new()),
            prover_opts: SP1ProverOpts::default(),
        }
    }
}

#[async_trait]
impl Agent for CpuAgent {
    fn as_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }

    fn setup(&self, input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        info!("CpuAgent::setup()");

        if input.is_empty() {
            bail!("shrink input is empty");
        }
        let start_time = Instant::now();

        let elf_path: String =
            deserialize_from_msgpack_bytes(&input).context("Failed to deserialize ELF path")?;

        let elf_bytes = fs::read(&elf_path)
            .with_context(|| format!("Failed to read ELF file at {}", elf_path))?;

        let (_, _pkey, _, vkey) = self.prover.setup(&elf_bytes);
        let vkey = serialize_to_bincode_bytes(&vkey).context("Failed to serialize vkey")?;
        let elapsed = start_time.elapsed();
        info!("CpuAgent::setup() took {:?}", elapsed);
        Ok(vkey)
    }

    fn prove(&self, input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        info!("CpuAgent::prove()");
        if input.is_empty() {
            bail!("prove input is empty");
        }
        let start_time = Instant::now();

        let inputs: Vec<Vec<u8>> = deserialize_from_msgpack_bytes(&input)
            .context("Failed to parse input as Vec<Vec<u8>>")?;

        if inputs.len() != PROVE_INPUT_LEN {
            bail!(
                "Expected {PROVE_INPUT_LEN} inputs for prove, got {}",
                inputs.len()
            );
        }

        let record_path: String = deserialize_from_msgpack_bytes(&inputs[0])
            .context("Failed to deserialize record path")?;
        let elf_path: String =
            deserialize_from_msgpack_bytes(&inputs[1]).context("Failed to deserialize ELF path")?;
        let vk: StarkVerifyingKey<CoreSC> =
            deserialize_from_bincode_bytes(&inputs[2]).context("Failed to deserialize vk")?;

        let record_bytes = fs::read(&record_path)
            .with_context(|| format!("Failed to read record file at {}", record_path))?;
        let elf_bytes = fs::read(&elf_path)
            .with_context(|| format!("Failed to read ELF file at {}", elf_path))?;

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

        let program = self
            .prover
            .get_program(&elf_bytes)
            .expect("Failed to get program");

        let pkey = self.prover.core_prover.pk_from_vk(&program, &vk);

        let mut challenger = self.prover.core_prover.config().challenger();
        pkey.observe_into(&mut challenger);

        let traces = self.prover.core_prover.generate_traces(&record);

        let shard = record.shard();

        let main_data = tracing::debug_span!("commit", shard)
            .in_scope(|| self.prover.core_prover.commit(&record, traces));

        let shard_proof = tracing::debug_span!("opening", shard).in_scope(|| {
            self.prover
                .core_prover
                .open(&pkey, main_data, &mut challenger)
                .unwrap()
        });

        let serialized = serialize_to_bincode_bytes(&shard_proof).context("Failed to serialize")?;
        let elapsed = start_time.elapsed();
        info!("CpuAgent::prove() took {:?}", elapsed);
        Ok(serialized)
    }

    fn prove_lift(&self, input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        info!("CpuAgent::prove_lift()");
        let start_time = Instant::now();

        if input.is_empty() {
            bail!("prove input is empty");
        }

        let inputs: Vec<Vec<u8>> = deserialize_from_msgpack_bytes(&input)
            .context("Failed to parse input as Vec<Vec<u8>>")?;

        if inputs.len() != PROVE_LIFT_INPUT_LEN {
            bail!(
                "Expected {PROVE_LIFT_INPUT_LEN} inputs for prove_lift, got {}",
                inputs.len()
            );
        }

        let vk = deserialize_from_bincode_bytes::<StarkVerifyingKey<CoreSC>>(&inputs[2])
            .context("Failed to deserialize vk")?;

        // Step 1: Load & process record
        let record_path = deserialize_from_msgpack_bytes::<String>(&inputs[0])
            .context("Failed to deserialize record path")?;
        let bytes = fs::read(&record_path).context("Failed to read record file")?;
        let mut record = deserialize_from_bincode_bytes::<ExecutionRecord>(&bytes)
            .context("Failed to bincode deserialize record")?;

        self.prover.core_prover.machine().generate_dependencies(
            from_mut(&mut record),
            &self.prover_opts.core_opts,
            None,
        );

        if let Some(shape_config) = &self.prover.core_shape_config {
            shape_config
                .fix_shape(&mut record)
                .context("Failed to fix shape")?;
        }
        let traces = self.prover.core_prover.generate_traces(&record);

        // Step 2: Load ELF & generate PK, challenger
        let elf_path = deserialize_from_msgpack_bytes::<String>(&inputs[1])
            .context("Failed to deserialize ELF path")?;
        let elf_bytes = fs::read(&elf_path).context("Failed to read ELF file")?;
        let program = self
            .prover
            .get_program(&elf_bytes)
            .expect("Failed to get program");

        let pk = self.prover.core_prover.pk_from_vk(&program, &vk);
        let mut challenger = self.prover.core_prover.config().challenger();
        pk.observe_into(&mut challenger);

        // Step 3: Commit and Open
        let main_data = tracing::debug_span!("commit")
            .in_scope(|| self.prover.core_prover.commit(&record, traces));

        let shard_proof = tracing::debug_span!("opening").in_scope(|| {
            self.prover
                .core_prover
                .open(&pk, main_data, &mut challenger.clone())
                .unwrap()
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
                (
                    self.prover.compress_program(&input_with_merkle),
                    witness_stream,
                )
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
        info!("CpuAgent::prove_lift() took {:?}", elapsed);

        Ok(serialized)
    }

    fn compress(&self, input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        info!("CpuAgent::compress()");
        let start_time = Instant::now();

        if input.is_empty() {
            bail!("compress input is empty");
        }

        let inputs: Vec<Vec<u8>> = deserialize_from_msgpack_bytes(&input)
            .context("Failed to parse input as Vec<Vec<u8>>")?;

        if inputs.len() != COMPRESS_INPUT_LEN {
            bail!(
                "Expected exactly {COMPRESS_INPUT_LEN} inputs for compress, got {}",
                inputs.len()
            );
        }

        let left: SP1ReduceProof<InnerSC> = deserialize_from_bincode_bytes(&inputs[0])
            .context("Failed to deserialize left receipt")?;
        let right: SP1ReduceProof<InnerSC> = deserialize_from_bincode_bytes(&inputs[1])
            .context("Failed to deserialize right receipt")?;
        let is_complete: bool = deserialize_from_msgpack_bytes(&inputs[2])
            .context("Failed to deserialize is_complete")?;

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
        info!("CpuAgent::compress() took {:?}", elapsed);
        Ok(serialized)
    }

    fn shrink(&self, input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        info!("CpuAgent::shrink()");

        if input.is_empty() {
            bail!("shrink input is empty");
        }
        let start_time = Instant::now();

        let reduce_proof: SP1ReduceProof<InnerSC> =
            deserialize_from_bincode_bytes(&input).context("Failed to deserialize reduce proof")?;

        let shrink_proof = self
            .prover
            .shrink(reduce_proof, self.prover_opts)
            .context("Failed to shrink")?;

        let serialized =
            serialize_to_bincode_bytes(&shrink_proof).context("Failed to serialize")?;
        let elapsed = start_time.elapsed();

        info!("CpuAgent::shrink() took {:?}", elapsed);
        Ok(serialized)
    }

    fn wrap(&self, input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        info!("CpuAgent::wrap()");

        if input.is_empty() {
            bail!("wrap input is empty");
        }
        let start_time = Instant::now();

        let shrink_proof: SP1ReduceProof<InnerSC> =
            deserialize_from_bincode_bytes(&input).context("Failed to deserialize shrink proof")?;

        let wrap_proof = self
            .prover
            .wrap_bn254(shrink_proof, self.prover_opts)
            .context("Failed to wrap")?;

        let serialized = serialize_to_bincode_bytes(&wrap_proof).context("Failed to serialize")?;
        let elapsed = start_time.elapsed();

        info!("CpuAgent::wrap() took {:?}", elapsed);
        Ok(serialized)
    }

    fn groth16(&self, input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        info!("CpuAgent::groth16()");

        if input.is_empty() {
            bail!("groth16 input is empty");
        }
        let start_time = Instant::now();

        let wrap_proof: SP1ReduceProof<OuterSC> =
            deserialize_from_bincode_bytes(&input).context("Failed to deserialize wrap proof")?;

        let groth16_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
            sp1_prover::build::try_build_groth16_bn254_artifacts_dev(
                &wrap_proof.vk,
                &wrap_proof.proof,
            )
        } else {
            try_install_circuit_artifacts("groth16")
        };

        let groth16_proof = self
            .prover
            .wrap_groth16_bn254(wrap_proof, &groth16_bn254_artifacts);

        let serialized =
            serialize_to_bincode_bytes(&groth16_proof).context("Failed to serialize")?;
        let elapsed = start_time.elapsed();

        info!("CpuAgent::groth16() took {:?}", elapsed);
        Ok(serialized)
    }

    fn plonk(&self, input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        info!("CpuAgent::plonk()");
        let start_time = Instant::now();
        if input.is_empty() {
            bail!("plonk input is empty");
        }

        let wrap_proof: SP1ReduceProof<OuterSC> =
            deserialize_from_bincode_bytes(&input).context("Failed to deserialize wrap proof")?;

        let plonk_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
            sp1_prover::build::try_build_plonk_bn254_artifacts_dev(
                &wrap_proof.vk,
                &wrap_proof.proof,
            )
        } else {
            try_install_circuit_artifacts("plonk")
        };

        let plonk_proof = self
            .prover
            .wrap_plonk_bn254(wrap_proof, &plonk_bn254_artifacts);

        let serialized = serialize_to_bincode_bytes(&plonk_proof).context("Failed to serialize")?;
        let elapsed = start_time.elapsed();

        info!("CpuAgent::plonk() took {:?}", elapsed);
        Ok(serialized)
    }
}
