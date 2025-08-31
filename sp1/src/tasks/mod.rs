use anyhow::{Error, Result};
use common::serialization::bincode::Bincode;
use common::serialization::mpk::Msgpack;
use p3_baby_bear::BabyBear;
use p3_matrix::dense::DenseMatrix;
use sp1_core_executor::SP1ReduceProof;
use sp1_prover::{CoreSC, DeviceProvingKey, InnerSC, OuterSC, SP1CircuitWitness, SP1Prover};
use sp1_recursion_circuit::machine::{SP1CompressWithVkeyShape, SP1DeferredWitnessValues};
use sp1_recursion_core::RecursionProgram;
use sp1_recursion_core::{DIGEST_SIZE, ExecutionRecord as RecursionExecutionRecord};
use sp1_sdk::SP1ProofWithPublicValues;
use sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2;
use sp1_stark::{SP1ProverOpts, ShardProof, StarkVerifyingKey, Val};
use std::any::Any;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

mod agent;

#[cfg(feature = "gpu")]
pub type ClusterProverComponents = moongate_prover::components::GpuProverComponents;
#[cfg(not(feature = "gpu"))]
pub type ClusterProverComponents = sp1_prover::components::CpuProverComponents;

pub type CachedKeys = Arc<(DeviceProvingKey<ClusterProverComponents>, StarkVerifyingKey<InnerSC>)>;

pub struct Sp1Agent {
    pub prover: Arc<SP1Prover<ClusterProverComponents>>,
    pub prover_opts: SP1ProverOpts,
    pub compress_keys: RwLock<BTreeMap<SP1CompressWithVkeyShape, CachedKeys>>,
}

pub trait Agent: Send + Sync {
    fn name(&self) -> &'static str;
    fn as_any(self: Box<Self>) -> Box<dyn Any>;
    fn setup(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn prove(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn prove_lift(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn compress(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn shrink_wrap(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn groth16(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn plonk(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn wrap_compress(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn verify_compress(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn verify_groth16(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn verify_plonk(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn setup_and_prove_compress(
        &self,
        input: SP1CircuitWitness,
        opts: SP1ProverOpts,
    ) -> Result<SP1ReduceProof<InnerSC>, Error>;
    fn full_recursion(
        &self,
        program: Arc<RecursionProgram<Val<InnerSC>>>,
        input: SP1CircuitWitness,
        opts: SP1ProverOpts,
        cached_keys: Option<SP1CompressWithVkeyShape>,
    ) -> Result<SP1ReduceProof<InnerSC>, Error>;
    fn prepare_recursion(
        &self,
        program: Arc<RecursionProgram<Val<InnerSC>>>,
        input: SP1CircuitWitness,
    ) -> Result<RecursionExecutionRecord<Val<InnerSC>>, Error>;
    fn prove_recursion(
        &self,
        program: Arc<RecursionProgram<Val<InnerSC>>>,
        traces: (RecursionExecutionRecord<Val<InnerSC>>, Traces),
        cache_shape: Option<SP1CompressWithVkeyShape>,
    ) -> Result<SP1ReduceProof<InnerSC>, Error>;
    fn get_compress_keys(
        &self,
        shape: SP1CompressWithVkeyShape,
        program: Arc<RecursionProgram<Val<InnerSC>>>,
    ) -> Arc<(DeviceProvingKey<ClusterProverComponents>, StarkVerifyingKey<InnerSC>)>;
    fn prove_deferred_leaves(
        &self,
        vk: &StarkVerifyingKey<InnerSC>,
        vks_and_proofs: Vec<(StarkVerifyingKey<BabyBearPoseidon2>, ShardProof<BabyBearPoseidon2>)>,
    ) -> Result<(Vec<SP1DeferredWitnessValues<InnerSC>>, [BabyBear; DIGEST_SIZE])>;
}

type SetupInput = Msgpack<String>;

type ProveInput = (Msgpack<String>, (Msgpack<String>, Bincode<StarkVerifyingKey<CoreSC>>));

type ProveLiftInput = (Msgpack<String>, (Msgpack<String>, Bincode<StarkVerifyingKey<CoreSC>>));

type CompressInput = (Bincode<SP1ReduceProof<InnerSC>>, Bincode<SP1ReduceProof<InnerSC>>);

type ShrinkWrapInput = Bincode<SP1ReduceProof<InnerSC>>;

type Groth16Input = (Msgpack<String>, Bincode<SP1ReduceProof<OuterSC>>);

type PlonkInput = (Msgpack<String>, Bincode<SP1ReduceProof<OuterSC>>);

type WrapCompressInput = (Msgpack<String>, Bincode<SP1ReduceProof<InnerSC>>);

type VerifyCompressInput = (Bincode<SP1ProofWithPublicValues>, Bincode<StarkVerifyingKey<CoreSC>>);

type VerifyGroth16Input =
    (Bincode<SP1ProofWithPublicValues>, (Bincode<StarkVerifyingKey<CoreSC>>, Msgpack<String>));

type VerifyPlonkInput =
    (Bincode<SP1ProofWithPublicValues>, (Bincode<StarkVerifyingKey<CoreSC>>, Msgpack<String>));

type Traces = Vec<(String, DenseMatrix<Val<InnerSC>>)>;
