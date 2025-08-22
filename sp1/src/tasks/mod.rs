use anyhow::Result;
use common::serialization::bincode::Bincode;
use common::serialization::mpk::Msgpack;
use sp1_core_executor::SP1ReduceProof;
use sp1_prover::{CoreSC, InnerSC, OuterSC, SP1Prover};
use sp1_sdk::SP1ProofWithPublicValues;
use sp1_stark::{SP1ProverOpts, StarkVerifyingKey};
use std::any::Any;
use std::sync::Arc;
mod agent;

#[cfg(feature = "gpu")]
pub type ClusterProverComponents = moongate_prover::components::GpuProverComponents;
#[cfg(not(feature = "gpu"))]
pub type ClusterProverComponents = sp1_prover::components::CpuProverComponents;

pub struct Sp1Agent {
    pub prover: Arc<SP1Prover<ClusterProverComponents>>,
    pub prover_opts: SP1ProverOpts,
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
