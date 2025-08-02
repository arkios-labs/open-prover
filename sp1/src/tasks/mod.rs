use anyhow::{Context, Result};
use async_trait::async_trait;
use sp1_prover::SP1Prover;
use sp1_stark::SP1ProverOpts;
use std::any::Any;
use std::sync::Arc;
mod agent;

#[cfg(feature = "gpu")]
pub type ClusterProverComponents = GpuProverComponents;
#[cfg(not(feature = "gpu"))]
pub type ClusterProverComponents = sp1_prover::components::CpuProverComponents;

const PROVE_INPUT_LEN: usize = 3;
const PROVE_LIFT_INPUT_LEN: usize = 3;
const COMPRESS_INPUT_LEN: usize = 3;
const GROTH16_INPUT_LEN: usize = 2;
const PLONK_INPUT_LEN: usize = 2;

pub struct Sp1Agent {
    pub prover: Arc<SP1Prover<ClusterProverComponents>>,
    pub prover_opts: SP1ProverOpts,
}

#[async_trait]
pub trait Agent: Send + Sync {
    fn name(&self) -> &'static str;
    fn as_any(self: Box<Self>) -> Box<dyn Any>;
    fn setup(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn prove(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn prove_lift(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn compress(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn shrink(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn wrap(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn groth16(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn plonk(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn wrap_compress(&self, input: Vec<u8>) -> Result<Vec<u8>>;
}
