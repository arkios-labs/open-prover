use anyhow::Result;
use sp1_prover::SP1Prover;
use sp1_stark::SP1ProverOpts;
use std::any::Any;
use std::sync::Arc;
mod agent;

#[cfg(feature = "gpu")]
pub type ClusterProverComponents = GpuProverComponents;
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
    fn shrink(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn wrap(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn groth16(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn plonk(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn wrap_compress(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn verify_compress(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn verify_groth16(&self, input: Vec<u8>) -> Result<Vec<u8>>;
    fn verify_plonk(&self, input: Vec<u8>) -> Result<Vec<u8>>;
}
