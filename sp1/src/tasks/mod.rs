use p3_baby_bear::BabyBear;
use p3_matrix::dense::DenseMatrix;
use sp1_core_executor::{ExecutionRecord, SP1ReduceProof};
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{CoreSC, InnerSC, OuterSC, SP1PublicValues, SP1VerifyingKey};
use sp1_recursion_circuit::machine::SP1DeferredWitnessValues;
use sp1_sdk::SP1ProofWithPublicValues;
use sp1_stark::{Challenger, DIGEST_SIZE, StarkVerifyingKey, Val};

pub mod agent;
mod prove;
mod recursion;
mod setup;
mod shrink_wrap;
mod snark;

pub struct SetupInput {
    pub elf: Vec<u8>,
    pub stdin: SP1Stdin,
}
pub struct SetupOutput {
    pub vk: Vec<u8>,
    pub challenger: Vec<u8>,
    pub deferred_inputs: Vec<Vec<u8>>,
    pub deferred_digest: Vec<u8>,
}

pub struct ProveInput<'a> {
    pub record: ExecutionRecord,
    pub elf: &'a Vec<u8>,
    pub vk: &'a StarkVerifyingKey<CoreSC>,
    pub challenger: Challenger<CoreSC>,
}
pub struct ProveOutput {
    pub shard_proof: Vec<u8>,
}

pub struct ProveLiftInput {
    pub record: ExecutionRecord,
    pub elf: Vec<u8>,
    pub vk: StarkVerifyingKey<CoreSC>,
    pub deferred_digest: [BabyBear; DIGEST_SIZE],
    pub challenger: Challenger<CoreSC>,
}
pub struct ProveLiftReduceProofOutput {
    pub reduce_proof: Vec<u8>,
}

pub struct LiftDeferInput {
    pub deferred_input: SP1DeferredWitnessValues<InnerSC>,
}
pub struct LiftDeferOutput {
    pub reduce_proof: Vec<u8>,
}

pub struct CompressInput {
    pub left_proof: SP1ReduceProof<InnerSC>,
    pub right_proof: SP1ReduceProof<InnerSC>,
}
pub struct CompressOutput {
    pub reduce_proof: Vec<u8>,
}

pub struct ShrinkWrapInput {
    pub reduce_proof: SP1ReduceProof<InnerSC>,
}
pub struct ShrinkWrapOutput {
    pub wrap_proof: Vec<u8>,
}

pub struct Groth16Input {
    pub public_values: SP1PublicValues,
    pub wrap_proof: SP1ReduceProof<OuterSC>,
}
pub struct Groth16Output {
    pub groth16_proof: Vec<u8>,
}

pub struct PlonkInput {
    pub public_values: SP1PublicValues,
    pub wrap_proof: SP1ReduceProof<OuterSC>,
}
pub struct PlonkOutput {
    pub plonk_proof: Vec<u8>,
}

pub struct WrapCompressInput {
    pub public_values: SP1PublicValues,
    pub reduce_proof: SP1ReduceProof<InnerSC>,
}
pub struct WrapCompressOutput {
    pub compressed_proof: Vec<u8>,
}

pub struct VerifyCompressInput {
    pub compressed_proof: SP1ProofWithPublicValues,
    pub vk: SP1VerifyingKey,
}

pub struct VerifyGroth16Input {
    pub groth16_proof: SP1ProofWithPublicValues,
    pub vk: SP1VerifyingKey,
    pub public_values: SP1PublicValues,
}

pub struct VerifyPlonkInput {
    pub plonk_proof: SP1ProofWithPublicValues,
    pub vk: SP1VerifyingKey,
    pub public_values: SP1PublicValues,
}

type Traces = Vec<(String, DenseMatrix<Val<InnerSC>>)>;
