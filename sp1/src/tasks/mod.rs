use common::serialization::bincode::Bincode;
use common::serialization::mpk::Msgpack;
use p3_baby_bear::BabyBear;
use p3_matrix::dense::DenseMatrix;
use sp1_core_executor::SP1ReduceProof;
use sp1_prover::{CoreSC, InnerSC, OuterSC};
use sp1_recursion_circuit::machine::SP1DeferredWitnessValues;
use sp1_sdk::SP1ProofWithPublicValues;
use sp1_stark::{DIGEST_SIZE, StarkVerifyingKey, Val};

pub mod agent;
mod prove;
mod recursion;
mod setup;
mod shrink_wrap;
mod snark;

pub type SetupInput = (Msgpack<String>, Msgpack<String>);

pub type SetupOutput = (
    Bincode<StarkVerifyingKey<CoreSC>>,
    (Msgpack<Vec<SP1DeferredWitnessValues<InnerSC>>>, Bincode<[BabyBear; DIGEST_SIZE]>),
);

type ProveInput = (Msgpack<String>, (Msgpack<String>, Bincode<StarkVerifyingKey<CoreSC>>));

type ProveLiftInput = (
    Msgpack<String>,
    (Msgpack<String>, (Bincode<StarkVerifyingKey<CoreSC>>, Bincode<[BabyBear; DIGEST_SIZE]>)),
);

type LiftDeferInput = Msgpack<SP1DeferredWitnessValues<InnerSC>>;

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
