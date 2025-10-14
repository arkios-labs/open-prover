use anyhow::Result;
use cfg_if::cfg_if;
use sp1_prover::{DeviceProvingKey, InnerSC, SP1Prover};
use sp1_recursion_circuit::machine::SP1CompressWithVkeyShape;
use sp1_stark::{MachineProver, SP1ProverOpts, StarkVerifyingKey};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

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

impl Sp1Agent {
    pub fn new() -> Result<Self> {
        cfg_if! {
            if #[cfg(feature = "gpu")] {
                let inner_prover: SP1Prover<ClusterProverComponents> = moongate_prover::SP1GpuProver::new();
            } else {
                let inner_prover: SP1Prover<ClusterProverComponents> = SP1Prover::new();
            }
        }
        let prover = Arc::new(inner_prover);

        let mut compress_keys = BTreeMap::new();

        for (shape, program) in prover.join_programs_map.iter() {
            let (pk, vk) = prover.compress_prover.setup(program);
            compress_keys.insert(shape.clone(), Arc::new((pk, vk)));
        }

        Ok(Self {
            prover,
            prover_opts: SP1ProverOpts::default(),
            compress_keys: RwLock::new(compress_keys),
        })
    }

    pub fn name(&self) -> &'static str {
        cfg_if! {
            if #[cfg(feature = "gpu")] {
                "sp1-gpu"
            } else {
                "sp1-cpu"
            }
        }
    }
}
