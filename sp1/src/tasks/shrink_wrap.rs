use crate::tasks::ShrinkWrapInput;
use crate::tasks::agent::Sp1Agent;
use anyhow::{Context, Result};
use common::serialization::ArgBytes;
use common::serialization::bincode::{Bincode, serialize_to_bincode_bytes};
use std::time::Instant;
use tracing::info;

impl Sp1Agent {
    pub fn shrink_wrap(&self, input: Vec<u8>) -> Result<Vec<u8>> {
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
}
