use crate::tasks::agent::Sp1Agent;
use crate::tasks::{ShrinkWrapInput, ShrinkWrapOutput};
use anyhow::{Context, Result, anyhow};
use common::serialization::bincode::serialize_to_bincode_bytes;
use sp1_prover::HashableKey;
use std::time::Instant;
use tracing::info;

impl Sp1Agent {
    pub fn shrink_wrap(&self, shrink_wrap_input: ShrinkWrapInput) -> Result<ShrinkWrapOutput> {
        info!("Agent::shrink_wrap()");
        let start_time = Instant::now();

        let shrink_proof = self
            .prover
            .shrink(shrink_wrap_input.reduce_proof, self.prover_opts)
            .context("Failed to shrink")?;

        let vkey_hash = shrink_proof.vk.hash_babybear();
        if !self.prover.recursion_vk_map.contains_key(&vkey_hash) {
            return Err(anyhow!("shrink vkey {:?} not found in map", vkey_hash));
        }

        let wrap_proof =
            self.prover.wrap_bn254(shrink_proof, self.prover_opts).context("Failed to wrap")?;

        let wrap_proof =
            serialize_to_bincode_bytes(&wrap_proof).context("Failed to serialize wrap_proof")?;
        let shrink_wrap_output = ShrinkWrapOutput { wrap_proof };

        let elapsed = start_time.elapsed();
        info!("Agent::shrink_wrap() took {:?}", elapsed);
        Ok(shrink_wrap_output)
    }
}
