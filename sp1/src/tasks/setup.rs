use crate::tasks::agent::Sp1Agent;
use crate::tasks::{SetupInput, SetupOutput};
use anyhow::{Context, Result};
use common::serialization::bincode::{deserialize_from_bincode_bytes, serialize_to_bincode_bytes};
use sp1_stark::{MachineProver, StarkGenericConfig};
use std::time::Instant;
use tracing::info;

impl Sp1Agent {
    pub fn setup(&self, setup_input: SetupInput) -> Result<SetupOutput> {
        info!("Agent::setup()");
        let start_time = Instant::now();

        let elf: Vec<u8> = deserialize_from_bincode_bytes(&setup_input.elf)
            .context("Failed to deserialize ELF")?;

        let stdin = setup_input.stdin;

        let (_, _, _, vkey) = self.prover.setup(&elf);

        let deferred_proofs = stdin.proofs;
        let (deferred_inputs, deferred_digest) = self
            .prove_deferred_leaves(
                &vkey.vk,
                deferred_proofs.into_iter().map(|p| (p.0.vk, p.0.proof)).collect::<Vec<_>>(),
            )
            .context("Failed to prove deferred leaves")?;

        let mut challenger = self.prover.core_prover.machine().config().challenger();
        vkey.vk.observe_into(&mut challenger);

        let vk = serialize_to_bincode_bytes(&vkey.vk).context("Failed to serialize vk")?;

        let challenger =
            serialize_to_bincode_bytes(&challenger).context("Failed to serialize challenger")?;

        let deferred_inputs = deferred_inputs
            .into_iter()
            .map(|input| {
                serialize_to_bincode_bytes(&input).context("Failed to serialize deferred input")
            })
            .collect::<Result<Vec<_>, _>>()?;

        let deferred_digest = serialize_to_bincode_bytes(&deferred_digest)
            .context("Failed to serialize deferred digest")?;

        let setup_output = SetupOutput { vk, challenger, deferred_inputs, deferred_digest };

        let elapsed = start_time.elapsed();
        info!("Agent::setup() took {:?}", elapsed);
        Ok(setup_output)
    }
}
