use crate::tasks::agent::Sp1Agent;
use crate::tasks::{SetupInput, SetupOutput};
use anyhow::{Context, Result};
use common::serialization::NestedArgBytes;
use common::serialization::bincode::{Bincode, deserialize_from_bincode_bytes};
use common::serialization::mpk::Msgpack;
use sp1_core_machine::io::SP1Stdin;
use sp1_stark::{MachineProver, StarkGenericConfig};
use std::fs;
use std::time::Instant;
use tracing::info;

impl Sp1Agent {
    pub fn setup(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        info!("Agent::setup()");
        let start_time = Instant::now();

        let (Msgpack(elf_path), Msgpack(stdin_path)): SetupInput =
            NestedArgBytes::from_nested_arg_bytes(&input).context("Failed to parse setup input")?;

        let elf_bytes = fs::read(&elf_path)
            .with_context(|| format!("Failed to read ELF file at {}", elf_path))?;

        let elf_deserialized: Vec<u8> =
            deserialize_from_bincode_bytes(&elf_bytes).context("Failed to deserialize ELF")?;

        let (_, _, _, vkey) = self.prover.setup(&elf_deserialized);

        let stdin_bytes = fs::read(&stdin_path)
            .with_context(|| format!("Failed to read stdin at {}", stdin_path))?;
        let stdin_deserialized: SP1Stdin =
            deserialize_from_bincode_bytes(&stdin_bytes).context("Failed to deserialize stdin")?;

        let deferred_proofs = stdin_deserialized.proofs;
        let (deferred_inputs, deferred_digest) = self
            .prove_deferred_leaves(
                &vkey.vk,
                deferred_proofs.into_iter().map(|p| (p.0.vk, p.0.proof)).collect::<Vec<_>>(),
            )
            .context("Failed to prove deferred leaves")?;

        let mut challenger = self.prover.core_prover.machine().config().challenger();
        vkey.vk.observe_into(&mut challenger);

        let setup_output: SetupOutput = (
            Bincode(vkey.vk),
            (Msgpack(deferred_inputs), (Bincode(deferred_digest), Bincode(challenger))),
        );

        let serialized = NestedArgBytes::to_nested_arg_bytes(&setup_output)
            .context("Failed to serialize setup output")?;

        let elapsed = start_time.elapsed();
        info!("Agent::setup() took {:?}", elapsed);
        Ok(serialized)
    }
}
