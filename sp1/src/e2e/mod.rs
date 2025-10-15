mod compressed;
mod core;
mod groth16;
mod plonk;
mod wrap;

#[cfg(test)]
pub mod tests {
    use crate::tasks::SetupInput;
    use crate::tasks::agent::Sp1Agent;
    use anyhow::Context;
    use anyhow::Result;
    use common::serialization::bincode::deserialize_from_bincode_bytes;
    use p3_baby_bear::BabyBear;
    use sp1_core_machine::io::SP1Stdin;
    use sp1_prover::{CoreSC, InnerSC};
    use sp1_recursion_circuit::machine::SP1DeferredWitnessValues;
    use sp1_stark::StarkVerifyingKey;
    use sp1_stark::baby_bear_poseidon2::Challenger;
    use std::fs;
    use std::path::PathBuf;

    pub fn setup_agent_and_metadata_dir() -> Result<(PathBuf, Sp1Agent)> {
        let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init();

        let metadata_dir = PathBuf::from("metadata");

        let agent = Sp1Agent::new().context("Failed to create agent")?;

        Ok((metadata_dir, agent))
    }

    pub fn setup(
        agent: &Sp1Agent,
        elf_path: &PathBuf,
        stdin_path: &PathBuf,
    ) -> Result<(
        Vec<u8>,
        StarkVerifyingKey<CoreSC>,
        Vec<SP1DeferredWitnessValues<InnerSC>>,
        [BabyBear; 8],
        Challenger,
    )> {
        let elf = fs::read(elf_path).context("Failed to read elf")?;

        let stdin = fs::read(stdin_path).context("Failed to read stdin")?;
        let stdin: SP1Stdin =
            deserialize_from_bincode_bytes(&stdin).context("Failed to deserialize stdin")?;

        let setup_input = SetupInput { elf: elf.clone(), stdin };

        let setup_output = agent.setup(setup_input).context("Failed to setup agent")?;

        let vk = deserialize_from_bincode_bytes(&setup_output.vk)
            .context("Failed to deserialize vkey")?;
        let deferred_inputs = setup_output
            .deferred_inputs
            .into_iter()
            .map(|input| {
                deserialize_from_bincode_bytes(&input)
                    .context("Failed to deserialize deferred_input")
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let deferred_digest = deserialize_from_bincode_bytes(&setup_output.deferred_digest)
            .context("Failed to deserialize deferred digest")?;
        let challenger = deserialize_from_bincode_bytes(&setup_output.challenger)
            .context("Failed to deserialize challenger")?;

        let elf = deserialize_from_bincode_bytes(&elf).context("Failed to deserialize elf")?;

        Ok((elf, vk, deferred_inputs, deferred_digest, challenger))
    }
}
