mod compressed;
mod core;
mod groth16;
mod plonk;
mod wrap;

#[cfg(test)]
pub mod tests {
    use crate::tasks::{Agent, SetupInput, SetupOutput, Sp1Agent};
    use anyhow::Context;
    use anyhow::Result;
    use common::serialization::NestedArgBytes;
    use common::serialization::bincode::Bincode;
    use common::serialization::mpk::Msgpack;
    use p3_baby_bear::BabyBear;
    use sp1_prover::{CoreSC, InnerSC};
    use sp1_recursion_circuit::machine::SP1DeferredWitnessValues;
    use sp1_stark::StarkVerifyingKey;
    use std::path::PathBuf;

    pub fn setup_agent_and_metadata_dir() -> Result<(PathBuf, Sp1Agent)> {
        let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init();

        let metadata_dir = PathBuf::from("metadata");

        let agent = Sp1Agent::new().context("Failed to create agent")?;

        Ok((metadata_dir, agent))
    }

    pub fn setup(
        agent: &impl Agent,
        elf_path: &PathBuf,
        stdin_path: &PathBuf,
    ) -> Result<(StarkVerifyingKey<CoreSC>, Vec<SP1DeferredWitnessValues<InnerSC>>, [BabyBear; 8])>
    {
        let setup_input: SetupInput = (
            Msgpack(elf_path.to_string_lossy().into()),
            Msgpack(stdin_path.to_string_lossy().into()),
        );
        let setup_input_packed = NestedArgBytes::to_nested_arg_bytes(&setup_input)
            .context("Failed to serialize setup input")?;

        let setup_result = agent.setup(setup_input_packed).context("Failed to setup")?;

        let (Bincode(vk), (Msgpack(deferred_inputs), Bincode(deferred_digest))): SetupOutput =
            NestedArgBytes::from_nested_arg_bytes(&setup_result).context("Failed to parse")?;

        Ok((vk, deferred_inputs, deferred_digest))
    }
}
