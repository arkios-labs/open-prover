mod compressed;
mod core;
mod groth16;
mod plonk;
mod wrap;

#[cfg(test)]
pub mod tests {
    use crate::tasks::Sp1Agent;
    use std::path::PathBuf;

    pub fn setup_agent_and_metadata_dir() -> anyhow::Result<(PathBuf, Sp1Agent)> {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .try_init();

        let metadata_dir = PathBuf::from("metadata");

        let agent = Sp1Agent::new()?;

        Ok((metadata_dir, agent))
    }
}
