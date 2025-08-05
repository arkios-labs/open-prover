mod compressed;
mod core;
mod groth16;
mod plonk;
mod shrink;
mod wrap;

#[cfg(test)]
pub mod tests {
    use crate::tasks::cpu_agent::CpuAgent;
    use crate::tasks::factory::get_agent;
    use anyhow::anyhow;
    use common::io::input::env::EnvProvider;
    use std::path::PathBuf;

    pub fn setup_cpu_agent_and_metadata_dir() -> anyhow::Result<(PathBuf, Box<CpuAgent>)> {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .try_init();

        let metadata_dir = PathBuf::from("metadata");

        let input = Box::new(EnvProvider {
            key: "AGENT_TYPE".to_string(),
        });

        let agent = get_agent(input)?;

        let cpu_agent = agent
            .as_any()
            .downcast::<CpuAgent>()
            .map_err(|_| anyhow!("Expected CpuAgent for this test."))?;

        Ok((metadata_dir, cpu_agent))
    }
}
