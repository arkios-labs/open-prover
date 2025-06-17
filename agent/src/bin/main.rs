use agent::io::input::env::EnvProvider;
use agent::tasks::Agent;
use agent::tasks::factory::get_agent;
use anyhow::Result;
use std::{env, fs};

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    unsafe {
        env::set_var("AGENT_TYPE", "invalid");
    }

    let input = Box::new(EnvProvider {
        key: "AGENT_TYPE".to_string(),
    });
    let agent = get_agent(input)?;
    let agent_ref: &dyn Agent = agent.as_ref();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, fs};
    use tracing::{debug, info};

    #[test]
    fn test_get_agent_with_invalid_input() -> Result<()> {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();

        unsafe {
            env::set_var("AGENT_TYPE", "invalid");
        }

        let input = Box::new(EnvProvider {
            key: "AGENT_TYPE".to_string(),
        });
        let agent = get_agent(input)?;
        let agent_ref: &dyn Agent = agent.as_ref();
        let mut path = env::current_dir()?;
        path.push("segment");

        info!("Reading from: {}", path.display());
        let bytes = fs::read(&path)?;

        // Since the input is invalid, the default RiscZeroAgent is returned and executed.
        agent_ref.prove(bytes)?;

        Ok(())
    }
}
