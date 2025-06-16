use std::env;
use agent::tasks::factory::get_agent;
use agent::io::input::env::EnvProvider;

use agent::tasks::Agent;
use anyhow::Result;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    
    let input = Box::new(EnvProvider { key: "AGENT_TYPE".parse()? });
    let agent = get_agent(input)?;
    let agent_ref: &dyn Agent = agent.as_ref();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_agent_with_invalid_input() -> Result<()> {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();

        unsafe { env::set_var("AGENT_TYPE", "invalid"); }

        let input = Box::new(EnvProvider {
            key: "AGENT_TYPE".to_string(),
        });
        let agent = get_agent(input)?;
        let agent_ref: &dyn Agent = agent.as_ref();

        // Since the input is invalid, the default RiscZeroAgent is returned and executed.
        agent_ref.execute()?;

        Ok(())
    }
}
