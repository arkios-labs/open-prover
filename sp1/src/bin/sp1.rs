use anyhow::{Context, Result};
use common::io::input::env::EnvProvider;
use sp1::command::registry::Command;
use sp1::tasks::factory::get_agent;
use sp1::tasks::Agent;
use std::io::{Read, Write};
use std::{env, io};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(io::stderr)
        .init();

    let agent_type =
        env::var("AGENT_TYPE").map_err(|_| anyhow::anyhow!("Missing AGENT_TYPE env var"))?;

    let task_type: Command = env::var("TASK_TYPE")
        .context("Missing TASK_TYPE")?
        .parse()?;

    info!(
        "Running AGENT_TYPE={} with TASK_TYPE={:?}",
        agent_type, task_type
    );

    let agent_provider = Box::new(EnvProvider { key: agent_type });
    let agent = get_agent(agent_provider)?;
    let agent_ref: &dyn Agent = agent.as_ref();

    let mut stdin = io::stdin();
    let mut input_bytes = Vec::new();
    stdin.read_to_end(&mut input_bytes)?;

    let result_bytes = task_type.apply(agent_ref, input_bytes).await?;

    let mut stdout = io::stdout();
    stdout.write_all(&result_bytes)?;
    stdout.flush()?;
    Ok(())
}
