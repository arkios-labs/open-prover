use anyhow::{Context, Result};
use sp1::command::registry::Command;
use sp1::tasks::{Agent, Sp1Agent};
use std::io::{Read, Write};
use std::{env, io};
use tracing::info;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(io::stderr)
        .init();

    let task_type: Command = env::var("TASK_TYPE")
        .context("Missing TASK_TYPE")?
        .parse()?;

    let sp1_agent = Sp1Agent::new()?;
    info!(
        "Running AGENT_TYPE={} with TASK_TYPE={:?}",
        sp1_agent.name(),
        task_type
    );

    let mut stdin = io::stdin();
    let mut input_bytes = Vec::new();
    stdin.read_to_end(&mut input_bytes)?;

    let result_bytes = task_type
        .apply(&sp1_agent, input_bytes)
        .context("Failed to execute task")?;

    let mut stdout = io::stdout();
    stdout.write_all(&result_bytes)?;
    stdout.flush()?;
    Ok(())
}
