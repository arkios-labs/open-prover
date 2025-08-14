use anyhow::{Context, Result};
use risc0::command::registry::Command;
use risc0::tasks::r0::RiscZeroAgent;
use std::io::{Read, Write};
use std::{env, io};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(io::stderr)
        .init();

    let task_type: Command = env::var("TASK_TYPE")
        .context("Missing TASK_TYPE")?
        .parse()?;

    info!("Running with TASK_TYPE={:?}", task_type);

    let agent = RiscZeroAgent::new().context("Failed to create agent")?;

    let mut stdin = io::stdin();
    let mut input_bytes = Vec::new();
    stdin.read_to_end(&mut input_bytes)?;

    let result_bytes = task_type
        .apply(&agent, input_bytes)
        .context("Failed to apply command")?;

    let mut stdout = io::stdout();
    stdout.write_all(&result_bytes)?;
    stdout.flush()?;
    Ok(())
}
