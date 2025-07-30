use common::io::input::env::EnvProvider;
use risc0::command::registry::Command;
use risc0::tasks::factory::get_agent;
use risc0::tasks::{
    Agent, ProveKeccakRequestLocal, SerializableSession, deserialize_obj, serialize_obj,
};
use anyhow::{Context, Result};
use bincode::deserialize;
use risc0_zkvm::{ReceiptClaim, SuccinctReceipt, Unknown};
use std::fs::File;
use std::io::{Read, Write};
use std::str::FromStr;
use std::{env, fs, io};
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
        "Running AGENT_TYPE={agent_type} with TASK_TYPE={:?}",
        task_type
    );

    let agent_provider = Box::new(EnvProvider {
        key: agent_type,
    });
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