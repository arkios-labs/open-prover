use agent::command::registry::Command;
use agent::io::input::env::EnvProvider;
use agent::tasks::factory::get_agent;
use agent::tasks::{
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
        key: "AGENT_TYPE".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use agent::tasks::SerializableSession;
    use serde_json::{from_reader, to_string_pretty};
    use std::io::BufReader;
    use std::{env, fs};
    use tracing::{debug, info};

    #[test]
    fn test_get_agent_with_invalid_input() -> Result<()> {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();

        let input = Box::new(EnvProvider {
            key: "AGENT_TYPE".to_string(),
        });

        let agent = get_agent(input)?;
        let agent_ref: &dyn Agent = agent.as_ref();
        let mut path = env::current_dir()?.join("metadata/segment.json");

        info!("Reading from: {}", path.display());
        let bytes = fs::read(&path)?;

        // Since the input is invalid, the default RiscZeroAgent is returned and executed.
        agent_ref.prove(bytes)?;

        Ok(())
    }

    #[test]
    fn test_deserialize_session_from_json() -> Result<()> {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();

        let mut path = env::current_dir()?.join("metadata/session_4_segments.json");

        info!("Reading JSON session file from: {}", path.display());

        let json = fs::read_to_string(&path)?;
        let session: SerializableSession = serde_json::from_str(&json)?;

        let segment_count = session.segments.len();

        assert_eq!(
            segment_count, 4,
            "Expected 4 segments, got {}",
            segment_count
        );

        Ok(())
    }

    // 테스트
    #[test]
    fn test_json_transform_and_write() -> Result<(), Box<dyn std::error::Error>> {
        let file = File::open("keccak_results.json")?;
        let reader = BufReader::new(file);
        let results: Vec<SuccinctReceipt<Unknown>> = from_reader(reader)?;

        let json = to_string_pretty(&results)?;
        fs::write("keccak_results2.json", json)?;

        Ok(())
    }
}
