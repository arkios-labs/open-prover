use agent::io::input::env::EnvProvider;
use agent::tasks::factory::get_agent;
use agent::tasks::{
    Agent, ProveKeccakRequestLocal, SerializableSession, deserialize_obj, serialize_obj,
};
use anyhow::Result;
use risc0_zkvm::{ReceiptClaim, SuccinctReceipt, Unknown};
use std::{env, fs};
use std::fs::File;
use std::io::Write;
use bincode::deserialize;
use tracing::info;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // TODO: Get input with stdin
    let input = Box::new(EnvProvider {
        key: "AGENT_TYPE".to_string(),
    });
    let agent = get_agent(input)?;
    let agent_ref: &dyn Agent = agent.as_ref();
    
    let path = env::current_dir()?.join("metadata/segments_0.json");

    let bytes = fs::read(&path)?;
    let lifted_receipt_bytes = agent_ref.prove(bytes)?;

    info!("Lifted receipt size: {}", lifted_receipt_bytes.len());
    let lifted_receipt: SuccinctReceipt<ReceiptClaim> = deserialize_obj(&lifted_receipt_bytes)?;

    let lifted_receipt = serde_json::to_string_pretty(&lifted_receipt)?;
    fs::write("metadata/lifted_receipt.json", lifted_receipt)?;
    
    // let mut path = env::current_dir()?;
    // path.push("session_4_segments.json");
    // info!("Reading JSON session file from: {}", path.display());
    // 
    // let json = fs::read_to_string(&path)?;
    // let session: SerializableSession = serde_json::from_str(&json)?;
    // 
    // let mut results_json = Vec::new();
    // 
    // for (i, keccak_req) in session.pending_keccaks.iter().enumerate() {
    //     let local_req = ProveKeccakRequestLocal {
    //         claim_digest: keccak_req.claim_digest,
    //         po2: keccak_req.po2,
    //         control_root: keccak_req.control_root,
    //         input: keccak_req.input.clone(),
    //     };
    // 
    //     let bytes = serialize_obj(&local_req)?;
    //     info!("Keccak test start");
    //     let result = agent_ref.keccak(bytes)?;
    //     let keccak_result: SuccinctReceipt<Unknown> = deserialize_obj(&result)?;
    //     results_json.push(keccak_result);
    // }
    // let json_data = serde_json::to_string_pretty(&results_json)?;
    // fs::write("metadata/pending_keccaks.json", json_data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent::tasks::SerializableSession;
    use std::{env, fs};
    use std::io::BufReader;
    use serde_json::{from_reader, to_string_pretty};
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
