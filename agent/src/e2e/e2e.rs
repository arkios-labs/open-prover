use anyhow::{Context, Result};
use tracing;
use crate::io::input::env::EnvProvider;
use crate::tasks::factory::get_agent;
use crate::tasks::{Agent, SerializableSession, deserialize_obj, serialize_obj};
use risc0_zkvm::{ReceiptClaim, SuccinctReceipt, Unknown};
use std::{collections::VecDeque, env, fs, time::Instant};

#[test]
fn test_e2e_start_proof_generation() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // TODO: Add actual e2e test logic here
    tracing::info!("E2E test started");
    
    Ok(())
}

#[test]
fn test_union_on_keccaks_tree_improved() -> Result<()> {
    use tracing::info;

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // 환경 변수 설정을 더 안전하게 처리
    env::set_var("AGENT_TYPE", "invalid");

    let input = Box::new(EnvProvider {
        key: "AGENT_TYPE".to_string(),
    });
    let agent = get_agent(input)?;
    let agent_ref: &dyn Agent = agent.as_ref();

    let path = env::current_dir()?.join("metadata/keccak/keccak_receipts.json");
    info!("Reading keccak receipts from: {:?}", path);
    
    let json = fs::read_to_string(&path)
        .context("Failed to read keccak_receipts.json")?;
    let keccak_receipts: Vec<SuccinctReceipt<Unknown>> = serde_json::from_str(&json)
        .context("Failed to deserialize keccak receipts")?;
    
    let keccak_receipts_count = keccak_receipts.len();
    info!("Processing {} keccak receipts", keccak_receipts_count);

    if keccak_receipts.is_empty() {
        return Err(anyhow::anyhow!("No keccak receipts to process"));
    }

    // 메모리 효율적인 트리 구조로 개선
    let mut queue: VecDeque<Vec<u8>> = keccak_receipts
        .into_iter()
        .map(|r| serialize_obj(&r).context("Failed to serialize receipt"))
        .collect::<Result<VecDeque<_>>>()?;

    let start = Instant::now();
    let mut union_count = 0;

    // 더 효율적인 병합 로직
    while queue.len() > 1 {
        let left = queue.pop_front()
            .ok_or_else(|| anyhow::anyhow!("Queue unexpectedly empty"))?;
        let right = queue.pop_front()
            .ok_or_else(|| anyhow::anyhow!("Queue unexpectedly empty"))?;

        let union = agent_ref
            .union(left, right)
            .context("Union operation failed")?;

        union_count += 1;
        info!("Union #{} successful, result size: {} bytes", union_count, union.len());
        
        queue.push_back(union);
    }

    let final_result = queue.pop_front()
        .ok_or_else(|| anyhow::anyhow!("No final result produced"))?;
    let elapsed = start.elapsed();

    info!("Final unioned result size: {} bytes", final_result.len());
    info!(
        "Union completed in {:?} with {} receipts, {} unions performed",
        elapsed, keccak_receipts_count, union_count
    );

    // 결과 저장
    let union_receipt: SuccinctReceipt<Unknown> = deserialize_obj(&final_result)
        .context("Failed to deserialize final union receipt")?;
    
    let union_json = serde_json::to_string_pretty(&union_receipt)
        .context("Failed to serialize union receipt to JSON")?;
    
    let output_path = env::current_dir()?.join("metadata/keccak/unioned_receipt.json");
    fs::write(&output_path, union_json)
        .context(format!("Failed to write result to {:?}", output_path))?;
    
    info!("Union result saved to {:?}", output_path);

    Ok(())
} 