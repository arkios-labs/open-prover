use std::{env, fs};
use std::collections::VecDeque;
use std::time::Instant;
use anyhow::{anyhow, Context};
use risc0_zkvm::{Receipt, ReceiptClaim, SuccinctReceipt, Unknown};
use risc0_zkvm::sha::Digestible;
use tracing::info;
use crate::io::input::env::EnvProvider;
use crate::tasks::{deserialize_obj, serialize_obj, Agent, FinalizeInput, ProveKeccakRequestLocal, ResolveInput, SerializableSession};
use crate::tasks::factory::get_agent;
use crate::tasks::r0::read_image_id;

#[tokio::test]
async fn test_e2e_stark_proof_generation() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).init();

    let agent_type = env::var("AGENT_TYPE").unwrap_or_else(|_|"r0".to_string());

    let input = Box::new(EnvProvider {
        key: agent_type,
    });

    let agent = get_agent(input)?;
    let agent_ref: &dyn Agent = agent.as_ref();

    let path = env::current_dir()?.join("metadata/session/session_4_segments.json");
    info!("Loading session data from: {:?}", path);

    let json = fs::read_to_string(&path)?;
    let session: SerializableSession = serde_json::from_str(&json)?;
    assert!(!session.segments.is_empty(), "No segments found in session");

    let mut all_succinct_receipts = Vec::new();

    // --------------------------------------------------------
    // Step 1: Generate Succinct Receipts from Segments
    // --------------------------------------------------------
    let start_step_1 = Instant::now();
    for (i, segment) in session.segments.iter().enumerate() {
        info!("Step 1: Proving segment [{} / {}]", i + 1, session.segments.len());
        let bytes = serialize_obj(segment)?;
        let lifted_bytes = agent_ref.prove(bytes)?;
        
        assert!(!lifted_bytes.is_empty(), "Lifted bytes should not be empty for segment {}", i);
        
        let lifted_receipt: SuccinctReceipt<ReceiptClaim> = deserialize_obj(&lifted_bytes)
            .context(format!("Failed to deserialize receipt for segment {}", i))?;
        
        assert!(lifted_receipt.claim.as_value().is_ok(), "Receipt claim should be present for segment {}", i);
        
        all_succinct_receipts.push(lifted_receipt);
        info!("Segment [{}] proof size: {}", i, lifted_bytes.len());
    }
    info!("Step 1 done in {:?}", start_step_1.elapsed());

    assert_eq!(all_succinct_receipts.len(), session.segments.len(), "Number of receipts should match number of segments");

    // --------------------------------------------------------
    // Step 2: Join All Succinct Receipts into Root Receipt
    // --------------------------------------------------------
    let start_step_2 = Instant::now();
    let serialized_succinct_receipts: Vec<Vec<u8>> =
        all_succinct_receipts.into_iter().map(|r| serialize_obj(&r).unwrap()).collect();
    let mut queue: VecDeque<Vec<u8>> = VecDeque::from(serialized_succinct_receipts);

    while queue.len() > 1 {
        let left = queue.pop_front().unwrap();
        let right = queue.pop_front().unwrap();

        let join_input = serde_json::to_vec(&vec![left.clone(), right.clone()])?;
        let joined = agent_ref.join(join_input).expect("Join failed");

        assert!(!joined.is_empty(), "Joined result should not be empty");
        assert!(joined.len() > left.len() || joined.len() > right.len(), "Joined result should be larger than individual receipts");

        info!("Join successful, resulting size: {}", joined.len());
        queue.push_back(joined);
    }

    let root_receipt_bytes = queue.pop_front().unwrap();
    info!(
        "Step 2 done in {:?} with {:?} receipts",
        start_step_2.elapsed(),
        session.segments.len()
    );

    assert!(!root_receipt_bytes.is_empty(), "Root receipt should not be empty");
    
    let root_receipt: SuccinctReceipt<ReceiptClaim> = deserialize_obj(&root_receipt_bytes)?;
    
    assert!(root_receipt.claim.as_value().is_ok(), "Root receipt should have a claim");

    // --------------------------------------------------------
    // Step 3: Prove Keccak Receipts
    // --------------------------------------------------------
    let start_step_3 = Instant::now();
    let mut keccak_receipts = Vec::new();

    for (i, keccak_req) in session.pending_keccaks.iter().enumerate() {
        info!("Step 3: Keccak [{} / {}]", i + 1, session.pending_keccaks.len());

        let local_req = ProveKeccakRequestLocal {
            claim_digest: keccak_req
                .claim_digest
                .as_bytes()
                .try_into()
                .expect("claim_digest must be 32 bytes"),
            po2: keccak_req.po2,
            control_root: keccak_req
                .control_root
                .as_bytes()
                .try_into()
                .expect("control_root must be 32 bytes"),
            input: keccak_req.input.clone(),
        };

        let bytes = serialize_obj(&local_req)?;
        let result = agent_ref.keccak(bytes)?;
        
        assert!(!result.is_empty(), "Keccak result should not be empty for request {}", i);
        
        let keccak_receipt: SuccinctReceipt<Unknown> =
            deserialize_obj(&result).context("Failed to deserialize keccak")?;
        
        assert!(keccak_receipt.claim.as_value().is_ok(), "Keccak receipt should have a claim");
        
        keccak_receipts.push(keccak_receipt);
        info!("Keccak [{}] result size: {}", i, result.len());
    }

    info!("Step 3 done in {:?} with {} receipts", start_step_3.elapsed(), keccak_receipts.len());
    
    assert_eq!(keccak_receipts.len(), session.pending_keccaks.len(), "Number of keccak receipts should match pending keccaks");

    // --------------------------------------------------------
    // Step 4: Union Keccak Receipts into Merkle-like Tree
    // --------------------------------------------------------
    let start_step_4 = Instant::now();

    let mut queue: Vec<Vec<Vec<u8>>> = keccak_receipts
        .into_iter()
        .map(|r| vec![serialize_obj(&r).expect("serialize failed")])
        .collect();

    while queue.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;
        while i + 1 < queue.len() {
            let left = queue[i].clone();
            let right = queue[i + 1].clone();

            let union_input = serde_json::to_vec(&vec![
                left.last().unwrap().clone(),
                right.last().unwrap().clone(),
            ])?;
            let union = agent_ref.union(union_input).expect("Union failed");

            assert!(!union.is_empty(), "Union result should not be empty");

            let mut new_branch = left;
            new_branch.extend(right);
            new_branch.push(union.clone());

            info!("Union [{} + {}] size: {}", i, i + 1, union.len());
            next_level.push(new_branch);
            i += 2;
        }

        if i < queue.len() {
            next_level.push(queue[i].clone());
        }

        queue = next_level;
    }

    let final_branch = queue.pop().unwrap();
    let final_result = final_branch.last().unwrap().clone();
    info!("Step 4 done in {:?}, final union size: {}", start_step_4.elapsed(), final_result.len());
    
    assert!(!final_result.is_empty(), "Final union result should not be empty");

    // --------------------------------------------------------
    // Step 5: Resolve Assumptions + Proof Tree
    // --------------------------------------------------------
    let start_step_5 = Instant::now();

    let union_path = env::current_dir()?.join("metadata/keccak/unioned_receipt.json");
    let union_json = fs::read_to_string(&union_path)?;
    let union_receipt: SuccinctReceipt<Unknown> = serde_json::from_str(&union_json)?;

    let resolve_input = ResolveInput {
        root: root_receipt,
        union: Some(union_receipt),
        assumptions: session.assumptions,
    };
    let resolve_bytes = serde_json::to_vec(&resolve_input)?;

    let resolved = agent_ref.resolve(resolve_bytes)?;
    
    assert!(!resolved.is_empty(), "Resolved result should not be empty");

    info!("Step 5 resolve done in {:?}", start_step_5.elapsed());

    // --------------------------------------------------------
    // Step 6: Finalize with Journal
    // --------------------------------------------------------
    let start_step_6 = Instant::now();

    let journal_bytes = session
        .journal
        .as_ref()
        .map(|j| j.bytes.clone())
        .ok_or_else(|| anyhow!("journal is missing"))?;

    let image_id = read_image_id("3fe354c3604a1b33f44a76bde3ee677e0f68a1777b0f74f7658c87b49e4c4c8a")?;

    let root_receipt: SuccinctReceipt<ReceiptClaim> = deserialize_obj(&resolved)?;
    let finalize_input = FinalizeInput {
        root: root_receipt,
        journal: journal_bytes,
        image_id: image_id.to_string(),
    };
    let finalize_bytes = serde_json::to_vec(&finalize_input)?;

    let rollup_receipt = agent_ref.finalize(finalize_bytes)?;
    
    assert!(!rollup_receipt.is_empty(), "Rollup receipt should not be empty");
    
    info!("Step 6 finalize done in {:?}", start_step_6.elapsed());

    // --------------------------------------------------------
    // Step 7: Stark2Snark
    // --------------------------------------------------------
    let start_step_7 = Instant::now();

    let groth16_receipt = agent_ref
        .get_snark_receipt(rollup_receipt)
        .expect("stark2snark conversion failed: could not convert stark receipt to snark");
    
    assert!(!groth16_receipt.is_empty(), "Groth16 receipt should not be empty");
    
    info!("Step 7 stark2Snark done in {:?}", start_step_7.elapsed());

    let groth16_receipt: Receipt = deserialize_obj(&groth16_receipt)?;
    
    assert!(groth16_receipt.claim().is_ok(), "Final Groth16 receipt should have a claim");

    let groth16_json = serde_json::to_string_pretty(&groth16_receipt)?;
    fs::write("metadata/result/groth16.json", groth16_json)?;
    
    assert!(fs::metadata("metadata/result/groth16.json").is_ok(), "Groth16 result file should be created");
    
    Ok(())
}