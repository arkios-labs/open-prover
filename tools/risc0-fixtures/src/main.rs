use std::{collections::VecDeque, fs, path::PathBuf};

use anyhow::{Context, Result};
use common::serialization::bincode::{deserialize_from_bincode_bytes, serialize_to_bincode_bytes};
use risc0_zkvm::{
    Digest, ProveKeccakRequest, Receipt, ReceiptClaim, Segment, SuccinctReceipt, Unknown,
    compute_image_id, serde::to_vec,
};
use risc0_zkvm_methods::{MULTI_TEST_ELF, multi_test::MultiTestSpec};

use risc0::tasks::{
    Risc0Agent, compress_binary_tree, deserialize_obj,
    execute::{ExecuteMessage, ExecuteResult},
    serialize_obj,
    test_constants::{
        ASSUMPTIONS_PATH, ELF_DATA_PATH, FINAL_RECEIPT_PATH, INPUT_DATA_PATH,
        JOIN_ROOT_RECEIPT_PATH, JOURNAL_PATH, KECCAK_RECEIPTS_PATH, KECCAKS_PATH, METADATA_PATH,
        RESOLVED_RECEIPT_PATH, SEGMENT_LIFTED_RECEIPTS_PATH, SEGMENTS_PATH,
        UNION_ROOT_RECEIPT_PATH,
    },
};

const SEGMENT_LIMIT_PO2: u32 = 18;
const KECCAK_LIMIT_PO2: u32 = 16;

fn main() {
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init();

    let elf_data = MULTI_TEST_ELF.to_vec();
    let image_id = compute_image_id(&elf_data).context("Failed to compute image id").unwrap();
    let input_data: Vec<u32> = to_vec(&MultiTestSpec::KeccakUnion(1)).unwrap();

    tracing::info!("Generating fixtures for image id: {}", image_id.to_string());

    let (metadata_dir, _agent) = generate_fixtures(elf_data, image_id, input_data)
        .context("Failed to generate fixtures")
        .unwrap();

    validate_generated_fixtures(metadata_dir, image_id)
        .context("Failed to validate generated fixtures")
        .unwrap();

    tracing::info!("Fixtures generated successfully");
}

pub fn generate_fixtures(
    elf_data: Vec<u8>,
    image_id: Digest,
    input_data: Vec<u32>,
) -> Result<(PathBuf, Risc0Agent)> {
    let agent = Risc0Agent::new().context("Failed to create agent")?;

    let mut segments: Vec<Segment> = Vec::new();
    let mut keccaks: Vec<ProveKeccakRequest> = Vec::new();
    let mut result: Option<ExecuteResult> = None;

    let metadata_dir = PathBuf::from(METADATA_PATH);
    fs::create_dir_all(&metadata_dir).context("Failed to create metadata directory")?;
    fs::write(metadata_dir.join(ELF_DATA_PATH), &serialize_to_bincode_bytes(&elf_data)?)?;
    fs::write(metadata_dir.join(INPUT_DATA_PATH), &serialize_to_bincode_bytes(&input_data)?)?;

    {
        let messages = agent.execute(SEGMENT_LIMIT_PO2, KECCAK_LIMIT_PO2, elf_data, input_data);
        for message in messages {
            match message {
                ExecuteMessage::Segment(seg) => segments.push(seg),
                ExecuteMessage::Keccak(kecc) => keccaks.push(kecc),
                ExecuteMessage::Result(res) => {
                    result = Some(res);
                }
                ExecuteMessage::Fault => {
                    return Err(anyhow::anyhow!("Execution failed with fault!"));
                }
            }
        }
    }

    if segments.is_empty() || keccaks.is_empty() {
        return Err(anyhow::anyhow!("Failed to prepare segments and keccaks"));
    }

    if result.is_none() {
        return Err(anyhow::anyhow!("Failed to get result"));
    }

    let result = result.unwrap();

    fs::create_dir_all(metadata_dir.join("session"))
        .context("Failed to create session directory")?;
    fs::create_dir_all(metadata_dir.join("receipt"))
        .context("Failed to create receipt directory")?;

    fs::write(metadata_dir.join(SEGMENTS_PATH), &serialize_to_bincode_bytes(&segments)?)?;
    fs::write(metadata_dir.join(KECCAKS_PATH), &serialize_to_bincode_bytes(&keccaks)?)?;

    fs::write(
        metadata_dir.join(JOURNAL_PATH),
        &serialize_to_bincode_bytes(&result.journal.clone().unwrap())?,
    )?;
    fs::write(
        metadata_dir.join(ASSUMPTIONS_PATH),
        &serialize_to_bincode_bytes(&result.assumptions.clone())?,
    )?;

    let mut segment_lifted_receipts: Vec<SuccinctReceipt<ReceiptClaim>> =
        Vec::with_capacity(segments.len());
    for segment in segments {
        let lifted_segment =
            agent.prove(serialize_obj(&segment)?).context("Failed to prove segment")?;
        segment_lifted_receipts.push(deserialize_obj(&lifted_segment)?);
    }
    fs::write(
        metadata_dir.join(SEGMENT_LIFTED_RECEIPTS_PATH),
        &serialize_to_bincode_bytes(&segment_lifted_receipts)?,
    )?;

    let mut keccak_receipts: Vec<SuccinctReceipt<Unknown>> = Vec::with_capacity(keccaks.len());
    for keccak in keccaks {
        let lifted_keccak =
            agent.keccak(serialize_obj(&keccak)?).context("Failed to prove keccak")?;
        keccak_receipts.push(deserialize_obj(&lifted_keccak)?);
    }
    fs::write(
        metadata_dir.join(KECCAK_RECEIPTS_PATH),
        &serialize_to_bincode_bytes(&keccak_receipts)?,
    )?;

    let segment_lifted_receipts_serialized: Vec<Vec<u8>> = segment_lifted_receipts
        .into_iter()
        .map(|r| serialize_obj(&r).context("Failed to serialize receipt"))
        .collect::<Result<_, _>>()?;
    let join_root_receipt = compress_binary_tree(
        |left, right| agent.join(serialize_obj(&vec![left, right])?),
        VecDeque::from(segment_lifted_receipts_serialized),
    )?;
    let join_root_receipt: SuccinctReceipt<ReceiptClaim> = deserialize_obj(&join_root_receipt)?;
    fs::write(
        metadata_dir.join(JOIN_ROOT_RECEIPT_PATH),
        &serialize_to_bincode_bytes(&join_root_receipt)?,
    )?;

    let keccak_receipts_serialized: Vec<Vec<u8>> = keccak_receipts
        .into_iter()
        .map(|r| serialize_obj(&r).context("Failed to serialize receipt"))
        .collect::<Result<_, _>>()?;
    let union_root_receipt = compress_binary_tree(
        |left, right| agent.union(serialize_obj(&vec![left, right])?),
        VecDeque::from(keccak_receipts_serialized),
    )?;
    let union_root_receipt: SuccinctReceipt<Unknown> = deserialize_obj(&union_root_receipt)?;
    fs::write(
        metadata_dir.join(UNION_ROOT_RECEIPT_PATH),
        &serialize_to_bincode_bytes(&union_root_receipt)?,
    )?;

    let resolved_receipt = agent
        .resolve(serde_json::to_vec(&vec![
            serialize_obj(&join_root_receipt)?,
            serialize_obj(&union_root_receipt)?,
            serialize_obj(&result.assumptions)?,
        ])?)
        .context("Failed to resolve")?;
    let resolved_receipt: SuccinctReceipt<ReceiptClaim> = deserialize_obj(&resolved_receipt)?;
    fs::write(
        metadata_dir.join(RESOLVED_RECEIPT_PATH),
        &serialize_to_bincode_bytes(&resolved_receipt)?,
    )?;

    let final_receipt = agent
        .finalize(serialize_obj(&vec![
            serialize_obj(&resolved_receipt)?,
            result.journal.unwrap().bytes,
            serialize_obj(&image_id.to_string())?,
        ])?)
        .context("Failed to finalize")?;
    let final_receipt: Receipt = deserialize_obj(&final_receipt)?;
    fs::write(metadata_dir.join(FINAL_RECEIPT_PATH), &serialize_to_bincode_bytes(&final_receipt)?)?;

    Ok((metadata_dir, agent))
}

fn validate_generated_fixtures(metadata_dir: PathBuf, image_id: Digest) -> Result<()> {
    let segments_path = metadata_dir.join(SEGMENTS_PATH);
    let segments = fs::read(&segments_path).context("Failed to read segments file")?;
    let segments: Vec<Segment> =
        deserialize_from_bincode_bytes(&segments).context("Failed to deserialize segments")?;

    let keccaks_path = metadata_dir.join(KECCAKS_PATH);
    let keccaks = fs::read(&keccaks_path).context("Failed to read keccaks file")?;
    let keccaks: Vec<ProveKeccakRequest> =
        deserialize_from_bincode_bytes(&keccaks).context("Failed to deserialize keccaks")?;

    assert!(!segments.is_empty(), "Segments should not be empty");
    assert!(!keccaks.is_empty(), "Keccaks should not be empty");

    let segment_lifted_receipts_path = metadata_dir.join(SEGMENT_LIFTED_RECEIPTS_PATH);
    let segment_lifted_receipts = fs::read(&segment_lifted_receipts_path)
        .context("Failed to read segment lifted receipts file")?;
    let segment_lifted_receipts: Vec<SuccinctReceipt<ReceiptClaim>> =
        deserialize_from_bincode_bytes(&segment_lifted_receipts)
            .context("Failed to deserialize segment lifted receipts")?;

    assert!(!segment_lifted_receipts.is_empty(), "Segment lifted receipts should not be empty");

    let keccak_lifted_receipts_path = metadata_dir.join(KECCAK_RECEIPTS_PATH);
    let keccak_lifted_receipts: Vec<u8> = fs::read(&keccak_lifted_receipts_path)
        .context("Failed to read keccak lifted receipts file")?;
    let keccak_lifted_receipts: Vec<SuccinctReceipt<Unknown>> =
        deserialize_from_bincode_bytes(&keccak_lifted_receipts)
            .context("Failed to deserialize keccak lifted receipts")?;

    assert!(!keccak_lifted_receipts.is_empty(), "Keccak lifted receipts should not be empty");

    let join_root_receipt_path = metadata_dir.join(JOIN_ROOT_RECEIPT_PATH);
    let join_root_receipt =
        fs::read(&join_root_receipt_path).context("Failed to read join root receipt file")?;
    let join_root_receipt: SuccinctReceipt<ReceiptClaim> =
        deserialize_from_bincode_bytes(&join_root_receipt)
            .context("Failed to deserialize join root receipt")?;

    assert!(!join_root_receipt.seal.is_empty(), "Join root receipt should have a seal");

    let union_root_receipt_path = metadata_dir.join(UNION_ROOT_RECEIPT_PATH);
    let union_root_receipt =
        fs::read(&union_root_receipt_path).context("Failed to read union root receipt file")?;
    let union_root_receipt: SuccinctReceipt<Unknown> =
        deserialize_from_bincode_bytes(&union_root_receipt)
            .context("Failed to deserialize union root receipt")?;
    assert!(!union_root_receipt.seal.is_empty(), "Union root receipt should have a seal");

    let resolved_receipt_path = metadata_dir.join(RESOLVED_RECEIPT_PATH);
    let resolved_receipt =
        fs::read(&resolved_receipt_path).context("Failed to read resolved receipt file")?;
    let resolved_receipt: SuccinctReceipt<ReceiptClaim> =
        deserialize_from_bincode_bytes(&resolved_receipt)
            .context("Failed to deserialize resolved receipt")?;

    assert!(!resolved_receipt.seal.is_empty(), "Resolved receipt should have a seal");

    let final_receipt_path = metadata_dir.join(FINAL_RECEIPT_PATH);
    let final_receipt =
        fs::read(&final_receipt_path).context("Failed to read final receipt file")?;
    let final_receipt: Receipt = deserialize_from_bincode_bytes(&final_receipt)
        .context("Failed to deserialize final receipt")?;

    assert!(final_receipt.verify(image_id).is_ok(), "Final receipt should be valid");

    Ok(())
}
