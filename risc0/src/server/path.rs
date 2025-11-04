pub const STORAGE_ROOT_DIR: &str = "bdls";

pub fn journal_path(job_id: &str) -> String {
    format!("jobs/{job_id}/journal.bincode")
}

pub fn segment_path(job_id: &str, index: u32) -> String {
    format!("jobs/{job_id}/segment_{index}.bincode")
}

pub fn keccak_path(job_id: &str, index: u32) -> String {
    format!("jobs/{job_id}/keccak_{index}.bincode")
}

pub fn join_receipt_path(job_id: &str, task_id: &str) -> String {
    format!("jobs/{job_id}/join_{task_id}_receipt.bincode")
}

pub fn union_receipt_path(job_id: &str, task_id: &str) -> String {
    format!("jobs/{job_id}/union_{task_id}_receipt.bincode")
}

pub fn resolved_receipt_path(job_id: &str) -> String {
    format!("jobs/{job_id}/resolved_receipt.bincode")
}

pub fn stark_receipt_path(job_id: &str) -> String {
    format!("jobs/{job_id}/stark_receipt.bincode")
}

pub fn groth16_receipt_path(job_id: &str) -> String {
    format!("jobs/{job_id}/groth16_receipt.bincode")
}
