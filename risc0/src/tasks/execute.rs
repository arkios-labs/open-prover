use anyhow::Result;
use risc0_zkvm::{
    Assumption, AssumptionReceipt, CoprocessorCallback, ExecutorEnv, ExecutorImpl, Journal,
    NullSegmentRef, ProveKeccakRequest, Segment,
};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::info;

pub struct ExecuteResult {
    pub total_cycles: u64,
    pub segment_count: u32,
    pub keccak_count: u32,
    pub journal: Option<Journal>,
    pub assumptions: Vec<(Assumption, AssumptionReceipt)>,
}

pub struct KeccakMessage {
    pub request: ProveKeccakRequest,
    pub index: u32,
}

#[allow(clippy::large_enum_variant)]
pub enum ExecuteMessage {
    Segment(Segment),
    Keccak(KeccakMessage),
    Result(ExecuteResult),
    Fault,
}

struct Coprocessor {
    tx: mpsc::Sender<ExecuteMessage>,
    keccak_count: Arc<Mutex<u32>>,
}

impl Coprocessor {
    fn new(tx: mpsc::Sender<ExecuteMessage>, keccak_count: Arc<Mutex<u32>>) -> Self {
        Self { tx, keccak_count }
    }
}

impl CoprocessorCallback for Coprocessor {
    fn prove_keccak(&mut self, request: ProveKeccakRequest) -> Result<()> {
        let mut count = self.keccak_count.lock().unwrap();
        let index = *count;
        self.tx.blocking_send(ExecuteMessage::Keccak(KeccakMessage { request, index }))?;
        *count += 1;
        Ok(())
    }
}

const V2_ELF_MAGIC: &[u8] = b"R0BF";
const EXEC_LIMIT: u64 = 100_000 * 1024 * 1024;

pub fn execute<T: bytemuck::Pod>(
    tx: mpsc::Sender<ExecuteMessage>,
    segment_limit_po2: u32,
    keccak_limit_po2: u32,
    elf_data: Vec<u8>,
    input: Vec<T>,
) {
    if elf_data.len() < V2_ELF_MAGIC.len() || elf_data[0..V2_ELF_MAGIC.len()] != *V2_ELF_MAGIC {
        tracing::error!("ELF MAGIC mismatch");
        tx.blocking_send(ExecuteMessage::Fault).unwrap();
        return;
    }

    let keccak_count: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let coproc = Coprocessor::new(tx.clone(), Arc::clone(&keccak_count));

    // Build executor environment
    let env = match ExecutorEnv::builder()
        .write_slice(&input)
        .session_limit(Some(EXEC_LIMIT))
        .coprocessor_callback(coproc)
        .segment_limit_po2(segment_limit_po2)
        .keccak_max_po2(keccak_limit_po2)
        .unwrap()
        .build()
    {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("Failed to build executor environment: {e}");
            tx.blocking_send(ExecuteMessage::Fault).unwrap();
            return;
        }
    };

    info!("Building executor from ELF");
    info!("ELF data length: {}", elf_data.len());

    let mut executor = match ExecutorImpl::from_elf(env, &elf_data) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("Failed to create executor from ELF: {e}");
            tx.blocking_send(ExecuteMessage::Fault).unwrap();
            return;
        }
    };

    match executor.run_with_callback(|segment| {
        tx.blocking_send(ExecuteMessage::Segment(segment))?;
        Ok(Box::new(NullSegmentRef {}))
    }) {
        Ok(session) => {
            let keccak_count_value = *keccak_count.lock().unwrap();
            let result = ExecuteResult {
                total_cycles: session.total_cycles,
                segment_count: session.segments.len() as u32,
                keccak_count: keccak_count_value,
                journal: session.journal.clone(),
                assumptions: session.assumptions.clone(),
            };
            tx.blocking_send(ExecuteMessage::Result(result)).unwrap();
        }
        Err(e) => {
            tracing::error!("Execution error: {e}");
            tx.blocking_send(ExecuteMessage::Fault).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::tasks::test_constants::{ELF_DATA_PATH, INPUT_DATA_PATH, METADATA_PATH};
    use common::serialization::bincode::deserialize_from_bincode_bytes;
    use std::{fs, path::PathBuf};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_execute_keccak_union() {
        let segment_limit_po2 = 18;
        let keccak_limit_po2 = 16;

        let metadata_dir = PathBuf::from(METADATA_PATH);
        let elf_bytes = fs::read(metadata_dir.join(ELF_DATA_PATH)).unwrap();
        let elf_data = deserialize_from_bincode_bytes(&elf_bytes).unwrap();
        let known_elf_total_cycles = 917504; // from previous runs
        let input_bytes: Vec<u8> = fs::read(metadata_dir.join(INPUT_DATA_PATH)).unwrap();
        let input_data: Vec<u32> = deserialize_from_bincode_bytes(&input_bytes).unwrap();

        let (tx, mut rx) = mpsc::channel::<ExecuteMessage>(50);

        tokio::task::spawn_blocking(move || {
            execute(tx, segment_limit_po2, keccak_limit_po2, elf_data, input_data);
        });

        let mut segment_count: u32 = 0;
        let mut keccak_count: u32 = 0;
        let mut has_result = false;

        while let Some(message) = rx.recv().await {
            match message {
                ExecuteMessage::Segment(segment) => {
                    segment_count += 1;
                    assert!(
                        segment_count == (segment.index + 1) as u32,
                        "Segment index + 1 ({}) should match segment count ({})",
                        segment.index,
                        segment_count
                    );
                }
                ExecuteMessage::Keccak(keccak) => {
                    keccak_count += 1;
                    assert!(
                        keccak_limit_po2 == keccak.request.po2 as u32,
                        "Keccak po2 ({}) should match keccak limit po2 ({})",
                        keccak.request.po2,
                        keccak_limit_po2
                    );
                }
                ExecuteMessage::Result(result) => {
                    has_result = true;
                    assert!(
                        result.total_cycles == known_elf_total_cycles,
                        "Total cycles ({}) should match known total cycles ({})",
                        result.total_cycles,
                        known_elf_total_cycles
                    );
                    assert!(
                        result.segment_count == segment_count,
                        "Result segment count ({}) should match with received segment count ({})",
                        result.segment_count,
                        segment_count
                    );
                    assert!(
                        result.keccak_count == keccak_count,
                        "Keccak count ({}) should match keccak count ({})",
                        result.keccak_count,
                        keccak_count
                    );
                }
                ExecuteMessage::Fault => {
                    panic!("Execution failed with fault!");
                }
            }
        }

        assert!(has_result, "Should have received a result message");
        assert!(segment_count > 0, "Should have received at least one segment");
        assert!(keccak_count > 0, "Should have received at least one keccak request");
    }
}
