use anyhow::Result;
use risc0_zkvm::{
    Assumption, AssumptionReceipt, CoprocessorCallback, ExecutorEnv, ExecutorImpl, Journal,
    NullSegmentRef, ProveKeccakRequest, Segment,
};
use std::sync::{Arc, Mutex};

use crate::tasks::Risc0Agent;

pub struct ExecuteResult {
    pub total_cycles: u64,
    pub segment_count: u64,
    pub keccak_count: u64,
    pub journal: Option<Journal>,
    pub assumptions: Vec<(Assumption, AssumptionReceipt)>,
}

#[allow(clippy::large_enum_variant)]
pub enum ExecuteMessage {
    Segment(Segment),
    Keccak(ProveKeccakRequest),
    Result(ExecuteResult),
    Fault,
}

struct Coprocessor {
    tx: std::sync::mpsc::SyncSender<ExecuteMessage>,
    keccak_count: Arc<Mutex<u64>>,
}

impl Coprocessor {
    fn new(tx: std::sync::mpsc::SyncSender<ExecuteMessage>, keccak_count: Arc<Mutex<u64>>) -> Self {
        Self { tx, keccak_count }
    }
}

impl CoprocessorCallback for Coprocessor {
    fn prove_keccak(&mut self, request: ProveKeccakRequest) -> Result<()> {
        self.tx.send(ExecuteMessage::Keccak(request))?;
        let mut count = self.keccak_count.lock().unwrap();
        *count += 1;
        Ok(())
    }
}

struct BufferedIterator {
    rx: std::sync::mpsc::Receiver<ExecuteMessage>,
}

impl Iterator for BufferedIterator {
    type Item = ExecuteMessage;

    fn next(&mut self) -> Option<Self::Item> {
        self.rx.recv().ok()
    }
}

const V2_ELF_MAGIC: &[u8] = b"R0BF";
const BUFFER_SIZE: usize = 50;
const EXEC_LIMIT: u64 = 100_000 * 1024 * 1024;

impl Risc0Agent {
    pub fn execute(
        &self,
        segment_limit_po2: u32,
        keccak_limit_po2: u32,
        elf_data: Vec<u8>,
        input: Vec<u32>,
    ) -> impl Iterator<Item = ExecuteMessage> {
        let (tx, rx) = std::sync::mpsc::sync_channel::<ExecuteMessage>(BUFFER_SIZE);

        if elf_data.len() < V2_ELF_MAGIC.len() || elf_data[0..V2_ELF_MAGIC.len()] != *V2_ELF_MAGIC {
            tracing::error!("ELF MAGIC mismatch");
            let _ = tx.send(ExecuteMessage::Fault);
            return BufferedIterator { rx };
        }

        std::thread::spawn(move || {
            let keccak_count: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
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
                    let _ = tx.send(ExecuteMessage::Fault);
                    return;
                }
            };

            let mut executor = match ExecutorImpl::from_elf(env, &elf_data) {
                Ok(e) => e,
                Err(e) => {
                    tracing::error!("Failed to create executor from ELF: {e}");
                    let _ = tx.send(ExecuteMessage::Fault);
                    return;
                }
            };

            match executor.run_with_callback(|segment| {
                tx.send(ExecuteMessage::Segment(segment))?;
                Ok(Box::new(NullSegmentRef {}))
            }) {
                Ok(session) => {
                    let keccak_count_value = *keccak_count.lock().unwrap();
                    let result = ExecuteResult {
                        total_cycles: session.total_cycles,
                        segment_count: session.segments.len() as u64,
                        keccak_count: keccak_count_value,
                        journal: session.journal.clone(),
                        assumptions: session.assumptions.clone(),
                    };
                    let _ = tx.send(ExecuteMessage::Result(result));
                }
                Err(e) => {
                    tracing::error!("Execution error: {e}");
                    let _ = tx.send(ExecuteMessage::Fault);
                }
            }
        });

        BufferedIterator { rx }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::tasks::test_constants::{ELF_DATA_PATH, INPUT_DATA_PATH, METADATA_PATH};
    use common::serialization::bincode::deserialize_from_bincode_bytes;
    use std::{fs, path::PathBuf};

    fn setup_agent() -> Risc0Agent {
        let agent = Risc0Agent::new().unwrap();
        agent
    }

    #[test]
    fn test_execute_keccak_union() {
        let agent = setup_agent();

        let segment_limit_po2 = 18;
        let keccak_limit_po2 = 16;

        let metadata_dir = PathBuf::from(METADATA_PATH);
        let elf_bytes = fs::read(&metadata_dir.join(ELF_DATA_PATH)).unwrap();
        let elf_data = deserialize_from_bincode_bytes(&elf_bytes).unwrap();
        let known_elf_total_cycles = 917504; // from previous runs
        let input_bytes: Vec<u8> = fs::read(&metadata_dir.join(INPUT_DATA_PATH)).unwrap();
        let input_data: Vec<u32> = deserialize_from_bincode_bytes(&input_bytes).unwrap();

        let mut messages = agent.execute(segment_limit_po2, keccak_limit_po2, elf_data, input_data);

        let mut segment_count: u64 = 0;
        let mut keccak_count: u64 = 0;
        let mut has_result = false;

        while let Some(message) = messages.next() {
            match message {
                ExecuteMessage::Segment(segment) => {
                    segment_count += 1;
                    assert!(
                        segment_count == (segment.index + 1) as u64,
                        "Segment index + 1 ({}) should match segment count ({})",
                        segment.index,
                        segment_count
                    );
                }
                ExecuteMessage::Keccak(keccak) => {
                    keccak_count += 1;
                    assert!(
                        keccak_limit_po2 == keccak.po2 as u32,
                        "Keccak po2 ({}) should match keccak limit po2 ({})",
                        keccak.po2,
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
