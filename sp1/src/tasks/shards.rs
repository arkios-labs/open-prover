use crate::tasks::agent::ClusterProverComponents;
use anyhow::{Context, Result};
use common::serialization::bincode::{deserialize_from_bincode_bytes, serialize_to_bincode_bytes};
use log::info;
use serde::{Deserialize, Serialize, Serializer};
use sp1_core_executor::events::{MemoryInitializeFinalizeEvent, PrecompileEvent, SyscallEvent};
use sp1_core_executor::syscalls::SyscallCode;
use sp1_core_executor::{ExecutionRecord, ExecutionState, Executor, Program};
use sp1_prover::SP1Prover;
use sp1_stark::air::PublicValues;
use sp1_stark::{MachineRecord, SP1ProverOpts, SplitOpts};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info_span, instrument, log};
use uuid::Uuid;

/// A wrapper object representing data that can be turned into a shard of events to prove.
///
/// The data can either be an execution checkpoint, list of global memory events, or a list of
/// precompile artifacts to download and combine.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ShardEventData {
    /// An execution checkpoint with just enough data to generate events for a shard. Public values
    /// are included in ExecutionState.
    Checkpoint(Box<ExecutionState>, PublicValues<u32, u32>),
    /// A list of global memory init and finalize events and [start, end) indices for a precompile
    /// shard. The Vec is shared to avoid cloning or moving events.
    GlobalMemory(GlobalMemoryEvents, GlobalMemoryEvents, PublicValues<u32, u32>),
    /// A list of DeferredEvents artifacts and start and end indices for a precompile shard.
    PrecompileRemote(Vec<(String, usize, usize)>, SyscallCode, PublicValues<u32, u32>),
}

impl ShardEventData {
    pub fn state(state: ExecutionState, pv: PublicValues<u32, u32>) -> Self {
        ShardEventData::Checkpoint(Box::new(state), pv)
    }

    pub fn memory(
        init: GlobalMemoryEvents,
        finalize: GlobalMemoryEvents,
        pv: PublicValues<u32, u32>,
    ) -> Self {
        ShardEventData::GlobalMemory(init, finalize, pv)
    }

    pub fn remote(artifacts: Vec<(String, usize, usize)>, code: SyscallCode) -> Self {
        ShardEventData::PrecompileRemote(artifacts, code, Default::default())
    }

    /// Convert ShardEventData into a record of events to prove.
    ///
    /// Checkpoints are executed and the execution events + deferred events are returned.
    /// Records are just unwrapped.
    #[instrument(name = "into_record", level = "info", skip_all)]
    pub async fn into_record(
        self,
        prover: Arc<SP1Prover<ClusterProverComponents>>,
        prover_opts: SP1ProverOpts,
        program: Program,
    ) -> Result<(ExecutionRecord, Option<ExecutionRecord>)> {
        let (shard, deferred) = match self {
            ShardEventData::Checkpoint(checkpoint, pv) => {
                let task = tokio::task::spawn_blocking(move || {
                    let opts = &prover_opts.core_opts;
                    let mut executor = Executor::recover(program, *checkpoint, *opts);
                    executor.maximal_shapes = prover.core_shape_config.as_ref().map(|config| {
                        config
                            .maximal_core_shapes(opts.shard_size.ilog2() as usize)
                            .into_iter()
                            .collect()
                    });
                    // Reserve space for events to prevent Vec growing.
                    executor.record.cpu_events.reserve(opts.shard_size);
                    executor.record.add_events.reserve(opts.shard_size);
                    executor.record.mul_events.reserve(opts.shard_size);
                    executor.record.sub_events.reserve(opts.shard_size);
                    executor.record.bitwise_events.reserve(opts.shard_size);
                    executor.record.shift_left_events.reserve(opts.shard_size);
                    executor.record.shift_right_events.reserve(opts.shard_size);
                    executor.record.divrem_events.reserve(opts.shard_size);
                    executor.record.lt_events.reserve(opts.shard_size);

                    let (mut events, _) =
                        info_span!("execute_record").in_scope(|| executor.execute_record(false))?;

                    let mut deferred = ExecutionRecord::new(events[0].program.clone());
                    for record in events.iter_mut() {
                        deferred.append(&mut record.defer());
                    }

                    // There should only be one shard now.
                    let mut shard = events.remove(0);
                    for mut other in events {
                        shard.append(&mut other);
                    }

                    shard.public_values = pv;

                    Ok::<_, anyhow::Error>((*shard, Some(deferred)))
                });
                task.await.context("Task execution failed")?
            }
            ShardEventData::GlobalMemory(init, finalize, pv) => {
                let mut record = ExecutionRecord::new(Arc::new(program));

                record.public_values = pv;
                record.global_memory_initialize_events = init.to_vec();
                record.global_memory_finalize_events = finalize.to_vec();

                Ok((record, None))
            }
            ShardEventData::PrecompileRemote(artifacts, code, pv) => {
                let mut main_record = ExecutionRecord::new(Arc::new(program));

                // [start, end)
                let mut total_events = 0;
                let mut indices = Vec::new();
                for (_, start, end) in artifacts.iter() {
                    indices.push(total_events);
                    total_events += end - start;
                }

                main_record.precompile_events.events.insert(code, Vec::with_capacity(total_events));

                // Download all artifacts at once.
                let mut futures = Vec::new();
                for (artifact, _, _) in &artifacts {
                    futures.push(async move {
                        let artifacts = tokio::fs::read(&artifact)
                            .await
                            .context("Failed to read artifact file")?;
                        let artifacts_deserialized = deserialize_from_bincode_bytes::<
                            Vec<(SyscallEvent, PrecompileEvent)>,
                        >(&artifacts)
                        .context("Failed to deserialize precompiled artifacts")?;
                        Ok(artifacts_deserialized)
                    });
                }

                let results: Vec<Result<Vec<(SyscallEvent, PrecompileEvent)>, anyhow::Error>> =
                    futures::future::join_all(futures).await;

                for (i, events) in results.into_iter().enumerate() {
                    let events = events?;
                    let (_, start, end) = artifacts[i];
                    main_record
                        .precompile_events
                        .events
                        .get_mut(&code)
                        .context("Failed to get precompile events")?
                        .append(&mut events.into_iter().skip(start).take(end - start).collect());
                }

                // Set public values to the provided values.
                main_record.public_values = pv;

                Ok((main_record, None))
            }
        }?;
        Ok((shard, deferred))
    }

    pub fn update_state(&mut self, state: &mut PublicValues<u32, u32>) {
        match self {
            ShardEventData::Checkpoint(_, pv) => {
                // Set the checkpoint's shard number which depends on precompile shards that
                // have been inserted.
                // Increment execution shard since this is an execution shard.
                state.execution_shard += 1;
                // Set next_pc and digests which are only known from the executor public values.
                state.next_pc = pv.next_pc;
                state.committed_value_digest = pv.committed_value_digest;
                state.deferred_proofs_digest = pv.deferred_proofs_digest;
                // All other values can be set from current state.
                *pv = *state;
                info!("[pv] memory {} {:?}", state.shard, state);
                // Next shard's start_pc should be current shard's next_pc.
                state.start_pc = state.next_pc;
            }
            ShardEventData::GlobalMemory(_, _, pv) => {
                // Update memory public values. Everything else is set from current state.
                state.previous_init_addr_bits = pv.previous_init_addr_bits;
                state.last_init_addr_bits = pv.last_init_addr_bits;
                state.previous_finalize_addr_bits = pv.previous_finalize_addr_bits;
                state.last_finalize_addr_bits = pv.last_finalize_addr_bits;
                // Use current controller state.
                *pv = *state;
                // For later shards, previous memory bits should be the current last bits.
                state.previous_init_addr_bits = state.last_init_addr_bits;
                state.previous_finalize_addr_bits = state.last_finalize_addr_bits;
            }
            ShardEventData::PrecompileRemote(artifacts, code, pv) => {
                // Use current controller state.
                *pv = *state;
                let debug_info = artifacts
                    .iter()
                    .map(|(artifact, start, end)| format!("{:?} {} {}", artifact, start, end))
                    .collect::<Vec<_>>();
                info!("[pv] precompile_remote {} {} {:?}", state.shard, code, debug_info);
            }
        }
    }
}

/// A view of a shared Vec of memory events.
///
/// It serializes without unnecessary copying in the format of a slice of MemoryInitializeFinalizeEvent.
#[derive(Debug, Deserialize, Clone)]
#[serde(from = "Vec<MemoryInitializeFinalizeEvent>")]
pub struct GlobalMemoryEvents {
    pub vec: Arc<Vec<MemoryInitializeFinalizeEvent>>,
    pub start: usize,
    pub end: usize,
}

impl GlobalMemoryEvents {
    pub fn to_vec(&self) -> Vec<MemoryInitializeFinalizeEvent> {
        self.vec.as_slice()[self.start..self.end].to_vec()
    }

    pub fn empty() -> Self {
        Self { vec: Arc::new(Vec::new()), start: 0, end: 0 }
    }

    pub fn new(vec: Arc<Vec<MemoryInitializeFinalizeEvent>>, start: usize, end: usize) -> Self {
        Self { vec, start, end }
    }
}

impl From<Vec<MemoryInitializeFinalizeEvent>> for GlobalMemoryEvents {
    fn from(vec: Vec<MemoryInitializeFinalizeEvent>) -> Self {
        Self { end: vec.len(), vec: Arc::new(vec), start: 0 }
    }
}

impl Serialize for GlobalMemoryEvents {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.vec.as_slice()[self.start..self.end].serialize(serializer)
    }
}

/// A lightweight container for the precompile events in a shard.
///
/// Rather than actually holding all of the events, the events are represented as `Artifact`s with
/// start and end indices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeferredEvents(pub HashMap<SyscallCode, Vec<(String, usize, usize)>>);

impl DeferredEvents {
    /// Defer all events in an ExecutionRecord by uploading each precompile in chunks.
    pub async fn defer_record(
        record: ExecutionRecord,
        split_opts: SplitOpts,
    ) -> Result<DeferredEvents> {
        let mut deferred: HashMap<SyscallCode, Vec<(String, usize, usize)>> = HashMap::new();
        let mut futures = Vec::new();
        for (code, events) in record.precompile_events.events.iter() {
            let threshold = match code {
                SyscallCode::KECCAK_PERMUTE => split_opts.keccak,
                SyscallCode::SHA_EXTEND => split_opts.sha_extend,
                SyscallCode::SHA_COMPRESS => split_opts.sha_compress,
                _ => split_opts.deferred,
            };
            futures.extend(
                events
                    .chunks(threshold)
                    .map(|chunk| async move {
                        let chunk_vec: Vec<_> = chunk.to_vec();
                        let chunk_len = chunk_vec.len();
                        let uuid = Uuid::now_v7();
                        let key = format!("deferred_events_{}_{}", uuid, chunk_len);
                        let serialized_chunk = serialize_to_bincode_bytes(&chunk_vec)
                            .context("Failed to serialize chunk")?;
                        tokio::fs::write(&key, serialized_chunk)
                            .await
                            .context("Failed to write artifact file")?;

                        Ok((*code, key, chunk_len))
                    })
                    .collect::<Vec<_>>(),
            );
        }
        let res: Vec<Result<(SyscallCode, String, usize), anyhow::Error>> =
            futures::future::join_all(futures).await;
        for result in res {
            let (code, artifact, count) = result?;
            deferred.entry(code).or_default().push((artifact, 0, count));
        }
        Ok(DeferredEvents(deferred))
    }

    /// Create an empty DeferredEvents.
    pub fn empty() -> Self {
        Self(HashMap::new())
    }

    /// Append the events from another DeferredEvents to self. Analogous to `ExecutionRecord::append`.
    pub async fn append(&mut self, other: DeferredEvents) {
        for (code, events) in other.0 {
            self.0.entry(code).or_default().extend(events);
        }
    }

    /// Split the DeferredEvents into multiple ShardEventData. Similar to `ExecutionRecord::split`.
    pub async fn split(&mut self, last: bool, opts: SplitOpts) -> Vec<ShardEventData> {
        let mut shards = Vec::new();
        let keys = self.0.keys().cloned().collect::<Vec<_>>();
        for code in keys {
            let threshold = match code {
                SyscallCode::KECCAK_PERMUTE => opts.keccak,
                SyscallCode::SHA_EXTEND => opts.sha_extend,
                SyscallCode::SHA_COMPRESS => opts.sha_compress,
                _ => opts.deferred,
            };
            // self.0[code] contains uploaded artifacts with start and end indices. start is initially 0.
            // Create shards of precompiles from self.0[code] up to threshold, then update new [start, end) indices
            // for future splits. If last is true, don't leave any remainder.
            loop {
                let mut count = 0;
                // Loop through until we've found enough precompiles, and remove from self.0[code].
                // `index` will be set such that artifacts [0, index) will be made into a shard.
                let mut index = 0;
                for (i, (_, start, end)) in self.0[&code].iter().enumerate() {
                    count += end - start;
                    // Break if we've found enough or it's the last Artifact and `last` is true.
                    if count >= threshold || (last && i == self.0[&code].len() - 1) {
                        index = i + 1;
                        break;
                    }
                }
                // If not enough was found, break.
                if index == 0 {
                    break;
                }
                // Otherwise remove the artifacts and handle remainder of last artifact if there is any.
                let mut artifacts =
                    self.0.get_mut(&code).unwrap().drain(..index).collect::<Vec<_>>();
                for (i, (_artifact, _start, _end)) in artifacts.iter().enumerate() {
                    // If there's a remainder, don't remove the controller ref yet.
                    if i == artifacts.len() - 1 && count > threshold {
                        break;
                    }
                }
                // If there's extra in the last artifact, truncate it and leave it in the front of self.0[code].
                if count > threshold {
                    let mut new_range = artifacts.last().cloned().unwrap();
                    new_range.1 = new_range.2 - (count - threshold);
                    artifacts[index - 1].2 = new_range.1;
                    self.0.get_mut(&code).unwrap().insert(0, new_range);
                }
                shards.push(ShardEventData::remote(artifacts, code));
            }
        }
        shards
    }
}
