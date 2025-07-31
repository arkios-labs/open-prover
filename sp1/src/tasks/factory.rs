use crate::tasks::cpu_agent::CpuAgent;
use crate::tasks::gpu_agent::GpuAgent;
use crate::tasks::Agent;
use common::io::input::InputProvider;
use tracing::{info, warn};

pub fn get_agent(input: Box<dyn InputProvider>) -> anyhow::Result<Box<dyn Agent>> {
    let bytes = input.read_bytes()?;
    let agent_type = String::from_utf8(bytes)?;
    match agent_type.trim() {
        "sp1-cpu" => Ok(Box::new(CpuAgent::new())),
        "sp1-gpu" => match GpuAgent::new() {
            Ok(gpu_agent) => Ok(Box::new(gpu_agent)),
            Err(e) => {
                warn!(
                    "Failed to create GPU agent: {}. Falling back to CPU agent.",
                    e
                );
                Ok(Box::new(CpuAgent::new()))
            }
        },
        _ => {
            warn!(
                "Unrecognized Succinct type '{}'; defaulting to CPU Agent.",
                agent_type.trim()
            );
            Ok(Box::new(CpuAgent::new()))
        }
    }
}
