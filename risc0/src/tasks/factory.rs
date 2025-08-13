use crate::tasks::r0::RiscZeroAgent;
use crate::tasks::Agent;
use anyhow::Result;
use common::io::input::InputProvider;
use tracing::warn;

pub fn get_agent(input: Box<dyn InputProvider>) -> Result<Box<dyn Agent>> {
    let bytes = input.read_bytes()?;
    let agent_type = String::from_utf8(bytes)?;

    match agent_type.trim() {
        "r0" => Ok(Box::new(RiscZeroAgent::new()?)),
        _ => {
            warn!(
                "Unrecognized risc0 type '{}'; defaulting to RiscZeroAgent.",
                agent_type.trim()
            );
            Ok(Box::new(RiscZeroAgent::new()?))
        }
    }
}
