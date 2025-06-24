use std::str::FromStr;
use crate::tasks::Agent;
use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Command {
    Execute,
    Join,
    Prove,
    Finalize,
    Resolve,
    Union,
    Keccak,
    Stark2Snark,
}

impl FromStr for Command {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "EXECUTE" => Ok(Command::Execute),
            "JOIN" => Ok(Command::Join),
            "PROVE" => Ok(Command::Prove),
            "FINALIZE" => Ok(Command::Finalize),
            "RESOLVE" => Ok(Command::Resolve),
            "UNION" => Ok(Command::Union),
            "KECCAK" => Ok(Command::Keccak),
            "STARK2SNARK" => Ok(Command::Stark2Snark),
            _ => Err(anyhow::anyhow!("Unknown command type: {}", s)),
        }
    }
}
impl Command {
    pub fn apply(self, agent: &dyn Agent, input: Vec<u8>) -> Result<Vec<u8>> {
        match self {
            Command::Execute => agent.execute(input),
            Command::Join => agent.join(input),
            Command::Prove => agent.prove(input),
            Command::Finalize => agent.finalize(input),
            Command::Resolve => agent.resolve(input),
            Command::Union => agent.union(input),
            Command::Keccak => agent.keccak(input),
            Command::Stark2Snark => agent.stark2snark(input),
        }
    }
}
