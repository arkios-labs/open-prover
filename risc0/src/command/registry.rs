use crate::tasks::Risc0Agent;
use anyhow::{Result, anyhow};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Command {
    Join,
    Prove,
    Finalize,
    Resolve,
    Union,
    Keccak,
    Snark,
}

impl FromStr for Command {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "JOIN" => Ok(Command::Join),
            "PROVE" => Ok(Command::Prove),
            "FINALIZE" => Ok(Command::Finalize),
            "RESOLVE" => Ok(Command::Resolve),
            "UNION" => Ok(Command::Union),
            "KECCAK" => Ok(Command::Keccak),
            "SNARK" => Ok(Command::Snark),
            _ => Err(anyhow!("Unknown command type: {}", s)),
        }
    }
}
impl Command {
    pub fn apply(self, agent: &Risc0Agent, input: Vec<u8>) -> Result<Vec<u8>> {
        match self {
            Command::Join => agent.join(input),
            Command::Prove => agent.prove(input),
            Command::Finalize => agent.finalize(input),
            Command::Resolve => agent.resolve(input),
            Command::Union => agent.union(input),
            Command::Keccak => agent.keccak(input),
            Command::Snark => agent.stark2snark(input),
        }
    }
}
