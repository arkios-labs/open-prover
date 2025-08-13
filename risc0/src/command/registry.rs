use crate::tasks::Agent;
use anyhow::Result;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Command {
    Join,
    Prove,
    Finalize,
    Resolve,
    Union,
    Keccak,
    GetSnarkReceipt,
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
            "GET_SNARK_RECEIPT" => Ok(Command::GetSnarkReceipt),
            _ => Err(anyhow::anyhow!("Unknown command type: {}", s)),
        }
    }
}
impl Command {
    pub fn apply(self, agent: &impl Agent, input: Vec<u8>) -> Result<Vec<u8>> {
        match self {
            Command::Join => agent.join(input),
            Command::Prove => agent.prove(input),
            Command::Finalize => agent.finalize(input),
            Command::Resolve => agent.resolve(input),
            Command::Union => agent.union(input),
            Command::Keccak => agent.keccak(input),
            Command::GetSnarkReceipt => agent.stark2snark(input),
        }
    }
}
