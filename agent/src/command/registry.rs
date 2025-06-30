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
    Snark,
    PrepareSnark,
    GetSnarkReceipt,
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
            "SNARK" => Ok(Command::Snark),
            "PREPARE_SNARK" => Ok(Command::PrepareSnark),
            "GET_SNARK_RECEIPT" => Ok(Command::GetSnarkReceipt),
            _ => Err(anyhow::anyhow!("Unknown command type: {}", s)),
        }
    }
}
impl Command {
    pub async fn apply(self, agent: &dyn Agent, input: Vec<u8>) -> Result<Vec<u8>> {
        match self {
            Command::Execute => agent.execute(input),
            Command::Join => agent.join(input),
            Command::Prove => agent.prove(input),
            Command::Finalize => agent.finalize(input),
            Command::Resolve => agent.resolve(input),
            Command::Union => agent.union(input),
            Command::Keccak => agent.keccak(input),
            Command::Snark => agent.snark(input).await,
            Command::PrepareSnark => agent.prepare_snark(input),
            Command::GetSnarkReceipt => agent.get_snark_receipt(input),
        }
    }
}
