use crate::tasks::Agent;
use anyhow::Result;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Command {
    Setup,
    Prove,
    ProveLift,
    Compress,
    Shrink,
    Wrap,
    Groth16,
    Plonk,
    WrapCore,
    WrapCompress,
    WrapGroth16,
    WrapPlonk,
}

impl FromStr for Command {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "SETUP" => Ok(Command::Setup),
            "PROVE" => Ok(Command::Prove),
            "PROVE_LIFT" => Ok(Command::ProveLift),
            "COMPRESS" => Ok(Command::Compress),
            "SHRINK" => Ok(Command::Shrink),
            "WRAP" => Ok(Command::Wrap),
            "GROTH16" => Ok(Command::Groth16),
            "PLONK" => Ok(Command::Plonk),
            "WRAP_CORE" => Ok(Command::WrapCore),
            "WRAP_COMPRESS" => Ok(Command::WrapCompress),
            "WRAP_GROTH16" => Ok(Command::WrapGroth16),
            "WRAP_PLONK" => Ok(Command::WrapPlonk),
            _ => Err(anyhow::anyhow!("Unknown command type: {}", s)),
        }
    }
}
impl Command {
    pub async fn apply(self, agent: &dyn Agent, input: Vec<u8>) -> Result<Vec<u8>> {
        match self {
            Command::Setup => agent.setup(input),
            Command::Prove => agent.prove(input),
            Command::ProveLift => agent.prove_lift(input),
            Command::Compress => agent.compress(input),
            Command::Shrink => agent.shrink(input),
            Command::Wrap => agent.wrap(input),
            Command::Groth16 => agent.groth16(input),
            Command::Plonk => agent.plonk(input),
            Command::WrapCore => agent.wrap_core(input),
            Command::WrapCompress => agent.wrap_compress(input),
            Command::WrapGroth16 => agent.wrap_groth16(input),
            Command::WrapPlonk => agent.wrap_plonk(input),
        }
    }
}
