use crate::tasks::Agent;
use anyhow::{Result, anyhow};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Command {
    Setup,
    Prove,
    ProveLift,
    LiftDefer,
    Compress,
    ShrinkWrap,
    Groth16,
    Plonk,
    WrapCompress,
    VerifyCompress,
    VerifyGroth16,
    VerifyPlonk,
}

impl FromStr for Command {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "SETUP" => Ok(Command::Setup),
            "PROVE" => Ok(Command::Prove),
            "PROVE_LIFT" => Ok(Command::ProveLift),
            "LIFT_DEFER" => Ok(Command::LiftDefer),
            "COMPRESS" => Ok(Command::Compress),
            "SHRINK_WRAP" => Ok(Command::ShrinkWrap),
            "GROTH16" => Ok(Command::Groth16),
            "PLONK" => Ok(Command::Plonk),
            "WRAP_COMPRESS" => Ok(Command::WrapCompress),
            "VERIFY_COMPRESS" => Ok(Command::VerifyCompress),
            "VERIFY_GROTH16" => Ok(Command::VerifyGroth16),
            "VERIFY_PLONK" => Ok(Command::VerifyPlonk),
            _ => Err(anyhow!("Unknown command type: {}", s)),
        }
    }
}
impl Command {
    pub fn apply(self, agent: &impl Agent, input: Vec<u8>) -> Result<Vec<u8>> {
        match self {
            Command::Setup => agent.setup(input),
            Command::Prove => agent.prove(input),
            Command::ProveLift => agent.prove_lift(input),
            Command::LiftDefer => agent.lift_defer(input),
            Command::Compress => agent.compress(input),
            Command::ShrinkWrap => agent.shrink_wrap(input),
            Command::Groth16 => agent.groth16(input),
            Command::Plonk => agent.plonk(input),
            Command::WrapCompress => agent.wrap_compress(input),
            Command::VerifyCompress => agent.verify_compress(input),
            Command::VerifyGroth16 => agent.verify_groth16(input),
            Command::VerifyPlonk => agent.verify_plonk(input),
        }
    }
}
