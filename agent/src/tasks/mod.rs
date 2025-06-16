pub mod r0;
pub mod factory;

use anyhow::{Context, Result};

pub trait Agent {
    fn execute(&self) -> Result<()>;
    fn prove(&self) -> Result<()>;
    fn join(&self) -> Result<()>;
    fn keccak(&self) -> Result<()>;
    fn union(&self) -> Result<()>;
    fn finalize(&self) -> Result<()>;
    fn stark2snark(&self) -> Result<()>;
    fn resolve(&self) -> Result<()>;
}