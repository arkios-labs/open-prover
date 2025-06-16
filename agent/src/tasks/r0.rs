use tracing::info;
use crate::tasks::Agent;
use crate::io::input::InputProvider;

pub struct RiscZeroAgent;

impl Agent for RiscZeroAgent {
    fn execute(&self) -> anyhow::Result<()> {
        info!("RiscZeroTask::execute()");
        Ok(())
    }

    fn prove(&self) -> anyhow::Result<()> {
        info!("RiscZeroTask::prove()");
        Ok(())
    }

    fn join(&self) -> anyhow::Result<()> {
        info!("RiscZeroTask::join()");
        Ok(())
    }

    fn keccak(&self) -> anyhow::Result<()> {
        info!("RiscZeroTask::keccak()");
        Ok(())
    }

    fn union(&self) -> anyhow::Result<()> {
        info!("RiscZeroTask::union()");
        Ok(())
    }

    fn finalize(&self) -> anyhow::Result<()> {
        info!("RiscZeroTask::finalize()");
        Ok(())
    }

    fn stark2snark(&self) -> anyhow::Result<()> {
        info!("RiscZeroTask::stark2snark()");
        Ok(())
    }

    fn resolve(&self) -> anyhow::Result<()> {
        info!("RiscZeroTask::resolve()");
        Ok(())
    }
}
