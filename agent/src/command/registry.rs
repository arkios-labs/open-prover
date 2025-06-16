use anyhow::Result;
use crate::tasks::Agent;

pub fn get_command_map() -> Vec<(&'static str, Box<dyn Fn(&dyn Agent) -> Result<()>>)> {
    vec![
        ("EXECUTE", Box::new(|a| a.execute())),
        ("JOIN", Box::new(|a| a.join())),
        ("PROVE", Box::new(|a| a.prove())),
        ("FINALIZE", Box::new(|a| a.finalize())),
        ("RESOLVE", Box::new(|a| a.resolve())),
        ("UNION", Box::new(|a| a.union())),
        ("KECCAK", Box::new(|a| a.keccak())),
        ("STARK2SNARK", Box::new(|a| a.stark2snark())),
    ]
}