use crate::tasks::Agent;
use anyhow::Result;

// pub fn get_command_map() -> Vec<(
//     &'static str,
//     Box<dyn Fn(&dyn Agent, Vec<u8>) -> Result<()>>,
// )> {
//     vec![
//         ("EXECUTE", Box::new(|a, input| a.execute(input))),
//         ("JOIN", Box::new(|a, input| a.join(input))),
//         ("PROVE", Box::new(|a, input| a.prove(input))),
//         ("FINALIZE", Box::new(|a, input| a.finalize(input))),
//         ("RESOLVE", Box::new(|a, input| a.resolve(input))),
//         ("UNION", Box::new(|a, input| a.union(input))),
//         ("KECCAK", Box::new(|a, input| a.keccak(input))),
//         ("STARK2SNARK", Box::new(|a, input| a.stark2snark(input))),
//     ]
// }