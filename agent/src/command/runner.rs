// use crate::command::registry::get_command_map;
use crate::tasks::Agent;
use anyhow::{Result, bail};
use tracing::info;

// pub fn run_selected_command(agent: &dyn Agent, command: &str, input: Vec<u8>) -> Result<()> {
//     let command_map = get_command_map();
// 
//     let selected = command_map
//         .into_iter()
//         .find(|(key, _)| key.eq_ignore_ascii_case(command) || std::env::var(key).is_ok());
// 
//     match selected {
//         Some((key, action)) => {
//             info!("Running command: {}", key);
//             action(agent, input)
//         }
//         None => {
//             let all_cmds: Vec<&str> = get_command_map().into_iter().map(|(k, _)| k).collect();
//             bail!(
//                 "No matching command found for '{}'. Available commands: {:?}",
//                 command,
//                 all_cmds
//             );
//         }
//     }
// }
