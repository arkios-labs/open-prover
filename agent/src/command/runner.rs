use std::collections::HashSet;
use anyhow::Result;
use crate::tasks::Agent;
use crate::command::registry::get_command_map;

fn is_command_enabled(key: &str, cli_args: &HashSet<String>) -> bool {
    cli_args.contains(key) || std::env::var(key).is_ok()
}

pub fn run_enabled_commands(agent: &dyn Agent, cli_args: &HashSet<String>) -> Result<()> {
    for (key, action) in get_command_map() {
        if is_command_enabled(key, cli_args) {
            println!("Running {}", key);
            action(agent)?;
        }
    }
    Ok(())
}
