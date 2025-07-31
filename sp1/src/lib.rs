pub mod command;
pub mod e2e;
pub mod tasks;

pub const FIBONACCI_ELF: &[u8] = include_bytes!("../fibonacci-elf");
pub const KECCAK_ELF: &[u8] = include_bytes!("../keccak-elf");
