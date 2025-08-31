use anyhow::Result;

pub mod env;
pub mod shmem;
pub mod stdin;

pub trait InputProvider {
    fn read_bytes(&self) -> Result<Vec<u8>>;
}
