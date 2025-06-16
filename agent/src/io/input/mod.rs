pub mod stdin;
pub mod shmem;
pub mod env;

pub trait InputProvider {
    fn read_bytes(&self) -> anyhow::Result<Vec<u8>>;
}