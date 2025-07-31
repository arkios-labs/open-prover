pub mod env;
pub mod shmem;
pub mod stdin;

pub trait InputProvider {
    fn read_bytes(&self) -> anyhow::Result<Vec<u8>>;
}
