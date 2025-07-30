use crate::io::input::InputProvider;
use anyhow::Result;
use memmap2::MmapOptions;
use std::fs::File;

pub struct ShmemProvider {
    pub path: String,
}

impl InputProvider for ShmemProvider {
    fn read_bytes(&self) -> Result<Vec<u8>> {
        let file = File::open(&self.path)?;
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        Ok(mmap.to_vec())
    }
}
