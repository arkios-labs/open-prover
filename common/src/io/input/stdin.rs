use crate::io::input::InputProvider;
use anyhow::Result;
use std::io::{self, Read};

pub struct StdinProvider;

impl InputProvider for StdinProvider {
    fn read_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    }
}
