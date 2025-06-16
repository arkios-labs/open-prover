use std::io::{self, Read};
use anyhow::Result;
use crate::io::input::InputProvider;

pub struct StdinProvider;

impl InputProvider for StdinProvider {
    fn read_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    }
}
