use crate::io::input::InputProvider;
use anyhow::Result;
use std::env;

pub struct EnvProvider {
    pub key: String,
}

impl InputProvider for EnvProvider {
    fn read_bytes(&self) -> Result<Vec<u8>> {
        let value = env::var(&self.key).unwrap_or_default();
        Ok(value.into_bytes())
    }
}