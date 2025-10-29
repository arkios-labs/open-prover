use thiserror::Error;

mod resolver;

mod data_uri;
mod http_uri;
mod storage_uri;

pub use resolver::UriResolver;

pub use data_uri::DataUriError;
pub use http_uri::HttpUriError;
pub use storage_uri::StorageUriError;

use crate::storage::StorageType;

#[derive(Debug, Error)]
pub enum UriError {
    #[error("Invalid URI format: {0}")]
    InvalidUri(#[from] url::ParseError),

    #[error("Unsupported URI scheme: '{0}'")]
    UnsupportedScheme(String),

    #[error(transparent)]
    Storage(#[from] StorageUriError),

    #[error(transparent)]
    Http(#[from] HttpUriError),

    #[error(transparent)]
    Data(#[from] DataUriError),
}

pub type Result<T> = std::result::Result<T, UriError>;

#[derive(Debug, Clone)]
pub struct ResourceMetadata {
    pub uri: String,
    pub size: u64,
}

impl StorageType {
    pub fn to_scheme(&self) -> String {
        match self {
            StorageType::EFS => "efs".to_string(),
        }
    }
}
