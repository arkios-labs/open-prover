use crate::uri::UriError;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum DataUriError {
    #[error("Invalid data URI")]
    InvalidDataUri,

    #[error("Invalid data URI: missing comma separator")]
    MissingCommaSeparator,

    #[error("Failed to decode base64 data URI: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("Failed to decode URL-encoded data: {0}")]
    UrlDecodeError(String),
}

const DATA_URI_PREFIX: &str = "data:";

pub(super) async fn read(url: &Url) -> Result<Vec<u8>, UriError> {
    let data_str = url.as_str();

    if !data_str.starts_with(DATA_URI_PREFIX) {
        return Err(UriError::Data(DataUriError::InvalidDataUri));
    }

    let comma_pos =
        data_str.find(',').ok_or(UriError::Data(DataUriError::MissingCommaSeparator))?;
    let metadata = &data_str[DATA_URI_PREFIX.len()..comma_pos];
    let content = &data_str[comma_pos + 1..];

    if _is_base64(metadata) {
        use base64::{Engine, engine::general_purpose::STANDARD};
        Ok(STANDARD
            .decode(content)
            .map_err(|e| UriError::Data(DataUriError::Base64DecodeError(e)))?)
    } else {
        let decoded = urlencoding::decode(content)
            .map_err(|e| UriError::Data(DataUriError::UrlDecodeError(e.to_string())))?;
        Ok(decoded.as_bytes().to_vec())
    }
}

fn _is_base64(metadata: &str) -> bool {
    metadata.split(';').any(|part| part == "base64")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_data_uri_base64() {
        let uri = "data:text/plain;base64,SGVsbG8sIFdvcmxkIQ==";
        let url = Url::parse(uri).unwrap();
        let content = read(&url).await.unwrap();
        assert_eq!(content, b"Hello, World!");
    }

    #[tokio::test]
    async fn test_data_uri_plain() {
        let uri = "data:text/plain,Hello%2C%20World%21";
        let url = Url::parse(uri).unwrap();
        let content = read(&url).await.unwrap();
        assert_eq!(content, b"Hello, World!");
    }

    #[tokio::test]
    async fn test_error_type_invalid_data_uri() {
        let uri = "notdata:text/plain";
        let url = Url::parse(uri).unwrap();
        let result = read(&url).await;

        match result {
            Err(UriError::Data(DataUriError::InvalidDataUri)) => {
                assert!(result.is_err());
            }
            _ => panic!("Expected InvalidDataUri error"),
        }
    }

    #[tokio::test]
    async fn test_error_type_missing_comma_separator() {
        let uri = "data:text/plain";
        let url = Url::parse(uri).unwrap();
        let result = read(&url).await;

        match result {
            Err(UriError::Data(DataUriError::MissingCommaSeparator)) => {
                assert!(result.is_err());
            }
            _ => panic!("Expected MissingCommaSeparator error"),
        }
    }

    #[tokio::test]
    async fn test_error_type_base64_decode_error() {
        let uri = "data:text/plain;base64,invalid_utf8";
        let url = Url::parse(uri).unwrap();
        let result = read(&url).await;

        match result {
            Err(UriError::Data(DataUriError::Base64DecodeError(_))) => {
                assert!(result.is_err());
            }
            _ => panic!("Expected Base64DecodeError error"),
        }
    }

    #[tokio::test]
    async fn test_error_type_url_decode_error() {
        let uri = "data:text/plain,invalid_utf8_char%80";
        let url = Url::parse(uri).unwrap();
        let result = read(&url).await;

        match result {
            Err(UriError::Data(DataUriError::UrlDecodeError(_))) => {
                assert!(result.is_err());
            }
            _ => panic!("Expected UrlDecodeError error"),
        }
    }
}
