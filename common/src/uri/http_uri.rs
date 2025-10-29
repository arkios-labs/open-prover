use crate::uri::UriError;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum HttpUriError {
    #[error("Failed to fetch from {url}: {source}")]
    HttpRequestError {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("HTTP request failed with status: {status}")]
    HttpStatusError { status: reqwest::StatusCode },

    #[error("Failed to read response body: {0}")]
    ResponseBodyError(#[source] reqwest::Error),
}

pub(super) async fn read(http_client: &reqwest::Client, url: &Url) -> Result<Vec<u8>, UriError> {
    let response = http_client.get(url.as_str()).send().await.map_err(|e| {
        UriError::Http(HttpUriError::HttpRequestError { url: url.to_string(), source: e })
    })?;

    if !response.status().is_success() {
        return Err(UriError::Http(HttpUriError::HttpStatusError { status: response.status() }));
    }

    let bytes =
        response.bytes().await.map_err(|e| UriError::Http(HttpUriError::ResponseBodyError(e)))?;

    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use httpmock::{Method::GET, MockServer};

    use super::*;

    async fn create_mock_server() -> MockServer {
        MockServer::start()
    }

    async fn create_test_http_client() -> reqwest::Client {
        reqwest::Client::new()
    }

    #[tokio::test]
    async fn test_http_uri_read() {
        let mock_server = create_mock_server().await;
        let http_client = create_test_http_client().await;

        let health_mock = mock_server.mock(|when, then| {
            when.method(GET).path("/health");
            then.status(200)
                .header("Content-Type", "application/json")
                .json_body_obj(&serde_json::json!({ "status": "ok" }));
        });

        let uri = mock_server.base_url() + "/health";
        let url = Url::parse(&uri).unwrap();
        let content = read(&http_client, &url).await.unwrap();
        assert!(!content.is_empty());
        health_mock.assert();
    }

    #[tokio::test]
    async fn test_http_uri_read_invalid_url() {
        let http_client = create_test_http_client().await;
        let uri = "https://invalid.url";
        let url = Url::parse(uri).unwrap();
        let result = read(&http_client, &url).await;
        match result {
            Err(UriError::Http(HttpUriError::HttpRequestError { url: _, source: _ })) => {
                assert!(result.is_err());
            }
            _ => panic!("Expected HttpRequestError error"),
        }
    }
}
