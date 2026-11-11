//! The one place the deployed-contract mode touches the network: a [`Transport`] that POSTs a JSON-RPC body.
//!
//! Everything above it is pure, so tests replay recorded responses through their own [`Transport`] and never
//! open a socket. [`HttpTransport`] is the production one.

use std::str::FromStr;
use std::time::Duration;

use ureq::http::Uri;

use super::display::clean;

/// Sends one JSON-RPC request body and returns the raw response body.
pub trait Transport {
    /// POSTs `request`. A response body longer than `max_bytes` is [`TransportError::TooLarge`], never truncated.
    fn post(&self, request: &str, max_bytes: usize) -> Result<Vec<u8>, TransportError>;

    /// Where requests go, safe to print and publish: scheme, host and port only, never a path or query that may
    /// carry an API key.
    fn endpoint(&self) -> &str;
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("no answer within {0:?}")]
    Timeout(Duration),
    #[error("cannot reach the endpoint: {0}")]
    Network(String),
    #[error("the endpoint is rate limiting requests (HTTP 429); wait, or pass another endpoint with --rpc")]
    RateLimited,
    #[error("the endpoint answered HTTP {status}: {body}")]
    Status { status: u16, body: String },
    #[error("the response is larger than the {limit} byte limit")]
    TooLarge { limit: usize },
}

/// A validated `http(s)` JSON-RPC endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcUrl {
    url: String,
    origin: String,
}

impl FromStr for RpcUrl {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let uri: Uri = text.parse().map_err(|_| "not a valid URL".to_owned())?;
        let scheme = uri.scheme_str().filter(|scheme| matches!(*scheme, "http" | "https"));
        let (Some(scheme), Some(host)) = (scheme, uri.host()) else {
            return Err("must be an http:// or https:// URL with a host".to_owned());
        };
        let port = uri.port_u16().map(|port| format!(":{port}")).unwrap_or_default();
        Ok(Self { url: text.to_owned(), origin: format!("{scheme}://{host}{port}") })
    }
}

impl RpcUrl {
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

pub struct HttpTransport {
    agent: ureq::Agent,
    url: RpcUrl,
    timeout: Duration,
}

impl HttpTransport {
    /// `timeout` bounds each whole request: connect, send and read. Redirects are not followed, so an endpoint
    /// that moved is an error that names its HTTP status rather than a silent hop to another host. Proxies are
    /// not used: ureq would otherwise read `HTTP(S)_PROXY` and `ALL_PROXY` from the environment and send every
    /// request, and the answers that decide a verdict, through whatever they name.
    pub fn new(url: RpcUrl, timeout: Duration) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .proxy(None)
            .user_agent(concat!("preflight/", env!("CARGO_PKG_VERSION")))
            .build();
        Self { agent: config.into(), url, timeout }
    }

    fn map_error(&self, error: ureq::Error) -> TransportError {
        match error {
            ureq::Error::Timeout(_) => TransportError::Timeout(self.timeout),
            other => TransportError::Network(clean(&other.to_string(), 200)),
        }
    }
}

impl Transport for HttpTransport {
    fn post(&self, request: &str, max_bytes: usize) -> Result<Vec<u8>, TransportError> {
        let mut response = self
            .agent
            .post(&self.url.url)
            .header("content-type", "application/json")
            .send(request)
            .map_err(|e| self.map_error(e))?;
        let status = response.status().as_u16();
        let limit = if status == 200 { max_bytes } else { 512 };
        let body = match response.body_mut().with_config().limit(limit as u64).read_to_vec() {
            Ok(body) => body,
            Err(ureq::Error::BodyExceedsLimit(_)) if status == 200 => return Err(TransportError::TooLarge { limit }),
            // An error page longer than the snippet limit is still just an error page.
            Err(ureq::Error::BodyExceedsLimit(_)) => Vec::new(),
            Err(error) => return Err(self.map_error(error)),
        };
        match status {
            200 => Ok(body),
            429 => Err(TransportError::RateLimited),
            status => Err(TransportError::Status { status, body: clean(&String::from_utf8_lossy(&body), 200) }),
        }
    }

    fn endpoint(&self) -> &str {
        self.url.origin()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_origin_drops_the_path_query_and_credentials() {
        let url: RpcUrl = "https://user:pw@rpc.example.com:8443/v1/SECRETKEY?token=abc".parse().unwrap();
        assert_eq!(url.origin(), "https://rpc.example.com:8443");
        let url: RpcUrl = "http://127.0.0.1:3030".parse().unwrap();
        assert_eq!(url.origin(), "http://127.0.0.1:3030");
    }

    #[test]
    fn only_http_and_https_urls_with_a_host_are_accepted() {
        for bad in ["", "rpc.example.com", "ftp://rpc.example.com", "file:///etc/passwd", "https://", "/path/only"] {
            assert!(bad.parse::<RpcUrl>().is_err(), "{bad:?} should be rejected");
        }
    }
}
