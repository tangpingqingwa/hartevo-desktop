use std::fmt;
use std::io::Read;

use reqwest::blocking::Client;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct OpaqueCredential(Zeroizing<String>);

impl OpaqueCredential {
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderTransportError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(ProviderTransportError::MissingCredential);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    pub fn from_env(name: &str) -> Result<Self, ProviderTransportError> {
        let value = std::env::var(name).map_err(|_| ProviderTransportError::MissingCredential)?;
        Self::new(value)
    }

    pub(crate) fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for OpaqueCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueCredential([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderHttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

#[derive(Clone)]
pub struct ProviderHttpRequest {
    method: ProviderHttpMethod,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    credential: Option<OpaqueCredential>,
}

impl ProviderHttpRequest {
    pub fn new(
        method: ProviderHttpMethod,
        url: impl Into<String>,
        credential: Option<OpaqueCredential>,
    ) -> Self {
        Self {
            method,
            url: url.into(),
            headers: vec![("Accept".into(), "application/json".into())],
            body: None,
            credential,
        }
    }

    pub fn get(url: impl Into<String>, credential: OpaqueCredential) -> Self {
        Self::new(ProviderHttpMethod::Get, url, Some(credential))
    }

    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    #[must_use]
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn method(&self) -> ProviderHttpMethod {
        self.method
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn header_names(&self) -> impl Iterator<Item = &str> {
        self.headers.iter().map(|(name, _)| name.as_str())
    }

    pub fn has_credential(&self) -> bool {
        self.credential.is_some()
    }

    pub fn body_len(&self) -> usize {
        self.body.as_ref().map_or(0, Vec::len)
    }

    fn credential(&self) -> Option<&OpaqueCredential> {
        self.credential.as_ref()
    }
}

impl fmt::Debug for ProviderHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderHttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>(),
            )
            .field("body_len", &self.body_len())
            .field("body", &"[REDACTED]")
            .field(
                "credential",
                &self.credential.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProviderHttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl ProviderHttpResponse {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            body: body.into(),
        }
    }

    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for ProviderHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderHttpResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .field("body_digest", &digest_bytes(&self.body))
            .finish()
    }
}

pub trait ProviderHttpTransport: fmt::Debug + Send + Sync {
    fn send(
        &self,
        request: ProviderHttpRequest,
    ) -> Result<ProviderHttpResponse, ProviderTransportError>;
}

pub struct ReqwestProviderHttpTransport {
    client: Client,
    max_response_bytes: usize,
}

impl ReqwestProviderHttpTransport {
    pub fn new(max_response_bytes: usize) -> Result<Self, ProviderTransportError> {
        if max_response_bytes == 0 {
            return Err(ProviderTransportError::InvalidResponseLimit);
        }
        let client = Client::builder()
            .build()
            .map_err(|_| ProviderTransportError::ClientInitialization)?;
        Ok(Self {
            client,
            max_response_bytes,
        })
    }
}

impl fmt::Debug for ReqwestProviderHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReqwestProviderHttpTransport")
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

impl ProviderHttpTransport for ReqwestProviderHttpTransport {
    fn send(
        &self,
        request: ProviderHttpRequest,
    ) -> Result<ProviderHttpResponse, ProviderTransportError> {
        let method = match request.method {
            ProviderHttpMethod::Get => reqwest::Method::GET,
            ProviderHttpMethod::Post => reqwest::Method::POST,
            ProviderHttpMethod::Put => reqwest::Method::PUT,
            ProviderHttpMethod::Patch => reqwest::Method::PATCH,
            ProviderHttpMethod::Delete => reqwest::Method::DELETE,
        };
        let mut builder = self.client.request(method, &request.url);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        if let Some(credential) = request.credential() {
            builder = builder.bearer_auth(credential.expose());
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        let response = builder
            .send()
            .map_err(|_| ProviderTransportError::RequestFailed)?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(ProviderTransportError::HttpStatus { status });
        }
        if response
            .content_length()
            .is_some_and(|length| length > self.max_response_bytes as u64)
        {
            return Err(ProviderTransportError::ResponseTooLarge {
                max_bytes: self.max_response_bytes,
            });
        }
        let read_limit = u64::try_from(self.max_response_bytes)
            .ok()
            .and_then(|limit| limit.checked_add(1))
            .ok_or(ProviderTransportError::InvalidResponseLimit)?;
        let mut body = Vec::new();
        response
            .take(read_limit)
            .read_to_end(&mut body)
            .map_err(|_| ProviderTransportError::RequestFailed)?;
        if body.len() > self.max_response_bytes {
            return Err(ProviderTransportError::ResponseTooLarge {
                max_bytes: self.max_response_bytes,
            });
        }
        Ok(ProviderHttpResponse::new(status, body))
    }
}

#[derive(Debug, Error)]
pub enum ProviderTransportError {
    #[error("provider credential is missing")]
    MissingCredential,
    #[error("provider HTTP client could not be initialized")]
    ClientInitialization,
    #[error("provider HTTP request failed")]
    RequestFailed,
    #[error("provider returned HTTP status {status}")]
    HttpStatus { status: u16 },
    #[error("provider response exceeded the configured {max_bytes} byte limit")]
    ResponseTooLarge { max_bytes: usize },
    #[error("provider response limit is invalid")]
    InvalidResponseLimit,
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_and_response_debug_are_content_safe() {
        let credential = OpaqueCredential::new("super-secret-token").expect("credential");
        let request =
            ProviderHttpRequest::get("https://api.example.invalid/contacts", credential.clone());
        let response = ProviderHttpResponse::new(200, br#"{"private":"body"}"#.to_vec());
        let request_debug = format!("{request:?}");
        let response_debug = format!("{response:?}");
        let credential_debug = format!("{credential:?}");
        assert!(!request_debug.contains("super-secret-token"));
        assert!(!response_debug.contains("private"));
        assert!(!response_debug.contains("body"));
        assert!(!credential_debug.contains("super-secret-token"));
        assert!(request.has_credential());
    }
}
