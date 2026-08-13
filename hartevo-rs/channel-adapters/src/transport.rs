//! Secret-free transport primitives for official provider calls.

use std::{collections::BTreeSet, fmt, fmt::Write as _};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::tiktok::{ProviderId, TiktokApiOperation, TiktokError};

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretReference(String);

impl SecretReference {
    pub fn new(value: impl Into<String>) -> Result<Self, TiktokError> {
        let value = value.into();
        let lower = value.to_ascii_lowercase();
        if value.is_empty()
            || value.len() > 512
            || value.chars().any(|character| character.is_whitespace())
            || lower.contains("bearer ")
            || lower.contains("access_token")
            || lower.contains("refresh_token")
            || lower.contains("client_secret")
        {
            return Err(TiktokError::InvalidRequest(
                "secret reference must be opaque and secret-free",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretReference(<opaque>)")
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct ScopeName(String);

impl ScopeName {
    pub fn new(value: impl Into<String>) -> Result<Self, TiktokError> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 || value.chars().any(char::is_whitespace) {
            return Err(TiktokError::InvalidRequest("invalid TikTok scope"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ScopeName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ScopeName").field(&self.0).finish()
    }
}

impl fmt::Display for ScopeName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Get => "GET",
            Self::Post => "POST",
        })
    }
}

#[derive(Clone)]
pub struct ProviderReadRequest {
    provider: ProviderId,
    operation: TiktokApiOperation,
    method: HttpMethod,
    url: Url,
    required_scopes: BTreeSet<ScopeName>,
    credential: SecretReference,
    body: Option<serde_json::Value>,
}

impl ProviderReadRequest {
    pub fn new(
        provider: ProviderId,
        operation: TiktokApiOperation,
        method: HttpMethod,
        url: Url,
        required_scopes: impl IntoIterator<Item = ScopeName>,
        credential: SecretReference,
        body: Option<serde_json::Value>,
    ) -> Result<Self, TiktokError> {
        if url.scheme() != "https" || body_contains_secret_key(body.as_ref()) {
            return Err(TiktokError::InvalidRequest(
                "provider request must be https and secret-free",
            ));
        }
        Ok(Self {
            provider,
            operation,
            method,
            url,
            required_scopes: required_scopes.into_iter().collect(),
            credential,
            body,
        })
    }

    pub const fn provider(&self) -> ProviderId {
        self.provider
    }

    pub const fn operation(&self) -> TiktokApiOperation {
        self.operation
    }

    pub const fn method(&self) -> HttpMethod {
        self.method
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn required_scopes(&self) -> &BTreeSet<ScopeName> {
        &self.required_scopes
    }

    pub fn credential(&self) -> &SecretReference {
        &self.credential
    }

    pub fn body(&self) -> Option<&serde_json::Value> {
        self.body.as_ref()
    }

    pub fn digest(&self) -> String {
        let material = serde_json::json!({
            "provider": self.provider,
            "operation": self.operation,
            "method": self.method.to_string(),
            "url": self.url.as_str(),
            "required_scopes": self.required_scopes.iter().map(ScopeName::as_str).collect::<Vec<_>>(),
            "body": self.body,
        });
        sha256_json(&material)
    }
}

impl fmt::Debug for ProviderReadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderReadRequest")
            .field("provider", &self.provider)
            .field("operation", &self.operation)
            .field("method", &self.method)
            .field("url", &self.url)
            .field("required_scopes", &self.required_scopes)
            .field("credential", &self.credential)
            .field("body_present", &self.body.is_some())
            .field("body_digest", &self.body.as_ref().map(sha256_json))
            .finish()
    }
}

impl fmt::Display for ProviderReadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}", self.method, self.url)
    }
}

#[derive(Clone)]
pub struct ProviderResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
    observed_at: DateTime<Utc>,
}

impl ProviderResponse {
    pub fn new(
        status: u16,
        headers: impl IntoIterator<Item = (String, String)>,
        body: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            status,
            headers: headers.into_iter().collect(),
            body: body.into(),
            observed_at,
        }
    }

    pub const fn status(&self) -> u16 {
        self.status
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn json(&self) -> Result<serde_json::Value, TiktokError> {
        serde_json::from_str(&self.body).map_err(|_| TiktokError::InvalidResponse {
            field: "json".to_owned(),
        })
    }

    pub fn body_digest(&self) -> String {
        sha256_bytes(self.body.as_bytes())
    }
}

impl fmt::Debug for ProviderResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderResponse")
            .field("status", &self.status)
            .field("header_count", &self.headers.len())
            .field("body_bytes", &self.body.len())
            .field("body_digest", &self.body_digest())
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportError {
    Unavailable,
    TimedOut,
}

pub trait ReadOnlyTransport {
    fn send(&mut self, request: &ProviderReadRequest) -> Result<ProviderResponse, TransportError>;
}

pub(crate) fn sha256_bytes(bytes: impl AsRef<[u8]>) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes.as_ref());
    hex_digest(digest.finalize())
}

pub(crate) fn sha256_json(value: &serde_json::Value) -> String {
    serde_json::to_vec(value)
        .map(sha256_bytes)
        .unwrap_or_else(|_| sha256_bytes([]))
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn body_contains_secret_key(value: Option<&serde_json::Value>) -> bool {
    let Some(value) = value else {
        return false;
    };
    match value {
        serde_json::Value::Object(object) => object.iter().any(|(key, value)| {
            let key = key.to_ascii_lowercase();
            key.contains("token")
                || key.contains("secret")
                || key.contains("password")
                || body_contains_secret_key(Some(value))
        }),
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| body_contains_secret_key(Some(value))),
        _ => false,
    }
}
