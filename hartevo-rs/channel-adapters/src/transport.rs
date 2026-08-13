//! Secret-free request/response ports for provider read-only operations.

use std::{collections::BTreeSet, fmt, fmt::Write as _};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::identity::{AccountIdentity, ProviderId};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ScopeName(String);

impl ScopeName {
    pub fn new(value: impl Into<String>) -> Result<Self, ChannelAdapterError> {
        let value = value.into();
        if value.is_empty() || value.len() > 256 || value.chars().any(char::is_whitespace) {
            return Err(ChannelAdapterError::InvalidRequest("invalid scope name"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ScopeName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct CredentialReference(String);

impl CredentialReference {
    pub fn new(value: impl Into<String>) -> Result<Self, ChannelAdapterError> {
        let value = value.into();
        let lower = value.to_ascii_lowercase();
        if value.is_empty()
            || value.len() > 256
            || value.chars().any(char::is_whitespace)
            || lower.contains("bearer")
            || lower.contains("access_token")
            || lower.contains("refresh_token")
            || lower.contains("client_secret")
        {
            return Err(ChannelAdapterError::InvalidRequest(
                "credential reference must be opaque and secret-free",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CredentialReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialReference(<opaque>)")
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadOperation {
    Probe,
    Identity,
    Content,
    Analytics,
    Status,
    IntegrationMode,
}

#[derive(Clone)]
pub struct ProviderReadRequest {
    provider: ProviderId,
    operation: ReadOperation,
    method: HttpMethod,
    url: Url,
    required_scopes: BTreeSet<ScopeName>,
    credential: CredentialReference,
    body: Option<serde_json::Value>,
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
            .field("body_digest", &self.body.as_ref().map(body_digest))
            .finish()
    }
}

impl ProviderReadRequest {
    pub fn new(
        provider: ProviderId,
        operation: ReadOperation,
        method: HttpMethod,
        url: Url,
        required_scopes: impl IntoIterator<Item = ScopeName>,
        credential: CredentialReference,
        body: Option<serde_json::Value>,
    ) -> Result<Self, ChannelAdapterError> {
        if url.scheme() != "https" {
            return Err(ChannelAdapterError::InvalidRequest(
                "provider requests must use https",
            ));
        }
        if body_contains_secret_key(body.as_ref()) {
            return Err(ChannelAdapterError::InvalidRequest(
                "read-only request body contains secret material",
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

    pub const fn operation(&self) -> ReadOperation {
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

    pub fn credential(&self) -> &CredentialReference {
        &self.credential
    }

    pub fn body(&self) -> Option<&serde_json::Value> {
        self.body.as_ref()
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
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn json(&self, provider: ProviderId) -> Result<serde_json::Value, ChannelAdapterError> {
        serde_json::from_str(&self.body).map_err(|_| ChannelAdapterError::InvalidResponse {
            provider,
            field: "json".to_owned(),
        })
    }

    pub fn body_digest(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(self.body.as_bytes());
        hex_digest(digest.finalize())
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationReason {
    MissingApproval,
    MissingScope,
    ScopeRevoked,
    CredentialExpired,
    CredentialRejected,
    NoApprovedIntegration,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ChannelAdapterError {
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("invalid response from {provider}: {field}")]
    InvalidResponse { provider: ProviderId, field: String },
    #[error("authorization required for {provider}: {reason:?}")]
    AuthorizationRequired {
        provider: ProviderId,
        reason: AuthorizationReason,
    },
    #[error("credential revoked for {provider}: {reason:?}")]
    CredentialRevoked {
        provider: ProviderId,
        reason: AuthorizationReason,
        account: Option<AccountIdentity>,
    },
    #[error("provider scope is not granted for {provider}: {scope}")]
    ScopeNotGranted {
        provider: ProviderId,
        scope: ScopeName,
    },
    #[error("quota exhausted for {provider}: {bucket}")]
    QuotaExhausted {
        provider: ProviderId,
        bucket: String,
    },
    #[error("provider rate limit for {provider}")]
    RateLimited {
        provider: ProviderId,
        retry_after_seconds: Option<u64>,
    },
    #[error("provider rejected {provider} request with status {status}")]
    ProviderRejected {
        provider: ProviderId,
        status: u16,
        code: Option<String>,
    },
    #[error("content not found for {provider}")]
    ContentNotFound { provider: ProviderId },
    #[error("unsupported {provider} surface: {surface}")]
    UnsupportedSurface {
        provider: ProviderId,
        surface: &'static str,
    },
    #[error("transport unavailable for {provider}")]
    TransportUnavailable { provider: ProviderId },
    #[error("provider read is blocked by environment for {provider}: {requirement}")]
    BlockedEnvironment {
        provider: ProviderId,
        requirement: &'static str,
    },
    #[error("durable cursor is stale for {provider} stream {stream}")]
    CursorStale {
        provider: ProviderId,
        stream: &'static str,
    },
    #[error("freshness expired for {provider}: valid until {valid_until}")]
    FreshnessExpired {
        provider: ProviderId,
        observed_at: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    },
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TransportError {
    #[error("transport unavailable")]
    Unavailable,
    #[error("transport timed out")]
    TimedOut,
}

pub trait ReadOnlyTransport {
    fn send(&mut self, request: &ProviderReadRequest) -> Result<ProviderResponse, TransportError>;
}

pub(crate) fn provider_code(body: &serde_json::Value) -> Option<String> {
    body.pointer("/error/errors/0/reason")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            body.pointer("/error/code")
                .and_then(serde_json::Value::as_str)
        })
        .or_else(|| body.get("error").and_then(serde_json::Value::as_str))
        .map(str::to_owned)
}

pub(crate) fn retry_after(response: &ProviderResponse) -> Option<u64> {
    response
        .header("retry-after")
        .and_then(|value| value.parse::<u64>().ok())
}

pub(crate) fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn body_digest(body: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(body).unwrap_or_default();
    let mut digest = Sha256::new();
    digest.update(bytes);
    hex_digest(digest.finalize())
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
