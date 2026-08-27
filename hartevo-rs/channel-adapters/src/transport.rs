//! Secret-free request/response ports for provider read-only operations.

use std::{collections::BTreeSet, fmt, fmt::Write as _};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::identity::{AccountIdentity, ProviderId};

use crate::tiktok::{ProviderId as TiktokProviderId, TiktokApiOperation, TiktokError};

/// Opaque TikTok credential handle passed to the external credential service.
///
/// The adapter never resolves or logs the referenced secret. It is kept
/// separate from the shared YouTube [`CredentialReference`] because the
/// TikTok plugin predates the shared channel root and has its own typed
/// credential contract.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretReference(String);

impl SecretReference {
    pub fn new(value: impl Into<String>) -> Result<Self, TiktokError> {
        let value = value.into();
        let lower = value.to_ascii_lowercase();
        if value.is_empty()
            || value.len() > 512
            || value.chars().any(char::is_whitespace)
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

/// Provider identity carried by a shared request while preserving the
/// independent TikTok and YouTube identity domains.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProviderKind {
    Youtube(ProviderId),
    Tiktok(TiktokProviderId),
}

impl From<ProviderId> for ProviderKind {
    fn from(provider: ProviderId) -> Self {
        Self::Youtube(provider)
    }
}

impl From<TiktokProviderId> for ProviderKind {
    fn from(provider: TiktokProviderId) -> Self {
        Self::Tiktok(provider)
    }
}

#[derive(Clone, Debug)]
pub enum CredentialKind {
    Youtube(CredentialReference),
    Tiktok(SecretReference),
}

impl From<CredentialReference> for CredentialKind {
    fn from(credential: CredentialReference) -> Self {
        Self::Youtube(credential)
    }
}

impl From<SecretReference> for CredentialKind {
    fn from(credential: SecretReference) -> Self {
        Self::Tiktok(credential)
    }
}

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
    TiktokUserInfo,
    TiktokVideoList,
    TiktokVideoQuery,
}

impl From<TiktokApiOperation> for ReadOperation {
    fn from(operation: TiktokApiOperation) -> Self {
        match operation {
            TiktokApiOperation::UserInfo => Self::TiktokUserInfo,
            TiktokApiOperation::VideoList => Self::TiktokVideoList,
            TiktokApiOperation::VideoQuery => Self::TiktokVideoQuery,
        }
    }
}

impl PartialEq<TiktokApiOperation> for ReadOperation {
    fn eq(&self, other: &TiktokApiOperation) -> bool {
        matches!(
            (self, other),
            (Self::TiktokUserInfo, TiktokApiOperation::UserInfo)
                | (Self::TiktokVideoList, TiktokApiOperation::VideoList)
                | (Self::TiktokVideoQuery, TiktokApiOperation::VideoQuery)
        )
    }
}

#[derive(Clone)]
pub struct ProviderReadRequest {
    provider: ProviderKind,
    operation: ReadOperation,
    method: HttpMethod,
    url: Url,
    required_scopes: BTreeSet<ScopeName>,
    credential: CredentialKind,
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
        provider: impl Into<ProviderKind>,
        operation: impl Into<ReadOperation>,
        method: HttpMethod,
        url: Url,
        required_scopes: impl IntoIterator<Item = ScopeName>,
        credential: impl Into<CredentialKind>,
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
            provider: provider.into(),
            operation: operation.into(),
            method,
            url,
            required_scopes: required_scopes.into_iter().collect(),
            credential: credential.into(),
            body,
        })
    }

    pub fn provider(&self) -> ProviderId {
        match self.provider {
            ProviderKind::Youtube(provider) => provider,
            ProviderKind::Tiktok(_) => {
                panic!("a TikTok request cannot be projected as a YouTube identity")
            }
        }
    }

    pub const fn provider_kind(&self) -> ProviderKind {
        self.provider
    }

    pub fn tiktok_provider(&self) -> TiktokProviderId {
        match self.provider {
            ProviderKind::Tiktok(provider) => provider,
            ProviderKind::Youtube(_) => {
                panic!("a YouTube request cannot be projected as a TikTok identity")
            }
        }
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

    pub fn credential(&self) -> &CredentialKind {
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

    pub fn json_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::from_str(&self.body)
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

pub(crate) fn sha256_json(value: &serde_json::Value) -> String {
    serde_json::to_vec(value).map_or_else(|_| hex_sha256([]), hex_sha256)
}

fn hex_sha256(bytes: impl AsRef<[u8]>) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes.as_ref());
    hex_digest(digest.finalize())
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
