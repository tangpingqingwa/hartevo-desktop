//! X API v2 OAuth user-context account insight read boundary.
//!
//! X API v2 exposes an authenticated user's account identity and authored-post
//! timeline.  The private, organic and promoted post metrics are provider
//! facts for posts owned by that authenticated user; this module never turns
//! them into a causal attribution claim.  X Ads account analytics use a
//! different host, API family and OAuth model, so they are deliberately not
//! represented by this X API v2 slice.

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    ConnectorError, ConnectorScope, CredentialLease, DispatchBudget, FreshnessWindow, ProbeStatus,
    ProviderCapabilitySupport, ProviderProvenanceClass, SecretReference,
};

pub const X_ADAPTER_ID: &str = "x.api-v2.account-insights";
pub const X_ADAPTER_VERSION: u32 = 1;
pub const X_INSIGHT_READ_SCHEMA: &str = "hartevo-x-api-v2-insight-read/v1";
pub const X_ACCESS_TOKEN_ENV: &str = "HARTEVO_X_ACCESS_TOKEN";
pub const X_RUN_PROBE_ENV: &str = "HARTEVO_RUN_X_CREDENTIAL_PROBE";
pub const X_DEFAULT_API_BASE_URL: &str = "https://api.x.com";
pub const X_API_VERSION: &str = "2";

/// No central provider registration or write authority is granted by this
/// product slice.  Mission reverse mapping remains an explicit later step.
pub const X_REGISTRATIONS: &[ProviderCapabilitySupport] = &[];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum XConnectionState {
    Unmounted,
    Mounted,
    Stale,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum XMissionCapability {
    PaidSocialInsightRead,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum XCausalStatus {
    NotClaimed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum XReviewState {
    Required,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum XInsightTargetKind {
    UserAccountPosts,
}

/// The provider-native X API v2 target in this slice is an authenticated
/// user's authored account timeline.  An optional organization id is kept in
/// the connector scope only as a Mission-owned binding; X API v2 does not
/// expose a native organization resource on this read path.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum XInsightTarget {
    UserAccountPosts { account_id: String },
}

impl XInsightTarget {
    pub fn kind(&self) -> XInsightTargetKind {
        XInsightTargetKind::UserAccountPosts
    }

    fn account_id(&self) -> &str {
        match self {
            Self::UserAccountPosts { account_id } => account_id,
        }
    }
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XInsightScope {
    user_id: String,
    organization_id: Option<String>,
    account_id: String,
}

impl XInsightScope {
    pub fn new(
        user_id: impl Into<String>,
        organization_id: Option<String>,
        account_id: impl Into<String>,
    ) -> Result<Self, XConnectorError> {
        let scope = Self {
            user_id: user_id.into(),
            organization_id,
            account_id: account_id.into(),
        };
        scope.validate(None)?;
        Ok(scope)
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    pub fn organization_id(&self) -> Option<&str> {
        self.organization_id.as_deref()
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn digest(&self, connector_scope: &ConnectorScope) -> String {
        digest_material([
            connector_scope.digest(),
            self.user_id.clone(),
            self.organization_id.clone().unwrap_or_default(),
            self.account_id.clone(),
        ])
    }

    fn validate(&self, connector_scope: Option<&ConnectorScope>) -> Result<(), XConnectorError> {
        validate_x_user_id(&self.user_id)?;
        validate_x_user_id(&self.account_id)?;
        if self.user_id != self.account_id {
            return Err(XConnectorError::ScopeMismatch);
        }
        if let Some(organization_id) = &self.organization_id {
            validate_scope_id(organization_id)?;
        }
        if let Some(connector_scope) = connector_scope
            && (connector_scope.provider_id() != "x"
                || connector_scope.account_id() != self.account_id)
        {
            return Err(XConnectorError::ScopeMismatch);
        }
        Ok(())
    }

    fn required_scopes() -> BTreeSet<String> {
        BTreeSet::from(["tweet.read".to_owned(), "users.read".to_owned()])
    }

    fn validate_target(&self, target: &XInsightTarget) -> Result<(), XConnectorError> {
        if target.account_id() == self.account_id {
            Ok(())
        } else {
            Err(XConnectorError::ScopeMismatch)
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct XAccessToken(Zeroizing<String>);

impl XAccessToken {
    pub fn new(value: impl Into<String>) -> Result<Self, XConnectorError> {
        let value = value.into();
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(XConnectorError::CredentialUnavailable);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    fn expose(&self) -> &str {
        self.0.as_str()
    }

    pub fn digest(&self) -> String {
        digest_bytes(self.expose().as_bytes())
    }
}

impl Drop for XAccessToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for XAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XAccessToken(REDACTED)")
    }
}

pub trait XCredentialResolver: fmt::Debug + Send + Sync {
    fn resolve(&self, reference: &SecretReference) -> Result<XAccessToken, XConnectorError>;
}

#[derive(Clone, Default)]
pub struct InMemoryXCredentialResolver {
    values: BTreeMap<String, XAccessToken>,
}

impl fmt::Debug for InMemoryXCredentialResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryXCredentialResolver")
            .field("references", &self.values.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl InMemoryXCredentialResolver {
    pub fn insert(
        &mut self,
        reference: &SecretReference,
        token: impl Into<String>,
    ) -> Result<(), XConnectorError> {
        self.values.insert(
            reference.reference_id().to_owned(),
            XAccessToken::new(token)?,
        );
        Ok(())
    }
}

impl XCredentialResolver for InMemoryXCredentialResolver {
    fn resolve(&self, reference: &SecretReference) -> Result<XAccessToken, XConnectorError> {
        self.values
            .get(reference.reference_id())
            .cloned()
            .ok_or(XConnectorError::CredentialUnavailable)
    }
}

#[derive(Clone, Debug)]
pub struct EnvXCredentialResolver {
    pub token_env: String,
}

impl Default for EnvXCredentialResolver {
    fn default() -> Self {
        Self {
            token_env: X_ACCESS_TOKEN_ENV.to_owned(),
        }
    }
}

impl XCredentialResolver for EnvXCredentialResolver {
    fn resolve(&self, _reference: &SecretReference) -> Result<XAccessToken, XConnectorError> {
        std::env::var(&self.token_env)
            .map_err(|_| XConnectorError::CredentialUnavailable)
            .and_then(XAccessToken::new)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XApiBinding {
    pub api_base_url: String,
    pub api_version: String,
}

pub type XApiConfig = XApiBinding;

impl Default for XApiBinding {
    fn default() -> Self {
        Self {
            api_base_url: X_DEFAULT_API_BASE_URL.to_owned(),
            api_version: X_API_VERSION.to_owned(),
        }
    }
}

impl XApiBinding {
    fn validate(&self) -> Result<(), XConnectorError> {
        validate_https_url(&self.api_base_url)?;
        if self.api_version != X_API_VERSION {
            return Err(XConnectorError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum XTransportError {
    #[error("curl process could not be started")]
    Spawn,
    #[error("curl process I/O failed")]
    Io,
    #[error("HTTPS response did not contain a status line")]
    InvalidResponse,
    #[error("transport URL must use HTTPS")]
    InsecureUrl,
}

#[derive(Clone, Eq, PartialEq)]
pub struct XHttpRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub query: Vec<(String, String)>,
}

impl fmt::Debug for XHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers = self
            .headers
            .iter()
            .map(|(name, value)| {
                let lower = name.to_ascii_lowercase();
                let rendered = if lower == "authorization"
                    || lower.contains("token")
                    || lower.contains("secret")
                    || lower == "cookie"
                {
                    "REDACTED".to_owned()
                } else {
                    value.clone()
                };
                (name, rendered)
            })
            .collect::<BTreeMap<_, _>>();
        formatter
            .debug_struct("XHttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &headers)
            .field("query", &self.query)
            .finish()
    }
}

impl XHttpRequest {
    fn get(url: impl Into<String>) -> Self {
        Self {
            method: "GET".to_owned(),
            url: url.into(),
            headers: BTreeMap::new(),
            query: Vec::new(),
        }
    }

    fn with_query(mut self, query: Vec<(String, String)>) -> Self {
        self.query = query;
        self
    }

    fn set_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.insert(name.into(), value.into());
    }

    pub fn path(&self) -> Result<String, XConnectorError> {
        let url = self.url_with_query();
        let authority = url
            .strip_prefix("https://")
            .ok_or(XConnectorError::InvalidRequest)?;
        let slash = authority.find('/').ok_or(XConnectorError::InvalidRequest)?;
        let path = authority[slash..].split('?').next().unwrap_or_default();
        if path.is_empty() {
            return Err(XConnectorError::InvalidRequest);
        }
        Ok(path.to_owned())
    }

    pub fn query_digest(&self) -> String {
        let mut query = self.query.clone();
        query.sort();
        digest_bytes(&serde_json::to_vec(&query).expect("query tuples serialize"))
    }

    fn url_with_query(&self) -> String {
        if self.query.is_empty() {
            return self.url.clone();
        }
        let query = self
            .query
            .iter()
            .map(|(name, value)| format!("{}={}", encode_component(name), encode_component(value)))
            .collect::<Vec<_>>()
            .join("&");
        format!("{}?{query}", self.url)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct XHttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub received_at: DateTime<Utc>,
}

impl fmt::Debug for XHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XHttpResponse")
            .field("status", &self.status)
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("body_length", &self.body.len())
            .field("received_at", &self.received_at)
            .finish()
    }
}

pub trait XHttpTransport: fmt::Debug + Send + Sync {
    fn send(
        &self,
        request: &XHttpRequest,
        token: &XAccessToken,
    ) -> Result<XHttpResponse, XTransportError>;
}

#[derive(Clone, Debug)]
pub struct XCurlHttpsTransport {
    pub curl_binary: String,
    pub timeout_seconds: u64,
}

impl Default for XCurlHttpsTransport {
    fn default() -> Self {
        Self {
            curl_binary: "curl".to_owned(),
            timeout_seconds: 20,
        }
    }
}

impl XCurlHttpsTransport {
    fn config_for(
        request: &XHttpRequest,
        token: &XAccessToken,
    ) -> Result<Zeroizing<String>, XTransportError> {
        let url = request.url_with_query();
        validate_https_url(&url).map_err(|_| XTransportError::InsecureUrl)?;
        let mut config = Zeroizing::new(String::new());
        let escaped_url = escape_curl_config(&url);
        let _ = writeln!(&mut *config, "url = \"{}\"", escaped_url.as_str());
        let _ = writeln!(&mut *config, "request = \"{}\"", request.method);
        let escaped_token = escape_curl_config(token.expose());
        let _ = writeln!(
            &mut *config,
            "header = \"Authorization: Bearer {}\"",
            escaped_token.as_str()
        );
        for (name, value) in &request.headers {
            let escaped_name = escape_curl_config(name);
            let escaped_value = escape_curl_config(value);
            let _ = writeln!(
                &mut *config,
                "header = \"{}: {}\"",
                escaped_name.as_str(),
                escaped_value.as_str()
            );
        }
        Ok(config)
    }
}

impl XHttpTransport for XCurlHttpsTransport {
    fn send(
        &self,
        request: &XHttpRequest,
        token: &XAccessToken,
    ) -> Result<XHttpResponse, XTransportError> {
        let config = Self::config_for(request, token)?;
        let mut child = Command::new(&self.curl_binary)
            .args([
                "--silent",
                "--show-error",
                "--location",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--max-time",
                &self.timeout_seconds.to_string(),
                "--dump-header",
                "/dev/stderr",
                "--output",
                "-",
                "--config",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| XTransportError::Spawn)?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(config.as_bytes())
                .map_err(|_| XTransportError::Io)?;
        }
        let output = child.wait_with_output().map_err(|_| XTransportError::Io)?;
        let (status, headers) = parse_curl_headers(&output.stderr)?;
        Ok(XHttpResponse {
            status,
            headers,
            body: output.stdout,
            received_at: Utc::now(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XPermissionObservation {
    pub required_scopes: BTreeSet<String>,
    pub granted_scopes: BTreeSet<String>,
    pub missing_scopes: BTreeSet<String>,
    pub review_state: XReviewState,
}

impl XPermissionObservation {
    fn for_scope(scope: &ConnectorScope, required: BTreeSet<String>) -> Self {
        let missing_scopes = required
            .difference(scope.scopes())
            .cloned()
            .collect::<BTreeSet<_>>();
        Self {
            required_scopes: required,
            granted_scopes: scope.scopes().clone(),
            missing_scopes,
            review_state: XReviewState::Unknown,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XRequestEvidence {
    pub method: String,
    pub path: String,
    pub query_digest: String,
    pub status: u16,
    pub provider_request_id: Option<String>,
    pub response_digest: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XRateLimit {
    pub limit: Option<u64>,
    pub remaining: Option<u64>,
    pub reset_at: Option<DateTime<Utc>>,
    pub retry_after_seconds: Option<u64>,
    pub evidence_headers: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XRetryReceipt {
    pub attempts: u8,
    pub retried: bool,
    pub last_retry_after_seconds: Option<u64>,
    pub exhausted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XAttribution {
    pub model: String,
    pub windows: Vec<String>,
    pub parameters: BTreeMap<String, String>,
    pub causal_status: XCausalStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XClassification {
    pub kind: XInsightTargetKind,
    pub attribution: XAttribution,
    pub review_state: XReviewState,
    pub provenance: ProviderProvenanceClass,
    pub causal_status: XCausalStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum XMetricValue {
    String(String),
    Integer(i64),
    Decimal(String),
    Boolean(bool),
    Null,
    Digest(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XInsightRecord {
    pub kind: XInsightTargetKind,
    pub external_id: String,
    pub period: Option<String>,
    pub dimensions: BTreeMap<String, String>,
    pub metrics: BTreeMap<String, XMetricValue>,
    pub provider_fields_digest: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XFreshnessReceipt {
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub ttl_seconds: i64,
    pub fresh_at_observation: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XQuotaReceipt {
    pub configured_limit: u64,
    pub used_before: u64,
    pub used_after: u64,
    pub rate_remaining_before: u64,
    pub rate_remaining_after: u64,
    pub provider_rate_limit: XRateLimit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XCostReceipt {
    pub configured_limit_minor: i64,
    pub charged_minor: i64,
    pub used_before_minor: i64,
    pub used_after_minor: i64,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XPaginationCursor {
    scope_digest: String,
    request_digest: String,
    sequence: u64,
    pagination_token: Option<String>,
    token_digest: String,
    complete: bool,
}

impl fmt::Debug for XPaginationCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XPaginationCursor")
            .field("scope_digest", &self.scope_digest)
            .field("request_digest", &self.request_digest)
            .field("sequence", &self.sequence)
            .field("token_digest", &self.token_digest)
            .field("complete", &self.complete)
            .finish_non_exhaustive()
    }
}

impl XPaginationCursor {
    fn new(
        scope: &XInsightScope,
        connector_scope: &ConnectorScope,
        request_digest: &str,
        sequence: u64,
        pagination_token: Option<String>,
        complete: bool,
    ) -> Self {
        let token_digest = cursor_token_digest(request_digest, pagination_token.as_deref());
        Self {
            scope_digest: scope.digest(connector_scope),
            request_digest: request_digest.to_owned(),
            sequence,
            pagination_token,
            token_digest,
            complete,
        }
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn pagination_token(&self) -> Option<&str> {
        self.pagination_token.as_deref()
    }

    pub fn token_digest(&self) -> &str {
        &self.token_digest
    }

    pub const fn complete(&self) -> bool {
        self.complete
    }

    fn validate(
        &self,
        scope: &XInsightScope,
        connector_scope: &ConnectorScope,
        request_digest: &str,
    ) -> Result<(), XConnectorError> {
        if self.scope_digest != scope.digest(connector_scope)
            || self.request_digest != request_digest
            || self.sequence == 0
            || self.token_digest
                != cursor_token_digest(request_digest, self.pagination_token.as_deref())
            || self.complete && self.pagination_token.is_some()
        {
            return Err(XConnectorError::CursorMismatch);
        }
        Ok(())
    }

    fn digest(&self) -> String {
        digest_serializable(self).expect("cursor serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XCursorReceipt {
    pub sequence: u64,
    pub current_digest: Option<String>,
    pub next_digest: Option<String>,
    pub durable_checkpoint_digest: String,
    pub durable_cursor: XPaginationCursor,
    pub complete: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XDigestReceipt {
    pub request_digest: String,
    pub response_digest: String,
    pub content_digest: String,
    pub observation_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XInsightObservation {
    pub schema_version: String,
    pub observation_id: String,
    pub mission_id: String,
    pub scope: XInsightScope,
    pub connector_scope_digest: String,
    pub target: XInsightTarget,
    pub requested_at: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    pub source: XRequestEvidence,
    pub records: Vec<XInsightRecord>,
    pub permission: XPermissionObservation,
    pub rate_limit: XRateLimit,
    pub retry: XRetryReceipt,
    pub freshness: XFreshnessReceipt,
    pub quota: XQuotaReceipt,
    pub cost: XCostReceipt,
    pub cursor: XCursorReceipt,
    pub classification: XClassification,
    pub digests: XDigestReceipt,
    pub provenance: ProviderProvenanceClass,
    pub causal_status: XCausalStatus,
}

impl XInsightObservation {
    pub fn validate(&self) -> Result<(), XConnectorError> {
        self.scope.validate(None)?;
        self.scope.validate_target(&self.target)?;
        validate_mission_id(&self.mission_id)?;
        let required_scopes = XInsightScope::required_scopes();
        if self.schema_version != X_INSIGHT_READ_SCHEMA
            || self.observation_id.is_empty()
            || !is_digest(&self.connector_scope_digest)
            || !is_digest(&self.source.query_digest)
            || !is_digest(&self.source.response_digest)
            || !is_digest(&self.digests.request_digest)
            || !is_digest(&self.digests.response_digest)
            || !is_digest(&self.digests.content_digest)
            || !is_digest(&self.digests.observation_digest)
            || !is_digest(&self.cursor.durable_checkpoint_digest)
            || !is_digest(&self.cursor.durable_cursor.scope_digest)
            || !self.cursor.current_digest.as_deref().is_none_or(is_digest)
            || !self.cursor.next_digest.as_deref().is_none_or(is_digest)
            || self.source.status / 100 != 2
            || self.source.method != "GET"
            || !self.source.path.starts_with("/2/")
            || self.source.response_digest != self.digests.response_digest
            || self.freshness.valid_until <= self.freshness.observed_at
            || self.freshness.ttl_seconds <= 0
            || !self.freshness.fresh_at_observation
            || self.freshness.observed_at != self.observed_at
            || self.permission.required_scopes != required_scopes
            || !required_scopes.is_subset(&self.permission.granted_scopes)
            || self.permission.missing_scopes.iter().next().is_some()
            || self.retry.attempts == 0
            || self.retry.retried != (self.retry.attempts > 1)
            || self.quota.used_after < self.quota.used_before
            || self.cost.used_after_minor < self.cost.used_before_minor
            || self.cost.charged_minor < 0
            || self.classification.kind != self.target.kind()
            || self.classification.provenance != self.provenance
            || self.causal_status != XCausalStatus::NotClaimed
            || self.classification.causal_status != XCausalStatus::NotClaimed
            || self.classification.attribution.causal_status != XCausalStatus::NotClaimed
        {
            return Err(XConnectorError::InvalidObservation);
        }
        if self.cursor.durable_cursor.request_digest != self.digests.request_digest
            || self.cursor.durable_cursor.sequence != self.cursor.sequence
            || self.cursor.durable_cursor.complete() != self.cursor.complete
            || self.cursor.durable_cursor.digest() != self.cursor.durable_checkpoint_digest
        {
            return Err(XConnectorError::InvalidObservation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XProbeRequest {
    pub scope: ConnectorScope,
    pub insight_scope: XInsightScope,
    pub secret_reference: SecretReference,
    pub lease: CredentialLease,
    pub requested_at: DateTime<Utc>,
    pub provenance: ProviderProvenanceClass,
}

impl XProbeRequest {
    fn validate(&self) -> Result<(), XConnectorError> {
        self.insight_scope.validate(Some(&self.scope))?;
        if self.secret_reference.scope() != &self.scope
            || self.lease.scope() != &self.scope
            || self.lease.adapter().adapter_id() != X_ADAPTER_ID
            || self.lease.adapter().adapter_version() != X_ADAPTER_VERSION
        {
            return Err(XConnectorError::CredentialLeaseInvalid);
        }
        self.lease
            .validate(&self.secret_reference, self.requested_at)
            .map_err(|_| XConnectorError::CredentialLeaseInvalid)?;
        self.lease
            .validate(&self.secret_reference, Utc::now())
            .map_err(|_| XConnectorError::CredentialLeaseInvalid)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XInsightReadRequest {
    pub scope: ConnectorScope,
    pub insight_scope: XInsightScope,
    pub secret_reference: SecretReference,
    pub lease: CredentialLease,
    pub target: XInsightTarget,
    pub since: DateTime<Utc>,
    pub until: DateTime<Utc>,
    pub page_size: u32,
    pub cursor: Option<XPaginationCursor>,
    pub requested_at: DateTime<Utc>,
    pub provenance: ProviderProvenanceClass,
}

impl XInsightReadRequest {
    fn validate(&self) -> Result<(), XConnectorError> {
        self.insight_scope.validate(Some(&self.scope))?;
        self.insight_scope.validate_target(&self.target)?;
        if self.secret_reference.scope() != &self.scope
            || self.lease.scope() != &self.scope
            || self.lease.adapter().adapter_id() != X_ADAPTER_ID
            || self.lease.adapter().adapter_version() != X_ADAPTER_VERSION
        {
            return Err(XConnectorError::CredentialLeaseInvalid);
        }
        self.lease
            .validate(&self.secret_reference, self.requested_at)
            .map_err(|_| XConnectorError::CredentialLeaseInvalid)?;
        self.lease
            .validate(&self.secret_reference, Utc::now())
            .map_err(|_| XConnectorError::CredentialLeaseInvalid)?;
        if self.until <= self.since
            || self.until - self.since > Duration::days(30)
            || !(5..=100).contains(&self.page_size)
        {
            return Err(XConnectorError::InvalidRequest);
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate(&self.insight_scope, &self.scope, &self.request_digest())?;
            if cursor.complete() {
                return Err(XConnectorError::CursorComplete);
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn with_cursor(mut self, cursor: XPaginationCursor) -> Self {
        self.cursor = Some(cursor);
        self
    }

    fn request_digest(&self) -> String {
        digest_serializable(&(
            self.scope.digest(),
            self.insight_scope.clone(),
            self.target.clone(),
            x_timestamp(self.since),
            x_timestamp(self.until),
            self.page_size,
            "x_api_v2_user_posts",
        ))
        .expect("read request serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XProbeObservation {
    pub schema_version: String,
    pub scope: XInsightScope,
    pub connector_scope_digest: String,
    pub source: Vec<XRequestEvidence>,
    pub permission: XPermissionObservation,
    pub status: ProbeStatus,
    pub observed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub credential_reference_digest: String,
    pub credential_revision: u64,
    pub lease_revision: u64,
    pub probe_digest: String,
    pub classification: XClassification,
    pub provenance: ProviderProvenanceClass,
    pub causal_status: XCausalStatus,
}

impl XProbeObservation {
    pub fn validate(&self) -> Result<(), XConnectorError> {
        self.scope.validate(None)?;
        let required_scopes = XInsightScope::required_scopes();
        if self.schema_version != X_INSIGHT_READ_SCHEMA
            || self.source.is_empty()
            || self.status != ProbeStatus::Reachable
            || self.expires_at <= self.observed_at
            || self.expires_at - self.observed_at > Duration::seconds(120)
            || !is_digest(&self.connector_scope_digest)
            || !is_digest(&self.credential_reference_digest)
            || !is_digest(&self.probe_digest)
            || self.permission.required_scopes != required_scopes
            || !required_scopes.is_subset(&self.permission.granted_scopes)
            || self.permission.missing_scopes.iter().next().is_some()
            || self.classification.kind != XInsightTargetKind::UserAccountPosts
            || self.classification.provenance != self.provenance
            || self.source.iter().any(|evidence| {
                evidence.method != "GET"
                    || evidence.status / 100 != 2
                    || !evidence.path.starts_with("/2/")
                    || !is_digest(&evidence.query_digest)
                    || !is_digest(&evidence.response_digest)
            })
            || self.causal_status != XCausalStatus::NotClaimed
            || self.classification.causal_status != XCausalStatus::NotClaimed
        {
            return Err(XConnectorError::InvalidProbe);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XReadPolicy {
    pub freshness_ttl: Duration,
    pub cost_minor: i64,
    pub max_attempts: u8,
    pub max_retry_delay_seconds: u64,
}

impl Default for XReadPolicy {
    fn default() -> Self {
        Self {
            freshness_ttl: Duration::minutes(15),
            cost_minor: 1,
            max_attempts: 1,
            max_retry_delay_seconds: 0,
        }
    }
}

impl XReadPolicy {
    pub fn new(
        freshness_ttl: Duration,
        cost_minor: i64,
        max_attempts: u8,
        max_retry_delay_seconds: u64,
    ) -> Result<Self, XConnectorError> {
        if freshness_ttl <= Duration::zero()
            || freshness_ttl > Duration::seconds(900)
            || cost_minor < 0
            || !(1..=3).contains(&max_attempts)
            || max_retry_delay_seconds > 60
        {
            return Err(XConnectorError::InvalidPolicy);
        }
        Ok(Self {
            freshness_ttl,
            cost_minor,
            max_attempts,
            max_retry_delay_seconds,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XMount {
    pub mission_id: String,
    pub scope_digest: String,
    pub credential_reference_digest: String,
    pub credential_revision: u64,
    pub lease_revision: u64,
    pub probe_digest: String,
    pub valid_until: DateTime<Utc>,
    pub generation: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XMissionCapabilityGrant {
    pub mission_id: String,
    pub capability: XMissionCapability,
    pub provider_id: String,
    pub scope_digest: String,
    pub connection_state: XConnectionState,
    pub connected_claim: bool,
    pub probe_digest: String,
    pub granted_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XMissionInsightResult {
    pub mission_id: String,
    pub capability: XMissionCapability,
    pub observation: XInsightObservation,
    pub durable_log_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XDurableObservationLog {
    pub schema_version: String,
    pub revision: u64,
    pub entries: Vec<XInsightObservation>,
}

impl Default for XDurableObservationLog {
    fn default() -> Self {
        Self {
            schema_version: X_INSIGHT_READ_SCHEMA.to_owned(),
            revision: 0,
            entries: Vec::new(),
        }
    }
}

impl XDurableObservationLog {
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn append(&mut self, observation: XInsightObservation) -> Result<(), XConnectorError> {
        observation.validate()?;
        let page_key = page_dedupe_key(
            &observation.digests.request_digest,
            &observation.digests.content_digest,
        );
        let response_key = page_dedupe_key(
            &observation.digests.request_digest,
            &observation.digests.response_digest,
        );
        if self.entries.iter().any(|entry| {
            page_dedupe_key(&entry.digests.request_digest, &entry.digests.content_digest)
                == page_key
                || page_dedupe_key(
                    &entry.digests.request_digest,
                    &entry.digests.response_digest,
                ) == response_key
        }) {
            return Err(XConnectorError::DuplicatePage);
        }
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(XConnectorError::InvalidObservation)?;
        self.entries.push(observation);
        Ok(())
    }

    pub fn checkpoint(&self) -> Result<Vec<u8>, XConnectorError> {
        serde_json::to_vec(self).map_err(|_| XConnectorError::InvalidObservation)
    }

    pub fn from_checkpoint(bytes: &[u8]) -> Result<Self, XConnectorError> {
        let log: Self =
            serde_json::from_slice(bytes).map_err(|_| XConnectorError::InvalidObservation)?;
        if log.schema_version != X_INSIGHT_READ_SCHEMA || log.revision != log.entries.len() as u64 {
            return Err(XConnectorError::InvalidObservation);
        }
        let mut page_keys = BTreeSet::new();
        let mut response_keys = BTreeSet::new();
        for entry in &log.entries {
            entry.validate()?;
            if !page_keys.insert(page_dedupe_key(
                &entry.digests.request_digest,
                &entry.digests.content_digest,
            )) || !response_keys.insert(page_dedupe_key(
                &entry.digests.request_digest,
                &entry.digests.response_digest,
            )) {
                return Err(XConnectorError::DuplicatePage);
            }
        }
        Ok(log)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum XConnectorError {
    #[error("X connector scope is invalid")]
    InvalidScope,
    #[error("X connector request is invalid")]
    InvalidRequest,
    #[error("X credential is unavailable")]
    CredentialUnavailable,
    #[error("X credential lease is invalid")]
    CredentialLeaseInvalid,
    #[error("X provider permission is missing")]
    MissingPermission,
    #[error("X provider scope does not match")]
    ScopeMismatch,
    #[error("X provider authorization was rejected ({status})")]
    Unauthorized { status: u16 },
    #[error("X provider permission was denied")]
    PermissionDenied,
    #[error("X provider rate limit was reached ({status})")]
    RateLimited { status: u16, rate_limit: XRateLimit },
    #[error("X provider is unavailable ({status})")]
    ProviderUnavailable { status: u16 },
    #[error("X provider response is invalid ({status})")]
    InvalidProviderResponse { status: u16 },
    #[error("X provider response could not be parsed ({status})")]
    ResponseParse { status: u16 },
    #[error("X transport failed: {0}")]
    Transport(XTransportError),
    #[error("X cursor does not match scope or query")]
    CursorMismatch,
    #[error("X cursor is complete")]
    CursorComplete,
    #[error("X provider returned a duplicate page")]
    DuplicatePage,
    #[error("X provider pagination cursor rolled back")]
    CursorRollback,
    #[error("X observation is invalid")]
    InvalidObservation,
    #[error("X probe observation is invalid")]
    InvalidProbe,
    #[error("X read policy is invalid")]
    InvalidPolicy,
    #[error("X read budget rejected the request: {0}")]
    Budget(ConnectorError),
    #[error("X connection is not mounted")]
    NotMounted,
    #[error("X probe is stale")]
    ProbeStale,
    #[error("X connection is revoked")]
    Revoked,
    #[error("X mount refresh drifted")]
    RefreshDrift,
    #[error("X mission id is invalid")]
    InvalidMission,
    #[error("X mission does not match the mounted consumer")]
    MissionMismatch,
    #[error("X provider writes are disabled")]
    WritesDisabled,
    #[error("X credential probe is blocked by the environment: {missing:?}")]
    BlockedEnv { missing: Vec<String> },
}

pub trait XInsightProvider: fmt::Debug + Send + Sync {
    fn provider_id(&self) -> &'static str;

    fn registrations(&self) -> &'static [ProviderCapabilitySupport];

    fn probe(
        &self,
        request: &XProbeRequest,
        resolver: &dyn XCredentialResolver,
    ) -> Result<XProbeObservation, XConnectorError>;

    fn read(
        &self,
        request: &XInsightReadRequest,
        resolver: &dyn XCredentialResolver,
    ) -> Result<XProviderPage, XConnectorError>;

    fn prepare_effect(&self, _capability: &str) -> Result<(), XConnectorError> {
        Err(XConnectorError::WritesDisabled)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XProviderPage {
    pub source: XRequestEvidence,
    pub response_digest: String,
    pub records: Vec<XInsightRecord>,
    pub next_token: Option<String>,
    pub rate_limit: XRateLimit,
    pub permission: XPermissionObservation,
    pub attribution: XAttribution,
    pub classification: XClassification,
    pub observed_at: DateTime<Utc>,
}

impl XProviderPage {
    fn validate(&self, request: &XInsightReadRequest) -> Result<(), XConnectorError> {
        let required_scopes = XInsightScope::required_scopes();
        if self.source.method != "GET"
            || self.source.status / 100 != 2
            || !self.source.path.starts_with("/2/")
            || !is_digest(&self.source.query_digest)
            || self.source.response_digest != self.response_digest
            || !is_digest(&self.response_digest)
            || self.permission.required_scopes != required_scopes
            || !required_scopes.is_subset(&self.permission.granted_scopes)
            || self.permission.missing_scopes.iter().next().is_some()
            || self.classification.kind != request.target.kind()
            || self.classification.provenance != request.provenance
            || self.classification.attribution != self.attribution
            || self.attribution.causal_status != XCausalStatus::NotClaimed
            || self.classification.causal_status != XCausalStatus::NotClaimed
            || self
                .records
                .iter()
                .any(|record| record.kind != request.target.kind())
        {
            return Err(XConnectorError::InvalidProviderResponse {
                status: self.source.status,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct XApiV2Adapter {
    pub config: XApiBinding,
    pub transport: Arc<dyn XHttpTransport>,
}

impl XApiV2Adapter {
    pub fn new(
        config: XApiBinding,
        transport: Arc<dyn XHttpTransport>,
    ) -> Result<Self, XConnectorError> {
        config.validate()?;
        Ok(Self { config, transport })
    }

    fn request(&self, path: &str, query: Vec<(String, String)>) -> XHttpRequest {
        let base = self.config.api_base_url.trim_end_matches('/');
        let version = self.config.api_version.trim_matches('/');
        let mut request = XHttpRequest::get(format!("{base}/{version}{path}")).with_query(query);
        request.set_header("Accept", "application/json");
        request.set_header("X-API-Version", self.config.api_version.clone());
        request
    }

    fn execute_json(
        &self,
        request: &XHttpRequest,
        token: &XAccessToken,
    ) -> Result<(serde_json::Value, XHttpResponse, XRateLimit), XConnectorError> {
        let response = self
            .transport
            .send(request, token)
            .map_err(XConnectorError::Transport)?;
        let rate_limit = parse_rate_limit(&response);
        if response.status == 401 {
            return Err(XConnectorError::Unauthorized {
                status: response.status,
            });
        }
        if response.status == 403 {
            return Err(XConnectorError::PermissionDenied);
        }
        if response.status == 429 {
            return Err(XConnectorError::RateLimited {
                status: response.status,
                rate_limit,
            });
        }
        if response.status >= 500 {
            return Err(XConnectorError::ProviderUnavailable {
                status: response.status,
            });
        }
        if !(200..300).contains(&response.status) {
            return Err(XConnectorError::InvalidProviderResponse {
                status: response.status,
            });
        }
        let value: serde_json::Value =
            serde_json::from_slice(&response.body).map_err(|_| XConnectorError::ResponseParse {
                status: response.status,
            })?;
        if value
            .get("errors")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|errors| !errors.is_empty())
            || value.get("error").is_some()
        {
            return Err(XConnectorError::InvalidProviderResponse {
                status: response.status,
            });
        }
        Ok((value, response, rate_limit))
    }

    fn validate_probe_identity(
        value: &serde_json::Value,
        expected: &str,
    ) -> Result<(), XConnectorError> {
        let observed = value
            .get("data")
            .and_then(|data| data.get("id"))
            .and_then(serde_json::Value::as_str)
            .ok_or(XConnectorError::InvalidProviderResponse { status: 200 })?;
        if observed != expected {
            return Err(XConnectorError::ScopeMismatch);
        }
        Ok(())
    }

    fn read_request(&self, request: &XInsightReadRequest) -> XHttpRequest {
        let mut query = vec![
            (
                "tweet.fields".to_owned(),
                "author_id,created_at,public_metrics,non_public_metrics,organic_metrics,promoted_metrics"
                    .to_owned(),
            ),
            ("max_results".to_owned(), request.page_size.to_string()),
            ("start_time".to_owned(), x_timestamp(request.since)),
            ("end_time".to_owned(), x_timestamp(request.until)),
        ];
        if let Some(cursor) = &request.cursor
            && let Some(token) = cursor.pagination_token()
        {
            query.push(("pagination_token".to_owned(), token.to_owned()));
        }
        self.request(
            &format!("/users/{}/tweets", request.target.account_id()),
            query,
        )
    }
}

impl XInsightProvider for XApiV2Adapter {
    fn provider_id(&self) -> &'static str {
        "x"
    }

    fn registrations(&self) -> &'static [ProviderCapabilitySupport] {
        X_REGISTRATIONS
    }

    fn probe(
        &self,
        request: &XProbeRequest,
        resolver: &dyn XCredentialResolver,
    ) -> Result<XProbeObservation, XConnectorError> {
        request.validate()?;
        let permission =
            XPermissionObservation::for_scope(&request.scope, XInsightScope::required_scopes());
        if !permission.missing_scopes.is_empty() {
            return Err(XConnectorError::MissingPermission);
        }
        let token = resolver.resolve(&request.secret_reference)?;
        let http_request = self.request("/users/me", Vec::new());
        let (value, response, _rate_limit) = self.execute_json(&http_request, &token)?;
        Self::validate_probe_identity(&value, request.insight_scope.user_id())?;
        let source = vec![request_evidence(&http_request, &response)];
        let observed_at = response.received_at;
        let expires_at = observed_at
            .checked_add_signed(Duration::seconds(120))
            .ok_or(XConnectorError::InvalidProbe)?;
        let classification = XClassification {
            kind: XInsightTargetKind::UserAccountPosts,
            attribution: XAttribution {
                model: "x_api_v2_authenticated_user_account".to_owned(),
                windows: Vec::new(),
                parameters: BTreeMap::from([
                    ("api_version".to_owned(), X_API_VERSION.to_owned()),
                    ("account_scope".to_owned(), "authenticated_user".to_owned()),
                ]),
                causal_status: XCausalStatus::NotClaimed,
            },
            review_state: permission.review_state,
            provenance: request.provenance,
            causal_status: XCausalStatus::NotClaimed,
        };
        let probe_digest = digest_serializable(&(&request.insight_scope, &source, observed_at))?;
        let observation = XProbeObservation {
            schema_version: X_INSIGHT_READ_SCHEMA.to_owned(),
            scope: request.insight_scope.clone(),
            connector_scope_digest: request.scope.digest(),
            source,
            permission,
            status: ProbeStatus::Reachable,
            observed_at,
            expires_at,
            credential_reference_digest: digest_bytes(
                request.secret_reference.reference_id().as_bytes(),
            ),
            credential_revision: request.secret_reference.credential_revision(),
            lease_revision: request.lease.lease_revision(),
            probe_digest,
            classification,
            provenance: request.provenance,
            causal_status: XCausalStatus::NotClaimed,
        };
        observation.validate()?;
        Ok(observation)
    }

    fn read(
        &self,
        request: &XInsightReadRequest,
        resolver: &dyn XCredentialResolver,
    ) -> Result<XProviderPage, XConnectorError> {
        request.validate()?;
        let permission =
            XPermissionObservation::for_scope(&request.scope, XInsightScope::required_scopes());
        if !permission.missing_scopes.is_empty() {
            return Err(XConnectorError::MissingPermission);
        }
        let token = resolver.resolve(&request.secret_reference)?;
        let http_request = self.read_request(request);
        let (value, response, rate_limit) = self.execute_json(&http_request, &token)?;
        let response_digest = digest_bytes(&response.body);
        let records = parse_records(&value, request.target.kind())?;
        let next_token = value
            .get("meta")
            .and_then(|meta| meta.get("next_token"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let windows = vec![format!(
            "{}..{}",
            x_timestamp(request.since),
            x_timestamp(request.until)
        )];
        let attribution = XAttribution {
            model: "x_api_v2_user_posts_metrics".to_owned(),
            windows,
            parameters: BTreeMap::from([
                ("activity".to_owned(), "provider_native".to_owned()),
                (
                    "metric_contexts".to_owned(),
                    "public,non_public,organic,promoted".to_owned(),
                ),
                (
                    "promoted_split".to_owned(),
                    "provider_promoted_metrics_only".to_owned(),
                ),
                (
                    "organization_scope".to_owned(),
                    "mission_bound_only".to_owned(),
                ),
            ]),
            causal_status: XCausalStatus::NotClaimed,
        };
        let classification = XClassification {
            kind: request.target.kind(),
            attribution: attribution.clone(),
            review_state: permission.review_state,
            provenance: request.provenance,
            causal_status: XCausalStatus::NotClaimed,
        };
        Ok(XProviderPage {
            source: request_evidence(&http_request, &response),
            response_digest,
            records,
            next_token,
            rate_limit,
            permission,
            attribution,
            classification,
            observed_at: response.received_at,
        })
    }
}

pub struct XInsightReadService {
    provider: Arc<dyn XInsightProvider>,
    budget: DispatchBudget,
    policy: XReadPolicy,
    state: XConnectionState,
    mount: Option<XMount>,
    cursor: Option<XPaginationCursor>,
    observation_log: XDurableObservationLog,
    seen_page_digests: BTreeSet<String>,
    seen_cursor_tokens: BTreeSet<String>,
}

impl fmt::Debug for XInsightReadService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XInsightReadService")
            .field("provider", &self.provider.provider_id())
            .field("state", &self.state)
            .field("mount", &self.mount)
            .field(
                "cursor",
                &self.cursor.as_ref().map(XPaginationCursor::digest),
            )
            .field("observation_log_revision", &self.observation_log.revision())
            .finish_non_exhaustive()
    }
}

impl XInsightReadService {
    pub fn new(
        provider: Arc<dyn XInsightProvider>,
        budget: DispatchBudget,
        policy: XReadPolicy,
    ) -> Result<Self, XConnectorError> {
        if provider.provider_id() != "x" || !provider.registrations().is_empty() {
            return Err(XConnectorError::InvalidRequest);
        }
        Ok(Self {
            provider,
            budget,
            policy,
            state: XConnectionState::Unmounted,
            mount: None,
            cursor: None,
            observation_log: XDurableObservationLog::default(),
            seen_page_digests: BTreeSet::new(),
            seen_cursor_tokens: BTreeSet::new(),
        })
    }

    pub fn state(&self) -> XConnectionState {
        self.state
    }

    pub fn mount(&self) -> Option<&XMount> {
        self.mount.as_ref()
    }

    pub fn provider(&self) -> &dyn XInsightProvider {
        self.provider.as_ref()
    }

    pub fn cursor(&self) -> Option<&XPaginationCursor> {
        self.cursor.as_ref()
    }

    pub fn observation_log(&self) -> &XDurableObservationLog {
        &self.observation_log
    }

    pub fn observation_log_checkpoint(&self) -> Result<Vec<u8>, XConnectorError> {
        self.observation_log.checkpoint()
    }

    pub fn restore_observation_log(&mut self, bytes: &[u8]) -> Result<(), XConnectorError> {
        let log = XDurableObservationLog::from_checkpoint(bytes)?;
        self.cursor = log
            .entries
            .last()
            .map(|entry| entry.cursor.durable_cursor.clone());
        self.seen_page_digests = log
            .entries
            .iter()
            .map(|entry| {
                page_dedupe_key(&entry.digests.request_digest, &entry.digests.content_digest)
            })
            .collect();
        self.seen_cursor_tokens = log
            .entries
            .iter()
            .map(|entry| entry.cursor.durable_cursor.token_digest.clone())
            .collect();
        self.observation_log = log;
        Ok(())
    }

    pub fn probe_and_mount(
        &mut self,
        mission_id: &str,
        request: &XProbeRequest,
        resolver: &dyn XCredentialResolver,
    ) -> Result<XMissionCapabilityGrant, XConnectorError> {
        validate_mission_id(mission_id)?;
        if self.state == XConnectionState::Revoked {
            return Err(XConnectorError::Revoked);
        }
        let observation = self.provider.probe(request, resolver)?;
        self.mount_from_probe(mission_id, request, &observation)?;
        Ok(XMissionCapabilityGrant {
            mission_id: mission_id.to_owned(),
            capability: XMissionCapability::PaidSocialInsightRead,
            provider_id: "x".to_owned(),
            scope_digest: observation.connector_scope_digest,
            connection_state: XConnectionState::Mounted,
            connected_claim: false,
            probe_digest: observation.probe_digest,
            granted_at: observation.observed_at,
        })
    }

    pub fn refresh_mount(
        &mut self,
        request: &XProbeRequest,
        observation: &XProbeObservation,
    ) -> Result<(), XConnectorError> {
        request.validate()?;
        observation.validate()?;
        let mount = self.mount.as_mut().ok_or(XConnectorError::NotMounted)?;
        if self.state != XConnectionState::Mounted
            || mount.scope_digest != request.scope.digest()
            || mount.credential_reference_digest
                != digest_bytes(request.secret_reference.reference_id().as_bytes())
            || mount.credential_revision != request.secret_reference.credential_revision()
            || mount.lease_revision != request.lease.lease_revision()
            || observation.scope != request.insight_scope
            || observation.connector_scope_digest != request.scope.digest()
            || observation.credential_revision != request.secret_reference.credential_revision()
            || observation.lease_revision != request.lease.lease_revision()
        {
            return Err(XConnectorError::RefreshDrift);
        }
        mount.probe_digest.clone_from(&observation.probe_digest);
        mount.valid_until = observation.expires_at;
        mount.generation = mount
            .generation
            .checked_add(1)
            .ok_or(XConnectorError::RefreshDrift)?;
        Ok(())
    }

    pub fn unmount(&mut self) {
        self.clear_session_state();
        if self.state != XConnectionState::Revoked {
            self.state = XConnectionState::Unmounted;
        }
    }

    pub fn revoke(&mut self) {
        self.clear_session_state();
        self.state = XConnectionState::Revoked;
    }

    #[allow(clippy::too_many_lines)]
    pub fn read(
        &mut self,
        mission_id: &str,
        request: &XInsightReadRequest,
        resolver: &dyn XCredentialResolver,
    ) -> Result<XInsightObservation, XConnectorError> {
        validate_mission_id(mission_id)?;
        request.validate()?;
        self.ensure_mount(mission_id, request)?;
        let request_digest = request.request_digest();
        if let Some(cursor) = &self.cursor {
            cursor.validate(&request.insight_scope, &request.scope, &request_digest)?;
            if cursor.complete() {
                return Err(XConnectorError::CursorComplete);
            }
            if request.cursor.as_ref().is_some_and(|value| value != cursor) {
                return Err(XConnectorError::CursorMismatch);
            }
        }
        let mut provider_request = request.clone();
        if provider_request.cursor.is_none() {
            provider_request.cursor.clone_from(&self.cursor);
        }
        let before = BudgetSnapshot::capture(&self.budget);
        self.budget
            .admit(request.requested_at, self.policy.cost_minor)
            .map_err(XConnectorError::Budget)?;
        let after = BudgetSnapshot::capture(&self.budget);

        let mut attempts = 0_u8;
        let mut last_retry_after = None;
        let page = loop {
            attempts = attempts.saturating_add(1);
            match self.provider.read(&provider_request, resolver) {
                Ok(page) => break page,
                Err(XConnectorError::RateLimited { rate_limit, .. })
                    if attempts < self.policy.max_attempts
                        && retry_delay(&rate_limit, request.requested_at).is_some_and(
                            |seconds| seconds <= self.policy.max_retry_delay_seconds,
                        ) =>
                {
                    last_retry_after = retry_delay(&rate_limit, request.requested_at);
                    if let Some(seconds) = last_retry_after
                        && seconds > 0
                    {
                        thread::sleep(std::time::Duration::from_secs(seconds));
                    }
                }
                Err(
                    error @ (XConnectorError::Unauthorized { .. }
                    | XConnectorError::PermissionDenied),
                ) => {
                    self.state = XConnectionState::Stale;
                    return Err(error);
                }
                Err(XConnectorError::Revoked) => {
                    self.state = XConnectionState::Revoked;
                    self.clear_session_state();
                    return Err(XConnectorError::Revoked);
                }
                Err(error) => return Err(error),
            }
        };
        page.validate(request)?;
        let sequence = match provider_request
            .cursor
            .as_ref()
            .map(|cursor| cursor.sequence.checked_add(1))
        {
            None => 1,
            Some(Some(sequence)) => sequence,
            Some(None) => return Err(XConnectorError::InvalidObservation),
        };
        let current_token = provider_request
            .cursor
            .as_ref()
            .and_then(|cursor| cursor.pagination_token());
        if current_token.is_some() && page.next_token.as_deref() == current_token {
            return Err(XConnectorError::CursorRollback);
        }
        let next_cursor = XPaginationCursor::new(
            &request.insight_scope,
            &request.scope,
            &request_digest,
            sequence,
            page.next_token.clone(),
            page.next_token.is_none(),
        );
        if !next_cursor.complete() && self.seen_cursor_tokens.contains(next_cursor.token_digest()) {
            return Err(XConnectorError::CursorRollback);
        }
        let content_digest = digest_serializable(&page.records)?;
        let page_key = page_dedupe_key(&request_digest, &content_digest);
        if self.seen_page_digests.contains(&page_key) {
            return Err(XConnectorError::DuplicatePage);
        }
        let checkpoint_digest = next_cursor.digest();
        let valid_until = page
            .observed_at
            .checked_add_signed(self.policy.freshness_ttl)
            .ok_or(XConnectorError::InvalidObservation)?;
        FreshnessWindow::new(page.observed_at, valid_until, sequence)
            .map_err(|_| XConnectorError::InvalidObservation)?
            .validate_at(page.observed_at)
            .map_err(|_| XConnectorError::InvalidObservation)?;
        let current_digest = provider_request
            .cursor
            .as_ref()
            .map(XPaginationCursor::digest);
        let observation_digest = digest_serializable(&(
            &request.scope,
            &request.insight_scope,
            &request.target,
            &page.source,
            &content_digest,
            page.observed_at,
            &checkpoint_digest,
        ))?;
        let observation = XInsightObservation {
            schema_version: X_INSIGHT_READ_SCHEMA.to_owned(),
            observation_id: format!(
                "x-insight-observation-{}",
                self.observation_log.revision() + 1
            ),
            mission_id: mission_id.to_owned(),
            scope: request.insight_scope.clone(),
            connector_scope_digest: request.scope.digest(),
            target: request.target.clone(),
            requested_at: request.requested_at,
            observed_at: page.observed_at,
            source: page.source.clone(),
            records: page.records.clone(),
            permission: page.permission.clone(),
            rate_limit: page.rate_limit.clone(),
            retry: XRetryReceipt {
                attempts,
                retried: attempts > 1,
                last_retry_after_seconds: last_retry_after,
                exhausted: attempts >= self.policy.max_attempts && attempts > 1,
            },
            freshness: XFreshnessReceipt {
                observed_at: page.observed_at,
                valid_until,
                ttl_seconds: self.policy.freshness_ttl.num_seconds(),
                fresh_at_observation: true,
            },
            quota: XQuotaReceipt {
                configured_limit: after.quota_limit,
                used_before: before.quota_used,
                used_after: after.quota_used,
                rate_remaining_before: before.rate_remaining,
                rate_remaining_after: after.rate_remaining,
                provider_rate_limit: page.rate_limit.clone(),
            },
            cost: XCostReceipt {
                configured_limit_minor: after.cost_limit_minor,
                charged_minor: after.cost_used_minor - before.cost_used_minor,
                used_before_minor: before.cost_used_minor,
                used_after_minor: after.cost_used_minor,
            },
            cursor: XCursorReceipt {
                sequence,
                current_digest,
                next_digest: Some(checkpoint_digest.clone()),
                durable_checkpoint_digest: checkpoint_digest,
                durable_cursor: next_cursor.clone(),
                complete: next_cursor.complete(),
            },
            classification: page.classification,
            digests: XDigestReceipt {
                request_digest: request_digest.clone(),
                response_digest: page.response_digest,
                content_digest,
                observation_digest,
            },
            provenance: request.provenance,
            causal_status: XCausalStatus::NotClaimed,
        };
        observation.validate()?;
        self.observation_log.append(observation.clone())?;
        self.seen_page_digests.insert(page_key);
        self.seen_cursor_tokens
            .insert(observation.cursor.durable_cursor.token_digest.clone());
        self.cursor = Some(next_cursor);
        Ok(observation)
    }

    fn mount_from_probe(
        &mut self,
        mission_id: &str,
        request: &XProbeRequest,
        observation: &XProbeObservation,
    ) -> Result<(), XConnectorError> {
        observation.validate()?;
        if self.observation_log.entries.iter().any(|entry| {
            entry.mission_id != mission_id
                || entry.scope != request.insight_scope
                || entry.connector_scope_digest != request.scope.digest()
        }) {
            return Err(XConnectorError::RefreshDrift);
        }
        if observation.scope != request.insight_scope
            || observation.connector_scope_digest != request.scope.digest()
            || observation.credential_revision != request.secret_reference.credential_revision()
            || observation.lease_revision != request.lease.lease_revision()
        {
            return Err(XConnectorError::RefreshDrift);
        }
        self.mount = Some(XMount {
            mission_id: mission_id.to_owned(),
            scope_digest: request.scope.digest(),
            credential_reference_digest: digest_bytes(
                request.secret_reference.reference_id().as_bytes(),
            ),
            credential_revision: request.secret_reference.credential_revision(),
            lease_revision: request.lease.lease_revision(),
            probe_digest: observation.probe_digest.clone(),
            valid_until: observation.expires_at,
            generation: 1,
        });
        self.state = XConnectionState::Mounted;
        Ok(())
    }

    fn ensure_mount(
        &mut self,
        mission_id: &str,
        request: &XInsightReadRequest,
    ) -> Result<(), XConnectorError> {
        if self.state == XConnectionState::Revoked {
            return Err(XConnectorError::Revoked);
        }
        if self.state == XConnectionState::Stale {
            return Err(XConnectorError::ProbeStale);
        }
        let mount = self.mount.as_ref().ok_or(XConnectorError::NotMounted)?;
        if self.state != XConnectionState::Mounted
            || mount.mission_id != mission_id
            || mount.scope_digest != request.scope.digest()
            || mount.credential_reference_digest
                != digest_bytes(request.secret_reference.reference_id().as_bytes())
            || mount.credential_revision != request.secret_reference.credential_revision()
            || mount.lease_revision != request.lease.lease_revision()
        {
            return Err(XConnectorError::RefreshDrift);
        }
        if request.requested_at >= mount.valid_until {
            self.state = XConnectionState::Stale;
            return Err(XConnectorError::ProbeStale);
        }
        Ok(())
    }

    fn clear_session_state(&mut self) {
        self.mount = None;
        self.cursor = None;
        self.seen_page_digests.clear();
        self.seen_cursor_tokens.clear();
    }
}

#[derive(Debug)]
pub struct MissionXInsightConsumer {
    service: XInsightReadService,
    capability: Option<XMissionCapabilityGrant>,
}

impl MissionXInsightConsumer {
    pub fn new(service: XInsightReadService) -> Self {
        Self {
            service,
            capability: None,
        }
    }

    pub fn service(&self) -> &XInsightReadService {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut XInsightReadService {
        &mut self.service
    }

    pub fn capability(&self) -> Option<&XMissionCapabilityGrant> {
        self.capability.as_ref()
    }

    pub fn attach(
        &mut self,
        mission_id: &str,
        request: &XProbeRequest,
        resolver: &dyn XCredentialResolver,
    ) -> Result<XMissionCapabilityGrant, XConnectorError> {
        let grant = self
            .service
            .probe_and_mount(mission_id, request, resolver)?;
        self.capability = Some(grant.clone());
        Ok(grant)
    }

    pub fn read(
        &mut self,
        mission_id: &str,
        request: &XInsightReadRequest,
        resolver: &dyn XCredentialResolver,
    ) -> Result<XMissionInsightResult, XConnectorError> {
        let grant = self
            .capability
            .as_ref()
            .ok_or(XConnectorError::NotMounted)?;
        if grant.mission_id != mission_id {
            return Err(XConnectorError::MissionMismatch);
        }
        if grant.connection_state != XConnectionState::Mounted || grant.connected_claim {
            return Err(XConnectorError::MissionMismatch);
        }
        let observation = match self.service.read(mission_id, request, resolver) {
            Ok(observation) => observation,
            Err(error) => {
                if let Some(capability) = self.capability.as_mut() {
                    match self.service.state() {
                        XConnectionState::Stale => {
                            capability.connection_state = XConnectionState::Stale;
                        }
                        XConnectionState::Revoked => {
                            capability.connection_state = XConnectionState::Revoked;
                        }
                        XConnectionState::Unmounted | XConnectionState::Mounted => {}
                    }
                }
                return Err(error);
            }
        };
        Ok(XMissionInsightResult {
            mission_id: mission_id.to_owned(),
            capability: XMissionCapability::PaidSocialInsightRead,
            observation,
            durable_log_revision: self.service.observation_log.revision(),
        })
    }

    pub fn unmount(&mut self) {
        self.service.unmount();
        self.capability = None;
    }

    pub fn revoke(&mut self) {
        self.service.revoke();
        self.capability = None;
    }
}

pub fn env_gated_x_credentialed_probe(
    adapter: &XApiV2Adapter,
    request: &XProbeRequest,
) -> Result<XProbeObservation, XConnectorError> {
    let mut missing = Vec::new();
    if std::env::var(X_RUN_PROBE_ENV).ok().as_deref() != Some("1") {
        missing.push(X_RUN_PROBE_ENV.to_owned());
    }
    if std::env::var(X_ACCESS_TOKEN_ENV)
        .ok()
        .is_none_or(|value| value.trim().is_empty())
    {
        missing.push(X_ACCESS_TOKEN_ENV.to_owned());
    }
    if !missing.is_empty() {
        return Err(XConnectorError::BlockedEnv { missing });
    }
    adapter.probe(request, &EnvXCredentialResolver::default())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BudgetSnapshot {
    rate_remaining: u64,
    quota_limit: u64,
    quota_used: u64,
    cost_limit_minor: i64,
    cost_used_minor: i64,
}

impl BudgetSnapshot {
    fn capture(budget: &DispatchBudget) -> Self {
        Self {
            rate_remaining: budget.rate_limit.remaining(),
            quota_limit: budget.quota.limit(),
            quota_used: budget.quota.used(),
            cost_limit_minor: budget.cost.limit_minor(),
            cost_used_minor: budget.cost.used_minor(),
        }
    }
}

fn parse_records(
    value: &serde_json::Value,
    kind: XInsightTargetKind,
) -> Result<Vec<XInsightRecord>, XConnectorError> {
    let Some(data) = value.get("data") else {
        return Ok(Vec::new());
    };
    let array = data
        .as_array()
        .ok_or(XConnectorError::InvalidProviderResponse { status: 200 })?;
    array.iter().map(|item| parse_record(item, kind)).collect()
}

fn parse_record(
    value: &serde_json::Value,
    kind: XInsightTargetKind,
) -> Result<XInsightRecord, XConnectorError> {
    let object = value
        .as_object()
        .ok_or(XConnectorError::InvalidProviderResponse { status: 200 })?;
    let external_id = object
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or(XConnectorError::InvalidProviderResponse { status: 200 })?
        .to_owned();
    validate_x_user_id(&external_id)?;
    let period = object
        .get("created_at")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let mut dimensions = BTreeMap::new();
    if let Some(author_id) = object.get("author_id").and_then(serde_json::Value::as_str) {
        dimensions.insert("author_id".to_owned(), author_id.to_owned());
    }
    let metric_fields = [
        "public_metrics",
        "non_public_metrics",
        "organic_metrics",
        "promoted_metrics",
    ];
    let mut metrics = BTreeMap::new();
    let mut provider_fields_digest = BTreeMap::new();
    for (field, field_value) in object {
        if metric_fields.contains(&field.as_str()) {
            if let Some(metric_object) = field_value.as_object() {
                for (metric_name, metric_value) in metric_object {
                    metrics.insert(
                        format!("{field}.{metric_name}"),
                        metric_value_to_typed(metric_value),
                    );
                }
            } else {
                provider_fields_digest.insert(field.clone(), digest_json(field_value));
            }
        } else if !matches!(field.as_str(), "id" | "author_id" | "created_at") {
            provider_fields_digest.insert(field.clone(), digest_json(field_value));
        }
    }
    Ok(XInsightRecord {
        kind,
        external_id,
        period,
        dimensions,
        metrics,
        provider_fields_digest,
    })
}

fn metric_value_to_typed(value: &serde_json::Value) -> XMetricValue {
    match value {
        serde_json::Value::String(value) => XMetricValue::String(value.clone()),
        serde_json::Value::Number(value) => value.as_i64().map_or_else(
            || XMetricValue::Decimal(value.to_string()),
            XMetricValue::Integer,
        ),
        serde_json::Value::Bool(value) => XMetricValue::Boolean(*value),
        serde_json::Value::Null => XMetricValue::Null,
        _ => XMetricValue::Digest(digest_json(value)),
    }
}

fn request_evidence(request: &XHttpRequest, response: &XHttpResponse) -> XRequestEvidence {
    XRequestEvidence {
        method: request.method.clone(),
        path: request.path().unwrap_or_else(|_| "/invalid".to_owned()),
        query_digest: request.query_digest(),
        status: response.status,
        provider_request_id: response
            .headers
            .get("x-request-id")
            .or_else(|| response.headers.get("x-client-request-id"))
            .cloned(),
        response_digest: digest_bytes(&response.body),
    }
}

fn parse_rate_limit(response: &XHttpResponse) -> XRateLimit {
    let header = |name: &str| response.headers.get(name).map(String::as_str);
    let mut evidence_headers = BTreeSet::new();
    let limit = header("x-rate-limit-limit").and_then(|value| {
        evidence_headers.insert("x-rate-limit-limit".to_owned());
        value.parse().ok()
    });
    let remaining = header("x-rate-limit-remaining").and_then(|value| {
        evidence_headers.insert("x-rate-limit-remaining".to_owned());
        value.parse().ok()
    });
    let reset_at = header("x-rate-limit-reset").and_then(|value| {
        evidence_headers.insert("x-rate-limit-reset".to_owned());
        value
            .parse::<i64>()
            .ok()
            .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
    });
    let retry_after_seconds = header("retry-after").and_then(|value| {
        evidence_headers.insert("retry-after".to_owned());
        value.parse().ok()
    });
    XRateLimit {
        limit,
        remaining,
        reset_at,
        retry_after_seconds,
        evidence_headers,
    }
}

fn retry_delay(rate_limit: &XRateLimit, now: DateTime<Utc>) -> Option<u64> {
    rate_limit.retry_after_seconds.or_else(|| {
        rate_limit
            .reset_at
            .and_then(|reset_at| (reset_at - now).num_seconds().try_into().ok())
    })
}

fn validate_mission_id(value: &str) -> Result<(), XConnectorError> {
    if value.is_empty()
        || value.len() > 128
        || value.chars().any(|character| {
            !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
        })
    {
        Err(XConnectorError::InvalidMission)
    } else {
        Ok(())
    }
}

fn x_timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn validate_x_user_id(value: &str) -> Result<(), XConnectorError> {
    if (1..=19).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit()) {
        Ok(())
    } else {
        Err(XConnectorError::InvalidScope)
    }
}

fn validate_scope_id(value: &str) -> Result<(), XConnectorError> {
    if !value.is_empty()
        && value.len() <= 128
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        Ok(())
    } else {
        Err(XConnectorError::InvalidScope)
    }
}

fn validate_https_url(value: &str) -> Result<(), XConnectorError> {
    let authority = value
        .strip_prefix("https://")
        .ok_or(XConnectorError::InvalidRequest)?;
    if authority.is_empty()
        || authority.contains(['?', '#', ' ', '\n', '\r', '\t'])
        || authority.ends_with('/')
    {
        return Err(XConnectorError::InvalidRequest);
    }
    Ok(())
}

fn escape_curl_config(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn parse_curl_headers(stderr: &[u8]) -> Result<(u16, BTreeMap<String, String>), XTransportError> {
    let text = String::from_utf8_lossy(stderr);
    let mut status = None;
    let mut headers = BTreeMap::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("HTTP/") {
            let code = rest
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<u16>().ok());
            if code.is_some() {
                status = code;
                headers.clear();
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    status
        .map(|value| (value, headers))
        .ok_or(XTransportError::InvalidResponse)
}

fn encode_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(&mut encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn digest_serializable<T: Serialize>(value: &T) -> Result<String, XConnectorError> {
    serde_json::to_vec(value)
        .map(|bytes| digest_bytes(&bytes))
        .map_err(|_| XConnectorError::InvalidObservation)
}

fn digest_material<const N: usize>(parts: [String; N]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.len().to_string().as_bytes());
        digest.update(b":");
        digest.update(part.as_bytes());
        digest.update(b"|");
    }
    hex_encode(&digest.finalize())
}

fn cursor_token_digest(request_digest: &str, pagination_token: Option<&str>) -> String {
    digest_material([
        request_digest.to_owned(),
        pagination_token.unwrap_or_default().to_owned(),
    ])
}

fn page_dedupe_key(request_digest: &str, page_digest: &str) -> String {
    digest_material([request_digest.to_owned(), page_digest.to_owned()])
}

fn digest_bytes(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn digest_json(value: &serde_json::Value) -> String {
    digest_bytes(value.to_string().as_bytes())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConnectorAuth, ProviderAdapterIdentity};
    use std::collections::VecDeque;
    use std::io::Read as _;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::Mutex;
    use std::thread::JoinHandle;
    use std::time::Duration as IoDuration;

    #[derive(Debug)]
    struct MockTransport {
        responses: Mutex<VecDeque<Result<XHttpResponse, XTransportError>>>,
        requests: Mutex<Vec<XHttpRequest>>,
        token_digests: Mutex<Vec<String>>,
    }

    impl MockTransport {
        fn new(responses: impl IntoIterator<Item = XHttpResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().map(Ok).collect()),
                requests: Mutex::new(Vec::new()),
                token_digests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<XHttpRequest> {
            self.requests.lock().expect("requests").clone()
        }
    }

    impl XHttpTransport for MockTransport {
        fn send(
            &self,
            request: &XHttpRequest,
            token: &XAccessToken,
        ) -> Result<XHttpResponse, XTransportError> {
            self.requests
                .lock()
                .expect("requests")
                .push(request.clone());
            self.token_digests
                .lock()
                .expect("token digests")
                .push(token.digest());
            self.responses
                .lock()
                .expect("responses")
                .pop_front()
                .unwrap_or(Err(XTransportError::InvalidResponse))
        }
    }

    #[derive(Debug)]
    struct LoopbackHttpTransport {
        address: SocketAddr,
    }

    impl XHttpTransport for LoopbackHttpTransport {
        fn send(
            &self,
            request: &XHttpRequest,
            token: &XAccessToken,
        ) -> Result<XHttpResponse, XTransportError> {
            let target = loopback_request_target(request)?;
            let mut stream = TcpStream::connect(self.address).map_err(|_| XTransportError::Io)?;
            stream
                .set_read_timeout(Some(IoDuration::from_secs(2)))
                .map_err(|_| XTransportError::Io)?;
            let mut wire = format!(
                "{} {} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\n",
                request.method,
                target,
                token.expose()
            );
            for (name, value) in &request.headers {
                let _ = writeln!(&mut wire, "{name}: {value}");
            }
            wire.push_str("Connection: close\r\n\r\n");
            stream
                .write_all(wire.as_bytes())
                .map_err(|_| XTransportError::Io)?;
            let mut bytes = Vec::new();
            stream
                .read_to_end(&mut bytes)
                .map_err(|_| XTransportError::Io)?;
            parse_loopback_response(&bytes)
        }
    }

    #[derive(Default)]
    struct LoopbackCapture {
        request_lines: Vec<String>,
        authenticated_requests: usize,
    }

    fn loopback_request_target(request: &XHttpRequest) -> Result<String, XTransportError> {
        let url = request.url_with_query();
        let authority = url
            .split_once("://")
            .map(|(_, rest)| rest)
            .ok_or(XTransportError::InvalidResponse)?;
        let slash = authority
            .find('/')
            .ok_or(XTransportError::InvalidResponse)?;
        Ok(authority[slash..].to_owned())
    }

    fn read_loopback_headers(stream: &mut TcpStream) -> Result<Vec<u8>, XTransportError> {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let count = stream.read(&mut buffer).map_err(|_| XTransportError::Io)?;
            if count == 0 {
                return Err(XTransportError::InvalidResponse);
            }
            bytes.extend_from_slice(&buffer[..count]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                return Ok(bytes);
            }
            if bytes.len() > 16 * 1024 {
                return Err(XTransportError::InvalidResponse);
            }
        }
    }

    fn parse_loopback_response(bytes: &[u8]) -> Result<XHttpResponse, XTransportError> {
        let separator = bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or(XTransportError::InvalidResponse)?;
        let header_end = separator + 4;
        let header_text = String::from_utf8_lossy(&bytes[..separator]);
        let mut lines = header_text.lines();
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or(XTransportError::InvalidResponse)?;
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        Ok(XHttpResponse {
            status,
            headers,
            body: bytes[header_end..].to_vec(),
            received_at: Utc::now(),
        })
    }

    fn loopback_server() -> (SocketAddr, Arc<Mutex<LoopbackCapture>>, JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
        let address = listener.local_addr().expect("loopback address");
        let capture = Arc::new(Mutex::new(LoopbackCapture::default()));
        let captured = Arc::clone(&capture);
        let server = std::thread::spawn(move || {
            for index in 0..3 {
                let (mut stream, _) = listener.accept().expect("loopback connection");
                let request = read_loopback_headers(&mut stream).expect("loopback request");
                let request_text = String::from_utf8_lossy(&request);
                let request_line = request_text.lines().next().unwrap_or_default();
                assert!(request_line.starts_with("GET "));
                assert!(request_text.contains("Authorization: Bearer x-test-access-token"));
                {
                    let mut capture = captured.lock().expect("loopback capture");
                    capture.request_lines.push(request_line.to_owned());
                    capture.authenticated_requests += 1;
                }
                match index {
                    0 => assert_eq!(request_line, "GET /2/users/me HTTP/1.1"),
                    1 => {
                        assert!(request_line.contains("GET /2/users/1234567890/tweets?"));
                        assert!(!request_line.contains("pagination_token="));
                    }
                    2 => assert!(request_line.contains("pagination_token=next-token-1")),
                    _ => unreachable!(),
                }
                let (body, request_id, remaining) = match index {
                    0 => (r#"{"data":{"id":"1234567890"}}"#, "loopback-probe", "900"),
                    1 => (
                        r#"{"data":[{"id":"111","author_id":"1234567890","public_metrics":{"like_count":7}}],"meta":{"next_token":"next-token-1"}}"#,
                        "loopback-page-1",
                        "899",
                    ),
                    2 => (
                        r#"{"data":[{"id":"222","author_id":"1234567890","public_metrics":{"like_count":8}}],"meta":{}}"#,
                        "loopback-page-2",
                        "898",
                    ),
                    _ => unreachable!(),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nx-request-id: {request_id}\r\nx-rate-limit-limit: 900\r\nx-rate-limit-remaining: {remaining}\r\nx-rate-limit-reset: 4102444800\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("loopback response");
            }
        });
        (address, capture, server)
    }

    fn response(body: &str, headers: &[(&str, &str)]) -> XHttpResponse {
        XHttpResponse {
            status: 200,
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_ascii_lowercase(), (*value).to_owned()))
                .collect(),
            body: body.as_bytes().to_vec(),
            received_at: Utc::now(),
        }
    }

    fn scope_and_auth(
        scopes: &[&str],
    ) -> (
        ConnectorScope,
        XInsightScope,
        SecretReference,
        CredentialLease,
        InMemoryXCredentialResolver,
    ) {
        let scope = ConnectorScope::new(
            "tenant-1",
            "project-1",
            "x",
            "1234567890",
            scopes.iter().map(|scope| (*scope).to_owned()),
        )
        .expect("connector scope");
        let insight_scope =
            XInsightScope::new("1234567890", Some("org-1".to_owned()), "1234567890")
                .expect("insight scope");
        let secret =
            SecretReference::new("secret-ref-x", scope.clone(), 1).expect("secret reference");
        let lease = ConnectorAuth::issue_credential_lease(
            &secret,
            ProviderAdapterIdentity::new(X_ADAPTER_ID, X_ADAPTER_VERSION)
                .expect("adapter identity"),
            "lease-x",
            1,
            Utc::now() - Duration::seconds(1),
            Utc::now() + Duration::minutes(5),
        )
        .expect("lease");
        let mut resolver = InMemoryXCredentialResolver::default();
        resolver
            .insert(&secret, "x-test-access-token")
            .expect("token");
        (scope, insight_scope, secret, lease, resolver)
    }

    fn probe_request(
        scope: ConnectorScope,
        insight_scope: XInsightScope,
        secret_reference: SecretReference,
        lease: CredentialLease,
    ) -> XProbeRequest {
        XProbeRequest {
            scope,
            insight_scope,
            secret_reference,
            lease,
            requested_at: Utc::now(),
            provenance: ProviderProvenanceClass::ComponentHarness,
        }
    }

    fn read_request(
        scope: ConnectorScope,
        insight_scope: XInsightScope,
        secret_reference: SecretReference,
        lease: CredentialLease,
    ) -> XInsightReadRequest {
        let now = Utc::now();
        XInsightReadRequest {
            scope,
            insight_scope,
            secret_reference,
            lease,
            target: XInsightTarget::UserAccountPosts {
                account_id: "1234567890".to_owned(),
            },
            since: now - Duration::days(1),
            until: now,
            page_size: 5,
            cursor: None,
            requested_at: now,
            provenance: ProviderProvenanceClass::ComponentHarness,
        }
    }

    fn service(transport: Arc<MockTransport>) -> XInsightReadService {
        let now = Utc::now();
        XInsightReadService::new(
            Arc::new(
                XApiV2Adapter::new(
                    XApiBinding {
                        api_base_url: "https://x.example.test".to_owned(),
                        ..XApiBinding::default()
                    },
                    transport,
                )
                .expect("adapter"),
            ),
            DispatchBudget::new(8, now + Duration::hours(1), 8, 100).expect("budget"),
            XReadPolicy::default(),
        )
        .expect("service")
    }

    #[test]
    fn provider_contract_is_empty_and_writes_are_disabled() {
        let transport = Arc::new(MockTransport::new([response("{}", &[])]));
        let adapter = XApiV2Adapter::new(XApiBinding::default(), transport).expect("adapter");
        assert!(adapter.registrations().is_empty());
        assert_eq!(adapter.provider_id(), "x");
        assert_eq!(
            adapter.prepare_effect("post.write").expect_err("writes"),
            XConnectorError::WritesDisabled
        );
    }

    #[test]
    fn probe_is_authenticated_and_binds_exact_user_scope() {
        let transport = Arc::new(MockTransport::new([response(
            r#"{"data":{"id":"1234567890","username":"brand"}}"#,
            &[("x-request-id", "probe-1")],
        )]));
        let adapter = XApiV2Adapter::new(
            XApiBinding {
                api_base_url: "https://x.example.test".to_owned(),
                ..XApiBinding::default()
            },
            transport.clone(),
        )
        .expect("adapter");
        let (scope, insight_scope, secret, lease, resolver) =
            scope_and_auth(&["users.read", "tweet.read"]);
        let observation = adapter
            .probe(
                &probe_request(scope, insight_scope, secret, lease),
                &resolver,
            )
            .expect("probe");
        assert_eq!(observation.status, ProbeStatus::Reachable);
        assert_eq!(observation.scope.user_id(), "1234567890");
        assert_eq!(observation.source[0].path, "/2/users/me");
        assert_eq!(transport.requests().len(), 1);
    }

    #[test]
    fn missing_scope_fails_before_network() {
        let transport = Arc::new(MockTransport::new([]));
        let adapter =
            XApiV2Adapter::new(XApiBinding::default(), transport.clone()).expect("adapter");
        let (scope, insight_scope, secret, lease, resolver) = scope_and_auth(&["users.read"]);
        assert_eq!(
            adapter
                .probe(
                    &probe_request(scope, insight_scope, secret, lease),
                    &resolver
                )
                .expect_err("missing permission"),
            XConnectorError::MissingPermission
        );
        assert!(transport.requests().is_empty());
    }

    #[test]
    fn provider_error_envelope_does_not_become_an_empty_success() {
        let transport = Arc::new(MockTransport::new([response(
            r#"{"errors":[{"title":"partial failure"}]}"#,
            &[],
        )]));
        let adapter = XApiV2Adapter::new(XApiBinding::default(), transport).expect("adapter");
        let (scope, insight_scope, secret, lease, resolver) =
            scope_and_auth(&["users.read", "tweet.read"]);
        assert_eq!(
            adapter
                .probe(
                    &probe_request(scope, insight_scope, secret, lease),
                    &resolver,
                )
                .expect_err("provider error envelope"),
            XConnectorError::InvalidProviderResponse { status: 200 }
        );
    }

    #[test]
    fn read_preserves_provider_metric_context_and_receipts() {
        let transport = Arc::new(MockTransport::new([
            response(r#"{"data":{"id":"1234567890"}}"#, &[]),
            response(
                r#"{"data":[{"id":"111","author_id":"1234567890","created_at":"2026-08-14T00:00:00Z","public_metrics":{"like_count":7,"impression_count":10},"organic_metrics":{"impressions":8},"promoted_metrics":{"impressions":2},"text":"do not persist"}],"meta":{"result_count":1}}"#,
                &[
                    ("x-rate-limit-limit", "900"),
                    ("x-rate-limit-remaining", "898"),
                ],
            ),
        ]));
        let mut service = service(transport);
        let (scope, insight_scope, secret, lease, resolver) =
            scope_and_auth(&["users.read", "tweet.read"]);
        let probe = probe_request(
            scope.clone(),
            insight_scope.clone(),
            secret.clone(),
            lease.clone(),
        );
        service
            .probe_and_mount("mission-x", &probe, &resolver)
            .expect("mount");
        let observation = service
            .read(
                "mission-x",
                &read_request(scope, insight_scope, secret, lease),
                &resolver,
            )
            .expect("read");
        assert_eq!(observation.records.len(), 1);
        assert!(
            observation.records[0]
                .metrics
                .contains_key("organic_metrics.impressions")
        );
        assert!(
            observation.records[0]
                .provider_fields_digest
                .get("text")
                .is_some_and(|digest| is_digest(digest))
        );
        assert_eq!(
            observation.attribution_model(),
            "x_api_v2_user_posts_metrics"
        );
        assert_eq!(observation.causal_status, XCausalStatus::NotClaimed);
        assert_eq!(observation.source.path, "/2/users/1234567890/tweets");
        assert!(is_digest(&observation.source.query_digest));
        assert!(is_digest(&observation.digests.observation_digest));
        assert_eq!(observation.cost.charged_minor, 1);
        assert_eq!(observation.quota.used_after, 1);
        assert_eq!(observation.cursor.sequence, 1);
        assert_eq!(service.observation_log().revision(), 1);
    }

    #[test]
    fn pagination_cursor_is_durable_and_resume_uses_exact_token() {
        let transport = Arc::new(MockTransport::new([
            response(r#"{"data":{"id":"1234567890"}}"#, &[]),
            response(
                r#"{"data":[{"id":"111","author_id":"1234567890"}],"meta":{"next_token":"next-token-1"}}"#,
                &[],
            ),
            response(
                r#"{"data":[{"id":"222","author_id":"1234567890"}],"meta":{}}"#,
                &[],
            ),
        ]));
        let mut first_service = service(transport.clone());
        let (scope, insight_scope, secret, lease, resolver) =
            scope_and_auth(&["users.read", "tweet.read"]);
        first_service
            .probe_and_mount(
                "mission-x",
                &probe_request(
                    scope.clone(),
                    insight_scope.clone(),
                    secret.clone(),
                    lease.clone(),
                ),
                &resolver,
            )
            .expect("mount");
        let first_request = read_request(
            scope.clone(),
            insight_scope.clone(),
            secret.clone(),
            lease.clone(),
        );
        let first = first_service
            .read("mission-x", &first_request, &resolver)
            .expect("first");
        let checkpoint = first_service
            .observation_log_checkpoint()
            .expect("checkpoint");
        assert_eq!(
            first.cursor.durable_cursor.pagination_token(),
            Some("next-token-1")
        );
        assert!(!format!("{:?}", first.cursor.durable_cursor).contains("next-token-1"));
        let resumed_transport = Arc::new(MockTransport::new([
            response(r#"{"data":{"id":"1234567890"}}"#, &[]),
            response(
                r#"{"data":[{"id":"222","author_id":"1234567890"}],"meta":{}}"#,
                &[],
            ),
        ]));
        let mut resumed = service(resumed_transport.clone());
        resumed
            .restore_observation_log(&checkpoint)
            .expect("restore");
        let second_request = first_request
            .clone()
            .with_cursor(first.cursor.durable_cursor.clone());
        resumed
            .probe_and_mount(
                "mission-x",
                &probe_request(
                    second_request.scope.clone(),
                    second_request.insight_scope.clone(),
                    second_request.secret_reference.clone(),
                    second_request.lease.clone(),
                ),
                &resolver,
            )
            .expect("resume mount");
        resumed
            .read("mission-x", &second_request, &resolver)
            .expect("resume read");
        let requests = resumed_transport.requests();
        assert_eq!(
            requests[1]
                .query
                .iter()
                .find(|(key, _)| key == "pagination_token")
                .map(|(_, value)| value.as_str()),
            Some("next-token-1")
        );
    }

    #[test]
    fn deterministic_loopback_http_proves_authenticated_pagination_and_rate_receipts() {
        let (address, capture, server) = loopback_server();
        let transport = Arc::new(LoopbackHttpTransport { address });
        let adapter = XApiV2Adapter::new(XApiBinding::default(), transport).expect("adapter");
        let now = Utc::now();
        let mut service = XInsightReadService::new(
            Arc::new(adapter),
            DispatchBudget::new(8, now + Duration::hours(1), 8, 100).expect("budget"),
            XReadPolicy::default(),
        )
        .expect("service");
        let (scope, insight_scope, secret, lease, resolver) =
            scope_and_auth(&["users.read", "tweet.read"]);
        service
            .probe_and_mount(
                "mission-loopback",
                &probe_request(
                    scope.clone(),
                    insight_scope.clone(),
                    secret.clone(),
                    lease.clone(),
                ),
                &resolver,
            )
            .expect("authenticated loopback probe");
        let first_request = read_request(
            scope.clone(),
            insight_scope.clone(),
            secret.clone(),
            lease.clone(),
        );
        let first = service
            .read("mission-loopback", &first_request, &resolver)
            .expect("first loopback page");
        assert_eq!(first.records[0].external_id, "111");
        assert_eq!(first.rate_limit.remaining, Some(899));
        assert_eq!(first.quota.provider_rate_limit.remaining, Some(899));
        assert_eq!(
            first.source.provider_request_id.as_deref(),
            Some("loopback-page-1")
        );
        assert_eq!(first.cursor.sequence, 1);
        assert_eq!(
            first.cursor.durable_cursor.pagination_token(),
            Some("next-token-1")
        );

        let second_request = first_request.with_cursor(first.cursor.durable_cursor.clone());
        let second = service
            .read("mission-loopback", &second_request, &resolver)
            .expect("second loopback page");
        assert_eq!(second.records[0].external_id, "222");
        assert_eq!(second.rate_limit.remaining, Some(898));
        assert_eq!(second.quota.provider_rate_limit.remaining, Some(898));
        assert_eq!(
            second.source.provider_request_id.as_deref(),
            Some("loopback-page-2")
        );
        assert!(second.cursor.complete);
        assert_eq!(service.observation_log().revision(), 2);

        let capture = capture.lock().expect("loopback capture");
        assert_eq!(capture.request_lines.len(), 3);
        assert_eq!(capture.authenticated_requests, 3);
        assert!(capture.request_lines[2].contains("pagination_token=next-token-1"));
        drop(capture);
        server.join().expect("loopback server");
    }

    #[test]
    fn provider_cursor_rollback_is_fail_closed() {
        let transport = Arc::new(MockTransport::new([
            response(r#"{"data":{"id":"1234567890"}}"#, &[]),
            response(
                r#"{"data":[{"id":"111","author_id":"1234567890"}],"meta":{"next_token":"next-token-1"}}"#,
                &[],
            ),
            response(
                r#"{"data":[{"id":"222","author_id":"1234567890"}],"meta":{"next_token":"next-token-1"}}"#,
                &[],
            ),
        ]));
        let mut service = service(transport);
        let (scope, insight_scope, secret, lease, resolver) =
            scope_and_auth(&["users.read", "tweet.read"]);
        service
            .probe_and_mount(
                "mission-x",
                &probe_request(
                    scope.clone(),
                    insight_scope.clone(),
                    secret.clone(),
                    lease.clone(),
                ),
                &resolver,
            )
            .expect("mount");
        let first_request = read_request(
            scope.clone(),
            insight_scope.clone(),
            secret.clone(),
            lease.clone(),
        );
        let first = service
            .read("mission-x", &first_request, &resolver)
            .expect("first");
        let error = service
            .read(
                "mission-x",
                &first_request.with_cursor(first.cursor.durable_cursor),
                &resolver,
            )
            .expect_err("rollback");
        assert_eq!(error, XConnectorError::CursorRollback);
        assert_eq!(service.observation_log().revision(), 1);
    }

    #[test]
    fn unauthorized_marks_service_stale_and_429_preserves_reset_receipt() {
        let reset = Utc::now().timestamp().to_string();
        let transport = Arc::new(MockTransport::new([
            response(r#"{"data":{"id":"1234567890"}}"#, &[]),
            XHttpResponse {
                status: 429,
                headers: BTreeMap::from([
                    ("x-rate-limit-reset".to_owned(), reset),
                    ("retry-after".to_owned(), "0".to_owned()),
                ]),
                body: br#"{"title":"rate"}"#.to_vec(),
                received_at: Utc::now(),
            },
            XHttpResponse {
                status: 401,
                headers: BTreeMap::new(),
                body: br#"{"title":"expired"}"#.to_vec(),
                received_at: Utc::now(),
            },
        ]));
        let now = Utc::now();
        let adapter = XApiV2Adapter::new(
            XApiBinding {
                api_base_url: "https://x.example.test".to_owned(),
                ..XApiBinding::default()
            },
            transport.clone(),
        )
        .expect("adapter");
        let (scope, insight_scope, secret, lease, resolver) =
            scope_and_auth(&["users.read", "tweet.read"]);
        let mut service = XInsightReadService::new(
            Arc::new(adapter),
            DispatchBudget::new(4, now + Duration::hours(1), 4, 20).expect("budget"),
            XReadPolicy::new(Duration::minutes(1), 1, 2, 0).expect("policy"),
        )
        .expect("service");
        service
            .probe_and_mount(
                "mission-x",
                &probe_request(
                    scope.clone(),
                    insight_scope.clone(),
                    secret.clone(),
                    lease.clone(),
                ),
                &resolver,
            )
            .expect("mount");
        let error = service
            .read(
                "mission-x",
                &read_request(scope, insight_scope, secret, lease),
                &resolver,
            )
            .expect_err("unauthorized after rate limit");
        assert_eq!(error, XConnectorError::Unauthorized { status: 401 });
        assert_eq!(service.state(), XConnectionState::Stale);
    }

    #[test]
    fn permission_denied_marks_service_stale_without_a_read_result() {
        let transport = Arc::new(MockTransport::new([
            response(r#"{"data":{"id":"1234567890"}}"#, &[]),
            XHttpResponse {
                status: 403,
                headers: BTreeMap::new(),
                body: br#"{"title":"forbidden"}"#.to_vec(),
                received_at: Utc::now(),
            },
        ]));
        let mut service = service(transport);
        let (scope, insight_scope, secret, lease, resolver) =
            scope_and_auth(&["users.read", "tweet.read"]);
        service
            .probe_and_mount(
                "mission-x",
                &probe_request(
                    scope.clone(),
                    insight_scope.clone(),
                    secret.clone(),
                    lease.clone(),
                ),
                &resolver,
            )
            .expect("mount");
        assert_eq!(
            service
                .read(
                    "mission-x",
                    &read_request(scope, insight_scope, secret, lease),
                    &resolver,
                )
                .expect_err("permission denied"),
            XConnectorError::PermissionDenied
        );
        assert_eq!(service.state(), XConnectionState::Stale);
        assert_eq!(service.observation_log().revision(), 0);
    }

    #[test]
    fn mission_consumer_adopts_durable_result_without_connected_claim() {
        let transport = Arc::new(MockTransport::new([
            response(r#"{"data":{"id":"1234567890"}}"#, &[]),
            response(
                r#"{"data":[{"id":"111","author_id":"1234567890"}],"meta":{}}"#,
                &[],
            ),
        ]));
        let mut consumer = MissionXInsightConsumer::new(service(transport));
        let (scope, insight_scope, secret, lease, resolver) =
            scope_and_auth(&["users.read", "tweet.read"]);
        let probe = probe_request(
            scope.clone(),
            insight_scope.clone(),
            secret.clone(),
            lease.clone(),
        );
        let grant = consumer
            .attach("mission-x", &probe, &resolver)
            .expect("attach");
        assert_eq!(grant.connection_state, XConnectionState::Mounted);
        assert!(!grant.connected_claim);
        let result = consumer
            .read(
                "mission-x",
                &read_request(scope, insight_scope, secret, lease),
                &resolver,
            )
            .expect("mission result");
        assert_eq!(result.mission_id, "mission-x");
        assert_eq!(result.durable_log_revision, 1);
        assert_eq!(result.observation.records.len(), 1);
        consumer.unmount();
        assert!(consumer.capability().is_none());
    }

    #[test]
    fn unmount_revoke_clear_session_and_env_missing_is_blocked() {
        let transport = Arc::new(MockTransport::new([response(
            r#"{"data":{"id":"1234567890"}}"#,
            &[],
        )]));
        let adapter = XApiV2Adapter::new(XApiBinding::default(), transport).expect("adapter");
        let (scope, insight_scope, secret, lease, _resolver) =
            scope_and_auth(&["users.read", "tweet.read"]);
        let request = probe_request(scope, insight_scope, secret, lease);
        let error = env_gated_x_credentialed_probe(&adapter, &request).expect_err("blocked env");
        assert!(matches!(error, XConnectorError::BlockedEnv { .. }));
        let transport = Arc::new(MockTransport::new([]));
        let mut service = service(transport);
        assert_eq!(service.state(), XConnectionState::Unmounted);
        service.unmount();
        assert!(service.cursor().is_none());
        service.revoke();
        assert_eq!(service.state(), XConnectionState::Revoked);
        assert!(service.mount().is_none());
    }

    #[test]
    fn revoked_service_and_mission_capability_fail_closed() {
        let transport = Arc::new(MockTransport::new([response(
            r#"{"data":{"id":"1234567890"}}"#,
            &[],
        )]));
        let mut consumer = MissionXInsightConsumer::new(service(transport));
        let (scope, insight_scope, secret, lease, resolver) =
            scope_and_auth(&["users.read", "tweet.read"]);
        consumer
            .attach(
                "mission-x",
                &probe_request(
                    scope.clone(),
                    insight_scope.clone(),
                    secret.clone(),
                    lease.clone(),
                ),
                &resolver,
            )
            .expect("attach");
        consumer.service_mut().revoke();
        let error = consumer
            .read(
                "mission-x",
                &read_request(
                    scope.clone(),
                    insight_scope.clone(),
                    secret.clone(),
                    lease.clone(),
                ),
                &resolver,
            )
            .expect_err("revoked");
        assert_eq!(error, XConnectorError::Revoked);
        assert_eq!(
            consumer
                .capability()
                .expect("capability state")
                .connection_state,
            XConnectionState::Revoked
        );
        assert_eq!(
            consumer
                .read(
                    "mission-x",
                    &read_request(scope, insight_scope, secret, lease,),
                    &resolver,
                )
                .expect_err("revoked capability"),
            XConnectorError::MissionMismatch
        );
    }

    impl XInsightObservation {
        fn attribution_model(&self) -> &str {
            &self.classification.attribution.model
        }
    }
}
