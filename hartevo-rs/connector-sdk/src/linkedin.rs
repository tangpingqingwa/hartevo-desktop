//! LinkedIn Marketing organization/page insight read boundary.
//!
//! This module is a read-only connector slice.  It reuses the Connector SDK's
//! scope, opaque secret reference, credential lease, provenance, freshness and
//! dispatch-budget types.  It deliberately does not register a provider, grant
//! Effect authority, or expose a Mission mutation handle.

use chrono::{DateTime, Duration, Utc};
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

pub const LINKEDIN_ADAPTER_ID: &str = "linkedin.marketing.organization-insights";
pub const LINKEDIN_ADAPTER_VERSION: u32 = 1;
pub const LINKEDIN_INSIGHT_READ_SCHEMA: &str = "hartevo-linkedin-insight-read/v1";
pub const LINKEDIN_ACCESS_TOKEN_ENV: &str = "HARTEVO_LINKEDIN_ACCESS_TOKEN";
pub const LINKEDIN_RUN_PROBE_ENV: &str = "HARTEVO_RUN_LINKEDIN_CREDENTIAL_PROBE";
pub const LINKEDIN_DEFAULT_API_BASE_URL: &str = "https://api.linkedin.com";
pub const LINKEDIN_DEFAULT_MARKETING_VERSION: &str = "202606";

/// Central catalog/provider registration remains empty until a Mission route
/// and reverse mapping are explicitly approved.
pub const LINKEDIN_REGISTRATIONS: &[ProviderCapabilitySupport] = &[];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkedInConnectionState {
    Unmounted,
    Mounted,
    Stale,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionCapability {
    PaidSocialInsightRead,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkedInCausalStatus {
    NotClaimed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkedInReviewState {
    Required,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkedInInsightTargetKind {
    OrganizationPage,
    OrganizationPost,
    AdAccount,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum LinkedInInsightTarget {
    OrganizationPage {
        organization_id: String,
        page_id: String,
    },
    OrganizationPost {
        organization_id: String,
        page_id: String,
        post_id: String,
    },
    AdAccount {
        ad_account_id: String,
    },
}

impl LinkedInInsightTarget {
    pub fn kind(&self) -> LinkedInInsightTargetKind {
        match self {
            Self::OrganizationPage { .. } => LinkedInInsightTargetKind::OrganizationPage,
            Self::OrganizationPost { .. } => LinkedInInsightTargetKind::OrganizationPost,
            Self::AdAccount { .. } => LinkedInInsightTargetKind::AdAccount,
        }
    }

    fn required_scope_ids(&self) -> Result<BTreeSet<String>, LinkedInConnectorError> {
        let mut ids = BTreeSet::new();
        match self {
            Self::OrganizationPage {
                organization_id,
                page_id,
            }
            | Self::OrganizationPost {
                organization_id,
                page_id,
                ..
            } => {
                validate_provider_id(organization_id)?;
                validate_provider_id(page_id)?;
                ids.insert(organization_id.clone());
                ids.insert(page_id.clone());
            }
            Self::AdAccount { ad_account_id } => {
                validate_provider_id(ad_account_id)?;
                ids.insert(ad_account_id.clone());
            }
        }
        Ok(ids)
    }
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInInsightScope {
    member_id: String,
    organization_id: Option<String>,
    page_id: Option<String>,
    ad_account_id: Option<String>,
}

impl LinkedInInsightScope {
    pub fn new(
        member_id: impl Into<String>,
        organization_id: Option<String>,
        page_id: Option<String>,
        ad_account_id: Option<String>,
    ) -> Result<Self, LinkedInConnectorError> {
        let scope = Self {
            member_id: member_id.into(),
            organization_id,
            page_id,
            ad_account_id,
        };
        scope.validate(None)?;
        Ok(scope)
    }

    pub fn member_id(&self) -> &str {
        &self.member_id
    }

    pub fn organization_id(&self) -> Option<&str> {
        self.organization_id.as_deref()
    }

    pub fn page_id(&self) -> Option<&str> {
        self.page_id.as_deref()
    }

    pub fn ad_account_id(&self) -> Option<&str> {
        self.ad_account_id.as_deref()
    }

    pub fn digest(&self, connector_scope: &ConnectorScope) -> String {
        digest_material([
            connector_scope.digest(),
            self.member_id.clone(),
            self.organization_id.clone().unwrap_or_default(),
            self.page_id.clone().unwrap_or_default(),
            self.ad_account_id.clone().unwrap_or_default(),
        ])
    }

    fn validate(
        &self,
        connector_scope: Option<&ConnectorScope>,
    ) -> Result<(), LinkedInConnectorError> {
        validate_provider_id(&self.member_id)?;
        if let Some(organization_id) = &self.organization_id {
            validate_provider_id(organization_id)?;
        }
        if let Some(page_id) = &self.page_id {
            validate_provider_id(page_id)?;
            if self.organization_id.is_none() {
                return Err(LinkedInConnectorError::InvalidScope);
            }
        }
        if let Some(ad_account_id) = &self.ad_account_id {
            validate_provider_id(ad_account_id)?;
        }
        if let Some(connector_scope) = connector_scope
            && (connector_scope.provider_id() != "linkedin"
                || connector_scope.account_id() != self.member_id)
        {
            return Err(LinkedInConnectorError::ScopeMismatch);
        }
        Ok(())
    }

    fn required_scopes(&self) -> BTreeSet<String> {
        let mut scopes = BTreeSet::from(["openid".to_owned(), "profile".to_owned()]);
        if self.organization_id.is_some() || self.page_id.is_some() {
            scopes.extend([
                // LinkedIn documents rw_organization_admin for the
                // organizationalEntityShareStatistics reporting endpoint.
                // The adapter still exposes no write operation or Effect
                // authority; this is a provider OAuth permission boundary.
                "rw_organization_admin".to_owned(),
                "r_organization_social".to_owned(),
            ]);
        }
        if self.ad_account_id.is_some() {
            scopes.extend(["r_ads".to_owned(), "r_ads_reporting".to_owned()]);
        }
        scopes
    }

    fn validate_target(
        &self,
        target: &LinkedInInsightTarget,
    ) -> Result<(), LinkedInConnectorError> {
        let _ = target.required_scope_ids()?;
        match target {
            LinkedInInsightTarget::OrganizationPage {
                organization_id,
                page_id,
            }
            | LinkedInInsightTarget::OrganizationPost {
                organization_id,
                page_id,
                ..
            } if self.organization_id.as_deref() == Some(organization_id)
                && self.page_id.as_deref() == Some(page_id) =>
            {
                Ok(())
            }
            LinkedInInsightTarget::AdAccount { ad_account_id }
                if self.ad_account_id.as_deref() == Some(ad_account_id) =>
            {
                Ok(())
            }
            _ => Err(LinkedInConnectorError::ScopeMismatch),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct LinkedInAccessToken(Zeroizing<String>);

impl LinkedInAccessToken {
    pub fn new(value: impl Into<String>) -> Result<Self, LinkedInConnectorError> {
        let value = value.into();
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(LinkedInConnectorError::CredentialUnavailable);
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

impl Drop for LinkedInAccessToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for LinkedInAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LinkedInAccessToken(REDACTED)")
    }
}

pub trait LinkedInCredentialResolver: fmt::Debug + Send + Sync {
    fn resolve(
        &self,
        reference: &SecretReference,
    ) -> Result<LinkedInAccessToken, LinkedInConnectorError>;
}

#[derive(Clone, Default)]
pub struct InMemoryLinkedInCredentialResolver {
    values: BTreeMap<String, LinkedInAccessToken>,
}

impl fmt::Debug for InMemoryLinkedInCredentialResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryLinkedInCredentialResolver")
            .field("references", &self.values.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl InMemoryLinkedInCredentialResolver {
    pub fn insert(
        &mut self,
        reference: &SecretReference,
        token: impl Into<String>,
    ) -> Result<(), LinkedInConnectorError> {
        self.values.insert(
            reference.reference_id().to_owned(),
            LinkedInAccessToken::new(token)?,
        );
        Ok(())
    }
}

impl LinkedInCredentialResolver for InMemoryLinkedInCredentialResolver {
    fn resolve(
        &self,
        reference: &SecretReference,
    ) -> Result<LinkedInAccessToken, LinkedInConnectorError> {
        self.values
            .get(reference.reference_id())
            .cloned()
            .ok_or(LinkedInConnectorError::CredentialUnavailable)
    }
}

#[derive(Clone, Debug)]
pub struct EnvLinkedInCredentialResolver {
    pub token_env: String,
}

impl Default for EnvLinkedInCredentialResolver {
    fn default() -> Self {
        Self {
            token_env: LINKEDIN_ACCESS_TOKEN_ENV.to_owned(),
        }
    }
}

impl LinkedInCredentialResolver for EnvLinkedInCredentialResolver {
    fn resolve(
        &self,
        _reference: &SecretReference,
    ) -> Result<LinkedInAccessToken, LinkedInConnectorError> {
        std::env::var(&self.token_env)
            .map_err(|_| LinkedInConnectorError::CredentialUnavailable)
            .and_then(LinkedInAccessToken::new)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInMarketingConfig {
    pub api_base_url: String,
    pub marketing_version: String,
    pub restli_protocol_version: String,
}

impl Default for LinkedInMarketingConfig {
    fn default() -> Self {
        Self {
            api_base_url: LINKEDIN_DEFAULT_API_BASE_URL.to_owned(),
            marketing_version: LINKEDIN_DEFAULT_MARKETING_VERSION.to_owned(),
            restli_protocol_version: "2.0.0".to_owned(),
        }
    }
}

impl LinkedInMarketingConfig {
    fn validate(&self) -> Result<(), LinkedInConnectorError> {
        validate_https_url(&self.api_base_url)?;
        if self.marketing_version.is_empty()
            || self.marketing_version.len() > 32
            || self
                .marketing_version
                .chars()
                .any(|character| !character.is_ascii_alphanumeric())
        {
            return Err(LinkedInConnectorError::InvalidRequest);
        }
        if self.restli_protocol_version.trim().is_empty()
            || self.restli_protocol_version.chars().any(char::is_control)
        {
            return Err(LinkedInConnectorError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum LinkedInTransportError {
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
pub struct LinkedInHttpRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub query: Vec<(String, String)>,
}

impl fmt::Debug for LinkedInHttpRequest {
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
            .debug_struct("LinkedInHttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &headers)
            .field("query", &self.query)
            .finish()
    }
}

impl LinkedInHttpRequest {
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

    fn path(&self) -> Result<String, LinkedInConnectorError> {
        let url = self.url_with_query();
        let authority = url
            .strip_prefix("https://")
            .ok_or(LinkedInConnectorError::InvalidRequest)?;
        let slash = authority
            .find('/')
            .ok_or(LinkedInConnectorError::InvalidRequest)?;
        let path = authority[slash..].split('?').next().unwrap_or_default();
        if path.is_empty() {
            return Err(LinkedInConnectorError::InvalidRequest);
        }
        Ok(path.to_owned())
    }

    fn query_digest(&self) -> String {
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
pub struct LinkedInHttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub received_at: DateTime<Utc>,
}

impl fmt::Debug for LinkedInHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinkedInHttpResponse")
            .field("status", &self.status)
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("body_length", &self.body.len())
            .field("received_at", &self.received_at)
            .finish()
    }
}

pub trait LinkedInHttpTransport: fmt::Debug + Send + Sync {
    fn send(
        &self,
        request: &LinkedInHttpRequest,
        token: &LinkedInAccessToken,
    ) -> Result<LinkedInHttpResponse, LinkedInTransportError>;
}

#[derive(Clone, Debug)]
pub struct CurlHttpsTransport {
    pub curl_binary: String,
    pub timeout_seconds: u64,
}

impl Default for CurlHttpsTransport {
    fn default() -> Self {
        Self {
            curl_binary: "curl".to_owned(),
            timeout_seconds: 20,
        }
    }
}

impl CurlHttpsTransport {
    fn config_for(
        request: &LinkedInHttpRequest,
        token: &LinkedInAccessToken,
    ) -> Result<Zeroizing<String>, LinkedInTransportError> {
        let url = request.url_with_query();
        validate_https_url(&url).map_err(|_| LinkedInTransportError::InsecureUrl)?;
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

impl LinkedInHttpTransport for CurlHttpsTransport {
    fn send(
        &self,
        request: &LinkedInHttpRequest,
        token: &LinkedInAccessToken,
    ) -> Result<LinkedInHttpResponse, LinkedInTransportError> {
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
            .map_err(|_| LinkedInTransportError::Spawn)?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(config.as_bytes())
                .map_err(|_| LinkedInTransportError::Io)?;
        }
        let output = child
            .wait_with_output()
            .map_err(|_| LinkedInTransportError::Io)?;
        let (status, headers) = parse_curl_headers(&output.stderr)?;
        Ok(LinkedInHttpResponse {
            status,
            headers,
            body: output.stdout,
            received_at: Utc::now(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInPermissionObservation {
    pub required_scopes: BTreeSet<String>,
    pub granted_scopes: BTreeSet<String>,
    pub missing_scopes: BTreeSet<String>,
    pub review_state: LinkedInReviewState,
}

impl LinkedInPermissionObservation {
    fn for_scope(scope: &ConnectorScope, required: BTreeSet<String>) -> Self {
        let missing_scopes = required
            .difference(scope.scopes())
            .cloned()
            .collect::<BTreeSet<_>>();
        Self {
            required_scopes: required,
            granted_scopes: scope.scopes().clone(),
            missing_scopes,
            review_state: LinkedInReviewState::Required,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInRequestEvidence {
    pub method: String,
    pub path: String,
    pub query_digest: String,
    pub status: u16,
    pub provider_request_id: Option<String>,
    pub response_digest: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInRateLimit {
    pub limit: Option<u64>,
    pub remaining: Option<u64>,
    pub reset_at: Option<DateTime<Utc>>,
    pub retry_after_seconds: Option<u64>,
    pub evidence_headers: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInRetryReceipt {
    pub attempts: u8,
    pub retried: bool,
    pub last_retry_after_seconds: Option<u64>,
    pub exhausted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInAttribution {
    pub model: String,
    pub windows: Vec<String>,
    pub parameters: BTreeMap<String, String>,
    pub causal_status: LinkedInCausalStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInClassification {
    pub kind: LinkedInInsightTargetKind,
    pub attribution: LinkedInAttribution,
    pub review_state: LinkedInReviewState,
    pub provenance: ProviderProvenanceClass,
    pub causal_status: LinkedInCausalStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum LinkedInMetricValue {
    String(String),
    Integer(i64),
    Decimal(String),
    Boolean(bool),
    Null,
    Digest(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInInsightRecord {
    pub kind: LinkedInInsightTargetKind,
    pub external_id: Option<String>,
    pub period: Option<String>,
    pub dimensions: BTreeMap<String, String>,
    pub metrics: BTreeMap<String, LinkedInMetricValue>,
    pub provider_fields_digest: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInFreshnessReceipt {
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub ttl_seconds: i64,
    pub fresh_at_observation: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInQuotaReceipt {
    pub configured_limit: u64,
    pub used_before: u64,
    pub used_after: u64,
    pub rate_remaining_before: u64,
    pub rate_remaining_after: u64,
    pub provider_rate_limit: LinkedInRateLimit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInCostReceipt {
    pub configured_limit_minor: i64,
    pub charged_minor: i64,
    pub used_before_minor: i64,
    pub used_after_minor: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInCursorReceipt {
    pub sequence: u64,
    pub current_digest: Option<String>,
    pub next_digest: Option<String>,
    pub durable_checkpoint_digest: String,
    pub durable_cursor: LinkedInPaginationCursor,
    pub complete: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInDigestReceipt {
    pub request_digest: String,
    pub response_digest: String,
    pub content_digest: String,
    pub observation_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInPaginationCursor {
    scope_digest: String,
    request_digest: String,
    sequence: u64,
    start: u64,
    token_digest: String,
    complete: bool,
}

impl LinkedInPaginationCursor {
    fn new(
        scope: &LinkedInInsightScope,
        request_digest: &str,
        sequence: u64,
        start: u64,
        complete: bool,
    ) -> Self {
        Self {
            scope_digest: digest_material([scope.member_id.clone(), scope.digest_material()]),
            request_digest: request_digest.to_owned(),
            sequence,
            start,
            token_digest: digest_bytes(start.to_string().as_bytes()),
            complete,
        }
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn start(&self) -> u64 {
        self.start
    }

    pub fn token_digest(&self) -> &str {
        &self.token_digest
    }

    pub const fn complete(&self) -> bool {
        self.complete
    }

    fn validate(
        &self,
        scope: &LinkedInInsightScope,
        request_digest: &str,
    ) -> Result<(), LinkedInConnectorError> {
        if self.scope_digest != digest_material([scope.member_id.clone(), scope.digest_material()])
            || self.request_digest != request_digest
            || self.sequence == 0
            || self.token_digest != digest_bytes(self.start.to_string().as_bytes())
        {
            return Err(LinkedInConnectorError::CursorMismatch);
        }
        Ok(())
    }

    fn digest(&self) -> String {
        digest_serializable(self).expect("cursor serialization")
    }
}

impl LinkedInInsightScope {
    fn digest_material(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.member_id,
            self.organization_id.as_deref().unwrap_or_default(),
            self.page_id.as_deref().unwrap_or_default(),
            self.ad_account_id.as_deref().unwrap_or_default()
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInInsightObservation {
    pub schema_version: String,
    pub observation_id: String,
    pub mission_id: String,
    pub scope: LinkedInInsightScope,
    pub connector_scope_digest: String,
    pub target: LinkedInInsightTarget,
    pub requested_at: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    pub source: LinkedInRequestEvidence,
    pub records: Vec<LinkedInInsightRecord>,
    pub permission: LinkedInPermissionObservation,
    pub rate_limit: LinkedInRateLimit,
    pub retry: LinkedInRetryReceipt,
    pub freshness: LinkedInFreshnessReceipt,
    pub quota: LinkedInQuotaReceipt,
    pub cost: LinkedInCostReceipt,
    pub cursor: LinkedInCursorReceipt,
    pub classification: LinkedInClassification,
    pub digests: LinkedInDigestReceipt,
    pub provenance: ProviderProvenanceClass,
    pub causal_status: LinkedInCausalStatus,
}

impl LinkedInInsightObservation {
    pub fn validate(&self) -> Result<(), LinkedInConnectorError> {
        if self.schema_version != LINKEDIN_INSIGHT_READ_SCHEMA
            || self.observation_id.is_empty()
            || !is_digest(&self.connector_scope_digest)
            || !is_digest(&self.source.query_digest)
            || !is_digest(&self.source.response_digest)
            || !is_digest(&self.digests.request_digest)
            || !is_digest(&self.digests.response_digest)
            || !is_digest(&self.digests.content_digest)
            || !is_digest(&self.digests.observation_digest)
            || !is_digest(&self.cursor.durable_checkpoint_digest)
            || !self.cursor.current_digest.as_deref().is_none_or(is_digest)
            || !self.cursor.next_digest.as_deref().is_none_or(is_digest)
            || self.source.status / 100 != 2
            || self.source.method != "GET"
            || self.source.response_digest != self.digests.response_digest
            || self.freshness.valid_until <= self.freshness.observed_at
            || self.freshness.ttl_seconds <= 0
            || !self.freshness.fresh_at_observation
            || self.freshness.observed_at != self.observed_at
            || self.permission.missing_scopes.iter().next().is_some()
            || self.retry.attempts == 0
            || self.retry.retried != (self.retry.attempts > 1)
            || self.quota.used_after < self.quota.used_before
            || self.cost.used_after_minor < self.cost.used_before_minor
            || self.cost.charged_minor < 0
            || self.classification.kind != self.target.kind()
            || self.classification.provenance != self.provenance
            || self.causal_status != LinkedInCausalStatus::NotClaimed
            || self.classification.causal_status != LinkedInCausalStatus::NotClaimed
            || self.classification.attribution.causal_status != LinkedInCausalStatus::NotClaimed
        {
            return Err(LinkedInConnectorError::InvalidObservation);
        }
        let expected_cursor_scope =
            digest_material([self.scope.member_id.clone(), self.scope.digest_material()]);
        if self.cursor.durable_cursor.scope_digest != expected_cursor_scope
            || self.cursor.durable_cursor.request_digest != self.digests.request_digest
            || self.cursor.durable_cursor.sequence != self.cursor.sequence
            || self.cursor.durable_cursor.complete() != self.cursor.complete
            || self.cursor.durable_cursor.digest() != self.cursor.durable_checkpoint_digest
        {
            return Err(LinkedInConnectorError::InvalidObservation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkedInProbeRequest {
    pub scope: ConnectorScope,
    pub insight_scope: LinkedInInsightScope,
    pub secret_reference: SecretReference,
    pub lease: CredentialLease,
    pub requested_at: DateTime<Utc>,
    pub provenance: ProviderProvenanceClass,
}

impl LinkedInProbeRequest {
    fn validate(&self) -> Result<(), LinkedInConnectorError> {
        self.insight_scope.validate(Some(&self.scope))?;
        if self.secret_reference.scope() != &self.scope
            || self.lease.scope() != &self.scope
            || self.lease.adapter().adapter_id() != LINKEDIN_ADAPTER_ID
            || self.lease.adapter().adapter_version() != LINKEDIN_ADAPTER_VERSION
        {
            return Err(LinkedInConnectorError::CredentialLeaseInvalid);
        }
        self.lease
            .validate(&self.secret_reference, self.requested_at)
            .map_err(|_| LinkedInConnectorError::CredentialLeaseInvalid)?;
        self.lease
            .validate(&self.secret_reference, Utc::now())
            .map_err(|_| LinkedInConnectorError::CredentialLeaseInvalid)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkedInInsightReadRequest {
    pub scope: ConnectorScope,
    pub insight_scope: LinkedInInsightScope,
    pub secret_reference: SecretReference,
    pub lease: CredentialLease,
    pub target: LinkedInInsightTarget,
    pub since: DateTime<Utc>,
    pub until: DateTime<Utc>,
    pub page_size: u32,
    pub cursor: Option<LinkedInPaginationCursor>,
    pub requested_at: DateTime<Utc>,
    pub provenance: ProviderProvenanceClass,
}

impl LinkedInInsightReadRequest {
    fn validate(&self) -> Result<(), LinkedInConnectorError> {
        self.insight_scope.validate(Some(&self.scope))?;
        self.insight_scope.validate_target(&self.target)?;
        if self.secret_reference.scope() != &self.scope
            || self.lease.scope() != &self.scope
            || self.lease.adapter().adapter_id() != LINKEDIN_ADAPTER_ID
            || self.lease.adapter().adapter_version() != LINKEDIN_ADAPTER_VERSION
        {
            return Err(LinkedInConnectorError::CredentialLeaseInvalid);
        }
        self.lease
            .validate(&self.secret_reference, self.requested_at)
            .map_err(|_| LinkedInConnectorError::CredentialLeaseInvalid)?;
        self.lease
            .validate(&self.secret_reference, Utc::now())
            .map_err(|_| LinkedInConnectorError::CredentialLeaseInvalid)?;
        if self.until <= self.since
            || self.until - self.since > Duration::days(31)
            || self.page_size == 0
            || self.page_size > 1_000
        {
            return Err(LinkedInConnectorError::InvalidRequest);
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate(&self.insight_scope, &self.request_digest())?;
            if cursor.complete() {
                return Err(LinkedInConnectorError::CursorComplete);
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn with_cursor(mut self, cursor: LinkedInPaginationCursor) -> Self {
        self.cursor = Some(cursor);
        self
    }

    fn request_digest(&self) -> String {
        digest_serializable(&(self.target.clone(), self.since, self.until, self.page_size))
            .expect("read request serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInProbeObservation {
    pub schema_version: String,
    pub scope: LinkedInInsightScope,
    pub connector_scope_digest: String,
    pub source: Vec<LinkedInRequestEvidence>,
    pub permission: LinkedInPermissionObservation,
    pub status: ProbeStatus,
    pub observed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub credential_reference_digest: String,
    pub credential_revision: u64,
    pub lease_revision: u64,
    pub probe_digest: String,
    pub classification: LinkedInClassification,
    pub provenance: ProviderProvenanceClass,
    pub causal_status: LinkedInCausalStatus,
}

impl LinkedInProbeObservation {
    pub fn validate(&self) -> Result<(), LinkedInConnectorError> {
        if self.schema_version != LINKEDIN_INSIGHT_READ_SCHEMA
            || self.source.is_empty()
            || self.status != ProbeStatus::Reachable
            || self.expires_at <= self.observed_at
            || self.expires_at - self.observed_at > Duration::seconds(120)
            || !is_digest(&self.connector_scope_digest)
            || !is_digest(&self.credential_reference_digest)
            || !is_digest(&self.probe_digest)
            || self.permission.missing_scopes.iter().next().is_some()
            || self.source.iter().any(|evidence| {
                evidence.method != "GET"
                    || evidence.status / 100 != 2
                    || !is_digest(&evidence.query_digest)
                    || !is_digest(&evidence.response_digest)
            })
            || self.causal_status != LinkedInCausalStatus::NotClaimed
            || self.classification.causal_status != LinkedInCausalStatus::NotClaimed
        {
            return Err(LinkedInConnectorError::InvalidProbe);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedInReadPolicy {
    pub freshness_ttl: Duration,
    pub cost_minor: i64,
    pub max_attempts: u8,
    pub max_retry_delay_seconds: u64,
}

impl Default for LinkedInReadPolicy {
    fn default() -> Self {
        Self {
            freshness_ttl: Duration::minutes(15),
            cost_minor: 1,
            max_attempts: 1,
            max_retry_delay_seconds: 0,
        }
    }
}

impl LinkedInReadPolicy {
    pub fn new(
        freshness_ttl: Duration,
        cost_minor: i64,
        max_attempts: u8,
        max_retry_delay_seconds: u64,
    ) -> Result<Self, LinkedInConnectorError> {
        if freshness_ttl <= Duration::zero()
            || freshness_ttl > Duration::seconds(900)
            || cost_minor < 0
            || !(1..=3).contains(&max_attempts)
            || max_retry_delay_seconds > 60
        {
            return Err(LinkedInConnectorError::InvalidPolicy);
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
pub struct LinkedInMount {
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
pub struct MissionCapabilityGrant {
    pub mission_id: String,
    pub capability: MissionCapability,
    pub provider_id: String,
    pub scope_digest: String,
    pub connection_state: LinkedInConnectionState,
    pub probe_digest: String,
    pub granted_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionInsightResult {
    pub mission_id: String,
    pub capability: MissionCapability,
    pub observation: LinkedInInsightObservation,
    pub durable_log_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DurableObservationLog {
    pub schema_version: String,
    pub revision: u64,
    pub entries: Vec<LinkedInInsightObservation>,
}

impl Default for DurableObservationLog {
    fn default() -> Self {
        Self {
            schema_version: LINKEDIN_INSIGHT_READ_SCHEMA.to_owned(),
            revision: 0,
            entries: Vec::new(),
        }
    }
}

impl DurableObservationLog {
    pub fn append(
        &mut self,
        observation: LinkedInInsightObservation,
    ) -> Result<(), LinkedInConnectorError> {
        observation.validate()?;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(LinkedInConnectorError::InvalidObservation)?;
        self.entries.push(observation);
        Ok(())
    }

    pub fn checkpoint(&self) -> Result<Vec<u8>, LinkedInConnectorError> {
        serde_json::to_vec(self).map_err(|_| LinkedInConnectorError::InvalidObservation)
    }

    pub fn from_checkpoint(bytes: &[u8]) -> Result<Self, LinkedInConnectorError> {
        let log: Self = serde_json::from_slice(bytes)
            .map_err(|_| LinkedInConnectorError::InvalidObservation)?;
        if log.schema_version != LINKEDIN_INSIGHT_READ_SCHEMA
            || log.revision != log.entries.len() as u64
        {
            return Err(LinkedInConnectorError::InvalidObservation);
        }
        for entry in &log.entries {
            entry.validate()?;
        }
        Ok(log)
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkedInConnectorError {
    InvalidRequest,
    InvalidScope,
    ScopeMismatch,
    CredentialUnavailable,
    CredentialLeaseInvalid,
    PermissionDenied,
    MissingPermission,
    Unauthorized {
        status: u16,
    },
    ProviderUnavailable {
        status: u16,
    },
    InvalidProviderResponse {
        status: u16,
    },
    PaginationUnsupported,
    ResponseParse {
        status: u16,
    },
    RateLimited {
        status: u16,
        rate_limit: LinkedInRateLimit,
    },
    Transport(LinkedInTransportError),
    InvalidObservation,
    InvalidProbe,
    InvalidPolicy,
    Budget(ConnectorError),
    NotMounted,
    ProbeStale,
    Revoked,
    RefreshDrift,
    CursorMismatch,
    CursorComplete,
    MissionMismatch,
    WritesDisabled,
    BlockedEnv {
        missing: Vec<String>,
    },
}

impl fmt::Display for LinkedInConnectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => formatter.write_str("invalid LinkedIn connector request"),
            Self::InvalidScope => {
                formatter.write_str("invalid LinkedIn member/org/page/ad-account scope")
            }
            Self::ScopeMismatch => formatter.write_str("LinkedIn scope mismatch"),
            Self::CredentialUnavailable => formatter.write_str("LinkedIn credential unavailable"),
            Self::CredentialLeaseInvalid => {
                formatter.write_str("LinkedIn credential lease invalid or revoked")
            }
            Self::PermissionDenied => formatter.write_str("LinkedIn permission denied"),
            Self::MissingPermission => formatter.write_str("LinkedIn required permission missing"),
            Self::Unauthorized { status } => write!(formatter, "LinkedIn unauthorized ({status})"),
            Self::ProviderUnavailable { status } => {
                write!(formatter, "LinkedIn unavailable ({status})")
            }
            Self::InvalidProviderResponse { status } => {
                write!(formatter, "invalid LinkedIn response ({status})")
            }
            Self::PaginationUnsupported => {
                formatter.write_str("LinkedIn insight endpoint does not support pagination")
            }
            Self::ResponseParse { status } => {
                write!(formatter, "could not parse LinkedIn response ({status})")
            }
            Self::RateLimited { status, .. } => {
                write!(formatter, "LinkedIn rate limited ({status})")
            }
            Self::Transport(error) => write!(formatter, "LinkedIn transport error: {error}"),
            Self::InvalidObservation => formatter.write_str("invalid LinkedIn observation"),
            Self::InvalidProbe => formatter.write_str("invalid LinkedIn probe observation"),
            Self::InvalidPolicy => formatter.write_str("invalid LinkedIn read policy"),
            Self::Budget(error) => write!(formatter, "LinkedIn read budget rejected: {error}"),
            Self::NotMounted => formatter.write_str("LinkedIn connection is not mounted"),
            Self::ProbeStale => formatter.write_str("LinkedIn authenticated probe is stale"),
            Self::Revoked => formatter.write_str("LinkedIn connection was revoked"),
            Self::RefreshDrift => {
                formatter.write_str("LinkedIn refresh drifted from mounted scope")
            }
            Self::CursorMismatch => formatter.write_str("LinkedIn pagination cursor mismatch"),
            Self::CursorComplete => formatter.write_str("LinkedIn pagination cursor is complete"),
            Self::MissionMismatch => formatter.write_str("LinkedIn Mission binding mismatch"),
            Self::WritesDisabled => {
                formatter.write_str("LinkedIn insight adapter writes are disabled")
            }
            Self::BlockedEnv { missing } => write!(formatter, "BLOCKED_ENV: missing {missing:?}"),
        }
    }
}

impl std::error::Error for LinkedInConnectorError {}

pub trait LinkedInInsightProvider: fmt::Debug + Send + Sync {
    fn provider_id(&self) -> &'static str;

    fn registrations(&self) -> &'static [ProviderCapabilitySupport];

    fn probe(
        &self,
        request: &LinkedInProbeRequest,
        resolver: &dyn LinkedInCredentialResolver,
    ) -> Result<LinkedInProbeObservation, LinkedInConnectorError>;

    fn read(
        &self,
        request: &LinkedInInsightReadRequest,
        resolver: &dyn LinkedInCredentialResolver,
    ) -> Result<LinkedInProviderPage, LinkedInConnectorError>;

    fn prepare_effect(&self, _operation: &str) -> Result<(), LinkedInConnectorError> {
        Err(LinkedInConnectorError::WritesDisabled)
    }
}

#[derive(Clone, Debug)]
pub struct LinkedInProviderPage {
    pub source: LinkedInRequestEvidence,
    pub records: Vec<LinkedInInsightRecord>,
    pub next_start: Option<u64>,
    pub rate_limit: LinkedInRateLimit,
    pub permission: LinkedInPermissionObservation,
    pub attribution: LinkedInAttribution,
    pub classification: LinkedInInsightTargetKind,
    pub observed_at: DateTime<Utc>,
}

impl LinkedInProviderPage {
    pub fn source(&self) -> &LinkedInRequestEvidence {
        &self.source
    }

    pub fn records(&self) -> &[LinkedInInsightRecord] {
        &self.records
    }

    pub fn next_start(&self) -> Option<u64> {
        self.next_start
    }

    pub fn rate_limit(&self) -> &LinkedInRateLimit {
        &self.rate_limit
    }

    pub fn permission(&self) -> &LinkedInPermissionObservation {
        &self.permission
    }

    pub fn attribution(&self) -> &LinkedInAttribution {
        &self.attribution
    }

    pub fn classification(&self) -> LinkedInInsightTargetKind {
        self.classification
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

#[derive(Clone, Debug)]
pub struct LinkedInMarketingOrganizationAdapter {
    pub config: LinkedInMarketingConfig,
    pub transport: Arc<dyn LinkedInHttpTransport>,
}

impl LinkedInMarketingOrganizationAdapter {
    pub fn new(
        config: LinkedInMarketingConfig,
        transport: Arc<dyn LinkedInHttpTransport>,
    ) -> Result<Self, LinkedInConnectorError> {
        config.validate()?;
        Ok(Self { config, transport })
    }

    fn request(&self, path: &str, query: Vec<(String, String)>) -> LinkedInHttpRequest {
        let base = self.config.api_base_url.trim_end_matches('/');
        let mut request = LinkedInHttpRequest::get(format!("{base}{path}")).with_query(query);
        request.set_header("Linkedin-Version", self.config.marketing_version.clone());
        request.set_header(
            "X-Restli-Protocol-Version",
            self.config.restli_protocol_version.clone(),
        );
        request.set_header("Content-Type", "application/json");
        request
    }

    fn execute_json(
        &self,
        request: &LinkedInHttpRequest,
        token: &LinkedInAccessToken,
    ) -> Result<(serde_json::Value, LinkedInHttpResponse, LinkedInRateLimit), LinkedInConnectorError>
    {
        let response = self
            .transport
            .send(request, token)
            .map_err(LinkedInConnectorError::Transport)?;
        let rate_limit = parse_rate_limit(&response);
        if response.status == 401 {
            return Err(LinkedInConnectorError::Unauthorized {
                status: response.status,
            });
        }
        if response.status == 403 {
            return Err(LinkedInConnectorError::PermissionDenied);
        }
        if response.status == 429 {
            return Err(LinkedInConnectorError::RateLimited {
                status: response.status,
                rate_limit,
            });
        }
        if response.status >= 500 {
            return Err(LinkedInConnectorError::ProviderUnavailable {
                status: response.status,
            });
        }
        if !(200..300).contains(&response.status) {
            return Err(LinkedInConnectorError::InvalidProviderResponse {
                status: response.status,
            });
        }
        let value = serde_json::from_slice(&response.body).map_err(|_| {
            LinkedInConnectorError::ResponseParse {
                status: response.status,
            }
        })?;
        Ok((value, response, rate_limit))
    }

    fn probe_plans(
        &self,
        scope: &LinkedInInsightScope,
    ) -> Vec<(String, LinkedInHttpRequest, String)> {
        let mut plans = vec![(
            "member".to_owned(),
            self.request("/v2/userinfo", Vec::new()),
            scope.member_id.clone(),
        )];
        if let Some(organization_id) = &scope.organization_id {
            plans.push((
                "organization".to_owned(),
                self.request(
                    &format!("/rest/organizations/{organization_id}"),
                    Vec::new(),
                ),
                organization_id.clone(),
            ));
        }
        if let Some(page_id) = &scope.page_id {
            plans.push((
                "page".to_owned(),
                self.request(&format!("/rest/organizations/{page_id}"), Vec::new()),
                page_id.clone(),
            ));
        }
        if let Some(ad_account_id) = &scope.ad_account_id {
            plans.push((
                "ad_account".to_owned(),
                self.request(&format!("/rest/adAccounts/{ad_account_id}"), Vec::new()),
                ad_account_id.clone(),
            ));
        }
        plans
    }

    fn validate_probe_identity(
        value: &serde_json::Value,
        expected: &str,
    ) -> Result<(), LinkedInConnectorError> {
        let observed = value
            .get("sub")
            .and_then(value_as_string)
            .or_else(|| value.get("id").and_then(value_as_string))
            .or_else(|| {
                value
                    .get("elements")
                    .and_then(serde_json::Value::as_array)
                    .and_then(|elements| elements.first())
                    .and_then(|element| element.get("id"))
                    .and_then(value_as_string)
            })
            .ok_or(LinkedInConnectorError::InvalidProviderResponse { status: 200 })?;
        if observed != expected {
            return Err(LinkedInConnectorError::ScopeMismatch);
        }
        Ok(())
    }
}

impl LinkedInInsightProvider for LinkedInMarketingOrganizationAdapter {
    fn provider_id(&self) -> &'static str {
        "linkedin"
    }

    fn registrations(&self) -> &'static [ProviderCapabilitySupport] {
        LINKEDIN_REGISTRATIONS
    }

    fn probe(
        &self,
        request: &LinkedInProbeRequest,
        resolver: &dyn LinkedInCredentialResolver,
    ) -> Result<LinkedInProbeObservation, LinkedInConnectorError> {
        request.validate()?;
        let permission = LinkedInPermissionObservation::for_scope(
            &request.scope,
            request.insight_scope.required_scopes(),
        );
        if !permission.missing_scopes.is_empty() {
            return Err(LinkedInConnectorError::MissingPermission);
        }
        let token = resolver.resolve(&request.secret_reference)?;
        let mut source = Vec::new();
        let mut observed_at = request.requested_at;
        for (_kind, http_request, expected_id) in self.probe_plans(&request.insight_scope) {
            let (value, response, _rate_limit) = self.execute_json(&http_request, &token)?;
            Self::validate_probe_identity(&value, &expected_id)?;
            observed_at = observed_at.max(response.received_at);
            source.push(request_evidence(&http_request, &response));
        }
        let expires_at = observed_at
            .checked_add_signed(Duration::seconds(120))
            .ok_or(LinkedInConnectorError::InvalidProbe)?;
        let classification = LinkedInClassification {
            kind: LinkedInInsightTargetKind::OrganizationPage,
            attribution: LinkedInAttribution {
                model: "linkedin_member_organization_scope".to_owned(),
                windows: Vec::new(),
                parameters: BTreeMap::new(),
                causal_status: LinkedInCausalStatus::NotClaimed,
            },
            review_state: permission.review_state,
            provenance: request.provenance,
            causal_status: LinkedInCausalStatus::NotClaimed,
        };
        let probe_digest = digest_serializable(&(&request.insight_scope, &source, observed_at))?;
        let observation = LinkedInProbeObservation {
            schema_version: LINKEDIN_INSIGHT_READ_SCHEMA.to_owned(),
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
            causal_status: LinkedInCausalStatus::NotClaimed,
        };
        observation.validate()?;
        Ok(observation)
    }

    fn read(
        &self,
        request: &LinkedInInsightReadRequest,
        resolver: &dyn LinkedInCredentialResolver,
    ) -> Result<LinkedInProviderPage, LinkedInConnectorError> {
        request.validate()?;
        let permission = LinkedInPermissionObservation::for_scope(
            &request.scope,
            request.insight_scope.required_scopes(),
        );
        if !permission.missing_scopes.is_empty() {
            return Err(LinkedInConnectorError::MissingPermission);
        }
        let token = resolver.resolve(&request.secret_reference)?;
        let (http_request, classification, model, parameters) = self.read_plan(request);
        let (value, response, rate_limit) = self.execute_json(&http_request, &token)?;
        if provider_reports_more_pages(&value) {
            return Err(LinkedInConnectorError::PaginationUnsupported);
        }
        let records = parse_records(&value, request.target.kind());
        let attribution = LinkedInAttribution {
            model,
            windows: Vec::new(),
            parameters,
            causal_status: LinkedInCausalStatus::NotClaimed,
        };
        Ok(LinkedInProviderPage {
            source: request_evidence(&http_request, &response),
            records,
            next_start: None,
            rate_limit,
            permission,
            attribution,
            classification,
            observed_at: response.received_at,
        })
    }
}

impl LinkedInMarketingOrganizationAdapter {
    fn read_plan(
        &self,
        request: &LinkedInInsightReadRequest,
    ) -> (
        LinkedInHttpRequest,
        LinkedInInsightTargetKind,
        String,
        BTreeMap<String, String>,
    ) {
        match &request.target {
            LinkedInInsightTarget::OrganizationPage { page_id, .. } => {
                let query = page_statistics_query(page_id, request.since, request.until);
                (
                    self.request("/rest/organizationalEntityShareStatistics", query),
                    LinkedInInsightTargetKind::OrganizationPage,
                    "linkedin_organization_share_statistics".to_owned(),
                    BTreeMap::from([("time_granularity".to_owned(), "DAY".to_owned())]),
                )
            }
            LinkedInInsightTarget::OrganizationPost {
                page_id, post_id, ..
            } => {
                let query = post_statistics_query(page_id, post_id);
                (
                    self.request("/rest/organizationalEntityShareStatistics", query),
                    LinkedInInsightTargetKind::OrganizationPost,
                    "linkedin_organization_share_statistics".to_owned(),
                    BTreeMap::from([
                        (
                            "time_window".to_owned(),
                            "provider_lifetime_only".to_owned(),
                        ),
                        ("post_filter".to_owned(), "provider_share_id".to_owned()),
                    ]),
                )
            }
            LinkedInInsightTarget::AdAccount { ad_account_id } => {
                let query = ad_analytics_query(ad_account_id, request.since, request.until);
                (
                    self.request("/rest/adAnalytics", query),
                    LinkedInInsightTargetKind::AdAccount,
                    "linkedin_ad_analytics".to_owned(),
                    BTreeMap::from([("time_granularity".to_owned(), "DAILY".to_owned())]),
                )
            }
        }
    }
}

pub struct PaidSocialInsightReadService {
    provider: Arc<dyn LinkedInInsightProvider>,
    budget: DispatchBudget,
    policy: LinkedInReadPolicy,
    state: LinkedInConnectionState,
    mount: Option<LinkedInMount>,
    cursor: Option<LinkedInPaginationCursor>,
    observation_log: DurableObservationLog,
}

impl fmt::Debug for PaidSocialInsightReadService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PaidSocialInsightReadService")
            .field("provider", &self.provider.provider_id())
            .field("state", &self.state)
            .field("mount", &self.mount)
            .field(
                "cursor",
                &self.cursor.as_ref().map(LinkedInPaginationCursor::digest),
            )
            .field("observation_log_revision", &self.observation_log.revision())
            .finish_non_exhaustive()
    }
}

impl PaidSocialInsightReadService {
    pub fn new(
        provider: Arc<dyn LinkedInInsightProvider>,
        budget: DispatchBudget,
        policy: LinkedInReadPolicy,
    ) -> Result<Self, LinkedInConnectorError> {
        if provider.provider_id() != "linkedin" || !provider.registrations().is_empty() {
            return Err(LinkedInConnectorError::InvalidRequest);
        }
        Ok(Self {
            provider,
            budget,
            policy,
            state: LinkedInConnectionState::Unmounted,
            mount: None,
            cursor: None,
            observation_log: DurableObservationLog::default(),
        })
    }

    pub fn state(&self) -> LinkedInConnectionState {
        self.state
    }

    pub fn mount(&self) -> Option<&LinkedInMount> {
        self.mount.as_ref()
    }

    pub fn provider(&self) -> &dyn LinkedInInsightProvider {
        self.provider.as_ref()
    }

    pub fn observation_log(&self) -> &DurableObservationLog {
        &self.observation_log
    }

    pub fn observation_log_checkpoint(&self) -> Result<Vec<u8>, LinkedInConnectorError> {
        self.observation_log.checkpoint()
    }

    pub fn restore_observation_log(&mut self, bytes: &[u8]) -> Result<(), LinkedInConnectorError> {
        self.observation_log = DurableObservationLog::from_checkpoint(bytes)?;
        Ok(())
    }

    pub fn probe_and_mount(
        &mut self,
        mission_id: &str,
        request: &LinkedInProbeRequest,
        resolver: &dyn LinkedInCredentialResolver,
    ) -> Result<LinkedInCapabilityProjection, LinkedInConnectorError> {
        validate_mission_id(mission_id)?;
        if self.state == LinkedInConnectionState::Revoked {
            return Err(LinkedInConnectorError::Revoked);
        }
        let observation = self.provider.probe(request, resolver)?;
        self.mount_from_probe(mission_id, request, &observation)?;
        Ok(LinkedInCapabilityProjection::from_mount(
            mission_id,
            &observation,
        ))
    }

    pub fn refresh_mount(
        &mut self,
        request: &LinkedInProbeRequest,
        observation: &LinkedInProbeObservation,
    ) -> Result<(), LinkedInConnectorError> {
        observation.validate()?;
        let mount = self
            .mount
            .as_mut()
            .ok_or(LinkedInConnectorError::NotMounted)?;
        if self.state != LinkedInConnectionState::Mounted
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
            return Err(LinkedInConnectorError::RefreshDrift);
        }
        mount.probe_digest.clone_from(&observation.probe_digest);
        mount.valid_until = observation.expires_at;
        mount.generation = mount
            .generation
            .checked_add(1)
            .ok_or(LinkedInConnectorError::RefreshDrift)?;
        Ok(())
    }

    pub fn unmount(&mut self) {
        self.mount = None;
        self.cursor = None;
        if self.state != LinkedInConnectionState::Revoked {
            self.state = LinkedInConnectionState::Unmounted;
        }
    }

    pub fn revoke(&mut self) {
        self.mount = None;
        self.cursor = None;
        self.state = LinkedInConnectionState::Revoked;
    }

    #[allow(clippy::too_many_lines)]
    pub fn read(
        &mut self,
        mission_id: &str,
        request: &LinkedInInsightReadRequest,
        resolver: &dyn LinkedInCredentialResolver,
    ) -> Result<LinkedInInsightObservation, LinkedInConnectorError> {
        validate_mission_id(mission_id)?;
        request.validate()?;
        self.ensure_mount(mission_id, request)?;
        let request_digest = request.request_digest();
        if let Some(cursor) = &self.cursor {
            cursor.validate(&request.insight_scope, &request_digest)?;
            if cursor.request_digest != request_digest {
                return Err(LinkedInConnectorError::CursorMismatch);
            }
            if cursor.complete() {
                return Err(LinkedInConnectorError::CursorComplete);
            }
            if request.cursor.as_ref().is_some_and(|value| value != cursor) {
                return Err(LinkedInConnectorError::CursorMismatch);
            }
        }
        let mut provider_request = request.clone();
        if provider_request.cursor.is_none() {
            provider_request.cursor.clone_from(&self.cursor);
        }
        let before = BudgetSnapshot::capture(&self.budget);
        self.budget
            .admit(request.requested_at, self.policy.cost_minor)
            .map_err(LinkedInConnectorError::Budget)?;
        let after = BudgetSnapshot::capture(&self.budget);

        let mut attempts = 0_u8;
        let mut last_retry_after = None;
        let page = loop {
            attempts = attempts.saturating_add(1);
            match self.provider.read(&provider_request, resolver) {
                Ok(page) => break page,
                Err(LinkedInConnectorError::RateLimited { rate_limit, .. })
                    if attempts < self.policy.max_attempts
                        && rate_limit.retry_after_seconds.is_some_and(|seconds| {
                            seconds <= self.policy.max_retry_delay_seconds
                        }) =>
                {
                    last_retry_after = rate_limit.retry_after_seconds;
                    if let Some(seconds) = last_retry_after
                        && seconds > 0
                    {
                        thread::sleep(std::time::Duration::from_secs(seconds));
                    }
                }
                Err(
                    error @ (LinkedInConnectorError::Unauthorized { .. }
                    | LinkedInConnectorError::PermissionDenied),
                ) => {
                    self.state = LinkedInConnectionState::Stale;
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        };
        let sequence = match provider_request
            .cursor
            .as_ref()
            .map(|cursor| cursor.sequence.checked_add(1))
        {
            None => 1,
            Some(Some(sequence)) => sequence,
            Some(None) => return Err(LinkedInConnectorError::InvalidObservation),
        };
        let next_cursor = page.next_start.map(|start| {
            LinkedInPaginationCursor::new(
                &request.insight_scope,
                &request_digest,
                sequence,
                start,
                false,
            )
        });
        let durable_cursor = next_cursor.clone().unwrap_or_else(|| {
            LinkedInPaginationCursor::new(
                &request.insight_scope,
                &request_digest,
                sequence,
                provider_request
                    .cursor
                    .as_ref()
                    .map_or(0, LinkedInPaginationCursor::start),
                true,
            )
        });
        let checkpoint_digest = durable_cursor.digest();
        let valid_until = page
            .observed_at
            .checked_add_signed(self.policy.freshness_ttl)
            .ok_or(LinkedInConnectorError::InvalidObservation)?;
        FreshnessWindow::new(page.observed_at, valid_until, durable_cursor.sequence())
            .map_err(|_| LinkedInConnectorError::InvalidObservation)?
            .validate_at(page.observed_at)
            .map_err(|_| LinkedInConnectorError::InvalidObservation)?;
        let content_digest = digest_serializable(&page.records)?;
        let observation_digest = digest_serializable(&(
            &request.scope,
            &request.insight_scope,
            &request.target,
            &page.source,
            &content_digest,
            page.observed_at,
        ))?;
        let cursor = LinkedInCursorReceipt {
            sequence: durable_cursor.sequence(),
            current_digest: provider_request
                .cursor
                .as_ref()
                .map(LinkedInPaginationCursor::digest),
            next_digest: next_cursor.as_ref().map(LinkedInPaginationCursor::digest),
            durable_checkpoint_digest: checkpoint_digest,
            durable_cursor: durable_cursor.clone(),
            complete: durable_cursor.complete(),
        };
        let observation = LinkedInInsightObservation {
            schema_version: LINKEDIN_INSIGHT_READ_SCHEMA.to_owned(),
            observation_id: format!("linkedin-observation-{observation_digest}"),
            mission_id: mission_id.to_owned(),
            scope: request.insight_scope.clone(),
            connector_scope_digest: request.scope.digest(),
            target: request.target.clone(),
            requested_at: request.requested_at,
            observed_at: page.observed_at,
            source: page.source.clone(),
            records: page.records,
            permission: page.permission.clone(),
            rate_limit: page.rate_limit,
            retry: LinkedInRetryReceipt {
                attempts,
                retried: attempts > 1,
                last_retry_after_seconds: last_retry_after,
                exhausted: false,
            },
            freshness: LinkedInFreshnessReceipt {
                observed_at: page.observed_at,
                valid_until,
                ttl_seconds: self.policy.freshness_ttl.num_seconds(),
                fresh_at_observation: true,
            },
            quota: LinkedInQuotaReceipt {
                configured_limit: before.quota_limit,
                used_before: before.quota_used,
                used_after: after.quota_used,
                rate_remaining_before: before.rate_remaining,
                rate_remaining_after: after.rate_remaining,
                provider_rate_limit: LinkedInRateLimit::default(),
            },
            cost: LinkedInCostReceipt {
                configured_limit_minor: before.cost_limit_minor,
                charged_minor: self.policy.cost_minor,
                used_before_minor: before.cost_used_minor,
                used_after_minor: after.cost_used_minor,
            },
            cursor,
            classification: LinkedInClassification {
                kind: page.classification,
                attribution: page.attribution,
                review_state: page.permission.review_state,
                provenance: request.provenance,
                causal_status: LinkedInCausalStatus::NotClaimed,
            },
            digests: LinkedInDigestReceipt {
                request_digest: request_digest.clone(),
                response_digest: page.source.response_digest.clone(),
                content_digest,
                observation_digest,
            },
            provenance: request.provenance,
            causal_status: LinkedInCausalStatus::NotClaimed,
        };
        let mut observation = observation;
        observation.quota.provider_rate_limit = observation.rate_limit.clone();
        observation.validate()?;
        self.observation_log.append(observation.clone())?;
        self.cursor = Some(durable_cursor);
        Ok(observation)
    }

    fn mount_from_probe(
        &mut self,
        mission_id: &str,
        request: &LinkedInProbeRequest,
        observation: &LinkedInProbeObservation,
    ) -> Result<(), LinkedInConnectorError> {
        observation.validate()?;
        if observation.scope != request.insight_scope
            || observation.connector_scope_digest != request.scope.digest()
            || observation.credential_reference_digest
                != digest_bytes(request.secret_reference.reference_id().as_bytes())
            || observation.credential_revision != request.secret_reference.credential_revision()
            || observation.lease_revision != request.lease.lease_revision()
        {
            return Err(LinkedInConnectorError::RefreshDrift);
        }
        self.mount = Some(LinkedInMount {
            mission_id: mission_id.to_owned(),
            scope_digest: request.scope.digest(),
            credential_reference_digest: observation.credential_reference_digest.clone(),
            credential_revision: observation.credential_revision,
            lease_revision: observation.lease_revision,
            probe_digest: observation.probe_digest.clone(),
            valid_until: observation.expires_at,
            generation: 1,
        });
        self.state = LinkedInConnectionState::Mounted;
        self.cursor = None;
        Ok(())
    }

    fn ensure_mount(
        &mut self,
        mission_id: &str,
        request: &LinkedInInsightReadRequest,
    ) -> Result<(), LinkedInConnectorError> {
        if self.state == LinkedInConnectionState::Revoked {
            return Err(LinkedInConnectorError::Revoked);
        }
        if self.state == LinkedInConnectionState::Stale {
            return Err(LinkedInConnectorError::ProbeStale);
        }
        let mount = self
            .mount
            .as_ref()
            .ok_or(LinkedInConnectorError::NotMounted)?;
        if self.state != LinkedInConnectionState::Mounted || mount.mission_id != mission_id {
            return Err(LinkedInConnectorError::MissionMismatch);
        }
        if request.scope.digest() != mount.scope_digest
            || digest_bytes(request.secret_reference.reference_id().as_bytes())
                != mount.credential_reference_digest
            || request.secret_reference.credential_revision() != mount.credential_revision
            || request.lease.lease_revision() != mount.lease_revision
        {
            return Err(LinkedInConnectorError::RefreshDrift);
        }
        if request.requested_at >= mount.valid_until {
            self.state = LinkedInConnectionState::Stale;
            return Err(LinkedInConnectorError::ProbeStale);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkedInCapabilityProjection {
    pub mission_id: String,
    pub capability: MissionCapability,
    pub provider_id: String,
    pub scope_digest: String,
    pub connection_state: LinkedInConnectionState,
    pub probe_digest: String,
    pub granted_at: DateTime<Utc>,
}

impl LinkedInCapabilityProjection {
    fn from_mount(mission_id: &str, observation: &LinkedInProbeObservation) -> Self {
        Self {
            mission_id: mission_id.to_owned(),
            capability: MissionCapability::PaidSocialInsightRead,
            provider_id: "linkedin".to_owned(),
            scope_digest: observation.connector_scope_digest.clone(),
            connection_state: LinkedInConnectionState::Mounted,
            probe_digest: observation.probe_digest.clone(),
            granted_at: observation.observed_at,
        }
    }
}

#[derive(Debug)]
pub struct MissionPaidSocialInsightConsumer {
    service: PaidSocialInsightReadService,
    capability: Option<MissionCapabilityGrant>,
}

impl MissionPaidSocialInsightConsumer {
    pub fn new(service: PaidSocialInsightReadService) -> Self {
        Self {
            service,
            capability: None,
        }
    }

    pub fn service(&self) -> &PaidSocialInsightReadService {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut PaidSocialInsightReadService {
        &mut self.service
    }

    pub fn capability(&self) -> Option<&MissionCapabilityGrant> {
        self.capability.as_ref()
    }

    pub fn attach(
        &mut self,
        mission_id: &str,
        request: &LinkedInProbeRequest,
        resolver: &dyn LinkedInCredentialResolver,
    ) -> Result<MissionCapabilityGrant, LinkedInConnectorError> {
        let projection = self
            .service
            .probe_and_mount(mission_id, request, resolver)?;
        let grant = MissionCapabilityGrant {
            mission_id: projection.mission_id,
            capability: projection.capability,
            provider_id: projection.provider_id,
            scope_digest: projection.scope_digest,
            connection_state: projection.connection_state,
            probe_digest: projection.probe_digest,
            granted_at: projection.granted_at,
        };
        self.capability = Some(grant.clone());
        Ok(grant)
    }

    pub fn read(
        &mut self,
        mission_id: &str,
        request: &LinkedInInsightReadRequest,
        resolver: &dyn LinkedInCredentialResolver,
    ) -> Result<MissionInsightResult, LinkedInConnectorError> {
        let grant = self
            .capability
            .as_ref()
            .ok_or(LinkedInConnectorError::NotMounted)?;
        if grant.mission_id != mission_id {
            return Err(LinkedInConnectorError::MissionMismatch);
        }
        if grant.connection_state == LinkedInConnectionState::Stale {
            return Err(LinkedInConnectorError::ProbeStale);
        }
        if grant.connection_state != LinkedInConnectionState::Mounted {
            return Err(LinkedInConnectorError::MissionMismatch);
        }
        let observation = match self.service.read(mission_id, request, resolver) {
            Ok(observation) => observation,
            Err(error) => {
                if self.service.state() == LinkedInConnectionState::Stale
                    && let Some(capability) = self.capability.as_mut()
                {
                    capability.connection_state = LinkedInConnectionState::Stale;
                }
                return Err(error);
            }
        };
        Ok(MissionInsightResult {
            mission_id: mission_id.to_owned(),
            capability: MissionCapability::PaidSocialInsightRead,
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

pub fn env_gated_credentialed_probe(
    adapter: &LinkedInMarketingOrganizationAdapter,
    request: &LinkedInProbeRequest,
) -> Result<LinkedInProbeObservation, LinkedInConnectorError> {
    let mut missing = Vec::new();
    if std::env::var(LINKEDIN_RUN_PROBE_ENV).ok().as_deref() != Some("1") {
        missing.push(LINKEDIN_RUN_PROBE_ENV.to_owned());
    }
    if std::env::var(LINKEDIN_ACCESS_TOKEN_ENV)
        .ok()
        .is_none_or(|value| value.trim().is_empty())
    {
        missing.push(LINKEDIN_ACCESS_TOKEN_ENV.to_owned());
    }
    if !missing.is_empty() {
        return Err(LinkedInConnectorError::BlockedEnv { missing });
    }
    adapter.probe(request, &EnvLinkedInCredentialResolver::default())
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

fn page_statistics_query(
    page_id: &str,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
) -> Vec<(String, String)> {
    vec![
        ("q".to_owned(), "organizationalEntity".to_owned()),
        (
            "organizationalEntity".to_owned(),
            format!("urn:li:organization:{page_id}"),
        ),
        (
            "timeIntervals".to_owned(),
            format!(
                "(timeRange:(start:{},end:{}),timeGranularityType:DAY)",
                since.timestamp_millis(),
                until.timestamp_millis()
            ),
        ),
    ]
}

fn post_statistics_query(page_id: &str, post_id: &str) -> Vec<(String, String)> {
    vec![
        ("q".to_owned(), "organizationalEntity".to_owned()),
        (
            "organizationalEntity".to_owned(),
            format!("urn:li:organization:{page_id}"),
        ),
        ("shares".to_owned(), format!("List(urn:li:share:{post_id})")),
    ]
}

fn ad_analytics_query(
    ad_account_id: &str,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
) -> Vec<(String, String)> {
    vec![
        ("q".to_owned(), "analytics".to_owned()),
        ("pivot".to_owned(), "ACCOUNT".to_owned()),
        (
            "accounts".to_owned(),
            format!("List(urn:li:sponsoredAccount:{ad_account_id})"),
        ),
        (
            "dateRange".to_owned(),
            format!(
                "(start:(year:{},month:{},day:{}),end:(year:{},month:{},day:{}))",
                since.format("%Y"),
                since.format("%-m"),
                since.format("%-d"),
                until.format("%Y"),
                until.format("%-m"),
                until.format("%-d")
            ),
        ),
        ("timeGranularity".to_owned(), "DAILY".to_owned()),
    ]
}

fn parse_records(
    value: &serde_json::Value,
    kind: LinkedInInsightTargetKind,
) -> Vec<LinkedInInsightRecord> {
    let values = value
        .get("elements")
        .or_else(|| value.get("results"))
        .or_else(|| value.get("data"))
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    values
        .iter()
        .filter_map(|value| value.as_object())
        .map(|object| {
            let mut dimensions = BTreeMap::new();
            let mut metrics = BTreeMap::new();
            let mut provider_fields_digest = BTreeMap::new();
            for (key, value) in object {
                if is_linkedin_metric_field(key) {
                    match value {
                        serde_json::Value::Number(number) => {
                            let metric = number.as_i64().map_or_else(
                                || LinkedInMetricValue::Decimal(number.to_string()),
                                LinkedInMetricValue::Integer,
                            );
                            metrics.insert(key.clone(), metric);
                        }
                        serde_json::Value::Bool(value) => {
                            metrics.insert(key.clone(), LinkedInMetricValue::Boolean(*value));
                        }
                        serde_json::Value::Null => {
                            metrics.insert(key.clone(), LinkedInMetricValue::Null);
                        }
                        serde_json::Value::String(value) => {
                            metrics.insert(key.clone(), LinkedInMetricValue::String(value.clone()));
                        }
                        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                            provider_fields_digest.insert(key.clone(), digest_json(value));
                        }
                    }
                } else if is_linkedin_dimension_field(key) {
                    if let Some(value) = value_as_string(value) {
                        dimensions.insert(key.clone(), value);
                    } else {
                        provider_fields_digest.insert(key.clone(), digest_json(value));
                    }
                } else {
                    provider_fields_digest.insert(key.clone(), digest_json(value));
                }
            }
            let external_id = ["id", "share", "ugcPost", "pivotValue", "pivotValues"]
                .iter()
                .find_map(|key| object.get(*key).and_then(value_as_string));
            let period = ["dateRange", "date", "timeRange"]
                .iter()
                .find_map(|key| object.get(*key).and_then(value_as_string));
            LinkedInInsightRecord {
                kind,
                external_id,
                period,
                dimensions,
                metrics,
                provider_fields_digest,
            }
        })
        .collect()
}

fn is_linkedin_metric_field(key: &str) -> bool {
    matches!(
        key,
        "clickCount"
            | "commentCount"
            | "engagement"
            | "impressionCount"
            | "likeCount"
            | "shareCount"
            | "uniqueImpressionsCount"
            | "impressions"
            | "clicks"
            | "landingPageClicks"
            | "likes"
            | "comments"
            | "shares"
            | "follows"
            | "totalEngagements"
            | "costInLocalCurrency"
            | "conversionValueInLocalCurrency"
            | "conversions"
            | "externalWebsiteConversions"
            | "oneClickLeads"
            | "approximateMemberReach"
            | "videoViews"
            | "videoWatchTime"
            | "averageVideoWatchTime"
            | "cardClicks"
            | "cardImpressions"
            | "viralCardClicks"
            | "viralCardImpressions"
    )
}

fn is_linkedin_dimension_field(key: &str) -> bool {
    matches!(
        key,
        "id" | "share"
            | "ugcPost"
            | "pivot"
            | "pivotValue"
            | "pivotValues"
            | "date"
            | "dateRange"
            | "timeRange"
            | "organizationalEntity"
            | "account"
            | "campaign"
            | "creative"
            | "currency"
    )
}

fn provider_reports_more_pages(value: &serde_json::Value) -> bool {
    let Some(paging) = value.get("paging") else {
        return false;
    };
    let start = paging
        .get("start")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let count = paging
        .get("count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let total = paging.get("total").and_then(serde_json::Value::as_u64);
    let next = start.saturating_add(count);
    total.is_some_and(|total| next < total)
}

fn request_evidence(
    request: &LinkedInHttpRequest,
    response: &LinkedInHttpResponse,
) -> LinkedInRequestEvidence {
    LinkedInRequestEvidence {
        method: request.method.clone(),
        path: request.path().unwrap_or_else(|_| "/invalid".to_owned()),
        query_digest: request.query_digest(),
        status: response.status,
        provider_request_id: ["x-restli-id", "x-li-request-id", "x-request-id"]
            .iter()
            .find_map(|name| response.headers.get(*name).cloned()),
        response_digest: digest_bytes(&response.body),
    }
}

fn parse_rate_limit(response: &LinkedInHttpResponse) -> LinkedInRateLimit {
    let reset_at = response
        .headers
        .get("x-ratelimit-reset")
        .and_then(|value| value.parse::<i64>().ok())
        .and_then(|value| DateTime::from_timestamp(value, 0));
    let rate_limit = LinkedInRateLimit {
        limit: parse_u64_header(&response.headers, "x-ratelimit-limit"),
        remaining: parse_u64_header(&response.headers, "x-ratelimit-remaining"),
        reset_at,
        retry_after_seconds: parse_u64_header(&response.headers, "retry-after"),
        ..LinkedInRateLimit::default()
    };
    let mut rate_limit = rate_limit;
    for name in [
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "retry-after",
    ] {
        if response.headers.contains_key(name) {
            rate_limit.evidence_headers.insert(name.to_owned());
        }
    }
    rate_limit
}

fn parse_u64_header(headers: &BTreeMap<String, String>, name: &str) -> Option<u64> {
    headers.get(name).and_then(|value| value.parse().ok())
}

fn parse_curl_headers(
    stderr: &[u8],
) -> Result<(u16, BTreeMap<String, String>), LinkedInTransportError> {
    let text = String::from_utf8_lossy(stderr);
    let mut status = None;
    let mut headers = BTreeMap::new();
    for line in text.lines() {
        if line.starts_with("HTTP/") {
            status = line
                .split_whitespace()
                .nth(1)
                .and_then(|value| value.parse().ok());
            headers.clear();
        } else if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            if !name.is_empty() {
                headers.insert(name, value.trim().to_owned());
            }
        }
    }
    status.map_or(Err(LinkedInTransportError::InvalidResponse), |status| {
        Ok((status, headers))
    })
}

fn validate_https_url(value: &str) -> Result<(), LinkedInConnectorError> {
    let authority = value
        .strip_prefix("https://")
        .ok_or(LinkedInConnectorError::InvalidRequest)?;
    if authority.is_empty()
        || authority.starts_with('/')
        || authority.contains(['#', '\r', '\n'])
        || authority.split('/').next().is_none_or(str::is_empty)
    {
        return Err(LinkedInConnectorError::InvalidRequest);
    }
    Ok(())
}

fn validate_provider_id(value: &str) -> Result<(), LinkedInConnectorError> {
    if value.trim().is_empty()
        || value.len() > 256
        || value.chars().any(char::is_control)
        || value
            .chars()
            .any(|character| !character.is_ascii_alphanumeric() && !matches!(character, '-' | '_'))
    {
        return Err(LinkedInConnectorError::InvalidScope);
    }
    Ok(())
}

fn validate_mission_id(value: &str) -> Result<(), LinkedInConnectorError> {
    if value.trim().is_empty()
        || value.len() > 128
        || value
            .chars()
            .any(|character| !character.is_ascii_alphanumeric() && !matches!(character, '-' | '_'))
    {
        return Err(LinkedInConnectorError::MissionMismatch);
    }
    Ok(())
}

fn value_as_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn encode_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(*byte as char);
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn escape_curl_config(value: &str) -> Zeroizing<String> {
    Zeroizing::new(value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn digest_serializable<T: Serialize>(value: &T) -> Result<String, LinkedInConnectorError> {
    serde_json::to_vec(value)
        .map(|bytes| digest_bytes(&bytes))
        .map_err(|_| LinkedInConnectorError::InvalidObservation)
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

fn digest_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_encode(&digest)
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
    use std::sync::Mutex;

    #[derive(Debug)]
    struct MockTransport {
        responses: Mutex<VecDeque<Result<LinkedInHttpResponse, LinkedInTransportError>>>,
        requests: Mutex<Vec<LinkedInHttpRequest>>,
        token_digests: Mutex<Vec<String>>,
    }

    impl MockTransport {
        fn new(responses: impl IntoIterator<Item = LinkedInHttpResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().map(Ok).collect()),
                requests: Mutex::new(Vec::new()),
                token_digests: Mutex::new(Vec::new()),
            }
        }

        fn push(&self, response: LinkedInHttpResponse) {
            self.responses
                .lock()
                .expect("responses")
                .push_back(Ok(response));
        }
    }

    impl LinkedInHttpTransport for MockTransport {
        fn send(
            &self,
            request: &LinkedInHttpRequest,
            token: &LinkedInAccessToken,
        ) -> Result<LinkedInHttpResponse, LinkedInTransportError> {
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
                .unwrap_or(Err(LinkedInTransportError::InvalidResponse))
        }
    }

    fn response(body: &str, headers: &[(&str, &str)]) -> LinkedInHttpResponse {
        LinkedInHttpResponse {
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
        LinkedInInsightScope,
        SecretReference,
        CredentialLease,
        InMemoryLinkedInCredentialResolver,
    ) {
        let scope = ConnectorScope::new(
            "tenant-1",
            "project-1",
            "linkedin",
            "member-1",
            scopes.iter().map(|scope| (*scope).to_owned()),
        )
        .expect("connector scope");
        let insight_scope = LinkedInInsightScope::new(
            "member-1",
            Some("org-1".to_owned()),
            Some("page-1".to_owned()),
            Some("ad-1".to_owned()),
        )
        .expect("insight scope");
        let secret = SecretReference::new("secret-ref-linkedin", scope.clone(), 1)
            .expect("secret reference");
        let lease = ConnectorAuth::issue_credential_lease(
            &secret,
            ProviderAdapterIdentity::new(LINKEDIN_ADAPTER_ID, LINKEDIN_ADAPTER_VERSION)
                .expect("adapter identity"),
            "lease-linkedin",
            1,
            Utc::now() - Duration::seconds(1),
            Utc::now() + Duration::minutes(5),
        )
        .expect("lease");
        let mut resolver = InMemoryLinkedInCredentialResolver::default();
        resolver
            .insert(&secret, "linkedin-test-token")
            .expect("token");
        (scope, insight_scope, secret, lease, resolver)
    }

    fn probe_request(
        scope: ConnectorScope,
        insight_scope: LinkedInInsightScope,
        secret_reference: SecretReference,
        lease: CredentialLease,
    ) -> LinkedInProbeRequest {
        LinkedInProbeRequest {
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
        insight_scope: LinkedInInsightScope,
        secret_reference: SecretReference,
        lease: CredentialLease,
        target: LinkedInInsightTarget,
    ) -> LinkedInInsightReadRequest {
        let now = Utc::now();
        LinkedInInsightReadRequest {
            scope,
            insight_scope,
            secret_reference,
            lease,
            target,
            since: now - Duration::days(1),
            until: now,
            page_size: 2,
            cursor: None,
            requested_at: now,
            provenance: ProviderProvenanceClass::ComponentHarness,
        }
    }

    fn probe_responses() -> Vec<LinkedInHttpResponse> {
        vec![
            response(r#"{"id":"member-1"}"#, &[("x-li-request-id", "member")]),
            response(r#"{"id":"org-1"}"#, &[("x-li-request-id", "org")]),
            response(r#"{"id":"page-1"}"#, &[("x-li-request-id", "page")]),
            response(r#"{"id":"ad-1"}"#, &[("x-li-request-id", "ad")]),
        ]
    }

    fn service(
        transport: Arc<MockTransport>,
        policy: LinkedInReadPolicy,
    ) -> PaidSocialInsightReadService {
        let now = Utc::now();
        PaidSocialInsightReadService::new(
            Arc::new(
                LinkedInMarketingOrganizationAdapter::new(
                    LinkedInMarketingConfig {
                        api_base_url: "https://linkedin.example.test".to_owned(),
                        ..LinkedInMarketingConfig::default()
                    },
                    transport,
                )
                .expect("adapter"),
            ),
            DispatchBudget::new(4, now + Duration::hours(1), 4, 100).expect("budget"),
            policy,
        )
        .expect("service")
    }

    #[test]
    fn provider_contract_is_empty_and_writes_are_disabled() {
        let transport = Arc::new(MockTransport::new([response("{}", &[])]));
        let adapter = LinkedInMarketingOrganizationAdapter::new(
            LinkedInMarketingConfig::default(),
            transport,
        )
        .expect("adapter");
        assert!(adapter.registrations().is_empty());
        assert_eq!(adapter.provider_id(), "linkedin");
        assert_eq!(
            adapter
                .prepare_effect("organization.post")
                .expect_err("writes"),
            LinkedInConnectorError::WritesDisabled
        );
    }

    #[test]
    fn permission_preflight_rejects_before_credential_or_transport() {
        let transport = Arc::new(MockTransport::new([response("{}", &[])]));
        let adapter = LinkedInMarketingOrganizationAdapter::new(
            LinkedInMarketingConfig::default(),
            transport.clone(),
        )
        .expect("adapter");
        let (scope, insight_scope, secret, lease, _resolver) = scope_and_auth(&["openid"]);
        let request = probe_request(scope, insight_scope, secret, lease);
        assert_eq!(
            adapter
                .probe(&request, &InMemoryLinkedInCredentialResolver::default())
                .expect_err("missing permission"),
            LinkedInConnectorError::MissingPermission
        );
        assert!(transport.requests.lock().expect("requests").is_empty());
    }

    #[test]
    fn probe_binds_member_organization_page_and_ad_account_scope() {
        let transport = Arc::new(MockTransport::new(probe_responses()));
        let adapter = LinkedInMarketingOrganizationAdapter::new(
            LinkedInMarketingConfig {
                api_base_url: "https://linkedin.example.test".to_owned(),
                ..LinkedInMarketingConfig::default()
            },
            transport.clone(),
        )
        .expect("adapter");
        let (scope, insight_scope, secret, lease, resolver) = scope_and_auth(&[
            "openid",
            "profile",
            "rw_organization_admin",
            "r_organization_social",
            "r_ads",
            "r_ads_reporting",
        ]);
        let observation = adapter
            .probe(
                &probe_request(scope, insight_scope.clone(), secret, lease),
                &resolver,
            )
            .expect("probe");
        assert_eq!(observation.status, ProbeStatus::Reachable);
        assert_eq!(observation.source.len(), 4);
        assert_eq!(observation.scope.member_id(), "member-1");
        assert_eq!(observation.scope.organization_id(), Some("org-1"));
        assert_eq!(observation.scope.page_id(), Some("page-1"));
        assert_eq!(observation.scope.ad_account_id(), Some("ad-1"));
        assert!(is_digest(&observation.probe_digest));
        let requests = transport.requests.lock().expect("requests");
        assert_eq!(requests[0].path().expect("path"), "/v2/userinfo");
        assert_eq!(
            requests[1].path().expect("path"),
            "/rest/organizations/org-1"
        );
        assert_eq!(
            requests[2].path().expect("path"),
            "/rest/organizations/page-1"
        );
        assert_eq!(requests[3].path().expect("path"), "/rest/adAccounts/ad-1");
        assert!(requests[0].headers.contains_key("Linkedin-Version"));
        assert_eq!(transport.token_digests.lock().expect("token").len(), 4);
        let _ = insight_scope;
    }

    #[test]
    fn mission_consumer_returns_adoptable_read_and_durable_logged_receipt() {
        let read_response = response(
            r#"{"elements":[{"id":"share-1","date":"2026-08-13","impressions":12,"clicks":3,"nested":{"private":"not persisted"}}],"paging":{"start":0,"count":1,"total":1}}"#,
            &[
                ("x-li-request-id", "read-1"),
                ("x-ratelimit-limit", "100"),
                ("x-ratelimit-remaining", "99"),
                ("x-ratelimit-reset", "1893456000"),
            ],
        );
        let transport = Arc::new(MockTransport::new(
            probe_responses().into_iter().chain([read_response]),
        ));
        let (scope, insight_scope, secret, lease, resolver) = scope_and_auth(&[
            "openid",
            "profile",
            "rw_organization_admin",
            "r_organization_social",
            "r_ads",
            "r_ads_reporting",
        ]);
        let probe = probe_request(
            scope.clone(),
            insight_scope.clone(),
            secret.clone(),
            lease.clone(),
        );
        let request = read_request(
            scope,
            insight_scope,
            secret,
            lease,
            LinkedInInsightTarget::OrganizationPage {
                organization_id: "org-1".to_owned(),
                page_id: "page-1".to_owned(),
            },
        );
        let mut consumer = MissionPaidSocialInsightConsumer::new(service(
            transport.clone(),
            LinkedInReadPolicy::default(),
        ));
        let grant = consumer
            .attach("mission-linkedin-1", &probe, &resolver)
            .expect("attach");
        assert_eq!(grant.capability, MissionCapability::PaidSocialInsightRead);
        assert_eq!(grant.connection_state, LinkedInConnectionState::Mounted);
        let result = consumer
            .read("mission-linkedin-1", &request, &resolver)
            .expect("read");
        assert_eq!(result.observation.records.len(), 1);
        assert_eq!(
            result.observation.source.provider_request_id.as_deref(),
            Some("read-1")
        );
        assert_eq!(
            result.observation.classification.attribution.model,
            "linkedin_organization_share_statistics"
        );
        assert_eq!(
            result.observation.causal_status,
            LinkedInCausalStatus::NotClaimed
        );
        assert_eq!(result.observation.quota.used_after, 1);
        assert_eq!(result.observation.cost.charged_minor, 1);
        assert_eq!(result.durable_log_revision, 1);
        let checkpoint = consumer
            .service()
            .observation_log_checkpoint()
            .expect("checkpoint");
        let restored = DurableObservationLog::from_checkpoint(&checkpoint).expect("restore");
        assert_eq!(restored.revision(), 1);
        let serialized = String::from_utf8(checkpoint).expect("utf8");
        assert!(!serialized.contains("private"));
        assert!(!serialized.contains("linkedin-test-token"));
    }

    #[test]
    fn post_and_ad_reads_preserve_native_provider_models() {
        let transport = Arc::new(MockTransport::new([
            response(
                r#"{"elements":[{"share":"urn:li:share:post-1","clickCount":2}]}"#,
                &[],
            ),
            response(
                r#"{"elements":[{"pivotValue":"urn:li:sponsoredAccount:ad-1","impressions":4}]}"#,
                &[],
            ),
        ]));
        let adapter = LinkedInMarketingOrganizationAdapter::new(
            LinkedInMarketingConfig {
                api_base_url: "https://linkedin.example.test".to_owned(),
                ..LinkedInMarketingConfig::default()
            },
            transport.clone(),
        )
        .expect("adapter");
        let (scope, insight_scope, secret, lease, resolver) = scope_and_auth(&[
            "openid",
            "profile",
            "rw_organization_admin",
            "r_organization_social",
            "r_ads",
            "r_ads_reporting",
        ]);
        let post_request = read_request(
            scope.clone(),
            insight_scope.clone(),
            secret.clone(),
            lease.clone(),
            LinkedInInsightTarget::OrganizationPost {
                organization_id: "org-1".to_owned(),
                page_id: "page-1".to_owned(),
                post_id: "post-1".to_owned(),
            },
        );
        let post = adapter.read(&post_request, &resolver).expect("post read");
        assert_eq!(
            post.attribution.model,
            "linkedin_organization_share_statistics"
        );
        assert_eq!(
            post.attribution.parameters.get("time_window"),
            Some(&"provider_lifetime_only".to_owned())
        );
        let ad_request = read_request(
            scope,
            insight_scope,
            secret,
            lease,
            LinkedInInsightTarget::AdAccount {
                ad_account_id: "ad-1".to_owned(),
            },
        );
        let ad = adapter.read(&ad_request, &resolver).expect("ad read");
        assert_eq!(ad.attribution.model, "linkedin_ad_analytics");
        let requests = transport.requests.lock().expect("requests");
        assert_eq!(
            requests[0].path().expect("post path"),
            "/rest/organizationalEntityShareStatistics"
        );
        assert!(
            requests[0]
                .query
                .iter()
                .any(|(name, value)| name == "shares" && value == "List(urn:li:share:post-1)")
        );
        assert!(
            !requests[0]
                .query
                .iter()
                .any(|(name, _)| name.starts_with("timeIntervals"))
        );
        assert_eq!(requests[1].path().expect("ad path"), "/rest/adAnalytics");
        assert!(requests[1].query.iter().any(
            |(name, value)| name == "accounts" && value == "List(urn:li:sponsoredAccount:ad-1)"
        ));
    }

    #[test]
    fn cursor_is_durable_and_scope_bound() {
        let first = response(
            r#"{"elements":[{"id":"share-1","impressions":1}],"paging":{"start":0,"count":1,"total":1}}"#,
            &[],
        );
        let transport = Arc::new(MockTransport::new(
            probe_responses().into_iter().chain([first]),
        ));
        let (scope, insight_scope, secret, lease, resolver) = scope_and_auth(&[
            "openid",
            "profile",
            "rw_organization_admin",
            "r_organization_social",
            "r_ads",
            "r_ads_reporting",
        ]);
        let probe = probe_request(
            scope.clone(),
            insight_scope.clone(),
            secret.clone(),
            lease.clone(),
        );
        let request = read_request(
            scope.clone(),
            insight_scope.clone(),
            secret.clone(),
            lease.clone(),
            LinkedInInsightTarget::OrganizationPage {
                organization_id: "org-1".to_owned(),
                page_id: "page-1".to_owned(),
            },
        );
        let mut consumer = MissionPaidSocialInsightConsumer::new(service(
            transport.clone(),
            LinkedInReadPolicy::default(),
        ));
        consumer
            .attach("mission-linkedin-1", &probe, &resolver)
            .expect("attach");
        let first_result = consumer
            .read("mission-linkedin-1", &request, &resolver)
            .expect("first read");
        assert_eq!(first_result.observation.cursor.sequence, 1);
        assert!(first_result.observation.cursor.complete);
        assert!(first_result.observation.cursor.durable_cursor.complete());
        let requests = transport.requests.lock().expect("requests");
        assert_eq!(requests.len(), 5);
        assert!(
            !requests[4]
                .query
                .iter()
                .any(|(name, _)| name == "start" || name == "count")
        );

        let mut wrong = request.clone();
        wrong.target = LinkedInInsightTarget::OrganizationPage {
            organization_id: "org-1".to_owned(),
            page_id: "page-other".to_owned(),
        };
        assert_eq!(
            consumer
                .read("mission-linkedin-1", &wrong, &resolver)
                .expect_err("scope mismatch"),
            LinkedInConnectorError::ScopeMismatch
        );
        assert_eq!(
            consumer
                .read("mission-linkedin-1", &request, &resolver)
                .expect_err("complete provider cursor"),
            LinkedInConnectorError::CursorComplete
        );
    }

    #[test]
    fn rate_limit_retry_is_bounded_and_header_typed() {
        let rate_limited = LinkedInHttpResponse {
            status: 429,
            headers: BTreeMap::from([
                ("retry-after".to_owned(), "0".to_owned()),
                ("x-ratelimit-remaining".to_owned(), "0".to_owned()),
            ]),
            body: br#"{"message":"slow down"}"#.to_vec(),
            received_at: Utc::now(),
        };
        let transport = Arc::new(MockTransport::new(probe_responses()));
        transport.push(rate_limited);
        transport.push(response(
            r#"{"elements":[{"impressions":2}],"paging":{"start":0,"count":1,"total":1}}"#,
            &[],
        ));
        let (scope, insight_scope, secret, lease, resolver) = scope_and_auth(&[
            "openid",
            "profile",
            "rw_organization_admin",
            "r_organization_social",
            "r_ads",
            "r_ads_reporting",
        ]);
        let probe = probe_request(
            scope.clone(),
            insight_scope.clone(),
            secret.clone(),
            lease.clone(),
        );
        let request = read_request(
            scope,
            insight_scope,
            secret,
            lease,
            LinkedInInsightTarget::OrganizationPage {
                organization_id: "org-1".to_owned(),
                page_id: "page-1".to_owned(),
            },
        );
        let mut consumer = MissionPaidSocialInsightConsumer::new(service(
            transport.clone(),
            LinkedInReadPolicy::new(Duration::minutes(15), 1, 2, 0).expect("policy"),
        ));
        consumer
            .attach("mission-linkedin-1", &probe, &resolver)
            .expect("attach");
        let result = consumer
            .read("mission-linkedin-1", &request, &resolver)
            .expect("retry read");
        assert_eq!(result.observation.retry.attempts, 2);
        assert!(result.observation.retry.retried);
        assert_eq!(result.observation.retry.last_retry_after_seconds, Some(0));
        let requests = transport.requests.lock().expect("requests");
        assert_eq!(requests.len(), 6);
    }

    #[test]
    fn provider_unauthorized_stales_the_mounted_mission_capability() {
        let unauthorized = LinkedInHttpResponse {
            status: 401,
            headers: BTreeMap::new(),
            body: br#"{"message":"token revoked"}"#.to_vec(),
            received_at: Utc::now(),
        };
        let transport = Arc::new(MockTransport::new(
            probe_responses().into_iter().chain([unauthorized]),
        ));
        let (scope, insight_scope, secret, lease, resolver) = scope_and_auth(&[
            "openid",
            "profile",
            "rw_organization_admin",
            "r_organization_social",
            "r_ads",
            "r_ads_reporting",
        ]);
        let probe = probe_request(
            scope.clone(),
            insight_scope.clone(),
            secret.clone(),
            lease.clone(),
        );
        let request = read_request(
            scope,
            insight_scope,
            secret,
            lease,
            LinkedInInsightTarget::OrganizationPage {
                organization_id: "org-1".to_owned(),
                page_id: "page-1".to_owned(),
            },
        );
        let mut consumer = MissionPaidSocialInsightConsumer::new(service(
            transport,
            LinkedInReadPolicy::default(),
        ));
        consumer
            .attach("mission-linkedin-1", &probe, &resolver)
            .expect("attach");
        assert_eq!(
            consumer
                .read("mission-linkedin-1", &request, &resolver)
                .expect_err("unauthorized"),
            LinkedInConnectorError::Unauthorized { status: 401 }
        );
        assert_eq!(consumer.service().state(), LinkedInConnectionState::Stale);
        assert_eq!(
            consumer.capability().expect("capability").connection_state,
            LinkedInConnectionState::Stale
        );
        assert_eq!(
            consumer
                .read("mission-linkedin-1", &request, &resolver)
                .expect_err("stale probe"),
            LinkedInConnectorError::ProbeStale
        );
    }

    #[test]
    fn revocation_unmount_and_refresh_drift_fail_closed() {
        let transport = Arc::new(MockTransport::new(
            probe_responses()
                .into_iter()
                .chain(probe_responses())
                .chain(probe_responses()),
        ));
        let (scope, insight_scope, secret, lease, resolver) = scope_and_auth(&[
            "openid",
            "profile",
            "rw_organization_admin",
            "r_organization_social",
            "r_ads",
            "r_ads_reporting",
        ]);
        let probe = probe_request(
            scope.clone(),
            insight_scope.clone(),
            secret.clone(),
            lease.clone(),
        );
        let request = read_request(
            scope.clone(),
            insight_scope.clone(),
            secret.clone(),
            lease.clone(),
            LinkedInInsightTarget::OrganizationPage {
                organization_id: "org-1".to_owned(),
                page_id: "page-1".to_owned(),
            },
        );
        let mut consumer = MissionPaidSocialInsightConsumer::new(service(
            transport,
            LinkedInReadPolicy::default(),
        ));
        let probe_observation = consumer
            .service()
            .provider()
            .probe(&probe, &resolver)
            .expect("probe");
        consumer
            .attach("mission-linkedin-1", &probe, &resolver)
            .expect("attach");
        let mut refreshed = probe_observation.clone();
        refreshed.scope = LinkedInInsightScope::new(
            "member-2",
            Some("org-1".to_owned()),
            Some("page-1".to_owned()),
            Some("ad-1".to_owned()),
        )
        .expect("drifted scope");
        assert_eq!(
            consumer
                .service_mut()
                .refresh_mount(&probe, &refreshed)
                .expect_err("refresh drift"),
            LinkedInConnectorError::RefreshDrift
        );
        consumer.unmount();
        assert_eq!(
            consumer
                .read("mission-linkedin-1", &request, &resolver)
                .expect_err("unmounted"),
            LinkedInConnectorError::NotMounted
        );
        consumer
            .attach("mission-linkedin-1", &probe, &resolver)
            .expect("reattach");
        consumer.revoke();
        assert_eq!(
            consumer
                .read("mission-linkedin-1", &request, &resolver)
                .expect_err("revoked"),
            LinkedInConnectorError::NotMounted
        );
        assert_eq!(consumer.service().state(), LinkedInConnectionState::Revoked);

        let mut revoked_secret = secret;
        revoked_secret
            .revoke(Utc::now())
            .expect("revoke secret reference");
        let mut revoked_request = request;
        revoked_request.secret_reference = revoked_secret;
        assert_eq!(
            revoked_request.validate().expect_err("revoked credential"),
            LinkedInConnectorError::CredentialLeaseInvalid
        );
    }

    #[test]
    fn live_probe_is_explicitly_blocked_without_credentials() {
        let adapter = LinkedInMarketingOrganizationAdapter::new(
            LinkedInMarketingConfig::default(),
            Arc::new(MockTransport::new([])),
        )
        .expect("adapter");
        let (scope, insight_scope, secret, lease, _resolver) = scope_and_auth(&[
            "openid",
            "profile",
            "rw_organization_admin",
            "r_organization_social",
            "r_ads",
            "r_ads_reporting",
        ]);
        let request = probe_request(scope, insight_scope, secret, lease);
        if std::env::var(LINKEDIN_RUN_PROBE_ENV).ok().as_deref() != Some("1")
            || std::env::var(LINKEDIN_ACCESS_TOKEN_ENV)
                .ok()
                .is_none_or(|value| value.trim().is_empty())
        {
            assert!(matches!(
                env_gated_credentialed_probe(&adapter, &request),
                Err(LinkedInConnectorError::BlockedEnv { .. })
            ));
        }
    }
}
