//! Provider-accurate, read-first connector contracts.
//!
//! This crate deliberately stops at a normalized observation boundary. It does not
//! contain a write executor, and it never turns a provider's reported conversion
//! or engagement metric into a causal business outcome.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::http::HttpTransportError;
use crate::paid_social::PaidSocialProvider;
pub use crate::{ConnectorScope, CredentialLease, SecretReference};

pub const READ_OBSERVATION_SCHEMA: &str = "hartevo-paid-social-read-observation/v1";
pub const MAX_CREDENTIAL_LEASE_SECONDS: i64 = crate::MAX_CREDENTIAL_LEASE_TTL_SECONDS;

/// Secret material is only available at the transport boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub(crate) fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString(REDACTED)")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OAuth1Credentials {
    pub consumer_key: SecretString,
    pub consumer_secret: SecretString,
    pub access_token: SecretString,
    pub access_token_secret: SecretString,
}

impl fmt::Debug for OAuth1Credentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OAuth1Credentials(REDACTED)")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolvedCredential {
    Bearer(SecretString),
    OAuth1(OAuth1Credentials),
}

pub trait CredentialResolver: fmt::Debug + Send + Sync {
    fn resolve(&self, reference: &SecretReference) -> Result<ResolvedCredential, ConnectorError>;
}

/// Testkit resolver. Production hosts should implement `CredentialResolver` over
/// their OS-backed secret store instead of using this type.
#[derive(Clone, Default)]
pub struct InMemoryCredentialResolver {
    values: BTreeMap<String, ResolvedCredential>,
}

impl InMemoryCredentialResolver {
    pub fn insert_bearer(&mut self, reference: &SecretReference, token: impl Into<String>) {
        self.values.insert(
            reference.reference_id().to_owned(),
            ResolvedCredential::Bearer(SecretString::new(token)),
        );
    }

    pub fn insert_oauth1(&mut self, reference: &SecretReference, credentials: OAuth1Credentials) {
        self.values.insert(
            reference.reference_id().to_owned(),
            ResolvedCredential::OAuth1(credentials),
        );
    }
}

impl fmt::Debug for InMemoryCredentialResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryCredentialResolver")
            .field("references", &self.values.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl CredentialResolver for InMemoryCredentialResolver {
    fn resolve(&self, reference: &SecretReference) -> Result<ResolvedCredential, ConnectorError> {
        self.values
            .get(reference.reference_id())
            .cloned()
            .ok_or(ConnectorError::CredentialUnavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadSurface {
    MetaMarketing,
    MetaInstagram,
    XAds,
    LinkedInAds,
}

impl ReadSurface {
    pub fn provider(self) -> PaidSocialProvider {
        match self {
            Self::MetaMarketing | Self::MetaInstagram => PaidSocialProvider::Meta,
            Self::XAds => PaidSocialProvider::X,
            Self::LinkedInAds => PaidSocialProvider::LinkedIn,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Account,
    Campaigns,
    AdGroups,
    Ads,
    Creatives,
    Media,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsightLevel {
    Account,
    Campaign,
    AdGroup,
    Ad,
    Creative,
    Media,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Granularity {
    Total,
    Daily,
    Hourly,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AttributionSelection {
    Explicit(BTreeSet<String>),
    ProviderConfigured,
    NotApplicable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InsightsQuery {
    pub since: DateTime<Utc>,
    pub until: DateTime<Utc>,
    pub level: InsightLevel,
    pub granularity: Granularity,
    pub fields: BTreeSet<String>,
    pub attribution: AttributionSelection,
    pub parameters: BTreeMap<String, String>,
}

impl InsightsQuery {
    pub fn validate(&self) -> Result<(), ConnectorError> {
        if self.until <= self.since || self.fields.is_empty() {
            return Err(ConnectorError::InvalidRequest);
        }
        if self.fields.iter().any(|field| field.trim().is_empty())
            || self
                .parameters
                .keys()
                .any(|parameter| parameter.trim().is_empty())
        {
            return Err(ConnectorError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CursorKind {
    MetaGraphAfter,
    XEntity,
    LinkedInAccount,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct OpaqueCursor {
    value: String,
    pub kind: CursorKind,
}

impl OpaqueCursor {
    pub fn new(value: impl Into<String>, kind: CursorKind) -> Result<Self, ConnectorError> {
        let value = value.into();
        if value.is_empty() || value.len() > 4096 {
            return Err(ConnectorError::InvalidRequest);
        }
        Ok(Self { value, kind })
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("value", &"REDACTED")
            .field("kind", &self.kind)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ReadCommand {
    Resource(ResourceKind),
    Insights {
        query: InsightsQuery,
        cursor: Option<OpaqueCursor>,
    },
}

impl ReadCommand {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Resource(kind) => match kind {
                ResourceKind::Account => "account",
                ResourceKind::Campaigns => "campaigns",
                ResourceKind::AdGroups => "ad_groups",
                ResourceKind::Ads => "ads",
                ResourceKind::Creatives => "creatives",
                ResourceKind::Media => "media",
            },
            Self::Insights { .. } => "insights",
        }
    }

    fn validate(&self) -> Result<(), ConnectorError> {
        if let Self::Insights { query, cursor } = self {
            query.validate()?;
            if let Some(cursor) = cursor
                && cursor.value().trim().is_empty()
            {
                return Err(ConnectorError::InvalidRequest);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadRequest {
    pub scope: ConnectorScope,
    pub connection_id: String,
    pub secret_reference: SecretReference,
    pub lease: CredentialLease,
    pub surface: ReadSurface,
    pub command: ReadCommand,
    pub provenance: ProvenanceClass,
    pub requested_at: DateTime<Utc>,
}

impl ReadRequest {
    pub fn validate(&self) -> Result<(), ConnectorError> {
        validate_identifier(&self.connection_id)?;
        if self.scope.provider_id() != self.surface.provider().provider_id() {
            return Err(ConnectorError::ScopeMismatch);
        }
        self.lease
            .validate_for(&self.secret_reference, self.requested_at)
            .map_err(|_| ConnectorError::InvalidCredentialLease)?;
        self.command.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProviderValue {
    String(String),
    Integer(i64),
    Decimal(String),
    Boolean(bool),
    Null,
    Digest(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservationRecord {
    pub kind: String,
    pub external_id: Option<String>,
    pub parent_external_id: Option<String>,
    pub name: Option<String>,
    pub status: Option<String>,
    pub provider_fields: BTreeMap<String, ProviderValue>,
    pub metrics: BTreeMap<String, ProviderValue>,
    pub period: Option<String>,
    pub attribution: Option<ProviderAttribution>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderAttribution {
    pub model: String,
    pub windows: Vec<String>,
    pub parameters: BTreeMap<String, String>,
    pub causal_status: CausalStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalStatus {
    NotClaimed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewState {
    NotRequired,
    Required,
    Pending,
    Approved,
    Rejected,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PermissionObservation {
    pub required_scopes: BTreeSet<String>,
    pub granted_scopes: BTreeSet<String>,
    pub missing_scopes: BTreeSet<String>,
    pub review_state: ReviewState,
}

impl PermissionObservation {
    pub fn from_scope(
        required_scopes: impl IntoIterator<Item = String>,
        scope: &ConnectorScope,
        review_state: ReviewState,
    ) -> Self {
        let required_scopes: BTreeSet<String> = required_scopes.into_iter().collect();
        let missing_scopes = required_scopes
            .difference(scope.scopes())
            .cloned()
            .collect();
        Self {
            required_scopes,
            granted_scopes: scope.scopes().clone(),
            missing_scopes,
            review_state,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKind {
    MetaBusinessUseCase,
    MetaAdAccount,
    XUser,
    XAccount,
    LinkedInAssignedQuota,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RateLimitObservation {
    pub kind: RateLimitKind,
    pub limit: Option<u64>,
    pub remaining: Option<u64>,
    pub reset_at: Option<DateTime<Utc>>,
    pub retry_after_seconds: Option<u64>,
    pub usage: BTreeMap<String, ProviderValue>,
    pub evidence_headers: BTreeSet<String>,
}

impl Default for RateLimitObservation {
    fn default() -> Self {
        Self {
            kind: RateLimitKind::Unknown,
            limit: None,
            remaining: None,
            reset_at: None,
            retry_after_seconds: None,
            usage: BTreeMap::new(),
            evidence_headers: BTreeSet::new(),
        }
    }
}

pub type ProvenanceClass = crate::ProviderProvenanceClass;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RequestEvidence {
    pub method: String,
    pub path: String,
    pub query_digest: String,
    pub status: u16,
    pub provider_request_id: Option<String>,
    pub response_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PaginationObservation {
    pub next: Option<OpaqueCursor>,
    pub provider_supports_cursor: bool,
    pub complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReadObservation {
    pub schema_version: String,
    pub observation_id: String,
    pub scope: ConnectorScope,
    pub connection_id: String,
    pub surface: ReadSurface,
    pub command_kind: String,
    pub request_evidence: RequestEvidence,
    pub records: Vec<ObservationRecord>,
    pub pagination: PaginationObservation,
    pub permissions: PermissionObservation,
    pub rate_limit: RateLimitObservation,
    pub review_state: ReviewState,
    pub provider_attribution_models: Vec<ProviderAttribution>,
    pub provenance: ProvenanceClass,
    pub observed_at: DateTime<Utc>,
    pub causal_status: CausalStatus,
}

impl ReadObservation {
    pub fn validate(&self) -> Result<(), ConnectorError> {
        if self.schema_version != READ_OBSERVATION_SCHEMA
            || self.causal_status != CausalStatus::NotClaimed
            || self
                .provider_attribution_models
                .iter()
                .any(|attribution| attribution.causal_status != CausalStatus::NotClaimed)
        {
            return Err(ConnectorError::InvalidObservation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteRequirement {
    ExactApproval,
    ProviderReceipt,
    IndependentReadback,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteState {
    Disabled,
    Enabled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WritePolicy {
    pub state: WriteState,
    pub requirements: BTreeSet<WriteRequirement>,
}

impl Default for WritePolicy {
    fn default() -> Self {
        Self {
            state: WriteState::Disabled,
            requirements: BTreeSet::from([
                WriteRequirement::ExactApproval,
                WriteRequirement::ProviderReceipt,
                WriteRequirement::IndependentReadback,
            ]),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreparedEffect {
    pub provider: PaidSocialProvider,
    pub operation: String,
    pub policy: WritePolicy,
}

pub trait PaidSocialReadAdapter: fmt::Debug + Send + Sync {
    fn provider(&self) -> PaidSocialProvider;
    fn read(
        &self,
        request: ReadRequest,
        resolver: &dyn CredentialResolver,
    ) -> Result<ReadObservation, ConnectorError>;

    fn prepare_effect(&self, operation: &str) -> Result<PreparedEffect, ConnectorError> {
        let _ = operation;
        Err(ConnectorError::WritesDisabled {
            provider: self.provider(),
        })
    }
}

#[derive(Debug, Error)]
pub enum ConnectorError {
    #[error("invalid connector request")]
    InvalidRequest,
    #[error("connector scope mismatch")]
    ScopeMismatch,
    #[error("invalid credential lease")]
    InvalidCredentialLease,
    #[error("credential unavailable")]
    CredentialUnavailable,
    #[error("credential type is not accepted by this provider")]
    CredentialTypeMismatch,
    #[error("missing provider permission")]
    MissingPermission,
    #[error("provider permission denied")]
    PermissionDenied { status: u16 },
    #[error("provider request was unauthorized")]
    Unauthorized { status: u16 },
    #[error("provider rate limit reached")]
    RateLimited {
        status: u16,
        rate_limit: RateLimitObservation,
    },
    #[error("provider is temporarily unavailable")]
    ProviderUnavailable { status: u16 },
    #[error("provider returned an unsupported response")]
    InvalidProviderResponse { status: u16 },
    #[error("provider response could not be parsed")]
    ResponseParse { status: u16 },
    #[error("transport failure")]
    Transport(#[source] HttpTransportError),
    #[error("connector writes are disabled")]
    WritesDisabled { provider: PaidSocialProvider },
    #[error("connector operation is unsupported")]
    UnsupportedOperation,
    #[error("invalid normalized observation")]
    InvalidObservation,
}

fn validate_identifier(value: &str) -> Result<(), ConnectorError> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(ConnectorError::InvalidRequest);
    }
    Ok(())
}

pub(crate) fn digest_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

pub(crate) fn digest_json(value: &serde_json::Value) -> String {
    digest_bytes(value.to_string().as_bytes())
}
