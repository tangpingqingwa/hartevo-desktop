//! Authenticated read canary and evidence boundary.
//!
//! This module deliberately stops at provider evidence.  It does not issue a
//! Domain approval, write an Effect, or claim business verification.  A
//! successful `TenantAccountProbe` is the only path that can produce the
//! `Connected` read status; fixtures and catalog metadata remain non-live.

use std::fmt;
use std::io::Write;
use std::process::{Command, Stdio};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use super::{
    AuthSession, ConnectorError, ConnectorScope, CredentialLease, Cursor, FreshnessWindow,
    ProviderAdapterIdentity, ProviderAdapterOperation, ProviderAdapterRegistry,
    ProviderCapabilityKey, ProviderCapabilitySupport, ProviderEvidenceClass,
    ProviderProvenanceClass, ReadObservation, SecretReference, canonical_digest, is_sha256,
    valid_identifier, valid_prefixed_identifier,
};

const LIVE_CONTRACT_JSON: &str =
    include_str!("../../../contracts/connectors/authenticated-read.v1.json");
const LIVE_SCHEMA_VERSION: &str = "hartevo-connector-authenticated-read/v1";
const LIVE_CONTRACT_VERSION: &str = "connector-authenticated-read-e1/v1";
const MAX_CANARY_FRESHNESS_SECONDS: i64 = 300;
const MAX_PROVIDER_CODE_LENGTH: usize = 96;

/// The canary status is evidence state, not a Domain connection authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadCanaryStatus {
    Connected,
    Degraded,
    Expired,
    Revoked,
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    Authentication,
    Authorization,
    RateLimited,
    QuotaExceeded,
    Expired,
    InvalidRequest,
    NotFound,
    Transient,
    Unavailable,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderError {
    kind: ProviderErrorKind,
    provider_code: String,
    status_code: Option<u16>,
    retryable: bool,
    retry_after_seconds: Option<u64>,
    code_digest: String,
}

impl ProviderError {
    pub fn new(
        kind: ProviderErrorKind,
        provider_code: impl Into<String>,
        status_code: Option<u16>,
        retryable: bool,
        retry_after_seconds: Option<u64>,
    ) -> Result<Self, LiveCanaryError> {
        let provider_code = provider_code.into();
        if !valid_identifier(&provider_code) || provider_code.len() > MAX_PROVIDER_CODE_LENGTH {
            return Err(LiveCanaryError::InvalidProviderError);
        }
        Ok(Self {
            kind,
            code_digest: digest_bytes(provider_code.as_bytes()),
            provider_code,
            status_code,
            retryable,
            retry_after_seconds,
        })
    }

    pub fn from_http_status(status_code: u16) -> Result<Self, LiveCanaryError> {
        let (kind, retryable) = match status_code {
            400 => (ProviderErrorKind::InvalidRequest, false),
            401 => (ProviderErrorKind::Authentication, false),
            403 => (ProviderErrorKind::Authorization, false),
            404 => (ProviderErrorKind::NotFound, false),
            408 | 409 => (ProviderErrorKind::Transient, true),
            410 => (ProviderErrorKind::Expired, false),
            429 => (ProviderErrorKind::RateLimited, true),
            500..=599 => (ProviderErrorKind::Unavailable, true),
            _ => (ProviderErrorKind::Unknown, false),
        };
        Self::new(
            kind,
            format!("http_{status_code}"),
            Some(status_code),
            retryable,
            None,
        )
    }

    pub const fn kind(&self) -> ProviderErrorKind {
        self.kind
    }

    pub fn provider_code(&self) -> &str {
        &self.provider_code
    }

    pub const fn status_code(&self) -> Option<u16> {
        self.status_code
    }

    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    pub const fn retry_after_seconds(&self) -> Option<u64> {
        self.retry_after_seconds
    }

    pub fn code_digest(&self) -> &str {
        &self.code_digest
    }

    fn validate(&self) -> Result<(), LiveCanaryError> {
        if !valid_identifier(&self.provider_code)
            || self.provider_code.len() > MAX_PROVIDER_CODE_LENGTH
            || self.code_digest != digest_bytes(self.provider_code.as_bytes())
        {
            return Err(LiveCanaryError::InvalidProviderError);
        }
        Ok(())
    }
}

impl std::error::Error for ProviderError {}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "provider {} ({:?})",
            self.provider_code, self.kind
        )
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectorImplementationBinding {
    provider_id: String,
    adapter_id: String,
    adapter_version: u32,
    implementation_digest: String,
    schema_digest: String,
    binary_digest: String,
}

impl ConnectorImplementationBinding {
    pub fn new(
        provider_id: impl Into<String>,
        adapter_id: impl Into<String>,
        adapter_version: u32,
        implementation_digest: impl Into<String>,
        schema_digest: impl Into<String>,
        binary_digest: impl Into<String>,
    ) -> Result<Self, LiveCanaryError> {
        let binding = Self {
            provider_id: provider_id.into(),
            adapter_id: adapter_id.into(),
            adapter_version,
            implementation_digest: implementation_digest.into(),
            schema_digest: schema_digest.into(),
            binary_digest: binary_digest.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn from_adapter(
        provider_id: impl Into<String>,
        adapter: &ProviderAdapterIdentity,
        implementation_digest: impl Into<String>,
        schema_digest: impl Into<String>,
        binary_digest: impl Into<String>,
    ) -> Result<Self, LiveCanaryError> {
        Self::new(
            provider_id,
            adapter.adapter_id(),
            adapter.adapter_version(),
            implementation_digest,
            schema_digest,
            binary_digest,
        )
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    pub const fn adapter_version(&self) -> u32 {
        self.adapter_version
    }

    pub fn implementation_digest(&self) -> &str {
        &self.implementation_digest
    }

    pub fn schema_digest(&self) -> &str {
        &self.schema_digest
    }

    pub fn binary_digest(&self) -> &str {
        &self.binary_digest
    }

    fn validate(&self) -> Result<(), LiveCanaryError> {
        if !valid_identifier(&self.provider_id)
            || !valid_identifier(&self.adapter_id)
            || self.adapter_version == 0
            || !is_sha256(&self.implementation_digest)
            || !is_sha256(&self.schema_digest)
            || !is_sha256(&self.binary_digest)
        {
            return Err(LiveCanaryError::InvalidBinding);
        }
        Ok(())
    }
}

impl fmt::Debug for ConnectorImplementationBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectorImplementationBinding")
            .field("provider_id", &self.provider_id)
            .field("adapter_id", &self.adapter_id)
            .field("adapter_version", &self.adapter_version)
            .field("implementation_digest", &"<digest>")
            .field("schema_digest", &"<digest>")
            .field("binary_digest", &"<digest>")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticatedReadContract {
    schema_version: String,
    contract_version: String,
    authority: LiveAuthority,
    secret_material: LiveSecretMaterial,
    statuses: Vec<ReadCanaryStatus>,
    operations: Vec<LiveOperation>,
    provider_error_kinds: Vec<ProviderErrorKind>,
    binding_fields: Vec<BindingField>,
    evidence_fields: Vec<EvidenceField>,
    plugin_seam: PluginSeamContract,
    registrations: Vec<serde_json::Value>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum LiveAuthority {
    AuthenticatedReadEvidenceOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum LiveSecretMaterial {
    OpaqueReferenceOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum LiveOperation {
    TenantAccountProbe,
    AuthenticatedRead,
    Checkpoint,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum BindingField {
    ProviderId,
    AdapterId,
    AdapterVersion,
    ImplementationDigest,
    SchemaDigest,
    BinaryDigest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum EvidenceField {
    ScopeDigest,
    ProvenanceClass,
    ProbeDigest,
    RequestDigest,
    ResponseDigest,
    ContentDigest,
    SourceRevision,
    CursorSequence,
    ObservedAt,
    FreshnessDeadline,
    QuotaRemaining,
    RateLimitRemaining,
    CostMinor,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum PluginServiceDefinition {
    ConnectorServiceDefinition,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum PluginProviderRegistration {
    EffectBrokerProviderRegistry,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum PluginMissionConsumer {
    EvidenceOnlyMissionConsumer,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum PluginLifecycle {
    Mount,
    Unmount,
    Revoke,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum PluginResource {
    Probe,
    Cursor,
    Webhook,
    Effect,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum PluginScopeBinding {
    ProjectScope,
    MissionScopeDigest,
    AccountScope,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum PluginDigestBinding {
    ProviderRegistry,
    AdapterVersion,
    Implementation,
    Schema,
    Binary,
    MissionConsumer,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PluginSeamContract {
    service_definition: PluginServiceDefinition,
    provider_registration: PluginProviderRegistration,
    mission_consumer: PluginMissionConsumer,
    lifecycle: Vec<PluginLifecycle>,
    recovery_resources: Vec<PluginResource>,
    scope_bindings: Vec<PluginScopeBinding>,
    digest_bindings: Vec<PluginDigestBinding>,
}

impl PluginSeamContract {
    fn validate(&self) -> bool {
        self.service_definition == PluginServiceDefinition::ConnectorServiceDefinition
            && self.provider_registration
                == PluginProviderRegistration::EffectBrokerProviderRegistry
            && self.mission_consumer == PluginMissionConsumer::EvidenceOnlyMissionConsumer
            && exact_set(
                &self.lifecycle,
                &[
                    PluginLifecycle::Mount,
                    PluginLifecycle::Unmount,
                    PluginLifecycle::Revoke,
                ],
            )
            && exact_set(
                &self.recovery_resources,
                &[
                    PluginResource::Probe,
                    PluginResource::Cursor,
                    PluginResource::Webhook,
                    PluginResource::Effect,
                ],
            )
            && exact_set(
                &self.scope_bindings,
                &[
                    PluginScopeBinding::ProjectScope,
                    PluginScopeBinding::MissionScopeDigest,
                    PluginScopeBinding::AccountScope,
                ],
            )
            && exact_set(
                &self.digest_bindings,
                &[
                    PluginDigestBinding::ProviderRegistry,
                    PluginDigestBinding::AdapterVersion,
                    PluginDigestBinding::Implementation,
                    PluginDigestBinding::Schema,
                    PluginDigestBinding::Binary,
                    PluginDigestBinding::MissionConsumer,
                ],
            )
    }
}

impl AuthenticatedReadContract {
    pub fn baseline() -> Result<Self, LiveCanaryError> {
        Self::from_json(LIVE_CONTRACT_JSON)
    }

    pub fn from_json(document: &str) -> Result<Self, LiveCanaryError> {
        let contract: Self = serde_json::from_str(document)
            .map_err(|error| LiveCanaryError::InvalidContract(error.to_string()))?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn digest(&self) -> String {
        digest_bytes(LIVE_CONTRACT_JSON.as_bytes())
    }

    pub fn registrations(&self) -> &[serde_json::Value] {
        &self.registrations
    }

    fn validate(&self) -> Result<(), LiveCanaryError> {
        if self.schema_version != LIVE_SCHEMA_VERSION
            || self.contract_version != LIVE_CONTRACT_VERSION
            || self.authority != LiveAuthority::AuthenticatedReadEvidenceOnly
            || self.secret_material != LiveSecretMaterial::OpaqueReferenceOnly
            || !exact_set(
                &self.statuses,
                &[
                    ReadCanaryStatus::Connected,
                    ReadCanaryStatus::Degraded,
                    ReadCanaryStatus::Expired,
                    ReadCanaryStatus::Revoked,
                    ReadCanaryStatus::BlockedEnv,
                ],
            )
            || !exact_set(
                &self.operations,
                &[
                    LiveOperation::TenantAccountProbe,
                    LiveOperation::AuthenticatedRead,
                    LiveOperation::Checkpoint,
                ],
            )
            || !exact_set(
                &self.provider_error_kinds,
                &[
                    ProviderErrorKind::Authentication,
                    ProviderErrorKind::Authorization,
                    ProviderErrorKind::RateLimited,
                    ProviderErrorKind::QuotaExceeded,
                    ProviderErrorKind::Expired,
                    ProviderErrorKind::InvalidRequest,
                    ProviderErrorKind::NotFound,
                    ProviderErrorKind::Transient,
                    ProviderErrorKind::Unavailable,
                    ProviderErrorKind::Unknown,
                ],
            )
            || !exact_set(
                &self.binding_fields,
                &[
                    BindingField::ProviderId,
                    BindingField::AdapterId,
                    BindingField::AdapterVersion,
                    BindingField::ImplementationDigest,
                    BindingField::SchemaDigest,
                    BindingField::BinaryDigest,
                ],
            )
            || !exact_set(
                &self.evidence_fields,
                &[
                    EvidenceField::ScopeDigest,
                    EvidenceField::ProvenanceClass,
                    EvidenceField::ProbeDigest,
                    EvidenceField::RequestDigest,
                    EvidenceField::ResponseDigest,
                    EvidenceField::ContentDigest,
                    EvidenceField::SourceRevision,
                    EvidenceField::CursorSequence,
                    EvidenceField::ObservedAt,
                    EvidenceField::FreshnessDeadline,
                    EvidenceField::QuotaRemaining,
                    EvidenceField::RateLimitRemaining,
                    EvidenceField::CostMinor,
                ],
            )
            || !self.plugin_seam.validate()
            || !self.registrations.is_empty()
        {
            return Err(LiveCanaryError::InvalidContract(
                "exact contract set mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SecretResolutionError {
    #[error("secret reference is invalid")]
    InvalidReference,
    #[error("credential lease is expired or revoked")]
    Expired,
    #[error("secret reference is revoked")]
    Revoked,
    #[error("required secret environment is unavailable")]
    BlockedEnv { variable: String },
    #[error("secret material is invalid")]
    InvalidMaterial,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LiveCanaryError {
    #[error("authenticated read contract is invalid: {0}")]
    InvalidContract(String),
    #[error("connector implementation binding is invalid")]
    InvalidBinding,
    #[error("provider error metadata is invalid")]
    InvalidProviderError,
    #[error("secret resolution failed: {0}")]
    SecretResolution(SecretResolutionError),
    #[error("provider returned an error: {0}")]
    Provider(ProviderError),
    #[error("connector metadata is invalid: {0}")]
    Connector(#[from] ConnectorError),
    #[error("authenticated read is expired")]
    Expired,
    #[error("authenticated read is revoked")]
    Revoked,
    #[error("cursor checkpoint is invalid")]
    InvalidCheckpoint,
    #[error("read response is invalid")]
    InvalidResponse,
    #[error("native canary configuration is blocked by environment: {0}")]
    BlockedEnv(String),
    #[error("native canary transport failed")]
    Transport,
    #[error("connector plugin contract is invalid")]
    PluginContract,
    #[error("connector plugin provider registration is not bound")]
    PluginRegistryMismatch,
    #[error("connector plugin scope is not bound")]
    PluginScopeMismatch,
    #[error("connector plugin is not mounted")]
    PluginNotMounted,
    #[error("connector plugin is revoked or unmounted")]
    PluginRevoked,
    #[error("connector mission evidence consumer rejected the envelope")]
    PluginConsumer,
}

impl From<SecretResolutionError> for LiveCanaryError {
    fn from(error: SecretResolutionError) -> Self {
        Self::SecretResolution(error)
    }
}

/// Resolved secret bytes are kept inside the resolver/transport boundary and
/// can only be borrowed for the duration of a callback.  The type is neither
/// serializable nor cloneable and its Debug output never contains material.
pub struct ResolvedSecret {
    bytes: Zeroizing<Vec<u8>>,
    fingerprint: String,
}

impl ResolvedSecret {
    fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, SecretResolutionError> {
        let bytes = bytes.as_ref();
        if bytes.is_empty() || bytes.len() > 16 * 1024 {
            return Err(SecretResolutionError::InvalidMaterial);
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes.to_vec()),
            fingerprint: digest_bytes(bytes),
        })
    }

    pub fn with_bytes<T>(&self, callback: impl FnOnce(&[u8]) -> T) -> T {
        callback(self.bytes.as_slice())
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

impl fmt::Debug for ResolvedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedSecret")
            .field("present", &true)
            .field("fingerprint", &"<digest>")
            .finish()
    }
}

/// Resolves an opaque `SecretReference` without making secret bytes part of
/// an authenticated read request or evidence envelope.
pub trait SecretReferenceResolver: Send + Sync {
    fn resolve(
        &self,
        reference: &SecretReference,
        lease: &CredentialLease,
        now: DateTime<Utc>,
    ) -> Result<ResolvedSecret, SecretResolutionError>;
}

#[derive(Clone)]
pub struct EnvironmentSecretResolver {
    variable: String,
}

impl EnvironmentSecretResolver {
    pub fn new(variable: impl Into<String>) -> Result<Self, SecretResolutionError> {
        let variable = variable.into();
        if !valid_identifier(&variable) || !variable.starts_with("HARTEVO_") {
            return Err(SecretResolutionError::InvalidReference);
        }
        Ok(Self { variable })
    }

    pub fn variable(&self) -> &str {
        &self.variable
    }
}

impl fmt::Debug for EnvironmentSecretResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvironmentSecretResolver")
            .field("variable", &self.variable)
            .finish()
    }
}

impl SecretReferenceResolver for EnvironmentSecretResolver {
    fn resolve(
        &self,
        reference: &SecretReference,
        lease: &CredentialLease,
        now: DateTime<Utc>,
    ) -> Result<ResolvedSecret, SecretResolutionError> {
        if reference.is_revoked_at(now) || lease.lease_revocation.is_revoked_at(now) {
            return Err(SecretResolutionError::Revoked);
        }
        lease
            .validate(reference, now)
            .map_err(|_| SecretResolutionError::Expired)?;
        let value =
            std::env::var(&self.variable).map_err(|_| SecretResolutionError::BlockedEnv {
                variable: self.variable.clone(),
            })?;
        ResolvedSecret::from_bytes(value.as_bytes())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    Reachable,
    Rejected,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantAccountProbe {
    scope_digest: String,
    tenant_digest: String,
    account_digest: String,
    adapter: ProviderAdapterIdentity,
    credential_revision: u64,
    lease_revision: u64,
    auth_revision: u64,
    probe_revision: u64,
    outcome: ProbeOutcome,
    observed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    evidence_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantAccountProbeInput {
    pub adapter: ProviderAdapterIdentity,
    pub credential_revision: u64,
    pub lease_revision: u64,
    pub auth_revision: u64,
    pub probe_revision: u64,
    pub outcome: ProbeOutcome,
    pub observed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub evidence_digest: String,
}

impl TenantAccountProbe {
    pub fn from_input(
        scope: &ConnectorScope,
        input: TenantAccountProbeInput,
    ) -> Result<Self, LiveCanaryError> {
        if input.credential_revision == 0
            || input.lease_revision == 0
            || input.auth_revision == 0
            || input.probe_revision == 0
            || input.expires_at <= input.observed_at
            || input.expires_at - input.observed_at
                > Duration::seconds(MAX_CANARY_FRESHNESS_SECONDS)
            || !is_sha256(&input.evidence_digest)
        {
            return Err(LiveCanaryError::InvalidResponse);
        }
        let probe = Self {
            scope_digest: scope.digest(),
            tenant_digest: digest_bytes(scope.tenant_id().as_bytes()),
            account_digest: digest_bytes(scope.account_id().as_bytes()),
            adapter: input.adapter,
            credential_revision: input.credential_revision,
            lease_revision: input.lease_revision,
            auth_revision: input.auth_revision,
            probe_revision: input.probe_revision,
            outcome: input.outcome,
            observed_at: input.observed_at,
            expires_at: input.expires_at,
            evidence_digest: input.evidence_digest,
        };
        probe.validate(scope, probe.observed_at)?;
        Ok(probe)
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub fn tenant_digest(&self) -> &str {
        &self.tenant_digest
    }

    pub fn account_digest(&self) -> &str {
        &self.account_digest
    }

    pub fn adapter(&self) -> &ProviderAdapterIdentity {
        &self.adapter
    }

    pub const fn probe_revision(&self) -> u64 {
        self.probe_revision
    }

    pub const fn outcome(&self) -> ProbeOutcome {
        self.outcome
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    fn validate(&self, scope: &ConnectorScope, now: DateTime<Utc>) -> Result<(), LiveCanaryError> {
        if self.scope_digest != scope.digest()
            || self.tenant_digest != digest_bytes(scope.tenant_id().as_bytes())
            || self.account_digest != digest_bytes(scope.account_id().as_bytes())
            || now < self.observed_at
            || now >= self.expires_at
        {
            return Err(if now >= self.expires_at {
                LiveCanaryError::Expired
            } else {
                LiveCanaryError::InvalidResponse
            });
        }
        Ok(())
    }
}

impl fmt::Debug for TenantAccountProbe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantAccountProbe")
            .field("scope_digest", &self.scope_digest)
            .field("tenant_digest", &"<digest>")
            .field("account_digest", &"<digest>")
            .field("adapter", &self.adapter)
            .field("credential_revision", &self.credential_revision)
            .field("lease_revision", &self.lease_revision)
            .field("auth_revision", &self.auth_revision)
            .field("probe_revision", &self.probe_revision)
            .field("outcome", &self.outcome)
            .field("observed_at", &self.observed_at)
            .field("expires_at", &self.expires_at)
            .field("evidence_digest", &"<digest>")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadBudgetMetadata {
    quota_remaining: u64,
    rate_limit_remaining: u64,
    cost_minor: i64,
    freshness_deadline: DateTime<Utc>,
}

impl ReadBudgetMetadata {
    pub fn new(
        quota_remaining: u64,
        rate_limit_remaining: u64,
        cost_minor: i64,
        freshness_deadline: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<Self, LiveCanaryError> {
        if cost_minor < 0 || freshness_deadline <= now {
            return Err(LiveCanaryError::InvalidResponse);
        }
        Ok(Self {
            quota_remaining,
            rate_limit_remaining,
            cost_minor,
            freshness_deadline,
        })
    }

    pub const fn quota_remaining(&self) -> u64 {
        self.quota_remaining
    }

    pub const fn rate_limit_remaining(&self) -> u64 {
        self.rate_limit_remaining
    }

    pub const fn cost_minor(&self) -> i64 {
        self.cost_minor
    }

    pub const fn freshness_deadline(&self) -> DateTime<Utc> {
        self.freshness_deadline
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedReadRequest {
    pub scope: ConnectorScope,
    pub secret_reference: SecretReference,
    pub credential_lease: CredentialLease,
    pub session: AuthSession,
    pub adapter: ProviderAdapterIdentity,
    pub capability: ProviderCapabilityKey,
    pub query_digest: String,
    pub cursor: Option<Cursor>,
    pub page_size: u32,
    pub probe_revision: u64,
    pub auth_revision: u64,
    pub at: DateTime<Utc>,
    pub budget: ReadBudgetMetadata,
}

impl fmt::Debug for AuthenticatedReadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedReadRequest")
            .field("scope_digest", &self.scope.digest())
            .field("adapter", &self.adapter)
            .field("capability", &self.capability)
            .field("query_digest", &"<digest>")
            .field("secret_reference", &"<opaque>")
            .field("credential_lease", &"<opaque>")
            .field("session", &"<opaque>")
            .field("cursor", &self.cursor)
            .field("page_size", &self.page_size)
            .field("probe_revision", &self.probe_revision)
            .field("auth_revision", &self.auth_revision)
            .field("at", &self.at)
            .field("budget", &self.budget)
            .finish()
    }
}

impl AuthenticatedReadRequest {
    pub fn validate(&self) -> Result<(), LiveCanaryError> {
        if self.secret_reference.is_revoked_at(self.at)
            || self
                .credential_lease
                .lease_revocation
                .is_revoked_at(self.at)
            || self.session.session_revocation.is_revoked_at(self.at)
        {
            return Err(LiveCanaryError::Revoked);
        }
        self.credential_lease
            .validate(&self.secret_reference, self.at)
            .map_err(|_| LiveCanaryError::Expired)?;
        self.session
            .validate(&self.secret_reference, &self.credential_lease, self.at)
            .map_err(|_| LiveCanaryError::Expired)?;
        if self.scope != *self.secret_reference.scope()
            || self.scope != *self.credential_lease.scope()
            || self.adapter != *self.credential_lease.adapter()
            || self.capability.provider_id() != self.scope.provider_id()
            || !is_sha256(&self.query_digest)
            || self.page_size == 0
            || self.probe_revision == 0
            || self.auth_revision == 0
            || self.cursor.as_ref().is_some_and(|cursor| {
                cursor.scope_digest() != self.scope.digest()
                    || cursor.request_digest() != self.query_digest
            })
        {
            return Err(LiveCanaryError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderHttpResponse {
    status_code: u16,
    response_digest: String,
    content_digest: String,
    body_len: u64,
    source_revision: u64,
    freshness_deadline: DateTime<Utc>,
    quota_remaining: u64,
    rate_limit_remaining: u64,
    cost_minor: i64,
    page_sequence: u64,
    next_cursor_token_digest: Option<String>,
}

impl ProviderHttpResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn from_body(
        status_code: u16,
        body: impl AsRef<[u8]>,
        source_revision: u64,
        freshness_deadline: DateTime<Utc>,
        quota_remaining: u64,
        rate_limit_remaining: u64,
        cost_minor: i64,
        next_cursor_token_digest: Option<String>,
    ) -> Result<Self, LiveCanaryError> {
        let body = body.as_ref();
        let response_digest = digest_bytes(body);
        let content_digest = digest_bytes(body);
        if source_revision == 0
            || cost_minor < 0
            || next_cursor_token_digest
                .as_ref()
                .is_some_and(|digest| !is_sha256(digest))
        {
            return Err(LiveCanaryError::InvalidResponse);
        }
        Ok(Self {
            status_code,
            response_digest,
            content_digest,
            body_len: u64::try_from(body.len()).expect("usize fits in u64"),
            source_revision,
            freshness_deadline,
            quota_remaining,
            rate_limit_remaining,
            cost_minor,
            page_sequence: 1,
            next_cursor_token_digest,
        })
    }

    pub fn status_code(&self) -> u16 {
        self.status_code
    }

    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }

    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    pub const fn body_len(&self) -> u64 {
        self.body_len
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub const fn freshness_deadline(&self) -> DateTime<Utc> {
        self.freshness_deadline
    }

    pub const fn quota_remaining(&self) -> u64 {
        self.quota_remaining
    }

    pub const fn rate_limit_remaining(&self) -> u64 {
        self.rate_limit_remaining
    }

    pub const fn cost_minor(&self) -> i64 {
        self.cost_minor
    }

    pub const fn page_sequence(&self) -> u64 {
        self.page_sequence
    }

    pub fn with_page_sequence(mut self, page_sequence: u64) -> Result<Self, LiveCanaryError> {
        if page_sequence == 0 {
            return Err(LiveCanaryError::InvalidResponse);
        }
        self.page_sequence = page_sequence;
        Ok(self)
    }

    pub fn next_cursor_token_digest(&self) -> Option<&str> {
        self.next_cursor_token_digest.as_deref()
    }

    fn provider_error(&self) -> Result<(), LiveCanaryError> {
        if (200..=299).contains(&self.status_code) {
            Ok(())
        } else {
            Err(LiveCanaryError::Provider(ProviderError::from_http_status(
                self.status_code,
            )?))
        }
    }

    fn validate_against(
        &self,
        budget: &ReadBudgetMetadata,
        at: DateTime<Utc>,
    ) -> Result<(), LiveCanaryError> {
        if at >= self.freshness_deadline
            || self.freshness_deadline() > budget.freshness_deadline()
            || self.cost_minor() > budget.cost_minor()
        {
            return Err(LiveCanaryError::Expired);
        }
        Ok(())
    }
}

/// A low-level transport is deliberately passed resolved material only via a
/// short-lived callback boundary.  It never receives an opaque reference's
/// identifier and cannot write a Mission.
pub trait AuthenticatedReadTransport: Send {
    fn provenance_class(&self) -> ProviderProvenanceClass {
        ProviderProvenanceClass::ProductionProvider
    }

    fn authenticated_probe(
        &mut self,
        scope: &ConnectorScope,
        secret: &ResolvedSecret,
        at: DateTime<Utc>,
    ) -> Result<ProviderHttpResponse, LiveCanaryError>;

    fn read(
        &mut self,
        request: &AuthenticatedReadRequest,
        secret: &ResolvedSecret,
    ) -> Result<ProviderHttpResponse, LiveCanaryError>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadCheckpoint {
    scope_digest: String,
    request_digest: String,
    sequence: u64,
    source_revision: u64,
    evidence_digest: String,
    next_cursor: Option<Cursor>,
    updated_at: DateTime<Utc>,
    checkpoint_digest: String,
}

impl ReadCheckpoint {
    pub fn from_response(
        scope: &ConnectorScope,
        request_digest: impl Into<String>,
        sequence: u64,
        source_revision: u64,
        evidence_digest: impl Into<String>,
        next_cursor: Option<Cursor>,
        updated_at: DateTime<Utc>,
    ) -> Result<Self, LiveCanaryError> {
        let request_digest = request_digest.into();
        let evidence_digest = evidence_digest.into();
        if sequence == 0
            || source_revision == 0
            || !is_sha256(&request_digest)
            || !is_sha256(&evidence_digest)
            || next_cursor.as_ref().is_some_and(|cursor| {
                cursor.scope_digest() != scope.digest() || cursor.request_digest() != request_digest
            })
        {
            return Err(LiveCanaryError::InvalidCheckpoint);
        }
        let mut checkpoint = Self {
            scope_digest: scope.digest(),
            request_digest,
            sequence,
            source_revision,
            evidence_digest,
            next_cursor,
            updated_at,
            checkpoint_digest: String::new(),
        };
        checkpoint.checkpoint_digest = checkpoint.calculate_digest();
        Ok(checkpoint)
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub fn next_cursor(&self) -> Option<&Cursor> {
        self.next_cursor.as_ref()
    }

    pub fn checkpoint_digest(&self) -> &str {
        &self.checkpoint_digest
    }

    pub fn validate(&self, scope: &ConnectorScope) -> Result<(), LiveCanaryError> {
        if self.scope_digest != scope.digest()
            || self.sequence == 0
            || self.source_revision == 0
            || !is_sha256(&self.request_digest)
            || !is_sha256(&self.evidence_digest)
            || self.checkpoint_digest != self.calculate_digest()
            || self.next_cursor.as_ref().is_some_and(|cursor| {
                cursor.scope_digest() != self.scope_digest
                    || cursor.request_digest() != self.request_digest
                    || cursor.sequence() <= self.sequence
            })
        {
            return Err(LiveCanaryError::InvalidCheckpoint);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> String {
        canonical_digest([
            self.scope_digest.as_str(),
            self.request_digest.as_str(),
            &self.sequence.to_string(),
            &self.source_revision.to_string(),
            self.evidence_digest.as_str(),
            self.next_cursor.as_ref().map_or("", Cursor::token_digest),
            &self.updated_at.to_rfc3339(),
        ])
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadEvidenceEnvelope {
    schema_version: String,
    contract_version: String,
    evidence_id: String,
    status: ReadCanaryStatus,
    scope_digest: String,
    provenance_class: ProviderProvenanceClass,
    probe_digest: String,
    request_digest: String,
    response_digest: String,
    content_digest: String,
    source_revision: u64,
    cursor_sequence: u64,
    observed_at: DateTime<Utc>,
    freshness_deadline: DateTime<Utc>,
    quota_remaining: u64,
    rate_limit_remaining: u64,
    cost_minor: i64,
    binding: ConnectorImplementationBinding,
    provider_error: Option<ProviderError>,
    envelope_digest: String,
}

impl ReadEvidenceEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_id: impl Into<String>,
        status: ReadCanaryStatus,
        scope: &ConnectorScope,
        probe: &TenantAccountProbe,
        request_digest: impl Into<String>,
        response: &ProviderHttpResponse,
        binding: ConnectorImplementationBinding,
        provenance_class: ProviderProvenanceClass,
        provider_error: Option<ProviderError>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, LiveCanaryError> {
        let evidence_id = evidence_id.into();
        let request_digest = request_digest.into();
        let contract = AuthenticatedReadContract::baseline()?;
        if !valid_prefixed_identifier(&evidence_id, "read-evidence-")
            || probe.scope_digest() != scope.digest()
            || binding.schema_digest() != contract.digest()
            || !is_sha256(&request_digest)
            || response.source_revision() == 0
            || response.freshness_deadline() <= observed_at
            || response.freshness_deadline() - observed_at
                > Duration::seconds(MAX_CANARY_FRESHNESS_SECONDS)
            || (status == ReadCanaryStatus::Connected
                && (provider_error.is_some()
                    || provenance_class != ProviderProvenanceClass::ProductionProvider))
            || (status != ReadCanaryStatus::Connected
                && provider_error.is_none()
                && !(status == ReadCanaryStatus::Degraded
                    && provenance_class != ProviderProvenanceClass::ProductionProvider))
        {
            return Err(LiveCanaryError::InvalidResponse);
        }
        if let Some(error) = &provider_error {
            error.validate()?;
        }
        let mut envelope = Self {
            schema_version: contract.schema_version().to_owned(),
            contract_version: contract.contract_version().to_owned(),
            evidence_id,
            status,
            scope_digest: scope.digest(),
            provenance_class,
            probe_digest: probe.evidence_digest().to_owned(),
            request_digest,
            response_digest: response.response_digest().to_owned(),
            content_digest: response.content_digest().to_owned(),
            source_revision: response.source_revision(),
            cursor_sequence: response.page_sequence(),
            observed_at,
            freshness_deadline: response.freshness_deadline(),
            quota_remaining: response.quota_remaining(),
            rate_limit_remaining: response.rate_limit_remaining(),
            cost_minor: response.cost_minor(),
            binding,
            provider_error,
            envelope_digest: String::new(),
        };
        envelope.envelope_digest = envelope.calculate_digest();
        Ok(envelope)
    }

    pub fn status(&self) -> ReadCanaryStatus {
        self.status
    }

    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub const fn provenance_class(&self) -> ProviderProvenanceClass {
        self.provenance_class
    }

    pub fn probe_digest(&self) -> &str {
        &self.probe_digest
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }

    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub const fn cursor_sequence(&self) -> u64 {
        self.cursor_sequence
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn freshness_deadline(&self) -> DateTime<Utc> {
        self.freshness_deadline
    }

    pub fn binding(&self) -> &ConnectorImplementationBinding {
        &self.binding
    }

    pub fn provider_error(&self) -> Option<&ProviderError> {
        self.provider_error.as_ref()
    }

    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }

    pub fn validate(&self) -> Result<(), LiveCanaryError> {
        if self.schema_version != LIVE_SCHEMA_VERSION
            || self.contract_version != LIVE_CONTRACT_VERSION
            || !is_sha256(&self.scope_digest)
            || !is_sha256(&self.probe_digest)
            || !is_sha256(&self.request_digest)
            || !is_sha256(&self.response_digest)
            || !is_sha256(&self.content_digest)
            || self.source_revision == 0
            || self.cursor_sequence == 0
            || self.freshness_deadline <= self.observed_at
            || self.freshness_deadline - self.observed_at
                > Duration::seconds(MAX_CANARY_FRESHNESS_SECONDS)
            || self.cost_minor < 0
            || (self.status == ReadCanaryStatus::Connected
                && (self.provider_error.is_some()
                    || self.provenance_class != ProviderProvenanceClass::ProductionProvider))
            || (self.status != ReadCanaryStatus::Connected
                && self.provider_error.is_none()
                && !(self.status == ReadCanaryStatus::Degraded
                    && self.provenance_class != ProviderProvenanceClass::ProductionProvider))
            || self.envelope_digest != self.calculate_digest()
        {
            return Err(LiveCanaryError::InvalidResponse);
        }
        self.binding.validate()?;
        if self.binding.schema_digest() != AuthenticatedReadContract::baseline()?.digest() {
            return Err(LiveCanaryError::InvalidBinding);
        }
        if let Some(error) = &self.provider_error {
            error.validate()?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> String {
        canonical_digest([
            self.schema_version.as_str(),
            self.contract_version.as_str(),
            self.evidence_id.as_str(),
            &format!("{:?}", self.status),
            self.scope_digest.as_str(),
            &format!("{:?}", self.provenance_class),
            self.probe_digest.as_str(),
            self.request_digest.as_str(),
            self.response_digest.as_str(),
            self.content_digest.as_str(),
            &self.source_revision.to_string(),
            &self.cursor_sequence.to_string(),
            &self.observed_at.to_rfc3339(),
            &self.freshness_deadline.to_rfc3339(),
            &self.quota_remaining.to_string(),
            &self.rate_limit_remaining.to_string(),
            &self.cost_minor.to_string(),
            self.binding.provider_id(),
            self.binding.adapter_id(),
            &self.binding.adapter_version().to_string(),
            self.binding.implementation_digest(),
            self.binding.schema_digest(),
            self.binding.binary_digest(),
            self.provider_error
                .as_ref()
                .map_or("", ProviderError::code_digest),
        ])
    }
}

impl fmt::Debug for ReadEvidenceEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadEvidenceEnvelope")
            .field("schema_version", &self.schema_version)
            .field("contract_version", &self.contract_version)
            .field("evidence_id", &self.evidence_id)
            .field("status", &self.status)
            .field("scope_digest", &self.scope_digest)
            .field("provenance_class", &self.provenance_class)
            .field("probe_digest", &"<digest>")
            .field("request_digest", &"<digest>")
            .field("response_digest", &"<digest>")
            .field("content_digest", &"<digest>")
            .field("source_revision", &self.source_revision)
            .field("cursor_sequence", &self.cursor_sequence)
            .field("observed_at", &self.observed_at)
            .field("freshness_deadline", &self.freshness_deadline)
            .field("quota_remaining", &self.quota_remaining)
            .field("rate_limit_remaining", &self.rate_limit_remaining)
            .field("cost_minor", &self.cost_minor)
            .field("binding", &self.binding)
            .field("provider_error", &self.provider_error)
            .field("envelope_digest", &"<digest>")
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct AuthenticatedReadReport {
    status: ReadCanaryStatus,
    probe: TenantAccountProbe,
    observation: ReadObservation,
    checkpoint: ReadCheckpoint,
    evidence: ReadEvidenceEnvelope,
    provider_error: Option<ProviderError>,
}

impl AuthenticatedReadReport {
    pub fn status(&self) -> ReadCanaryStatus {
        self.status
    }

    pub fn probe(&self) -> &TenantAccountProbe {
        &self.probe
    }

    pub fn observation(&self) -> &ReadObservation {
        &self.observation
    }

    pub fn checkpoint(&self) -> &ReadCheckpoint {
        &self.checkpoint
    }

    pub fn evidence(&self) -> &ReadEvidenceEnvelope {
        &self.evidence
    }

    pub fn provider_error(&self) -> Option<&ProviderError> {
        self.provider_error.as_ref()
    }
}

impl fmt::Debug for AuthenticatedReadReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedReadReport")
            .field("status", &self.status)
            .field("probe", &self.probe)
            .field("checkpoint", &self.checkpoint)
            .field("evidence", &self.evidence)
            .field("provider_error", &self.provider_error)
            .finish_non_exhaustive()
    }
}

/// The Mission side of the plugin seam consumes evidence only.  It receives
/// no adapter, credential, transport, or Domain Mission handle.
pub trait MissionEvidenceConsumer: Send {
    fn consume_read_evidence(
        &mut self,
        scope: &ConnectorScope,
        evidence: &ReadEvidenceEnvelope,
    ) -> Result<(), LiveCanaryError>;
}

#[derive(Clone, Eq, PartialEq)]
pub struct MissionConsumerBinding {
    consumer_id: String,
    consumer_version: u32,
    implementation_digest: String,
}

impl MissionConsumerBinding {
    pub fn new(
        consumer_id: impl Into<String>,
        consumer_version: u32,
        implementation_digest: impl Into<String>,
    ) -> Result<Self, LiveCanaryError> {
        let binding = Self {
            consumer_id: consumer_id.into(),
            consumer_version,
            implementation_digest: implementation_digest.into(),
        };
        if !valid_prefixed_identifier(&binding.consumer_id, "mission-consumer-")
            || binding.consumer_version == 0
            || !is_sha256(&binding.implementation_digest)
        {
            return Err(LiveCanaryError::PluginContract);
        }
        Ok(binding)
    }

    pub fn consumer_id(&self) -> &str {
        &self.consumer_id
    }

    pub const fn consumer_version(&self) -> u32 {
        self.consumer_version
    }

    pub fn implementation_digest(&self) -> &str {
        &self.implementation_digest
    }
}

impl fmt::Debug for MissionConsumerBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionConsumerBinding")
            .field("consumer_id", &self.consumer_id)
            .field("consumer_version", &self.consumer_version)
            .field("implementation_digest", &"<digest>")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConnectorServiceDefinition {
    service_id: String,
    scope: ConnectorScope,
    mission_scope_digest: String,
    capability: ProviderCapabilityKey,
    adapter: ProviderAdapterIdentity,
    binding: ConnectorImplementationBinding,
    provenance_class: ProviderProvenanceClass,
    provider_registry_digest: String,
    mission_consumer: MissionConsumerBinding,
    service_revision: u64,
    definition_digest: String,
}

impl ConnectorServiceDefinition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        service_id: impl Into<String>,
        scope: ConnectorScope,
        mission_scope_digest: impl Into<String>,
        capability: ProviderCapabilityKey,
        adapter: ProviderAdapterIdentity,
        binding: ConnectorImplementationBinding,
        provenance_class: ProviderProvenanceClass,
        provider_registry_digest: impl Into<String>,
        mission_consumer: MissionConsumerBinding,
        service_revision: u64,
    ) -> Result<Self, LiveCanaryError> {
        let service = Self {
            service_id: service_id.into(),
            scope,
            mission_scope_digest: mission_scope_digest.into(),
            capability,
            adapter,
            binding,
            provenance_class,
            provider_registry_digest: provider_registry_digest.into(),
            mission_consumer,
            service_revision,
            definition_digest: String::new(),
        };
        service.validate_without_digest()?;
        let mut service = service;
        service.definition_digest = service.calculate_digest();
        Ok(service)
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn mission_scope_digest(&self) -> &str {
        &self.mission_scope_digest
    }

    pub fn capability(&self) -> &ProviderCapabilityKey {
        &self.capability
    }

    pub fn adapter(&self) -> &ProviderAdapterIdentity {
        &self.adapter
    }

    pub fn binding(&self) -> &ConnectorImplementationBinding {
        &self.binding
    }

    pub const fn provenance_class(&self) -> ProviderProvenanceClass {
        self.provenance_class
    }

    pub fn provider_registry_digest(&self) -> &str {
        &self.provider_registry_digest
    }

    pub fn mission_consumer(&self) -> &MissionConsumerBinding {
        &self.mission_consumer
    }

    pub const fn service_revision(&self) -> u64 {
        self.service_revision
    }

    pub fn definition_digest(&self) -> &str {
        &self.definition_digest
    }

    fn validate_without_digest(&self) -> Result<(), LiveCanaryError> {
        if !valid_prefixed_identifier(&self.service_id, "connector-service-")
            || !is_sha256(&self.mission_scope_digest)
            || self.capability.provider_id() != self.scope.provider_id()
            || self.binding.provider_id() != self.scope.provider_id()
            || self.binding.adapter_id() != self.adapter.adapter_id()
            || self.binding.adapter_version() != self.adapter.adapter_version()
            || self.binding.schema_digest() != AuthenticatedReadContract::baseline()?.digest()
            || !is_sha256(&self.provider_registry_digest)
            || self.service_revision == 0
        {
            return Err(LiveCanaryError::PluginContract);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> String {
        canonical_digest([
            self.service_id.as_str(),
            self.scope.digest().as_str(),
            self.mission_scope_digest.as_str(),
            self.capability.provider_id(),
            self.capability.capability_id(),
            self.adapter.adapter_id(),
            &self.adapter.adapter_version().to_string(),
            self.binding.implementation_digest(),
            self.binding.schema_digest(),
            self.binding.binary_digest(),
            &format!("{:?}", self.provenance_class),
            self.provider_registry_digest.as_str(),
            self.mission_consumer.consumer_id(),
            &self.mission_consumer.consumer_version().to_string(),
            self.mission_consumer.implementation_digest(),
            &self.service_revision.to_string(),
        ])
    }

    fn validate(&self) -> Result<(), LiveCanaryError> {
        self.validate_without_digest()?;
        if self.definition_digest != self.calculate_digest() {
            return Err(LiveCanaryError::PluginContract);
        }
        Ok(())
    }
}

impl fmt::Debug for ConnectorServiceDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectorServiceDefinition")
            .field("service_id", &self.service_id)
            .field("scope_digest", &self.scope.digest())
            .field("mission_scope_digest", &"<digest>")
            .field("capability", &self.capability)
            .field("adapter", &self.adapter)
            .field("binding", &self.binding)
            .field("provenance_class", &self.provenance_class)
            .field("provider_registry_digest", &"<digest>")
            .field("mission_consumer", &self.mission_consumer)
            .field("service_revision", &self.service_revision)
            .field("definition_digest", &"<digest>")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConnectorPluginDefinition {
    service: ConnectorServiceDefinition,
    provider_registration: ProviderCapabilitySupport,
}

impl ConnectorPluginDefinition {
    pub fn new(
        service: ConnectorServiceDefinition,
        provider_registration: ProviderCapabilitySupport,
    ) -> Result<Self, LiveCanaryError> {
        let definition = Self {
            service,
            provider_registration,
        };
        definition.validate()?;
        Ok(definition)
    }

    pub fn service(&self) -> &ConnectorServiceDefinition {
        &self.service
    }

    pub fn provider_registration(&self) -> &ProviderCapabilitySupport {
        &self.provider_registration
    }

    fn validate(&self) -> Result<(), LiveCanaryError> {
        self.service.validate()?;
        if self.provider_registration.key() != self.service.capability()
            || self.provider_registration.adapter() != self.service.adapter()
            || !self
                .provider_registration
                .evidence_support()
                .iter()
                .any(|support| {
                    support.operation() == ProviderAdapterOperation::Probe
                        && support.evidence_class() == ProviderEvidenceClass::ProbeObservation
                        && support.provenance_class() == self.service.provenance_class()
                })
            || !self
                .provider_registration
                .evidence_support()
                .iter()
                .any(|support| {
                    support.operation() == ProviderAdapterOperation::Read
                        && support.evidence_class() == ProviderEvidenceClass::ReadObservation
                        && support.provenance_class() == self.service.provenance_class()
                })
        {
            return Err(LiveCanaryError::PluginRegistryMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for ConnectorPluginDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectorPluginDefinition")
            .field("service", &self.service)
            .field("provider_registration", &"<registration>")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PluginHandlerBinding {
    handler_id: String,
    handler_version: u32,
    implementation_digest: String,
}

impl PluginHandlerBinding {
    fn new(
        prefix: &str,
        handler_id: impl Into<String>,
        handler_version: u32,
        implementation_digest: impl Into<String>,
    ) -> Result<Self, LiveCanaryError> {
        let binding = Self {
            handler_id: handler_id.into(),
            handler_version,
            implementation_digest: implementation_digest.into(),
        };
        if !valid_prefixed_identifier(&binding.handler_id, prefix)
            || binding.handler_version == 0
            || !is_sha256(&binding.implementation_digest)
        {
            return Err(LiveCanaryError::PluginContract);
        }
        Ok(binding)
    }

    pub fn webhook(
        handler_id: impl Into<String>,
        handler_version: u32,
        implementation_digest: impl Into<String>,
    ) -> Result<Self, LiveCanaryError> {
        Self::new(
            "webhook-handler-",
            handler_id,
            handler_version,
            implementation_digest,
        )
    }

    pub fn effect(
        handler_id: impl Into<String>,
        handler_version: u32,
        implementation_digest: impl Into<String>,
    ) -> Result<Self, LiveCanaryError> {
        Self::new(
            "effect-handler-",
            handler_id,
            handler_version,
            implementation_digest,
        )
    }
}

impl fmt::Debug for PluginHandlerBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginHandlerBinding")
            .field("handler_id", &self.handler_id)
            .field("handler_version", &self.handler_version)
            .field("implementation_digest", &"<digest>")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginHandlerSet {
    webhook: PluginHandlerBinding,
    effect: PluginHandlerBinding,
}

impl PluginHandlerSet {
    pub fn new(webhook: PluginHandlerBinding, effect: PluginHandlerBinding) -> Self {
        Self { webhook, effect }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorPluginState {
    Mounted,
    Unmounted,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PluginResourcePresence {
    Retained,
    Cleared,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PluginResourceState {
    probe: PluginResourcePresence,
    cursor: PluginResourcePresence,
    webhook: PluginResourcePresence,
    effect: PluginResourcePresence,
}

impl PluginResourceState {
    pub const fn probe(&self) -> bool {
        matches!(self.probe, PluginResourcePresence::Retained)
    }

    pub const fn cursor(&self) -> bool {
        matches!(self.cursor, PluginResourcePresence::Retained)
    }

    pub const fn webhook(&self) -> bool {
        matches!(self.webhook, PluginResourcePresence::Retained)
    }

    pub const fn effect(&self) -> bool {
        matches!(self.effect, PluginResourcePresence::Retained)
    }
}

#[derive(Default)]
struct PluginResourceSet {
    probe: Option<TenantAccountProbe>,
    cursor: Option<ReadCheckpoint>,
    webhook: Option<PluginHandlerBinding>,
    effect: Option<PluginHandlerBinding>,
}

impl PluginResourceSet {
    fn state(&self) -> PluginResourceState {
        PluginResourceState {
            probe: if self.probe.is_some() {
                PluginResourcePresence::Retained
            } else {
                PluginResourcePresence::Cleared
            },
            cursor: if self.cursor.is_some() {
                PluginResourcePresence::Retained
            } else {
                PluginResourcePresence::Cleared
            },
            webhook: if self.webhook.is_some() {
                PluginResourcePresence::Retained
            } else {
                PluginResourcePresence::Cleared
            },
            effect: if self.effect.is_some() {
                PluginResourcePresence::Retained
            } else {
                PluginResourcePresence::Cleared
            },
        }
    }

    fn clear(&mut self) {
        self.probe.take();
        self.cursor.take();
        self.webhook.take();
        self.effect.take();
    }
}

/// A mounted plugin owns the read canary and all ephemeral connector
/// resources.  Revoke and unmount consume the resources as one lifecycle
/// transition; no handler survives either transition.
pub struct MountedConnectorPlugin<R, T, C> {
    definition: ConnectorPluginDefinition,
    canary: Option<AuthenticatedReadCanary<R, T>>,
    consumer: Option<C>,
    resources: PluginResourceSet,
    state: ConnectorPluginState,
}

impl<R, T, C> fmt::Debug for MountedConnectorPlugin<R, T, C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MountedConnectorPlugin")
            .field("definition", &self.definition)
            .field("state", &self.state)
            .field("resources", &self.resources.state())
            .finish_non_exhaustive()
    }
}

impl<R, T, C> MountedConnectorPlugin<R, T, C>
where
    R: SecretReferenceResolver,
    T: AuthenticatedReadTransport,
    C: MissionEvidenceConsumer,
{
    pub fn mount(
        definition: ConnectorPluginDefinition,
        registry: &ProviderAdapterRegistry,
        resolver: R,
        transport: T,
        consumer: C,
        handlers: PluginHandlerSet,
    ) -> Result<Self, LiveCanaryError> {
        definition.validate()?;
        registry
            .validate()
            .map_err(|_| LiveCanaryError::PluginRegistryMismatch)?;
        if registry
            .registrations()
            .iter()
            .all(|registration| registration != definition.provider_registration())
            || digest_provider_registry(registry) != definition.service.provider_registry_digest()
            || transport.provenance_class() != definition.service.provenance_class()
        {
            return Err(LiveCanaryError::PluginRegistryMismatch);
        }
        let canary =
            AuthenticatedReadCanary::new(resolver, transport, definition.service.binding.clone())?;
        Ok(Self {
            definition,
            canary: Some(canary),
            consumer: Some(consumer),
            resources: PluginResourceSet {
                webhook: Some(handlers.webhook),
                effect: Some(handlers.effect),
                ..PluginResourceSet::default()
            },
            state: ConnectorPluginState::Mounted,
        })
    }

    pub fn state(&self) -> ConnectorPluginState {
        self.state
    }

    pub fn definition(&self) -> &ConnectorPluginDefinition {
        &self.definition
    }

    pub fn resources(&self) -> PluginResourceState {
        self.resources.state()
    }

    pub fn read(
        &mut self,
        request: &AuthenticatedReadRequest,
    ) -> Result<AuthenticatedReadReport, LiveCanaryError> {
        if self.state != ConnectorPluginState::Mounted {
            return Err(LiveCanaryError::PluginNotMounted);
        }
        if request.scope != *self.definition.service.scope() {
            return Err(LiveCanaryError::PluginScopeMismatch);
        }
        let report = self
            .canary
            .as_mut()
            .ok_or(LiveCanaryError::PluginNotMounted)?
            .run(request)?;
        self.resources.probe = Some(report.probe().clone());
        self.resources.cursor = Some(report.checkpoint().clone());
        self.consumer
            .as_mut()
            .ok_or(LiveCanaryError::PluginNotMounted)?
            .consume_read_evidence(&request.scope, report.evidence())?;
        Ok(report)
    }

    pub fn unmount(&mut self) -> Result<(), LiveCanaryError> {
        self.release(ConnectorPluginState::Unmounted)
    }

    pub fn revoke(&mut self, _at: DateTime<Utc>) -> Result<(), LiveCanaryError> {
        self.release(ConnectorPluginState::Revoked)
    }

    fn release(&mut self, next: ConnectorPluginState) -> Result<(), LiveCanaryError> {
        if self.state != ConnectorPluginState::Mounted {
            return Err(LiveCanaryError::PluginRevoked);
        }
        self.state = next;
        self.canary.take();
        self.consumer.take();
        self.resources.clear();
        Ok(())
    }
}

pub struct AuthenticatedReadCanary<R, T> {
    resolver: R,
    transport: T,
    binding: ConnectorImplementationBinding,
    last_sequence: Option<u64>,
    last_source_revision: Option<u64>,
}

impl<R, T> fmt::Debug for AuthenticatedReadCanary<R, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedReadCanary")
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

impl<R, T> AuthenticatedReadCanary<R, T>
where
    R: SecretReferenceResolver,
    T: AuthenticatedReadTransport,
{
    pub fn new(
        resolver: R,
        transport: T,
        binding: ConnectorImplementationBinding,
    ) -> Result<Self, LiveCanaryError> {
        AuthenticatedReadContract::baseline()?;
        binding.validate()?;
        Ok(Self {
            resolver,
            transport,
            binding,
            last_sequence: None,
            last_source_revision: None,
        })
    }

    pub fn run(
        &mut self,
        request: &AuthenticatedReadRequest,
    ) -> Result<AuthenticatedReadReport, LiveCanaryError> {
        request.validate()?;
        let requested_sequence = request.cursor.as_ref().map_or(1, Cursor::sequence);
        if self
            .last_sequence
            .is_some_and(|last_sequence| requested_sequence <= last_sequence)
        {
            return Err(LiveCanaryError::InvalidCheckpoint);
        }
        let secret = self.resolver.resolve(
            &request.secret_reference,
            &request.credential_lease,
            request.at,
        )?;
        let probe_response =
            self.transport
                .authenticated_probe(&request.scope, &secret, request.at)?;
        probe_response.validate_against(&request.budget, request.at)?;
        let probe_ok = probe_response.provider_error().is_ok();
        let provenance_class = self.transport.provenance_class();
        let probe_error = probe_response
            .provider_error()
            .err()
            .map(|error| match error {
                LiveCanaryError::Provider(provider) => provider,
                _ => {
                    ProviderError::new(ProviderErrorKind::Unknown, "probe_error", None, false, None)
                        .expect("static provider error")
                }
            });
        let probe = TenantAccountProbe::from_input(
            &request.scope,
            TenantAccountProbeInput {
                adapter: request.adapter.clone(),
                credential_revision: request.credential_lease.credential_revision(),
                lease_revision: request.credential_lease.lease_revision(),
                auth_revision: request.auth_revision,
                probe_revision: request.probe_revision,
                outcome: if probe_ok {
                    ProbeOutcome::Reachable
                } else {
                    ProbeOutcome::Rejected
                },
                observed_at: request.at,
                expires_at: probe_response.freshness_deadline(),
                evidence_digest: probe_response.response_digest().to_owned(),
            },
        )?;
        if !probe_ok {
            let provider_error = probe_error.ok_or(LiveCanaryError::InvalidResponse)?;
            return self.rejected_report(
                request,
                probe,
                &probe_response,
                provenance_class,
                provider_error,
            );
        }
        let response = self.transport.read(request, &secret)?;
        response.validate_against(&request.budget, request.at)?;
        if response.page_sequence() != requested_sequence {
            return Err(LiveCanaryError::InvalidCheckpoint);
        }
        if self
            .last_source_revision
            .is_some_and(|last_revision| response.source_revision() < last_revision)
        {
            return Err(LiveCanaryError::InvalidCheckpoint);
        }
        self.read_report(request, probe, &response, provenance_class)
    }

    fn rejected_report(
        &self,
        request: &AuthenticatedReadRequest,
        probe: TenantAccountProbe,
        response: &ProviderHttpResponse,
        provenance_class: ProviderProvenanceClass,
        provider_error: ProviderError,
    ) -> Result<AuthenticatedReadReport, LiveCanaryError> {
        let status = status_for_provider_error(provider_error.kind());
        let observation = ReadObservation::new(
            "read-observation-rejected",
            request.scope.clone(),
            request.capability.clone(),
            request.adapter.clone(),
            request.query_digest.clone(),
            response.response_digest().to_owned(),
            response.content_digest().to_owned(),
            provenance_class,
            FreshnessWindow::new(
                request.at,
                response.freshness_deadline(),
                response.source_revision(),
            )?,
            response.page_sequence(),
            0,
            None,
        )?;
        let evidence = ReadEvidenceEnvelope::new(
            "read-evidence-rejected",
            status,
            &request.scope,
            &probe,
            request.query_digest.clone(),
            response,
            self.binding.clone(),
            provenance_class,
            Some(provider_error.clone()),
            request.at,
        )?;
        let checkpoint = ReadCheckpoint::from_response(
            &request.scope,
            request.query_digest.clone(),
            response.page_sequence(),
            response.source_revision(),
            evidence.envelope_digest().to_owned(),
            None,
            request.at,
        )?;
        Ok(AuthenticatedReadReport {
            status,
            probe,
            observation,
            checkpoint,
            evidence,
            provider_error: Some(provider_error),
        })
    }

    fn read_report(
        &mut self,
        request: &AuthenticatedReadRequest,
        probe: TenantAccountProbe,
        response: &ProviderHttpResponse,
        provenance_class: ProviderProvenanceClass,
    ) -> Result<AuthenticatedReadReport, LiveCanaryError> {
        let provider_error = response.provider_error().err().map(|error| match error {
            LiveCanaryError::Provider(provider) => provider,
            _ => ProviderError::new(ProviderErrorKind::Unknown, "read_error", None, false, None)
                .expect("static provider error"),
        });
        let status = provider_error.as_ref().map_or_else(
            || {
                if provenance_class == ProviderProvenanceClass::ProductionProvider {
                    ReadCanaryStatus::Connected
                } else {
                    ReadCanaryStatus::Degraded
                }
            },
            |error| status_for_provider_error(error.kind()),
        );
        let next_cursor = response
            .next_cursor_token_digest()
            .map(|token_digest| {
                Cursor::new(
                    &request.scope,
                    request.query_digest.clone(),
                    response.page_sequence().saturating_add(1),
                    token_digest,
                )
            })
            .transpose()?;
        let observation = ReadObservation::new(
            "read-observation-canary",
            request.scope.clone(),
            request.capability.clone(),
            request.adapter.clone(),
            request.query_digest.clone(),
            response.response_digest().to_owned(),
            response.content_digest().to_owned(),
            provenance_class,
            FreshnessWindow::new(
                request.at,
                response.freshness_deadline(),
                response.source_revision(),
            )?,
            response.page_sequence(),
            u32::try_from(response.body_len().min(u64::from(u32::MAX)))
                .expect("bounded response length"),
            next_cursor.clone(),
        )?;
        let evidence = ReadEvidenceEnvelope::new(
            "read-evidence-canary",
            status,
            &request.scope,
            &probe,
            request.query_digest.clone(),
            response,
            self.binding.clone(),
            provenance_class,
            provider_error.clone(),
            request.at,
        )?;
        let checkpoint = ReadCheckpoint::from_response(
            &request.scope,
            request.query_digest.clone(),
            response.page_sequence(),
            response.source_revision(),
            evidence.envelope_digest().to_owned(),
            next_cursor,
            request.at,
        )?;
        if provider_error.is_none() {
            self.last_sequence = Some(response.page_sequence());
            self.last_source_revision = Some(response.source_revision());
        }
        Ok(AuthenticatedReadReport {
            status,
            probe,
            observation,
            checkpoint,
            evidence,
            provider_error,
        })
    }
}

fn status_for_provider_error(kind: ProviderErrorKind) -> ReadCanaryStatus {
    match kind {
        ProviderErrorKind::Authentication
        | ProviderErrorKind::Authorization
        | ProviderErrorKind::Expired => ReadCanaryStatus::Revoked,
        _ => ReadCanaryStatus::Degraded,
    }
}

#[derive(Clone)]
pub struct NativeReadConfig {
    pub scope: ConnectorScope,
    pub secret_reference: SecretReference,
    pub credential_lease: CredentialLease,
    pub session: AuthSession,
    pub adapter: ProviderAdapterIdentity,
    pub capability: ProviderCapabilityKey,
    pub probe_url: String,
    pub read_url: String,
    pub query_digest: String,
    pub binding: ConnectorImplementationBinding,
    pub at: DateTime<Utc>,
    pub budget: ReadBudgetMetadata,
}

impl fmt::Debug for NativeReadConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeReadConfig")
            .field("scope_digest", &self.scope.digest())
            .field("adapter", &self.adapter)
            .field("capability", &self.capability)
            .field("query_digest", &"<digest>")
            .field("binding", &self.binding)
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

impl NativeReadConfig {
    pub fn from_environment(now: DateTime<Utc>) -> Result<Self, LiveCanaryError> {
        let required = [
            "HARTEVO_CANARY_PROBE_URL",
            "HARTEVO_CANARY_READ_URL",
            "HARTEVO_CANARY_TOKEN",
            "HARTEVO_CANARY_TENANT",
            "HARTEVO_CANARY_PROJECT",
            "HARTEVO_CANARY_PROVIDER",
            "HARTEVO_CANARY_ACCOUNT",
            "HARTEVO_CANARY_ADAPTER",
            "HARTEVO_CANARY_ADAPTER_VERSION",
            "HARTEVO_CANARY_CAPABILITY",
            "HARTEVO_CANARY_IMPLEMENTATION_DIGEST",
            "HARTEVO_CANARY_BINARY_DIGEST",
        ];
        let mut missing = Vec::new();
        let mut values = std::collections::BTreeMap::new();
        for name in required {
            match std::env::var(name) {
                Ok(value) if !value.is_empty() => {
                    values.insert(name, value);
                }
                _ => missing.push(name.to_owned()),
            }
        }
        if !missing.is_empty() {
            return Err(LiveCanaryError::BlockedEnv(missing.join(",")));
        }
        let scope = ConnectorScope::new(
            values["HARTEVO_CANARY_TENANT"].clone(),
            values["HARTEVO_CANARY_PROJECT"].clone(),
            values["HARTEVO_CANARY_PROVIDER"].clone(),
            values["HARTEVO_CANARY_ACCOUNT"].clone(),
            [values["HARTEVO_CANARY_CAPABILITY"].clone()],
        )?;
        let adapter_version = values["HARTEVO_CANARY_ADAPTER_VERSION"]
            .parse::<u32>()
            .map_err(|_| LiveCanaryError::InvalidBinding)?;
        let adapter =
            ProviderAdapterIdentity::new(values["HARTEVO_CANARY_ADAPTER"].clone(), adapter_version)
                .map_err(|_| LiveCanaryError::InvalidBinding)?;
        let capability = ProviderCapabilityKey::new(
            scope.provider_id().to_owned(),
            values["HARTEVO_CANARY_CAPABILITY"].clone(),
        )
        .map_err(|_| LiveCanaryError::InvalidResponse)?;
        let secret = SecretReference::new("secret-ref-native-canary", scope.clone(), 1)
            .map_err(|_| LiveCanaryError::InvalidResponse)?;
        let lease = super::ConnectorAuth::issue_credential_lease(
            &secret,
            adapter.clone(),
            "credential-lease-native-canary",
            1,
            now,
            now + Duration::minutes(5),
        )
        .map_err(|_| LiveCanaryError::Expired)?;
        let session = super::ConnectorAuth::begin_auth_session(
            &secret,
            &lease,
            "auth-session-native-canary",
            1,
            now,
            now + Duration::minutes(5),
        )
        .map_err(|_| LiveCanaryError::Expired)?;
        let contract = AuthenticatedReadContract::baseline()?;
        let binding = ConnectorImplementationBinding::from_adapter(
            scope.provider_id().to_owned(),
            &adapter,
            values["HARTEVO_CANARY_IMPLEMENTATION_DIGEST"].clone(),
            contract.digest(),
            values["HARTEVO_CANARY_BINARY_DIGEST"].clone(),
        )?;
        let query_digest = digest_bytes(values["HARTEVO_CANARY_READ_URL"].as_bytes());
        let budget = ReadBudgetMetadata::new(1, 1, 0, now + Duration::minutes(5), now)?;
        Ok(Self {
            scope,
            secret_reference: secret,
            credential_lease: lease,
            session,
            adapter,
            capability,
            probe_url: values["HARTEVO_CANARY_PROBE_URL"].clone(),
            read_url: values["HARTEVO_CANARY_READ_URL"].clone(),
            query_digest,
            binding,
            at: now,
            budget,
        })
    }

    pub fn request(&self) -> AuthenticatedReadRequest {
        AuthenticatedReadRequest {
            scope: self.scope.clone(),
            secret_reference: self.secret_reference.clone(),
            credential_lease: self.credential_lease.clone(),
            session: self.session.clone(),
            adapter: self.adapter.clone(),
            capability: self.capability.clone(),
            query_digest: self.query_digest.clone(),
            cursor: None,
            page_size: 100,
            probe_revision: 1,
            auth_revision: 1,
            at: self.at,
            budget: self.budget.clone(),
        }
    }
}

pub struct NativeReadRunner {
    config: NativeReadConfig,
}

impl fmt::Debug for NativeReadRunner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeReadRunner")
            .field("scope_digest", &self.config.scope.digest())
            .field("binding", &self.config.binding)
            .finish_non_exhaustive()
    }
}

impl NativeReadRunner {
    pub fn from_environment(now: DateTime<Utc>) -> Result<Self, LiveCanaryError> {
        Ok(Self {
            config: NativeReadConfig::from_environment(now)?,
        })
    }

    pub fn config(&self) -> &NativeReadConfig {
        &self.config
    }

    pub fn run(&self) -> Result<AuthenticatedReadReport, LiveCanaryError> {
        let transport = CurlReadTransport {
            probe_url: self.config.probe_url.clone(),
            read_url: self.config.read_url.clone(),
        };
        let mut canary = AuthenticatedReadCanary::new(
            EnvironmentSecretResolver::new("HARTEVO_CANARY_TOKEN")?,
            transport,
            self.config.binding.clone(),
        )?;
        let request = self.config.request();
        canary.run(&request)
    }
}

struct CurlReadTransport {
    probe_url: String,
    read_url: String,
}

impl CurlReadTransport {
    fn request(
        url: &str,
        secret: &ResolvedSecret,
        at: DateTime<Utc>,
    ) -> Result<ProviderHttpResponse, LiveCanaryError> {
        let config = secret.with_bytes(|bytes| {
            let token = std::str::from_utf8(bytes).map_err(|_| LiveCanaryError::Transport)?;
            if token.contains('"') || token.contains('\n') || token.contains('\r') {
                return Err(LiveCanaryError::Transport);
            }
            Ok(format!(
                "url = \"{}\"\nheader = \"Authorization: Bearer {}\"\nlocation\nmax-time = 20\nwrite-out = \"\\nHARTEVO_STATUS:%{{http_code}}\"\n",
                escape_curl_config(url)?,
                token
            ))
        })?;
        let mut child = Command::new("curl")
            .args(["--silent", "--show-error", "--config", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| LiveCanaryError::Transport)?;
        child
            .stdin
            .take()
            .ok_or(LiveCanaryError::Transport)?
            .write_all(config.as_bytes())
            .map_err(|_| LiveCanaryError::Transport)?;
        let output = child
            .wait_with_output()
            .map_err(|_| LiveCanaryError::Transport)?;
        let marker = b"HARTEVO_STATUS:";
        let marker_index = output
            .stdout
            .windows(marker.len())
            .rposition(|window| window == marker)
            .ok_or(LiveCanaryError::Transport)?;
        let body = &output.stdout[..marker_index.saturating_sub(1)];
        let status = std::str::from_utf8(&output.stdout[marker_index + marker.len()..])
            .ok()
            .and_then(|value| value.trim().parse::<u16>().ok())
            .ok_or(LiveCanaryError::Transport)?;
        if !output.status.success() && !(200..=599).contains(&status) {
            return Err(LiveCanaryError::Transport);
        }
        ProviderHttpResponse::from_body(status, body, 1, at + Duration::minutes(5), 1, 1, 0, None)
    }
}

impl AuthenticatedReadTransport for CurlReadTransport {
    fn authenticated_probe(
        &mut self,
        _scope: &ConnectorScope,
        secret: &ResolvedSecret,
        at: DateTime<Utc>,
    ) -> Result<ProviderHttpResponse, LiveCanaryError> {
        Self::request(&self.probe_url, secret, at)
    }

    fn read(
        &mut self,
        request: &AuthenticatedReadRequest,
        secret: &ResolvedSecret,
    ) -> Result<ProviderHttpResponse, LiveCanaryError> {
        Self::request(&self.read_url, secret, request.at)
    }
}

fn escape_curl_config(value: &str) -> Result<String, LiveCanaryError> {
    if value.contains('"') || value.contains('\n') || value.contains('\r') {
        return Err(LiveCanaryError::Transport);
    }
    Ok(value.to_owned())
}

fn exact_set<T: Ord + Copy>(actual: &[T], expected: &[T]) -> bool {
    actual.len() == expected.len()
        && actual
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            == expected
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
}

fn digest_bytes(value: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(value);
    super::hex_encode(&digest.finalize())
}

fn digest_provider_registry(registry: &ProviderAdapterRegistry) -> String {
    let document = serde_json::to_string(registry).expect("provider registry is serializable");
    digest_bytes(document.as_bytes())
}

#[cfg(any(test, feature = "testkit"))]
pub mod deterministic {
    use super::{
        AuthenticatedReadRequest, AuthenticatedReadTransport, ConnectorScope, CredentialLease,
        DateTime, LiveCanaryError, ProviderHttpResponse, ProviderProvenanceClass, ResolvedSecret,
        SecretReference, SecretReferenceResolver, Utc,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub struct FixedSecretResolver {
        value: Vec<u8>,
    }

    impl FixedSecretResolver {
        pub fn new(value: impl AsRef<[u8]>) -> Self {
            Self {
                value: value.as_ref().to_vec(),
            }
        }
    }

    impl std::fmt::Debug for FixedSecretResolver {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("FixedSecretResolver")
                .field("present", &true)
                .finish()
        }
    }

    impl SecretReferenceResolver for FixedSecretResolver {
        fn resolve(
            &self,
            reference: &SecretReference,
            lease: &CredentialLease,
            now: DateTime<Utc>,
        ) -> Result<ResolvedSecret, super::SecretResolutionError> {
            lease
                .validate(reference, now)
                .map_err(|_| super::SecretResolutionError::Expired)?;
            ResolvedSecret::from_bytes(&self.value)
        }
    }

    pub struct DeterministicReadTransport {
        probe: ProviderHttpResponse,
        pages: Vec<ProviderHttpResponse>,
        retry: Option<(ProviderHttpResponse, bool)>,
        probe_calls: AtomicUsize,
        read_calls: AtomicUsize,
    }

    impl DeterministicReadTransport {
        pub fn new(probe: ProviderHttpResponse, pages: Vec<ProviderHttpResponse>) -> Self {
            Self {
                probe,
                pages,
                retry: None,
                probe_calls: AtomicUsize::new(0),
                read_calls: AtomicUsize::new(0),
            }
        }

        pub fn probe_calls(&self) -> usize {
            self.probe_calls.load(Ordering::Acquire)
        }

        pub fn read_calls(&self) -> usize {
            self.read_calls.load(Ordering::Acquire)
        }

        #[must_use]
        pub fn with_retry(mut self, first_response: ProviderHttpResponse) -> Self {
            self.retry = Some((first_response, false));
            self
        }
    }

    impl std::fmt::Debug for DeterministicReadTransport {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("DeterministicReadTransport")
                .field("probe", &"<response>")
                .field("page_count", &self.pages.len())
                .field("probe_calls", &self.probe_calls())
                .field("read_calls", &self.read_calls())
                .finish_non_exhaustive()
        }
    }

    impl AuthenticatedReadTransport for DeterministicReadTransport {
        fn provenance_class(&self) -> ProviderProvenanceClass {
            ProviderProvenanceClass::Fixture
        }

        fn authenticated_probe(
            &mut self,
            _scope: &ConnectorScope,
            _secret: &ResolvedSecret,
            _at: DateTime<Utc>,
        ) -> Result<ProviderHttpResponse, LiveCanaryError> {
            self.probe_calls.fetch_add(1, Ordering::AcqRel);
            Ok(self.probe.clone())
        }

        fn read(
            &mut self,
            request: &AuthenticatedReadRequest,
            _secret: &ResolvedSecret,
        ) -> Result<ProviderHttpResponse, LiveCanaryError> {
            self.read_calls.fetch_add(1, Ordering::AcqRel);
            if let Some((response, consumed)) = &mut self.retry
                && !*consumed
            {
                *consumed = true;
                return Ok(response.clone());
            }
            let index = request.cursor.as_ref().map_or(0, |cursor| {
                usize::try_from(cursor.sequence().saturating_sub(1)).unwrap_or(usize::MAX)
            });
            self.pages
                .get(index)
                .cloned()
                .ok_or(LiveCanaryError::InvalidCheckpoint)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::deterministic::{DeterministicReadTransport, FixedSecretResolver};
    use super::*;
    use chrono::Duration;
    use hartevo_effect_broker::ProviderEvidenceSupport;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fixture_request(now: DateTime<Utc>) -> Result<AuthenticatedReadRequest, LiveCanaryError> {
        let scope = ConnectorScope::new(
            "tenant-live",
            "project-live",
            "provider-live",
            "account-live",
            ["research.read".to_owned()],
        )?;
        let adapter = ProviderAdapterIdentity::new("live.connector", 1)
            .map_err(|_| LiveCanaryError::InvalidBinding)?;
        let secret = SecretReference::new("secret-ref-live", scope.clone(), 1)?;
        let lease = super::super::ConnectorAuth::issue_credential_lease(
            &secret,
            adapter.clone(),
            "credential-lease-live",
            1,
            now,
            now + Duration::minutes(5),
        )?;
        let session = super::super::ConnectorAuth::begin_auth_session(
            &secret,
            &lease,
            "auth-session-live",
            1,
            now,
            now + Duration::minutes(5),
        )?;
        let capability = ProviderCapabilityKey::new("provider-live", "research.read")
            .map_err(|error| LiveCanaryError::Connector(error.into()))?;
        let budget = ReadBudgetMetadata::new(5, 5, 2, now + Duration::minutes(2), now)?;
        Ok(AuthenticatedReadRequest {
            scope,
            secret_reference: secret,
            credential_lease: lease,
            session,
            adapter,
            capability,
            query_digest: digest_bytes(b"live-query"),
            cursor: None,
            page_size: 100,
            probe_revision: 1,
            auth_revision: 1,
            at: now,
            budget,
        })
    }

    fn fixture_binding() -> Result<ConnectorImplementationBinding, LiveCanaryError> {
        let adapter = ProviderAdapterIdentity::new("live.connector", 1)
            .map_err(|_| LiveCanaryError::InvalidBinding)?;
        ConnectorImplementationBinding::from_adapter(
            "provider-live",
            &adapter,
            digest_bytes(b"live-implementation"),
            AuthenticatedReadContract::baseline()?.digest(),
            digest_bytes(b"live-binary"),
        )
    }

    fn fixture_plugin(
        now: DateTime<Utc>,
    ) -> Result<
        (
            ConnectorPluginDefinition,
            ProviderAdapterRegistry,
            AuthenticatedReadRequest,
        ),
        LiveCanaryError,
    > {
        let request = fixture_request(now)?;
        let binding = fixture_binding()?;
        let probe_support = ProviderEvidenceSupport::new(
            ProviderAdapterOperation::Probe,
            ProviderEvidenceClass::ProbeObservation,
            ProviderProvenanceClass::Fixture,
        )
        .map_err(|_| LiveCanaryError::PluginRegistryMismatch)?;
        let read_support = ProviderEvidenceSupport::new(
            ProviderAdapterOperation::Read,
            ProviderEvidenceClass::ReadObservation,
            ProviderProvenanceClass::Fixture,
        )
        .map_err(|_| LiveCanaryError::PluginRegistryMismatch)?;
        let registration = ProviderCapabilitySupport::new(
            request.capability.clone(),
            request.adapter.clone(),
            [probe_support, read_support],
        )
        .map_err(|_| LiveCanaryError::PluginRegistryMismatch)?;
        let registry = ProviderAdapterRegistry::new("live-registry-1", [registration.clone()])
            .map_err(|_| LiveCanaryError::PluginRegistryMismatch)?;
        let consumer = MissionConsumerBinding::new(
            "mission-consumer-live",
            1,
            digest_bytes(b"mission-consumer-live"),
        )?;
        let service = ConnectorServiceDefinition::new(
            "connector-service-live",
            request.scope.clone(),
            digest_bytes(b"mission-scope-live"),
            request.capability.clone(),
            request.adapter.clone(),
            binding,
            ProviderProvenanceClass::Fixture,
            digest_provider_registry(&registry),
            consumer,
            1,
        )?;
        Ok((
            ConnectorPluginDefinition::new(service, registration)?,
            registry,
            request,
        ))
    }

    struct CountingConsumer(Arc<AtomicUsize>);

    impl MissionEvidenceConsumer for CountingConsumer {
        fn consume_read_evidence(
            &mut self,
            scope: &ConnectorScope,
            evidence: &ReadEvidenceEnvelope,
        ) -> Result<(), LiveCanaryError> {
            if scope.digest() != evidence.scope_digest() {
                return Err(LiveCanaryError::PluginScopeMismatch);
            }
            self.0.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    #[test]
    fn checked_in_contract_and_binding_tamper_fail_closed() -> Result<(), LiveCanaryError> {
        let contract = AuthenticatedReadContract::baseline()?;
        assert!(contract.registrations().is_empty());
        let baseline = include_str!("../../../contracts/connectors/authenticated-read.v1.json");
        assert!(matches!(
            AuthenticatedReadContract::from_json(&baseline.replace(
                "\"registrations\": []",
                "\"registrations\": [], \"unknown\": true"
            )),
            Err(LiveCanaryError::InvalidContract(_))
        ));
        assert!(matches!(
            AuthenticatedReadContract::from_json(&baseline.replace(
                "\"connected\",\n    \"degraded\"",
                "\"connected\",\n    \"connected\""
            )),
            Err(LiveCanaryError::InvalidContract(_))
        ));
        assert!(matches!(
            AuthenticatedReadContract::from_json(&baseline.replace(
                "\"mount\",\n      \"unmount\"",
                "\"mount\",\n      \"mount\""
            )),
            Err(LiveCanaryError::InvalidContract(_))
        ));
        let mut binding = fixture_binding()?;
        binding.schema_digest = digest_bytes(b"tampered-schema");
        let now = DateTime::UNIX_EPOCH;
        let request = fixture_request(now)?;
        let probe = TenantAccountProbe::from_input(
            &request.scope,
            TenantAccountProbeInput {
                adapter: request.adapter.clone(),
                credential_revision: 1,
                lease_revision: 1,
                auth_revision: 1,
                probe_revision: 1,
                outcome: ProbeOutcome::Reachable,
                observed_at: now,
                expires_at: now + Duration::minutes(1),
                evidence_digest: digest_bytes(b"probe"),
            },
        )?;
        let response = ProviderHttpResponse::from_body(
            200,
            b"body",
            1,
            now + Duration::minutes(1),
            1,
            1,
            0,
            None,
        )?;
        assert!(matches!(
            ReadEvidenceEnvelope::new(
                "read-evidence-tamper",
                ReadCanaryStatus::Connected,
                &request.scope,
                &probe,
                digest_bytes(b"query"),
                &response,
                binding,
                ProviderProvenanceClass::ProductionProvider,
                None,
                now,
            ),
            Err(LiveCanaryError::InvalidResponse | LiveCanaryError::InvalidBinding)
        ));
        Ok(())
    }

    #[test]
    fn deterministic_canary_paginates_and_replay_is_rejected() -> Result<(), LiveCanaryError> {
        let now = DateTime::UNIX_EPOCH + Duration::seconds(1_700_000_000);
        let request = fixture_request(now)?;
        let probe = ProviderHttpResponse::from_body(
            200,
            b"probe",
            1,
            now + Duration::minutes(1),
            4,
            4,
            1,
            None,
        )?;
        let page_one = ProviderHttpResponse::from_body(
            200,
            b"page-one",
            10,
            now + Duration::minutes(1),
            4,
            4,
            1,
            Some(digest_bytes(b"page-two")),
        )?;
        let page_two = ProviderHttpResponse::from_body(
            200,
            b"page-two",
            11,
            now + Duration::minutes(1),
            3,
            3,
            1,
            None,
        )?
        .with_page_sequence(2)?;
        let transport = DeterministicReadTransport::new(probe, vec![page_one, page_two]);
        let mut canary = AuthenticatedReadCanary::new(
            FixedSecretResolver::new(b"synthetic-secret"),
            transport,
            fixture_binding()?,
        )?;
        let first = canary.run(&request)?;
        assert_eq!(first.status(), ReadCanaryStatus::Degraded);
        assert_eq!(
            first.evidence().provenance_class(),
            ProviderProvenanceClass::Fixture
        );
        let cursor = first
            .checkpoint()
            .next_cursor()
            .cloned()
            .ok_or(LiveCanaryError::InvalidCheckpoint)?;
        let mut second_request = request;
        second_request.cursor = Some(cursor);
        let second = canary.run(&second_request)?;
        assert_eq!(second.checkpoint().sequence(), 2);
        assert_eq!(second.status(), ReadCanaryStatus::Degraded);
        assert!(matches!(
            canary.run(&second_request),
            Err(LiveCanaryError::InvalidCheckpoint)
        ));
        Ok(())
    }

    #[test]
    fn deterministic_rate_limit_errors_are_typed() -> Result<(), LiveCanaryError> {
        let now = DateTime::UNIX_EPOCH + Duration::seconds(1_700_000_000);
        let request = fixture_request(now)?;
        let probe = ProviderHttpResponse::from_body(
            429,
            b"rate-limit",
            1,
            now + Duration::minutes(1),
            0,
            0,
            0,
            None,
        )?;
        let page = ProviderHttpResponse::from_body(
            200,
            b"unused",
            1,
            now + Duration::minutes(1),
            1,
            1,
            0,
            None,
        )?;
        let mut canary = AuthenticatedReadCanary::new(
            FixedSecretResolver::new(b"synthetic-secret"),
            DeterministicReadTransport::new(probe, vec![page]),
            fixture_binding()?,
        )?;
        let report = canary.run(&request)?;
        assert_eq!(report.status(), ReadCanaryStatus::Degraded);
        assert_eq!(
            report.provider_error().map(ProviderError::kind),
            Some(ProviderErrorKind::RateLimited)
        );
        Ok(())
    }

    #[test]
    fn deterministic_retry_recovers_after_typed_provider_error() -> Result<(), LiveCanaryError> {
        let now = DateTime::UNIX_EPOCH + Duration::seconds(1_700_000_000);
        let request = fixture_request(now)?;
        let successful_probe = ProviderHttpResponse::from_body(
            200,
            b"probe",
            1,
            now + Duration::minutes(1),
            5,
            5,
            0,
            None,
        )?;
        let successful_page = ProviderHttpResponse::from_body(
            200,
            b"retry-success",
            2,
            now + Duration::minutes(1),
            4,
            4,
            1,
            None,
        )?;
        let retry_response = ProviderHttpResponse::from_body(
            429,
            b"retry-later",
            1,
            now + Duration::minutes(1),
            0,
            0,
            0,
            None,
        )?;
        let mut retry_canary = AuthenticatedReadCanary::new(
            FixedSecretResolver::new(b"synthetic-secret"),
            DeterministicReadTransport::new(successful_probe, vec![successful_page])
                .with_retry(retry_response),
            fixture_binding()?,
        )?;
        assert_eq!(
            retry_canary.run(&request)?.status(),
            ReadCanaryStatus::Degraded
        );
        assert_eq!(
            retry_canary.run(&request)?.status(),
            ReadCanaryStatus::Degraded
        );
        Ok(())
    }

    #[test]
    fn deterministic_revocation_and_expiry_are_rejected() -> Result<(), LiveCanaryError> {
        let now = DateTime::UNIX_EPOCH + Duration::seconds(1_700_000_000);
        let request = fixture_request(now)?;
        let mut revoked = request;
        revoked.secret_reference.revoke(now)?;
        let probe = ProviderHttpResponse::from_body(
            200,
            b"probe",
            1,
            now + Duration::minutes(1),
            1,
            1,
            0,
            None,
        )?;
        let page = probe.clone();
        let mut revoked_canary = AuthenticatedReadCanary::new(
            FixedSecretResolver::new(b"synthetic-secret"),
            DeterministicReadTransport::new(probe, vec![page]),
            fixture_binding()?,
        )?;
        assert!(matches!(
            revoked_canary.run(&revoked),
            Err(LiveCanaryError::Revoked)
        ));

        let mut expired = fixture_request(now)?;
        expired.at = now + Duration::minutes(6);
        let probe = ProviderHttpResponse::from_body(
            200,
            b"probe",
            1,
            expired.at + Duration::minutes(1),
            1,
            1,
            0,
            None,
        )?;
        let mut expired_canary = AuthenticatedReadCanary::new(
            FixedSecretResolver::new(b"synthetic-secret"),
            DeterministicReadTransport::new(probe.clone(), vec![probe]),
            fixture_binding()?,
        )?;
        assert!(matches!(
            expired_canary.run(&expired),
            Err(LiveCanaryError::Expired)
        ));
        Ok(())
    }

    #[test]
    fn plugin_mount_binds_registration_scope_and_mission_consumer() -> Result<(), LiveCanaryError> {
        let now = DateTime::UNIX_EPOCH + Duration::seconds(1_700_000_000);
        let (definition, registry, request) = fixture_plugin(now)?;
        let seen = Arc::new(AtomicUsize::new(0));
        let probe = ProviderHttpResponse::from_body(
            200,
            b"probe",
            1,
            now + Duration::minutes(1),
            2,
            2,
            0,
            None,
        )?;
        let page = ProviderHttpResponse::from_body(
            200,
            b"page",
            1,
            now + Duration::minutes(1),
            1,
            1,
            0,
            None,
        )?;
        let handlers = PluginHandlerSet::new(
            PluginHandlerBinding::webhook(
                "webhook-handler-live",
                1,
                digest_bytes(b"webhook-handler-live"),
            )?,
            PluginHandlerBinding::effect(
                "effect-handler-live",
                1,
                digest_bytes(b"effect-handler-live"),
            )?,
        );
        let mut plugin = MountedConnectorPlugin::mount(
            definition,
            &registry,
            FixedSecretResolver::new(b"synthetic-secret"),
            DeterministicReadTransport::new(probe, vec![page]),
            CountingConsumer(Arc::clone(&seen)),
            handlers,
        )?;
        assert_eq!(plugin.state(), ConnectorPluginState::Mounted);
        assert!(!plugin.resources().probe());
        assert!(plugin.resources().webhook());
        let report = plugin.read(&request)?;
        assert_eq!(report.status(), ReadCanaryStatus::Degraded);
        assert_eq!(
            report.evidence().provenance_class(),
            ProviderProvenanceClass::Fixture
        );
        assert_eq!(seen.load(Ordering::Acquire), 1);
        assert!(plugin.resources().probe());
        assert!(plugin.resources().cursor());
        plugin.unmount()?;
        assert_eq!(plugin.state(), ConnectorPluginState::Unmounted);
        assert_eq!(
            plugin.resources(),
            PluginResourceState {
                probe: PluginResourcePresence::Cleared,
                cursor: PluginResourcePresence::Cleared,
                webhook: PluginResourcePresence::Cleared,
                effect: PluginResourcePresence::Cleared,
            }
        );
        assert!(matches!(
            plugin.read(&request),
            Err(LiveCanaryError::PluginNotMounted)
        ));
        Ok(())
    }

    #[test]
    fn plugin_revoke_is_atomic_and_empty_registry_stays_blocked() -> Result<(), LiveCanaryError> {
        let now = DateTime::UNIX_EPOCH + Duration::seconds(1_700_000_000);
        let (definition, registry, request) = fixture_plugin(now)?;
        let empty = ProviderAdapterRegistry::contract_baseline()
            .map_err(|_| LiveCanaryError::PluginRegistryMismatch)?;
        assert!(empty.is_empty());
        let probe = ProviderHttpResponse::from_body(
            200,
            b"probe",
            1,
            now + Duration::minutes(1),
            1,
            1,
            0,
            None,
        )?;
        let page = probe.clone();
        let handlers = PluginHandlerSet::new(
            PluginHandlerBinding::webhook(
                "webhook-handler-empty",
                1,
                digest_bytes(b"webhook-handler-empty"),
            )?,
            PluginHandlerBinding::effect(
                "effect-handler-empty",
                1,
                digest_bytes(b"effect-handler-empty"),
            )?,
        );
        assert!(matches!(
            MountedConnectorPlugin::mount(
                definition.clone(),
                &empty,
                FixedSecretResolver::new(b"synthetic-secret"),
                DeterministicReadTransport::new(probe.clone(), vec![page.clone()]),
                CountingConsumer(Arc::new(AtomicUsize::new(0))),
                handlers.clone(),
            ),
            Err(LiveCanaryError::PluginRegistryMismatch)
        ));
        let mut plugin = MountedConnectorPlugin::mount(
            definition,
            &registry,
            FixedSecretResolver::new(b"synthetic-secret"),
            DeterministicReadTransport::new(probe, vec![page]),
            CountingConsumer(Arc::new(AtomicUsize::new(0))),
            handlers,
        )?;
        plugin.read(&request)?;
        plugin.revoke(now)?;
        assert_eq!(plugin.state(), ConnectorPluginState::Revoked);
        assert!(!plugin.resources().probe());
        assert!(!plugin.resources().cursor());
        assert!(!plugin.resources().webhook());
        assert!(!plugin.resources().effect());
        Ok(())
    }

    #[test]
    fn debug_redaction_excludes_account_and_secret_material() -> Result<(), LiveCanaryError> {
        let now = DateTime::UNIX_EPOCH + Duration::seconds(1_700_000_000);
        let request = fixture_request(now)?;
        let debug = format!("{request:?}");
        assert!(!debug.contains("account-live"));
        assert!(!debug.contains("secret-ref-live"));
        assert!(
            !format!("{:?}", FixedSecretResolver::new(b"synthetic-secret")).contains("synthetic")
        );
        Ok(())
    }
}
