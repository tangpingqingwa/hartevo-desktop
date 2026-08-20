use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::events::{ConnectionRepairEvent, ConnectionRepairEventKind, ConnectionRepairEventSink};
use crate::{
    AuthSession, ConnectorAuth, ConnectorError, ConnectorScope, CredentialLease, FreshnessWindow,
    MAX_AUTH_SESSION_TTL_SECONDS, MAX_PROBE_TTL_SECONDS, ProbeObservation, ProbeStatus,
    ProviderAdapterIdentity, ProviderAdapterOperation, ProviderAdapterRegistry,
    ProviderCapabilityKey, ProviderEvidenceClass, ProviderProvenanceClass, SecretReference,
};

const CONNECTION_PROBE_CAPABILITY: &str = "connection.probe";
const REPAIR_ID_BYTES: usize = 32;

/// Repair sessions are intentionally shorter than the existing connector
/// authentication chain. A repair is an inline recovery action, not a new
/// long-lived connection authority.
pub const MAX_REPAIR_SESSION_TTL_SECONDS: i64 = 120;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionRepairScope {
    tenant_id: String,
    project_id: String,
    mission_id: String,
    mission_revision: u64,
}

impl MissionRepairScope {
    pub fn new(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        mission_revision: u64,
    ) -> Result<Self, ConnectionRepairError> {
        let scope = Self {
            tenant_id: tenant_id.into(),
            project_id: project_id.into(),
            mission_id: mission_id.into(),
            mission_revision,
        };
        if !valid_identifier(&scope.tenant_id)
            || !valid_identifier(&scope.project_id)
            || !valid_identifier(&scope.mission_id)
            || scope.mission_revision == 0
        {
            return Err(ConnectionRepairError::InvalidRequest);
        }
        Ok(scope)
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    pub fn mission_id(&self) -> &str {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub fn digest(&self) -> String {
        crate::canonical_digest([
            self.tenant_id.as_str(),
            self.project_id.as_str(),
            self.mission_id.as_str(),
            &self.mission_revision.to_string(),
        ])
    }
}

/// The complete Mission + connector scope used by every repair boundary.
/// `ConnectorScope` remains the existing provider-neutral connector contract;
/// this wrapper only binds it to one Mission and never becomes a connector
/// enum or a second Connected authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionRepairScope {
    mission: MissionRepairScope,
    connector: ConnectorScope,
}

impl ConnectionRepairScope {
    pub fn new(
        mission: MissionRepairScope,
        connector: ConnectorScope,
    ) -> Result<Self, ConnectionRepairError> {
        if mission.tenant_id() != connector.tenant_id()
            || mission.project_id() != connector.project_id()
        {
            return Err(ConnectionRepairError::ScopeMismatch);
        }
        Ok(Self { mission, connector })
    }

    pub const fn mission(&self) -> &MissionRepairScope {
        &self.mission
    }

    pub const fn connector(&self) -> &ConnectorScope {
        &self.connector
    }

    pub fn digest(&self) -> String {
        crate::canonical_digest([
            self.mission.digest().as_str(),
            self.connector.digest().as_str(),
        ])
    }
}

/// Provider plugin identity is explicit and digest-bound. The connector ID
/// is still read from the exact `ConnectorScope`; no central connector list
/// is introduced here.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionRepairPlugin {
    plugin_id: String,
    version: u32,
    digest: String,
}

impl ConnectionRepairPlugin {
    pub fn new(
        plugin_id: impl Into<String>,
        version: u32,
        digest: impl Into<String>,
    ) -> Result<Self, ConnectionRepairError> {
        let plugin = Self {
            plugin_id: plugin_id.into(),
            version,
            digest: digest.into(),
        };
        if !valid_identifier(&plugin.plugin_id) || plugin.version == 0 || !is_sha256(&plugin.digest)
        {
            return Err(ConnectionRepairError::InvalidRequest);
        }
        Ok(plugin)
    }

    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    pub const fn version(&self) -> u32 {
        self.version
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    fn matches(&self, adapter: &ProviderAdapterIdentity) -> bool {
        self.plugin_id == adapter.adapter_id() && self.version == adapter.adapter_version()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionRepairReason {
    Disconnected,
    Expired,
    ReauthRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionRepairProviderStatus {
    Reachable,
    Disconnected,
    Expired,
    ReauthRequired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionRepairResultStatus {
    Verified,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionRepairSessionState {
    Mounted,
    Repairing,
    Ready,
    Completed,
    Revoked,
    Expired,
    Crashed,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ConnectionRepairProviderFailure {
    #[error("provider repair mount was rejected")]
    MountRejected,
    #[error("provider reauthorization was rejected")]
    ReauthRejected,
    #[error("provider repair probe was rejected")]
    ProbeRejected,
    #[error("provider repair scope was revoked")]
    Revoked,
    #[error("provider repair endpoint was unavailable")]
    Unavailable,
    #[error("provider repair boundary failed")]
    Boundary,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConnectionRepairError {
    #[error("connection repair request is invalid")]
    InvalidRequest,
    #[error("connection repair scope does not match")]
    ScopeMismatch,
    #[error("connection repair plugin identity does not match the provider")]
    PluginMismatch,
    #[error("provider adapter registry is invalid")]
    InvalidRegistry,
    #[error("provider repair capability is not registered for the required lifecycle")]
    RepairCapabilityNotRegistered,
    #[error("provider repair boundary is unsupported")]
    UnsupportedProviderBoundary,
    #[error("opaque SecretReference does not match the repair scope")]
    SecretScopeMismatch,
    #[error("connector authentication chain is invalid")]
    InvalidAuthChain,
    #[error("provider repair observation is invalid")]
    InvalidObservation,
    #[error("provider repair returned status {0:?}")]
    ProviderStatus(ConnectionRepairProviderStatus),
    #[error("provider repair quota is exhausted")]
    QuotaExhausted,
    #[error("provider repair freshness is insufficient")]
    FreshnessInsufficient,
    #[error("provider repair session was not found")]
    SessionNotFound,
    #[error("provider repair session is not active")]
    SessionNotActive,
    #[error("provider repair session has expired")]
    SessionExpired,
    #[error("provider repair session cannot be reused")]
    SessionNotReusable,
    #[error("provider repair is already in progress")]
    RepairInProgress,
    #[error("provider repair result was not accepted by the Mission")]
    ResultNotAccepted,
    #[error("provider repair result is expired")]
    ResultExpired,
    #[error("Mission repair scope does not match")]
    MissionMismatch,
    #[error("Mission invocation digest does not match")]
    InvocationMismatch,
    #[error("provider repair result was already consumed")]
    AlreadyConsumed,
    #[error("connection repair timestamp moved backwards")]
    TimestampRegression,
    #[error("connection repair revision overflowed")]
    RevisionOverflow,
    #[error("connection repair event is invalid")]
    InvalidEvent,
    #[error("connection repair event sequence conflicts")]
    EventSequenceConflict,
    #[error("connection repair event persistence failed")]
    EventPersistence,
    #[error("provider revoke failed during repair cleanup")]
    ProviderRevokeFailed,
    #[error("secure repair handle generation failed")]
    EntropyUnavailable,
    #[error("provider repair failed: {0}")]
    Provider(ConnectionRepairProviderFailure),
}

/// A provider observation has no Mission authority and no credential bytes.
/// The service binds it to the request before producing a result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionRepairObservation {
    scope: ConnectorScope,
    account_id: String,
    capabilities: BTreeSet<ProviderCapabilityKey>,
    quota: RepairQuota,
    freshness: FreshnessWindow,
    provider: ProviderAdapterIdentity,
    plugin_digest: String,
    status: ConnectionRepairProviderStatus,
    evidence_digest: String,
    observed_at: DateTime<Utc>,
}

impl ConnectionRepairObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ConnectorScope,
        account_id: impl Into<String>,
        capabilities: impl IntoIterator<Item = ProviderCapabilityKey>,
        quota: RepairQuota,
        freshness: FreshnessWindow,
        provider: ProviderAdapterIdentity,
        plugin_digest: impl Into<String>,
        status: ConnectionRepairProviderStatus,
        evidence_digest: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ConnectionRepairError> {
        let observation = Self {
            scope,
            account_id: account_id.into(),
            capabilities: capabilities.into_iter().collect(),
            quota,
            freshness,
            provider,
            plugin_digest: plugin_digest.into(),
            status,
            evidence_digest: evidence_digest.into(),
            observed_at,
        };
        observation.validate_shape()?;
        Ok(observation)
    }

    pub const fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub const fn capabilities(&self) -> &BTreeSet<ProviderCapabilityKey> {
        &self.capabilities
    }

    pub const fn quota(&self) -> &RepairQuota {
        &self.quota
    }

    pub const fn freshness(&self) -> &FreshnessWindow {
        &self.freshness
    }

    pub const fn provider(&self) -> &ProviderAdapterIdentity {
        &self.provider
    }

    pub fn plugin_digest(&self) -> &str {
        &self.plugin_digest
    }

    pub const fn status(&self) -> ConnectionRepairProviderStatus {
        self.status
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    fn validate_shape(&self) -> Result<(), ConnectionRepairError> {
        if self.account_id.trim().is_empty()
            || self.capabilities.is_empty()
            || self
                .capabilities
                .iter()
                .any(|capability| capability.provider_id() != self.scope.provider_id())
            || self.freshness.observed_at() != self.observed_at
            || self.freshness.valid_until() <= self.observed_at
            || self.freshness.valid_until() - self.freshness.observed_at()
                > Duration::seconds(MAX_PROBE_TTL_SECONDS)
            || !is_sha256(&self.plugin_digest)
            || !is_sha256(&self.evidence_digest)
        {
            return Err(ConnectionRepairError::InvalidObservation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepairQuota {
    limit: u64,
    used: u64,
}

impl RepairQuota {
    pub fn new(limit: u64, used: u64) -> Result<Self, ConnectionRepairError> {
        if limit == 0 || used > limit {
            return Err(ConnectionRepairError::InvalidObservation);
        }
        Ok(Self { limit, used })
    }

    pub const fn limit(&self) -> u64 {
        self.limit
    }

    pub const fn used(&self) -> u64 {
        self.used
    }

    pub const fn available(&self) -> bool {
        self.used < self.limit
    }
}

/// A repair request is created by the inline Mission node after a typed
/// connector failure. It carries only digests and an opaque SecretReference.
#[derive(Clone, Eq, PartialEq)]
pub struct ConnectionRepairRequest {
    scope: ConnectionRepairScope,
    connection_id: String,
    plugin: ConnectionRepairPlugin,
    secret_reference: SecretReference,
    invocation_digest: String,
    objective_digest: String,
    required_capability: ProviderCapabilityKey,
    reason: ConnectionRepairReason,
    failed_result_digest: String,
    failed_result_revision: u64,
    session_revision: u64,
    previous_auth_revision: u64,
    session_ttl: Duration,
    quota_limit: u64,
    request_digest: String,
}

impl fmt::Debug for ConnectionRepairRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionRepairRequest")
            .field("scope", &self.scope)
            .field("connection_id", &self.connection_id)
            .field("plugin", &self.plugin)
            .field("secret_reference", &"[OPAQUE_REFERENCE]")
            .field("invocation_digest", &self.invocation_digest)
            .field("objective_digest", &self.objective_digest)
            .field("required_capability", &self.required_capability)
            .field("reason", &self.reason)
            .field("failed_result_digest", &self.failed_result_digest)
            .field("failed_result_revision", &self.failed_result_revision)
            .field("session_revision", &self.session_revision)
            .field("previous_auth_revision", &self.previous_auth_revision)
            .field("session_ttl", &self.session_ttl)
            .field("quota_limit", &self.quota_limit)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl ConnectionRepairRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ConnectionRepairScope,
        connection_id: impl Into<String>,
        plugin: ConnectionRepairPlugin,
        secret_reference: SecretReference,
        invocation_digest: impl Into<String>,
        objective_digest: impl Into<String>,
        required_capability: ProviderCapabilityKey,
        reason: ConnectionRepairReason,
        failed_result_digest: impl Into<String>,
        failed_result_revision: u64,
        session_revision: u64,
        previous_auth_revision: u64,
        session_ttl: Duration,
        quota_limit: u64,
    ) -> Result<Self, ConnectionRepairError> {
        let connection_id = connection_id.into();
        let invocation_digest = invocation_digest.into();
        let objective_digest = objective_digest.into();
        let failed_result_digest = failed_result_digest.into();
        if !valid_identifier(&connection_id)
            || !is_sha256(&invocation_digest)
            || !is_sha256(&objective_digest)
            || !is_sha256(&failed_result_digest)
            || failed_result_revision == 0
            || session_revision == 0
            || required_capability.provider_id() != scope.connector().provider_id()
            || !scope
                .connector()
                .scopes()
                .contains(required_capability.capability_id())
            || secret_reference.scope() != scope.connector()
            || session_ttl <= Duration::zero()
            || session_ttl > Duration::seconds(MAX_REPAIR_SESSION_TTL_SECONDS)
            || quota_limit == 0
        {
            return Err(ConnectionRepairError::InvalidRequest);
        }
        let request_digest = crate::canonical_digest([
            scope.digest().as_str(),
            connection_id.as_str(),
            plugin.plugin_id(),
            &plugin.version().to_string(),
            plugin.digest(),
            secret_reference.reference_id(),
            &secret_reference.credential_revision().to_string(),
            invocation_digest.as_str(),
            objective_digest.as_str(),
            required_capability.provider_id(),
            required_capability.capability_id(),
            &format!("{reason:?}"),
            failed_result_digest.as_str(),
            &failed_result_revision.to_string(),
            &session_revision.to_string(),
            &previous_auth_revision.to_string(),
            &session_ttl.num_seconds().to_string(),
            &quota_limit.to_string(),
        ]);
        Ok(Self {
            scope,
            connection_id,
            plugin,
            secret_reference,
            invocation_digest,
            objective_digest,
            required_capability,
            reason,
            failed_result_digest,
            failed_result_revision,
            session_revision,
            previous_auth_revision,
            session_ttl,
            quota_limit,
            request_digest,
        })
    }

    pub const fn scope(&self) -> &ConnectionRepairScope {
        &self.scope
    }

    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    pub const fn plugin(&self) -> &ConnectionRepairPlugin {
        &self.plugin
    }

    pub fn invocation_digest(&self) -> &str {
        &self.invocation_digest
    }

    pub fn objective_digest(&self) -> &str {
        &self.objective_digest
    }

    pub const fn required_capability(&self) -> &ProviderCapabilityKey {
        &self.required_capability
    }

    pub const fn reason(&self) -> ConnectionRepairReason {
        self.reason
    }

    pub fn failed_result_digest(&self) -> &str {
        &self.failed_result_digest
    }

    pub const fn failed_result_revision(&self) -> u64 {
        self.failed_result_revision
    }

    pub const fn session_revision(&self) -> u64 {
        self.session_revision
    }

    pub const fn previous_auth_revision(&self) -> u64 {
        self.previous_auth_revision
    }

    pub const fn session_ttl(&self) -> Duration {
        self.session_ttl
    }

    pub const fn quota_limit(&self) -> u64 {
        self.quota_limit
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }
}

/// Public repair session handle. Its raw ID is never serialized or printed;
/// provider calls receive only its digest.
#[derive(Clone, Eq, PartialEq)]
pub struct ConnectionRepairSession {
    session_id: String,
    request_digest: String,
    scope: ConnectionRepairScope,
    connection_id: String,
    plugin: ConnectionRepairPlugin,
    invocation_digest: String,
    reason: ConnectionRepairReason,
    session_revision: u64,
    generation: u64,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    state: ConnectionRepairSessionState,
}

impl fmt::Debug for ConnectionRepairSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionRepairSession")
            .field("session_digest", &self.session_digest())
            .field("request_digest", &self.request_digest)
            .field("scope", &self.scope)
            .field("connection_id", &self.connection_id)
            .field("plugin", &self.plugin)
            .field("invocation_digest", &self.invocation_digest)
            .field("reason", &self.reason)
            .field("session_revision", &self.session_revision)
            .field("generation", &self.generation)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl ConnectionRepairSession {
    pub fn session_digest(&self) -> String {
        crate::canonical_digest([self.session_id.as_str()])
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub const fn scope(&self) -> &ConnectionRepairScope {
        &self.scope
    }

    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    pub const fn plugin(&self) -> &ConnectionRepairPlugin {
        &self.plugin
    }

    pub fn invocation_digest(&self) -> &str {
        &self.invocation_digest
    }

    pub const fn reason(&self) -> ConnectionRepairReason {
        self.reason
    }

    pub const fn session_revision(&self) -> u64 {
        self.session_revision
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub const fn state(&self) -> ConnectionRepairSessionState {
        self.state
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionRepairResult {
    request_digest: String,
    scope: ConnectionRepairScope,
    connection_id: String,
    plugin: ConnectionRepairPlugin,
    invocation_digest: String,
    objective_digest: String,
    required_capability: ProviderCapabilityKey,
    reason: ConnectionRepairReason,
    failed_result_digest: String,
    failed_result_revision: u64,
    session_digest: String,
    session_revision: u64,
    generation: u64,
    credential_revision: u64,
    lease_revision: u64,
    auth_revision: u64,
    probe_revision: u64,
    status: ConnectionRepairResultStatus,
    quota: RepairQuota,
    freshness: FreshnessWindow,
    provider_result_digest: String,
    evidence_digest: String,
    observed_at: DateTime<Utc>,
    result_digest: String,
}

impl ConnectionRepairResult {
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub const fn scope(&self) -> &ConnectionRepairScope {
        &self.scope
    }

    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    pub const fn plugin(&self) -> &ConnectionRepairPlugin {
        &self.plugin
    }

    pub fn invocation_digest(&self) -> &str {
        &self.invocation_digest
    }

    pub fn objective_digest(&self) -> &str {
        &self.objective_digest
    }

    pub const fn required_capability(&self) -> &ProviderCapabilityKey {
        &self.required_capability
    }

    pub const fn reason(&self) -> ConnectionRepairReason {
        self.reason
    }

    pub fn failed_result_digest(&self) -> &str {
        &self.failed_result_digest
    }

    pub const fn failed_result_revision(&self) -> u64 {
        self.failed_result_revision
    }

    pub fn session_digest(&self) -> &str {
        &self.session_digest
    }

    pub const fn session_revision(&self) -> u64 {
        self.session_revision
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub const fn lease_revision(&self) -> u64 {
        self.lease_revision
    }

    pub const fn auth_revision(&self) -> u64 {
        self.auth_revision
    }

    pub const fn probe_revision(&self) -> u64 {
        self.probe_revision
    }

    pub const fn status(&self) -> ConnectionRepairResultStatus {
        self.status
    }

    pub const fn quota(&self) -> &RepairQuota {
        &self.quota
    }

    pub const fn freshness(&self) -> &FreshnessWindow {
        &self.freshness
    }

    pub fn provider_result_digest(&self) -> &str {
        &self.provider_result_digest
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn result_digest(&self) -> &str {
        &self.result_digest
    }

    pub fn is_live_at(&self, at: DateTime<Utc>) -> bool {
        at >= self.observed_at
            && at < self.freshness.valid_until()
            && self.quota.available()
            && self.status == ConnectionRepairResultStatus::Verified
    }

    fn from_observation(
        request: &ConnectionRepairRequest,
        session: &ConnectionRepairSession,
        lease: &CredentialLease,
        auth_session: &AuthSession,
        probe_revision: u64,
        provider_result_digest: String,
        observation: &ConnectionRepairObservation,
    ) -> Result<Self, ConnectionRepairError> {
        let provider_result_digest_material = observation.provider_result_digest_material();
        let result_digest = crate::canonical_digest([
            request.request_digest(),
            session.session_digest().as_str(),
            &session.generation().to_string(),
            &lease.credential_revision().to_string(),
            &lease.lease_revision().to_string(),
            &auth_session.auth_revision().to_string(),
            &probe_revision.to_string(),
            provider_result_digest_material.as_str(),
            observation.evidence_digest(),
        ]);
        let result = Self {
            request_digest: request.request_digest().to_owned(),
            scope: request.scope().clone(),
            connection_id: request.connection_id().to_owned(),
            plugin: request.plugin().clone(),
            invocation_digest: request.invocation_digest().to_owned(),
            objective_digest: request.objective_digest().to_owned(),
            required_capability: request.required_capability().clone(),
            reason: request.reason(),
            failed_result_digest: request.failed_result_digest().to_owned(),
            failed_result_revision: request.failed_result_revision(),
            session_digest: session.session_digest(),
            session_revision: request.session_revision(),
            generation: session.generation(),
            credential_revision: lease.credential_revision(),
            lease_revision: lease.lease_revision(),
            auth_revision: auth_session.auth_revision(),
            probe_revision,
            status: ConnectionRepairResultStatus::Verified,
            quota: observation.quota.clone(),
            freshness: observation.freshness.clone(),
            provider_result_digest,
            evidence_digest: observation.evidence_digest.clone(),
            observed_at: observation.observed_at,
            result_digest,
        };
        result.validate_for_request(request, observation.observed_at)?;
        Ok(result)
    }

    fn validate_for_request(
        &self,
        request: &ConnectionRepairRequest,
        at: DateTime<Utc>,
    ) -> Result<(), ConnectionRepairError> {
        if self.request_digest != request.request_digest()
            || self.scope != *request.scope()
            || self.connection_id != request.connection_id()
            || self.plugin != *request.plugin()
            || self.invocation_digest != request.invocation_digest()
            || self.objective_digest != request.objective_digest()
            || self.required_capability != *request.required_capability()
            || self.reason != request.reason()
            || self.failed_result_digest != request.failed_result_digest()
            || self.failed_result_revision != request.failed_result_revision()
            || self.session_revision != request.session_revision()
            || self.generation == 0
            || self.credential_revision != request.secret_reference.credential_revision()
            || self.lease_revision != request.session_revision()
            || self.status != ConnectionRepairResultStatus::Verified
            || !is_sha256(&self.request_digest)
            || !is_sha256(&self.session_digest)
            || !is_sha256(&self.provider_result_digest)
            || !is_sha256(&self.evidence_digest)
            || !self.quota.available()
            || self.freshness.observed_at() != self.observed_at
            || self.freshness.valid_until() > self.observed_at + request.session_ttl()
            || at < self.observed_at
            || at >= self.freshness.valid_until()
        {
            return Err(if at >= self.freshness.valid_until() {
                ConnectionRepairError::ResultExpired
            } else {
                ConnectionRepairError::ResultNotAccepted
            });
        }
        Ok(())
    }
}

impl ConnectionRepairObservation {
    fn provider_result_digest_material(&self) -> String {
        crate::canonical_digest([
            self.scope.digest().as_str(),
            self.account_id.as_str(),
            &self.quota.limit().to_string(),
            &self.quota.used().to_string(),
            &self.freshness.valid_until().to_rfc3339(),
            self.plugin_digest.as_str(),
            self.evidence_digest.as_str(),
        ])
    }
}

/// Provider calls receive only metadata and opaque references. They do not
/// receive a Mission handle or any raw token/secret material.
#[derive(Debug)]
pub struct RepairMountRequest<'a> {
    pub scope: &'a ConnectorScope,
    pub secret_reference: &'a SecretReference,
    pub credential_lease: &'a CredentialLease,
    pub session_digest: &'a str,
    pub request_digest: &'a str,
    pub at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct RepairAuthRequest<'a> {
    pub scope: &'a ConnectorScope,
    pub secret_reference: &'a SecretReference,
    pub credential_lease: &'a CredentialLease,
    pub previous_session: Option<&'a AuthSession>,
    pub session_digest: &'a str,
    pub reason: ConnectionRepairReason,
    pub auth_revision: u64,
    pub at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct RepairProbeRequest<'a> {
    pub scope: &'a ConnectorScope,
    pub secret_reference: &'a SecretReference,
    pub credential_lease: &'a CredentialLease,
    pub auth_session: &'a AuthSession,
    pub session_digest: &'a str,
    pub requested_capability: &'a ProviderCapabilityKey,
    pub probe_revision: u64,
    pub at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct RepairLifecycleRequest<'a> {
    pub scope: &'a ConnectorScope,
    pub secret_reference: &'a SecretReference,
    pub credential_lease: &'a CredentialLease,
    pub auth_session: Option<&'a AuthSession>,
    pub session_digest: String,
    pub at: DateTime<Utc>,
}

/// Narrow provider boundary for the inline repair plugin.
pub trait ConnectionRepairProvider {
    fn identity(&self) -> &ProviderAdapterIdentity;

    fn mount(&mut self, request: RepairMountRequest<'_>) -> Result<(), ConnectionRepairError>;

    fn reauthorize(
        &mut self,
        request: RepairAuthRequest<'_>,
    ) -> Result<AuthSession, ConnectionRepairError>;

    fn probe(
        &mut self,
        request: RepairProbeRequest<'_>,
    ) -> Result<ConnectionRepairObservation, ConnectionRepairError>;

    fn unmount(&mut self, request: RepairLifecycleRequest<'_>);

    fn revoke(&mut self, request: RepairLifecycleRequest<'_>) -> Result<(), ConnectionRepairError>;
}

struct MountedRepair {
    request: ConnectionRepairRequest,
    session: ConnectionRepairSession,
    secret_reference: SecretReference,
    credential_lease: CredentialLease,
    auth_session: Option<AuthSession>,
    result: Option<ConnectionRepairResult>,
}

/// Provider-neutral service that owns only ephemeral repair mounts and typed
/// lifecycle events. It has no Store/keyring authority.
pub struct ConnectionRepairService<
    P: ConnectionRepairProvider,
    E = super::events::ConnectionRepairEventLog,
> {
    provider: P,
    registry: ProviderAdapterRegistry,
    events: E,
    sessions: BTreeMap<String, ConnectionRepairSession>,
    request_index: BTreeMap<String, String>,
    mounts: BTreeMap<String, MountedRepair>,
    next_event_sequence: u64,
}

impl<P, E> fmt::Debug for ConnectionRepairService<P, E>
where
    P: ConnectionRepairProvider,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionRepairService")
            .field("provider", &self.provider.identity())
            .field("registry_version", &self.registry.registry_version())
            .field("session_count", &self.sessions.len())
            .field("active_mount_count", &self.mounts.len())
            .finish_non_exhaustive()
    }
}

impl<P, E> ConnectionRepairService<P, E>
where
    P: ConnectionRepairProvider,
    E: ConnectionRepairEventSink,
{
    pub fn new(
        provider: P,
        registry: ProviderAdapterRegistry,
        events: E,
    ) -> Result<Self, ConnectionRepairError> {
        registry
            .validate()
            .map_err(|_| ConnectionRepairError::InvalidRegistry)?;
        Ok(Self {
            provider,
            registry,
            events,
            sessions: BTreeMap::new(),
            request_index: BTreeMap::new(),
            mounts: BTreeMap::new(),
            next_event_sequence: 1,
        })
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn events(&self) -> &E {
        &self.events
    }

    pub fn active_session_count(&self) -> usize {
        self.mounts.len()
    }

    pub fn open(
        &mut self,
        request: ConnectionRepairRequest,
        at: DateTime<Utc>,
    ) -> Result<ConnectionRepairSession, ConnectionRepairError> {
        if !request.plugin().matches(self.provider.identity()) {
            return Err(ConnectionRepairError::PluginMismatch);
        }
        self.validate_provider_registration(request.scope().connector())?;
        if let Some(existing_id) = self.request_index.get(request.request_digest()) {
            let existing = self
                .sessions
                .get(existing_id)
                .ok_or(ConnectionRepairError::SessionNotFound)?;
            if matches!(
                existing.state(),
                ConnectionRepairSessionState::Mounted
                    | ConnectionRepairSessionState::Repairing
                    | ConnectionRepairSessionState::Ready
            ) {
                return Ok(existing.clone());
            }
            return Err(ConnectionRepairError::SessionNotReusable);
        }
        let expires_at = at
            .checked_add_signed(request.session_ttl())
            .ok_or(ConnectionRepairError::InvalidRequest)?;
        let session_id = new_opaque_id(&self.sessions)?;
        let session = ConnectionRepairSession {
            session_id: session_id.clone(),
            request_digest: request.request_digest().to_owned(),
            scope: request.scope().clone(),
            connection_id: request.connection_id().to_owned(),
            plugin: request.plugin().clone(),
            invocation_digest: request.invocation_digest().to_owned(),
            reason: request.reason(),
            session_revision: request.session_revision(),
            generation: 1,
            issued_at: at,
            expires_at,
            state: ConnectionRepairSessionState::Mounted,
        };
        let lease_id = format!("credential-lease-connection-repair-{session_id}");
        let credential_lease = ConnectorAuth::issue_credential_lease(
            &request.secret_reference,
            self.provider.identity().clone(),
            lease_id,
            request.session_revision(),
            at,
            expires_at,
        )
        .map_err(|error| map_connector_error(&error))?;
        let mount_request = RepairMountRequest {
            scope: request.scope().connector(),
            secret_reference: &request.secret_reference,
            credential_lease: &credential_lease,
            session_digest: &session.session_digest(),
            request_digest: request.request_digest(),
            at,
            expires_at,
        };
        if let Err(error) = self.provider.mount(mount_request) {
            self.provider.unmount(RepairLifecycleRequest {
                scope: request.scope().connector(),
                secret_reference: &request.secret_reference,
                credential_lease: &credential_lease,
                auth_session: None,
                session_digest: session.session_digest(),
                at,
            });
            return Err(error);
        }
        if let Err(error) = self.append_event(
            &session,
            ConnectionRepairEventKind::SessionOpened,
            None,
            None,
            at,
        ) {
            self.provider.unmount(RepairLifecycleRequest {
                scope: request.scope().connector(),
                secret_reference: &request.secret_reference,
                credential_lease: &credential_lease,
                auth_session: None,
                session_digest: session.session_digest(),
                at,
            });
            return Err(error);
        }
        let secret_reference = request.secret_reference.clone();
        self.request_index
            .insert(request.request_digest().to_owned(), session_id.clone());
        self.sessions.insert(session_id.clone(), session.clone());
        self.mounts.insert(
            session_id,
            MountedRepair {
                request,
                session: session.clone(),
                secret_reference,
                credential_lease,
                auth_session: None,
                result: None,
            },
        );
        Ok(session)
    }

    #[allow(clippy::too_many_lines)]
    pub fn repair(
        &mut self,
        session: &ConnectionRepairSession,
        at: DateTime<Utc>,
    ) -> Result<ConnectionRepairResult, ConnectionRepairError> {
        let session_id = session.session_id.clone();
        let mut mounted = self
            .mounts
            .remove(&session_id)
            .ok_or(ConnectionRepairError::SessionNotFound)?;
        if !same_session(&mounted.session, session) {
            self.mounts.insert(session_id, mounted);
            return Err(ConnectionRepairError::SessionNotActive);
        }
        if let Some(result) = &mounted.result {
            let result = result.clone();
            self.mounts.insert(session_id, mounted);
            return Ok(result);
        }
        if mounted.session.state != ConnectionRepairSessionState::Mounted {
            let state = mounted.session.state;
            self.mounts.insert(session_id, mounted);
            return Err(if state == ConnectionRepairSessionState::Repairing {
                ConnectionRepairError::RepairInProgress
            } else {
                ConnectionRepairError::SessionNotActive
            });
        }
        if at < mounted.session.issued_at {
            self.mounts.insert(session_id, mounted);
            return Err(ConnectionRepairError::TimestampRegression);
        }
        if at >= mounted.session.expires_at {
            let error = ConnectionRepairError::SessionExpired;
            self.retire_mount(
                &mut mounted,
                ConnectionRepairSessionState::Expired,
                ConnectionRepairEventKind::SessionExpired,
                at,
                None,
                None,
            )?;
            return Err(error);
        }
        mounted.session.state = ConnectionRepairSessionState::Repairing;
        self.sessions
            .insert(session_id.clone(), mounted.session.clone());
        let Some(auth_revision) = mounted.request.previous_auth_revision().checked_add(1) else {
            let error = ConnectionRepairError::RevisionOverflow;
            self.retire_mount(
                &mut mounted,
                ConnectionRepairSessionState::Revoked,
                ConnectionRepairEventKind::ProbeFailed,
                at,
                None,
                None,
            )?;
            return Err(error);
        };
        let session_digest = mounted.session.session_digest();
        let auth_session = match self.provider.reauthorize(RepairAuthRequest {
            scope: mounted.request.scope().connector(),
            secret_reference: &mounted.secret_reference,
            credential_lease: &mounted.credential_lease,
            previous_session: mounted.auth_session.as_ref(),
            session_digest: &session_digest,
            reason: mounted.request.reason(),
            auth_revision,
            at,
            expires_at: mounted.session.expires_at,
        }) {
            Ok(auth_session) => auth_session,
            Err(error) => {
                self.retire_mount(
                    &mut mounted,
                    ConnectionRepairSessionState::Revoked,
                    ConnectionRepairEventKind::ProbeFailed,
                    at,
                    None,
                    None,
                )?;
                return Err(error);
            }
        };
        if let Err(error) = validate_auth_session(
            &mounted.request,
            &mounted.secret_reference,
            &mounted.credential_lease,
            &auth_session,
            auth_revision,
            at,
            mounted.session.expires_at,
        ) {
            self.retire_mount(
                &mut mounted,
                ConnectionRepairSessionState::Revoked,
                ConnectionRepairEventKind::ProbeFailed,
                at,
                Some(auth_revision),
                None,
            )?;
            return Err(error);
        }
        mounted.auth_session = Some(auth_session.clone());
        let Some(probe_revision) = mounted.request.failed_result_revision().checked_add(1) else {
            let error = ConnectionRepairError::RevisionOverflow;
            self.retire_mount(
                &mut mounted,
                ConnectionRepairSessionState::Revoked,
                ConnectionRepairEventKind::ProbeFailed,
                at,
                Some(auth_revision),
                None,
            )?;
            return Err(error);
        };
        let observation = match self.provider.probe(RepairProbeRequest {
            scope: mounted.request.scope().connector(),
            secret_reference: &mounted.secret_reference,
            credential_lease: &mounted.credential_lease,
            auth_session: &auth_session,
            session_digest: &session_digest,
            requested_capability: mounted.request.required_capability(),
            probe_revision,
            at,
            expires_at: mounted.session.expires_at,
        }) {
            Ok(observation) => observation,
            Err(error) => {
                self.retire_mount(
                    &mut mounted,
                    ConnectionRepairSessionState::Revoked,
                    ConnectionRepairEventKind::ProbeFailed,
                    at,
                    Some(auth_revision),
                    None,
                )?;
                return Err(error);
            }
        };
        if let Err(error) = validate_observation(
            &mounted.request,
            &mounted.session,
            &auth_session,
            &observation,
            at,
        ) {
            self.retire_mount(
                &mut mounted,
                ConnectionRepairSessionState::Revoked,
                ConnectionRepairEventKind::ProbeFailed,
                at,
                Some(auth_revision),
                Some(probe_revision),
            )?;
            return Err(error);
        }
        let probe_observation = match ProbeObservation::new(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
            observation.observed_at(),
            observation.freshness().valid_until(),
            observation.evidence_digest(),
        )
        .map_err(|error| map_connector_error(&error))
        {
            Ok(probe_observation) => probe_observation,
            Err(error) => {
                self.retire_mount(
                    &mut mounted,
                    ConnectionRepairSessionState::Revoked,
                    ConnectionRepairEventKind::ProbeFailed,
                    at,
                    Some(auth_revision),
                    Some(probe_revision),
                )?;
                return Err(error);
            }
        };
        let probe_result = match ConnectorAuth::record_probe(
            &mounted.secret_reference,
            &mounted.credential_lease,
            &auth_session,
            format!("probe-result-{session_digest}-{probe_revision}"),
            probe_revision,
            probe_observation,
        )
        .map_err(|error| map_connector_error(&error))
        {
            Ok(probe_result) => probe_result,
            Err(error) => {
                self.retire_mount(
                    &mut mounted,
                    ConnectionRepairSessionState::Revoked,
                    ConnectionRepairEventKind::ProbeFailed,
                    at,
                    Some(auth_revision),
                    Some(probe_revision),
                )?;
                return Err(error);
            }
        };
        let result = match ConnectionRepairResult::from_observation(
            &mounted.request,
            &mounted.session,
            &mounted.credential_lease,
            &auth_session,
            probe_revision,
            crate::canonical_digest([probe_result.result_id(), probe_result.binding_digest()]),
            &observation,
        ) {
            Ok(result) => result,
            Err(error) => {
                self.retire_mount(
                    &mut mounted,
                    ConnectionRepairSessionState::Revoked,
                    ConnectionRepairEventKind::ProbeFailed,
                    at,
                    Some(auth_revision),
                    Some(probe_revision),
                )?;
                return Err(error);
            }
        };
        if let Err(error) = self.append_event(
            &mounted.session,
            ConnectionRepairEventKind::ProbeSucceeded,
            Some(auth_revision),
            Some(probe_revision),
            observation.observed_at(),
        ) {
            self.retire_mount(
                &mut mounted,
                ConnectionRepairSessionState::Revoked,
                ConnectionRepairEventKind::ProbeFailed,
                at,
                Some(auth_revision),
                Some(probe_revision),
            )?;
            return Err(error);
        }
        mounted.session.state = ConnectionRepairSessionState::Ready;
        mounted.result = Some(result.clone());
        self.sessions
            .insert(session_id.clone(), mounted.session.clone());
        self.mounts.insert(session_id, mounted);
        Ok(result)
    }

    pub fn complete(
        &mut self,
        session: &ConnectionRepairSession,
        at: DateTime<Utc>,
    ) -> Result<(), ConnectionRepairError> {
        let session_id = session.session_id.clone();
        let mut mounted = self
            .mounts
            .remove(&session_id)
            .ok_or(ConnectionRepairError::SessionNotFound)?;
        if !same_session(&mounted.session, session)
            || mounted.session.state != ConnectionRepairSessionState::Ready
        {
            self.mounts.insert(session_id, mounted);
            return Err(ConnectionRepairError::SessionNotActive);
        }
        if at < mounted.session.issued_at {
            self.mounts.insert(session_id, mounted);
            return Err(ConnectionRepairError::TimestampRegression);
        }
        if at >= mounted.session.expires_at {
            let auth_revision = mounted
                .result
                .as_ref()
                .map(ConnectionRepairResult::auth_revision);
            let probe_revision = mounted
                .result
                .as_ref()
                .map(ConnectionRepairResult::probe_revision);
            self.retire_mount(
                &mut mounted,
                ConnectionRepairSessionState::Expired,
                ConnectionRepairEventKind::SessionExpired,
                at,
                auth_revision,
                probe_revision,
            )?;
            return Err(ConnectionRepairError::SessionExpired);
        }
        self.provider.unmount(lifecycle_request(&mounted, at));
        mounted.session.state = ConnectionRepairSessionState::Completed;
        self.sessions.insert(session_id, mounted.session.clone());
        self.append_event(
            &mounted.session,
            ConnectionRepairEventKind::SessionCompleted,
            mounted
                .result
                .as_ref()
                .map(ConnectionRepairResult::auth_revision),
            mounted
                .result
                .as_ref()
                .map(ConnectionRepairResult::probe_revision),
            at,
        )
    }

    pub fn revoke(
        &mut self,
        session: &ConnectionRepairSession,
        at: DateTime<Utc>,
    ) -> Result<(), ConnectionRepairError> {
        let session_id = session.session_id.clone();
        let mut mounted = self
            .mounts
            .remove(&session_id)
            .ok_or(ConnectionRepairError::SessionNotFound)?;
        if !same_session(&mounted.session, session) {
            self.mounts.insert(session_id, mounted);
            return Err(ConnectionRepairError::SessionNotActive);
        }
        if at < mounted.session.issued_at {
            self.mounts.insert(session_id, mounted);
            return Err(ConnectionRepairError::TimestampRegression);
        }
        let revoke_result = self.provider.revoke(lifecycle_request(&mounted, at));
        self.provider.unmount(lifecycle_request(&mounted, at));
        mounted.session.state = ConnectionRepairSessionState::Revoked;
        self.sessions.insert(session_id, mounted.session.clone());
        self.append_event(
            &mounted.session,
            ConnectionRepairEventKind::SessionRevoked,
            mounted
                .result
                .as_ref()
                .map(ConnectionRepairResult::auth_revision),
            mounted
                .result
                .as_ref()
                .map(ConnectionRepairResult::probe_revision),
            at,
        )?;
        revoke_result.map_err(|_| ConnectionRepairError::ProviderRevokeFailed)
    }

    pub fn expire(&mut self, at: DateTime<Utc>) -> Result<usize, ConnectionRepairError> {
        let expired = self
            .mounts
            .values()
            .filter(|mounted| at >= mounted.session.expires_at)
            .map(|mounted| mounted.session.session_id.clone())
            .collect::<Vec<_>>();
        for session_id in &expired {
            let mut mounted = self
                .mounts
                .remove(session_id)
                .ok_or(ConnectionRepairError::SessionNotFound)?;
            let auth_revision = mounted
                .result
                .as_ref()
                .map(ConnectionRepairResult::auth_revision);
            let probe_revision = mounted
                .result
                .as_ref()
                .map(ConnectionRepairResult::probe_revision);
            self.retire_mount(
                &mut mounted,
                ConnectionRepairSessionState::Expired,
                ConnectionRepairEventKind::SessionExpired,
                at,
                auth_revision,
                probe_revision,
            )?;
        }
        Ok(expired.len())
    }

    /// Explicit crash-gap cleanup for the owner that detects a dead inline
    /// node. `Drop` performs the same provider unmount defensively.
    pub fn crash_cleanup(&mut self, at: DateTime<Utc>) -> Result<usize, ConnectionRepairError> {
        let active = self.mounts.keys().cloned().collect::<Vec<_>>();
        for session_id in &active {
            let mut mounted = self
                .mounts
                .remove(session_id)
                .ok_or(ConnectionRepairError::SessionNotFound)?;
            let auth_revision = mounted
                .result
                .as_ref()
                .map(ConnectionRepairResult::auth_revision);
            let probe_revision = mounted
                .result
                .as_ref()
                .map(ConnectionRepairResult::probe_revision);
            self.retire_mount(
                &mut mounted,
                ConnectionRepairSessionState::Crashed,
                ConnectionRepairEventKind::SessionCrashed,
                at,
                auth_revision,
                probe_revision,
            )?;
        }
        Ok(active.len())
    }

    fn validate_provider_registration(
        &self,
        scope: &ConnectorScope,
    ) -> Result<(), ConnectionRepairError> {
        let key = ProviderCapabilityKey::new(scope.provider_id(), CONNECTION_PROBE_CAPABILITY)
            .map_err(|_| ConnectionRepairError::InvalidRequest)?;
        let registration = self
            .registry
            .registrations()
            .iter()
            .find(|registration| registration.key() == &key)
            .ok_or(ConnectionRepairError::RepairCapabilityNotRegistered)?;
        if registration.adapter() != self.provider.identity() {
            return Err(ConnectionRepairError::PluginMismatch);
        }
        let required = [
            (
                ProviderAdapterOperation::BeginAuth,
                ProviderEvidenceClass::Authentication,
            ),
            (
                ProviderAdapterOperation::Refresh,
                ProviderEvidenceClass::Authentication,
            ),
            (
                ProviderAdapterOperation::Probe,
                ProviderEvidenceClass::ProbeObservation,
            ),
            (
                ProviderAdapterOperation::Revoke,
                ProviderEvidenceClass::RevocationObservation,
            ),
        ];
        if required.iter().any(|(operation, evidence)| {
            !registration.evidence_support().iter().any(|support| {
                support.operation() == *operation
                    && support.evidence_class() == *evidence
                    && support.provenance_class() == ProviderProvenanceClass::ProductionProvider
            })
        }) {
            return Err(ConnectionRepairError::UnsupportedProviderBoundary);
        }
        Ok(())
    }

    fn append_event(
        &mut self,
        session: &ConnectionRepairSession,
        kind: ConnectionRepairEventKind,
        auth_revision: Option<u64>,
        probe_revision: Option<u64>,
        at: DateTime<Utc>,
    ) -> Result<(), ConnectionRepairError> {
        let status = (kind == ConnectionRepairEventKind::ProbeSucceeded)
            .then_some(ConnectionRepairResultStatus::Verified);
        let event = ConnectionRepairEvent::new(
            self.next_event_sequence,
            kind,
            session.scope.clone(),
            session.connection_id.clone(),
            session.plugin.clone(),
            session.request_digest.clone(),
            session.session_digest(),
            session.invocation_digest.clone(),
            session.reason,
            status,
            session.session_revision,
            auth_revision,
            probe_revision,
            at,
        )?;
        self.events.append(event)?;
        self.next_event_sequence = self
            .next_event_sequence
            .checked_add(1)
            .ok_or(ConnectionRepairError::RevisionOverflow)?;
        Ok(())
    }

    fn retire_mount(
        &mut self,
        mounted: &mut MountedRepair,
        state: ConnectionRepairSessionState,
        event_kind: ConnectionRepairEventKind,
        at: DateTime<Utc>,
        auth_revision: Option<u64>,
        probe_revision: Option<u64>,
    ) -> Result<(), ConnectionRepairError> {
        self.provider.unmount(lifecycle_request(mounted, at));
        mounted.session.state = state;
        self.sessions
            .insert(mounted.session.session_id.clone(), mounted.session.clone());
        self.append_event(
            &mounted.session,
            event_kind,
            auth_revision,
            probe_revision,
            at,
        )
    }
}

fn same_session(left: &ConnectionRepairSession, right: &ConnectionRepairSession) -> bool {
    left.session_id == right.session_id
        && left.request_digest == right.request_digest
        && left.scope == right.scope
        && left.plugin == right.plugin
        && left.invocation_digest == right.invocation_digest
        && left.reason == right.reason
        && left.session_revision == right.session_revision
        && left.generation == right.generation
}

impl<P, E> Drop for ConnectionRepairService<P, E>
where
    P: ConnectionRepairProvider,
{
    fn drop(&mut self) {
        let mounts = std::mem::take(&mut self.mounts);
        for mounted in mounts.into_values() {
            self.provider
                .unmount(lifecycle_request(&mounted, mounted.session.issued_at));
        }
    }
}

/// A Mission consumer accepts only the exact request that opened the repair
/// session. This is the same-Mission handoff and not a global Connection state.
#[derive(Clone, Debug)]
pub struct MissionConnectionRepairConsumer {
    request: ConnectionRepairRequest,
    consumed: Option<ConnectionRepairResult>,
}

impl MissionConnectionRepairConsumer {
    pub fn new(request: ConnectionRepairRequest) -> Self {
        Self {
            request,
            consumed: None,
        }
    }

    pub fn request(&self) -> &ConnectionRepairRequest {
        &self.request
    }

    pub fn consume(
        &mut self,
        result: &ConnectionRepairResult,
        at: DateTime<Utc>,
    ) -> Result<ConnectionRepairResult, ConnectionRepairError> {
        if let Some(existing) = &self.consumed {
            return if existing == result {
                Ok(existing.clone())
            } else {
                Err(ConnectionRepairError::AlreadyConsumed)
            };
        }
        result.validate_for_request(&self.request, at)?;
        self.consumed = Some(result.clone());
        Ok(result.clone())
    }

    pub fn consumed(&self) -> Option<&ConnectionRepairResult> {
        self.consumed.as_ref()
    }
}

fn validate_auth_session(
    request: &ConnectionRepairRequest,
    secret: &SecretReference,
    lease: &CredentialLease,
    session: &AuthSession,
    expected_auth_revision: u64,
    at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<(), ConnectionRepairError> {
    if session.scope() != request.scope().connector()
        || session.adapter() != lease.adapter()
        || session.credential_revision() != secret.credential_revision()
        || session.lease_revision() != lease.lease_revision()
        || session.auth_revision() != expected_auth_revision
        || session.issued_at() != at
        || session.expires_at() > expires_at
        || session.expires_at() - session.issued_at()
            > Duration::seconds(MAX_AUTH_SESSION_TTL_SECONDS)
        || at >= session.expires_at()
        || session.expires_at() <= session.issued_at()
    {
        return Err(ConnectionRepairError::InvalidAuthChain);
    }
    Ok(())
}

fn validate_observation(
    request: &ConnectionRepairRequest,
    session: &ConnectionRepairSession,
    auth_session: &AuthSession,
    observation: &ConnectionRepairObservation,
    at: DateTime<Utc>,
) -> Result<(), ConnectionRepairError> {
    observation.validate_shape()?;
    if observation.status() != ConnectionRepairProviderStatus::Reachable {
        return Err(match observation.status() {
            ConnectionRepairProviderStatus::Disconnected => {
                ConnectionRepairError::ProviderStatus(ConnectionRepairProviderStatus::Disconnected)
            }
            ConnectionRepairProviderStatus::Expired => {
                ConnectionRepairError::ProviderStatus(ConnectionRepairProviderStatus::Expired)
            }
            ConnectionRepairProviderStatus::ReauthRequired => {
                ConnectionRepairError::ProviderStatus(
                    ConnectionRepairProviderStatus::ReauthRequired,
                )
            }
            ConnectionRepairProviderStatus::Rejected => {
                ConnectionRepairError::ProviderStatus(ConnectionRepairProviderStatus::Rejected)
            }
            ConnectionRepairProviderStatus::Reachable => unreachable!(),
        });
    }
    if observation.scope() != request.scope().connector()
        || observation.account_id() != request.scope().connector().account_id()
        || observation.provider() != auth_session.adapter()
        || observation.plugin_digest() != request.plugin().digest()
        || !observation
            .capabilities()
            .contains(request.required_capability())
        || observation.freshness().valid_until() > session.expires_at()
        || observation.observed_at() < at
        || observation.observed_at() < auth_session.issued_at()
        || !observation.quota().available()
    {
        return Err(ConnectionRepairError::InvalidObservation);
    }
    if observation.quota().used() >= request.quota_limit() {
        return Err(ConnectionRepairError::QuotaExhausted);
    }
    if observation.freshness().valid_until() <= observation.observed_at() {
        return Err(ConnectionRepairError::FreshnessInsufficient);
    }
    Ok(())
}

fn lifecycle_request(mounted: &MountedRepair, at: DateTime<Utc>) -> RepairLifecycleRequest<'_> {
    RepairLifecycleRequest {
        scope: mounted.request.scope().connector(),
        secret_reference: &mounted.secret_reference,
        credential_lease: &mounted.credential_lease,
        auth_session: mounted.auth_session.as_ref(),
        session_digest: mounted.session.session_digest(),
        at,
    }
}

fn map_connector_error(error: &ConnectorError) -> ConnectionRepairError {
    match error {
        ConnectorError::ProbeExpired | ConnectorError::ProbeNotLive => {
            ConnectionRepairError::FreshnessInsufficient
        }
        _ => ConnectionRepairError::InvalidAuthChain,
    }
}

fn new_opaque_id<T>(occupied: &BTreeMap<String, T>) -> Result<String, ConnectionRepairError> {
    let random = SystemRandom::new();
    for _ in 0..4 {
        let mut bytes = [0_u8; REPAIR_ID_BYTES];
        random
            .fill(&mut bytes)
            .map_err(|_| ConnectionRepairError::EntropyUnavailable)?;
        let candidate = crate::hex_encode(&bytes);
        if !occupied.contains_key(&candidate) {
            return Ok(candidate);
        }
    }
    Err(ConnectionRepairError::EntropyUnavailable)
}

fn valid_identifier(value: &str) -> bool {
    crate::valid_identifier(value)
}

fn is_sha256(value: &str) -> bool {
    crate::is_sha256(value)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use chrono::TimeZone;

    use super::*;
    use crate::{ProviderCapabilitySupport, ProviderEvidenceSupport};

    const ACCOUNT_ID: &str = "account-repair";
    const PLUGIN_ID: &str = "repair.plugin";
    const PROJECT_ID: &str = "project-repair";
    const PROVIDER_ID: &str = "repair-provider";
    const TENANT_ID: &str = "tenant-repair";

    #[derive(Debug, Default)]
    struct ProviderCalls {
        mounts: usize,
        reauthorizations: usize,
        probes: usize,
        unmounts: usize,
        revocations: usize,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ProviderFault {
        Mount,
        Reauthorize,
        InvalidAuthRevision,
        Revoke,
        FreshnessBeyondSession,
    }

    struct TestProvider {
        identity: ProviderAdapterIdentity,
        plugin_digest: String,
        status: ConnectionRepairProviderStatus,
        quota_used: u64,
        fault: Option<ProviderFault>,
        calls: Rc<RefCell<ProviderCalls>>,
    }

    impl TestProvider {
        fn new(status: ConnectionRepairProviderStatus) -> (Self, Rc<RefCell<ProviderCalls>>) {
            let calls = Rc::new(RefCell::new(ProviderCalls::default()));
            let provider = Self {
                identity: ProviderAdapterIdentity::new(PLUGIN_ID, 1).expect("provider identity"),
                plugin_digest: crate::sha256("repair-plugin-binary"),
                status,
                quota_used: 1,
                fault: None,
                calls: Rc::clone(&calls),
            };
            (provider, calls)
        }
    }

    impl ConnectionRepairProvider for TestProvider {
        fn identity(&self) -> &ProviderAdapterIdentity {
            &self.identity
        }

        fn mount(&mut self, request: RepairMountRequest<'_>) -> Result<(), ConnectionRepairError> {
            self.calls.borrow_mut().mounts += 1;
            if self.fault == Some(ProviderFault::Mount) {
                return Err(ConnectionRepairError::Provider(
                    ConnectionRepairProviderFailure::MountRejected,
                ));
            }
            if request.scope != request.secret_reference.scope()
                || request.scope != request.credential_lease.scope()
                || request.session_digest.len() != 64
            {
                return Err(ConnectionRepairError::SecretScopeMismatch);
            }
            Ok(())
        }

        fn reauthorize(
            &mut self,
            request: RepairAuthRequest<'_>,
        ) -> Result<AuthSession, ConnectionRepairError> {
            self.calls.borrow_mut().reauthorizations += 1;
            if self.fault == Some(ProviderFault::Reauthorize) {
                return Err(ConnectionRepairError::Provider(
                    ConnectionRepairProviderFailure::ReauthRejected,
                ));
            }
            let auth_revision = if self.fault == Some(ProviderFault::InvalidAuthRevision) {
                request.auth_revision + 1
            } else {
                request.auth_revision
            };
            ConnectorAuth::begin_auth_session(
                request.secret_reference,
                request.credential_lease,
                format!("auth-session-repair-{auth_revision}"),
                auth_revision,
                request.at,
                request.expires_at,
            )
            .map_err(|_| ConnectionRepairError::Provider(ConnectionRepairProviderFailure::Boundary))
        }

        fn probe(
            &mut self,
            request: RepairProbeRequest<'_>,
        ) -> Result<ConnectionRepairObservation, ConnectionRepairError> {
            self.calls.borrow_mut().probes += 1;
            let valid_until = if self.fault == Some(ProviderFault::FreshnessBeyondSession) {
                request.expires_at + Duration::seconds(1)
            } else {
                request.at + Duration::seconds(20)
            };
            let freshness = FreshnessWindow::new(request.at, valid_until, request.probe_revision)
                .map_err(|_| {
                ConnectionRepairError::Provider(ConnectionRepairProviderFailure::Boundary)
            })?;
            let quota = RepairQuota::new(10, self.quota_used)?;
            ConnectionRepairObservation::new(
                request.scope.clone(),
                request.scope.account_id(),
                [request.requested_capability.clone()],
                quota,
                freshness,
                self.identity.clone(),
                self.plugin_digest.clone(),
                self.status,
                crate::sha256("provider-observation-evidence"),
                request.at,
            )
        }

        fn unmount(&mut self, _request: RepairLifecycleRequest<'_>) {
            self.calls.borrow_mut().unmounts += 1;
        }

        fn revoke(
            &mut self,
            _request: RepairLifecycleRequest<'_>,
        ) -> Result<(), ConnectionRepairError> {
            self.calls.borrow_mut().revocations += 1;
            if self.fault == Some(ProviderFault::Revoke) {
                return Err(ConnectionRepairError::Provider(
                    ConnectionRepairProviderFailure::Revoked,
                ));
            }
            Ok(())
        }
    }

    fn at(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(seconds, 0)
            .single()
            .expect("valid test timestamp")
    }

    fn digest(value: &str) -> String {
        crate::sha256(value)
    }

    fn connector_scope(tenant_id: &str, project_id: &str, account_id: &str) -> ConnectorScope {
        ConnectorScope::new(
            tenant_id,
            project_id,
            PROVIDER_ID,
            account_id,
            ["repair.invoke".to_owned(), "connection.probe".to_owned()],
        )
        .expect("connector scope")
    }

    fn repair_scope(mission_id: &str) -> ConnectionRepairScope {
        ConnectionRepairScope::new(
            MissionRepairScope::new(TENANT_ID, PROJECT_ID, mission_id, 7).expect("Mission scope"),
            connector_scope(TENANT_ID, PROJECT_ID, ACCOUNT_ID),
        )
        .expect("repair scope")
    }

    fn plugin(plugin_id: &str) -> ConnectionRepairPlugin {
        ConnectionRepairPlugin::new(plugin_id, 1, digest("repair-plugin-binary"))
            .expect("repair plugin")
    }

    fn request_with_plugin(
        mission_id: &str,
        invocation: &str,
        plugin_id: &str,
        reason: ConnectionRepairReason,
        session_ttl: Duration,
        quota_limit: u64,
    ) -> ConnectionRepairRequest {
        let scope = repair_scope(mission_id);
        let secret_reference =
            SecretReference::new("secret-ref-opaque-reference", scope.connector().clone(), 11)
                .expect("secret reference");
        ConnectionRepairRequest::new(
            scope,
            "connection-repair",
            plugin(plugin_id),
            secret_reference,
            digest(invocation),
            digest("objective-content"),
            ProviderCapabilityKey::new(PROVIDER_ID, "repair.invoke").expect("capability"),
            reason,
            digest("failed-connection-result"),
            6,
            4,
            12,
            session_ttl,
            quota_limit,
        )
        .expect("repair request")
    }

    fn request(
        mission_id: &str,
        invocation: &str,
        reason: ConnectionRepairReason,
        session_ttl: Duration,
        quota_limit: u64,
    ) -> ConnectionRepairRequest {
        request_with_plugin(
            mission_id,
            invocation,
            PLUGIN_ID,
            reason,
            session_ttl,
            quota_limit,
        )
    }

    fn registry_for(
        identity: &ProviderAdapterIdentity,
        provenance: ProviderProvenanceClass,
    ) -> ProviderAdapterRegistry {
        let key = ProviderCapabilityKey::new(PROVIDER_ID, CONNECTION_PROBE_CAPABILITY)
            .expect("probe capability");
        let evidence = [
            (
                ProviderAdapterOperation::BeginAuth,
                ProviderEvidenceClass::Authentication,
            ),
            (
                ProviderAdapterOperation::Refresh,
                ProviderEvidenceClass::Authentication,
            ),
            (
                ProviderAdapterOperation::Probe,
                ProviderEvidenceClass::ProbeObservation,
            ),
            (
                ProviderAdapterOperation::Revoke,
                ProviderEvidenceClass::RevocationObservation,
            ),
        ]
        .into_iter()
        .map(|(operation, evidence_class)| {
            ProviderEvidenceSupport::new(operation, evidence_class, provenance)
                .expect("provider evidence support")
        });
        let registration =
            ProviderCapabilitySupport::new(key, identity.clone(), evidence).expect("registration");
        ProviderAdapterRegistry::new("repair-test-v1", [registration]).expect("registry")
    }

    fn service(
        provider: TestProvider,
        provenance: ProviderProvenanceClass,
    ) -> ConnectionRepairService<TestProvider> {
        let identity = provider.identity.clone();
        ConnectionRepairService::new(
            provider,
            registry_for(&identity, provenance),
            super::super::events::ConnectionRepairEventLog::default(),
        )
        .expect("repair service")
    }

    #[test]
    fn successful_repair_is_consumed_by_same_mission_and_redacts_secrets() {
        let start = at(1_700_000_000);
        let repair_request = request(
            "mission-success",
            "invocation-success",
            ConnectionRepairReason::Disconnected,
            Duration::seconds(30),
            5,
        );
        let mut consumer = MissionConnectionRepairConsumer::new(repair_request.clone());
        let (provider, calls) = TestProvider::new(ConnectionRepairProviderStatus::Reachable);
        let mut service = service(provider, ProviderProvenanceClass::ProductionProvider);
        let session = service
            .open(repair_request.clone(), start)
            .expect("open repair");
        let result = service
            .repair(&session, start + Duration::seconds(1))
            .expect("repair");

        assert_eq!(result.status(), ConnectionRepairResultStatus::Verified);
        assert_eq!(result.scope(), repair_request.scope());
        assert_eq!(
            result.invocation_digest(),
            repair_request.invocation_digest()
        );
        assert_eq!(result.plugin(), repair_request.plugin());
        assert_eq!(result.auth_revision(), 13);
        assert_eq!(result.probe_revision(), 7);
        assert!(result.is_live_at(start + Duration::seconds(2)));
        assert_eq!(
            consumer.consume(&result, start + Duration::seconds(2)),
            Ok(result.clone())
        );
        assert_eq!(
            consumer.consume(&result, start + Duration::seconds(3)),
            Ok(result.clone())
        );

        let mut wrong_mission = MissionConnectionRepairConsumer::new(request(
            "mission-other",
            "invocation-success",
            ConnectionRepairReason::Disconnected,
            Duration::seconds(30),
            5,
        ));
        assert_eq!(
            wrong_mission.consume(&result, start + Duration::seconds(2)),
            Err(ConnectionRepairError::ResultNotAccepted)
        );

        let request_debug = format!("{repair_request:?}");
        assert!(!request_debug.contains("secret-ref-opaque-reference"));
        assert!(!request_debug.contains("objective-content"));
        let session_debug = format!("{session:?}");
        assert!(!session_debug.contains(&session.session_id));
        let result_json = serde_json::to_string(&result).expect("result serialization");
        let events_json = serde_json::to_string(service.events()).expect("event serialization");
        assert!(!result_json.contains("secret-ref-opaque-reference"));
        assert!(!result_json.contains("objective-content"));
        assert!(!events_json.contains("secret-ref-opaque-reference"));
        assert!(!events_json.contains("objective-content"));

        let mut stale_consumer = MissionConnectionRepairConsumer::new(repair_request.clone());
        assert_eq!(
            stale_consumer.consume(&result, start + Duration::seconds(21)),
            Err(ConnectionRepairError::ResultExpired)
        );
        service
            .complete(&session, start + Duration::seconds(3))
            .expect("complete repair");
        assert_eq!(service.active_session_count(), 0);
        assert_eq!(calls.borrow().mounts, 1);
        assert_eq!(calls.borrow().reauthorizations, 1);
        assert_eq!(calls.borrow().probes, 1);
        assert_eq!(calls.borrow().unmounts, 1);
        assert!(service.events().validate_chain().is_ok());
        assert_eq!(service.events().events().len(), 3);
        assert_eq!(
            *service.events().events()[0].kind(),
            ConnectionRepairEventKind::SessionOpened
        );
        assert_eq!(
            *service.events().events()[1].kind(),
            ConnectionRepairEventKind::ProbeSucceeded
        );
        assert_eq!(
            *service.events().events()[2].kind(),
            ConnectionRepairEventKind::SessionCompleted
        );
    }

    #[test]
    fn disconnected_expired_and_reauth_required_results_fail_closed() {
        let start = at(1_700_000_100);
        for status in [
            ConnectionRepairProviderStatus::Disconnected,
            ConnectionRepairProviderStatus::Expired,
            ConnectionRepairProviderStatus::ReauthRequired,
        ] {
            let (provider, calls) = TestProvider::new(status);
            let mut service = service(provider, ProviderProvenanceClass::ProductionProvider);
            let request = request(
                "mission-fail-closed",
                &format!("invocation-{status:?}"),
                ConnectionRepairReason::ReauthRequired,
                Duration::seconds(30),
                5,
            );
            let session = service.open(request, start).expect("open repair");
            assert_eq!(
                service.repair(&session, start + Duration::seconds(1)),
                Err(ConnectionRepairError::ProviderStatus(status))
            );
            assert_eq!(service.active_session_count(), 0);
            assert_eq!(calls.borrow().reauthorizations, 1);
            assert_eq!(calls.borrow().probes, 1);
            assert_eq!(calls.borrow().unmounts, 1);
            assert_eq!(
                *service.events().events()[1].kind(),
                ConnectionRepairEventKind::ProbeFailed
            );
        }
    }

    #[test]
    fn reauthorization_error_unmounts_and_does_not_return_a_result() {
        let (mut provider, calls) = TestProvider::new(ConnectionRepairProviderStatus::Reachable);
        provider.fault = Some(ProviderFault::Reauthorize);
        let mut service = service(provider, ProviderProvenanceClass::ProductionProvider);
        let start = at(1_700_000_200);
        let request = request(
            "mission-reauth-error",
            "invocation-reauth-error",
            ConnectionRepairReason::ReauthRequired,
            Duration::seconds(30),
            5,
        );
        let session = service.open(request, start).expect("open repair");
        assert_eq!(
            service.repair(&session, start + Duration::seconds(1)),
            Err(ConnectionRepairError::Provider(
                ConnectionRepairProviderFailure::ReauthRejected
            ))
        );
        assert_eq!(service.active_session_count(), 0);
        assert_eq!(calls.borrow().unmounts, 1);
        assert!(service.events().validate_chain().is_ok());
    }

    #[test]
    fn invalid_provider_auth_metadata_is_reclaimed_before_error_returns() {
        let (mut provider, calls) = TestProvider::new(ConnectionRepairProviderStatus::Reachable);
        provider.fault = Some(ProviderFault::InvalidAuthRevision);
        let mut service = service(provider, ProviderProvenanceClass::ProductionProvider);
        let start = at(1_700_000_250);
        let request = request(
            "mission-invalid-auth",
            "invocation-invalid-auth",
            ConnectionRepairReason::ReauthRequired,
            Duration::seconds(30),
            5,
        );
        let session = service.open(request, start).expect("open repair");
        assert_eq!(
            service.repair(&session, start + Duration::seconds(1)),
            Err(ConnectionRepairError::InvalidAuthChain)
        );
        assert_eq!(service.active_session_count(), 0);
        assert_eq!(calls.borrow().unmounts, 1);
        assert_eq!(
            *service.events().events()[1].kind(),
            ConnectionRepairEventKind::ProbeFailed
        );
    }

    #[test]
    fn scope_plugin_and_fixture_boundaries_fail_closed_before_mount() {
        let connector = connector_scope("tenant-other", PROJECT_ID, ACCOUNT_ID);
        let mismatched_mission =
            MissionRepairScope::new(TENANT_ID, PROJECT_ID, "mission-scope-mismatch", 1)
                .expect("mission scope");
        assert_eq!(
            ConnectionRepairScope::new(mismatched_mission, connector),
            Err(ConnectionRepairError::ScopeMismatch)
        );

        let (provider, calls) = TestProvider::new(ConnectionRepairProviderStatus::Reachable);
        let mut plugin_service = service(provider, ProviderProvenanceClass::ProductionProvider);
        let wrong_plugin = request_with_plugin(
            "mission-plugin-mismatch",
            "invocation-plugin-mismatch",
            "different.plugin",
            ConnectionRepairReason::Disconnected,
            Duration::seconds(30),
            5,
        );
        assert_eq!(
            plugin_service.open(wrong_plugin, at(1_700_000_300)),
            Err(ConnectionRepairError::PluginMismatch)
        );
        assert_eq!(calls.borrow().mounts, 0);

        let (fixture_provider, fixture_calls) =
            TestProvider::new(ConnectionRepairProviderStatus::Reachable);
        let mut fixture_service = service(fixture_provider, ProviderProvenanceClass::Fixture);
        let fixture_request = request(
            "mission-fixture",
            "invocation-fixture",
            ConnectionRepairReason::Disconnected,
            Duration::seconds(30),
            5,
        );
        assert_eq!(
            fixture_service.open(fixture_request, at(1_700_000_301)),
            Err(ConnectionRepairError::UnsupportedProviderBoundary)
        );
        assert_eq!(fixture_calls.borrow().mounts, 0);
    }

    #[test]
    fn quota_and_freshness_fences_reclaim_the_mount() {
        let start = at(1_700_000_400);
        let (mut quota_provider, quota_calls) =
            TestProvider::new(ConnectionRepairProviderStatus::Reachable);
        quota_provider.quota_used = 5;
        let mut quota_service =
            service(quota_provider, ProviderProvenanceClass::ProductionProvider);
        let quota_request = request(
            "mission-quota",
            "invocation-quota",
            ConnectionRepairReason::Expired,
            Duration::seconds(30),
            5,
        );
        let quota_session = quota_service
            .open(quota_request, start)
            .expect("open quota repair");
        assert_eq!(
            quota_service.repair(&quota_session, start + Duration::seconds(1)),
            Err(ConnectionRepairError::QuotaExhausted)
        );
        assert_eq!(quota_service.active_session_count(), 0);
        assert_eq!(quota_calls.borrow().unmounts, 1);

        let (mut stale_provider, stale_calls) =
            TestProvider::new(ConnectionRepairProviderStatus::Reachable);
        stale_provider.fault = Some(ProviderFault::FreshnessBeyondSession);
        let mut stale_service =
            service(stale_provider, ProviderProvenanceClass::ProductionProvider);
        let stale_request = request(
            "mission-freshness",
            "invocation-freshness",
            ConnectionRepairReason::Expired,
            Duration::seconds(30),
            5,
        );
        let stale_session = stale_service
            .open(stale_request, start)
            .expect("open stale repair");
        assert_eq!(
            stale_service.repair(&stale_session, start + Duration::seconds(1)),
            Err(ConnectionRepairError::InvalidObservation)
        );
        assert_eq!(stale_service.active_session_count(), 0);
        assert_eq!(stale_calls.borrow().unmounts, 1);
    }

    #[test]
    fn expiry_revoke_and_crash_cleanup_are_reversible_and_non_reusable() {
        let start = at(1_700_000_500);
        let (provider, calls) = TestProvider::new(ConnectionRepairProviderStatus::Reachable);
        let mut service = service(provider, ProviderProvenanceClass::ProductionProvider);
        let expiring_request = request(
            "mission-expiry",
            "invocation-expiry",
            ConnectionRepairReason::Expired,
            Duration::seconds(1),
            5,
        );
        let expiring_session = service
            .open(expiring_request.clone(), start)
            .expect("open expiring repair");
        assert_eq!(
            service.repair(&expiring_session, start - Duration::seconds(1)),
            Err(ConnectionRepairError::TimestampRegression)
        );
        assert_eq!(service.active_session_count(), 1);
        assert_eq!(service.expire(start + Duration::seconds(1)), Ok(1));
        assert_eq!(service.active_session_count(), 0);
        assert_eq!(calls.borrow().unmounts, 1);
        assert_eq!(
            service.open(expiring_request, start + Duration::seconds(1)),
            Err(ConnectionRepairError::SessionNotReusable)
        );
        assert_eq!(
            service.repair(&expiring_session, start + Duration::seconds(1)),
            Err(ConnectionRepairError::SessionNotFound)
        );

        let revocable_request = request(
            "mission-revoke",
            "invocation-revoke",
            ConnectionRepairReason::Disconnected,
            Duration::seconds(30),
            5,
        );
        let revocable_session = service
            .open(revocable_request.clone(), start + Duration::seconds(2))
            .expect("open revocable repair");
        service
            .revoke(&revocable_session, start + Duration::seconds(3))
            .expect("revoke repair");
        assert_eq!(service.active_session_count(), 0);
        assert_eq!(calls.borrow().revocations, 1);
        assert_eq!(calls.borrow().unmounts, 2);
        assert_eq!(
            service.open(revocable_request, start + Duration::seconds(3)),
            Err(ConnectionRepairError::SessionNotReusable)
        );

        let crash_request = request(
            "mission-crash",
            "invocation-crash",
            ConnectionRepairReason::Disconnected,
            Duration::seconds(30),
            5,
        );
        let crash_session = service
            .open(crash_request, start + Duration::seconds(4))
            .expect("open crash repair");
        assert_eq!(service.crash_cleanup(start + Duration::seconds(5)), Ok(1));
        assert_eq!(service.active_session_count(), 0);
        assert_eq!(calls.borrow().unmounts, 3);
        assert_eq!(
            service.repair(&crash_session, start + Duration::seconds(5)),
            Err(ConnectionRepairError::SessionNotFound)
        );
        assert!(service.events().validate_chain().is_ok());
        assert!(
            service
                .events()
                .events()
                .iter()
                .any(|event| *event.kind() == ConnectionRepairEventKind::SessionExpired)
        );
        assert!(
            service
                .events()
                .events()
                .iter()
                .any(|event| *event.kind() == ConnectionRepairEventKind::SessionRevoked)
        );
        assert!(
            service
                .events()
                .events()
                .iter()
                .any(|event| *event.kind() == ConnectionRepairEventKind::SessionCrashed)
        );
    }

    #[test]
    fn mount_failure_is_cleaned_without_opening_a_durable_session() {
        let (mut provider, calls) = TestProvider::new(ConnectionRepairProviderStatus::Reachable);
        provider.fault = Some(ProviderFault::Mount);
        let mut service = service(provider, ProviderProvenanceClass::ProductionProvider);
        let request = request(
            "mission-mount-error",
            "invocation-mount-error",
            ConnectionRepairReason::Disconnected,
            Duration::seconds(30),
            5,
        );
        assert_eq!(
            service.open(request, at(1_700_000_600)),
            Err(ConnectionRepairError::Provider(
                ConnectionRepairProviderFailure::MountRejected
            ))
        );
        assert_eq!(service.active_session_count(), 0);
        assert_eq!(calls.borrow().mounts, 1);
        assert_eq!(calls.borrow().unmounts, 1);
        assert!(service.events().events().is_empty());
    }
}
