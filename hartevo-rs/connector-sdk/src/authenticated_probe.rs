//! Live, authenticated provider probe results for Mission capability use.
//!
//! This module is intentionally narrower than the general connector worker.
//! A provider receives an exact [`SecretReference`] resolution and may only
//! return read-only probe evidence.  The service never exposes credential
//! material in a result, handle, Debug implementation, or Mission-facing
//! availability projection.  A successful result is production evidence, not
//! a provider catalog card and not an Effect authorization.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use super::{
    AuthSession, ConnectorAuth, ConnectorError, ConnectorScope, CostState, CredentialLease,
    FreshnessWindow, MAX_AUTH_SESSION_TTL_SECONDS, MAX_CREDENTIAL_LEASE_TTL_SECONDS,
    MAX_PROBE_TTL_SECONDS, ProbeStatus, ProviderAdapterIdentity, ProviderAdapterOperation,
    ProviderAdapterRegistry, ProviderCapabilityKey, ProviderEvidenceClass, ProviderProvenanceClass,
    QuotaState, SecretReference,
};

const CONNECTION_PROBE_CAPABILITY: &str = "connection.probe";
const HANDLE_BYTES: usize = 32;

/// A short-lived secret view returned by a keyring/project-secret resolver.
///
/// The value is intentionally not serializable and its Debug output never
/// includes bytes.  The service does not retain it after the provider call.
pub struct SecretMaterial(Zeroizing<Vec<u8>>);

impl SecretMaterial {
    /// Constructs a temporary credential view for a provider call.
    pub fn new(bytes: impl AsRef<[u8]>) -> Result<Self, AuthenticatedProbeError> {
        let bytes = bytes.as_ref();
        if bytes.is_empty() {
            return Err(AuthenticatedProbeError::SecretUnavailable);
        }
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }

    /// Returns the credential bytes only to the provider during its call.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretMaterial")
            .field("present", &true)
            .finish_non_exhaustive()
    }
}

/// Resolves an opaque reference from the OS/project secret boundary.
///
/// Implementations must look up the exact reference and scope.  They must not
/// return a credential for a different account, project, tenant, or revision.
pub trait SecretReferenceResolver {
    fn resolve(
        &mut self,
        reference: &SecretReference,
        at: DateTime<Utc>,
    ) -> Result<SecretMaterial, AuthenticatedProbeError>;

    /// Revoke the exact reference after the service has already reclaimed its
    /// active mount.
    fn revoke_reference(
        &mut self,
        reference: &SecretReference,
        at: DateTime<Utc>,
    ) -> Result<(), AuthenticatedProbeError>;
}

/// A provider request with the authenticated chain and an exact
/// SecretReference-backed resolver.
///
/// The provider obtains a temporary credential by calling
/// [`Self::resolve_credentials`]. The trait exposes no read/write/effect
/// method other than `probe`, so this service cannot turn an authenticated
/// probe into a provider write effect.
pub struct AuthenticatedProbeRequest<'a> {
    scope: &'a ConnectorScope,
    secret_reference: &'a SecretReference,
    credential_lease: &'a CredentialLease,
    auth_session: &'a AuthSession,
    resolver: &'a mut dyn SecretReferenceResolver,
    at: DateTime<Utc>,
    probe_revision: u64,
}

impl<'a> AuthenticatedProbeRequest<'a> {
    pub fn scope(&self) -> &'a ConnectorScope {
        self.scope
    }

    pub fn secret_reference(&self) -> &'a SecretReference {
        self.secret_reference
    }

    pub fn credential_lease(&self) -> &'a CredentialLease {
        self.credential_lease
    }

    pub fn auth_session(&self) -> &'a AuthSession {
        self.auth_session
    }

    pub fn resolve_credentials(&mut self) -> Result<SecretMaterial, AuthenticatedProbeError> {
        self.resolver.resolve(self.secret_reference, self.at)
    }

    pub const fn at(&self) -> DateTime<Utc> {
        self.at
    }

    pub const fn probe_revision(&self) -> u64 {
        self.probe_revision
    }
}

impl fmt::Debug for AuthenticatedProbeRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedProbeRequest")
            .field("scope", &self.scope)
            .field("secret_reference", &self.secret_reference)
            .field("credential_lease", &self.credential_lease)
            .field("auth_session", &self.auth_session)
            .field("resolver", &"[OPAQUE]")
            .field("at", &self.at)
            .field("probe_revision", &self.probe_revision)
            .finish_non_exhaustive()
    }
}

/// A lifecycle request without credential bytes.  It is used to unwind a
/// provider's in-memory state after unmount or revoke.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeLifecycleRequest {
    scope: ConnectorScope,
    secret_reference: SecretReference,
    credential_lease: CredentialLease,
    auth_session: AuthSession,
    mount_digest: String,
    at: DateTime<Utc>,
}

impl ProbeLifecycleRequest {
    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn credential_lease(&self) -> &CredentialLease {
        &self.credential_lease
    }

    pub fn auth_session(&self) -> &AuthSession {
        &self.auth_session
    }

    pub fn mount_digest(&self) -> &str {
        &self.mount_digest
    }

    pub const fn at(&self) -> DateTime<Utc> {
        self.at
    }
}

/// The provider-facing seam for a real authenticated probe.
pub trait AuthenticatedProbeProvider {
    fn identity(&self) -> &ProviderAdapterIdentity;

    fn probe(
        &mut self,
        request: AuthenticatedProbeRequest<'_>,
    ) -> Result<AuthenticatedProbeObservation, AuthenticatedProbeError>;

    fn unmount(&mut self, request: ProbeLifecycleRequest);

    fn revoke(&mut self, request: ProbeLifecycleRequest) -> Result<(), AuthenticatedProbeError>;
}

/// Read-only evidence returned by a provider after it used the resolved
/// SecretReference credential.  It is not accepted directly by a Mission
/// consumer until the service validates the exact provider registry binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedProbeObservation {
    scope: ConnectorScope,
    capabilities: BTreeSet<ProviderCapabilityKey>,
    quota: QuotaState,
    freshness: FreshnessWindow,
    cost: CostState,
    provider_identity: ProviderAdapterIdentity,
    provider_digest: String,
    status: ProbeStatus,
    provenance: ProviderProvenanceClass,
    evidence_digest: String,
    observed_at: DateTime<Utc>,
}

impl AuthenticatedProbeObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ConnectorScope,
        capabilities: impl IntoIterator<Item = ProviderCapabilityKey>,
        quota: QuotaState,
        freshness: FreshnessWindow,
        cost: CostState,
        provider_identity: ProviderAdapterIdentity,
        provider_digest: impl Into<String>,
        status: ProbeStatus,
        provenance: ProviderProvenanceClass,
        evidence_digest: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, AuthenticatedProbeError> {
        let observation = Self {
            scope,
            capabilities: capabilities.into_iter().collect(),
            quota,
            freshness,
            cost,
            provider_identity,
            provider_digest: provider_digest.into(),
            status,
            provenance,
            evidence_digest: evidence_digest.into(),
            observed_at,
        };
        observation.validate_shape()?;
        Ok(observation)
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn capabilities(&self) -> &BTreeSet<ProviderCapabilityKey> {
        &self.capabilities
    }

    pub const fn quota(&self) -> &QuotaState {
        &self.quota
    }

    pub const fn freshness(&self) -> &FreshnessWindow {
        &self.freshness
    }

    pub const fn cost(&self) -> &CostState {
        &self.cost
    }

    pub fn provider_identity(&self) -> &ProviderAdapterIdentity {
        &self.provider_identity
    }

    pub fn provider_digest(&self) -> &str {
        &self.provider_digest
    }

    pub const fn status(&self) -> ProbeStatus {
        self.status
    }

    pub const fn provenance(&self) -> ProviderProvenanceClass {
        self.provenance
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    fn validate_shape(&self) -> Result<(), AuthenticatedProbeError> {
        if self.capabilities.is_empty()
            || self
                .capabilities
                .iter()
                .any(|capability| capability.provider_id() != self.scope.provider_id())
            || self.freshness.observed_at() != self.observed_at
            || self.freshness.valid_until() - self.freshness.observed_at()
                > Duration::seconds(MAX_PROBE_TTL_SECONDS)
            || self.quota.used() > self.quota.limit()
            || self.cost.used_minor() > self.cost.limit_minor()
            || !super::is_sha256(&self.provider_digest)
            || !super::is_sha256(&self.evidence_digest)
        {
            return Err(AuthenticatedProbeError::InvalidObservation);
        }
        Ok(())
    }
}

/// A successful, registry-bound authenticated probe result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticatedProbeResult {
    result_id: String,
    mount_digest: String,
    scope: ConnectorScope,
    capabilities: BTreeSet<ProviderCapabilityKey>,
    quota: QuotaState,
    freshness: FreshnessWindow,
    cost: CostState,
    provider_identity: ProviderAdapterIdentity,
    provider_digest: String,
    status: ProbeStatus,
    provenance: ProviderProvenanceClass,
    evidence_digest: String,
    observed_at: DateTime<Utc>,
    result_digest: String,
}

impl AuthenticatedProbeResult {
    pub fn result_id(&self) -> &str {
        &self.result_id
    }

    /// A digest of the opaque mount, not the opaque handle itself.
    pub fn mount_digest(&self) -> &str {
        &self.mount_digest
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn capabilities(&self) -> &BTreeSet<ProviderCapabilityKey> {
        &self.capabilities
    }

    pub const fn quota(&self) -> &QuotaState {
        &self.quota
    }

    pub const fn freshness(&self) -> &FreshnessWindow {
        &self.freshness
    }

    pub const fn cost(&self) -> &CostState {
        &self.cost
    }

    pub fn provider_identity(&self) -> &ProviderAdapterIdentity {
        &self.provider_identity
    }

    pub fn provider_digest(&self) -> &str {
        &self.provider_digest
    }

    pub const fn status(&self) -> ProbeStatus {
        self.status
    }

    pub const fn provenance(&self) -> ProviderProvenanceClass {
        self.provenance
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

    fn from_observation(
        mount_digest: String,
        observation: AuthenticatedProbeObservation,
    ) -> Result<Self, AuthenticatedProbeError> {
        observation.validate_shape()?;
        if !super::is_sha256(&mount_digest) {
            return Err(AuthenticatedProbeError::InvalidObservation);
        }
        let result_digest = digest_values([
            mount_digest.as_str(),
            observation.scope.digest().as_str(),
            &capability_digest_material(&observation.capabilities),
            &observation.quota.limit().to_string(),
            &observation.quota.used().to_string(),
            &observation.freshness.observed_at().to_rfc3339(),
            &observation.freshness.valid_until().to_rfc3339(),
            &observation.freshness.source_revision().to_string(),
            &observation.cost.limit_minor().to_string(),
            &observation.cost.used_minor().to_string(),
            observation.provider_identity.adapter_id(),
            &observation.provider_identity.adapter_version().to_string(),
            observation.provider_digest.as_str(),
            &format!("{:?}", observation.status),
            &format!("{:?}", observation.provenance),
            observation.evidence_digest.as_str(),
            &observation.observed_at.to_rfc3339(),
        ]);
        Ok(Self {
            result_id: format!("probe-result-{result_digest}"),
            mount_digest,
            scope: observation.scope,
            capabilities: observation.capabilities,
            quota: observation.quota,
            freshness: observation.freshness,
            cost: observation.cost,
            provider_identity: observation.provider_identity,
            provider_digest: observation.provider_digest,
            status: observation.status,
            provenance: observation.provenance,
            evidence_digest: observation.evidence_digest,
            observed_at: observation.observed_at,
            result_digest,
        })
    }

    fn validate_live_at(&self, at: DateTime<Utc>) -> Result<(), AuthenticatedProbeError> {
        if self.status != ProbeStatus::Reachable {
            return Err(AuthenticatedProbeError::ProbeDisconnected);
        }
        if self.provenance != ProviderProvenanceClass::ProductionProvider {
            return Err(AuthenticatedProbeError::FixtureEvidence);
        }
        if at < self.observed_at || at >= self.freshness.valid_until() {
            return Err(AuthenticatedProbeError::ProbeExpired);
        }
        if self.quota.used() >= self.quota.limit() {
            return Err(AuthenticatedProbeError::QuotaExhausted);
        }
        if self.cost.used_minor() >= self.cost.limit_minor() {
            return Err(AuthenticatedProbeError::CostExhausted);
        }
        Ok(())
    }
}

/// The Mission identity used by the consumer projection.  Probe results do
/// not claim a Mission; a consumer binds them to one exact Mission scope.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    tenant_id: String,
    project_id: String,
    mission_id: String,
    mission_revision: u64,
}

impl MissionScope {
    pub fn new(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        mission_revision: u64,
    ) -> Result<Self, AuthenticatedProbeError> {
        let scope = Self {
            tenant_id: tenant_id.into(),
            project_id: project_id.into(),
            mission_id: mission_id.into(),
            mission_revision,
        };
        if !super::valid_identifier(&scope.tenant_id)
            || !super::valid_identifier(&scope.project_id)
            || !super::valid_identifier(&scope.mission_id)
            || scope.mission_revision == 0
        {
            return Err(AuthenticatedProbeError::InvalidMissionScope);
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
        digest_values([
            self.tenant_id.as_str(),
            self.project_id.as_str(),
            self.mission_id.as_str(),
            &self.mission_revision.to_string(),
        ])
    }
}

/// A Mission-facing projection of authenticated availability.  This is not a
/// catalog entry: it is bound to one Mission and one live probe result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionCapabilityAvailability {
    mission: MissionScope,
    source_result_id: String,
    source_result_digest: String,
    source_mount_digest: String,
    scope: ConnectorScope,
    capabilities: BTreeSet<ProviderCapabilityKey>,
    quota: QuotaState,
    freshness: FreshnessWindow,
    cost: CostState,
    provider_identity: ProviderAdapterIdentity,
    provider_digest: String,
    observed_at: DateTime<Utc>,
    availability_digest: String,
}

impl MissionCapabilityAvailability {
    pub fn mission(&self) -> &MissionScope {
        &self.mission
    }

    pub fn source_result_id(&self) -> &str {
        &self.source_result_id
    }

    pub fn source_result_digest(&self) -> &str {
        &self.source_result_digest
    }

    pub fn source_mount_digest(&self) -> &str {
        &self.source_mount_digest
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn capabilities(&self) -> &BTreeSet<ProviderCapabilityKey> {
        &self.capabilities
    }

    pub const fn quota(&self) -> &QuotaState {
        &self.quota
    }

    pub const fn freshness(&self) -> &FreshnessWindow {
        &self.freshness
    }

    pub const fn cost(&self) -> &CostState {
        &self.cost
    }

    pub fn provider_identity(&self) -> &ProviderAdapterIdentity {
        &self.provider_identity
    }

    pub fn provider_digest(&self) -> &str {
        &self.provider_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn availability_digest(&self) -> &str {
        &self.availability_digest
    }

    pub fn supports(&self, capability: &ProviderCapabilityKey, at: DateTime<Utc>) -> bool {
        self.is_live_at(at) && self.capabilities.contains(capability)
    }

    pub fn is_live_at(&self, at: DateTime<Utc>) -> bool {
        at >= self.observed_at
            && at < self.freshness.valid_until()
            && self.quota.used() < self.quota.limit()
            && self.cost.used_minor() < self.cost.limit_minor()
    }

    fn from_result(mission: MissionScope, result: &AuthenticatedProbeResult) -> Self {
        let availability_digest = digest_values([
            mission.digest().as_str(),
            result.result_digest(),
            result.scope.digest().as_str(),
            result.provider_digest(),
        ]);
        Self {
            mission,
            source_result_id: result.result_id.clone(),
            source_result_digest: result.result_digest.clone(),
            source_mount_digest: result.mount_digest.clone(),
            scope: result.scope.clone(),
            capabilities: result.capabilities.clone(),
            quota: result.quota.clone(),
            freshness: result.freshness.clone(),
            cost: result.cost.clone(),
            provider_identity: result.provider_identity.clone(),
            provider_digest: result.provider_digest.clone(),
            observed_at: result.observed_at,
            availability_digest,
        }
    }
}

/// Consumes authenticated probe results as Mission capability availability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionCapabilityConsumer {
    mission: MissionScope,
    availability: BTreeMap<String, MissionCapabilityAvailability>,
}

impl MissionCapabilityConsumer {
    pub fn new(mission: MissionScope) -> Self {
        Self {
            mission,
            availability: BTreeMap::new(),
        }
    }

    pub fn mission(&self) -> &MissionScope {
        &self.mission
    }

    pub fn accept(
        &mut self,
        result: &AuthenticatedProbeResult,
        at: DateTime<Utc>,
    ) -> Result<MissionCapabilityAvailability, AuthenticatedProbeError> {
        result.validate_live_at(at)?;
        if result.scope.tenant_id() != self.mission.tenant_id
            || result.scope.project_id() != self.mission.project_id
        {
            return Err(AuthenticatedProbeError::MissionScopeMismatch);
        }
        let availability = MissionCapabilityAvailability::from_result(self.mission.clone(), result);
        self.availability
            .insert(result.result_id.clone(), availability.clone());
        Ok(availability)
    }

    pub fn availability(&self, result_id: &str) -> Option<&MissionCapabilityAvailability> {
        self.availability.get(result_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &MissionCapabilityAvailability> {
        self.availability.values()
    }

    pub fn availability_count(&self) -> usize {
        self.availability.len()
    }

    pub fn supports(&self, capability: &ProviderCapabilityKey, at: DateTime<Utc>) -> bool {
        self.availability
            .values()
            .any(|availability| availability.supports(capability, at))
    }

    /// Reclaims expired or exhausted availability projections.
    pub fn reclaim_expired(&mut self, at: DateTime<Utc>) -> usize {
        let before = self.availability.len();
        self.availability
            .retain(|_, availability| availability.is_live_at(at));
        before - self.availability.len()
    }

    /// Removes every availability sourced from one service mount.
    pub fn unmount(&mut self, mount_digest: &str) -> usize {
        let before = self.availability.len();
        self.availability
            .retain(|_, availability| availability.source_mount_digest() != mount_digest);
        before - self.availability.len()
    }

    /// Removes every availability for the exact revoked provider scope.
    pub fn revoke(&mut self, scope: &ConnectorScope) -> usize {
        let before = self.availability.len();
        self.availability
            .retain(|_, availability| availability.scope() != scope);
        before - self.availability.len()
    }

    pub fn clear(&mut self) {
        self.availability.clear();
    }
}

/// Opaque process-local handle for one authenticated probe mount.
pub struct AuthenticatedProbeHandle(String);

impl Clone for AuthenticatedProbeHandle {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl PartialEq for AuthenticatedProbeHandle {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for AuthenticatedProbeHandle {}

impl PartialOrd for AuthenticatedProbeHandle {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AuthenticatedProbeHandle {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl fmt::Debug for AuthenticatedProbeHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AuthenticatedProbeHandle")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl AuthenticatedProbeHandle {
    pub fn digest(&self) -> String {
        digest_values([self.0.as_str()])
    }
}

#[derive(Clone, Debug)]
struct MountedProbe {
    scope: ConnectorScope,
    secret_reference: SecretReference,
    credential_lease: CredentialLease,
    auth_session: AuthSession,
    provider_identity: ProviderAdapterIdentity,
    mount_digest: String,
    mounted_at: DateTime<Utc>,
    next_probe_revision: u64,
}

/// Service that mounts a provider, resolves its SecretReference at probe time,
/// and emits only authenticated, live, production probe results.
pub struct AuthenticatedProbeService<P, R>
where
    P: AuthenticatedProbeProvider,
    R: SecretReferenceResolver,
{
    provider: P,
    resolver: R,
    registry: ProviderAdapterRegistry,
    mounts: BTreeMap<String, MountedProbe>,
    next_mount_revision: u64,
}

impl<P, R> fmt::Debug for AuthenticatedProbeService<P, R>
where
    P: AuthenticatedProbeProvider,
    R: SecretReferenceResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedProbeService")
            .field("provider_identity", self.provider.identity())
            .field("registry_version", &self.registry.registry_version())
            .field("active_mount_count", &self.mounts.len())
            .finish_non_exhaustive()
    }
}

impl<P, R> AuthenticatedProbeService<P, R>
where
    P: AuthenticatedProbeProvider,
    R: SecretReferenceResolver,
{
    pub fn new(
        provider: P,
        resolver: R,
        registry: ProviderAdapterRegistry,
    ) -> Result<Self, AuthenticatedProbeError> {
        registry
            .validate()
            .map_err(|_| AuthenticatedProbeError::InvalidRegistry)?;
        if registry.is_empty() {
            return Err(AuthenticatedProbeError::EmptyRegistry);
        }
        Ok(Self {
            provider,
            resolver,
            registry,
            mounts: BTreeMap::new(),
            next_mount_revision: 1,
        })
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn registry(&self) -> &ProviderAdapterRegistry {
        &self.registry
    }

    pub fn active_mount_count(&self) -> usize {
        self.mounts.len()
    }

    pub fn mount(
        &mut self,
        scope: ConnectorScope,
        secret_reference: SecretReference,
        at: DateTime<Utc>,
    ) -> Result<AuthenticatedProbeHandle, AuthenticatedProbeError> {
        if secret_reference.scope() != &scope {
            return Err(AuthenticatedProbeError::SecretScopeMismatch);
        }
        if secret_reference.is_revoked_at(at) {
            return Err(AuthenticatedProbeError::SecretReferenceRevoked);
        }
        self.validate_probe_registration(&scope)?;

        let lease_revision = self.next_mount_revision;
        self.next_mount_revision = self.next_mount_revision.saturating_add(1);
        let lease = ConnectorAuth::issue_credential_lease(
            &secret_reference,
            self.provider.identity().clone(),
            format!("credential-lease-auth-probe-{lease_revision}"),
            lease_revision,
            at,
            at + Duration::seconds(MAX_CREDENTIAL_LEASE_TTL_SECONDS),
        )
        .map_err(|error| map_connector_error(&error))?;
        let session = ConnectorAuth::begin_auth_session(
            &secret_reference,
            &lease,
            format!("auth-session-auth-probe-{lease_revision}"),
            lease_revision,
            at,
            at + Duration::seconds(MAX_AUTH_SESSION_TTL_SECONDS),
        )
        .map_err(|error| map_connector_error(&error))?;

        let handle = new_handle(&self.mounts)?;
        let mount_digest = handle.digest();
        self.mounts.insert(
            handle.0.clone(),
            MountedProbe {
                scope,
                secret_reference,
                credential_lease: lease,
                auth_session: session,
                provider_identity: self.provider.identity().clone(),
                mount_digest,
                mounted_at: at,
                next_probe_revision: 1,
            },
        );
        Ok(handle)
    }

    pub fn probe(
        &mut self,
        handle: &AuthenticatedProbeHandle,
        at: DateTime<Utc>,
    ) -> Result<AuthenticatedProbeResult, AuthenticatedProbeError> {
        let mount_state = {
            let mount = self
                .mounts
                .get(&handle.0)
                .ok_or(AuthenticatedProbeError::HandleNotMounted)?;
            (
                at < mount.mounted_at || at >= mount.auth_session.expires_at(),
                mount.secret_reference.is_revoked_at(at),
            )
        };
        if mount_state.0 {
            self.reclaim_mount(handle, at);
            return Err(AuthenticatedProbeError::MountExpired);
        }
        if mount_state.1 {
            self.reclaim_mount(handle, at);
            return Err(AuthenticatedProbeError::SecretReferenceRevoked);
        }
        let (
            scope,
            secret_reference,
            credential_lease,
            auth_session,
            provider_identity,
            mount_digest,
            probe_revision,
        ) = {
            let mount = self
                .mounts
                .get_mut(&handle.0)
                .ok_or(AuthenticatedProbeError::HandleNotMounted)?;
            let probe_revision = mount.next_probe_revision;
            mount.next_probe_revision = mount.next_probe_revision.saturating_add(1);
            (
                mount.scope.clone(),
                mount.secret_reference.clone(),
                mount.credential_lease.clone(),
                mount.auth_session.clone(),
                mount.provider_identity.clone(),
                mount.mount_digest.clone(),
                probe_revision,
            )
        };

        if let Err(error) = self.validate_probe_registration(&scope) {
            self.reclaim_mount(handle, at);
            return Err(error);
        }
        let observation = match self.provider.probe(AuthenticatedProbeRequest {
            scope: &scope,
            secret_reference: &secret_reference,
            credential_lease: &credential_lease,
            auth_session: &auth_session,
            resolver: &mut self.resolver,
            at,
            probe_revision,
        }) {
            Ok(observation) => observation,
            Err(error) => {
                self.reclaim_mount(handle, at);
                return Err(error);
            }
        };
        if let Err(error) = self.validate_observation(&scope, &provider_identity, &observation, at)
        {
            self.reclaim_mount(handle, at);
            return Err(error);
        }
        AuthenticatedProbeResult::from_observation(mount_digest, observation)
    }

    pub fn unmount(
        &mut self,
        handle: &AuthenticatedProbeHandle,
        at: DateTime<Utc>,
    ) -> Result<(), AuthenticatedProbeError> {
        let mount = self
            .mounts
            .remove(&handle.0)
            .ok_or(AuthenticatedProbeError::HandleNotMounted)?;
        self.provider.unmount(lifecycle_request(&mount, at));
        Ok(())
    }

    pub fn revoke(
        &mut self,
        handle: &AuthenticatedProbeHandle,
        at: DateTime<Utc>,
    ) -> Result<(), AuthenticatedProbeError> {
        let mount = self
            .mounts
            .remove(&handle.0)
            .ok_or(AuthenticatedProbeError::HandleNotMounted)?;
        let lifecycle = lifecycle_request(&mount, at);
        let provider_result = self.provider.revoke(lifecycle);
        let resolver_result = self.resolver.revoke_reference(&mount.secret_reference, at);
        if provider_result.is_err() {
            return Err(AuthenticatedProbeError::ProviderRevokeFailed);
        }
        if resolver_result.is_err() {
            return Err(AuthenticatedProbeError::SecretRevokeFailed);
        }
        Ok(())
    }

    fn reclaim_mount(&mut self, handle: &AuthenticatedProbeHandle, at: DateTime<Utc>) {
        if let Some(mount) = self.mounts.remove(&handle.0) {
            self.provider.unmount(lifecycle_request(&mount, at));
        }
    }

    fn validate_probe_registration(
        &self,
        scope: &ConnectorScope,
    ) -> Result<(), AuthenticatedProbeError> {
        self.registry
            .validate()
            .map_err(|_| AuthenticatedProbeError::InvalidRegistry)?;
        let key = ProviderCapabilityKey::new(scope.provider_id(), CONNECTION_PROBE_CAPABILITY)
            .map_err(|_| AuthenticatedProbeError::InvalidScope)?;
        let registration = self
            .registry
            .registrations()
            .iter()
            .find(|registration| registration.key() == &key)
            .ok_or(AuthenticatedProbeError::ProbeCapabilityNotRegistered)?;
        if registration.adapter() != self.provider.identity() {
            return Err(AuthenticatedProbeError::AdapterIdentityMismatch);
        }
        if !registration.evidence_support().iter().any(|support| {
            support.operation() == ProviderAdapterOperation::Probe
                && support.evidence_class() == ProviderEvidenceClass::ProbeObservation
                && support.provenance_class() == ProviderProvenanceClass::ProductionProvider
        }) {
            return Err(AuthenticatedProbeError::ProbeCapabilityNotRegistered);
        }
        Ok(())
    }

    fn validate_observation(
        &self,
        scope: &ConnectorScope,
        provider_identity: &ProviderAdapterIdentity,
        observation: &AuthenticatedProbeObservation,
        at: DateTime<Utc>,
    ) -> Result<(), AuthenticatedProbeError> {
        observation.validate_shape()?;
        if observation.scope() != scope {
            return Err(AuthenticatedProbeError::ScopeDrift);
        }
        if observation.provider_identity() != provider_identity {
            return Err(AuthenticatedProbeError::ProviderIdentityDrift);
        }
        match observation.status() {
            ProbeStatus::Reachable => {}
            ProbeStatus::Unreachable => return Err(AuthenticatedProbeError::ProbeDisconnected),
            ProbeStatus::Rejected => return Err(AuthenticatedProbeError::ProbeRejected),
        }
        if observation.provenance() != ProviderProvenanceClass::ProductionProvider {
            return Err(AuthenticatedProbeError::FixtureEvidence);
        }
        if at < observation.observed_at() || at >= observation.freshness().valid_until() {
            return Err(AuthenticatedProbeError::ProbeExpired);
        }
        if observation.quota().used() >= observation.quota().limit() {
            return Err(AuthenticatedProbeError::QuotaExhausted);
        }
        if observation.cost().used_minor() >= observation.cost().limit_minor() {
            return Err(AuthenticatedProbeError::CostExhausted);
        }
        for capability in observation.capabilities() {
            let registration = self
                .registry
                .registrations()
                .iter()
                .find(|registration| registration.key() == capability)
                .ok_or(AuthenticatedProbeError::CapabilityNotRegistered)?;
            if registration.adapter() != provider_identity {
                return Err(AuthenticatedProbeError::AdapterIdentityMismatch);
            }
            if !registration.evidence_support().iter().any(|support| {
                support.provenance_class() == ProviderProvenanceClass::ProductionProvider
            }) {
                return Err(AuthenticatedProbeError::FixtureEvidence);
            }
        }
        Ok(())
    }
}

impl<P, R> Drop for AuthenticatedProbeService<P, R>
where
    P: AuthenticatedProbeProvider,
    R: SecretReferenceResolver,
{
    fn drop(&mut self) {
        let mounts = std::mem::take(&mut self.mounts);
        for mount in mounts.into_values() {
            self.provider
                .unmount(lifecycle_request(&mount, mount.mounted_at));
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AuthenticatedProbeError {
    #[error("connector scope is invalid")]
    InvalidScope,
    #[error("Mission scope is invalid")]
    InvalidMissionScope,
    #[error("connector authentication chain is invalid")]
    AuthenticationChainInvalid,
    #[error("provider adapter registry is invalid")]
    InvalidRegistry,
    #[error("provider adapter registry is empty")]
    EmptyRegistry,
    #[error("connection probe capability is not registered")]
    ProbeCapabilityNotRegistered,
    #[error("provider adapter identity does not match the registry")]
    AdapterIdentityMismatch,
    #[error("provider identity changed during probe")]
    ProviderIdentityDrift,
    #[error("secret reference scope does not match the requested scope")]
    SecretScopeMismatch,
    #[error("secret reference is revoked")]
    SecretReferenceRevoked,
    #[error("secret reference could not be resolved")]
    SecretUnavailable,
    #[error("secret reference revoke failed")]
    SecretRevokeFailed,
    #[error("probe handle is not mounted")]
    HandleNotMounted,
    #[error("probe mount has expired")]
    MountExpired,
    #[error("probe observation is invalid")]
    InvalidObservation,
    #[error("provider probe is disconnected")]
    ProbeDisconnected,
    #[error("provider rejected the authenticated probe")]
    ProbeRejected,
    #[error("fixture or non-production probe evidence is not admissible")]
    FixtureEvidence,
    #[error("provider probe scope drifted")]
    ScopeDrift,
    #[error("provider capability is not registered")]
    CapabilityNotRegistered,
    #[error("provider probe has expired")]
    ProbeExpired,
    #[error("provider probe quota is exhausted")]
    QuotaExhausted,
    #[error("provider probe cost budget is exhausted")]
    CostExhausted,
    #[error("provider revoke failed")]
    ProviderRevokeFailed,
    #[error("Mission scope does not match the authenticated probe")]
    MissionScopeMismatch,
    #[error("secure handle generation failed")]
    EntropyUnavailable,
}

fn lifecycle_request(mount: &MountedProbe, at: DateTime<Utc>) -> ProbeLifecycleRequest {
    ProbeLifecycleRequest {
        scope: mount.scope.clone(),
        secret_reference: mount.secret_reference.clone(),
        credential_lease: mount.credential_lease.clone(),
        auth_session: mount.auth_session.clone(),
        mount_digest: mount.mount_digest.clone(),
        at,
    }
}

fn new_handle(
    mounts: &BTreeMap<String, MountedProbe>,
) -> Result<AuthenticatedProbeHandle, AuthenticatedProbeError> {
    let random = SystemRandom::new();
    for _ in 0..4 {
        let mut bytes = [0_u8; HANDLE_BYTES];
        random
            .fill(&mut bytes)
            .map_err(|_| AuthenticatedProbeError::EntropyUnavailable)?;
        let candidate = super::hex_encode(&bytes);
        if !mounts.contains_key(&candidate) {
            return Ok(AuthenticatedProbeHandle(candidate));
        }
    }
    Err(AuthenticatedProbeError::EntropyUnavailable)
}

fn map_connector_error(error: &ConnectorError) -> AuthenticatedProbeError {
    match error {
        ConnectorError::InvalidScope => AuthenticatedProbeError::InvalidScope,
        ConnectorError::InvalidSecretReference => AuthenticatedProbeError::SecretUnavailable,
        _ => AuthenticatedProbeError::AuthenticationChainInvalid,
    }
}

fn capability_digest_material(capabilities: &BTreeSet<ProviderCapabilityKey>) -> String {
    capabilities
        .iter()
        .map(|capability| {
            format!(
                "{}:{}",
                capability.provider_id(),
                capability.capability_id()
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn digest_values<'a>(values: impl IntoIterator<Item = &'a str>) -> String {
    super::canonical_digest(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    const PROVIDER_ID: &str = "fixture-provider";
    const ADAPTER_ID: &str = "fixture.connector";
    const REGISTRY_VERSION: &str = "authenticated-probe-test/v1";
    const NOW_SECONDS: i64 = 1_700_000_000;

    #[derive(Clone, Debug)]
    struct TestResolver {
        secret: Vec<u8>,
        revoked: Rc<Cell<bool>>,
        resolved_reference: Rc<RefCell<Vec<String>>>,
        revoked_reference: Rc<RefCell<Vec<String>>>,
    }

    impl TestResolver {
        fn new(secret: &[u8]) -> Self {
            Self {
                secret: secret.to_vec(),
                revoked: Rc::new(Cell::new(false)),
                resolved_reference: Rc::new(RefCell::new(Vec::new())),
                revoked_reference: Rc::new(RefCell::new(Vec::new())),
            }
        }
    }

    impl SecretReferenceResolver for TestResolver {
        fn resolve(
            &mut self,
            reference: &SecretReference,
            _at: DateTime<Utc>,
        ) -> Result<SecretMaterial, AuthenticatedProbeError> {
            self.resolved_reference
                .borrow_mut()
                .push(reference.reference_id().to_owned());
            if self.revoked.get() {
                return Err(AuthenticatedProbeError::SecretReferenceRevoked);
            }
            SecretMaterial::new(&self.secret)
        }

        fn revoke_reference(
            &mut self,
            reference: &SecretReference,
            _at: DateTime<Utc>,
        ) -> Result<(), AuthenticatedProbeError> {
            self.revoked.set(true);
            self.revoked_reference
                .borrow_mut()
                .push(reference.reference_id().to_owned());
            Ok(())
        }
    }

    #[derive(Debug)]
    struct TestProvider {
        identity: ProviderAdapterIdentity,
        scope_drift: bool,
        provenance: ProviderProvenanceClass,
        status: ProbeStatus,
        write_effects: u64,
        probes: u64,
        unmounts: u64,
        revokes: u64,
        last_reference: Option<String>,
        last_secret_digest: Option<String>,
    }

    impl TestProvider {
        fn new() -> Self {
            Self {
                identity: ProviderAdapterIdentity::new(ADAPTER_ID, 1).expect("identity"),
                scope_drift: false,
                provenance: ProviderProvenanceClass::ProductionProvider,
                status: ProbeStatus::Reachable,
                write_effects: 0,
                probes: 0,
                unmounts: 0,
                revokes: 0,
                last_reference: None,
                last_secret_digest: None,
            }
        }
    }

    impl AuthenticatedProbeProvider for TestProvider {
        fn identity(&self) -> &ProviderAdapterIdentity {
            &self.identity
        }

        fn probe(
            &mut self,
            mut request: AuthenticatedProbeRequest<'_>,
        ) -> Result<AuthenticatedProbeObservation, AuthenticatedProbeError> {
            self.probes += 1;
            self.last_reference = Some(request.secret_reference().reference_id().to_owned());
            let credentials = request.resolve_credentials()?;
            self.last_secret_digest = Some(super::digest_values([std::str::from_utf8(
                credentials.as_bytes(),
            )
            .unwrap_or("invalid")]));
            let scope = if self.scope_drift {
                ConnectorScope::new(
                    "tenant-other",
                    request.scope().project_id(),
                    request.scope().provider_id(),
                    request.scope().account_id(),
                    request.scope().scopes().iter().cloned(),
                )
                .map_err(|error| map_connector_error(&error))?
            } else {
                request.scope().clone()
            };
            let capabilities = [ProviderCapabilityKey::new(PROVIDER_ID, "research.discover")
                .map_err(|_| AuthenticatedProbeError::InvalidObservation)?];
            let observed_at = request.at();
            AuthenticatedProbeObservation::new(
                scope,
                capabilities,
                QuotaState::new(10),
                FreshnessWindow::new(observed_at, observed_at + Duration::seconds(30), 1)
                    .map_err(|error| map_connector_error(&error))?,
                CostState::new(100).map_err(|error| map_connector_error(&error))?,
                self.identity.clone(),
                super::digest_values(["provider-account-digest"]),
                self.status,
                self.provenance,
                super::digest_values(["authenticated-probe-evidence"]),
                observed_at,
            )
        }

        fn unmount(&mut self, _request: ProbeLifecycleRequest) {
            self.unmounts += 1;
        }

        fn revoke(
            &mut self,
            _request: ProbeLifecycleRequest,
        ) -> Result<(), AuthenticatedProbeError> {
            self.revokes += 1;
            Ok(())
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::UNIX_EPOCH + Duration::seconds(NOW_SECONDS)
    }

    fn scope() -> ConnectorScope {
        ConnectorScope::new(
            "tenant-test",
            "project-test",
            PROVIDER_ID,
            "account-test",
            ["research.discover".to_owned()],
        )
        .expect("scope")
    }

    fn secret() -> SecretReference {
        SecretReference::new("secret-ref-authenticated-probe", scope(), 1).expect("secret")
    }

    fn registry() -> ProviderAdapterRegistry {
        let identity = ProviderAdapterIdentity::new(ADAPTER_ID, 1).expect("identity");
        let probe_key = ProviderCapabilityKey::new(PROVIDER_ID, CONNECTION_PROBE_CAPABILITY)
            .expect("probe key");
        let capability_key =
            ProviderCapabilityKey::new(PROVIDER_ID, "research.discover").expect("capability key");
        let probe_support = hartevo_effect_broker::ProviderEvidenceSupport::new(
            ProviderAdapterOperation::Probe,
            ProviderEvidenceClass::ProbeObservation,
            ProviderProvenanceClass::ProductionProvider,
        )
        .expect("probe support");
        let read_support = hartevo_effect_broker::ProviderEvidenceSupport::new(
            ProviderAdapterOperation::Read,
            ProviderEvidenceClass::ReadObservation,
            ProviderProvenanceClass::ProductionProvider,
        )
        .expect("read support");
        ProviderAdapterRegistry::new(
            REGISTRY_VERSION,
            [
                hartevo_effect_broker::ProviderCapabilitySupport::new(
                    probe_key,
                    identity.clone(),
                    [probe_support],
                )
                .expect("probe registration"),
                hartevo_effect_broker::ProviderCapabilitySupport::new(
                    capability_key,
                    identity,
                    [read_support],
                )
                .expect("capability registration"),
            ],
        )
        .expect("registry")
    }

    fn service() -> AuthenticatedProbeService<TestProvider, TestResolver> {
        AuthenticatedProbeService::new(
            TestProvider::new(),
            TestResolver::new(b"opaque-provider-credential"),
            registry(),
        )
        .expect("service")
    }

    fn mission() -> MissionScope {
        MissionScope::new("tenant-test", "project-test", "mission-test", 7).expect("mission")
    }

    #[test]
    fn authenticated_probe_returns_scoped_result_and_resolves_reference_without_write_effect() {
        let at = now();
        let mut service = service();
        let handle = service.mount(scope(), secret(), at).expect("mount");
        let result = service
            .probe(&handle, at + Duration::seconds(1))
            .expect("probe");

        assert_eq!(result.scope().tenant_id(), "tenant-test");
        assert_eq!(result.scope().project_id(), "project-test");
        assert_eq!(result.scope().account_id(), "account-test");
        assert!(
            result
                .capabilities()
                .iter()
                .any(|capability| { capability.capability_id() == "research.discover" })
        );
        assert_eq!(result.quota().limit(), 10);
        assert_eq!(result.cost().limit_minor(), 100);
        assert_eq!(result.freshness().source_revision(), 1);
        assert_eq!(result.provider_identity().adapter_id(), ADAPTER_ID);
        assert_eq!(result.provider_digest().len(), 64);
        assert_eq!(result.observed_at(), at + Duration::seconds(1));
        assert_eq!(service.provider().probes, 1);
        assert_eq!(service.provider().write_effects, 0);
        assert_eq!(
            service.provider().last_reference.as_deref(),
            Some("secret-ref-authenticated-probe")
        );
        assert!(service.provider().last_secret_digest.is_some());
        let material = SecretMaterial::new(b"opaque-provider-credential").expect("material");
        assert!(!format!("{material:?}").contains("opaque-provider-credential"));
        assert!(!format!("{handle:?}").contains("secret-ref-authenticated-probe"));
    }

    #[test]
    fn consumer_projects_mission_availability_instead_of_catalog_metadata() {
        let at = now();
        let mut service = service();
        let handle = service.mount(scope(), secret(), at).expect("mount");
        let result = service
            .probe(&handle, at + Duration::seconds(1))
            .expect("probe");
        let capability = result
            .capabilities()
            .iter()
            .next()
            .expect("capability")
            .clone();
        let mut consumer = MissionCapabilityConsumer::new(mission());
        let availability = consumer
            .accept(&result, at + Duration::seconds(2))
            .expect("accept");

        assert_eq!(consumer.availability_count(), 1);
        assert!(consumer.supports(&capability, at + Duration::seconds(2)));
        assert_eq!(availability.mission().mission_id(), "mission-test");
        assert_eq!(availability.source_result_digest(), result.result_digest());
        let serialized = serde_json::to_string(&availability).expect("safe availability");
        assert!(!serialized.contains("catalog"));
        assert!(!serialized.contains("opaque-provider-credential"));

        let expired = at + Duration::seconds(32);
        assert!(!consumer.supports(&capability, expired));
        assert_eq!(
            consumer.accept(&result, expired),
            Err(AuthenticatedProbeError::ProbeExpired)
        );
        assert_eq!(consumer.reclaim_expired(expired), 1);
        assert_eq!(consumer.availability_count(), 0);
    }

    #[test]
    fn disconnected_expired_revoked_scope_drift_and_fixture_fail_closed() {
        let at = now();
        let empty =
            ProviderAdapterRegistry::new("empty-probe-test/v1", []).expect("empty registry");
        assert_eq!(
            AuthenticatedProbeService::new(
                TestProvider::new(),
                TestResolver::new(b"secret"),
                empty
            )
            .expect_err("empty registrations must fail closed"),
            AuthenticatedProbeError::EmptyRegistry
        );

        let mut expired_service = service();
        let expired_handle = expired_service.mount(scope(), secret(), at).expect("mount");
        assert_eq!(
            expired_service.probe(&expired_handle, at + Duration::seconds(601)),
            Err(AuthenticatedProbeError::MountExpired)
        );
        assert_eq!(expired_service.active_mount_count(), 0);

        let mut revoked_service = service();
        let revoked_handle = revoked_service.mount(scope(), secret(), at).expect("mount");
        revoked_service.resolver.revoked.set(true);
        assert_eq!(
            revoked_service.probe(&revoked_handle, at + Duration::seconds(1)),
            Err(AuthenticatedProbeError::SecretReferenceRevoked)
        );
        assert_eq!(revoked_service.active_mount_count(), 0);

        let mut disconnected_service = service();
        disconnected_service.provider_mut().status = ProbeStatus::Unreachable;
        let disconnected_handle = disconnected_service
            .mount(scope(), secret(), at)
            .expect("mount");
        assert_eq!(
            disconnected_service.probe(&disconnected_handle, at + Duration::seconds(1)),
            Err(AuthenticatedProbeError::ProbeDisconnected)
        );
        assert_eq!(disconnected_service.active_mount_count(), 0);

        let mut drift_service = service();
        drift_service.provider_mut().scope_drift = true;
        let drift_handle = drift_service.mount(scope(), secret(), at).expect("mount");
        assert_eq!(
            drift_service.probe(&drift_handle, at + Duration::seconds(1)),
            Err(AuthenticatedProbeError::ScopeDrift)
        );
        assert_eq!(drift_service.active_mount_count(), 0);

        let mut fixture_service = service();
        fixture_service.provider_mut().provenance = ProviderProvenanceClass::Fixture;
        let fixture_handle = fixture_service.mount(scope(), secret(), at).expect("mount");
        assert_eq!(
            fixture_service.probe(&fixture_handle, at + Duration::seconds(1)),
            Err(AuthenticatedProbeError::FixtureEvidence)
        );
        assert_eq!(fixture_service.active_mount_count(), 0);
    }

    #[test]
    fn unmount_and_revoke_reclaim_provider_and_consumer_state() {
        let at = now();
        let mut service = service();
        let handle = service.mount(scope(), secret(), at).expect("mount");
        let result = service
            .probe(&handle, at + Duration::seconds(1))
            .expect("probe");
        let mount_digest = result.mount_digest().to_owned();
        let mut consumer = MissionCapabilityConsumer::new(mission());
        consumer
            .accept(&result, at + Duration::seconds(2))
            .expect("accept");
        assert_eq!(consumer.availability_count(), 1);

        service
            .unmount(&handle, at + Duration::seconds(3))
            .expect("unmount");
        assert_eq!(service.active_mount_count(), 0);
        assert_eq!(service.provider().unmounts, 1);
        assert_eq!(consumer.unmount(&mount_digest), 1);
        assert_eq!(consumer.availability_count(), 0);
        assert_eq!(
            service.probe(&handle, at + Duration::seconds(4)),
            Err(AuthenticatedProbeError::HandleNotMounted)
        );

        let revoke_handle = service
            .mount(scope(), secret(), at + Duration::seconds(5))
            .expect("remount");
        let revoke_result = service
            .probe(&revoke_handle, at + Duration::seconds(6))
            .expect("revoke probe");
        consumer
            .accept(&revoke_result, at + Duration::seconds(7))
            .expect("revoke availability");
        service
            .revoke(&revoke_handle, at + Duration::seconds(8))
            .expect("revoke");
        assert_eq!(service.active_mount_count(), 0);
        assert_eq!(service.provider().revokes, 1);
        assert_eq!(service.provider().unmounts, 1);
        assert_eq!(consumer.revoke(&scope()), 1);
        assert_eq!(consumer.availability_count(), 0);
        assert_eq!(
            service.probe(&revoke_handle, at + Duration::seconds(9)),
            Err(AuthenticatedProbeError::HandleNotMounted)
        );
    }

    #[test]
    fn reopened_service_rejects_a_stale_opaque_handle() {
        let at = now();
        let old_handle = {
            let mut service = service();
            service.mount(scope(), secret(), at).expect("mount")
        };
        let mut reopened = service();
        assert_eq!(
            reopened.probe(&old_handle, at + Duration::seconds(1)),
            Err(AuthenticatedProbeError::HandleNotMounted)
        );
    }

    #[test]
    fn wrong_mission_scope_is_rejected_before_availability_projection() {
        let at = now();
        let mut service = service();
        let handle = service.mount(scope(), secret(), at).expect("mount");
        let result = service
            .probe(&handle, at + Duration::seconds(1))
            .expect("probe");
        let wrong_mission = MissionScope::new("tenant-other", "project-test", "mission-test", 7)
            .expect("wrong mission");
        let mut consumer = MissionCapabilityConsumer::new(wrong_mission);
        assert_eq!(
            consumer.accept(&result, at + Duration::seconds(2)),
            Err(AuthenticatedProbeError::MissionScopeMismatch)
        );
        assert_eq!(consumer.availability_count(), 0);
    }
}
