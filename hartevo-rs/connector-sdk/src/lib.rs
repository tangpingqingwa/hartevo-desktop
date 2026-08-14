//! Hartevo-owned Connector SDK and Worker boundary.
//!
//! The SDK is deliberately narrower than the Domain Kernel.  A connector can
//! authenticate, probe, read, prepare an external effect, execute through an
//! Effect Broker supplied dispatch context, reconcile, verify and consume a
//! signed webhook.  None of the types in this crate can mutate a Mission.
//! Provider metadata is always expressed with the existing
//! `hartevo-effect-broker` provider contract types; this crate does not create
//! a second authority model.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use hartevo_effect_broker::{ConnectedAuthority, ConnectedAuthorization};
pub use hartevo_effect_broker::{
    ProviderAdapterIdentity, ProviderAdapterOperation, ProviderAdapterRegistry,
    ProviderCapabilityKey, ProviderCapabilitySupport, ProviderContractError, ProviderEvidenceClass,
    ProviderProvenanceClass,
};
use ring::hmac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

pub mod authenticated_probe;

pub const CONNECTOR_SDK_SCHEMA_VERSION: &str = "hartevo-connector-sdk/v1";
pub const MAX_CREDENTIAL_LEASE_TTL_SECONDS: i64 = 900;
pub const MAX_AUTH_SESSION_TTL_SECONDS: i64 = 600;
pub const MAX_PROBE_TTL_SECONDS: i64 = 120;
pub const MAX_WORKER_LEASE_TTL_SECONDS: i64 = 900;
pub const DEFAULT_PAGE_SIZE: u32 = 100;
pub const MAX_PAGE_SIZE: u32 = 1_000;

/// A tenant/project/provider/account scope.  The scope contains identifiers,
/// never a secret or a provider payload.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectorScope {
    tenant_id: String,
    project_id: String,
    provider_id: String,
    account_id: String,
    scopes: BTreeSet<String>,
}

impl ConnectorScope {
    pub fn new(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        provider_id: impl Into<String>,
        account_id: impl Into<String>,
        scopes: impl IntoIterator<Item = String>,
    ) -> Result<Self, ConnectorError> {
        let scope = Self {
            tenant_id: tenant_id.into(),
            project_id: project_id.into(),
            provider_id: provider_id.into(),
            account_id: account_id.into(),
            scopes: scopes.into_iter().collect(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn scopes(&self) -> &BTreeSet<String> {
        &self.scopes
    }

    pub fn digest(&self) -> String {
        canonical_digest([
            self.tenant_id.as_str(),
            self.project_id.as_str(),
            self.provider_id.as_str(),
            self.account_id.as_str(),
            &self.scopes.iter().cloned().collect::<Vec<_>>().join(","),
        ])
    }

    fn validate(&self) -> Result<(), ConnectorError> {
        if !valid_identifier(&self.tenant_id)
            || !valid_identifier(&self.project_id)
            || !valid_identifier(&self.provider_id)
            || !valid_identifier(&self.account_id)
            || self.scopes.is_empty()
            || self.scopes.iter().any(|value| !valid_scope(value))
        {
            return Err(ConnectorError::InvalidScope);
        }
        Ok(())
    }
}

/// An opaque keyring reference.  The SDK never accepts secret bytes and does
/// not implement `Serialize` for this type, so a reference cannot be confused
/// with the credential it names.
pub struct SecretReference {
    reference_id: String,
    scope: ConnectorScope,
    credential_revision: u64,
    revoked_at: Option<DateTime<Utc>>,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_id: self.reference_id.clone(),
            scope: self.scope.clone(),
            credential_revision: self.credential_revision,
            revoked_at: self.revoked_at,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_id == other.reference_id
            && self.scope == other.scope
            && self.credential_revision == other.credential_revision
            && self.revoked_at == other.revoked_at
    }
}

impl Eq for SecretReference {}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("scope_digest", &self.scope.digest())
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked_at.is_some())
            .finish_non_exhaustive()
    }
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: ConnectorScope,
        credential_revision: u64,
    ) -> Result<Self, ConnectorError> {
        let reference = Self {
            reference_id: reference_id.into(),
            scope,
            credential_revision,
            revoked_at: None,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn reference_id(&self) -> &str {
        &self.reference_id
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub fn revoke(&mut self, revoked_at: DateTime<Utc>) -> Result<(), ConnectorError> {
        if let Some(existing) = self.revoked_at {
            return if existing == revoked_at {
                Ok(())
            } else {
                Err(ConnectorError::AlreadyRevoked)
            };
        }
        self.revoked_at = Some(revoked_at);
        Ok(())
    }

    fn validate(&self) -> Result<(), ConnectorError> {
        if !valid_prefixed_identifier(&self.reference_id, "secret-ref-")
            || self.credential_revision == 0
        {
            return Err(ConnectorError::InvalidSecretReference);
        }
        self.scope.validate()
    }

    fn is_revoked_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_some_and(|revoked_at| revoked_at <= now)
    }
}

/// A credential lease contains only a keyring reference identity and scope.
/// It has no conversion into provider credentials.
#[derive(Eq, PartialEq)]
pub struct CredentialLease {
    lease_id: String,
    secret_reference_id: String,
    scope: ConnectorScope,
    adapter: ProviderAdapterIdentity,
    credential_revision: u64,
    lease_revision: u64,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl Clone for CredentialLease {
    fn clone(&self) -> Self {
        Self {
            lease_id: self.lease_id.clone(),
            secret_reference_id: self.secret_reference_id.clone(),
            scope: self.scope.clone(),
            adapter: self.adapter.clone(),
            credential_revision: self.credential_revision,
            lease_revision: self.lease_revision,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            revoked_at: self.revoked_at,
        }
    }
}

impl fmt::Debug for CredentialLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialLease")
            .field("scope_digest", &self.scope.digest())
            .field("adapter", &self.adapter)
            .field("credential_revision", &self.credential_revision)
            .field("lease_revision", &self.lease_revision)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("revoked", &self.revoked_at.is_some())
            .finish_non_exhaustive()
    }
}

impl CredentialLease {
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn adapter(&self) -> &ProviderAdapterIdentity {
        &self.adapter
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub const fn lease_revision(&self) -> u64 {
        self.lease_revision
    }

    pub const fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn revoke(&mut self, revoked_at: DateTime<Utc>) -> Result<(), ConnectorError> {
        if revoked_at < self.issued_at {
            return Err(ConnectorError::InvalidRevocation);
        }
        if let Some(existing) = self.revoked_at {
            return if existing == revoked_at {
                Ok(())
            } else {
                Err(ConnectorError::AlreadyRevoked)
            };
        }
        self.revoked_at = Some(revoked_at);
        Ok(())
    }

    fn validate(&self, secret: &SecretReference, now: DateTime<Utc>) -> Result<(), ConnectorError> {
        if secret.is_revoked_at(now)
            || self.scope != *secret.scope()
            || self.secret_reference_id != secret.reference_id()
            || self.credential_revision != secret.credential_revision()
            || self.lease_revision == 0
            || self.adapter.adapter_version() == 0
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at
                > Duration::seconds(MAX_CREDENTIAL_LEASE_TTL_SECONDS)
            || self.is_revoked_at(now)
            || now < self.issued_at
            || now >= self.expires_at
        {
            return Err(ConnectorError::InvalidCredentialLease);
        }
        Ok(())
    }

    fn is_revoked_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_some_and(|revoked_at| revoked_at <= now)
    }
}

/// Authentication session metadata.  The actual OAuth/API secret remains in
/// the OS/project secret store and never enters this struct.
#[derive(Eq, PartialEq)]
pub struct AuthSession {
    session_id: String,
    scope: ConnectorScope,
    adapter: ProviderAdapterIdentity,
    credential_revision: u64,
    lease_revision: u64,
    auth_revision: u64,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl Clone for AuthSession {
    fn clone(&self) -> Self {
        Self {
            session_id: self.session_id.clone(),
            scope: self.scope.clone(),
            adapter: self.adapter.clone(),
            credential_revision: self.credential_revision,
            lease_revision: self.lease_revision,
            auth_revision: self.auth_revision,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            revoked_at: self.revoked_at,
        }
    }
}

impl fmt::Debug for AuthSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthSession")
            .field("scope_digest", &self.scope.digest())
            .field("adapter", &self.adapter)
            .field("credential_revision", &self.credential_revision)
            .field("lease_revision", &self.lease_revision)
            .field("auth_revision", &self.auth_revision)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("revoked", &self.revoked_at.is_some())
            .finish_non_exhaustive()
    }
}

impl AuthSession {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn adapter(&self) -> &ProviderAdapterIdentity {
        &self.adapter
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

    pub const fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn revoke(&mut self, revoked_at: DateTime<Utc>) -> Result<(), ConnectorError> {
        if revoked_at < self.issued_at {
            return Err(ConnectorError::InvalidRevocation);
        }
        if let Some(existing) = self.revoked_at {
            return if existing == revoked_at {
                Ok(())
            } else {
                Err(ConnectorError::AlreadyRevoked)
            };
        }
        self.revoked_at = Some(revoked_at);
        Ok(())
    }

    fn validate(
        &self,
        secret: &SecretReference,
        lease: &CredentialLease,
        now: DateTime<Utc>,
    ) -> Result<(), ConnectorError> {
        lease.validate(secret, now)?;
        if self.scope != *lease.scope()
            || self.adapter != *lease.adapter()
            || self.credential_revision != lease.credential_revision()
            || self.lease_revision != lease.lease_revision()
            || self.auth_revision == 0
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > Duration::seconds(MAX_AUTH_SESSION_TTL_SECONDS)
            || self.revoked_at.is_some_and(|revoked_at| revoked_at <= now)
            || now < self.issued_at
            || now >= self.expires_at
        {
            return Err(ConnectorError::InvalidAuthSession);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Reachable,
    Unreachable,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeObservation {
    pub status: ProbeStatus,
    pub provenance_class: ProviderProvenanceClass,
    pub observed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub evidence_digest: String,
}

impl ProbeObservation {
    pub fn new(
        status: ProbeStatus,
        provenance_class: ProviderProvenanceClass,
        observed_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        evidence_digest: impl Into<String>,
    ) -> Result<Self, ConnectorError> {
        let observation = Self {
            status,
            provenance_class,
            observed_at,
            expires_at,
            evidence_digest: evidence_digest.into(),
        };
        observation.validate()?;
        Ok(observation)
    }

    fn validate(&self) -> Result<(), ConnectorError> {
        if self.expires_at <= self.observed_at
            || self.expires_at - self.observed_at > Duration::seconds(MAX_PROBE_TTL_SECONDS)
            || !is_sha256(&self.evidence_digest)
        {
            return Err(ConnectorError::InvalidProbe);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeResult {
    result_id: String,
    scope: ConnectorScope,
    adapter: ProviderAdapterIdentity,
    credential_revision: u64,
    lease_revision: u64,
    auth_revision: u64,
    probe_revision: u64,
    status: ProbeStatus,
    provenance_class: ProviderProvenanceClass,
    observed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    evidence_digest: String,
    binding_digest: String,
}

impl ProbeResult {
    pub fn result_id(&self) -> &str {
        &self.result_id
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn adapter(&self) -> &ProviderAdapterIdentity {
        &self.adapter
    }

    pub const fn probe_revision(&self) -> u64 {
        self.probe_revision
    }

    pub const fn status(&self) -> ProbeStatus {
        self.status
    }

    pub const fn provenance_class(&self) -> ProviderProvenanceClass {
        self.provenance_class
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

    pub fn binding_digest(&self) -> &str {
        &self.binding_digest
    }

    #[allow(clippy::too_many_arguments)]
    fn from_observation(
        scope: ConnectorScope,
        adapter: ProviderAdapterIdentity,
        secret: &SecretReference,
        lease: &CredentialLease,
        session: &AuthSession,
        probe_revision: u64,
        result_id: impl Into<String>,
        observation: ProbeObservation,
    ) -> Result<Self, ConnectorError> {
        observation.validate()?;
        session.validate(secret, lease, observation.observed_at)?;
        if scope != *session.scope() || adapter != *session.adapter() || probe_revision == 0 {
            return Err(ConnectorError::ScopeMismatch);
        }
        let mut result = Self {
            result_id: result_id.into(),
            scope,
            adapter,
            credential_revision: session.credential_revision(),
            lease_revision: session.lease_revision(),
            auth_revision: session.auth_revision(),
            probe_revision,
            status: observation.status,
            provenance_class: observation.provenance_class,
            observed_at: observation.observed_at,
            expires_at: observation.expires_at,
            evidence_digest: observation.evidence_digest,
            binding_digest: String::new(),
        };
        if !valid_prefixed_identifier(&result.result_id, "probe-result-") {
            return Err(ConnectorError::InvalidProbe);
        }
        result.binding_digest = result.calculate_binding_digest();
        Ok(result)
    }

    fn calculate_binding_digest(&self) -> String {
        canonical_digest([
            self.result_id.as_str(),
            &self.scope.digest(),
            self.adapter.adapter_id(),
            &self.adapter.adapter_version().to_string(),
            &self.credential_revision.to_string(),
            &self.lease_revision.to_string(),
            &self.auth_revision.to_string(),
            &self.probe_revision.to_string(),
            &format!("{:?}", self.status),
            &format!("{:?}", self.provenance_class),
            &self.observed_at.to_rfc3339(),
            &self.expires_at.to_rfc3339(),
            self.evidence_digest.as_str(),
        ])
    }

    fn validate_binding(&self, now: DateTime<Utc>) -> Result<(), ConnectorError> {
        if self.binding_digest != self.calculate_binding_digest()
            || self.status != ProbeStatus::Reachable
            || now < self.observed_at
            || now >= self.expires_at
        {
            return Err(ConnectorError::ProbeNotLive);
        }
        Ok(())
    }
}

/// A dispatch fence derived from a live probe and an exact adapter registry
/// entry.  It is intentionally not a Connected/Effect approval object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveProbeFence {
    scope: ConnectorScope,
    adapter: ProviderAdapterIdentity,
    credential_revision: u64,
    lease_revision: u64,
    auth_revision: u64,
    probe_revision: u64,
    provenance_class: ProviderProvenanceClass,
    evidence_digest: String,
    observed_valid_until: DateTime<Utc>,
    registry_version: String,
}

impl LiveProbeFence {
    /// Bridges the existing A2 connection-state authority into the connector
    /// dispatch fence.  This is the production path; the SDK does not create
    /// a second Connected or business-approval authority.
    pub fn from_connected_authorization(
        connected: &ConnectedAuthorization,
        now: DateTime<Utc>,
    ) -> Result<Self, ConnectorError> {
        if connected.authority() != ConnectedAuthority::ConnectionStateOnly
            || now >= connected.observed_valid_until()
        {
            return Err(ConnectorError::ProbeExpired);
        }
        let auth_scope = connected.scope();
        let scope = ConnectorScope::new(
            auth_scope.tenant_id().as_str(),
            auth_scope.project_id().as_str(),
            auth_scope.provider_id(),
            auth_scope.account_id().as_str(),
            auth_scope.scopes().iter().cloned(),
        )?;
        Ok(Self {
            scope,
            adapter: connected.adapter().clone(),
            credential_revision: connected.credential_revision(),
            lease_revision: connected.lease_revision(),
            auth_revision: connected.auth_revision(),
            probe_revision: connected.probe_revision(),
            provenance_class: connected.provenance_class(),
            evidence_digest: connected.evidence_digest().to_owned(),
            observed_valid_until: connected.observed_valid_until(),
            registry_version: "provider-auth-a2".to_owned(),
        })
    }

    pub fn authorize(
        registry: &ProviderAdapterRegistry,
        probe: &ProbeResult,
        now: DateTime<Utc>,
    ) -> Result<Self, ConnectorError> {
        Self::authorize_with_provenance(
            registry,
            probe,
            now,
            ProviderProvenanceClass::ProductionProvider,
        )
    }

    pub(crate) fn authorize_with_provenance(
        registry: &ProviderAdapterRegistry,
        probe: &ProbeResult,
        now: DateTime<Utc>,
        required_provenance: ProviderProvenanceClass,
    ) -> Result<Self, ConnectorError> {
        registry
            .validate()
            .map_err(|_| ConnectorError::InvalidRegistry)?;
        probe.validate_binding(now)?;
        if probe.provenance_class != required_provenance {
            return Err(ConnectorError::UnsupportedProvenance);
        }
        let key = ProviderCapabilityKey::new(probe.scope.provider_id.clone(), "connection.probe")
            .map_err(|_| ConnectorError::InvalidCapability)?;
        let registration = registry
            .registrations()
            .iter()
            .find(|registration| registration.key() == &key)
            .ok_or(ConnectorError::UnregisteredAdapter)?;
        if registration.adapter() != &probe.adapter
            || !registration.evidence_support().iter().any(|support| {
                support.operation() == ProviderAdapterOperation::Probe
                    && support.evidence_class() == ProviderEvidenceClass::ProbeObservation
                    && support.provenance_class() == required_provenance
            })
        {
            return Err(ConnectorError::AdapterMetadataMismatch);
        }
        Ok(Self {
            scope: probe.scope.clone(),
            adapter: probe.adapter.clone(),
            credential_revision: probe.credential_revision,
            lease_revision: probe.lease_revision,
            auth_revision: probe.auth_revision,
            probe_revision: probe.probe_revision,
            provenance_class: probe.provenance_class,
            evidence_digest: probe.evidence_digest.clone(),
            observed_valid_until: probe.expires_at,
            registry_version: registry.registry_version().to_owned(),
        })
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn adapter(&self) -> &ProviderAdapterIdentity {
        &self.adapter
    }

    pub const fn probe_revision(&self) -> u64 {
        self.probe_revision
    }

    pub const fn observed_valid_until(&self) -> DateTime<Utc> {
        self.observed_valid_until
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub fn registry_version(&self) -> &str {
        &self.registry_version
    }

    fn validate_at(&self, now: DateTime<Utc>) -> Result<(), ConnectorError> {
        if now >= self.observed_valid_until {
            return Err(ConnectorError::ProbeExpired);
        }
        Ok(())
    }
}

/// Constructs the opaque authentication chain used by a connector adapter.
#[derive(Debug)]
pub struct ConnectorAuth;

impl ConnectorAuth {
    pub fn issue_credential_lease(
        secret: &SecretReference,
        adapter: ProviderAdapterIdentity,
        lease_id: impl Into<String>,
        lease_revision: u64,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<CredentialLease, ConnectorError> {
        let lease = CredentialLease {
            lease_id: lease_id.into(),
            secret_reference_id: secret.reference_id.clone(),
            scope: secret.scope.clone(),
            adapter,
            credential_revision: secret.credential_revision,
            lease_revision,
            issued_at,
            expires_at,
            revoked_at: None,
        };
        lease.validate(secret, issued_at)?;
        Ok(lease)
    }

    pub fn begin_auth_session(
        secret: &SecretReference,
        lease: &CredentialLease,
        session_id: impl Into<String>,
        auth_revision: u64,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<AuthSession, ConnectorError> {
        lease.validate(secret, issued_at)?;
        let session = AuthSession {
            session_id: session_id.into(),
            scope: lease.scope.clone(),
            adapter: lease.adapter.clone(),
            credential_revision: lease.credential_revision,
            lease_revision: lease.lease_revision,
            auth_revision,
            issued_at,
            expires_at,
            revoked_at: None,
        };
        if !valid_prefixed_identifier(&session.session_id, "auth-session-") {
            return Err(ConnectorError::InvalidAuthSession);
        }
        session.validate(secret, lease, issued_at)?;
        Ok(session)
    }

    pub fn record_probe(
        secret: &SecretReference,
        lease: &CredentialLease,
        session: &AuthSession,
        result_id: impl Into<String>,
        probe_revision: u64,
        observation: ProbeObservation,
    ) -> Result<ProbeResult, ConnectorError> {
        session.validate(secret, lease, observation.observed_at)?;
        ProbeResult::from_observation(
            session.scope.clone(),
            session.adapter.clone(),
            secret,
            lease,
            session,
            probe_revision,
            result_id,
            observation,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectorDescriptor {
    identity: ProviderAdapterIdentity,
    registrations: Vec<ProviderCapabilitySupport>,
}

impl ConnectorDescriptor {
    pub fn new(
        identity: ProviderAdapterIdentity,
        registrations: impl IntoIterator<Item = ProviderCapabilitySupport>,
    ) -> Result<Self, ConnectorError> {
        let descriptor = Self {
            identity,
            registrations: registrations.into_iter().collect(),
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub fn identity(&self) -> &ProviderAdapterIdentity {
        &self.identity
    }

    pub fn registrations(&self) -> &[ProviderCapabilitySupport] {
        &self.registrations
    }

    pub fn supports(
        &self,
        key: &ProviderCapabilityKey,
        operation: ProviderAdapterOperation,
        provenance: ProviderProvenanceClass,
    ) -> bool {
        self.registrations.iter().any(|registration| {
            registration.key() == key
                && registration.evidence_support().iter().any(|support| {
                    support.operation() == operation && support.provenance_class() == provenance
                })
        })
    }

    fn validate(&self) -> Result<(), ConnectorError> {
        if self.registrations.is_empty()
            || self
                .registrations
                .iter()
                .any(|registration| registration.adapter() != &self.identity)
        {
            return Err(ConnectorError::InvalidAdapterMetadata);
        }
        let mut keys = BTreeSet::new();
        for registration in &self.registrations {
            if !keys.insert(registration.key().clone()) {
                return Err(ConnectorError::DuplicateCapability);
            }
        }
        Ok(())
    }

    fn validate_against(&self, registry: &ProviderAdapterRegistry) -> Result<(), ConnectorError> {
        for registration in &self.registrations {
            let contract_registration = registry
                .registrations()
                .iter()
                .find(|candidate| candidate.key() == registration.key())
                .ok_or(ConnectorError::UnregisteredAdapter)?;
            if contract_registration != registration {
                return Err(ConnectorError::AdapterMetadataMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Cursor {
    scope_digest: String,
    request_digest: String,
    sequence: u64,
    token_digest: String,
}

impl Cursor {
    pub fn new(
        scope: &ConnectorScope,
        request_digest: impl Into<String>,
        sequence: u64,
        token_digest: impl Into<String>,
    ) -> Result<Self, ConnectorError> {
        let cursor = Self {
            scope_digest: scope.digest(),
            request_digest: request_digest.into(),
            sequence,
            token_digest: token_digest.into(),
        };
        cursor.validate(scope)?;
        Ok(cursor)
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

    pub fn token_digest(&self) -> &str {
        &self.token_digest
    }

    fn validate(&self, scope: &ConnectorScope) -> Result<(), ConnectorError> {
        if self.scope_digest != scope.digest()
            || self.sequence == 0
            || !is_sha256(&self.request_digest)
            || !is_sha256(&self.token_digest)
        {
            return Err(ConnectorError::InvalidCursor);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    Canceled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorTask {
    task_id: String,
    scope_digest: String,
    kind: ConnectorTaskKind,
    generation: u64,
    status: TaskStatus,
    cursor: Option<Cursor>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorTaskKind {
    Probe,
    Read,
    Effect,
    Reconcile,
    Verify,
    Webhook,
}

impl ConnectorTask {
    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn status(&self) -> TaskStatus {
        self.status
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FreshnessWindow {
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    source_revision: u64,
}

impl FreshnessWindow {
    pub fn new(
        observed_at: DateTime<Utc>,
        valid_until: DateTime<Utc>,
        source_revision: u64,
    ) -> Result<Self, ConnectorError> {
        if valid_until <= observed_at || source_revision == 0 {
            return Err(ConnectorError::InvalidFreshness);
        }
        Ok(Self {
            observed_at,
            valid_until,
            source_revision,
        })
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), ConnectorError> {
        if now < self.observed_at || now >= self.valid_until {
            return Err(ConnectorError::FreshnessExpired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimitState {
    remaining: u64,
    reset_at: DateTime<Utc>,
}

impl RateLimitState {
    pub fn new(remaining: u64, reset_at: DateTime<Utc>) -> Self {
        Self {
            remaining,
            reset_at,
        }
    }

    pub const fn remaining(&self) -> u64 {
        self.remaining
    }

    pub const fn reset_at(&self) -> DateTime<Utc> {
        self.reset_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuotaState {
    limit: u64,
    used: u64,
}

impl QuotaState {
    pub fn new(limit: u64) -> Self {
        Self { limit, used: 0 }
    }

    pub const fn limit(&self) -> u64 {
        self.limit
    }

    pub const fn used(&self) -> u64 {
        self.used
    }

    fn consume(&mut self) -> Result<(), ConnectorError> {
        if self.used >= self.limit {
            return Err(ConnectorError::QuotaExceeded);
        }
        self.used += 1;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CostState {
    limit_minor: i64,
    used_minor: i64,
}

impl CostState {
    pub fn new(limit_minor: i64) -> Result<Self, ConnectorError> {
        if limit_minor < 0 {
            return Err(ConnectorError::InvalidCostBoundary);
        }
        Ok(Self {
            limit_minor,
            used_minor: 0,
        })
    }

    pub const fn limit_minor(&self) -> i64 {
        self.limit_minor
    }

    pub const fn used_minor(&self) -> i64 {
        self.used_minor
    }

    fn charge(&mut self, amount_minor: i64) -> Result<(), ConnectorError> {
        if amount_minor < 0
            || self
                .used_minor
                .checked_add(amount_minor)
                .is_none_or(|total| total > self.limit_minor)
        {
            return Err(ConnectorError::CostLimitExceeded);
        }
        self.used_minor += amount_minor;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchBudget {
    pub rate_limit: RateLimitState,
    pub quota: QuotaState,
    pub cost: CostState,
}

impl DispatchBudget {
    pub fn new(
        rate_remaining: u64,
        rate_reset_at: DateTime<Utc>,
        quota_limit: u64,
        cost_limit_minor: i64,
    ) -> Result<Self, ConnectorError> {
        Ok(Self {
            rate_limit: RateLimitState::new(rate_remaining, rate_reset_at),
            quota: QuotaState::new(quota_limit),
            cost: CostState::new(cost_limit_minor)?,
        })
    }

    fn admit(&mut self, now: DateTime<Utc>, cost_minor: i64) -> Result<(), ConnectorError> {
        if now >= self.rate_limit.reset_at() && self.rate_limit.remaining == 0 {
            self.rate_limit.remaining = 1;
        }
        if self.rate_limit.remaining == 0 {
            return Err(ConnectorError::RateLimited);
        }
        self.rate_limit.remaining -= 1;
        self.quota.consume()?;
        if let Err(error) = self.cost.charge(cost_minor) {
            self.rate_limit.remaining += 1;
            self.quota.used -= 1;
            return Err(error);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadObservation {
    observation_id: String,
    scope: ConnectorScope,
    capability: ProviderCapabilityKey,
    adapter: ProviderAdapterIdentity,
    request_digest: String,
    response_digest: String,
    content_digest: String,
    provenance_class: ProviderProvenanceClass,
    freshness: FreshnessWindow,
    page_sequence: u64,
    item_count: u32,
    next_cursor: Option<Cursor>,
}

impl ReadObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        observation_id: impl Into<String>,
        scope: ConnectorScope,
        capability: ProviderCapabilityKey,
        adapter: ProviderAdapterIdentity,
        request_digest: impl Into<String>,
        response_digest: impl Into<String>,
        content_digest: impl Into<String>,
        provenance_class: ProviderProvenanceClass,
        freshness: FreshnessWindow,
        page_sequence: u64,
        item_count: u32,
        next_cursor: Option<Cursor>,
    ) -> Result<Self, ConnectorError> {
        let observation = Self {
            observation_id: observation_id.into(),
            scope,
            capability,
            adapter,
            request_digest: request_digest.into(),
            response_digest: response_digest.into(),
            content_digest: content_digest.into(),
            provenance_class,
            freshness,
            page_sequence,
            item_count,
            next_cursor,
        };
        observation.validate()?;
        Ok(observation)
    }

    pub fn observation_id(&self) -> &str {
        &self.observation_id
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn capability(&self) -> &ProviderCapabilityKey {
        &self.capability
    }

    pub fn adapter(&self) -> &ProviderAdapterIdentity {
        &self.adapter
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

    pub const fn provenance_class(&self) -> ProviderProvenanceClass {
        self.provenance_class
    }

    pub const fn freshness(&self) -> &FreshnessWindow {
        &self.freshness
    }

    pub const fn page_sequence(&self) -> u64 {
        self.page_sequence
    }

    pub const fn item_count(&self) -> u32 {
        self.item_count
    }

    pub fn next_cursor(&self) -> Option<&Cursor> {
        self.next_cursor.as_ref()
    }

    fn validate(&self) -> Result<(), ConnectorError> {
        if !valid_prefixed_identifier(&self.observation_id, "read-observation-")
            || !is_sha256(&self.request_digest)
            || !is_sha256(&self.response_digest)
            || !is_sha256(&self.content_digest)
            || self.page_sequence == 0
        {
            return Err(ConnectorError::InvalidObservation);
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate(&self.scope)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedEffect {
    effect_digest: String,
    scope: ConnectorScope,
    capability: ProviderCapabilityKey,
    adapter: ProviderAdapterIdentity,
    payload_digest: String,
    idempotency_key: String,
    prepared_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    cost_minor: i64,
}

impl PreparedEffect {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: ConnectorScope,
        capability: ProviderCapabilityKey,
        adapter: ProviderAdapterIdentity,
        payload_digest: impl Into<String>,
        idempotency_key: impl Into<String>,
        prepared_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        cost_minor: i64,
    ) -> Result<Self, ConnectorError> {
        let payload_digest = payload_digest.into();
        let idempotency_key = idempotency_key.into();
        if !is_sha256(&payload_digest)
            || !valid_prefixed_identifier(&idempotency_key, "effect-idem-")
            || expires_at <= prepared_at
            || cost_minor < 0
        {
            return Err(ConnectorError::InvalidPreparedEffect);
        }
        let effect_digest = canonical_digest([
            &scope.digest(),
            capability.provider_id(),
            capability.capability_id(),
            adapter.adapter_id(),
            &adapter.adapter_version().to_string(),
            payload_digest.as_str(),
            idempotency_key.as_str(),
            &prepared_at.to_rfc3339(),
            &expires_at.to_rfc3339(),
            &cost_minor.to_string(),
        ]);
        Ok(Self {
            effect_digest,
            scope,
            capability,
            adapter,
            payload_digest,
            idempotency_key,
            prepared_at,
            expires_at,
            cost_minor,
        })
    }

    pub fn effect_digest(&self) -> &str {
        &self.effect_digest
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn capability(&self) -> &ProviderCapabilityKey {
        &self.capability
    }

    pub fn adapter(&self) -> &ProviderAdapterIdentity {
        &self.adapter
    }

    pub fn payload_digest(&self) -> &str {
        &self.payload_digest
    }

    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    pub const fn prepared_at(&self) -> DateTime<Utc> {
        self.prepared_at
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub const fn cost_minor(&self) -> i64 {
        self.cost_minor
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptCandidateStatus {
    Accepted,
    Rejected,
    Uncertain,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptCandidate {
    receipt_digest: String,
    effect_digest: String,
    scope: ConnectorScope,
    provider_request_id_digest: String,
    idempotency_key: String,
    status: ReceiptCandidateStatus,
    response_digest: String,
    observed_at: DateTime<Utc>,
}

impl ReceiptCandidate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        effect: &PreparedEffect,
        provider_request_id_digest: impl Into<String>,
        status: ReceiptCandidateStatus,
        response_digest: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ConnectorError> {
        let provider_request_id_digest = provider_request_id_digest.into();
        let response_digest = response_digest.into();
        if !is_sha256(&provider_request_id_digest) || !is_sha256(&response_digest) {
            return Err(ConnectorError::InvalidReceiptCandidate);
        }
        let receipt_digest = canonical_digest([
            effect.effect_digest(),
            provider_request_id_digest.as_str(),
            &format!("{status:?}"),
            response_digest.as_str(),
            &observed_at.to_rfc3339(),
        ]);
        Ok(Self {
            receipt_digest,
            effect_digest: effect.effect_digest.clone(),
            scope: effect.scope.clone(),
            provider_request_id_digest,
            idempotency_key: effect.idempotency_key.clone(),
            status,
            response_digest,
            observed_at,
        })
    }

    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }

    pub fn effect_digest(&self) -> &str {
        &self.effect_digest
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn provider_request_id_digest(&self) -> &str {
        &self.provider_request_id_digest
    }

    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    pub const fn status(&self) -> ReceiptCandidateStatus {
        self.status
    }

    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationStatus {
    ReceiptFound,
    NotExecuted,
    StillUncertain,
    ProviderRejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReconciliationObservation {
    effect_digest: String,
    scope: ConnectorScope,
    status: ReconciliationStatus,
    provider_state_digest: String,
    observed_at: DateTime<Utc>,
    freshness: FreshnessWindow,
}

impl ReconciliationObservation {
    pub fn new(
        effect_digest: impl Into<String>,
        scope: ConnectorScope,
        status: ReconciliationStatus,
        provider_state_digest: impl Into<String>,
        observed_at: DateTime<Utc>,
        freshness: FreshnessWindow,
    ) -> Result<Self, ConnectorError> {
        let effect_digest = effect_digest.into();
        let provider_state_digest = provider_state_digest.into();
        if !is_sha256(&effect_digest) || !is_sha256(&provider_state_digest) {
            return Err(ConnectorError::InvalidReconciliation);
        }
        Ok(Self {
            effect_digest,
            scope,
            status,
            provider_state_digest,
            observed_at,
            freshness,
        })
    }

    pub fn effect_digest(&self) -> &str {
        &self.effect_digest
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub const fn status(&self) -> ReconciliationStatus {
        self.status
    }

    pub fn provider_state_digest(&self) -> &str {
        &self.provider_state_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn freshness(&self) -> &FreshnessWindow {
        &self.freshness
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Confirmed,
    Rejected,
    Inconclusive,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationObservation {
    subject_digest: String,
    scope: ConnectorScope,
    status: VerificationStatus,
    evidence_digest: String,
    observed_at: DateTime<Utc>,
    independent: bool,
}

impl VerificationObservation {
    pub fn new(
        subject_digest: impl Into<String>,
        scope: ConnectorScope,
        status: VerificationStatus,
        evidence_digest: impl Into<String>,
        observed_at: DateTime<Utc>,
        independent: bool,
    ) -> Result<Self, ConnectorError> {
        let subject_digest = subject_digest.into();
        let evidence_digest = evidence_digest.into();
        if !is_sha256(&subject_digest) || !is_sha256(&evidence_digest) {
            return Err(ConnectorError::InvalidVerification);
        }
        Ok(Self {
            subject_digest,
            scope,
            status,
            evidence_digest,
            observed_at,
            independent,
        })
    }

    pub fn subject_digest(&self) -> &str {
        &self.subject_digest
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub const fn status(&self) -> VerificationStatus {
        self.status
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn independent(&self) -> bool {
        self.independent
    }
}

/// A signing key is deliberately non-serializable and zeroized on drop.
pub struct WebhookSigningKey {
    key: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for WebhookSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookSigningKey")
            .field("present", &true)
            .finish()
    }
}

impl WebhookSigningKey {
    pub fn new(key: impl AsRef<[u8]>) -> Result<Self, ConnectorError> {
        let key = key.as_ref();
        if key.len() < 16 {
            return Err(ConnectorError::InvalidWebhookKey);
        }
        Ok(Self {
            key: Zeroizing::new(key.to_vec()),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebhookEnvelope {
    provider_id: String,
    account_id: String,
    scope_digest: String,
    adapter: ProviderAdapterIdentity,
    event_id: String,
    sequence: u64,
    occurred_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
    payload_digest: String,
    signature: String,
}

impl WebhookEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        scope: &ConnectorScope,
        adapter: ProviderAdapterIdentity,
        event_id: impl Into<String>,
        sequence: u64,
        occurred_at: DateTime<Utc>,
        received_at: DateTime<Utc>,
        payload_digest: impl Into<String>,
        key: &WebhookSigningKey,
    ) -> Result<Self, ConnectorError> {
        let event_id = event_id.into();
        let payload_digest = payload_digest.into();
        if !valid_prefixed_identifier(&event_id, "webhook-event-")
            || sequence == 0
            || !is_sha256(&payload_digest)
            || occurred_at > received_at
        {
            return Err(ConnectorError::InvalidWebhook);
        }
        let mut envelope = Self {
            provider_id: scope.provider_id.clone(),
            account_id: scope.account_id.clone(),
            scope_digest: scope.digest(),
            adapter,
            event_id,
            sequence,
            occurred_at,
            received_at,
            payload_digest,
            signature: String::new(),
        };
        envelope.signature = envelope.calculate_signature(key);
        Ok(envelope)
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn payload_digest(&self) -> &str {
        &self.payload_digest
    }

    pub fn adapter(&self) -> &ProviderAdapterIdentity {
        &self.adapter
    }

    fn calculate_signature(&self, key: &WebhookSigningKey) -> String {
        let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key.key.as_slice());
        let tag = hmac::sign(&signing_key, self.signing_material().as_bytes());
        hex_encode(tag.as_ref())
    }

    fn signing_material(&self) -> String {
        canonical_material([
            self.provider_id.as_str(),
            self.account_id.as_str(),
            self.scope_digest.as_str(),
            self.adapter.adapter_id(),
            &self.adapter.adapter_version().to_string(),
            self.event_id.as_str(),
            &self.sequence.to_string(),
            &self.occurred_at.to_rfc3339(),
            &self.received_at.to_rfc3339(),
            self.payload_digest.as_str(),
        ])
    }

    fn verify_signature(&self, key: &WebhookSigningKey) -> Result<(), ConnectorError> {
        let expected = self.calculate_signature(key);
        if expected != self.signature {
            return Err(ConnectorError::InvalidWebhookSignature);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WebhookReplayGuard {
    highest_sequence: BTreeMap<String, u64>,
    seen_events: BTreeSet<String>,
}

impl WebhookReplayGuard {
    pub fn accept(
        &mut self,
        scope: &ConnectorScope,
        envelope: &WebhookEnvelope,
        key: &WebhookSigningKey,
        now: DateTime<Utc>,
    ) -> Result<(), ConnectorError> {
        envelope.verify_signature(key)?;
        if envelope.provider_id != scope.provider_id
            || envelope.account_id != scope.account_id
            || envelope.scope_digest != scope.digest()
            || envelope.adapter.adapter_id() == ""
            || now < envelope.occurred_at
            || now - envelope.occurred_at > Duration::hours(24)
        {
            return Err(ConnectorError::WebhookScopeMismatch);
        }
        let stream = format!("{}:{}", scope.digest(), envelope.adapter.adapter_id());
        if self
            .highest_sequence
            .get(&stream)
            .is_some_and(|highest| envelope.sequence <= *highest)
            || !self.seen_events.insert(envelope.event_id.clone())
        {
            return Err(ConnectorError::WebhookReplay);
        }
        self.highest_sequence.insert(stream, envelope.sequence);
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchFence {
    scope: ConnectorScope,
    generation: u64,
    lease_digest: String,
}

impl DispatchFence {
    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn lease_digest(&self) -> &str {
        &self.lease_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeginAuthRequest {
    pub dispatch: DispatchFence,
    pub scope: ConnectorScope,
    pub secret_reference: SecretReference,
    pub credential_lease: CredentialLease,
    pub auth_revision: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefreshAuthRequest {
    pub dispatch: DispatchFence,
    pub scope: ConnectorScope,
    pub secret_reference: SecretReference,
    pub credential_lease: CredentialLease,
    pub session: AuthSession,
    pub auth_revision: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeRequest {
    pub dispatch: DispatchFence,
    pub scope: ConnectorScope,
    pub secret_reference: SecretReference,
    pub credential_lease: CredentialLease,
    pub session: AuthSession,
    pub probe_revision: u64,
    pub result_id: String,
    pub at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadRequest {
    pub dispatch: DispatchFence,
    pub scope: ConnectorScope,
    pub live_probe: LiveProbeFence,
    pub capability: ProviderCapabilityKey,
    pub query_digest: String,
    pub cursor: Option<Cursor>,
    pub page_size: u32,
    pub at: DateTime<Utc>,
    pub budget: DispatchBudget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareEffectRequest {
    pub dispatch: DispatchFence,
    pub scope: ConnectorScope,
    pub live_probe: LiveProbeFence,
    pub capability: ProviderCapabilityKey,
    pub payload_digest: String,
    pub idempotency_key: String,
    pub prepared_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub cost_minor: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectExecutionContext {
    scope: ConnectorScope,
    effect_digest: String,
    authorization_digest: String,
    expires_at: DateTime<Utc>,
}

impl EffectExecutionContext {
    /// The Effect Broker creates this capsule after its own approval, policy,
    /// idempotency and claim checks.  The connector only validates the capsule
    /// and never interprets it as a standalone approval.
    pub fn from_broker(
        scope: ConnectorScope,
        effect_digest: impl Into<String>,
        authorization_digest: impl Into<String>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, ConnectorError> {
        let effect_digest = effect_digest.into();
        let authorization_digest = authorization_digest.into();
        if !is_sha256(&effect_digest) || !is_sha256(&authorization_digest) {
            return Err(ConnectorError::InvalidExecutionContext);
        }
        Ok(Self {
            scope,
            effect_digest,
            authorization_digest,
            expires_at,
        })
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn effect_digest(&self) -> &str {
        &self.effect_digest
    }

    pub fn authorization_digest(&self) -> &str {
        &self.authorization_digest
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteRequest {
    pub dispatch: DispatchFence,
    pub scope: ConnectorScope,
    pub live_probe: LiveProbeFence,
    pub prepared_effect: PreparedEffect,
    pub execution_context: EffectExecutionContext,
    pub at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconcileRequest {
    pub dispatch: DispatchFence,
    pub scope: ConnectorScope,
    pub live_probe: LiveProbeFence,
    pub capability: ProviderCapabilityKey,
    pub effect_digest: String,
    pub at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifyRequest {
    pub dispatch: DispatchFence,
    pub scope: ConnectorScope,
    pub live_probe: LiveProbeFence,
    pub capability: ProviderCapabilityKey,
    pub subject_digest: String,
    pub at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebhookRequest {
    pub dispatch: DispatchFence,
    pub scope: ConnectorScope,
    pub envelope: WebhookEnvelope,
    pub at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeRequest {
    pub dispatch: DispatchFence,
    pub scope: ConnectorScope,
    pub reason_digest: String,
    pub at: DateTime<Utc>,
}

/// Object-safe adapter lifecycle.  The adapter only returns typed connector
/// evidence; it has no Domain Kernel or Mission handle.
pub trait ConnectorAdapter: Send {
    fn descriptor(&self) -> &ConnectorDescriptor;

    fn begin_auth(&mut self, request: BeginAuthRequest) -> Result<AuthSession, ConnectorError>;

    fn refresh_auth(&mut self, request: RefreshAuthRequest) -> Result<AuthSession, ConnectorError>;

    fn probe(&mut self, request: ProbeRequest) -> Result<ProbeObservation, ConnectorError>;

    fn read(&mut self, request: ReadRequest) -> Result<ReadObservation, ConnectorError>;

    fn prepare_effect(
        &mut self,
        request: PrepareEffectRequest,
    ) -> Result<PreparedEffect, ConnectorError>;

    fn execute(&mut self, request: ExecuteRequest) -> Result<ReceiptCandidate, ConnectorError>;

    fn reconcile(
        &mut self,
        request: ReconcileRequest,
    ) -> Result<ReconciliationObservation, ConnectorError>;

    fn verify(&mut self, request: VerifyRequest)
    -> Result<VerificationObservation, ConnectorError>;

    fn handle_webhook(
        &mut self,
        request: WebhookRequest,
    ) -> Result<WebhookObservation, ConnectorError>;

    fn revoke(&mut self, request: RevokeRequest) -> Result<(), ConnectorError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebhookObservation {
    event_id: String,
    scope: ConnectorScope,
    payload_digest: String,
    sequence: u64,
    observed_at: DateTime<Utc>,
}

impl WebhookObservation {
    pub fn from_envelope(
        envelope: &WebhookEnvelope,
        scope: ConnectorScope,
        now: DateTime<Utc>,
    ) -> Result<Self, ConnectorError> {
        if envelope.scope_digest != scope.digest() {
            return Err(ConnectorError::WebhookScopeMismatch);
        }
        Ok(Self {
            event_id: envelope.event_id.clone(),
            scope,
            payload_digest: envelope.payload_digest.clone(),
            sequence: envelope.sequence,
            observed_at: now,
        })
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn payload_digest(&self) -> &str {
        &self.payload_digest
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerLeaseState {
    Active,
    Canceled,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerLease {
    worker_id: String,
    scope_digest: String,
    generation: u64,
    lease_digest: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    state: WorkerLeaseState,
}

impl WorkerLease {
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn lease_digest(&self) -> &str {
        &self.lease_digest
    }

    pub const fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub const fn state(&self) -> WorkerLeaseState {
        self.state
    }
}

/// A single-owner connector worker.  The worker enforces scope, registry,
/// generation, cancellation and idempotency before invoking the adapter.
pub struct ConnectorWorker<A: ConnectorAdapter> {
    adapter: A,
    contract_registry: ProviderAdapterRegistry,
    scope: ConnectorScope,
    lease: WorkerLease,
    now: DateTime<Utc>,
    next_task: u64,
    tasks: BTreeMap<String, ConnectorTask>,
    executed_effects: BTreeMap<String, ReceiptCandidate>,
    idempotency_effects: BTreeMap<String, String>,
    webhook_replay: WebhookReplayGuard,
    last_budget: Option<DispatchBudget>,
}

impl<A: ConnectorAdapter> fmt::Debug for ConnectorWorker<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectorWorker")
            .field("adapter", &self.descriptor().identity())
            .field("scope_digest", &self.scope.digest())
            .field("lease", &self.lease)
            .field("task_count", &self.tasks.len())
            .field("executed_effect_count", &self.executed_effects.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConnectorError {
    #[error("provider contract metadata is invalid")]
    ProviderContract,
    #[error("connector scope is invalid")]
    InvalidScope,
    #[error("opaque secret reference is invalid")]
    InvalidSecretReference,
    #[error("credential lease is invalid or expired")]
    InvalidCredentialLease,
    #[error("authentication session is invalid or expired")]
    InvalidAuthSession,
    #[error("credential/session/worker revocation is invalid")]
    InvalidRevocation,
    #[error("credential/session/worker is already revoked")]
    AlreadyRevoked,
    #[error("probe observation is invalid")]
    InvalidProbe,
    #[error("probe is not live")]
    ProbeNotLive,
    #[error("probe has expired")]
    ProbeExpired,
    #[error("probe scope does not match the worker")]
    ProbeScopeMismatch,
    #[error("provider provenance is not allowed")]
    UnsupportedProvenance,
    #[error("provider adapter registry is invalid")]
    InvalidRegistry,
    #[error("provider adapter is not registered")]
    UnregisteredAdapter,
    #[error("provider adapter metadata does not match the registry")]
    AdapterMetadataMismatch,
    #[error("adapter metadata is invalid")]
    InvalidAdapterMetadata,
    #[error("adapter declares a duplicate capability")]
    DuplicateCapability,
    #[error("capability is invalid")]
    InvalidCapability,
    #[error("capability is not registered for this operation")]
    CapabilityNotRegistered,
    #[error("scope or operation request is invalid")]
    InvalidRequest,
    #[error("scope does not match the authenticated chain")]
    ScopeMismatch,
    #[error("page size is outside the connector bound")]
    InvalidPageSize,
    #[error("cursor is invalid")]
    InvalidCursor,
    #[error("cursor does not match the request")]
    CursorMismatch,
    #[error("read observation is invalid")]
    InvalidObservation,
    #[error("read observation binding does not match the request")]
    ObservationBindingMismatch,
    #[error("freshness window is invalid")]
    InvalidFreshness,
    #[error("freshness window has expired")]
    FreshnessExpired,
    #[error("rate limit is exhausted")]
    RateLimited,
    #[error("provider quota is exhausted")]
    QuotaExceeded,
    #[error("cost boundary is invalid or exhausted")]
    InvalidCostBoundary,
    #[error("cost limit is exhausted")]
    CostLimitExceeded,
    #[error("prepared effect is invalid")]
    InvalidPreparedEffect,
    #[error("prepared effect binding does not match the request")]
    EffectBindingMismatch,
    #[error("execution context is invalid")]
    InvalidExecutionContext,
    #[error("execution context does not match the effect")]
    ExecutionContextMismatch,
    #[error("effect idempotency key conflicts with an existing dispatch")]
    IdempotencyConflict,
    #[error("receipt candidate is invalid")]
    InvalidReceiptCandidate,
    #[error("receipt candidate binding does not match the effect")]
    ReceiptBindingMismatch,
    #[error("receipt candidate is missing for an idempotent replay")]
    MissingReceiptCandidate,
    #[error("reconciliation observation is invalid")]
    InvalidReconciliation,
    #[error("verification observation is invalid")]
    InvalidVerification,
    #[error("webhook signing key is invalid")]
    InvalidWebhookKey,
    #[error("webhook envelope is invalid")]
    InvalidWebhook,
    #[error("webhook signature is invalid")]
    InvalidWebhookSignature,
    #[error("webhook scope is invalid")]
    WebhookScopeMismatch,
    #[error("webhook envelope was replayed or reordered")]
    WebhookReplay,
    #[error("worker lease is invalid")]
    InvalidWorkerLease,
    #[error("worker generation or lease does not match")]
    GenerationMismatch,
    #[error("connector task was not found")]
    TaskNotFound,
    #[error("connector task transition is invalid")]
    InvalidTaskTransition,
    #[error("provider adapter rejected the operation")]
    ProviderRejected,
    #[error("provider operation is uncertain")]
    ProviderUncertain,
    #[error("connector operation was canceled")]
    Canceled,
}

impl From<ProviderContractError> for ConnectorError {
    fn from(_error: ProviderContractError) -> Self {
        Self::ProviderContract
    }
}

fn canonical_material<'a>(parts: impl IntoIterator<Item = &'a str>) -> String {
    parts
        .into_iter()
        .map(|part| format!("{}:{}", part.len(), part))
        .collect::<Vec<_>>()
        .join("|")
}

fn canonical_digest<'a>(parts: impl IntoIterator<Item = &'a str>) -> String {
    let mut digest = Sha256::new();
    digest.update(canonical_material(parts).as_bytes());
    hex_encode(&digest.finalize())
}

#[cfg(any(test, feature = "testkit"))]
fn sha256(value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(value.as_bytes());
    hex_encode(&digest.finalize())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_prefixed_identifier(value: &str, prefix: &str) -> bool {
    value.starts_with(prefix) && valid_identifier(value)
}

fn valid_scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'.' | b'/' | b'-' | b'_')
        })
}

#[cfg(any(test, feature = "testkit"))]
pub mod testkit {
    use super::{
        AuthSession, BeginAuthRequest, ConnectorAdapter, ConnectorAuth, ConnectorDescriptor,
        ConnectorError, ConnectorScope, ConnectorWorker, Cursor, ExecuteRequest, FreshnessWindow,
        PrepareEffectRequest, PreparedEffect, ProbeObservation, ProbeRequest, ProbeStatus,
        ProviderAdapterIdentity, ProviderAdapterOperation, ProviderAdapterRegistry,
        ProviderCapabilityKey, ProviderCapabilitySupport, ProviderEvidenceClass,
        ProviderProvenanceClass, ReadObservation, ReadRequest, ReceiptCandidate,
        ReceiptCandidateStatus, ReconcileRequest, ReconciliationObservation, ReconciliationStatus,
        RefreshAuthRequest, RevokeRequest, SecretReference, VerificationObservation,
        VerificationStatus, VerifyRequest, WebhookObservation, WebhookRequest,
    };
    #[cfg(test)]
    use super::{
        CredentialLease, DEFAULT_PAGE_SIZE, DispatchBudget, EffectExecutionContext, LiveProbeFence,
        ProbeResult, WebhookEnvelope, WebhookReplayGuard, WebhookSigningKey,
    };
    use chrono::{DateTime, Duration, Utc};
    use std::collections::BTreeMap;

    const PROVIDER_ID: &str = "test-provider";
    const ADAPTER_ID: &str = "test.connector";
    const REGISTRY_VERSION: &str = "connector-test-1";

    #[derive(Clone, Debug)]
    pub struct DeterministicAdapter {
        descriptor: ConnectorDescriptor,
        execute_count: u64,
        read_count: u64,
        externally_applied: BTreeMap<String, String>,
        revoked: bool,
    }

    impl DeterministicAdapter {
        pub fn new(descriptor: ConnectorDescriptor) -> Self {
            Self {
                descriptor,
                execute_count: 0,
                read_count: 0,
                externally_applied: BTreeMap::new(),
                revoked: false,
            }
        }

        pub fn execute_count(&self) -> u64 {
            self.execute_count
        }

        pub fn read_count(&self) -> u64 {
            self.read_count
        }

        pub fn external_state_digest(&self, effect_digest: &str) -> Option<&str> {
            self.externally_applied
                .get(effect_digest)
                .map(String::as_str)
        }
    }

    impl ConnectorAdapter for DeterministicAdapter {
        fn descriptor(&self) -> &ConnectorDescriptor {
            &self.descriptor
        }

        fn begin_auth(&mut self, request: BeginAuthRequest) -> Result<AuthSession, ConnectorError> {
            ConnectorAuth::begin_auth_session(
                &request.secret_reference,
                &request.credential_lease,
                format!("auth-session-{}", request.auth_revision),
                request.auth_revision,
                request.issued_at,
                request.expires_at,
            )
        }

        fn refresh_auth(
            &mut self,
            request: RefreshAuthRequest,
        ) -> Result<AuthSession, ConnectorError> {
            ConnectorAuth::begin_auth_session(
                &request.secret_reference,
                &request.credential_lease,
                format!("auth-session-{}", request.auth_revision),
                request.auth_revision,
                request.issued_at,
                request.expires_at,
            )
        }

        fn probe(&mut self, request: ProbeRequest) -> Result<ProbeObservation, ConnectorError> {
            if self.revoked {
                return Err(ConnectorError::ProviderRejected);
            }
            ProbeObservation::new(
                ProbeStatus::Reachable,
                ProviderProvenanceClass::ControlledProvider,
                request.at,
                request.at + Duration::seconds(60),
                sha256("deterministic-probe"),
            )
        }

        fn read(&mut self, request: ReadRequest) -> Result<ReadObservation, ConnectorError> {
            self.read_count += 1;
            let page_sequence = request
                .cursor
                .as_ref()
                .map_or(1, |cursor| cursor.sequence() + 1);
            let response_digest = sha256(&format!(
                "response:{}:{}",
                request.query_digest, page_sequence
            ));
            let content_digest = sha256(&format!(
                "content:{}:{}",
                request.scope.digest(),
                page_sequence
            ));
            let next_cursor = if page_sequence < 2 {
                Some(Cursor::new(
                    &request.scope,
                    request.query_digest.clone(),
                    page_sequence,
                    sha256(&format!("cursor:{page_sequence}")),
                )?)
            } else {
                None
            };
            ReadObservation::new(
                format!("read-observation-{}", self.read_count),
                request.scope,
                request.capability,
                self.descriptor.identity().clone(),
                request.query_digest,
                response_digest,
                content_digest,
                request.live_probe.provenance_class,
                FreshnessWindow::new(
                    request.at,
                    request.at + Duration::seconds(30),
                    page_sequence,
                )?,
                page_sequence,
                3,
                next_cursor,
            )
        }

        fn prepare_effect(
            &mut self,
            request: PrepareEffectRequest,
        ) -> Result<PreparedEffect, ConnectorError> {
            PreparedEffect::new(
                request.scope,
                request.capability,
                self.descriptor.identity().clone(),
                request.payload_digest,
                request.idempotency_key,
                request.prepared_at,
                request.expires_at,
                request.cost_minor,
            )
        }

        fn execute(&mut self, request: ExecuteRequest) -> Result<ReceiptCandidate, ConnectorError> {
            self.execute_count += 1;
            let response_digest = sha256(&format!(
                "receipt:{}",
                request.prepared_effect.effect_digest()
            ));
            self.externally_applied.insert(
                request.prepared_effect.effect_digest().to_owned(),
                response_digest.clone(),
            );
            ReceiptCandidate::new(
                &request.prepared_effect,
                sha256(&format!("provider-request:{}", self.execute_count)),
                ReceiptCandidateStatus::Uncertain,
                response_digest,
                request.at,
            )
        }

        fn reconcile(
            &mut self,
            request: ReconcileRequest,
        ) -> Result<ReconciliationObservation, ConnectorError> {
            let (status, provider_state_digest) =
                self.externally_applied.get(&request.effect_digest).map_or(
                    (ReconciliationStatus::NotExecuted, sha256("not-executed")),
                    |digest| (ReconciliationStatus::ReceiptFound, digest.clone()),
                );
            ReconciliationObservation::new(
                request.effect_digest,
                request.scope,
                status,
                provider_state_digest,
                request.at,
                FreshnessWindow::new(request.at, request.at + Duration::seconds(30), 1)?,
            )
        }

        fn verify(
            &mut self,
            request: VerifyRequest,
        ) -> Result<VerificationObservation, ConnectorError> {
            VerificationObservation::new(
                request.subject_digest.clone(),
                request.scope,
                VerificationStatus::Confirmed,
                sha256(&format!("verify:{}", request.subject_digest)),
                request.at,
                true,
            )
        }

        fn handle_webhook(
            &mut self,
            request: WebhookRequest,
        ) -> Result<WebhookObservation, ConnectorError> {
            WebhookObservation::from_envelope(&request.envelope, request.scope, request.at)
        }

        fn revoke(&mut self, _request: RevokeRequest) -> Result<(), ConnectorError> {
            self.revoked = true;
            Ok(())
        }
    }

    #[derive(Debug)]
    pub struct ProviderTestkit {
        pub scope: ConnectorScope,
        pub now: DateTime<Utc>,
        pub contract_registry: ProviderAdapterRegistry,
        pub descriptor: ConnectorDescriptor,
    }

    impl ProviderTestkit {
        pub fn new() -> Result<Self, ConnectorError> {
            let scope = ConnectorScope::new(
                "tenant-test",
                "project-test",
                PROVIDER_ID,
                "account-test",
                ["research.read".to_owned(), "webhook.read".to_owned()],
            )?;
            let identity = ProviderAdapterIdentity::new(ADAPTER_ID, 1)
                .map_err(|_| ConnectorError::InvalidAdapterMetadata)?;
            let registrations = registrations(&identity)?;
            let contract_registry =
                ProviderAdapterRegistry::new(REGISTRY_VERSION, registrations.clone())
                    .map_err(|_| ConnectorError::InvalidRegistry)?;
            let descriptor = ConnectorDescriptor::new(identity, registrations)?;
            Ok(Self {
                scope,
                now: DateTime::UNIX_EPOCH + Duration::seconds(1_700_000_000),
                contract_registry,
                descriptor,
            })
        }

        pub fn worker(&self) -> Result<ConnectorWorker<DeterministicAdapter>, ConnectorError> {
            ConnectorWorker::new(
                "worker-deterministic",
                DeterministicAdapter::new(self.descriptor.clone()),
                self.contract_registry.clone(),
                self.scope.clone(),
                self.now,
                self.now + Duration::minutes(10),
            )
        }

        pub fn secret(&self) -> Result<SecretReference, ConnectorError> {
            SecretReference::new("secret-ref-deterministic", self.scope.clone(), 1)
        }

        pub fn capability(&self) -> Result<ProviderCapabilityKey, ConnectorError> {
            ProviderCapabilityKey::new(PROVIDER_ID, "research.discover")
                .map_err(|_| ConnectorError::InvalidCapability)
        }

        pub fn synthetic_registry(&self) -> ProviderAdapterRegistry {
            self.contract_registry.clone()
        }
    }

    fn registrations(
        identity: &ProviderAdapterIdentity,
    ) -> Result<Vec<ProviderCapabilitySupport>, ConnectorError> {
        let mut values = Vec::new();
        for capability in [
            "connection.probe",
            "research.discover",
            "effect.reconcile",
            "publication.publish",
        ] {
            let key = ProviderCapabilityKey::new(PROVIDER_ID, capability)
                .map_err(|_| ConnectorError::InvalidCapability)?;
            let mut evidence = Vec::new();
            let operation = if capability == "connection.probe" {
                ProviderAdapterOperation::Probe
            } else if capability == "publication.publish" {
                ProviderAdapterOperation::PrepareEffect
            } else {
                ProviderAdapterOperation::Read
            };
            let evidence_class = match operation {
                ProviderAdapterOperation::Probe => ProviderEvidenceClass::ProbeObservation,
                ProviderAdapterOperation::Reconcile => {
                    ProviderEvidenceClass::ReconciliationObservation
                }
                ProviderAdapterOperation::PrepareEffect => ProviderEvidenceClass::PreparedEffect,
                _ => ProviderEvidenceClass::ReadObservation,
            };
            for provenance in [
                ProviderProvenanceClass::ControlledProvider,
                ProviderProvenanceClass::ProductionProvider,
            ] {
                evidence.push(
                    hartevo_effect_broker::ProviderEvidenceSupport::new(
                        operation,
                        evidence_class,
                        provenance,
                    )
                    .map_err(|_| ConnectorError::InvalidAdapterMetadata)?,
                );
            }
            if capability == "publication.publish" {
                for (operation, evidence_class) in [
                    (
                        ProviderAdapterOperation::Execute,
                        ProviderEvidenceClass::ReceiptCandidate,
                    ),
                    (
                        ProviderAdapterOperation::Reconcile,
                        ProviderEvidenceClass::ReconciliationObservation,
                    ),
                    (
                        ProviderAdapterOperation::Verify,
                        ProviderEvidenceClass::VerificationObservation,
                    ),
                ] {
                    evidence.push(
                        hartevo_effect_broker::ProviderEvidenceSupport::new(
                            operation,
                            evidence_class,
                            ProviderProvenanceClass::ControlledProvider,
                        )
                        .map_err(|_| ConnectorError::InvalidAdapterMetadata)?,
                    );
                }
            }
            values.push(
                ProviderCapabilitySupport::new(key, identity.clone(), evidence)
                    .map_err(|_| ConnectorError::InvalidAdapterMetadata)?,
            );
        }
        Ok(values)
    }

    fn sha256(value: &str) -> String {
        super::sha256(value)
    }

    #[cfg(test)]
    fn auth_and_probe(
        kit: &ProviderTestkit,
        worker: &mut ConnectorWorker<DeterministicAdapter>,
    ) -> Result<
        (
            SecretReference,
            CredentialLease,
            AuthSession,
            ProbeResult,
            LiveProbeFence,
        ),
        ConnectorError,
    > {
        let secret = kit.secret()?;
        let lease = ConnectorAuth::issue_credential_lease(
            &secret,
            kit.descriptor.identity().clone(),
            "credential-lease-deterministic",
            1,
            kit.now,
            kit.now + Duration::minutes(5),
        )?;
        let dispatch = worker.dispatch_fence();
        let session = worker.begin_auth(BeginAuthRequest {
            dispatch: dispatch.clone(),
            scope: kit.scope.clone(),
            secret_reference: secret.clone(),
            credential_lease: lease.clone(),
            auth_revision: 1,
            issued_at: kit.now,
            expires_at: kit.now + Duration::minutes(5),
        })?;
        let probe = worker.probe(ProbeRequest {
            dispatch,
            scope: kit.scope.clone(),
            secret_reference: secret.clone(),
            credential_lease: lease.clone(),
            session: session.clone(),
            probe_revision: 1,
            result_id: "probe-result-deterministic".to_owned(),
            at: kit.now + Duration::seconds(1),
        })?;
        let live = LiveProbeFence::authorize_with_provenance(
            &kit.contract_registry,
            &probe,
            kit.now + Duration::seconds(1),
            ProviderProvenanceClass::ControlledProvider,
        )?;
        Ok((secret, lease, session, probe, live))
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn synthetic_adapter_passes_full_typed_lifecycle() -> Result<(), ConnectorError> {
        let kit = ProviderTestkit::new().expect("testkit");
        let mut worker = kit.worker().expect("worker");
        let (_, _, _, _, live) = auth_and_probe(&kit, &mut worker).expect("auth/probe");
        let dispatch = worker.dispatch_fence();
        let query_digest = sha256("germany-market-query");
        let budget = DispatchBudget::new(4, kit.now + Duration::hours(1), 4, 100)?;
        let first = worker
            .read(ReadRequest {
                dispatch: dispatch.clone(),
                scope: kit.scope.clone(),
                live_probe: live.clone(),
                capability: kit.capability()?,
                query_digest: query_digest.clone(),
                cursor: None,
                page_size: DEFAULT_PAGE_SIZE,
                at: kit.now + Duration::seconds(1),
                budget,
            })
            .expect("first page");
        let second = worker
            .read(ReadRequest {
                dispatch: dispatch.clone(),
                scope: kit.scope.clone(),
                live_probe: live.clone(),
                capability: kit.capability()?,
                query_digest,
                cursor: first.next_cursor().cloned(),
                page_size: DEFAULT_PAGE_SIZE,
                at: kit.now + Duration::seconds(2),
                budget: DispatchBudget::new(4, kit.now + Duration::hours(1), 4, 100)?,
            })
            .expect("second page");
        assert!(second.next_cursor().is_none());

        let effect = worker
            .prepare_effect(PrepareEffectRequest {
                dispatch: dispatch.clone(),
                scope: kit.scope.clone(),
                live_probe: live.clone(),
                capability: ProviderCapabilityKey::new(PROVIDER_ID, "publication.publish")?,
                payload_digest: sha256("payload"),
                idempotency_key: "effect-idem-deterministic".to_owned(),
                prepared_at: kit.now + Duration::seconds(2),
                expires_at: kit.now + Duration::minutes(2),
                cost_minor: 1,
            })
            .expect("prepare");
        let execution_context = EffectExecutionContext::from_broker(
            kit.scope.clone(),
            effect.effect_digest(),
            sha256("broker-authorization"),
            kit.now + Duration::minutes(2),
        )?;
        let receipt = worker
            .execute(ExecuteRequest {
                dispatch: dispatch.clone(),
                scope: kit.scope.clone(),
                live_probe: live.clone(),
                prepared_effect: effect.clone(),
                execution_context,
                at: kit.now + Duration::seconds(3),
            })
            .expect("execute candidate");
        assert_eq!(receipt.status(), ReceiptCandidateStatus::Uncertain);
        let reconciliation = worker
            .reconcile(ReconcileRequest {
                dispatch: dispatch.clone(),
                scope: kit.scope.clone(),
                live_probe: live.clone(),
                capability: ProviderCapabilityKey::new(PROVIDER_ID, "publication.publish")?,
                effect_digest: effect.effect_digest().to_owned(),
                at: kit.now + Duration::seconds(4),
            })
            .expect("reconcile");
        assert_eq!(reconciliation.status(), ReconciliationStatus::ReceiptFound);
        let verification = worker
            .verify(VerifyRequest {
                dispatch: dispatch.clone(),
                scope: kit.scope.clone(),
                live_probe: live.clone(),
                capability: ProviderCapabilityKey::new(PROVIDER_ID, "publication.publish")?,
                subject_digest: receipt.receipt_digest().to_owned(),
                at: kit.now + Duration::seconds(5),
            })
            .expect("verify");
        assert_eq!(verification.status(), VerificationStatus::Confirmed);

        let key = WebhookSigningKey::new(b"deterministic-webhook-key")?;
        let envelope = WebhookEnvelope::sign(
            &kit.scope,
            kit.descriptor.identity().clone(),
            "webhook-event-deterministic",
            1,
            kit.now + Duration::seconds(5),
            kit.now + Duration::seconds(5),
            sha256("webhook-payload"),
            &key,
        )?;
        let webhook = worker.handle_webhook(
            WebhookRequest {
                dispatch,
                scope: kit.scope.clone(),
                envelope,
                at: kit.now + Duration::seconds(5),
            },
            &key,
        )?;
        assert_eq!(webhook.sequence(), 1);
        Ok(())
    }

    #[test]
    fn crash_after_external_success_reconciles_without_duplicate_write()
    -> Result<(), ConnectorError> {
        let kit = ProviderTestkit::new()?;
        let mut worker = kit.worker()?;
        let (_, _, _, _, live) = auth_and_probe(&kit, &mut worker)?;
        let dispatch = worker.dispatch_fence();
        let effect = worker.prepare_effect(PrepareEffectRequest {
            dispatch: dispatch.clone(),
            scope: kit.scope.clone(),
            live_probe: live.clone(),
            capability: ProviderCapabilityKey::new(PROVIDER_ID, "publication.publish")?,
            payload_digest: sha256("crash-payload"),
            idempotency_key: "effect-idem-crash".to_owned(),
            prepared_at: kit.now + Duration::seconds(1),
            expires_at: kit.now + Duration::minutes(2),
            cost_minor: 1,
        })?;
        let context = EffectExecutionContext::from_broker(
            kit.scope.clone(),
            effect.effect_digest(),
            sha256("approval"),
            kit.now + Duration::minutes(2),
        )?;
        let first = worker.execute(ExecuteRequest {
            dispatch: dispatch.clone(),
            scope: kit.scope.clone(),
            live_probe: live.clone(),
            prepared_effect: effect.clone(),
            execution_context: context.clone(),
            at: kit.now + Duration::seconds(2),
        })?;
        assert_eq!(first.status(), ReceiptCandidateStatus::Uncertain);
        let replay = worker.execute(ExecuteRequest {
            dispatch: dispatch.clone(),
            scope: kit.scope.clone(),
            live_probe: live.clone(),
            prepared_effect: effect.clone(),
            execution_context: context,
            at: kit.now + Duration::seconds(3),
        })?;
        assert_eq!(first, replay);
        assert_eq!(worker.adapter.execute_count(), 1);
        let reconciliation = worker.reconcile(ReconcileRequest {
            dispatch,
            scope: kit.scope.clone(),
            live_probe: live,
            capability: ProviderCapabilityKey::new(PROVIDER_ID, "publication.publish")?,
            effect_digest: effect.effect_digest().to_owned(),
            at: kit.now + Duration::seconds(4),
        })?;
        assert_eq!(reconciliation.status(), ReconciliationStatus::ReceiptFound);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn wrong_scope_cursor_generation_signature_and_quota_fail_before_adapter()
    -> Result<(), ConnectorError> {
        let kit = ProviderTestkit::new()?;
        let mut worker = kit.worker()?;
        let (_, _, _, _, live) = auth_and_probe(&kit, &mut worker)?;
        let dispatch = worker.dispatch_fence();
        let query_digest = sha256("scope-query");
        let wrong_scope = ConnectorScope::new(
            "tenant-other",
            kit.scope.project_id(),
            kit.scope.provider_id(),
            kit.scope.account_id(),
            kit.scope.scopes().iter().cloned(),
        )?;
        let wrong_cursor = Cursor::new(&wrong_scope, query_digest.clone(), 1, sha256("cursor"))?;
        let result = worker.read(ReadRequest {
            dispatch: dispatch.clone(),
            scope: kit.scope.clone(),
            live_probe: live.clone(),
            capability: kit.capability()?,
            query_digest: query_digest.clone(),
            cursor: Some(wrong_cursor),
            page_size: DEFAULT_PAGE_SIZE,
            at: kit.now + Duration::seconds(1),
            budget: DispatchBudget::new(1, kit.now + Duration::hours(1), 1, 1)?,
        });
        assert_eq!(result, Err(ConnectorError::InvalidCursor));
        assert_eq!(worker.adapter.read_count(), 0);

        let wrong_tenant = ConnectorScope::new(
            "tenant-other",
            kit.scope.project_id(),
            kit.scope.provider_id(),
            kit.scope.account_id(),
            kit.scope.scopes().iter().cloned(),
        )?;
        let result = worker.read(ReadRequest {
            dispatch: worker.dispatch_fence(),
            scope: wrong_tenant,
            live_probe: live.clone(),
            capability: kit.capability()?,
            query_digest: sha256("tenant-query"),
            cursor: None,
            page_size: DEFAULT_PAGE_SIZE,
            at: kit.now + Duration::seconds(1),
            budget: DispatchBudget::new(1, kit.now + Duration::hours(1), 1, 1)?,
        });
        assert_eq!(result, Err(ConnectorError::ScopeMismatch));

        let wrong_account = ConnectorScope::new(
            kit.scope.tenant_id(),
            kit.scope.project_id(),
            kit.scope.provider_id(),
            "account-other",
            kit.scope.scopes().iter().cloned(),
        )?;
        let result = worker.read(ReadRequest {
            dispatch: worker.dispatch_fence(),
            scope: wrong_account,
            live_probe: live.clone(),
            capability: kit.capability()?,
            query_digest: sha256("account-query"),
            cursor: None,
            page_size: DEFAULT_PAGE_SIZE,
            at: kit.now + Duration::seconds(1),
            budget: DispatchBudget::new(1, kit.now + Duration::hours(1), 1, 1)?,
        });
        assert_eq!(result, Err(ConnectorError::ScopeMismatch));

        let result = worker.read(ReadRequest {
            dispatch: worker.dispatch_fence(),
            scope: kit.scope.clone(),
            live_probe: live.clone(),
            capability: ProviderCapabilityKey::new(PROVIDER_ID, "unknown.read")?,
            query_digest: sha256("capability-query"),
            cursor: None,
            page_size: DEFAULT_PAGE_SIZE,
            at: kit.now + Duration::seconds(1),
            budget: DispatchBudget::new(1, kit.now + Duration::hours(1), 1, 1)?,
        });
        assert_eq!(result, Err(ConnectorError::CapabilityNotRegistered));
        assert_eq!(worker.adapter.read_count(), 0);

        let result = worker.read(ReadRequest {
            dispatch: worker.dispatch_fence(),
            scope: kit.scope.clone(),
            live_probe: live.clone(),
            capability: kit.capability()?,
            query_digest: sha256("quota-query"),
            cursor: None,
            page_size: DEFAULT_PAGE_SIZE,
            at: kit.now + Duration::seconds(1),
            budget: DispatchBudget::new(1, kit.now + Duration::hours(1), 0, 1)?,
        });
        assert_eq!(result, Err(ConnectorError::QuotaExceeded));

        let result = worker.read(ReadRequest {
            dispatch: worker.dispatch_fence(),
            scope: kit.scope.clone(),
            live_probe: live.clone(),
            capability: kit.capability()?,
            query_digest: sha256("rate-query"),
            cursor: None,
            page_size: DEFAULT_PAGE_SIZE,
            at: kit.now + Duration::seconds(1),
            budget: DispatchBudget::new(0, kit.now + Duration::hours(1), 1, 1)?,
        });
        assert_eq!(result, Err(ConnectorError::RateLimited));

        let canceled = worker.cancel(&dispatch, kit.now + Duration::seconds(1));
        assert!(canceled.is_ok());
        let result = worker.read(ReadRequest {
            dispatch,
            scope: kit.scope,
            live_probe: live,
            capability: ProviderCapabilityKey::new(PROVIDER_ID, "research.discover")?,
            query_digest,
            cursor: None,
            page_size: DEFAULT_PAGE_SIZE,
            at: kit.now + Duration::seconds(1),
            budget: DispatchBudget::new(1, kit.now + Duration::hours(1), 1, 1)?,
        });
        assert_eq!(result, Err(ConnectorError::GenerationMismatch));
        Ok(())
    }

    #[test]
    fn empty_registry_and_webhook_replay_fail_closed() -> Result<(), ConnectorError> {
        let kit = ProviderTestkit::new()?;
        let empty = ProviderAdapterRegistry::contract_baseline()
            .map_err(|_| ConnectorError::InvalidRegistry)?;
        let adapter = DeterministicAdapter::new(kit.descriptor.clone());
        assert!(matches!(
            ConnectorWorker::new(
                "worker-empty",
                adapter,
                empty,
                kit.scope.clone(),
                kit.now,
                kit.now + Duration::minutes(5),
            ),
            Err(ConnectorError::UnregisteredAdapter)
        ));

        let key = WebhookSigningKey::new(b"deterministic-webhook-key")?;
        let mut guard = WebhookReplayGuard::default();
        let envelope = WebhookEnvelope::sign(
            &kit.scope,
            kit.descriptor.identity().clone(),
            "webhook-event-replay",
            1,
            kit.now,
            kit.now,
            sha256("payload"),
            &key,
        )?;
        let mut tampered = envelope.clone();
        tampered.signature = sha256("tampered-signature");
        assert_eq!(
            guard.accept(&kit.scope, &tampered, &key, kit.now),
            Err(ConnectorError::InvalidWebhookSignature)
        );
        guard.accept(&kit.scope, &envelope, &key, kit.now)?;
        assert_eq!(
            guard.accept(&kit.scope, &envelope, &key, kit.now),
            Err(ConnectorError::WebhookReplay)
        );
        Ok(())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 0x0f) as usize] as char);
    }
    value
}

impl<A: ConnectorAdapter> ConnectorWorker<A> {
    pub fn new(
        worker_id: impl Into<String>,
        adapter: A,
        contract_registry: ProviderAdapterRegistry,
        scope: ConnectorScope,
        now: DateTime<Utc>,
        lease_expires_at: DateTime<Utc>,
    ) -> Result<Self, ConnectorError> {
        let worker_id = worker_id.into();
        if !valid_prefixed_identifier(&worker_id, "worker-")
            || lease_expires_at <= now
            || lease_expires_at - now > Duration::seconds(MAX_WORKER_LEASE_TTL_SECONDS)
        {
            return Err(ConnectorError::InvalidWorkerLease);
        }
        contract_registry
            .validate()
            .map_err(|_| ConnectorError::InvalidRegistry)?;
        adapter.descriptor().validate()?;
        adapter.descriptor().validate_against(&contract_registry)?;
        let scope_digest = scope.digest();
        let lease_digest = canonical_digest([
            worker_id.as_str(),
            &scope_digest,
            "1",
            &now.to_rfc3339(),
            &lease_expires_at.to_rfc3339(),
        ]);
        Ok(Self {
            adapter,
            contract_registry,
            scope,
            lease: WorkerLease {
                worker_id,
                scope_digest,
                generation: 1,
                lease_digest,
                issued_at: now,
                expires_at: lease_expires_at,
                state: WorkerLeaseState::Active,
            },
            now,
            next_task: 1,
            tasks: BTreeMap::new(),
            executed_effects: BTreeMap::new(),
            idempotency_effects: BTreeMap::new(),
            webhook_replay: WebhookReplayGuard::default(),
            last_budget: None,
        })
    }

    pub fn descriptor(&self) -> &ConnectorDescriptor {
        self.adapter.descriptor()
    }

    pub fn lease(&self) -> &WorkerLease {
        &self.lease
    }

    pub fn scope(&self) -> &ConnectorScope {
        &self.scope
    }

    pub fn now(&self) -> DateTime<Utc> {
        self.now
    }

    pub fn set_now(&mut self, now: DateTime<Utc>) {
        self.now = now;
        if now >= self.lease.expires_at && self.lease.state == WorkerLeaseState::Active {
            self.lease.state = WorkerLeaseState::Expired;
        }
    }

    pub fn dispatch_fence(&self) -> DispatchFence {
        DispatchFence {
            scope: self.scope.clone(),
            generation: self.lease.generation,
            lease_digest: self.lease.lease_digest.clone(),
        }
    }

    pub fn cancel(
        &mut self,
        fence: &DispatchFence,
        at: DateTime<Utc>,
    ) -> Result<(), ConnectorError> {
        self.validate_dispatch(fence, &self.scope, at)?;
        self.lease.state = WorkerLeaseState::Canceled;
        self.lease.generation = self.lease.generation.saturating_add(1);
        self.lease.lease_digest = canonical_digest([
            self.lease.worker_id.as_str(),
            &self.scope.digest(),
            &self.lease.generation.to_string(),
            &at.to_rfc3339(),
        ]);
        Ok(())
    }

    pub fn renew_generation(
        &mut self,
        previous: &DispatchFence,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<DispatchFence, ConnectorError> {
        if previous.generation != self.lease.generation
            || previous.lease_digest != self.lease.lease_digest
            || expires_at <= issued_at
            || expires_at - issued_at > Duration::seconds(MAX_WORKER_LEASE_TTL_SECONDS)
        {
            return Err(ConnectorError::GenerationMismatch);
        }
        self.lease.generation = self.lease.generation.saturating_add(1);
        self.lease.issued_at = issued_at;
        self.lease.expires_at = expires_at;
        self.lease.state = WorkerLeaseState::Active;
        self.lease.lease_digest = canonical_digest([
            self.lease.worker_id.as_str(),
            &self.scope.digest(),
            &self.lease.generation.to_string(),
            &issued_at.to_rfc3339(),
            &expires_at.to_rfc3339(),
        ]);
        Ok(self.dispatch_fence())
    }

    pub fn last_budget(&self) -> Option<&DispatchBudget> {
        self.last_budget.as_ref()
    }

    pub fn enqueue_task(
        &mut self,
        fence: &DispatchFence,
        kind: ConnectorTaskKind,
        cursor: Option<Cursor>,
        at: DateTime<Utc>,
    ) -> Result<ConnectorTask, ConnectorError> {
        self.validate_dispatch(fence, &self.scope, at)?;
        if let Some(cursor) = &cursor {
            cursor.validate(&self.scope)?;
        }
        let task_id = format!("connector-task-{}", self.next_task);
        self.next_task = self.next_task.saturating_add(1);
        let task = ConnectorTask {
            task_id: task_id.clone(),
            scope_digest: self.scope.digest(),
            kind,
            generation: self.lease.generation,
            status: TaskStatus::Queued,
            cursor,
            created_at: at,
            updated_at: at,
        };
        self.tasks.insert(task_id, task.clone());
        Ok(task)
    }

    pub fn start_task(
        &mut self,
        fence: &DispatchFence,
        task_id: &str,
        at: DateTime<Utc>,
    ) -> Result<(), ConnectorError> {
        self.validate_dispatch(fence, &self.scope, at)?;
        let task = self
            .tasks
            .get_mut(task_id)
            .ok_or(ConnectorError::TaskNotFound)?;
        if task.generation != fence.generation || task.status != TaskStatus::Queued {
            return Err(ConnectorError::GenerationMismatch);
        }
        task.status = TaskStatus::Running;
        task.updated_at = at;
        Ok(())
    }

    pub fn finish_task(
        &mut self,
        fence: &DispatchFence,
        task_id: &str,
        status: TaskStatus,
        at: DateTime<Utc>,
    ) -> Result<(), ConnectorError> {
        if !matches!(
            status,
            TaskStatus::Succeeded | TaskStatus::Failed | TaskStatus::Canceled
        ) {
            return Err(ConnectorError::InvalidTaskTransition);
        }
        self.validate_dispatch(fence, &self.scope, at)?;
        let task = self
            .tasks
            .get_mut(task_id)
            .ok_or(ConnectorError::TaskNotFound)?;
        if task.generation != fence.generation || task.status != TaskStatus::Running {
            return Err(ConnectorError::GenerationMismatch);
        }
        task.status = status;
        task.updated_at = at;
        Ok(())
    }

    pub fn begin_auth(&mut self, request: BeginAuthRequest) -> Result<AuthSession, ConnectorError> {
        self.validate_dispatch(&request.dispatch, &request.scope, request.issued_at)?;
        if request.secret_reference.scope() != &request.scope
            || request.credential_lease.scope() != &request.scope
            || request.credential_lease.adapter() != self.descriptor().identity()
        {
            return Err(ConnectorError::ScopeMismatch);
        }
        self.adapter.begin_auth(request)
    }

    pub fn refresh_auth(
        &mut self,
        request: RefreshAuthRequest,
    ) -> Result<AuthSession, ConnectorError> {
        self.validate_dispatch(&request.dispatch, &request.scope, request.issued_at)?;
        if request.secret_reference.scope() != &request.scope
            || request.credential_lease.scope() != &request.scope
            || request.credential_lease.adapter() != self.descriptor().identity()
            || request.session.scope() != &request.scope
            || request.session.adapter() != self.descriptor().identity()
        {
            return Err(ConnectorError::ScopeMismatch);
        }
        self.adapter.refresh_auth(request)
    }

    pub fn probe(&mut self, request: ProbeRequest) -> Result<ProbeResult, ConnectorError> {
        self.validate_dispatch(&request.dispatch, &request.scope, request.at)?;
        if request.secret_reference.scope() != &request.scope
            || request.credential_lease.scope() != &request.scope
            || request.credential_lease.adapter() != self.descriptor().identity()
            || request.session.scope() != &request.scope
            || request.session.adapter() != self.descriptor().identity()
        {
            return Err(ConnectorError::ScopeMismatch);
        }
        let observation = self.adapter.probe(request.clone())?;
        ConnectorAuth::record_probe(
            &request.secret_reference,
            &request.credential_lease,
            &request.session,
            request.result_id,
            request.probe_revision,
            observation,
        )
    }

    pub fn authorize_probe(
        &self,
        probe: &ProbeResult,
        now: DateTime<Utc>,
    ) -> Result<LiveProbeFence, ConnectorError> {
        LiveProbeFence::authorize(&self.contract_registry, probe, now)
    }

    pub fn read(&mut self, request: ReadRequest) -> Result<ReadObservation, ConnectorError> {
        self.validate_dispatch(&request.dispatch, &request.scope, request.at)?;
        self.validate_live_probe(&request.scope, &request.live_probe, request.at)?;
        self.validate_capability(
            &request.capability,
            ProviderAdapterOperation::Read,
            request.live_probe.provenance_class,
        )?;
        if request.query_digest.len() != 64 || !is_sha256(&request.query_digest) {
            return Err(ConnectorError::InvalidRequest);
        }
        if !(1..=MAX_PAGE_SIZE).contains(&request.page_size) {
            return Err(ConnectorError::InvalidPageSize);
        }
        if let Some(cursor) = &request.cursor {
            cursor.validate(&request.scope)?;
            if cursor.request_digest() != request.query_digest {
                return Err(ConnectorError::CursorMismatch);
            }
        }
        let request_at = request.at;
        let request_capability = request.capability.clone();
        let request_provenance = request.live_probe.provenance_class;
        let mut budget = request.budget.clone();
        budget.admit(request_at, 0)?;
        let observation = self.adapter.read(request)?;
        if observation.scope() != &self.scope
            || observation.capability() != &request_capability
            || observation.adapter() != self.descriptor().identity()
            || observation.provenance_class() != request_provenance
        {
            return Err(ConnectorError::ObservationBindingMismatch);
        }
        observation.freshness().validate_at(request_at)?;
        self.last_budget = Some(budget);
        Ok(observation)
    }

    pub fn prepare_effect(
        &mut self,
        request: PrepareEffectRequest,
    ) -> Result<PreparedEffect, ConnectorError> {
        self.validate_dispatch(&request.dispatch, &request.scope, request.prepared_at)?;
        self.validate_live_probe(&request.scope, &request.live_probe, request.prepared_at)?;
        self.validate_capability(
            &request.capability,
            ProviderAdapterOperation::PrepareEffect,
            request.live_probe.provenance_class,
        )?;
        let prepared = self.adapter.prepare_effect(request)?;
        if prepared.scope() != &self.scope || prepared.adapter() != self.descriptor().identity() {
            return Err(ConnectorError::EffectBindingMismatch);
        }
        Ok(prepared)
    }

    pub fn execute(&mut self, request: ExecuteRequest) -> Result<ReceiptCandidate, ConnectorError> {
        self.validate_dispatch(&request.dispatch, &request.scope, request.at)?;
        self.validate_live_probe(&request.scope, &request.live_probe, request.at)?;
        if request.execution_context.scope() != &request.scope
            || request.execution_context.effect_digest() != request.prepared_effect.effect_digest()
            || request.at >= request.execution_context.expires_at()
            || request.at >= request.prepared_effect.expires_at()
        {
            return Err(ConnectorError::ExecutionContextMismatch);
        }
        let effect_digest = request.prepared_effect.effect_digest().to_owned();
        let idempotency_key = request.prepared_effect.idempotency_key().to_owned();
        let effect_capability = request.prepared_effect.capability().clone();
        let provenance = request.live_probe.provenance_class;
        self.validate_capability(
            &effect_capability,
            ProviderAdapterOperation::Execute,
            provenance,
        )?;
        if let Some(existing_digest) = self.idempotency_effects.get(&idempotency_key) {
            if existing_digest != &effect_digest {
                return Err(ConnectorError::IdempotencyConflict);
            }
            return self
                .executed_effects
                .get(existing_digest)
                .cloned()
                .ok_or(ConnectorError::MissingReceiptCandidate);
        }
        let receipt = self.adapter.execute(request)?;
        if receipt.scope() != &self.scope || receipt.effect_digest() != effect_digest {
            return Err(ConnectorError::ReceiptBindingMismatch);
        }
        self.idempotency_effects
            .insert(idempotency_key, effect_digest.clone());
        self.executed_effects.insert(effect_digest, receipt.clone());
        Ok(receipt)
    }

    pub fn reconcile(
        &mut self,
        request: ReconcileRequest,
    ) -> Result<ReconciliationObservation, ConnectorError> {
        self.validate_dispatch(&request.dispatch, &request.scope, request.at)?;
        self.validate_live_probe(&request.scope, &request.live_probe, request.at)?;
        if !is_sha256(&request.effect_digest) {
            return Err(ConnectorError::InvalidReconciliation);
        }
        self.validate_capability(
            &request.capability,
            ProviderAdapterOperation::Reconcile,
            request.live_probe.provenance_class,
        )?;
        let at = request.at;
        let observation = self.adapter.reconcile(request)?;
        if observation.scope() != &self.scope {
            return Err(ConnectorError::ObservationBindingMismatch);
        }
        observation.freshness().validate_at(at)?;
        Ok(observation)
    }

    pub fn verify(
        &mut self,
        request: VerifyRequest,
    ) -> Result<VerificationObservation, ConnectorError> {
        self.validate_dispatch(&request.dispatch, &request.scope, request.at)?;
        self.validate_live_probe(&request.scope, &request.live_probe, request.at)?;
        if !is_sha256(&request.subject_digest) {
            return Err(ConnectorError::InvalidVerification);
        }
        self.validate_capability(
            &request.capability,
            ProviderAdapterOperation::Verify,
            request.live_probe.provenance_class,
        )?;
        let observation = self.adapter.verify(request)?;
        if observation.scope() != &self.scope {
            return Err(ConnectorError::ObservationBindingMismatch);
        }
        Ok(observation)
    }

    pub fn handle_webhook(
        &mut self,
        request: WebhookRequest,
        key: &WebhookSigningKey,
    ) -> Result<WebhookObservation, ConnectorError> {
        self.validate_dispatch(&request.dispatch, &request.scope, request.at)?;
        self.webhook_replay
            .accept(&request.scope, &request.envelope, key, request.at)?;
        if request.envelope.adapter() != self.descriptor().identity() {
            return Err(ConnectorError::AdapterMetadataMismatch);
        }
        self.adapter.handle_webhook(request)
    }

    pub fn revoke(&mut self, request: RevokeRequest) -> Result<(), ConnectorError> {
        self.validate_dispatch(&request.dispatch, &request.scope, request.at)?;
        if !is_sha256(&request.reason_digest) {
            return Err(ConnectorError::InvalidRevocation);
        }
        self.adapter.revoke(request)
    }

    fn validate_dispatch(
        &self,
        fence: &DispatchFence,
        scope: &ConnectorScope,
        at: DateTime<Utc>,
    ) -> Result<(), ConnectorError> {
        if fence.scope != *scope || fence.scope != self.scope {
            return Err(ConnectorError::ScopeMismatch);
        }
        if fence.generation != self.lease.generation
            || fence.lease_digest != self.lease.lease_digest
            || self.lease.state != WorkerLeaseState::Active
            || at < self.lease.issued_at
            || at >= self.lease.expires_at
        {
            return Err(ConnectorError::GenerationMismatch);
        }
        Ok(())
    }

    fn validate_live_probe(
        &self,
        scope: &ConnectorScope,
        fence: &LiveProbeFence,
        now: DateTime<Utc>,
    ) -> Result<(), ConnectorError> {
        fence.validate_at(now)?;
        if fence.scope != *scope
            || fence.scope != self.scope
            || fence.adapter != *self.descriptor().identity()
        {
            return Err(ConnectorError::ProbeScopeMismatch);
        }
        Ok(())
    }

    fn validate_capability(
        &self,
        capability: &ProviderCapabilityKey,
        operation: ProviderAdapterOperation,
        provenance: ProviderProvenanceClass,
    ) -> Result<(), ConnectorError> {
        if capability.provider_id() != self.scope.provider_id
            || !self
                .descriptor()
                .supports(capability, operation, provenance)
        {
            return Err(ConnectorError::CapabilityNotRegistered);
        }
        Ok(())
    }
}
