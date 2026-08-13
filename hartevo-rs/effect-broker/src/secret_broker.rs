//! Mission-scoped opaque credential leases for provider plugins.
//!
//! The broker owns references and lifecycle fences only.  It never accepts,
//! stores, serializes, or returns a keyring value, token, cookie, or other
//! secret bytes. A consumer dispatch carries only a Mission-scoped reference;
//! the broker resolves it into a live handle for the registered provider
//! callback and reclaims that lease before returning a receipt. The receipt
//! carries no Effect authority.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use hartevo_domain_kernel::{AccountId, MissionId, ProjectId, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::provider_contract::{
    ProviderAdapterIdentity, ProviderAdapterOperation, ProviderAdapterRegistry,
    ProviderCapabilityKey, ProviderProvenanceClass,
};

pub const SECRET_BROKER_SCHEMA_VERSION: u32 = 1;
pub const SECRET_BROKER_SERVICE_VERSION: u32 = 1;
pub const SECRET_BROKER_SERVICE_ID: &str = "hartevo.secret-broker";
pub const SECRET_BROKER_MAX_LEASE_TTL_SECONDS: u64 = 900;
pub const SECRET_BROKER_DISPATCH_LEASE_TTL_SECONDS: u64 = 60;

const SECRET_REFERENCE_PREFIX: &str = "secret-ref-";
const SECRET_HANDLE_PREFIX: &str = "secret-use-";
const SECRET_CONSUMER_PREFIX: &str = "secret-consumer-";
const SECRET_EVENT_PREFIX: &str = "secret-event-";

/// The only authority a secret-broker receipt can carry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretUseAuthority {
    MissionScopedOpaqueCredentialUse,
}

/// Lifecycle state of the mounted broker service.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretBrokerState {
    Unmounted,
    Mounted,
    Revoked,
    Crashed,
}

/// Stable service metadata.  The definition contains no secret material.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretBrokerServiceDefinition {
    schema_version: u32,
    service_id: String,
    version: u32,
    service_digest: String,
}

impl SecretBrokerServiceDefinition {
    /// Creates a service definition for the opaque Mission-scoped broker.
    pub fn new(service_id: impl Into<String>) -> Result<Self, SecretBrokerError> {
        let mut definition = Self {
            schema_version: SECRET_BROKER_SCHEMA_VERSION,
            service_id: service_id.into(),
            version: SECRET_BROKER_SERVICE_VERSION,
            service_digest: String::new(),
        };
        definition.service_digest = definition.unsigned_digest();
        definition.validate()?;
        Ok(definition)
    }

    /// Returns the checked-in production service identity.
    pub fn production() -> Result<Self, SecretBrokerError> {
        Self::new(SECRET_BROKER_SERVICE_ID)
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub const fn version(&self) -> u32 {
        self.version
    }

    pub fn service_digest(&self) -> &str {
        &self.service_digest
    }

    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn validate(&self) -> Result<(), SecretBrokerError> {
        if self.schema_version != SECRET_BROKER_SCHEMA_VERSION
            || self.version != SECRET_BROKER_SERVICE_VERSION
            || !valid_identifier(&self.service_id)
            || !is_sha256(&self.service_digest)
            || self.service_digest != self.unsigned_digest()
        {
            return Err(SecretBrokerError::InvalidServiceDefinition);
        }
        Ok(())
    }

    fn unsigned_digest(&self) -> String {
        digest_fields([
            "hartevo-secret-broker-service/v1",
            &self.schema_version.to_string(),
            &self.service_id,
            &self.version.to_string(),
        ])
    }
}

impl fmt::Debug for SecretBrokerServiceDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBrokerServiceDefinition")
            .field("schema_version", &self.schema_version)
            .field("service_id", &self.service_id)
            .field("version", &self.version)
            .field("service_digest", &self.service_digest)
            .finish()
    }
}

/// Composite scope for a Mission-scoped provider credential reference.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct SecretScope {
    tenant_id: TenantId,
    project_id: ProjectId,
    mission_id: MissionId,
    provider_id: String,
    account_id: AccountId,
    capability_id: String,
}

impl SecretScope {
    /// Builds an exact tenant/project/Mission/provider/account/capability scope.
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: MissionId,
        provider_id: impl Into<String>,
        account_id: AccountId,
        capability_id: impl Into<String>,
    ) -> Result<Self, SecretBrokerError> {
        let scope = Self {
            tenant_id,
            project_id,
            mission_id,
            provider_id: provider_id.into(),
            account_id,
            capability_id: capability_id.into(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub const fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    pub fn capability_key(&self) -> Result<ProviderCapabilityKey, SecretBrokerError> {
        ProviderCapabilityKey::new(self.provider_id.clone(), self.capability_id.clone())
            .map_err(|_| SecretBrokerError::InvalidScope)
    }

    pub fn digest(&self) -> String {
        digest_fields([
            "hartevo-secret-broker-scope/v1",
            self.tenant_id.as_str(),
            self.project_id.as_str(),
            self.mission_id.as_str(),
            &self.provider_id,
            self.account_id.as_str(),
            &self.capability_id,
        ])
    }

    fn validate(&self) -> Result<(), SecretBrokerError> {
        if !valid_identifier(self.tenant_id.as_str())
            || !valid_identifier(self.project_id.as_str())
            || !valid_identifier(self.mission_id.as_str())
            || !valid_identifier(self.account_id.as_str())
            || self.capability_key().is_err()
        {
            return Err(SecretBrokerError::InvalidScope);
        }
        Ok(())
    }
}

impl fmt::Debug for SecretScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretScope")
            .field("scope_digest", &self.digest())
            .finish_non_exhaustive()
    }
}

/// An opaque keyring/secret-store reference.  This type intentionally has no
/// field for a key, token, cookie, or other secret bytes.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    reference_id: String,
    service_digest: String,
    scope: SecretScope,
    credential_revision: u64,
    revoked_at: Option<DateTime<Utc>>,
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        service: &SecretBrokerServiceDefinition,
        scope: SecretScope,
        credential_revision: u64,
    ) -> Result<Self, SecretBrokerError> {
        service.validate()?;
        let reference = Self {
            reference_id: reference_id.into(),
            service_digest: service.service_digest.clone(),
            scope,
            credential_revision,
            revoked_at: None,
        };
        reference.validate_for(service)?;
        Ok(reference)
    }

    pub fn reference_id(&self) -> &str {
        &self.reference_id
    }

    pub fn service_digest(&self) -> &str {
        &self.service_digest
    }

    pub const fn scope(&self) -> &SecretScope {
        &self.scope
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub fn digest(&self) -> String {
        digest_fields([
            "hartevo-secret-reference/v1",
            &self.reference_id,
            &self.service_digest,
            &self.scope.digest(),
            &self.credential_revision.to_string(),
        ])
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Builds a provider dispatch containing this reference only. The
    /// dispatch has no lease and does not authorize provider use by itself.
    pub fn provider_dispatch(&self) -> Result<SecretProviderDispatch, SecretBrokerError> {
        SecretProviderDispatch::new(self.clone())
    }

    fn validate_unbound(&self) -> Result<(), SecretBrokerError> {
        self.scope.validate()?;
        if !valid_prefixed_identifier(&self.reference_id, SECRET_REFERENCE_PREFIX)
            || !is_sha256(&self.service_digest)
            || self.credential_revision == 0
            || self
                .revoked_at
                .is_some_and(|revoked_at| revoked_at.timestamp() < 0)
        {
            return Err(SecretBrokerError::InvalidSecretReference);
        }
        Ok(())
    }

    fn validate_for(
        &self,
        service: &SecretBrokerServiceDefinition,
    ) -> Result<(), SecretBrokerError> {
        service.validate()?;
        self.scope.validate()?;
        if !valid_prefixed_identifier(&self.reference_id, SECRET_REFERENCE_PREFIX)
            || self.service_digest != service.service_digest
            || self.credential_revision == 0
            || self
                .revoked_at
                .is_some_and(|revoked_at| revoked_at.timestamp() < 0)
        {
            return Err(SecretBrokerError::InvalidSecretReference);
        }
        Ok(())
    }

    fn revoke_at(&mut self, at: DateTime<Utc>) -> Result<(), SecretBrokerError> {
        if let Some(existing) = self.revoked_at {
            return if existing == at {
                Ok(())
            } else {
                Err(SecretBrokerError::AlreadyRevoked)
            };
        }
        self.revoked_at = Some(at);
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.digest())
            .field("service_digest", &self.service_digest)
            .field("scope_digest", &self.scope.digest())
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked_at.is_some())
            .finish_non_exhaustive()
    }
}

/// A Mission-owned consumer identity.  A consumer never receives secret bytes.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct SecretBrokerConsumer {
    consumer_id: String,
    tenant_id: TenantId,
    project_id: ProjectId,
    mission_id: MissionId,
}

impl SecretBrokerConsumer {
    pub fn new(
        consumer_id: impl Into<String>,
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: MissionId,
    ) -> Result<Self, SecretBrokerError> {
        let consumer = Self {
            consumer_id: consumer_id.into(),
            tenant_id,
            project_id,
            mission_id,
        };
        consumer.validate()?;
        Ok(consumer)
    }

    pub fn consumer_id(&self) -> &str {
        &self.consumer_id
    }

    pub fn digest(&self) -> String {
        digest_fields([
            "hartevo-secret-broker-consumer/v1",
            &self.consumer_id,
            self.tenant_id.as_str(),
            self.project_id.as_str(),
            self.mission_id.as_str(),
        ])
    }

    fn validate(&self) -> Result<(), SecretBrokerError> {
        if !valid_prefixed_identifier(&self.consumer_id, SECRET_CONSUMER_PREFIX)
            || !valid_identifier(self.tenant_id.as_str())
            || !valid_identifier(self.project_id.as_str())
            || !valid_identifier(self.mission_id.as_str())
        {
            return Err(SecretBrokerError::InvalidConsumer);
        }
        Ok(())
    }

    fn matches(&self, scope: &SecretScope) -> bool {
        self.tenant_id == *scope.tenant_id()
            && self.project_id == *scope.project_id()
            && self.mission_id == *scope.mission_id()
    }
}

impl fmt::Debug for SecretBrokerConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBrokerConsumer")
            .field("consumer_digest", &self.digest())
            .finish_non_exhaustive()
    }
}

/// Provider dispatch input. It carries only a Mission-scoped reference; the
/// broker resolves it into a short lease at the final provider boundary.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretProviderDispatch {
    reference: SecretReference,
    reference_digest: String,
}

impl SecretProviderDispatch {
    pub fn new(reference: SecretReference) -> Result<Self, SecretBrokerError> {
        reference.validate_unbound()?;
        let dispatch = Self {
            reference_digest: reference.digest(),
            reference,
        };
        dispatch.validate()?;
        Ok(dispatch)
    }

    pub fn reference(&self) -> &SecretReference {
        &self.reference
    }

    pub fn reference_digest(&self) -> &str {
        &self.reference_digest
    }

    pub fn scope(&self) -> &SecretScope {
        self.reference.scope()
    }

    pub const fn credential_revision(&self) -> u64 {
        self.reference.credential_revision()
    }

    pub fn validate(&self) -> Result<(), SecretBrokerError> {
        self.reference.validate_unbound()?;
        if !is_sha256(&self.reference_digest) || self.reference_digest != self.reference.digest() {
            return Err(SecretBrokerError::InvalidDispatch);
        }
        Ok(())
    }
}

impl fmt::Debug for SecretProviderDispatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretProviderDispatch")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope().digest())
            .field("credential_revision", &self.credential_revision())
            .finish_non_exhaustive()
    }
}

/// Opaque, short-lived credential-use capability.
///
/// The handle contains only references, scope metadata, revisions, and
/// lifecycle fences.  It cannot be converted into an Effect or a credential.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretUseHandle {
    handle_id: String,
    service_id: String,
    service_digest: String,
    reference_id: String,
    scope: SecretScope,
    consumer_id: String,
    adapter: ProviderAdapterIdentity,
    credential_revision: u64,
    lease_revision: u64,
    generation: u64,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    handle_digest: String,
}

impl SecretUseHandle {
    pub fn handle_id(&self) -> &str {
        &self.handle_id
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn service_digest(&self) -> &str {
        &self.service_digest
    }

    /// Returns the opaque reference identifier, never the referenced bytes.
    pub fn reference_id(&self) -> &str {
        &self.reference_id
    }

    pub const fn scope(&self) -> &SecretScope {
        &self.scope
    }

    pub fn consumer_id(&self) -> &str {
        &self.consumer_id
    }

    pub const fn adapter(&self) -> &ProviderAdapterIdentity {
        &self.adapter
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub const fn lease_revision(&self) -> u64 {
        self.lease_revision
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

    pub fn handle_digest(&self) -> &str {
        &self.handle_digest
    }

    fn unsigned_digest(&self) -> String {
        digest_fields([
            "hartevo-secret-use-handle/v1",
            &self.handle_id,
            &self.service_id,
            &self.service_digest,
            &self.reference_id,
            &self.scope.digest(),
            &self.consumer_id,
            self.adapter.adapter_id(),
            &self.adapter.adapter_version().to_string(),
            &self.credential_revision.to_string(),
            &self.lease_revision.to_string(),
            &self.generation.to_string(),
            &self.issued_at.to_rfc3339(),
            &self.expires_at.to_rfc3339(),
        ])
    }
}

impl fmt::Debug for SecretUseHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretUseHandle")
            .field("handle_digest", &self.handle_digest)
            .field("service_digest", &self.service_digest)
            .field("scope_digest", &self.scope.digest())
            .field(
                "consumer_digest",
                &digest_fields([self.consumer_id.as_str()]),
            )
            .field("adapter", &self.adapter)
            .field("credential_revision", &self.credential_revision)
            .field("lease_revision", &self.lease_revision)
            .field("generation", &self.generation)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Content-free receipt returned after a registered adapter consumes a handle.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretUseReceipt {
    use_digest: String,
    service_digest: String,
    scope_digest: String,
    adapter: ProviderAdapterIdentity,
    credential_revision: u64,
    lease_revision: u64,
    generation: u64,
    used_at: DateTime<Utc>,
    lease_reclaimed: bool,
}

impl SecretUseReceipt {
    pub const fn authority(&self) -> SecretUseAuthority {
        SecretUseAuthority::MissionScopedOpaqueCredentialUse
    }

    pub fn use_digest(&self) -> &str {
        &self.use_digest
    }

    pub fn service_digest(&self) -> &str {
        &self.service_digest
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub const fn adapter(&self) -> &ProviderAdapterIdentity {
        &self.adapter
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub const fn lease_revision(&self) -> u64 {
        self.lease_revision
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn used_at(&self) -> DateTime<Utc> {
        self.used_at
    }

    pub const fn lease_reclaimed(&self) -> bool {
        self.lease_reclaimed
    }
}

impl fmt::Debug for SecretUseReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretUseReceipt")
            .field("use_digest", &self.use_digest)
            .field("service_digest", &self.service_digest)
            .field("scope_digest", &self.scope_digest)
            .field("adapter", &self.adapter)
            .field("credential_revision", &self.credential_revision)
            .field("lease_revision", &self.lease_revision)
            .field("generation", &self.generation)
            .field("used_at", &self.used_at)
            .field("lease_reclaimed", &self.lease_reclaimed)
            .finish()
    }
}

/// Content-free lifecycle/audit event.  It contains only digests and counters.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretBrokerEventKind {
    Mounted,
    Unmounted,
    Revoked,
    Crashed,
    Reconnected,
    Rotated,
    CredentialUse,
    CredentialLeaseReclaimed,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretBrokerEvent {
    event_id: String,
    kind: SecretBrokerEventKind,
    service_digest: String,
    reference_digest: String,
    scope_digest: String,
    generation: u64,
    credential_revision: u64,
    lease_revision: Option<u64>,
    recorded_at: DateTime<Utc>,
}

impl SecretBrokerEvent {
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub const fn kind(&self) -> SecretBrokerEventKind {
        self.kind
    }

    pub fn service_digest(&self) -> &str {
        &self.service_digest
    }

    pub fn reference_digest(&self) -> &str {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub const fn lease_revision(&self) -> Option<u64> {
        self.lease_revision
    }

    pub const fn recorded_at(&self) -> DateTime<Utc> {
        self.recorded_at
    }
}

impl fmt::Debug for SecretBrokerEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBrokerEvent")
            .field("event_id", &self.event_id)
            .field("kind", &self.kind)
            .field("service_digest", &self.service_digest)
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("generation", &self.generation)
            .field("credential_revision", &self.credential_revision)
            .field("lease_revision", &self.lease_revision)
            .field("recorded_at", &self.recorded_at)
            .finish()
    }
}

/// Provider adapter boundary.  An adapter receives only an opaque handle and
/// can report success/failure; it cannot receive an Effect approval or secret
/// bytes through this trait.
pub trait SecretBrokerProvider {
    fn identity(&self) -> &ProviderAdapterIdentity;

    fn use_opaque_credential(
        &mut self,
        handle: &SecretUseHandle,
    ) -> Result<(), SecretProviderError>;
}

/// Errors returned by a provider adapter without exposing provider content.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SecretProviderError {
    #[error("provider adapter rejected the opaque credential handle")]
    Rejected,
    #[error("provider adapter is temporarily unavailable")]
    Unavailable,
}

/// Secret-broker service owner and lifecycle fence.
pub struct SecretBrokerService {
    definition: SecretBrokerServiceDefinition,
    reference: SecretReference,
    state: SecretBrokerState,
    generation: u64,
    mounted_at: Option<DateTime<Utc>>,
    lease_sequence: u64,
    active_leases: BTreeMap<String, ActiveLease>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveLease {
    generation: u64,
    lease_revision: u64,
}

impl SecretBrokerService {
    pub fn new(
        definition: SecretBrokerServiceDefinition,
        reference: SecretReference,
    ) -> Result<Self, SecretBrokerError> {
        definition.validate()?;
        reference.validate_for(&definition)?;
        Ok(Self {
            definition,
            reference,
            state: SecretBrokerState::Unmounted,
            generation: 0,
            mounted_at: None,
            lease_sequence: 0,
            active_leases: BTreeMap::new(),
        })
    }

    pub fn definition(&self) -> &SecretBrokerServiceDefinition {
        &self.definition
    }

    pub fn reference(&self) -> &SecretReference {
        &self.reference
    }

    pub const fn state(&self) -> SecretBrokerState {
        self.state
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn active_lease_count(&self) -> usize {
        self.active_leases.len()
    }

    /// Returns a reference-only dispatch for the configured credential.
    /// Calling this does not mount, authorize, or issue a lease.
    pub fn provider_dispatch(&self) -> Result<SecretProviderDispatch, SecretBrokerError> {
        self.reference.provider_dispatch()
    }

    pub fn mount(&mut self, at: DateTime<Utc>) -> Result<SecretBrokerEvent, SecretBrokerError> {
        if self.state == SecretBrokerState::Revoked {
            return Err(SecretBrokerError::ReferenceRevoked);
        }
        if self.state == SecretBrokerState::Mounted {
            return Err(SecretBrokerError::AlreadyMounted);
        }
        self.advance_generation()?;
        self.state = SecretBrokerState::Mounted;
        self.mounted_at = Some(at);
        Ok(self.lifecycle_event(SecretBrokerEventKind::Mounted, at, None))
    }

    pub fn unmount(&mut self, at: DateTime<Utc>) -> Result<SecretBrokerEvent, SecretBrokerError> {
        if self.state != SecretBrokerState::Mounted {
            return Err(self.state_error());
        }
        self.advance_generation()?;
        self.state = SecretBrokerState::Unmounted;
        self.mounted_at = None;
        Ok(self.lifecycle_event(SecretBrokerEventKind::Unmounted, at, None))
    }

    pub fn revoke(&mut self, at: DateTime<Utc>) -> Result<SecretBrokerEvent, SecretBrokerError> {
        if self.state == SecretBrokerState::Revoked {
            return Err(SecretBrokerError::ReferenceRevoked);
        }
        self.reference.revoke_at(at)?;
        self.advance_generation()?;
        self.state = SecretBrokerState::Revoked;
        self.mounted_at = None;
        Ok(self.lifecycle_event(SecretBrokerEventKind::Revoked, at, None))
    }

    pub fn crash(&mut self, at: DateTime<Utc>) -> Result<SecretBrokerEvent, SecretBrokerError> {
        if self.state != SecretBrokerState::Mounted {
            return Err(self.state_error());
        }
        self.advance_generation()?;
        self.state = SecretBrokerState::Crashed;
        self.mounted_at = None;
        Ok(self.lifecycle_event(SecretBrokerEventKind::Crashed, at, None))
    }

    pub fn reconnect(&mut self, at: DateTime<Utc>) -> Result<SecretBrokerEvent, SecretBrokerError> {
        if self.state == SecretBrokerState::Revoked {
            return Err(SecretBrokerError::ReferenceRevoked);
        }
        if self.state == SecretBrokerState::Mounted {
            return Err(SecretBrokerError::AlreadyMounted);
        }
        self.advance_generation()?;
        self.state = SecretBrokerState::Mounted;
        self.mounted_at = Some(at);
        Ok(self.lifecycle_event(SecretBrokerEventKind::Reconnected, at, None))
    }

    /// Rotates the opaque reference and fences every lease from the prior
    /// credential revision/generation.
    pub fn rotate(
        &mut self,
        successor: SecretReference,
        at: DateTime<Utc>,
    ) -> Result<SecretBrokerEvent, SecretBrokerError> {
        self.ensure_mounted()?;
        successor.validate_for(&self.definition)?;
        if successor.scope != self.reference.scope
            || successor.credential_revision <= self.reference.credential_revision
            || successor.is_revoked()
            || self.mounted_at.is_some_and(|mounted_at| at < mounted_at)
        {
            return Err(SecretBrokerError::InvalidRotation);
        }
        self.advance_generation()?;
        self.reference = successor;
        self.mounted_at = Some(at);
        Ok(self.lifecycle_event(SecretBrokerEventKind::Rotated, at, None))
    }

    /// Issues a Mission-scoped handle only for an exact registered adapter.
    #[allow(clippy::too_many_arguments)]
    fn issue_handle(
        &mut self,
        consumer: &SecretBrokerConsumer,
        registry: &ProviderAdapterRegistry,
        adapter: ProviderAdapterIdentity,
        handle_id: impl Into<String>,
        lease_revision: u64,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<SecretUseHandle, SecretBrokerError> {
        self.ensure_mounted()?;
        self.reference.validate_for(&self.definition)?;
        if !consumer.matches(self.reference.scope()) {
            return Err(SecretBrokerError::ConsumerScopeMismatch);
        }
        validate_registered_adapter(registry, self.reference.scope(), &adapter)?;
        if lease_revision == 0
            || issued_at < self.mounted_at.ok_or(SecretBrokerError::NotMounted)?
            || !valid_window(issued_at, expires_at, SECRET_BROKER_MAX_LEASE_TTL_SECONDS)
        {
            return Err(SecretBrokerError::InvalidLease);
        }
        let mut handle = SecretUseHandle {
            handle_id: handle_id.into(),
            service_id: self.definition.service_id.clone(),
            service_digest: self.definition.service_digest.clone(),
            reference_id: self.reference.reference_id.clone(),
            scope: self.reference.scope.clone(),
            consumer_id: consumer.consumer_id.clone(),
            adapter,
            credential_revision: self.reference.credential_revision,
            lease_revision,
            generation: self.generation,
            issued_at,
            expires_at,
            handle_digest: String::new(),
        };
        if !valid_prefixed_identifier(&handle.handle_id, SECRET_HANDLE_PREFIX) {
            return Err(SecretBrokerError::InvalidHandle);
        }
        handle.handle_digest = handle.unsigned_digest();
        if self.active_leases.contains_key(&handle.handle_digest) {
            return Err(SecretBrokerError::LeaseAlreadyActive);
        }
        self.active_leases.insert(
            handle.handle_digest.clone(),
            ActiveLease {
                generation: handle.generation,
                lease_revision: handle.lease_revision,
            },
        );
        Ok(handle)
    }

    fn resolve_dispatch(
        &mut self,
        consumer: &SecretBrokerConsumer,
        registry: &ProviderAdapterRegistry,
        adapter: ProviderAdapterIdentity,
        dispatch: &SecretProviderDispatch,
        now: DateTime<Utc>,
    ) -> Result<SecretUseHandle, SecretBrokerError> {
        self.ensure_mounted()?;
        dispatch.validate()?;
        if dispatch.reference != self.reference {
            return Err(SecretBrokerError::ReferenceDrift);
        }
        self.lease_sequence = self
            .lease_sequence
            .checked_add(1)
            .ok_or(SecretBrokerError::LeaseRevisionOverflow)?;
        let lease_revision = self.lease_sequence;
        let expires_at = now
            .checked_add_signed(Duration::seconds(
                i64::try_from(SECRET_BROKER_DISPATCH_LEASE_TTL_SECONDS)
                    .map_err(|_| SecretBrokerError::InvalidLease)?,
            ))
            .ok_or(SecretBrokerError::InvalidLease)?;
        self.issue_handle(
            consumer,
            registry,
            adapter,
            format!("{SECRET_HANDLE_PREFIX}{}-{lease_revision}", self.generation),
            lease_revision,
            now,
            expires_at,
        )
    }

    fn validate_handle(
        &self,
        consumer: &SecretBrokerConsumer,
        registry: &ProviderAdapterRegistry,
        adapter: &ProviderAdapterIdentity,
        handle: &SecretUseHandle,
        now: DateTime<Utc>,
    ) -> Result<(), SecretBrokerError> {
        self.ensure_mounted()?;
        self.reference.validate_for(&self.definition)?;
        if self.reference.is_revoked() {
            return Err(SecretBrokerError::ReferenceRevoked);
        }
        if handle.generation != self.generation {
            return Err(SecretBrokerError::GenerationMismatch);
        }
        if handle.service_id != self.definition.service_id
            || handle.service_digest != self.definition.service_digest
            || handle.reference_id != self.reference.reference_id
            || handle.scope != self.reference.scope
            || handle.credential_revision != self.reference.credential_revision
            || handle.consumer_id != consumer.consumer_id
            || !consumer.matches(&handle.scope)
            || handle.adapter != *adapter
            || !is_sha256(&handle.handle_digest)
            || handle.handle_digest != handle.unsigned_digest()
            || !valid_window_at(handle.issued_at, handle.expires_at, now)
        {
            return Err(SecretBrokerError::HandleMismatch);
        }
        let active = self
            .active_leases
            .get(handle.handle_digest())
            .ok_or(SecretBrokerError::LeaseNotActive)?;
        if active.generation != handle.generation || active.lease_revision != handle.lease_revision
        {
            return Err(SecretBrokerError::LeaseMismatch);
        }
        validate_registered_adapter(registry, &handle.scope, adapter)
    }

    fn reclaim_lease(&mut self, handle: &SecretUseHandle) -> Result<(), SecretBrokerError> {
        if self.active_leases.remove(handle.handle_digest()).is_none() {
            return Err(SecretBrokerError::LeaseNotActive);
        }
        Ok(())
    }

    fn ensure_mounted(&self) -> Result<(), SecretBrokerError> {
        match self.state {
            SecretBrokerState::Mounted => Ok(()),
            SecretBrokerState::Unmounted => Err(SecretBrokerError::Unmounted),
            SecretBrokerState::Revoked => Err(SecretBrokerError::ReferenceRevoked),
            SecretBrokerState::Crashed => Err(SecretBrokerError::Crashed),
        }
    }

    fn state_error(&self) -> SecretBrokerError {
        match self.state {
            SecretBrokerState::Unmounted => SecretBrokerError::Unmounted,
            SecretBrokerState::Mounted => SecretBrokerError::AlreadyMounted,
            SecretBrokerState::Revoked => SecretBrokerError::ReferenceRevoked,
            SecretBrokerState::Crashed => SecretBrokerError::Crashed,
        }
    }

    fn advance_generation(&mut self) -> Result<(), SecretBrokerError> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(SecretBrokerError::GenerationOverflow)?;
        self.active_leases.clear();
        Ok(())
    }

    fn lifecycle_event(
        &self,
        kind: SecretBrokerEventKind,
        recorded_at: DateTime<Utc>,
        lease_revision: Option<u64>,
    ) -> SecretBrokerEvent {
        let event_id = digest_fields([
            SECRET_EVENT_PREFIX,
            &self.definition.service_digest,
            &self.reference.digest(),
            &self.generation.to_string(),
            &format!("{kind:?}"),
            &recorded_at.to_rfc3339(),
        ]);
        SecretBrokerEvent {
            event_id,
            kind,
            service_digest: self.definition.service_digest.clone(),
            reference_digest: self.reference.digest(),
            scope_digest: self.reference.scope.digest(),
            generation: self.generation,
            credential_revision: self.reference.credential_revision,
            lease_revision,
            recorded_at,
        }
    }
}

impl fmt::Debug for SecretBrokerService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBrokerService")
            .field("service_digest", &self.definition.service_digest)
            .field("reference_digest", &self.reference.digest())
            .field("scope_digest", &self.reference.scope.digest())
            .field("state", &self.state)
            .field("generation", &self.generation)
            .field("mounted", &self.mounted_at.is_some())
            .finish_non_exhaustive()
    }
}

impl SecretBrokerConsumer {
    /// Resolves a reference-only dispatch into a short broker lease at the
    /// final provider boundary, then reclaims that lease after the adapter
    /// returns. Reusing the same dispatch performs a fresh authorization.
    pub fn dispatch_with_provider<P: SecretBrokerProvider>(
        &self,
        service: &mut SecretBrokerService,
        registry: &ProviderAdapterRegistry,
        provider: &mut P,
        dispatch: &SecretProviderDispatch,
        now: DateTime<Utc>,
    ) -> Result<SecretUseReceipt, SecretBrokerError> {
        let handle =
            service.resolve_dispatch(self, registry, provider.identity().clone(), dispatch, now)?;
        self.use_with_provider(service, registry, provider, &handle, now)
    }

    fn use_with_provider<P: SecretBrokerProvider>(
        &self,
        service: &mut SecretBrokerService,
        registry: &ProviderAdapterRegistry,
        provider: &mut P,
        handle: &SecretUseHandle,
        now: DateTime<Utc>,
    ) -> Result<SecretUseReceipt, SecretBrokerError> {
        service.validate_handle(self, registry, provider.identity(), handle, now)?;
        let provider_result = provider.use_opaque_credential(handle);
        service.reclaim_lease(handle)?;
        let provider_result = provider_result.map_err(SecretBrokerError::ProviderRejected);
        provider_result?;
        let receipt = SecretUseReceipt {
            use_digest: digest_fields([
                "hartevo-secret-broker-use/v1",
                handle.handle_digest(),
                &now.to_rfc3339(),
            ]),
            service_digest: handle.service_digest.clone(),
            scope_digest: handle.scope.digest(),
            adapter: handle.adapter.clone(),
            credential_revision: handle.credential_revision,
            lease_revision: handle.lease_revision,
            generation: handle.generation,
            used_at: now,
            lease_reclaimed: true,
        };
        Ok(receipt)
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SecretBrokerError {
    #[error("secret broker service definition is invalid")]
    InvalidServiceDefinition,
    #[error("secret broker scope is invalid")]
    InvalidScope,
    #[error("secret reference is invalid")]
    InvalidSecretReference,
    #[error("secret consumer is invalid")]
    InvalidConsumer,
    #[error("secret handle is invalid")]
    InvalidHandle,
    #[error("provider dispatch is invalid")]
    InvalidDispatch,
    #[error("secret lease is invalid or outside its bounded window")]
    InvalidLease,
    #[error("secret broker service is not mounted")]
    NotMounted,
    #[error("secret broker service is already mounted")]
    AlreadyMounted,
    #[error("secret broker service is unmounted")]
    Unmounted,
    #[error("secret broker reference is revoked")]
    ReferenceRevoked,
    #[error("secret broker service crashed")]
    Crashed,
    #[error("secret broker generation changed")]
    GenerationMismatch,
    #[error("secret reference changed and must be reauthorized")]
    ReferenceDrift,
    #[error("secret reference rotation is invalid")]
    InvalidRotation,
    #[error("secret consumer scope does not match the Mission reference")]
    ConsumerScopeMismatch,
    #[error("secret handle scope, revision, consumer, adapter, or window does not match")]
    HandleMismatch,
    #[error("secret broker generation overflowed")]
    GenerationOverflow,
    #[error("secret lease revision overflowed")]
    LeaseRevisionOverflow,
    #[error("secret lease is no longer active")]
    LeaseNotActive,
    #[error("secret lease generation or revision does not match")]
    LeaseMismatch,
    #[error("secret lease is already active")]
    LeaseAlreadyActive,
    #[error("secret reference was already revoked at another time")]
    AlreadyRevoked,
    #[error("provider adapter registry is invalid")]
    InvalidAdapterRegistry,
    #[error("provider capability has no registered adapter")]
    AdapterNotRegistered,
    #[error("provider adapter identity does not match the registration")]
    AdapterMismatch,
    #[error("provider capability is not registered for read-only secret use")]
    CapabilityNotReadOnly,
    #[error("provider capability is not registered for production secret use")]
    CapabilityNotProduction,
    #[error("provider adapter rejected the opaque credential use")]
    ProviderRejected(SecretProviderError),
}

fn validate_registered_adapter(
    registry: &ProviderAdapterRegistry,
    scope: &SecretScope,
    adapter: &ProviderAdapterIdentity,
) -> Result<(), SecretBrokerError> {
    registry
        .validate()
        .map_err(|_| SecretBrokerError::InvalidAdapterRegistry)?;
    let key = scope.capability_key()?;
    let registration = registry
        .registrations()
        .iter()
        .find(|registration| registration.key() == &key)
        .ok_or(SecretBrokerError::AdapterNotRegistered)?;
    if registration.adapter() != adapter {
        return Err(SecretBrokerError::AdapterMismatch);
    }
    if !registration.evidence_support().iter().any(|support| {
        matches!(
            support.operation(),
            ProviderAdapterOperation::Probe
                | ProviderAdapterOperation::BeginAuth
                | ProviderAdapterOperation::Refresh
                | ProviderAdapterOperation::Read
        )
    }) {
        return Err(SecretBrokerError::CapabilityNotReadOnly);
    }
    if !registration.evidence_support().iter().any(|support| {
        support.provenance_class() == ProviderProvenanceClass::ProductionProvider
            && matches!(
                support.operation(),
                ProviderAdapterOperation::Probe
                    | ProviderAdapterOperation::BeginAuth
                    | ProviderAdapterOperation::Refresh
                    | ProviderAdapterOperation::Read
            )
    }) {
        return Err(SecretBrokerError::CapabilityNotProduction);
    }
    Ok(())
}

fn valid_window(issued_at: DateTime<Utc>, expires_at: DateTime<Utc>, max_ttl_seconds: u64) -> bool {
    let Some(max_ttl) = i64::try_from(max_ttl_seconds).ok() else {
        return false;
    };
    let Some(max_expires_at) = issued_at.checked_add_signed(Duration::seconds(max_ttl)) else {
        return false;
    };
    issued_at < expires_at && expires_at <= max_expires_at
}

fn valid_window_at(
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> bool {
    issued_at <= now && now < expires_at
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn valid_prefixed_identifier(value: &str, prefix: &str) -> bool {
    value.len() > prefix.len() && value.starts_with(prefix) && valid_identifier(value)
}

fn digest_fields<'a>(fields: impl IntoIterator<Item = &'a str>) -> String {
    let mut digest = Sha256::new();
    for field in fields {
        digest.update(field.len().to_be_bytes());
        digest.update(field.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Alias used by callers that want to make the Mission scope explicit.
pub type MissionSecretReference = SecretReference;
/// Alias used by callers that want to make the Mission scope explicit.
pub type MissionSecretScope = SecretScope;

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::Value;

    use crate::provider_contract::{
        ProviderCapabilitySupport, ProviderEvidenceClass, ProviderEvidenceSupport,
        ProviderProvenanceClass,
    };

    struct TestProvider {
        identity: ProviderAdapterIdentity,
        use_count: usize,
        last_handle_digest: Option<String>,
        last_reference_id: Option<String>,
        last_generation: Option<u64>,
        last_lease_revision: Option<u64>,
        return_error: Option<SecretProviderError>,
    }

    impl SecretBrokerProvider for TestProvider {
        fn identity(&self) -> &ProviderAdapterIdentity {
            &self.identity
        }

        fn use_opaque_credential(
            &mut self,
            handle: &SecretUseHandle,
        ) -> Result<(), SecretProviderError> {
            self.use_count += 1;
            self.last_handle_digest = Some(handle.handle_digest().to_owned());
            self.last_reference_id = Some(handle.reference_id().to_owned());
            self.last_generation = Some(handle.generation());
            self.last_lease_revision = Some(handle.lease_revision());
            self.return_error.take().map_or(Ok(()), Err)
        }
    }

    fn test_provider(identity: ProviderAdapterIdentity) -> TestProvider {
        TestProvider {
            identity,
            use_count: 0,
            last_handle_digest: None,
            last_reference_id: None,
            last_generation: None,
            last_lease_revision: None,
            return_error: None,
        }
    }

    fn instant(offset_seconds: i64) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z")
            .expect("timestamp")
            .with_timezone(&Utc)
            + Duration::seconds(offset_seconds)
    }

    fn adapter(version: u32) -> ProviderAdapterIdentity {
        ProviderAdapterIdentity::new("hartevo.dataforseo", version).expect("adapter")
    }

    fn scope() -> SecretScope {
        SecretScope::new(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            MissionId::from("mission-1"),
            "dataforseo",
            AccountId::from("account-1"),
            "search.measure",
        )
        .expect("scope")
    }

    fn consumer() -> SecretBrokerConsumer {
        SecretBrokerConsumer::new(
            "secret-consumer-1",
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            MissionId::from("mission-1"),
        )
        .expect("consumer")
    }

    fn registry(identity: ProviderAdapterIdentity) -> ProviderAdapterRegistry {
        ProviderAdapterRegistry::new(
            "secret-broker-test/v1",
            [ProviderCapabilitySupport::new(
                ProviderCapabilityKey::new("dataforseo", "search.measure").expect("key"),
                identity,
                [ProviderEvidenceSupport::new(
                    ProviderAdapterOperation::Read,
                    ProviderEvidenceClass::ReadObservation,
                    ProviderProvenanceClass::ProductionProvider,
                )
                .expect("support")],
            )
            .expect("registration")],
        )
        .expect("registry")
    }

    fn mounted_service() -> SecretBrokerService {
        let definition = SecretBrokerServiceDefinition::production().expect("definition");
        let reference = SecretReference::new("secret-ref-dataforseo-1", &definition, scope(), 7)
            .expect("reference");
        let mut service = SecretBrokerService::new(definition, reference).expect("service");
        service.mount(instant(0)).expect("mount");
        service
    }

    fn handle(service: &mut SecretBrokerService) -> SecretUseHandle {
        service
            .issue_handle(
                &consumer(),
                &registry(adapter(1)),
                adapter(1),
                "secret-use-1",
                11,
                instant(1),
                instant(300),
            )
            .expect("handle")
    }

    #[test]
    fn only_registered_read_adapter_receives_opaque_handle() {
        let mut service = mounted_service();
        let handle = handle(&mut service);
        let mut provider = test_provider(adapter(1));
        let receipt = consumer()
            .use_with_provider(
                &mut service,
                &registry(adapter(1)),
                &mut provider,
                &handle,
                instant(2),
            )
            .expect("opaque use");
        assert_eq!(
            receipt.authority(),
            SecretUseAuthority::MissionScopedOpaqueCredentialUse
        );
        assert_eq!(receipt.generation(), 1);
        assert_eq!(receipt.credential_revision(), 7);
        assert_eq!(receipt.lease_revision(), 11);
        assert_eq!(
            provider.last_handle_digest.as_deref(),
            Some(handle.handle_digest())
        );
        assert_eq!(
            provider.last_reference_id.as_deref(),
            Some("secret-ref-dataforseo-1")
        );
        assert!(receipt.lease_reclaimed());
        assert_eq!(service.active_lease_count(), 0);
    }

    #[test]
    fn reference_only_dispatch_resolves_at_service_boundary_and_reauthorizes_replay() {
        let mut service = mounted_service();
        let dispatch = service.provider_dispatch().expect("dispatch");
        let dispatch_json = serde_json::to_value(&dispatch).expect("dispatch JSON");
        assert!(dispatch_json.get("reference").is_some());
        assert!(dispatch_json.get("handleId").is_none());
        assert!(dispatch_json.get("leaseRevision").is_none());
        assert!(dispatch_json.get("expiresAt").is_none());

        let mut provider = test_provider(adapter(1));
        let first = consumer()
            .dispatch_with_provider(
                &mut service,
                &registry(adapter(1)),
                &mut provider,
                &dispatch,
                instant(2),
            )
            .expect("first dispatch");
        let second = consumer()
            .dispatch_with_provider(
                &mut service,
                &registry(adapter(1)),
                &mut provider,
                &dispatch,
                instant(3),
            )
            .expect("replayed reference dispatch");

        let receipt_json = serde_json::to_value(&second).expect("receipt JSON");
        assert!(receipt_json.get("handleId").is_none());
        assert!(receipt_json.get("plaintext").is_none());
        assert_eq!(provider.use_count, 2);
        assert_eq!(provider.last_generation, Some(1));
        assert_eq!(
            provider.last_reference_id.as_deref(),
            Some("secret-ref-dataforseo-1")
        );
        assert_ne!(first.lease_revision(), second.lease_revision());
        assert!(first.lease_reclaimed());
        assert!(second.lease_reclaimed());
        assert_eq!(service.active_lease_count(), 0);
    }

    #[test]
    fn provider_return_reclaims_lease_even_when_adapter_rejects() {
        let mut service = mounted_service();
        let dispatch = service.provider_dispatch().expect("dispatch");
        let mut provider = test_provider(adapter(1));
        provider.return_error = Some(SecretProviderError::Rejected);
        assert_eq!(
            consumer().dispatch_with_provider(
                &mut service,
                &registry(adapter(1)),
                &mut provider,
                &dispatch,
                instant(2),
            ),
            Err(SecretBrokerError::ProviderRejected(
                SecretProviderError::Rejected
            ))
        );
        assert_eq!(provider.use_count, 1);
        assert_eq!(service.active_lease_count(), 0);

        provider.return_error = None;
        let receipt = consumer()
            .dispatch_with_provider(
                &mut service,
                &registry(adapter(1)),
                &mut provider,
                &dispatch,
                instant(3),
            )
            .expect("fresh authorization after rejection");
        assert!(receipt.lease_reclaimed());
        assert_eq!(provider.use_count, 2);
    }

    #[test]
    fn cross_scope_consumer_and_adapter_replay_is_rejected() {
        let mut service = mounted_service();
        let handle = handle(&mut service);
        let wrong_consumer = SecretBrokerConsumer::new(
            "secret-consumer-2",
            TenantId::from("tenant-1"),
            ProjectId::from("project-2"),
            MissionId::from("mission-1"),
        )
        .expect("wrong consumer");
        let mut provider = test_provider(adapter(1));
        assert_eq!(
            wrong_consumer.use_with_provider(
                &mut service,
                &registry(adapter(1)),
                &mut provider,
                &handle,
                instant(2),
            ),
            Err(SecretBrokerError::HandleMismatch)
        );

        let mut wrong_provider =
            test_provider(ProviderAdapterIdentity::new("hartevo.sorftime", 1).expect("provider"));
        assert_eq!(
            consumer().use_with_provider(
                &mut service,
                &registry(adapter(1)),
                &mut wrong_provider,
                &handle,
                instant(2),
            ),
            Err(SecretBrokerError::HandleMismatch)
        );
    }

    #[test]
    fn unmount_revoke_and_crash_invalidate_immediately() {
        let mut unmounted = mounted_service();
        let old_handle = handle(&mut unmounted);
        unmounted.unmount(instant(2)).expect("unmount");
        let mut provider = test_provider(adapter(1));
        assert_eq!(
            consumer().use_with_provider(
                &mut unmounted,
                &registry(adapter(1)),
                &mut provider,
                &old_handle,
                instant(2),
            ),
            Err(SecretBrokerError::Unmounted)
        );

        let mut revoked = mounted_service();
        let old_handle = handle(&mut revoked);
        revoked.revoke(instant(2)).expect("revoke");
        assert_eq!(
            consumer().use_with_provider(
                &mut revoked,
                &registry(adapter(1)),
                &mut provider,
                &old_handle,
                instant(2),
            ),
            Err(SecretBrokerError::ReferenceRevoked)
        );

        let mut crashed = mounted_service();
        let old_handle = handle(&mut crashed);
        crashed.crash(instant(2)).expect("crash");
        assert_eq!(
            consumer().use_with_provider(
                &mut crashed,
                &registry(adapter(1)),
                &mut provider,
                &old_handle,
                instant(2),
            ),
            Err(SecretBrokerError::Crashed)
        );
    }

    #[test]
    fn reconnect_retires_old_generation_and_issues_new_handle() {
        let mut service = mounted_service();
        let old_handle = handle(&mut service);
        service.crash(instant(2)).expect("crash");
        service.reconnect(instant(3)).expect("reconnect");
        assert_eq!(service.generation(), 3);

        let mut provider = test_provider(adapter(1));
        assert_eq!(
            consumer().use_with_provider(
                &mut service,
                &registry(adapter(1)),
                &mut provider,
                &old_handle,
                instant(4),
            ),
            Err(SecretBrokerError::GenerationMismatch)
        );

        let new_handle = service
            .issue_handle(
                &consumer(),
                &registry(adapter(1)),
                adapter(1),
                "secret-use-2",
                12,
                instant(4),
                instant(300),
            )
            .expect("new handle");
        let receipt = consumer()
            .use_with_provider(
                &mut service,
                &registry(adapter(1)),
                &mut provider,
                &new_handle,
                instant(5),
            )
            .expect("new generation use");
        assert_eq!(receipt.generation(), 3);
    }

    #[test]
    fn rotation_fences_old_reference_and_generation_before_new_dispatch() {
        let mut service = mounted_service();
        let old_dispatch = service.provider_dispatch().expect("old dispatch");
        let old_handle = handle(&mut service);
        let definition = service.definition().clone();
        let successor = SecretReference::new("secret-ref-dataforseo-2", &definition, scope(), 8)
            .expect("successor");
        service.rotate(successor, instant(2)).expect("rotate");
        assert_eq!(service.generation(), 2);
        assert_eq!(service.reference().credential_revision(), 8);
        assert_eq!(service.active_lease_count(), 0);

        let mut provider = test_provider(adapter(1));
        assert_eq!(
            consumer().dispatch_with_provider(
                &mut service,
                &registry(adapter(1)),
                &mut provider,
                &old_dispatch,
                instant(3),
            ),
            Err(SecretBrokerError::ReferenceDrift)
        );
        assert_eq!(
            consumer().use_with_provider(
                &mut service,
                &registry(adapter(1)),
                &mut provider,
                &old_handle,
                instant(3),
            ),
            Err(SecretBrokerError::GenerationMismatch)
        );

        let new_dispatch = service.provider_dispatch().expect("new dispatch");
        let receipt = consumer()
            .dispatch_with_provider(
                &mut service,
                &registry(adapter(1)),
                &mut provider,
                &new_dispatch,
                instant(3),
            )
            .expect("new dispatch");
        assert_eq!(receipt.credential_revision(), 8);
        assert_eq!(receipt.generation(), 2);
    }

    #[test]
    fn expired_or_reclaimed_lease_is_not_reusable() {
        let mut service = mounted_service();
        let expired = service
            .issue_handle(
                &consumer(),
                &registry(adapter(1)),
                adapter(1),
                "secret-use-expired",
                99,
                instant(1),
                instant(2),
            )
            .expect("expired handle");
        let mut provider = test_provider(adapter(1));
        assert_eq!(
            consumer().use_with_provider(
                &mut service,
                &registry(adapter(1)),
                &mut provider,
                &expired,
                instant(2),
            ),
            Err(SecretBrokerError::HandleMismatch)
        );
        assert_eq!(service.active_lease_count(), 1);
        service.reclaim_lease(&expired).expect("reclaim expired");
        assert_eq!(service.active_lease_count(), 0);
        assert_eq!(
            consumer().use_with_provider(
                &mut service,
                &registry(adapter(1)),
                &mut provider,
                &expired,
                instant(1),
            ),
            Err(SecretBrokerError::LeaseNotActive)
        );
    }

    #[test]
    fn empty_or_effect_only_registry_is_denied() {
        let mut service = mounted_service();
        assert_eq!(
            service.issue_handle(
                &consumer(),
                &ProviderAdapterRegistry::contract_baseline().expect("baseline"),
                adapter(1),
                "secret-use-1",
                1,
                instant(1),
                instant(2),
            ),
            Err(SecretBrokerError::AdapterNotRegistered)
        );

        let effect_only = ProviderAdapterRegistry::new(
            "secret-broker-test/v1",
            [ProviderCapabilitySupport::new(
                ProviderCapabilityKey::new("dataforseo", "search.measure").expect("key"),
                adapter(1),
                [ProviderEvidenceSupport::new(
                    ProviderAdapterOperation::Execute,
                    ProviderEvidenceClass::ReceiptCandidate,
                    ProviderProvenanceClass::ProductionProvider,
                )
                .expect("support")],
            )
            .expect("registration")],
        )
        .expect("registry");
        assert_eq!(
            service.issue_handle(
                &consumer(),
                &effect_only,
                adapter(1),
                "secret-use-1",
                1,
                instant(1),
                instant(2),
            ),
            Err(SecretBrokerError::CapabilityNotReadOnly)
        );

        let fixture_only = ProviderAdapterRegistry::new(
            "secret-broker-test/v1",
            [ProviderCapabilitySupport::new(
                ProviderCapabilityKey::new("dataforseo", "search.measure").expect("key"),
                adapter(1),
                [ProviderEvidenceSupport::new(
                    ProviderAdapterOperation::Read,
                    ProviderEvidenceClass::ReadObservation,
                    ProviderProvenanceClass::Fixture,
                )
                .expect("support")],
            )
            .expect("registration")],
        )
        .expect("registry");
        assert_eq!(
            service.issue_handle(
                &consumer(),
                &fixture_only,
                adapter(1),
                "secret-use-fixture",
                2,
                instant(1),
                instant(2),
            ),
            Err(SecretBrokerError::CapabilityNotProduction)
        );
    }

    #[test]
    fn debug_and_events_redact_reference_and_handle_content() {
        let mut service = mounted_service();
        let handle = handle(&mut service);
        let dispatch = service.provider_dispatch().expect("dispatch");
        let debug = format!(
            "{:?} {:?} {:?} {:?}",
            service.reference(),
            service,
            handle,
            dispatch
        );
        assert!(!debug.contains("token-value"));
        assert!(!debug.contains("secret-bytes"));
        assert!(!debug.contains("credential-value"));
        assert!(debug.contains("scope_digest"));
        let error = SecretBrokerError::ProviderRejected(SecretProviderError::Rejected);
        assert!(!format!("{error}").contains("secret-bytes"));

        let event = service.unmount(instant(2)).expect("event");
        let encoded = serde_json::to_string(&event).expect("event JSON");
        assert!(!encoded.contains("token-value"));
        assert!(!encoded.contains("secret-bytes"));
        assert!(!encoded.contains("credential-value"));
        let value: Value = serde_json::from_str(&encoded).expect("event value");
        assert!(value.get("scopeDigest").is_some());
        assert!(value.get("credentialRevision").is_some());
        assert!(value.get("rawToken").is_none());
    }

    #[test]
    fn lease_window_equality_and_overflow_fail_closed() {
        let mut service = mounted_service();
        assert_eq!(
            service.issue_handle(
                &consumer(),
                &registry(adapter(1)),
                adapter(1),
                "secret-use-1",
                1,
                instant(1),
                instant(1),
            ),
            Err(SecretBrokerError::InvalidLease)
        );
        assert_eq!(
            service.issue_handle(
                &consumer(),
                &registry(adapter(1)),
                adapter(1),
                "secret-use-1",
                1,
                instant(1),
                instant(902),
            ),
            Err(SecretBrokerError::InvalidLease)
        );
        let overflow = DateTime::<Utc>::MAX_UTC;
        assert_eq!(
            service.issue_handle(
                &consumer(),
                &registry(adapter(1)),
                adapter(1),
                "secret-use-1",
                1,
                overflow,
                overflow,
            ),
            Err(SecretBrokerError::InvalidLease)
        );
    }
}
