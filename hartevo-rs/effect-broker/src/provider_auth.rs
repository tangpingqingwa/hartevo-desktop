//! Opaque credential, authentication-session, and live Provider probe boundaries.
//!
//! This module can authorize only a point-in-time `Connected` projection. It
//! cannot approve or execute an Effect, manufacture a Provider Receipt, claim
//! business verification, or raise evidence to E4.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use hartevo_domain_kernel::{AccountId, ProjectId, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::provider_contract::{
    PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION, ProviderAdapterIdentity, ProviderAdapterOperation,
    ProviderAdapterRegistry, ProviderCapabilityKey, ProviderEvidenceClass, ProviderProvenanceClass,
};

pub const PROVIDER_AUTH_PROBE_SCHEMA_VERSION: &str = "hartevo-provider-auth-probe-contract/v1";
pub const PROVIDER_AUTH_PROBE_CONTRACT_VERSION: &str = "provider-auth-probe-e1/v1";
pub const PROVIDER_AUTH_PROBE_CONTRACT_JSON: &str =
    include_str!("../../../contracts/providers/auth-probe.v1.json");

const CONNECTION_PROBE_CAPABILITY: &str = "connection.probe";
const CREDENTIAL_LEASE_MAX_TTL_SECONDS: u64 = 900;
const AUTH_SESSION_MAX_TTL_SECONDS: u64 = 600;
const PROBE_MAX_TTL_SECONDS: u64 = 120;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectedAuthority {
    ConnectionStateOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Reachable,
    Unreachable,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum SecretMaterialPolicy {
    OpaqueReferenceOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum AdapterRegistrySource {
    ProviderAdapterRegistry,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum EmptyRegistryBehavior {
    DenyConnected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum ForbiddenAuthority {
    RuntimeLocalApproval,
    ProviderExecution,
    ProviderReceipt,
    BusinessVerification,
    E4,
}

impl ForbiddenAuthority {
    const ALL: [Self; 5] = [
        Self::RuntimeLocalApproval,
        Self::ProviderExecution,
        Self::ProviderReceipt,
        Self::BusinessVerification,
        Self::E4,
    ];
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryBinding {
    capability_id: String,
    operation: ProviderAdapterOperation,
    evidence_class: ProviderEvidenceClass,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryPolicy {
    source: AdapterRegistrySource,
    empty_registry_behavior: EmptyRegistryBehavior,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct FreshnessPolicy {
    #[serde(rename = "credentialLeaseMaxTtlSeconds")]
    credential_lease_max_ttl: u64,
    #[serde(rename = "authSessionMaxTtlSeconds")]
    auth_session_max_ttl: u64,
    #[serde(rename = "probeMaxTtlSeconds")]
    probe_max_ttl: u64,
    #[serde(rename = "clockSkewSeconds")]
    clock_skew: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderAuthProbePolicy {
    schema_version: String,
    contract_version: String,
    secret_material: SecretMaterialPolicy,
    connected_authority: ConnectedAuthority,
    adapter_registry_schema_version: String,
    registry_binding: RegistryBinding,
    registry_policy: RegistryPolicy,
    freshness: FreshnessPolicy,
    connected_probe_statuses: Vec<ProbeStatus>,
    connected_provenance_classes: Vec<ProviderProvenanceClass>,
    forbidden_authorities: Vec<ForbiddenAuthority>,
}

impl ProviderAuthProbePolicy {
    pub fn contract_baseline() -> Result<Self, ProviderAuthProbeError> {
        Self::from_contract_json(PROVIDER_AUTH_PROBE_CONTRACT_JSON)
    }

    pub fn from_contract_json(contract_json: &str) -> Result<Self, ProviderAuthProbeError> {
        let policy = serde_json::from_str::<Self>(contract_json)
            .map_err(|_| ProviderAuthProbeError::InvalidContractDocument)?;
        policy.validate()?;
        Ok(policy)
    }

    pub const fn connected_authority(&self) -> ConnectedAuthority {
        ConnectedAuthority::ConnectionStateOnly
    }

    pub const fn credential_lease_max_ttl_seconds(&self) -> u64 {
        self.freshness.credential_lease_max_ttl
    }

    pub const fn auth_session_max_ttl_seconds(&self) -> u64 {
        self.freshness.auth_session_max_ttl
    }

    pub const fn probe_max_ttl_seconds(&self) -> u64 {
        self.freshness.probe_max_ttl
    }

    pub fn validate(&self) -> Result<(), ProviderAuthProbeError> {
        if self.schema_version != PROVIDER_AUTH_PROBE_SCHEMA_VERSION {
            return Err(ProviderAuthProbeError::InvalidSchemaVersion);
        }
        if self.contract_version != PROVIDER_AUTH_PROBE_CONTRACT_VERSION {
            return Err(ProviderAuthProbeError::InvalidContractVersion);
        }
        if self.secret_material != SecretMaterialPolicy::OpaqueReferenceOnly
            || self.connected_authority != ConnectedAuthority::ConnectionStateOnly
            || self.adapter_registry_schema_version != PROVIDER_ADAPTER_CONTRACT_SCHEMA_VERSION
            || self.registry_policy.source != AdapterRegistrySource::ProviderAdapterRegistry
            || self.registry_policy.empty_registry_behavior != EmptyRegistryBehavior::DenyConnected
        {
            return Err(ProviderAuthProbeError::InvalidAuthorityBoundary);
        }
        if self.registry_binding.capability_id != CONNECTION_PROBE_CAPABILITY
            || self.registry_binding.operation != ProviderAdapterOperation::Probe
            || self.registry_binding.evidence_class != ProviderEvidenceClass::ProbeObservation
        {
            return Err(ProviderAuthProbeError::InvalidRegistryBinding);
        }
        if self.freshness.credential_lease_max_ttl != CREDENTIAL_LEASE_MAX_TTL_SECONDS
            || self.freshness.auth_session_max_ttl != AUTH_SESSION_MAX_TTL_SECONDS
            || self.freshness.probe_max_ttl != PROBE_MAX_TTL_SECONDS
            || self.freshness.clock_skew != 0
        {
            return Err(ProviderAuthProbeError::InvalidFreshnessPolicy);
        }
        validate_exact_set(
            &self.connected_probe_statuses,
            &[ProbeStatus::Reachable],
            "connected probe statuses",
        )?;
        validate_exact_set(
            &self.connected_provenance_classes,
            &[ProviderProvenanceClass::ProductionProvider],
            "connected provenance classes",
        )?;
        validate_exact_set(
            &self.forbidden_authorities,
            &ForbiddenAuthority::ALL,
            "forbidden authorities",
        )?;
        Ok(())
    }

    pub fn issue_credential_lease(
        &self,
        secret_reference: &SecretReference,
        adapter: ProviderAdapterIdentity,
        lease_id: impl Into<String>,
        lease_revision: u64,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<CredentialLease, ProviderAuthProbeError> {
        let lease = CredentialLease {
            lease_id: lease_id.into(),
            scope: secret_reference.scope.clone(),
            secret_reference_id: secret_reference.reference_id.clone(),
            credential_revision: secret_reference.credential_revision,
            adapter,
            lease_revision,
            issued_at,
            expires_at,
            revoked_at: None,
        };
        self.validate_credential_lease(secret_reference, &lease, issued_at)?;
        Ok(lease)
    }

    pub fn begin_auth_session(
        &self,
        secret_reference: &SecretReference,
        credential_lease: &CredentialLease,
        session_id: impl Into<String>,
        auth_revision: u64,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<AuthSession, ProviderAuthProbeError> {
        self.validate_credential_lease(secret_reference, credential_lease, issued_at)?;
        let session = AuthSession {
            session_id: session_id.into(),
            scope: credential_lease.scope.clone(),
            secret_reference_id: credential_lease.secret_reference_id.clone(),
            credential_revision: credential_lease.credential_revision,
            lease_id: credential_lease.lease_id.clone(),
            lease_revision: credential_lease.lease_revision,
            adapter: credential_lease.adapter.clone(),
            auth_revision,
            issued_at,
            expires_at,
            revoked_at: None,
        };
        self.validate_auth_session(secret_reference, credential_lease, &session, issued_at)?;
        Ok(session)
    }

    pub fn record_probe(
        &self,
        secret_reference: &SecretReference,
        credential_lease: &CredentialLease,
        auth_session: &AuthSession,
        observation: ProbeObservation,
    ) -> Result<ProbeResult, ProviderAuthProbeError> {
        self.validate_auth_session(
            secret_reference,
            credential_lease,
            auth_session,
            observation.observed_at,
        )?;
        let mut result = ProbeResult {
            result_id: observation.result_id,
            scope: auth_session.scope.clone(),
            secret_reference_id: auth_session.secret_reference_id.clone(),
            credential_revision: auth_session.credential_revision,
            lease_id: auth_session.lease_id.clone(),
            lease_revision: auth_session.lease_revision,
            auth_session_id: auth_session.session_id.clone(),
            auth_revision: auth_session.auth_revision,
            adapter: auth_session.adapter.clone(),
            probe_revision: observation.probe_revision,
            status: observation.status,
            provenance_class: observation.provenance_class,
            observed_at: observation.observed_at,
            expires_at: observation.expires_at,
            evidence_digest: observation.evidence_digest,
            binding_digest: String::new(),
        };
        result.binding_digest = probe_binding_digest(&result);
        self.validate_probe_result(
            secret_reference,
            credential_lease,
            auth_session,
            &result,
            result.observed_at,
        )?;
        Ok(result)
    }

    pub fn authorize_connected(
        &self,
        secret_reference: &SecretReference,
        credential_lease: &CredentialLease,
        auth_session: &AuthSession,
        probe_result: &ProbeResult,
        now: DateTime<Utc>,
    ) -> Result<ConnectedAuthorization, ProviderAuthProbeError> {
        let adapter_registry = ProviderAdapterRegistry::contract_baseline()
            .map_err(|_| ProviderAuthProbeError::InvalidAdapterRegistry)?;
        self.authorize_connected_against_registry(
            &adapter_registry,
            secret_reference,
            credential_lease,
            auth_session,
            probe_result,
            now,
        )
    }

    fn authorize_connected_against_registry(
        &self,
        adapter_registry: &ProviderAdapterRegistry,
        secret_reference: &SecretReference,
        credential_lease: &CredentialLease,
        auth_session: &AuthSession,
        probe_result: &ProbeResult,
        now: DateTime<Utc>,
    ) -> Result<ConnectedAuthorization, ProviderAuthProbeError> {
        self.validate_probe_result(
            secret_reference,
            credential_lease,
            auth_session,
            probe_result,
            now,
        )?;
        if !self.connected_probe_statuses.contains(&probe_result.status) {
            return Err(ProviderAuthProbeError::ProbeNotReachable);
        }
        if !self
            .connected_provenance_classes
            .contains(&probe_result.provenance_class)
        {
            return Err(ProviderAuthProbeError::UnsupportedConnectedProvenance);
        }
        adapter_registry
            .validate()
            .map_err(|_| ProviderAuthProbeError::InvalidAdapterRegistry)?;
        let probe_key = ProviderCapabilityKey::new(
            probe_result.scope.provider_id.clone(),
            CONNECTION_PROBE_CAPABILITY,
        )
        .map_err(|_| ProviderAuthProbeError::InvalidScope)?;
        let registration = adapter_registry
            .registrations()
            .iter()
            .find(|registration| registration.key() == &probe_key)
            .ok_or(ProviderAuthProbeError::UnknownAdapter)?;
        if registration.adapter() != &probe_result.adapter {
            return Err(ProviderAuthProbeError::UnknownAdapter);
        }
        let supports_probe = registration.evidence_support().iter().any(|support| {
            support.operation() == ProviderAdapterOperation::Probe
                && support.evidence_class() == ProviderEvidenceClass::ProbeObservation
                && support.provenance_class() == probe_result.provenance_class
        });
        if !supports_probe {
            return Err(ProviderAuthProbeError::UnsupportedProbeRegistration);
        }
        Ok(ConnectedAuthorization {
            scope: probe_result.scope.clone(),
            adapter: probe_result.adapter.clone(),
            credential_revision: probe_result.credential_revision,
            lease_revision: probe_result.lease_revision,
            auth_revision: probe_result.auth_revision,
            probe_revision: probe_result.probe_revision,
            provenance_class: probe_result.provenance_class,
            evidence_digest: probe_result.evidence_digest.clone(),
            authorized_at: now,
            observed_valid_until: probe_result.expires_at,
        })
    }

    fn validate_credential_lease(
        &self,
        secret_reference: &SecretReference,
        credential_lease: &CredentialLease,
        now: DateTime<Utc>,
    ) -> Result<(), ProviderAuthProbeError> {
        secret_reference.validate()?;
        credential_lease.validate(self)?;
        if credential_lease.scope != secret_reference.scope {
            return Err(ProviderAuthProbeError::ScopeMismatch);
        }
        if credential_lease.secret_reference_id != secret_reference.reference_id
            || credential_lease.credential_revision != secret_reference.credential_revision
        {
            return Err(ProviderAuthProbeError::CredentialRevisionMismatch);
        }
        if secret_reference.is_revoked_at(now) {
            return Err(ProviderAuthProbeError::SecretReferenceRevoked);
        }
        if credential_lease.is_revoked_at(now) {
            return Err(ProviderAuthProbeError::CredentialLeaseRevoked);
        }
        if !is_live_window(credential_lease.issued_at, credential_lease.expires_at, now) {
            return Err(ProviderAuthProbeError::CredentialLeaseStale);
        }
        Ok(())
    }

    fn validate_auth_session(
        &self,
        secret_reference: &SecretReference,
        credential_lease: &CredentialLease,
        auth_session: &AuthSession,
        now: DateTime<Utc>,
    ) -> Result<(), ProviderAuthProbeError> {
        self.validate_credential_lease(secret_reference, credential_lease, now)?;
        auth_session.validate(self)?;
        if auth_session.scope != credential_lease.scope {
            return Err(ProviderAuthProbeError::ScopeMismatch);
        }
        if auth_session.secret_reference_id != credential_lease.secret_reference_id
            || auth_session.credential_revision != credential_lease.credential_revision
            || auth_session.lease_id != credential_lease.lease_id
            || auth_session.lease_revision != credential_lease.lease_revision
        {
            return Err(ProviderAuthProbeError::AuthRevisionMismatch);
        }
        if auth_session.adapter != credential_lease.adapter {
            return Err(ProviderAuthProbeError::AdapterMismatch);
        }
        if auth_session.expires_at > credential_lease.expires_at {
            return Err(ProviderAuthProbeError::InvalidTtl);
        }
        if auth_session.is_revoked_at(now) {
            return Err(ProviderAuthProbeError::AuthSessionRevoked);
        }
        if !is_live_window(auth_session.issued_at, auth_session.expires_at, now) {
            return Err(ProviderAuthProbeError::AuthSessionStale);
        }
        Ok(())
    }

    fn validate_probe_result(
        &self,
        secret_reference: &SecretReference,
        credential_lease: &CredentialLease,
        auth_session: &AuthSession,
        probe_result: &ProbeResult,
        now: DateTime<Utc>,
    ) -> Result<(), ProviderAuthProbeError> {
        self.validate_auth_session(secret_reference, credential_lease, auth_session, now)?;
        probe_result.validate(self)?;
        if probe_result.scope != auth_session.scope {
            return Err(ProviderAuthProbeError::ScopeMismatch);
        }
        if probe_result.secret_reference_id != auth_session.secret_reference_id
            || probe_result.credential_revision != auth_session.credential_revision
            || probe_result.lease_id != auth_session.lease_id
            || probe_result.lease_revision != auth_session.lease_revision
            || probe_result.auth_session_id != auth_session.session_id
            || probe_result.auth_revision != auth_session.auth_revision
        {
            return Err(ProviderAuthProbeError::ProbeRevisionMismatch);
        }
        if probe_result.adapter != auth_session.adapter {
            return Err(ProviderAuthProbeError::AdapterMismatch);
        }
        if probe_result.expires_at > auth_session.expires_at
            || probe_result.expires_at > credential_lease.expires_at
        {
            return Err(ProviderAuthProbeError::InvalidTtl);
        }
        if now < probe_result.observed_at || now >= probe_result.expires_at {
            return Err(ProviderAuthProbeError::ProbeStale);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderAuthScope {
    tenant_id: TenantId,
    project_id: ProjectId,
    provider_id: String,
    account_id: AccountId,
    scopes: Vec<String>,
}

impl ProviderAuthScope {
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        provider_id: impl Into<String>,
        account_id: AccountId,
        scopes: impl IntoIterator<Item = String>,
    ) -> Result<Self, ProviderAuthProbeError> {
        let mut scopes = scopes.into_iter().collect::<Vec<_>>();
        scopes.sort();
        let scope = Self {
            tenant_id,
            project_id,
            provider_id: provider_id.into(),
            account_id,
            scopes,
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

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    fn validate(&self) -> Result<(), ProviderAuthProbeError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.account_id.as_str().trim().is_empty()
            || self.scopes.is_empty()
            || ProviderCapabilityKey::new(self.provider_id.clone(), CONNECTION_PROBE_CAPABILITY)
                .is_err()
            || self.scopes.iter().any(|scope| !valid_scope_value(scope))
            || self.scopes.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(ProviderAuthProbeError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    reference_id: String,
    scope: ProviderAuthScope,
    credential_revision: u64,
    revoked_at: Option<DateTime<Utc>>,
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: ProviderAuthScope,
        credential_revision: u64,
    ) -> Result<Self, ProviderAuthProbeError> {
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

    pub const fn scope(&self) -> &ProviderAuthScope {
        &self.scope
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub fn revoke(&mut self, revoked_at: DateTime<Utc>) -> Result<(), ProviderAuthProbeError> {
        if let Some(existing) = self.revoked_at {
            return if existing == revoked_at {
                Ok(())
            } else {
                Err(ProviderAuthProbeError::AlreadyRevoked)
            };
        }
        self.revoked_at = Some(revoked_at);
        Ok(())
    }

    fn validate(&self) -> Result<(), ProviderAuthProbeError> {
        self.scope.validate()?;
        if !valid_opaque_identifier(&self.reference_id, "secret-ref-")
            || self.credential_revision == 0
        {
            return Err(ProviderAuthProbeError::InvalidSecretReference);
        }
        Ok(())
    }

    fn is_revoked_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_some_and(|revoked_at| revoked_at <= now)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialLease {
    lease_id: String,
    scope: ProviderAuthScope,
    secret_reference_id: String,
    credential_revision: u64,
    adapter: ProviderAdapterIdentity,
    lease_revision: u64,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl CredentialLease {
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    pub const fn scope(&self) -> &ProviderAuthScope {
        &self.scope
    }

    pub const fn adapter(&self) -> &ProviderAdapterIdentity {
        &self.adapter
    }

    pub const fn lease_revision(&self) -> u64 {
        self.lease_revision
    }

    pub fn revoke(&mut self, revoked_at: DateTime<Utc>) -> Result<(), ProviderAuthProbeError> {
        if revoked_at < self.issued_at {
            return Err(ProviderAuthProbeError::InvalidRevocation);
        }
        if let Some(existing) = self.revoked_at {
            return if existing == revoked_at {
                Ok(())
            } else {
                Err(ProviderAuthProbeError::AlreadyRevoked)
            };
        }
        self.revoked_at = Some(revoked_at);
        Ok(())
    }

    fn validate(&self, policy: &ProviderAuthProbePolicy) -> Result<(), ProviderAuthProbeError> {
        self.scope.validate()?;
        validate_adapter(&self.adapter)?;
        if !valid_opaque_identifier(&self.lease_id, "credential-lease-")
            || !valid_opaque_identifier(&self.secret_reference_id, "secret-ref-")
            || self.credential_revision == 0
            || self.lease_revision == 0
        {
            return Err(ProviderAuthProbeError::InvalidCredentialLease);
        }
        validate_window(
            self.issued_at,
            self.expires_at,
            self.revoked_at,
            policy.credential_lease_max_ttl_seconds(),
        )
    }

    fn is_revoked_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_some_and(|revoked_at| revoked_at <= now)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthSession {
    session_id: String,
    scope: ProviderAuthScope,
    secret_reference_id: String,
    credential_revision: u64,
    lease_id: String,
    lease_revision: u64,
    adapter: ProviderAdapterIdentity,
    auth_revision: u64,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl AuthSession {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub const fn scope(&self) -> &ProviderAuthScope {
        &self.scope
    }

    pub const fn adapter(&self) -> &ProviderAdapterIdentity {
        &self.adapter
    }

    pub const fn auth_revision(&self) -> u64 {
        self.auth_revision
    }

    pub fn revoke(&mut self, revoked_at: DateTime<Utc>) -> Result<(), ProviderAuthProbeError> {
        if revoked_at < self.issued_at {
            return Err(ProviderAuthProbeError::InvalidRevocation);
        }
        if let Some(existing) = self.revoked_at {
            return if existing == revoked_at {
                Ok(())
            } else {
                Err(ProviderAuthProbeError::AlreadyRevoked)
            };
        }
        self.revoked_at = Some(revoked_at);
        Ok(())
    }

    fn validate(&self, policy: &ProviderAuthProbePolicy) -> Result<(), ProviderAuthProbeError> {
        self.scope.validate()?;
        validate_adapter(&self.adapter)?;
        if !valid_opaque_identifier(&self.session_id, "auth-session-")
            || !valid_opaque_identifier(&self.secret_reference_id, "secret-ref-")
            || !valid_opaque_identifier(&self.lease_id, "credential-lease-")
            || self.credential_revision == 0
            || self.lease_revision == 0
            || self.auth_revision == 0
        {
            return Err(ProviderAuthProbeError::InvalidAuthSession);
        }
        validate_window(
            self.issued_at,
            self.expires_at,
            self.revoked_at,
            policy.auth_session_max_ttl_seconds(),
        )
    }

    fn is_revoked_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_some_and(|revoked_at| revoked_at <= now)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeObservation {
    result_id: String,
    probe_revision: u64,
    status: ProbeStatus,
    provenance_class: ProviderProvenanceClass,
    observed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    evidence_digest: String,
}

impl ProbeObservation {
    pub fn new(
        result_id: impl Into<String>,
        probe_revision: u64,
        status: ProbeStatus,
        provenance_class: ProviderProvenanceClass,
        observed_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        evidence_digest: impl Into<String>,
    ) -> Self {
        Self {
            result_id: result_id.into(),
            probe_revision,
            status,
            provenance_class,
            observed_at,
            expires_at,
            evidence_digest: evidence_digest.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProbeResult {
    result_id: String,
    scope: ProviderAuthScope,
    secret_reference_id: String,
    credential_revision: u64,
    lease_id: String,
    lease_revision: u64,
    auth_session_id: String,
    auth_revision: u64,
    adapter: ProviderAdapterIdentity,
    probe_revision: u64,
    status: ProbeStatus,
    provenance_class: ProviderProvenanceClass,
    observed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    evidence_digest: String,
    binding_digest: String,
}

impl ProbeResult {
    pub const fn scope(&self) -> &ProviderAuthScope {
        &self.scope
    }

    pub const fn adapter(&self) -> &ProviderAdapterIdentity {
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

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    fn validate(&self, policy: &ProviderAuthProbePolicy) -> Result<(), ProviderAuthProbeError> {
        self.scope.validate()?;
        validate_adapter(&self.adapter)?;
        if !valid_opaque_identifier(&self.result_id, "probe-result-")
            || !valid_opaque_identifier(&self.secret_reference_id, "secret-ref-")
            || !valid_opaque_identifier(&self.lease_id, "credential-lease-")
            || !valid_opaque_identifier(&self.auth_session_id, "auth-session-")
            || self.credential_revision == 0
            || self.lease_revision == 0
            || self.auth_revision == 0
            || self.probe_revision == 0
            || !is_canonical_sha256(&self.evidence_digest)
            || !is_canonical_sha256(&self.binding_digest)
            || self.binding_digest != probe_binding_digest(self)
        {
            return Err(ProviderAuthProbeError::InvalidProbeResult);
        }
        validate_window(
            self.observed_at,
            self.expires_at,
            None,
            policy.probe_max_ttl_seconds(),
        )
    }
}

/// A point-in-time authorization for a `Connected` projection only.
///
/// It is deliberately not convertible into an Effect approval or execution
/// permit:
///
/// ```compile_fail
/// use hartevo_effect_broker::ConnectedAuthorization;
/// use hartevo_domain_kernel::Approval;
///
/// fn illegal_upgrade(connected: ConnectedAuthorization) -> Approval {
///     connected.into()
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectedAuthorization {
    scope: ProviderAuthScope,
    adapter: ProviderAdapterIdentity,
    credential_revision: u64,
    lease_revision: u64,
    auth_revision: u64,
    probe_revision: u64,
    provenance_class: ProviderProvenanceClass,
    evidence_digest: String,
    authorized_at: DateTime<Utc>,
    observed_valid_until: DateTime<Utc>,
}

impl ConnectedAuthorization {
    pub const fn authority(&self) -> ConnectedAuthority {
        ConnectedAuthority::ConnectionStateOnly
    }

    pub const fn scope(&self) -> &ProviderAuthScope {
        &self.scope
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

    pub const fn auth_revision(&self) -> u64 {
        self.auth_revision
    }

    pub const fn probe_revision(&self) -> u64 {
        self.probe_revision
    }

    pub const fn provenance_class(&self) -> ProviderProvenanceClass {
        self.provenance_class
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub const fn authorized_at(&self) -> DateTime<Utc> {
        self.authorized_at
    }

    pub const fn observed_valid_until(&self) -> DateTime<Utc> {
        self.observed_valid_until
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderAuthProbeError {
    #[error("Provider auth/probe contract JSON is malformed, incomplete, duplicated, or unknown")]
    InvalidContractDocument,
    #[error("Provider auth/probe schema version is not supported")]
    InvalidSchemaVersion,
    #[error("Provider auth/probe contract version is not supported")]
    InvalidContractVersion,
    #[error("Provider auth/probe contract authority boundary is invalid")]
    InvalidAuthorityBoundary,
    #[error("Provider auth/probe registry binding is invalid")]
    InvalidRegistryBinding,
    #[error("Provider auth/probe freshness policy is invalid")]
    InvalidFreshnessPolicy,
    #[error("Provider auth/probe contract repeats a value in {0}")]
    DuplicateContractValue(&'static str),
    #[error("Provider auth/probe contract does not declare the exact {0} set")]
    ContractSetMismatch(&'static str),
    #[error("Provider auth scope is invalid or non-canonical")]
    InvalidScope,
    #[error("opaque secret reference is invalid")]
    InvalidSecretReference,
    #[error("credential lease is invalid")]
    InvalidCredentialLease,
    #[error("authentication session is invalid")]
    InvalidAuthSession,
    #[error("Provider probe result is invalid")]
    InvalidProbeResult,
    #[error("Provider adapter identity or version is invalid")]
    InvalidAdapter,
    #[error("freshness window or TTL is invalid")]
    InvalidTtl,
    #[error("revocation timestamp is invalid")]
    InvalidRevocation,
    #[error("credential object was already revoked at another time")]
    AlreadyRevoked,
    #[error("opaque secret reference is revoked")]
    SecretReferenceRevoked,
    #[error("credential lease is revoked")]
    CredentialLeaseRevoked,
    #[error("authentication session is revoked")]
    AuthSessionRevoked,
    #[error("credential lease is not live")]
    CredentialLeaseStale,
    #[error("authentication session is not live")]
    AuthSessionStale,
    #[error("Provider probe result is not live")]
    ProbeStale,
    #[error("tenant/project/provider/account/scope binding changed")]
    ScopeMismatch,
    #[error("credential revision changed")]
    CredentialRevisionMismatch,
    #[error("authentication or credential-lease revision changed")]
    AuthRevisionMismatch,
    #[error("probe, auth, credential, or lease revision changed")]
    ProbeRevisionMismatch,
    #[error("Provider adapter identity or version changed")]
    AdapterMismatch,
    #[error("Provider adapter registry is invalid")]
    InvalidAdapterRegistry,
    #[error("no registered adapter supports this Provider connection probe")]
    UnknownAdapter,
    #[error("registered adapter does not support the exact probe provenance")]
    UnsupportedProbeRegistration,
    #[error("Provider probe did not prove reachability")]
    ProbeNotReachable,
    #[error("Provider probe provenance cannot authorize Connected")]
    UnsupportedConnectedProvenance,
}

fn validate_exact_set<T: Copy + Ord>(
    values: &[T],
    expected: &[T],
    label: &'static str,
) -> Result<(), ProviderAuthProbeError> {
    let actual = values.iter().copied().collect::<BTreeSet<_>>();
    if actual.len() != values.len() {
        return Err(ProviderAuthProbeError::DuplicateContractValue(label));
    }
    if actual != expected.iter().copied().collect::<BTreeSet<_>>() {
        return Err(ProviderAuthProbeError::ContractSetMismatch(label));
    }
    Ok(())
}

fn validate_adapter(adapter: &ProviderAdapterIdentity) -> Result<(), ProviderAuthProbeError> {
    ProviderAdapterIdentity::new(adapter.adapter_id(), adapter.adapter_version())
        .map(|_| ())
        .map_err(|_| ProviderAuthProbeError::InvalidAdapter)
}

fn validate_window(
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    max_ttl_seconds: u64,
) -> Result<(), ProviderAuthProbeError> {
    let max_ttl = i64::try_from(max_ttl_seconds)
        .ok()
        .and_then(|seconds| issued_at.checked_add_signed(Duration::seconds(seconds)))
        .ok_or(ProviderAuthProbeError::InvalidTtl)?;
    if expires_at <= issued_at
        || expires_at > max_ttl
        || revoked_at.is_some_and(|revoked_at| revoked_at < issued_at)
    {
        return Err(ProviderAuthProbeError::InvalidTtl);
    }
    Ok(())
}

fn is_live_window(issued_at: DateTime<Utc>, expires_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    issued_at <= now && now < expires_at
}

fn valid_scope_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.is_ascii()
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_opaque_identifier(value: &str, prefix: &str) -> bool {
    value.len() > prefix.len()
        && value.len() <= 128
        && value.starts_with(prefix)
        && value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn probe_binding_digest(probe_result: &ProbeResult) -> String {
    let mut digest = Sha256::new();
    hash_field(&mut digest, "hartevo-provider-probe-binding/v1");
    hash_field(&mut digest, probe_result.scope.tenant_id.as_str());
    hash_field(&mut digest, probe_result.scope.project_id.as_str());
    hash_field(&mut digest, &probe_result.scope.provider_id);
    hash_field(&mut digest, probe_result.scope.account_id.as_str());
    hash_field(&mut digest, &probe_result.scope.scopes.len().to_string());
    for scope in &probe_result.scope.scopes {
        hash_field(&mut digest, scope);
    }
    hash_field(&mut digest, &probe_result.secret_reference_id);
    hash_field(&mut digest, &probe_result.credential_revision.to_string());
    hash_field(&mut digest, &probe_result.lease_id);
    hash_field(&mut digest, &probe_result.lease_revision.to_string());
    hash_field(&mut digest, &probe_result.auth_session_id);
    hash_field(&mut digest, &probe_result.auth_revision.to_string());
    hash_field(&mut digest, probe_result.adapter.adapter_id());
    hash_field(
        &mut digest,
        &probe_result.adapter.adapter_version().to_string(),
    );
    hash_field(&mut digest, &probe_result.probe_revision.to_string());
    hash_field(&mut digest, probe_status_name(probe_result.status));
    hash_field(
        &mut digest,
        provenance_class_name(probe_result.provenance_class),
    );
    hash_field(&mut digest, &probe_result.observed_at.to_rfc3339());
    hash_field(&mut digest, &probe_result.expires_at.to_rfc3339());
    hash_field(&mut digest, &probe_result.evidence_digest);
    format!("{:x}", digest.finalize())
}

const fn probe_status_name(status: ProbeStatus) -> &'static str {
    match status {
        ProbeStatus::Reachable => "reachable",
        ProbeStatus::Unreachable => "unreachable",
        ProbeStatus::Rejected => "rejected",
    }
}

const fn provenance_class_name(provenance: ProviderProvenanceClass) -> &'static str {
    match provenance {
        ProviderProvenanceClass::Fixture => "fixture",
        ProviderProvenanceClass::ComponentHarness => "component_harness",
        ProviderProvenanceClass::ControlledProvider => "controlled_provider",
        ProviderProvenanceClass::ProductionProvider => "production_provider",
    }
}

fn hash_field(digest: &mut Sha256, value: &str) {
    digest.update(value.len().to_be_bytes());
    digest.update(value.as_bytes());
}

fn is_canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;
    use serde_json::{Value, json};

    use crate::provider_contract::{ProviderCapabilitySupport, ProviderEvidenceSupport};

    struct LiveChain {
        policy: ProviderAuthProbePolicy,
        secret: SecretReference,
        lease: CredentialLease,
        session: AuthSession,
        probe: ProbeResult,
        now: DateTime<Utc>,
    }

    fn instant(offset_seconds: i64) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-12T00:00:00Z")
            .expect("timestamp")
            .with_timezone(&Utc)
            + Duration::seconds(offset_seconds)
    }

    fn adapter(version: u32) -> ProviderAdapterIdentity {
        ProviderAdapterIdentity::new("hartevo.github", version).expect("adapter")
    }

    fn scope() -> ProviderAuthScope {
        ProviderAuthScope::new(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            "github",
            AccountId::from("account-1"),
            ["repo.read".to_owned(), "user.read".to_owned()],
        )
        .expect("scope")
    }

    fn live_chain(status: ProbeStatus, provenance_class: ProviderProvenanceClass) -> LiveChain {
        let policy = ProviderAuthProbePolicy::contract_baseline().expect("policy");
        let secret = SecretReference::new("secret-ref-1", scope(), 1).expect("secret reference");
        let lease = policy
            .issue_credential_lease(
                &secret,
                adapter(1),
                "credential-lease-1",
                2,
                instant(0),
                instant(600),
            )
            .expect("credential lease");
        let session = policy
            .begin_auth_session(
                &secret,
                &lease,
                "auth-session-1",
                3,
                instant(1),
                instant(301),
            )
            .expect("auth session");
        let probe = policy
            .record_probe(
                &secret,
                &lease,
                &session,
                ProbeObservation::new(
                    "probe-result-1",
                    4,
                    status,
                    provenance_class,
                    instant(2),
                    instant(62),
                    "a".repeat(64),
                ),
            )
            .expect("probe result");
        LiveChain {
            policy,
            secret,
            lease,
            session,
            probe,
            now: instant(3),
        }
    }

    fn registered_registry(
        adapter: ProviderAdapterIdentity,
        provenance_class: ProviderProvenanceClass,
    ) -> ProviderAdapterRegistry {
        ProviderAdapterRegistry::new(
            "auth-probe-test/v1",
            [ProviderCapabilitySupport::new(
                ProviderCapabilityKey::new("github", CONNECTION_PROBE_CAPABILITY).expect("key"),
                adapter,
                [ProviderEvidenceSupport::new(
                    ProviderAdapterOperation::Probe,
                    ProviderEvidenceClass::ProbeObservation,
                    provenance_class,
                )
                .expect("probe support")],
            )
            .expect("registration")],
        )
        .expect("registry")
    }

    fn production_registry() -> ProviderAdapterRegistry {
        registered_registry(adapter(1), ProviderProvenanceClass::ProductionProvider)
    }

    fn authorize(
        chain: &LiveChain,
        registry: &ProviderAdapterRegistry,
    ) -> Result<ConnectedAuthorization, ProviderAuthProbeError> {
        chain.policy.authorize_connected_against_registry(
            registry,
            &chain.secret,
            &chain.lease,
            &chain.session,
            &chain.probe,
            chain.now,
        )
    }

    fn contract_value() -> Value {
        serde_json::from_str(PROVIDER_AUTH_PROBE_CONTRACT_JSON).expect("contract JSON")
    }

    fn parse_tampered_contract(
        tamper: impl FnOnce(&mut Value),
    ) -> Result<ProviderAuthProbePolicy, ProviderAuthProbeError> {
        let mut value = contract_value();
        tamper(&mut value);
        ProviderAuthProbePolicy::from_contract_json(
            &serde_json::to_string(&value).expect("tampered JSON"),
        )
    }

    #[test]
    fn checked_in_contract_is_connection_state_only() {
        let policy = ProviderAuthProbePolicy::contract_baseline().expect("typed contract");
        policy.validate().expect("valid contract");
        assert_eq!(
            policy.connected_authority(),
            ConnectedAuthority::ConnectionStateOnly
        );
        assert_eq!(policy.credential_lease_max_ttl_seconds(), 900);
        assert_eq!(policy.auth_session_max_ttl_seconds(), 600);
        assert_eq!(policy.probe_max_ttl_seconds(), 120);
    }

    #[test]
    fn unregistered_provider_makes_connected_unreachable() {
        let chain = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        let registry = ProviderAdapterRegistry::contract_baseline().expect("actual registry");
        assert!(!registry.is_empty());
        assert_eq!(
            chain.policy.authorize_connected(
                &chain.secret,
                &chain.lease,
                &chain.session,
                &chain.probe,
                chain.now,
            ),
            Err(ProviderAuthProbeError::UnknownAdapter)
        );
    }

    #[test]
    fn registered_live_probe_authorizes_only_connected_state() {
        let chain = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        let authorization = authorize(&chain, &production_registry()).expect("Connected gate");
        assert_eq!(
            authorization.authority(),
            ConnectedAuthority::ConnectionStateOnly
        );
        assert_eq!(authorization.scope(), chain.probe.scope());
        assert_eq!(authorization.adapter(), &adapter(1));
        assert_eq!(authorization.credential_revision(), 1);
        assert_eq!(authorization.lease_revision(), 2);
        assert_eq!(authorization.auth_revision(), 3);
        assert_eq!(authorization.probe_revision(), 4);
        assert_eq!(
            authorization.provenance_class(),
            ProviderProvenanceClass::ProductionProvider
        );
        let expected_evidence_digest = "a".repeat(64);
        assert_eq!(
            authorization.evidence_digest(),
            expected_evidence_digest.as_str()
        );
        assert!(authorization.authorized_at() < authorization.observed_valid_until());
    }

    #[test]
    fn exact_tenant_project_provider_account_and_scope_are_required() {
        let registry = production_registry();

        let mut tenant = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        tenant.lease.scope.tenant_id = TenantId::from("tenant-2");
        assert_eq!(
            authorize(&tenant, &registry),
            Err(ProviderAuthProbeError::ScopeMismatch)
        );

        let mut project = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        project.lease.scope.project_id = ProjectId::from("project-2");
        assert_eq!(
            authorize(&project, &registry),
            Err(ProviderAuthProbeError::ScopeMismatch)
        );

        let mut provider = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        provider.lease.scope.provider_id = "gitlab".into();
        assert_eq!(
            authorize(&provider, &registry),
            Err(ProviderAuthProbeError::ScopeMismatch)
        );

        let mut account = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        account.lease.scope.account_id = AccountId::from("account-2");
        assert_eq!(
            authorize(&account, &registry),
            Err(ProviderAuthProbeError::ScopeMismatch)
        );

        let mut scopes = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        scopes.lease.scope.scopes.push("write.read".into());
        assert_eq!(
            authorize(&scopes, &registry),
            Err(ProviderAuthProbeError::ScopeMismatch)
        );
    }

    #[test]
    fn adapter_identity_and_all_revisions_are_bound() {
        let registry = production_registry();

        let mut credential = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        credential.secret.credential_revision = 2;
        assert_eq!(
            authorize(&credential, &registry),
            Err(ProviderAuthProbeError::CredentialRevisionMismatch)
        );

        let mut lease = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        lease.lease.lease_revision = 9;
        assert_eq!(
            authorize(&lease, &registry),
            Err(ProviderAuthProbeError::AuthRevisionMismatch)
        );

        let mut auth = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        auth.session.auth_revision = 9;
        assert_eq!(
            authorize(&auth, &registry),
            Err(ProviderAuthProbeError::ProbeRevisionMismatch)
        );

        let mut probe = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        probe.probe.probe_revision = 9;
        assert_eq!(
            authorize(&probe, &registry),
            Err(ProviderAuthProbeError::InvalidProbeResult)
        );

        let mut adapter_identity = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        adapter_identity.lease.adapter =
            ProviderAdapterIdentity::new("hartevo.gitlab", 1).expect("adapter identity");
        assert_eq!(
            authorize(&adapter_identity, &registry),
            Err(ProviderAuthProbeError::AdapterMismatch)
        );

        let mut adapter_version = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        adapter_version.lease.adapter = adapter(2);
        assert_eq!(
            authorize(&adapter_version, &registry),
            Err(ProviderAuthProbeError::AdapterMismatch)
        );
    }

    #[test]
    fn stale_credential_auth_and_probe_are_rejected() {
        let registry = production_registry();

        let mut probe = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        probe.now = instant(62);
        assert_eq!(
            authorize(&probe, &registry),
            Err(ProviderAuthProbeError::ProbeStale)
        );

        let mut auth = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        auth.now = instant(301);
        assert_eq!(
            authorize(&auth, &registry),
            Err(ProviderAuthProbeError::AuthSessionStale)
        );

        let mut lease = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        lease.now = instant(600);
        assert_eq!(
            authorize(&lease, &registry),
            Err(ProviderAuthProbeError::CredentialLeaseStale)
        );
    }

    #[test]
    fn secret_lease_and_auth_revocation_fail_closed() {
        let registry = production_registry();

        let mut secret = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        secret.secret.revoke(secret.now).expect("revoke secret");
        assert_eq!(
            authorize(&secret, &registry),
            Err(ProviderAuthProbeError::SecretReferenceRevoked)
        );

        let mut lease = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        lease.lease.revoke(lease.now).expect("revoke lease");
        assert_eq!(
            authorize(&lease, &registry),
            Err(ProviderAuthProbeError::CredentialLeaseRevoked)
        );

        let mut auth = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        auth.session.revoke(auth.now).expect("revoke auth");
        assert_eq!(
            authorize(&auth, &registry),
            Err(ProviderAuthProbeError::AuthSessionRevoked)
        );
    }

    #[test]
    fn status_provenance_and_evidence_tamper_fail_closed() {
        let unreachable = live_chain(
            ProbeStatus::Unreachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        assert_eq!(
            authorize(&unreachable, &production_registry()),
            Err(ProviderAuthProbeError::ProbeNotReachable)
        );

        let controlled = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ControlledProvider,
        );
        let controlled_registry =
            registered_registry(adapter(1), ProviderProvenanceClass::ControlledProvider);
        assert_eq!(
            authorize(&controlled, &controlled_registry),
            Err(ProviderAuthProbeError::UnsupportedConnectedProvenance)
        );

        let mut evidence = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        evidence.probe.evidence_digest = "b".repeat(64);
        assert_eq!(
            authorize(&evidence, &production_registry()),
            Err(ProviderAuthProbeError::InvalidProbeResult)
        );
    }

    #[test]
    fn unknown_adapter_and_wrong_registered_provenance_fail_closed() {
        let chain = live_chain(
            ProbeStatus::Reachable,
            ProviderProvenanceClass::ProductionProvider,
        );
        assert_eq!(
            authorize(
                &chain,
                &registered_registry(adapter(2), ProviderProvenanceClass::ProductionProvider),
            ),
            Err(ProviderAuthProbeError::UnknownAdapter)
        );
        assert_eq!(
            authorize(
                &chain,
                &registered_registry(adapter(1), ProviderProvenanceClass::ControlledProvider),
            ),
            Err(ProviderAuthProbeError::UnsupportedProbeRegistration)
        );
    }

    #[test]
    fn ttl_boundaries_are_enforced_at_each_layer() {
        let policy = ProviderAuthProbePolicy::contract_baseline().expect("policy");
        let secret = SecretReference::new("secret-ref-1", scope(), 1).expect("secret");
        assert_eq!(
            policy.issue_credential_lease(
                &secret,
                adapter(1),
                "credential-lease-1",
                1,
                instant(0),
                instant(901),
            ),
            Err(ProviderAuthProbeError::InvalidTtl)
        );

        let lease = policy
            .issue_credential_lease(
                &secret,
                adapter(1),
                "credential-lease-1",
                1,
                instant(0),
                instant(900),
            )
            .expect("lease");
        assert_eq!(
            policy.begin_auth_session(
                &secret,
                &lease,
                "auth-session-1",
                1,
                instant(1),
                instant(602),
            ),
            Err(ProviderAuthProbeError::InvalidTtl)
        );

        let session = policy
            .begin_auth_session(
                &secret,
                &lease,
                "auth-session-1",
                1,
                instant(1),
                instant(601),
            )
            .expect("session");
        assert_eq!(
            policy.record_probe(
                &secret,
                &lease,
                &session,
                ProbeObservation::new(
                    "probe-result-1",
                    1,
                    ProbeStatus::Reachable,
                    ProviderProvenanceClass::ProductionProvider,
                    instant(2),
                    instant(123),
                    "a".repeat(64),
                ),
            ),
            Err(ProviderAuthProbeError::InvalidTtl)
        );
    }

    #[test]
    fn top_level_unknown_missing_and_duplicate_fields_fail_closed() {
        assert_eq!(
            parse_tampered_contract(|value| {
                value
                    .as_object_mut()
                    .expect("contract")
                    .insert("unknownField".into(), json!(true));
            }),
            Err(ProviderAuthProbeError::InvalidContractDocument)
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value
                    .as_object_mut()
                    .expect("contract")
                    .remove("registryBinding");
            }),
            Err(ProviderAuthProbeError::InvalidContractDocument)
        );

        let duplicate_schema = PROVIDER_AUTH_PROBE_CONTRACT_JSON.replacen(
            "{\n",
            "{\n  \"schemaVersion\": \"hartevo-provider-auth-probe-contract/v1\",\n",
            1,
        );
        assert_eq!(
            ProviderAuthProbePolicy::from_contract_json(&duplicate_schema),
            Err(ProviderAuthProbeError::InvalidContractDocument)
        );
    }

    #[test]
    fn schema_contract_and_authority_tamper_fail_closed() {
        assert_eq!(
            parse_tampered_contract(|value| {
                value["schemaVersion"] = json!("hartevo-provider-auth-probe-contract/v2");
            }),
            Err(ProviderAuthProbeError::InvalidSchemaVersion)
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["contractVersion"] = json!("provider-auth-probe-e1/v2");
            }),
            Err(ProviderAuthProbeError::InvalidContractVersion)
        );
        for (field, tampered_value) in [
            ("secretMaterial", "secret_value_allowed"),
            ("connectedAuthority", "provider_execution"),
        ] {
            assert_eq!(
                parse_tampered_contract(|value| {
                    value[field] = json!(tampered_value);
                }),
                Err(ProviderAuthProbeError::InvalidContractDocument)
            );
        }
        assert_eq!(
            parse_tampered_contract(|value| {
                value["adapterRegistrySchemaVersion"] =
                    json!("hartevo-provider-adapter-contract/v2");
            }),
            Err(ProviderAuthProbeError::InvalidAuthorityBoundary)
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["registryPolicy"]["source"] = json!("runtime_metadata");
            }),
            Err(ProviderAuthProbeError::InvalidContractDocument)
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["registryPolicy"]["emptyRegistryBehavior"] = json!("allow_connected");
            }),
            Err(ProviderAuthProbeError::InvalidContractDocument)
        );
    }

    #[test]
    fn registry_binding_unknown_missing_duplicate_and_value_tamper_fail_closed() {
        for (field, tampered_value) in [
            ("capabilityId", "connection.read"),
            ("operation", "read"),
            ("evidenceClass", "read_observation"),
        ] {
            assert_eq!(
                parse_tampered_contract(|value| {
                    value["registryBinding"][field] = json!(tampered_value);
                }),
                Err(ProviderAuthProbeError::InvalidRegistryBinding)
            );
        }
        assert_eq!(
            parse_tampered_contract(|value| {
                value["registryBinding"]
                    .as_object_mut()
                    .expect("registry binding")
                    .insert("unknownField".into(), json!(true));
            }),
            Err(ProviderAuthProbeError::InvalidContractDocument)
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["registryBinding"]
                    .as_object_mut()
                    .expect("registry binding")
                    .remove("operation");
            }),
            Err(ProviderAuthProbeError::InvalidContractDocument)
        );

        let duplicate_operation = PROVIDER_AUTH_PROBE_CONTRACT_JSON.replacen(
            "    \"operation\": \"probe\",\n",
            concat!(
                "    \"operation\": \"probe\",\n",
                "    \"operation\": \"probe\",\n"
            ),
            1,
        );
        assert_eq!(
            ProviderAuthProbePolicy::from_contract_json(&duplicate_operation),
            Err(ProviderAuthProbeError::InvalidContractDocument)
        );
    }

    #[test]
    fn freshness_unknown_missing_and_value_tamper_fail_closed() {
        for (field, tampered_value) in [
            ("credentialLeaseMaxTtlSeconds", 901),
            ("authSessionMaxTtlSeconds", 601),
            ("probeMaxTtlSeconds", 121),
            ("clockSkewSeconds", 1),
        ] {
            assert_eq!(
                parse_tampered_contract(|value| {
                    value["freshness"][field] = json!(tampered_value);
                }),
                Err(ProviderAuthProbeError::InvalidFreshnessPolicy)
            );
        }
        assert_eq!(
            parse_tampered_contract(|value| {
                value["freshness"]
                    .as_object_mut()
                    .expect("freshness")
                    .insert("unknownField".into(), json!(true));
            }),
            Err(ProviderAuthProbeError::InvalidContractDocument)
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["freshness"]
                    .as_object_mut()
                    .expect("freshness")
                    .remove("probeMaxTtlSeconds");
            }),
            Err(ProviderAuthProbeError::InvalidContractDocument)
        );
    }

    #[test]
    fn connected_status_set_duplicate_missing_wrong_and_unknown_values_fail_closed() {
        assert_eq!(
            parse_tampered_contract(|value| {
                value["connectedProbeStatuses"]
                    .as_array_mut()
                    .expect("probe statuses")
                    .push(json!("reachable"));
            }),
            Err(ProviderAuthProbeError::DuplicateContractValue(
                "connected probe statuses"
            ))
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["connectedProbeStatuses"]
                    .as_array_mut()
                    .expect("probe statuses")
                    .clear();
            }),
            Err(ProviderAuthProbeError::ContractSetMismatch(
                "connected probe statuses"
            ))
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["connectedProbeStatuses"][0] = json!("unreachable");
            }),
            Err(ProviderAuthProbeError::ContractSetMismatch(
                "connected probe statuses"
            ))
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["connectedProbeStatuses"][0] = json!("unknown_status");
            }),
            Err(ProviderAuthProbeError::InvalidContractDocument)
        );
    }

    #[test]
    fn connected_provenance_set_duplicate_missing_wrong_and_unknown_values_fail_closed() {
        assert_eq!(
            parse_tampered_contract(|value| {
                value["connectedProvenanceClasses"]
                    .as_array_mut()
                    .expect("provenance classes")
                    .push(json!("production_provider"));
            }),
            Err(ProviderAuthProbeError::DuplicateContractValue(
                "connected provenance classes"
            ))
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["connectedProvenanceClasses"]
                    .as_array_mut()
                    .expect("provenance classes")
                    .clear();
            }),
            Err(ProviderAuthProbeError::ContractSetMismatch(
                "connected provenance classes"
            ))
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["connectedProvenanceClasses"][0] = json!("controlled_provider");
            }),
            Err(ProviderAuthProbeError::ContractSetMismatch(
                "connected provenance classes"
            ))
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["connectedProvenanceClasses"][0] = json!("unknown_provenance");
            }),
            Err(ProviderAuthProbeError::InvalidContractDocument)
        );
    }

    #[test]
    fn forbidden_authority_set_duplicate_missing_and_unknown_values_fail_closed() {
        assert_eq!(
            parse_tampered_contract(|value| {
                value["forbiddenAuthorities"]
                    .as_array_mut()
                    .expect("forbidden authorities")
                    .push(json!("e4"));
            }),
            Err(ProviderAuthProbeError::DuplicateContractValue(
                "forbidden authorities"
            ))
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["forbiddenAuthorities"]
                    .as_array_mut()
                    .expect("forbidden authorities")
                    .pop();
            }),
            Err(ProviderAuthProbeError::ContractSetMismatch(
                "forbidden authorities"
            ))
        );
        assert_eq!(
            parse_tampered_contract(|value| {
                value["forbiddenAuthorities"][0] = json!("connected");
            }),
            Err(ProviderAuthProbeError::InvalidContractDocument)
        );
    }

    proptest! {
        #[test]
        fn revision_tamper_never_authorizes_connected(
            selector in 0_u8..4,
            delta in 1_u64..1000,
        ) {
            let mut chain = live_chain(
                ProbeStatus::Reachable,
                ProviderProvenanceClass::ProductionProvider,
            );
            match selector {
                0 => chain.secret.credential_revision += delta,
                1 => chain.lease.lease_revision += delta,
                2 => chain.session.auth_revision += delta,
                _ => chain.probe.probe_revision += delta,
            }
            prop_assert!(authorize(&chain, &production_registry()).is_err());
        }
    }
}
