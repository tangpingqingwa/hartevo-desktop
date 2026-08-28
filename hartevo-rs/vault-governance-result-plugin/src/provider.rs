//! Typed Vault provider and reversible Layer-1 registration.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use serde::{Deserialize, Serialize, de::Error as DeError};
use thiserror::Error;

use crate::model::{
    Digest, HealthStatus, MAX_RESPONSE_BYTES, ProviderProvenance, SecretReference,
    VaultCapabilityEvidence, VaultCapabilityMetadata, VaultGovernanceEvidence, VaultHealthEvidence,
    VaultHealthMetadata, VaultLeaseEvidence, VaultOperation, VaultReadRequest,
    VaultResponsePayload, VaultResponseReceipt, VaultScope, VaultSecretRole, VaultTokenEvidence,
};
use crate::transport::{
    VaultEndpoint, VaultHttpResponse, VaultRequest, VaultTransport, VaultTransportError,
};
use crate::{
    MISSION_VAULT_GOVERNANCE_CONSUMER_ID, VAULT_GOVERNANCE_RESULT_CONTRACT_VERSION,
    VAULT_GOVERNANCE_RESULT_PROVIDER_ID, VAULT_GOVERNANCE_RESULT_PROVIDER_REVISION,
    VAULT_GOVERNANCE_RESULT_SCHEMA_VERSION, VAULT_GOVERNANCE_RESULT_SERVICE_ID,
    VAULT_GOVERNANCE_RESULT_SERVICE_VERSION, contract_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatusClass {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimitedOrStandby,
    ServerError,
    Unknown,
}

pub const fn classify_status(status: u16) -> VaultStatusClass {
    match status {
        401 => VaultStatusClass::Unauthorized,
        403 => VaultStatusClass::Forbidden,
        404 => VaultStatusClass::NotFound,
        409 => VaultStatusClass::Conflict,
        429 => VaultStatusClass::RateLimitedOrStandby,
        500..=599 => VaultStatusClass::ServerError,
        _ => VaultStatusClass::Unknown,
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum VaultProviderError {
    #[error("BLOCKED_ENV: native Vault authentication and HTTPS authority are unavailable")]
    BlockedEnv,
    #[error("Vault provider request is invalid")]
    InvalidRequest,
    #[error("Vault provider registration is revoked")]
    RegistrationRevoked,
    #[error("Vault provider registration scope or revision drifted")]
    RegistrationDrift,
    #[error("Vault provider contract digest drifted")]
    ContractDigestMismatch,
    #[error("Vault provider revision drifted")]
    ProviderRevisionMismatch,
    #[error("Vault response operation does not match the request")]
    OperationMismatch,
    #[error("Vault response was too large")]
    ResponseTooLarge,
    #[error("Vault returned HTTP status {status} ({class:?}) for {operation:?}")]
    UnexpectedStatus {
        operation: VaultOperation,
        status: u16,
        class: VaultStatusClass,
    },
    #[error("Vault response payload is invalid for the request")]
    InvalidPayload,
    #[error("Vault capability classes did not satisfy the requested check")]
    CapabilityMismatch { path_digest: Digest },
    #[error("Vault lease metadata did not match the scoped lease")]
    LeaseMismatch,
    #[error("Vault evidence is partial after {completed} completed operation(s)")]
    Partial {
        completed: usize,
        operation: VaultOperation,
    },
    #[error("Vault provider is unknown to the Layer-1 adapter")]
    ProviderUnknown,
    #[error("Vault transport timed out")]
    Timeout,
    #[error("Vault transport failed")]
    TransportFailure,
    #[error("Vault registration lifecycle fence is unavailable; operation failed closed")]
    LifecycleUnavailable,
    #[error("Vault registration replayed a revoked or conflicting lifecycle fence")]
    RegistrationReplay,
    #[error("Vault response request digest does not match the canonical request")]
    RequestDigestMismatch,
    #[error("Vault response digest does not match the canonical response")]
    ResponseDigestMismatch,
    #[error("Vault secret reference, credential, role, or time-window binding drifted")]
    SecretBindingMismatch,
}

impl From<VaultTransportError> for VaultProviderError {
    fn from(error: VaultTransportError) -> Self {
        match error {
            VaultTransportError::BlockedEnv => Self::BlockedEnv,
            VaultTransportError::Timeout => Self::Timeout,
            VaultTransportError::ProviderUnknown => Self::ProviderUnknown,
            VaultTransportError::InvalidRequest | VaultTransportError::Decode => {
                Self::InvalidPayload
            }
            VaultTransportError::Transport => Self::TransportFailure,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty")]
    EmptyVersion,
    #[error("provider version is not the checked-in Layer-1 version")]
    VersionDrift,
    #[error("provider revision is not the checked-in Layer-1 revision")]
    RevisionDrift,
    #[error("Layer 1 cannot register a native provider")]
    NativeProviderForbidden,
    #[error("provider capability digest does not match its canonical definition")]
    CapabilityDigestMismatch,
    #[error("provider digest does not match its canonical definition")]
    ProviderDigestMismatch,
    #[error("provider identity does not match the checked-in contract")]
    IdentityDrift,
}

impl From<ProviderDefinitionError> for VaultProviderError {
    fn from(error: ProviderDefinitionError) -> Self {
        match error {
            ProviderDefinitionError::EmptyVersion => Self::InvalidRequest,
            ProviderDefinitionError::VersionDrift
            | ProviderDefinitionError::NativeProviderForbidden
            | ProviderDefinitionError::CapabilityDigestMismatch
            | ProviderDefinitionError::ProviderDigestMismatch
            | ProviderDefinitionError::IdentityDrift => Self::RegistrationDrift,
            ProviderDefinitionError::RevisionDrift => Self::ProviderRevisionMismatch,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub capability_digest: Digest,
    pub provider_digest: Digest,
    pub provenance: ProviderProvenance,
    pub native: bool,
    pub secret_values_read: bool,
    pub token_material_retained: bool,
    pub login: bool,
    pub policy_mutation: bool,
    pub lease_renew: bool,
    pub lease_revoke: bool,
    pub root_token_paths: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VaultProviderDefinitionWire {
    schema_version: String,
    provider_id: String,
    provider_version: String,
    provider_revision: String,
    capability_digest: Digest,
    provider_digest: Digest,
    provenance: ProviderProvenance,
    native: bool,
    secret_values_read: bool,
    token_material_retained: bool,
    login: bool,
    policy_mutation: bool,
    lease_renew: bool,
    lease_revoke: bool,
    root_token_paths: bool,
}

impl<'de> Deserialize<'de> for VaultProviderDefinition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = VaultProviderDefinitionWire::deserialize(deserializer)?;
        let definition = Self {
            schema_version: wire.schema_version,
            provider_id: wire.provider_id,
            provider_version: wire.provider_version,
            provider_revision: wire.provider_revision,
            capability_digest: wire.capability_digest,
            provider_digest: wire.provider_digest,
            provenance: wire.provenance,
            native: wire.native,
            secret_values_read: wire.secret_values_read,
            token_material_retained: wire.token_material_retained,
            login: wire.login,
            policy_mutation: wire.policy_mutation,
            lease_renew: wire.lease_renew,
            lease_revoke: wire.lease_revoke,
            root_token_paths: wire.root_token_paths,
        };
        definition.validate().map_err(DeError::custom)?;
        Ok(definition)
    }
}

impl VaultProviderDefinition {
    fn expected_capability_digest(provider_version: &str) -> Digest {
        Digest::from_fields(
            "vault-provider-capabilities/v1",
            &[
                VAULT_GOVERNANCE_RESULT_SCHEMA_VERSION.to_owned(),
                VAULT_GOVERNANCE_RESULT_PROVIDER_ID.to_owned(),
                provider_version.to_owned(),
                VAULT_GOVERNANCE_RESULT_PROVIDER_REVISION.to_owned(),
                "sys_health".to_owned(),
                "auth_token_lookup_self".to_owned(),
                "sys_capabilities_self_allowlisted".to_owned(),
                "sys_leases_lookup_metadata".to_owned(),
                "native=false".to_owned(),
                "secret_values_read=false".to_owned(),
                "token_material_retained=false".to_owned(),
                "login=false".to_owned(),
                "policy_mutation=false".to_owned(),
                "lease_renew=false".to_owned(),
                "lease_revoke=false".to_owned(),
                "root_token_paths=false".to_owned(),
            ],
        )
    }

    fn expected_provider_digest(
        provider_version: &str,
        provenance: ProviderProvenance,
        capability_digest: &Digest,
    ) -> Digest {
        Digest::from_fields(
            "vault-provider-definition/v1",
            &[
                VAULT_GOVERNANCE_RESULT_SCHEMA_VERSION.to_owned(),
                VAULT_GOVERNANCE_RESULT_PROVIDER_ID.to_owned(),
                provider_version.to_owned(),
                VAULT_GOVERNANCE_RESULT_PROVIDER_REVISION.to_owned(),
                capability_digest.as_str().to_owned(),
                format!("{provenance:?}"),
            ],
        )
    }

    pub fn new(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        if provider_version != VAULT_GOVERNANCE_RESULT_SERVICE_VERSION {
            return Err(ProviderDefinitionError::VersionDrift);
        }
        if provenance.is_native() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let capability_digest = Self::expected_capability_digest(&provider_version);
        let provider_digest =
            Self::expected_provider_digest(&provider_version, provenance, &capability_digest);
        Ok(Self {
            schema_version: VAULT_GOVERNANCE_RESULT_SCHEMA_VERSION.to_owned(),
            provider_id: VAULT_GOVERNANCE_RESULT_PROVIDER_ID.to_owned(),
            provider_version,
            provider_revision: VAULT_GOVERNANCE_RESULT_PROVIDER_REVISION.to_owned(),
            capability_digest,
            provider_digest,
            provenance,
            native: false,
            secret_values_read: false,
            token_material_retained: false,
            login: false,
            policy_mutation: false,
            lease_renew: false,
            lease_revoke: false,
            root_token_paths: false,
        })
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        if self.schema_version != VAULT_GOVERNANCE_RESULT_SCHEMA_VERSION
            || self.provider_id != VAULT_GOVERNANCE_RESULT_PROVIDER_ID
            || self.provider_version != VAULT_GOVERNANCE_RESULT_SERVICE_VERSION
        {
            return Err(ProviderDefinitionError::IdentityDrift);
        }
        if self.provider_revision != VAULT_GOVERNANCE_RESULT_PROVIDER_REVISION {
            return Err(ProviderDefinitionError::RevisionDrift);
        }
        if self.native
            || self.secret_values_read
            || self.token_material_retained
            || self.login
            || self.policy_mutation
            || self.lease_renew
            || self.lease_revoke
            || self.root_token_paths
        {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        if self.capability_digest != Self::expected_capability_digest(&self.provider_version) {
            return Err(ProviderDefinitionError::CapabilityDigestMismatch);
        }
        if self.provider_digest
            != Self::expected_provider_digest(
                &self.provider_version,
                self.provenance,
                &self.capability_digest,
            )
        {
            return Err(ProviderDefinitionError::ProviderDigestMismatch);
        }
        Ok(())
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LifecycleFence {
    epoch: u64,
    state: RegistrationState,
    contract_digest: Digest,
    provider_digest: Digest,
    scope_digest: Digest,
    secret_reference_digest: Digest,
    credential_revision: u64,
    secret_role: VaultSecretRole,
    valid_from_unix_seconds: u64,
    valid_until_unix_seconds: u64,
}

static REGISTRATION_LIFECYCLE: OnceLock<Mutex<BTreeMap<String, LifecycleFence>>> = OnceLock::new();
static NEXT_LIFECYCLE_EPOCH: AtomicU64 = AtomicU64::new(1);

fn registration_lifecycle() -> &'static Mutex<BTreeMap<String, LifecycleFence>> {
    REGISTRATION_LIFECYCLE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(crate) fn validate_lifecycle_generation(
    registration_digest: &Digest,
    lifecycle_generation: u64,
) -> Result<(), VaultProviderError> {
    if lifecycle_generation == 0 {
        return Err(VaultProviderError::RegistrationReplay);
    }
    let lifecycle = registration_lifecycle()
        .lock()
        .map_err(|_| VaultProviderError::LifecycleUnavailable)?;
    let Some(fence) = lifecycle.get(registration_digest.as_str()) else {
        return Err(VaultProviderError::LifecycleUnavailable);
    };
    if fence.epoch != lifecycle_generation {
        return Err(VaultProviderError::RegistrationReplay);
    }
    if fence.state != RegistrationState::Active {
        return Err(VaultProviderError::RegistrationRevoked);
    }
    Ok(())
}

fn lifecycle_fence(
    contract_digest: &Digest,
    provider_digest: &Digest,
    scope: &VaultScope,
    secret_reference: &SecretReference,
) -> Result<LifecycleFence, VaultProviderError> {
    let epoch = NEXT_LIFECYCLE_EPOCH
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(1)
        })
        .map_err(|_| VaultProviderError::LifecycleUnavailable)?;
    Ok(LifecycleFence {
        epoch,
        state: RegistrationState::Active,
        contract_digest: contract_digest.clone(),
        provider_digest: provider_digest.clone(),
        scope_digest: scope.scope_digest(),
        secret_reference_digest: secret_reference.reference_digest().clone(),
        credential_revision: secret_reference.credential_revision().get(),
        secret_role: secret_reference.secret_role(),
        valid_from_unix_seconds: secret_reference.valid_from_unix_seconds(),
        valid_until_unix_seconds: secret_reference.valid_until_unix_seconds(),
    })
}

fn same_fence(
    fence: &LifecycleFence,
    contract_digest: &Digest,
    provider_digest: &Digest,
    scope: &VaultScope,
    secret_reference: &SecretReference,
) -> bool {
    fence.contract_digest == *contract_digest
        && fence.provider_digest == *provider_digest
        && fence.scope_digest == scope.scope_digest()
        && fence.secret_reference_digest == *secret_reference.reference_digest()
        && fence.credential_revision == secret_reference.credential_revision().get()
        && fence.secret_role == secret_reference.secret_role()
        && fence.valid_from_unix_seconds == secret_reference.valid_from_unix_seconds()
        && fence.valid_until_unix_seconds == secret_reference.valid_until_unix_seconds()
}

/// A reversible, digest-bound registration.  It is not serializable because
/// it contains the opaque SecretReference authority object.
pub struct VaultRegistration {
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    scope: VaultScope,
    secret_reference: SecretReference,
    provider_definition: VaultProviderDefinition,
    registration_digest: Digest,
    lifecycle_epoch: u64,
    state: RegistrationState,
    revoked_at_unix_seconds: Option<u64>,
}

impl Clone for VaultRegistration {
    fn clone(&self) -> Self {
        Self {
            plugin_version: self.plugin_version.clone(),
            contract_version: self.contract_version.clone(),
            contract_digest: self.contract_digest.clone(),
            scope: self.scope.clone(),
            secret_reference: self.secret_reference.clone(),
            provider_definition: self.provider_definition.clone(),
            registration_digest: self.registration_digest.clone(),
            lifecycle_epoch: self.lifecycle_epoch,
            state: self.state,
            revoked_at_unix_seconds: self.revoked_at_unix_seconds,
        }
    }
}

impl fmt::Debug for VaultRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultRegistration")
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("scope_digest", &self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider_digest", &self.provider_definition.provider_digest)
            .field("registration_digest", &self.registration_digest)
            .field("lifecycle_epoch", &self.lifecycle_epoch)
            .field("state", &self.state)
            .field("revoked_at_unix_seconds", &self.revoked_at_unix_seconds)
            .finish()
    }
}

impl PartialEq for VaultRegistration {
    fn eq(&self, other: &Self) -> bool {
        self.plugin_version == other.plugin_version
            && self.contract_version == other.contract_version
            && self.contract_digest == other.contract_digest
            && self.scope == other.scope
            && self.secret_reference == other.secret_reference
            && self.provider_definition == other.provider_definition
            && self.registration_digest == other.registration_digest
            && self.lifecycle_epoch == other.lifecycle_epoch
            && self.state == other.state
            && self.revoked_at_unix_seconds == other.revoked_at_unix_seconds
    }
}

impl Eq for VaultRegistration {}

impl VaultRegistration {
    pub(crate) fn expected_registration_digest(
        scope: &VaultScope,
        provider_digest: &Digest,
        secret_reference_digest: &Digest,
        credential_revision: u64,
        secret_role: VaultSecretRole,
        valid_from_unix_seconds: u64,
        valid_until_unix_seconds: u64,
    ) -> Digest {
        Digest::from_fields(
            "vault-registration/v2",
            &[
                VAULT_GOVERNANCE_RESULT_SERVICE_ID.to_owned(),
                VAULT_GOVERNANCE_RESULT_PROVIDER_ID.to_owned(),
                MISSION_VAULT_GOVERNANCE_CONSUMER_ID.to_owned(),
                VAULT_GOVERNANCE_RESULT_SERVICE_VERSION.to_owned(),
                VAULT_GOVERNANCE_RESULT_CONTRACT_VERSION.to_owned(),
                contract_digest().as_str().to_owned(),
                provider_digest.as_str().to_owned(),
                scope.scope_digest().as_str().to_owned(),
                secret_reference_digest.as_str().to_owned(),
                credential_revision.to_string(),
                secret_role.as_str().to_owned(),
                valid_from_unix_seconds.to_string(),
                valid_until_unix_seconds.to_string(),
            ],
        )
    }

    pub fn new(
        scope: VaultScope,
        secret_reference: SecretReference,
        provider_definition: VaultProviderDefinition,
    ) -> Result<Self, VaultProviderError> {
        provider_definition
            .validate()
            .map_err(|_| VaultProviderError::ProviderRevisionMismatch)?;
        if !scope.is_secret_bound()
            || scope.secret_reference_digest() != Some(secret_reference.reference_digest())
            || scope.credential_revision() != Some(secret_reference.credential_revision())
            || scope.secret_role() != Some(secret_reference.secret_role())
            || scope.valid_from_unix_seconds() != Some(secret_reference.valid_from_unix_seconds())
            || scope.valid_until_unix_seconds() != Some(secret_reference.valid_until_unix_seconds())
            || secret_reference.scope_identity_digest() != &scope.identity_digest()
            || secret_reference.is_revoked()
        {
            return Err(VaultProviderError::RegistrationDrift);
        }
        let contract_digest = contract_digest();
        let registration_digest = Self::expected_registration_digest(
            &scope,
            &provider_definition.provider_digest,
            secret_reference.reference_digest(),
            secret_reference.credential_revision().get(),
            secret_reference.secret_role(),
            secret_reference.valid_from_unix_seconds(),
            secret_reference.valid_until_unix_seconds(),
        );
        let lifecycle_epoch = {
            let mut lifecycle = registration_lifecycle()
                .lock()
                .map_err(|_| VaultProviderError::LifecycleUnavailable)?;
            if let Some(existing) = lifecycle.get(registration_digest.as_str()) {
                if existing.state == RegistrationState::Revoked {
                    return Err(VaultProviderError::RegistrationReplay);
                }
                if !same_fence(
                    existing,
                    &contract_digest,
                    &provider_definition.provider_digest,
                    &scope,
                    &secret_reference,
                ) {
                    return Err(VaultProviderError::RegistrationReplay);
                }
                existing.epoch
            } else {
                let fence = lifecycle_fence(
                    &contract_digest,
                    &provider_definition.provider_digest,
                    &scope,
                    &secret_reference,
                )?;
                let epoch = fence.epoch;
                lifecycle.insert(registration_digest.as_str().to_owned(), fence);
                epoch
            }
        };
        Ok(Self {
            plugin_version: VAULT_GOVERNANCE_RESULT_SERVICE_VERSION.to_owned(),
            contract_version: VAULT_GOVERNANCE_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest,
            scope,
            secret_reference,
            provider_definition,
            registration_digest,
            lifecycle_epoch,
            state: RegistrationState::Active,
            revoked_at_unix_seconds: None,
        })
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn scope(&self) -> &VaultScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider_definition(&self) -> &VaultProviderDefinition {
        &self.provider_definition
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub(crate) const fn lifecycle_generation(&self) -> u64 {
        self.lifecycle_epoch
    }

    pub const fn state(&self) -> RegistrationState {
        self.state
    }

    pub const fn revoked_at_unix_seconds(&self) -> Option<u64> {
        self.revoked_at_unix_seconds
    }

    pub fn revoke(&mut self, at_unix_seconds: u64) -> Result<(), VaultProviderError> {
        if self.state == RegistrationState::Revoked {
            return Err(VaultProviderError::RegistrationRevoked);
        }
        let mut lifecycle = registration_lifecycle()
            .lock()
            .map_err(|_| VaultProviderError::LifecycleUnavailable)?;
        let Some(fence) = lifecycle.get_mut(self.registration_digest.as_str()) else {
            return Err(VaultProviderError::LifecycleUnavailable);
        };
        if fence.epoch != self.lifecycle_epoch {
            return Err(VaultProviderError::RegistrationReplay);
        }
        if fence.state == RegistrationState::Revoked {
            return Err(VaultProviderError::RegistrationRevoked);
        }
        fence.state = RegistrationState::Revoked;
        self.state = RegistrationState::Revoked;
        self.revoked_at_unix_seconds = Some(at_unix_seconds);
        Ok(())
    }

    fn validate_integrity(&self) -> Result<(), VaultProviderError> {
        self.provider_definition
            .validate()
            .map_err(VaultProviderError::from)?;
        if self.plugin_version != VAULT_GOVERNANCE_RESULT_SERVICE_VERSION
            || self.contract_version != VAULT_GOVERNANCE_RESULT_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || !self.scope.is_secret_bound()
            || self.scope.secret_reference_digest()
                != Some(self.secret_reference.reference_digest())
            || self.scope.credential_revision() != Some(self.secret_reference.credential_revision())
            || self.scope.secret_role() != Some(self.secret_reference.secret_role())
            || self.scope.valid_from_unix_seconds()
                != Some(self.secret_reference.valid_from_unix_seconds())
            || self.scope.valid_until_unix_seconds()
                != Some(self.secret_reference.valid_until_unix_seconds())
            || self.secret_reference.scope_identity_digest() != &self.scope.identity_digest()
            || self.secret_reference.is_revoked()
            || self.registration_digest
                != Self::expected_registration_digest(
                    &self.scope,
                    &self.provider_definition.provider_digest,
                    self.secret_reference.reference_digest(),
                    self.secret_reference.credential_revision().get(),
                    self.secret_reference.secret_role(),
                    self.secret_reference.valid_from_unix_seconds(),
                    self.secret_reference.valid_until_unix_seconds(),
                )
        {
            return Err(VaultProviderError::RegistrationDrift);
        }
        Ok(())
    }

    fn validate_active(
        &self,
        scope: &VaultScope,
        observed_at_unix_seconds: u64,
    ) -> Result<(), VaultProviderError> {
        if self.state == RegistrationState::Revoked {
            return Err(VaultProviderError::RegistrationRevoked);
        }
        self.validate_integrity()?;
        let (Some(valid_from), Some(valid_until)) = (
            scope.valid_from_unix_seconds(),
            scope.valid_until_unix_seconds(),
        ) else {
            return Err(VaultProviderError::SecretBindingMismatch);
        };
        if &self.scope != scope
            || observed_at_unix_seconds < valid_from
            || observed_at_unix_seconds >= valid_until
        {
            return Err(VaultProviderError::RegistrationDrift);
        }
        validate_lifecycle_generation(&self.registration_digest, self.lifecycle_epoch)
    }
}

pub struct VaultProvider<T>
where
    T: VaultTransport,
{
    registration: VaultRegistration,
    transport: T,
}

impl<T> fmt::Debug for VaultProvider<T>
where
    T: VaultTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultProvider")
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("scope_digest", &self.registration.scope.scope_digest())
            .field(
                "provider_digest",
                &self.registration.provider_definition.provider_digest,
            )
            .field("provenance", &self.transport.provenance())
            .finish_non_exhaustive()
    }
}

impl<T> VaultProvider<T>
where
    T: VaultTransport,
{
    pub fn new(
        scope: VaultScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, VaultProviderError> {
        let provider_definition = VaultProviderDefinition::new(
            VAULT_GOVERNANCE_RESULT_SERVICE_VERSION,
            transport.provenance(),
        )?;
        let registration = VaultRegistration::new(scope, secret_reference, provider_definition)?;
        Ok(Self {
            registration,
            transport,
        })
    }

    pub fn from_registration(
        registration: VaultRegistration,
        transport: T,
    ) -> Result<Self, VaultProviderError> {
        let observed_at = registration
            .scope
            .valid_from_unix_seconds()
            .ok_or(VaultProviderError::SecretBindingMismatch)?;
        registration.validate_active(&registration.scope, observed_at)?;
        Ok(Self {
            registration,
            transport,
        })
    }

    pub fn registration(&self) -> &VaultRegistration {
        &self.registration
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub const fn is_connected(&self) -> bool {
        false
    }

    pub fn revoke_registration(&mut self, at_unix_seconds: u64) -> Result<(), VaultProviderError> {
        self.registration.revoke(at_unix_seconds)
    }

    pub fn read(
        &mut self,
        request: &VaultReadRequest,
    ) -> Result<VaultGovernanceEvidence, VaultProviderError> {
        self.registration.validate_active(
            self.registration.scope(),
            request.observed_at_unix_seconds(),
        )?;
        request
            .validate(self.registration.scope())
            .map_err(|_| VaultProviderError::InvalidRequest)?;

        let mut endpoints = Vec::new();
        if request.includes_health() {
            endpoints.push(VaultEndpoint::SysHealth);
        }
        if request.includes_token_self() {
            endpoints.push(VaultEndpoint::AuthTokenLookupSelf);
        }
        if !request.capability_checks().is_empty() {
            endpoints.push(VaultEndpoint::SysCapabilitiesSelf {
                path_digests: request
                    .capability_checks()
                    .iter()
                    .map(|check| check.path().digest())
                    .collect(),
            });
        }
        if let Some(lease) = request.lease_reference() {
            endpoints.push(VaultEndpoint::SysLeasesLookup {
                lease_digest: lease.reference_digest().clone(),
            });
        }

        let mut operations = Vec::new();
        let mut receipts = Vec::new();
        let mut health = None;
        let mut token = None;
        let mut capabilities = Vec::new();
        let mut lease = None;

        for (completed, endpoint) in endpoints.iter().enumerate() {
            let operation = endpoint.operation();
            let request_for_endpoint =
                VaultRequest::new(self.registration.scope(), endpoint.clone());
            let response = match self.transport.execute(&request_for_endpoint) {
                Ok(response) => response,
                Err(error) => {
                    let error = VaultProviderError::from(error);
                    return if completed == 0 {
                        Err(error)
                    } else {
                        Err(VaultProviderError::Partial {
                            completed,
                            operation,
                        })
                    };
                }
            };
            self.validate_response(&request_for_endpoint, &response)?;
            if operation != response.operation() {
                return Err(VaultProviderError::OperationMismatch);
            }
            if !is_accepted_status(operation, response.status()) {
                return Err(VaultProviderError::UnexpectedStatus {
                    operation,
                    status: response.status(),
                    class: classify_status(response.status()),
                });
            }

            let receipt = VaultResponseReceipt {
                operation,
                request_digest: request_for_endpoint.request_digest().clone(),
                response_status: response.status(),
                response_size: response.response_size(),
                response_digest: response.response_digest().clone(),
                provider_revision: response.provider_revision().to_owned(),
                raw_provider_payload_retained: false,
                secret_values_retained: false,
                token_material_retained: false,
            };
            receipts.push(receipt);
            operations.push(operation);

            match (endpoint, response.payload()) {
                (VaultEndpoint::SysHealth, VaultResponsePayload::Health(metadata)) => {
                    health = Some(VaultHealthEvidence {
                        status: health_status(response.status(), metadata),
                        http_status: response.status(),
                        metadata: metadata.clone(),
                    });
                }
                (VaultEndpoint::AuthTokenLookupSelf, VaultResponsePayload::TokenSelf(metadata)) => {
                    token = Some(VaultTokenEvidence::from(metadata.clone()));
                }
                (
                    VaultEndpoint::SysCapabilitiesSelf { .. },
                    VaultResponsePayload::CapabilitiesSelf(entries),
                ) => {
                    Self::validate_capabilities(request, entries)?;
                    capabilities = entries
                        .iter()
                        .cloned()
                        .map(VaultCapabilityEvidence::from)
                        .collect();
                }
                (
                    VaultEndpoint::SysLeasesLookup { lease_digest },
                    VaultResponsePayload::LeaseLookup(metadata),
                ) => {
                    if &metadata.lease_digest != lease_digest
                        || metadata.mount_digest != self.registration.scope().mount().mount_digest()
                    {
                        return Err(VaultProviderError::LeaseMismatch);
                    }
                    lease = Some(VaultLeaseEvidence::from(metadata.clone()));
                }
                _ => return Err(VaultProviderError::InvalidPayload),
            }
        }

        let mut evidence = VaultGovernanceEvidence {
            schema_version: VAULT_GOVERNANCE_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: VAULT_GOVERNANCE_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            service_id: VAULT_GOVERNANCE_RESULT_SERVICE_ID.to_owned(),
            provider_id: VAULT_GOVERNANCE_RESULT_PROVIDER_ID.to_owned(),
            provider_version: self
                .registration
                .provider_definition
                .provider_version
                .clone(),
            provider_revision: self
                .registration
                .provider_definition
                .provider_revision
                .clone(),
            provider_digest: self
                .registration
                .provider_definition
                .provider_digest
                .clone(),
            consumer_id: MISSION_VAULT_GOVERNANCE_CONSUMER_ID.to_owned(),
            scope_digest: self.registration.scope.scope_digest(),
            registration_digest: self.registration.registration_digest.clone(),
            lifecycle_generation: self.registration.lifecycle_generation(),
            secret_reference_digest: self
                .registration
                .secret_reference
                .reference_digest()
                .clone(),
            credential_revision: self.registration.secret_reference.credential_revision(),
            secret_role: self.registration.secret_reference.secret_role(),
            valid_from_unix_seconds: self.registration.secret_reference.valid_from_unix_seconds(),
            valid_until_unix_seconds: self
                .registration
                .secret_reference
                .valid_until_unix_seconds(),
            provenance: self.transport.provenance(),
            observed_at_unix_seconds: request.observed_at_unix_seconds(),
            operations,
            receipts,
            health,
            token,
            capabilities,
            lease,
            partial: false,
            provider_unknown: false,
            read_only: true,
            native_evidence: false,
            external_write_performed: false,
            secret_values_retained: false,
            token_material_retained: false,
            raw_provider_payload_retained: false,
            evidence_digest: Digest::zero(),
            origin_seal: None,
        };
        evidence
            .seal_from_provider(self.registration.lifecycle_generation())
            .map_err(|_| VaultProviderError::InvalidPayload)?;
        evidence.evidence_digest = evidence.compute_evidence_digest();
        evidence
            .validate()
            .map_err(|_| VaultProviderError::InvalidPayload)?;
        Ok(evidence)
    }

    fn validate_response(
        &self,
        request: &VaultRequest,
        response: &VaultHttpResponse,
    ) -> Result<(), VaultProviderError> {
        if response.provider_revision() != self.registration.provider_definition.provider_revision {
            return Err(VaultProviderError::ProviderRevisionMismatch);
        }
        if response.response_size() > MAX_RESPONSE_BYTES {
            return Err(VaultProviderError::ResponseTooLarge);
        }
        request
            .verify_digest()
            .map_err(|_| VaultProviderError::RequestDigestMismatch)?;
        if response.request_digest() != request.request_digest() {
            return Err(VaultProviderError::RequestDigestMismatch);
        }
        response
            .verify_digest()
            .map_err(|_| VaultProviderError::ResponseDigestMismatch)?;
        if response.response_digest().is_zero() {
            return Err(VaultProviderError::ResponseDigestMismatch);
        }
        Ok(())
    }

    fn validate_capabilities(
        request: &VaultReadRequest,
        entries: &[VaultCapabilityMetadata],
    ) -> Result<(), VaultProviderError> {
        if entries.len() != request.capability_checks().len() {
            return Err(VaultProviderError::InvalidPayload);
        }
        for check in request.capability_checks() {
            let path_digest = check.path().digest();
            let Some(entry) = entries
                .iter()
                .find(|entry| entry.path_digest == path_digest)
            else {
                return Err(VaultProviderError::CapabilityMismatch { path_digest });
            };
            if !check
                .required()
                .iter()
                .all(|required| entry.capability_classes.contains(required))
            {
                return Err(VaultProviderError::CapabilityMismatch { path_digest });
            }
        }
        Ok(())
    }
}

fn is_accepted_status(operation: VaultOperation, status: u16) -> bool {
    match operation {
        VaultOperation::SysHealth => {
            matches!(status, 200 | 429 | 472 | 473 | 474 | 501 | 503 | 530)
        }
        VaultOperation::AuthTokenLookupSelf
        | VaultOperation::SysCapabilitiesSelfAllowlisted
        | VaultOperation::SysLeasesLookupMetadata => status == 200,
    }
}

fn health_status(status: u16, metadata: &VaultHealthMetadata) -> HealthStatus {
    if metadata.removed_from_cluster || status == 530 {
        HealthStatus::Removed
    } else if metadata.sealed || status == 503 {
        HealthStatus::Sealed
    } else if !metadata.initialized || status == 501 {
        HealthStatus::Uninitialized
    } else if metadata.performance_standby || status == 473 {
        HealthStatus::PerformanceStandby
    } else if metadata.standby || matches!(status, 429 | 472 | 474) {
        HealthStatus::Standby
    } else if status == 200 && metadata.initialized && !metadata.sealed {
        HealthStatus::Active
    } else {
        HealthStatus::Unknown
    }
}
