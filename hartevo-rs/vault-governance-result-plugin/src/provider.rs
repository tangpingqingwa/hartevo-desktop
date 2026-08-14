//! Typed Vault provider and reversible Layer-1 registration.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    Digest, HealthStatus, MAX_RESPONSE_BYTES, ProviderProvenance, SecretReference,
    VaultCapabilityEvidence, VaultCapabilityMetadata, VaultGovernanceEvidence, VaultHealthEvidence,
    VaultHealthMetadata, VaultLeaseEvidence, VaultOperation, VaultReadRequest,
    VaultResponsePayload, VaultResponseReceipt, VaultScope, VaultTokenEvidence,
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
    #[error("provider revision is not the checked-in Layer-1 revision")]
    RevisionDrift,
    #[error("Layer 1 cannot register a native provider")]
    NativeProviderForbidden,
}

impl From<ProviderDefinitionError> for VaultProviderError {
    fn from(error: ProviderDefinitionError) -> Self {
        match error {
            ProviderDefinitionError::EmptyVersion => Self::InvalidRequest,
            ProviderDefinitionError::RevisionDrift => Self::ProviderRevisionMismatch,
            ProviderDefinitionError::NativeProviderForbidden => Self::RegistrationDrift,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

impl VaultProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        if provenance.is_native() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let capability_digest = Digest::from_fields(
            "vault-provider-capabilities/v1",
            &[
                VAULT_GOVERNANCE_RESULT_SCHEMA_VERSION.to_owned(),
                VAULT_GOVERNANCE_RESULT_PROVIDER_ID.to_owned(),
                provider_version.clone(),
                VAULT_GOVERNANCE_RESULT_PROVIDER_REVISION.to_owned(),
                "sys_health".to_owned(),
                "auth_token_lookup_self".to_owned(),
                "sys_capabilities_self_allowlisted".to_owned(),
                "sys_leases_lookup_metadata".to_owned(),
                "native=false".to_owned(),
                "secret_values_read=false".to_owned(),
                "token_material_retained=false".to_owned(),
            ],
        );
        let provider_digest = Digest::from_fields(
            "vault-provider-definition/v1",
            &[
                VAULT_GOVERNANCE_RESULT_SCHEMA_VERSION.to_owned(),
                VAULT_GOVERNANCE_RESULT_PROVIDER_ID.to_owned(),
                provider_version.clone(),
                VAULT_GOVERNANCE_RESULT_PROVIDER_REVISION.to_owned(),
                capability_digest.as_str().to_owned(),
                format!("{provenance:?}"),
            ],
        );
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
            && self.state == other.state
            && self.revoked_at_unix_seconds == other.revoked_at_unix_seconds
    }
}

impl Eq for VaultRegistration {}

impl VaultRegistration {
    pub fn new(
        scope: VaultScope,
        secret_reference: SecretReference,
        provider_definition: VaultProviderDefinition,
    ) -> Result<Self, VaultProviderError> {
        provider_definition
            .validate()
            .map_err(|_| VaultProviderError::ProviderRevisionMismatch)?;
        if secret_reference.scope_digest() != &scope.scope_digest() || secret_reference.is_revoked()
        {
            return Err(VaultProviderError::RegistrationDrift);
        }
        let contract_digest = contract_digest();
        let registration_digest = Digest::from_fields(
            "vault-registration/v1",
            &[
                VAULT_GOVERNANCE_RESULT_SERVICE_ID.to_owned(),
                VAULT_GOVERNANCE_RESULT_PROVIDER_ID.to_owned(),
                MISSION_VAULT_GOVERNANCE_CONSUMER_ID.to_owned(),
                VAULT_GOVERNANCE_RESULT_SERVICE_VERSION.to_owned(),
                VAULT_GOVERNANCE_RESULT_CONTRACT_VERSION.to_owned(),
                contract_digest.as_str().to_owned(),
                provider_definition.provider_digest.as_str().to_owned(),
                scope.scope_digest().as_str().to_owned(),
                secret_reference.reference_digest().as_str().to_owned(),
                secret_reference.credential_revision().get().to_string(),
            ],
        );
        Ok(Self {
            plugin_version: VAULT_GOVERNANCE_RESULT_SERVICE_VERSION.to_owned(),
            contract_version: VAULT_GOVERNANCE_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest,
            scope,
            secret_reference,
            provider_definition,
            registration_digest,
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
        self.state = RegistrationState::Revoked;
        self.revoked_at_unix_seconds = Some(at_unix_seconds);
        Ok(())
    }

    fn validate_active(&self, scope: &VaultScope) -> Result<(), VaultProviderError> {
        if self.state == RegistrationState::Revoked {
            return Err(VaultProviderError::RegistrationRevoked);
        }
        if &self.scope != scope || self.contract_digest != contract_digest() {
            return Err(VaultProviderError::RegistrationDrift);
        }
        Ok(())
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
        registration.provider_definition.validate()?;
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
        self.registration
            .validate_active(self.registration.scope())?;
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
            provider_digest: self
                .registration
                .provider_definition
                .provider_digest
                .clone(),
            consumer_id: MISSION_VAULT_GOVERNANCE_CONSUMER_ID.to_owned(),
            scope_digest: self.registration.scope.scope_digest(),
            registration_digest: self.registration.registration_digest.clone(),
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
        };
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
        if response.request_digest() != &Digest::zero()
            && response.request_digest() != request.request_digest()
        {
            return Err(VaultProviderError::RegistrationDrift);
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
