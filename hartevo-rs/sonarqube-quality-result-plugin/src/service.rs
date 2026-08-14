//! Typed service and reversible/revocable registration boundary.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::{
    MissionSonarQubeQualityConsumer, RecordedSonarQubeQualityResult, SonarQubeQualityProposal,
    SonarQubeQualityRecordingLog,
};
use crate::model::{
    Digest, RegistrationId, RegistrationStatus, SecretReference, SonarQubeQualityScope, Version,
};
use crate::provider::{
    SonarQubeProvider, SonarQubeProviderError, SonarQubeQualityProjection, SonarQubeTransport,
};
use crate::{
    CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID, Result,
    SERVICE_ID, SonarQubeQualityResultError, contract_digest, validate_identifier, validate_text,
};

/// Provider metadata is descriptive and digest-bound; it never grants native
/// execution or credential resolution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderIdentity {
    pub provider_id: String,
    pub api_revision: String,
    pub provider_revision: u64,
    pub release: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
}

impl ProviderIdentity {
    pub fn recording(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let identity = Self {
            provider_id: PROVIDER_ID.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            provider_revision,
            release: release.into(),
            provider_digest: Digest::from_text("unsealed-sonarqube-provider"),
            api_digest: Digest::from_text("unsealed-sonarqube-api"),
        };
        identity.sealed()
    }

    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        Self::recording(provider_revision, release)
    }

    fn sealed(mut self) -> Result<Self> {
        validate_identifier(&self.provider_id, "providerId", 256)?;
        validate_identifier(&self.api_revision, "apiRevision", 256)?;
        validate_text(&self.release, "providerRelease", 128, false)?;
        if self.provider_revision == 0 {
            return Err(SonarQubeQualityResultError::InvalidRegistration);
        }
        self.api_digest = Digest::from_parts(
            "sonarqube-api-binding/v1",
            &[
                ("revision", self.api_revision.clone()),
                ("analyses", crate::PROJECT_ANALYSES_SEARCH_PATH.to_owned()),
                ("quality_gate", crate::QUALITY_GATE_STATUS_PATH.to_owned()),
                ("measures", crate::MEASURES_COMPONENT_PATH.to_owned()),
            ],
        );
        self.provider_digest = Digest::from_serialized(&(
            &self.provider_id,
            &self.api_revision,
            self.provider_revision,
            &self.release,
            &self.api_digest,
        ));
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.api_revision != PROVIDER_API_REVISION
            || self.provider_revision == 0
        {
            return Err(SonarQubeQualityResultError::InvalidRegistration);
        }
        validate_text(&self.release, "providerRelease", 128, false)?;
        self.provider_digest.validate()?;
        self.api_digest.validate()?;
        let expected_api = Digest::from_parts(
            "sonarqube-api-binding/v1",
            &[
                ("revision", self.api_revision.clone()),
                ("analyses", crate::PROJECT_ANALYSES_SEARCH_PATH.to_owned()),
                ("quality_gate", crate::QUALITY_GATE_STATUS_PATH.to_owned()),
                ("measures", crate::MEASURES_COMPONENT_PATH.to_owned()),
            ],
        );
        let expected_provider = Digest::from_serialized(&(
            &self.provider_id,
            &self.api_revision,
            self.provider_revision,
            &self.release,
            &self.api_digest,
        ));
        if self.api_digest != expected_api || self.provider_digest != expected_provider {
            Err(SonarQubeQualityResultError::InvalidRegistration)
        } else {
            Ok(())
        }
    }
}

/// The capability set is explicit and read/proposal/recording-only.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityDescription {
    pub service_id: String,
    pub operations: Vec<String>,
    pub endpoints: Vec<String>,
    pub read_only: bool,
    pub proposals_below_kernel: bool,
    pub local_recording_only: bool,
    pub can_execute_analysis: bool,
    pub can_mutate_issues: bool,
    pub can_mutate_quality_gates: bool,
    pub can_create_webhooks: bool,
    pub can_export_source: bool,
    pub can_query_arbitrary_dsl: bool,
    pub can_adopt_outcome: bool,
    pub capability_digest: Digest,
}

impl CapabilityDescription {
    pub fn recording() -> Self {
        let mut value = Self {
            service_id: SERVICE_ID.to_owned(),
            operations: vec![
                "describe_capabilities".to_owned(),
                "read_project_analyses".to_owned(),
                "read_quality_gate_status".to_owned(),
                "read_component_measures".to_owned(),
                "compile_quality_result_proposal".to_owned(),
                "record_quality_result".to_owned(),
            ],
            endpoints: vec![
                crate::PROJECT_ANALYSES_SEARCH_PATH.to_owned(),
                crate::QUALITY_GATE_STATUS_PATH.to_owned(),
                crate::MEASURES_COMPONENT_PATH.to_owned(),
            ],
            read_only: true,
            proposals_below_kernel: true,
            local_recording_only: true,
            can_execute_analysis: false,
            can_mutate_issues: false,
            can_mutate_quality_gates: false,
            can_create_webhooks: false,
            can_export_source: false,
            can_query_arbitrary_dsl: false,
            can_adopt_outcome: false,
            capability_digest: Digest::from_text("unsealed-sonarqube-capability"),
        };
        value.capability_digest = value.computed_digest();
        value
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.service_id,
            &self.operations,
            &self.endpoints,
            self.read_only,
            self.proposals_below_kernel,
            self.local_recording_only,
            self.can_execute_analysis,
            self.can_mutate_issues,
            self.can_mutate_quality_gates,
            self.can_create_webhooks,
            self.can_export_source,
            self.can_query_arbitrary_dsl,
            self.can_adopt_outcome,
        ))
    }

    pub fn validate(&self) -> Result<()> {
        let expected_operations = vec![
            "describe_capabilities".to_owned(),
            "read_project_analyses".to_owned(),
            "read_quality_gate_status".to_owned(),
            "read_component_measures".to_owned(),
            "compile_quality_result_proposal".to_owned(),
            "record_quality_result".to_owned(),
        ];
        if self.service_id != SERVICE_ID
            || self.operations != expected_operations
            || self.endpoints
                != vec![
                    crate::PROJECT_ANALYSES_SEARCH_PATH.to_owned(),
                    crate::QUALITY_GATE_STATUS_PATH.to_owned(),
                    crate::MEASURES_COMPONENT_PATH.to_owned(),
                ]
            || !self.read_only
            || !self.proposals_below_kernel
            || !self.local_recording_only
            || self.can_execute_analysis
            || self.can_mutate_issues
            || self.can_mutate_quality_gates
            || self.can_create_webhooks
            || self.can_export_source
            || self.can_query_arbitrary_dsl
            || self.can_adopt_outcome
            || self.capability_digest != self.computed_digest()
        {
            Err(SonarQubeQualityResultError::InvalidRegistration)
        } else {
            Ok(())
        }
    }
}

/// A registration binds version, contract, provider/API/capability,
/// permission, exact scope, opaque secret handle, and a monotonic revision.
#[derive(Clone, Eq, PartialEq)]
pub struct SonarQubeQualityRegistration {
    id: RegistrationId,
    plugin_version: Version,
    contract_version: String,
    contract_digest: Digest,
    provider: ProviderIdentity,
    capability_digest: Digest,
    permission_snapshot: crate::PermissionSnapshot,
    scope: SonarQubeQualityScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl SonarQubeQualityRegistration {
    pub fn new(
        id: RegistrationId,
        scope: SonarQubeQualityScope,
        secret_reference: SecretReference,
        permission_snapshot: crate::PermissionSnapshot,
        provider: ProviderIdentity,
        registration_revision: u64,
    ) -> Result<Self> {
        let capability = CapabilityDescription::recording();
        let mut registration = Self {
            id,
            plugin_version: Version::new(1, 0, 0),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider,
            capability_digest: capability.capability_digest,
            permission_snapshot,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-sonarqube-registration"),
        };
        registration.registration_digest = registration.computed_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn validate(&self) -> Result<()> {
        self.id.validate()?;
        self.scope.validate()?;
        self.provider.validate()?;
        self.permission_snapshot.validate()?;
        if self.capability_digest != CapabilityDescription::recording().capability_digest {
            return Err(SonarQubeQualityResultError::InvalidRegistration);
        }
        if self.plugin_version != Version::new(1, 0, 0)
            || self.plugin_version.to_string() != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.registration_digest != self.computed_digest()
        {
            return Err(SonarQubeQualityResultError::InvalidRegistration);
        }
        self.secret_reference.validate_shape()
    }

    pub fn id(&self) -> &RegistrationId {
        &self.id
    }

    pub const fn plugin_version(&self) -> Version {
        self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider(&self) -> &ProviderIdentity {
        &self.provider
    }

    pub fn capability_digest(&self) -> &Digest {
        &self.capability_digest
    }

    pub fn permission_snapshot(&self) -> &crate::PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn scope(&self) -> &SonarQubeQualityScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn is_active(&self) -> bool {
        self.status == RegistrationStatus::Active && !self.secret_reference.is_revoked()
    }

    pub fn unmount(&mut self) -> Result<()> {
        match self.status {
            RegistrationStatus::Active | RegistrationStatus::Unmounted => {
                self.status = RegistrationStatus::Unmounted;
                Ok(())
            }
            RegistrationStatus::Revoked => Err(SonarQubeQualityResultError::RegistrationRevoked),
        }
    }

    pub fn remount(&mut self) -> Result<()> {
        match self.status {
            RegistrationStatus::Active => Ok(()),
            RegistrationStatus::Unmounted => {
                self.status = RegistrationStatus::Active;
                Ok(())
            }
            RegistrationStatus::Revoked => Err(SonarQubeQualityResultError::RegistrationRevoked),
        }
    }

    pub fn revoke(&mut self) -> Result<()> {
        self.status = RegistrationStatus::Revoked;
        Ok(())
    }

    pub fn revoke_secret_reference(&mut self) {
        self.secret_reference.revoke();
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_parts(
            "sonarqube-registration-binding/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("plugin_version", self.plugin_version.to_string()),
                ("contract_version", self.contract_version.clone()),
                ("contract_digest", self.contract_digest.as_str().to_owned()),
                (
                    "provider_digest",
                    self.provider.provider_digest.as_str().to_owned(),
                ),
                ("api_digest", self.provider.api_digest.as_str().to_owned()),
                (
                    "capability_digest",
                    self.capability_digest.as_str().to_owned(),
                ),
                (
                    "permission_digest",
                    self.permission_snapshot.digest().as_str().to_owned(),
                ),
                ("scope_digest", self.scope_digest.as_str().to_owned()),
                (
                    "secret_reference_digest",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                (
                    "secret_revision",
                    self.secret_reference.revision().to_string(),
                ),
                (
                    "registration_revision",
                    self.registration_revision.to_string(),
                ),
            ],
        )
    }
}

impl fmt::Debug for SonarQubeQualityRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SonarQubeQualityRegistration")
            .field("id", &self.id)
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider", &self.provider)
            .field("capability_digest", &self.capability_digest)
            .field("permission_digest", &self.permission_snapshot.digest())
            .field("scope", &self.scope)
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference", &self.secret_reference)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for SonarQubeQualityRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SonarQubeQualityRegistration", 15)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("provider", &self.provider)?;
        state.serialize_field("capabilityDigest", &self.capability_digest)?;
        state.serialize_field("permissionSnapshot", &self.permission_snapshot)?;
        state.serialize_field("scope", &self.scope)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field(
            "secretReferenceDigest",
            self.secret_reference.reference_digest(),
        )?;
        state.serialize_field("secretKind", &self.secret_reference.kind())?;
        state.serialize_field("secretRevision", &self.secret_reference.revision())?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub registration_id: RegistrationId,
    pub status: RegistrationStatus,
    pub registration_revision: u64,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub capability_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
    pub receipt_digest: Digest,
}

impl RegistrationReceipt {
    fn from_registration(registration: &SonarQubeQualityRegistration) -> Self {
        let mut receipt = Self {
            registration_id: registration.id.clone(),
            status: registration.status,
            registration_revision: registration.registration_revision,
            contract_digest: registration.contract_digest.clone(),
            provider_digest: registration.provider.provider_digest.clone(),
            api_digest: registration.provider.api_digest.clone(),
            capability_digest: registration.capability_digest.clone(),
            permission_digest: registration.permission_snapshot.digest().clone(),
            scope_digest: registration.scope_digest.clone(),
            secret_reference_digest: registration.secret_reference.reference_digest().clone(),
            connected: false,
            native: false,
            first_party: false,
            durable_provider_receipt: false,
            receipt_digest: Digest::from_text("unsealed-sonarqube-registration-receipt"),
        };
        receipt.receipt_digest = receipt.computed_digest();
        receipt
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.registration_id,
            self.status,
            self.registration_revision,
            &self.contract_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.capability_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.secret_reference_digest,
            self.connected,
            self.native,
            self.first_party,
            self.durable_provider_receipt,
        ))
    }
}

/// The typed Layer-1 service. The generic transport is intentionally confined
/// to the nested crate and has no write or native-credential API.
#[derive(Clone, Debug)]
pub struct SonarQubeQualityResultService<T: SonarQubeTransport> {
    provider: SonarQubeProvider<T>,
    registration: SonarQubeQualityRegistration,
    capabilities: CapabilityDescription,
}

impl<T: SonarQubeTransport> SonarQubeQualityResultService<T> {
    pub fn new(
        provider: SonarQubeProvider<T>,
        scope: SonarQubeQualityScope,
        secret_reference: SecretReference,
        registration_id: RegistrationId,
    ) -> Result<Self> {
        Self::new_with_permissions(
            provider,
            scope,
            secret_reference,
            registration_id,
            crate::PermissionSnapshot::read_only(),
        )
    }

    pub fn new_with_permissions(
        provider: SonarQubeProvider<T>,
        scope: SonarQubeQualityScope,
        secret_reference: SecretReference,
        registration_id: RegistrationId,
        permission_snapshot: crate::PermissionSnapshot,
    ) -> Result<Self> {
        let provider_identity = ProviderIdentity::recording(1, "layer1-recording")?;
        let registration = SonarQubeQualityRegistration::new(
            registration_id,
            scope,
            secret_reference,
            permission_snapshot,
            provider_identity,
            1,
        )?;
        Self::from_registration(provider, registration)
    }

    pub fn from_registration(
        provider: SonarQubeProvider<T>,
        registration: SonarQubeQualityRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        let capabilities = CapabilityDescription::recording();
        capabilities.validate()?;
        Ok(Self {
            provider,
            registration,
            capabilities,
        })
    }

    pub fn registration(&self) -> &SonarQubeQualityRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut SonarQubeQualityRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &SonarQubeProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut SonarQubeProvider<T> {
        &mut self.provider
    }

    pub fn capabilities(&self) -> &CapabilityDescription {
        &self.capabilities
    }

    pub fn contract_json(&self) -> &'static str {
        crate::CONTRACT_JSON
    }

    pub fn registration_receipt(&self) -> RegistrationReceipt {
        RegistrationReceipt::from_registration(&self.registration)
    }

    pub fn read_quality_result(
        &mut self,
    ) -> std::result::Result<SonarQubeQualityProjection, SonarQubeProviderError> {
        self.ensure_readable()?;
        self.provider.read_quality_result(
            self.registration.scope(),
            self.registration.secret_reference(),
        )
    }

    pub fn compile_quality_result_proposal(
        &self,
        projection: &SonarQubeQualityProjection,
        idempotency_key: impl Into<String>,
    ) -> Result<SonarQubeQualityProposal> {
        self.ensure_readable().map_err(|error| match error {
            SonarQubeProviderError::Contract(error) => error,
            SonarQubeProviderError::RegistrationInactive => {
                SonarQubeQualityResultError::RegistrationUnmounted
            }
            SonarQubeProviderError::RegistrationRevoked => {
                SonarQubeQualityResultError::RegistrationRevoked
            }
            SonarQubeProviderError::SecretRevoked => SonarQubeQualityResultError::SecretRevoked,
            _ => SonarQubeQualityResultError::RegistrationDrift,
        })?;
        MissionSonarQubeQualityConsumer::new(self.registration.scope().clone())?
            .compile_quality_result_proposal(&self.registration, projection, idempotency_key)
    }

    pub fn record_quality_result(
        &self,
        log: &mut SonarQubeQualityRecordingLog,
        proposal: &SonarQubeQualityProposal,
    ) -> Result<RecordedSonarQubeQualityResult> {
        self.ensure_readable().map_err(|error| match error {
            SonarQubeProviderError::Contract(error) => error,
            SonarQubeProviderError::RegistrationInactive => {
                SonarQubeQualityResultError::RegistrationUnmounted
            }
            SonarQubeProviderError::RegistrationRevoked => {
                SonarQubeQualityResultError::RegistrationRevoked
            }
            SonarQubeProviderError::SecretRevoked => SonarQubeQualityResultError::SecretRevoked,
            _ => SonarQubeQualityResultError::RegistrationDrift,
        })?;
        if proposal.registration_id != *self.registration.id()
            || proposal.registration_revision != self.registration.registration_revision()
            || proposal.registration_digest != *self.registration.registration_digest()
        {
            return Err(SonarQubeQualityResultError::RegistrationDrift);
        }
        MissionSonarQubeQualityConsumer::new(self.registration.scope().clone())?
            .record_quality_result(log, proposal)
    }

    pub fn unmount(&mut self) -> Result<RegistrationReceipt> {
        self.registration.unmount()?;
        Ok(self.registration_receipt())
    }

    pub fn remount(&mut self) -> Result<RegistrationReceipt> {
        self.registration.remount()?;
        Ok(self.registration_receipt())
    }

    pub fn revoke(&mut self) -> Result<RegistrationReceipt> {
        self.registration.revoke()?;
        Ok(self.registration_receipt())
    }

    pub fn revoke_secret_reference(&mut self) -> RegistrationReceipt {
        self.registration.revoke_secret_reference();
        self.registration_receipt()
    }

    fn ensure_readable(&self) -> std::result::Result<(), SonarQubeProviderError> {
        self.registration
            .validate()
            .map_err(SonarQubeProviderError::Contract)?;
        match self.registration.status() {
            RegistrationStatus::Active => {
                if self.registration.secret_reference().is_revoked() {
                    Err(SonarQubeProviderError::SecretRevoked)
                } else {
                    Ok(())
                }
            }
            RegistrationStatus::Unmounted => Err(SonarQubeProviderError::RegistrationInactive),
            RegistrationStatus::Revoked => Err(SonarQubeProviderError::RegistrationRevoked),
        }
    }
}

pub type SonarQubeRegistration = SonarQubeQualityRegistration;

#[derive(Clone, Debug, Default)]
pub struct SonarQubeRegistrationRegistry {
    registrations: BTreeMap<RegistrationId, SonarQubeQualityRegistration>,
}

impl SonarQubeRegistrationRegistry {
    pub fn register(&mut self, registration: SonarQubeQualityRegistration) -> Result<()> {
        registration.validate()?;
        if self.registrations.contains_key(registration.id()) {
            return Err(SonarQubeQualityResultError::RegistrationAlreadyExists);
        }
        self.registrations
            .insert(registration.id().clone(), registration);
        Ok(())
    }

    pub fn get(&self, id: &RegistrationId) -> Option<&SonarQubeQualityRegistration> {
        self.registrations.get(id)
    }

    pub fn revoke(&mut self, id: &RegistrationId) -> Result<()> {
        let registration = self
            .registrations
            .get_mut(id)
            .ok_or(SonarQubeQualityResultError::RegistrationUnknown)?;
        registration.revoke()
    }

    pub fn len(&self) -> usize {
        self.registrations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.registrations.is_empty()
    }
}
