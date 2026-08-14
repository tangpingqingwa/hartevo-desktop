//! Typed JFrog service and reversible registration boundary.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::{
    JfrogArtifactRecordingLog, JfrogArtifactReleaseProposal, MissionJfrogArtifactConsumer,
    RecordedJfrogArtifactResult,
};
use crate::model::{
    Digest, JfrogScope, PermissionSnapshot, PluginVersion, RegistrationId, RegistrationStatus,
    SecretReference,
};
use crate::provider::{
    JfrogArtifactProjection, JfrogArtifactoryProvider, JfrogArtifactoryTransport,
};
use crate::{
    CONTRACT_DIGEST, CONTRACT_VERSION, JfrogArtifactoryResultError, JfrogProviderError,
    PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID, Result, SERVICE_ID, contract_digest,
    validate_text,
};

/// Provider metadata is descriptive only; it never grants native execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderIdentity {
    pub provider_id: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub release: String,
}

impl ProviderIdentity {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let identity = Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            release: release.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.api_revision != PROVIDER_API_REVISION
            || self.provider_revision == 0
        {
            return Err(JfrogArtifactoryResultError::InvalidRegistration);
        }
        validate_text(&self.release, "providerRelease", 128, false)
    }
}

pub type JfrogArtifactoryProviderIdentity = ProviderIdentity;
pub type JfrogArtifactoryRegistration = JfrogRegistration;

/// A version/contract/provider/permission/scope/secret-bound registration.
/// The secret handle itself is intentionally not serializable.
#[derive(Clone, Eq, PartialEq)]
pub struct JfrogRegistration {
    id: RegistrationId,
    plugin_version: PluginVersion,
    contract_version: String,
    contract_digest: Digest,
    provider: ProviderIdentity,
    permission_snapshot: PermissionSnapshot,
    scope: JfrogScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    binding_digest: Digest,
}

impl JfrogRegistration {
    pub fn new(
        id: RegistrationId,
        scope: JfrogScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        provider: ProviderIdentity,
        registration_revision: u64,
    ) -> Result<Self> {
        let mut registration = Self {
            id,
            plugin_version: PluginVersion::V1,
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST)?,
            provider,
            permission_snapshot,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            binding_digest: Digest::from_text("unsealed-jfrog-registration"),
        };
        registration.binding_digest = registration.calculate_binding_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn validate(&self) -> Result<()> {
        self.id.validate()?;
        if self.plugin_version != PluginVersion::V1
            || self.plugin_version.to_string() != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != contract_digest()
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.binding_digest != self.calculate_binding_digest()
        {
            return Err(JfrogArtifactoryResultError::InvalidRegistration);
        }
        self.provider.validate()?;
        self.permission_snapshot.validate()?;
        self.scope.validate()?;
        self.secret_reference.validate()
    }

    pub fn id(&self) -> &RegistrationId {
        &self.id
    }

    pub const fn plugin_version(&self) -> PluginVersion {
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

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn scope(&self) -> &JfrogScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn revoke_secret_reference(&mut self) {
        self.secret_reference.revoke();
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn is_active(&self) -> bool {
        self.status == RegistrationStatus::Active && !self.secret_reference.is_revoked()
    }

    /// Revocation blocks future reads but preserves registration evidence.
    pub fn revoke(&mut self) -> Result<()> {
        match self.status {
            RegistrationStatus::Active | RegistrationStatus::Revoked => {
                self.status = RegistrationStatus::Revoked;
                Ok(())
            }
            RegistrationStatus::Reversed => Err(JfrogArtifactoryResultError::RegistrationReversed),
        }
    }

    /// Reversal is the explicit non-deleting unmount path.
    pub fn reverse(&mut self) -> Result<()> {
        self.status = RegistrationStatus::Reversed;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<()> {
        match self.status {
            RegistrationStatus::Active | RegistrationStatus::Revoked => {
                self.status = RegistrationStatus::Active;
                Ok(())
            }
            RegistrationStatus::Reversed => Err(JfrogArtifactoryResultError::RegistrationReversed),
        }
    }

    fn calculate_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "jfrog-registration-binding/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("plugin_version", self.plugin_version.to_string()),
                ("contract_version", self.contract_version.clone()),
                ("contract_digest", self.contract_digest.as_str().to_owned()),
                (
                    "provider",
                    serde_json::to_string(&self.provider).expect("provider metadata"),
                ),
                (
                    "permissions",
                    self.permission_snapshot.digest().as_str().to_owned(),
                ),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "secret",
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

impl fmt::Debug for JfrogRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JfrogRegistration")
            .field("id", &self.id)
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider", &self.provider)
            .field("permission_digest", &self.permission_snapshot.digest())
            .field("scope_digest", &self.scope_digest)
            .field("scope", &self.scope)
            .field("secret_reference", &self.secret_reference)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("binding_digest", &self.binding_digest)
            .finish()
    }
}

impl Serialize for JfrogRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("JfrogRegistration", 14)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("provider", &self.provider)?;
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
        state.serialize_field("bindingDigest", &self.binding_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub registration_id: RegistrationId,
    pub status: RegistrationStatus,
    pub binding_digest: Digest,
    pub scope_digest: Digest,
    pub registration_revision: u64,
    pub transition_digest: Digest,
    pub receipt_digest: Digest,
}

impl RegistrationReceipt {
    fn for_registration(registration: &JfrogRegistration) -> Self {
        let transition_digest = Digest::from_serialized(&(
            &registration.id,
            registration.status,
            registration.registration_revision,
            &registration.binding_digest,
            &registration.scope_digest,
        ));
        let mut receipt = Self {
            registration_id: registration.id.clone(),
            status: registration.status,
            binding_digest: registration.binding_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            registration_revision: registration.registration_revision,
            transition_digest,
            receipt_digest: Digest::from_text("unsealed-jfrog-registration-receipt"),
        };
        receipt.receipt_digest = Digest::from_serialized(&(
            &receipt.registration_id,
            receipt.status,
            &receipt.binding_digest,
            &receipt.scope_digest,
            receipt.registration_revision,
            &receipt.transition_digest,
        ));
        receipt
    }
}

#[derive(Clone, Debug, Default)]
pub struct JfrogRegistrationRegistry {
    registrations: BTreeMap<RegistrationId, JfrogRegistration>,
}

impl JfrogRegistrationRegistry {
    pub fn register(&mut self, registration: JfrogRegistration) -> Result<RegistrationReceipt> {
        registration.validate()?;
        if self.registrations.contains_key(registration.id()) {
            return Err(JfrogArtifactoryResultError::RegistrationAlreadyExists);
        }
        let receipt = RegistrationReceipt::for_registration(&registration);
        self.registrations
            .insert(registration.id.clone(), registration);
        Ok(receipt)
    }

    pub fn get(&self, id: &RegistrationId) -> Result<&JfrogRegistration> {
        self.registrations
            .get(id)
            .ok_or(JfrogArtifactoryResultError::RegistrationUnknown)
    }

    pub fn get_mut(&mut self, id: &RegistrationId) -> Result<&mut JfrogRegistration> {
        self.registrations
            .get_mut(id)
            .ok_or(JfrogArtifactoryResultError::RegistrationUnknown)
    }

    pub fn revoke(&mut self, id: &RegistrationId) -> Result<RegistrationReceipt> {
        let registration = self.get_mut(id)?;
        registration.revoke()?;
        Ok(RegistrationReceipt::for_registration(registration))
    }

    pub fn reverse(&mut self, id: &RegistrationId) -> Result<RegistrationReceipt> {
        let registration = self.get_mut(id)?;
        registration.reverse()?;
        Ok(RegistrationReceipt::for_registration(registration))
    }

    pub fn restore(&mut self, id: &RegistrationId) -> Result<RegistrationReceipt> {
        let registration = self.get_mut(id)?;
        registration.restore()?;
        Ok(RegistrationReceipt::for_registration(registration))
    }

    pub fn iter(&self) -> impl Iterator<Item = &JfrogRegistration> {
        self.registrations.values()
    }
}

/// Capabilities are explicit and non-native. The service owns only bounded
/// reads and proposal/recording composition.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub can_read_build_info: bool,
    pub can_read_artifact_metadata: bool,
    pub can_query_allowlisted_aql: bool,
    pub can_upload: bool,
    pub can_download_bytes: bool,
    pub can_delete: bool,
    pub can_overwrite: bool,
    pub can_promote: bool,
    pub can_demote: bool,
    pub can_configure_repository: bool,
    pub can_mutate_xray: bool,
    pub can_adopt_outcome: bool,
}

#[derive(Debug)]
pub struct JfrogArtifactoryResultService<T> {
    provider: JfrogArtifactoryProvider<T>,
}

impl<T: JfrogArtifactoryTransport> JfrogArtifactoryResultService<T> {
    pub fn new(
        registration: JfrogRegistration,
        transport: T,
    ) -> std::result::Result<Self, JfrogProviderError> {
        Ok(Self {
            provider: JfrogArtifactoryProvider::new(registration, transport)?,
        })
    }

    pub fn provider(&self) -> &JfrogArtifactoryProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut JfrogArtifactoryProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &JfrogRegistration {
        self.provider.registration()
    }

    pub fn registration_mut(&mut self) -> &mut JfrogRegistration {
        self.provider.registration_mut()
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            read_only: true,
            connected: false,
            native: false,
            can_read_build_info: true,
            can_read_artifact_metadata: true,
            can_query_allowlisted_aql: true,
            can_upload: false,
            can_download_bytes: false,
            can_delete: false,
            can_overwrite: false,
            can_promote: false,
            can_demote: false,
            can_configure_repository: false,
            can_mutate_xray: false,
            can_adopt_outcome: false,
        }
    }

    pub fn read_artifact_metadata<S: Into<crate::provider::ArtifactReadSelector>>(
        &mut self,
        selector: S,
    ) -> std::result::Result<JfrogArtifactProjection, JfrogProviderError> {
        self.provider.read_artifact_metadata(selector)
    }

    pub fn read_release_evidence(
        &mut self,
        request_id: impl Into<String>,
    ) -> std::result::Result<JfrogArtifactProjection, JfrogProviderError> {
        self.provider.read_release_evidence(request_id)
    }

    pub fn read_build_info(
        &mut self,
        request_id: impl Into<String>,
    ) -> std::result::Result<JfrogArtifactProjection, JfrogProviderError> {
        self.provider.read_build_info(request_id)
    }

    pub fn read_artifact_metadata_with_page_size(
        &mut self,
        request_id: impl Into<String>,
        page_size: usize,
    ) -> std::result::Result<JfrogArtifactProjection, JfrogProviderError> {
        self.provider
            .read_artifact_metadata_with_page_size(request_id, page_size)
    }

    pub fn read_artifact_with_expected_checksums(
        &mut self,
        request_id: impl Into<String>,
        expected_checksums: impl AsRef<crate::ArtifactChecksums>,
    ) -> std::result::Result<JfrogArtifactProjection, JfrogProviderError> {
        self.provider
            .read_artifact_with_expected_checksums(request_id, expected_checksums)
    }

    pub fn read_aql_metadata(
        &mut self,
        request_id: impl Into<String>,
        page_size: usize,
    ) -> std::result::Result<JfrogArtifactProjection, JfrogProviderError> {
        self.provider.read_aql_metadata(request_id, page_size)
    }

    pub fn compile_release_decision_proposal(
        &self,
        projection: &JfrogArtifactProjection,
        idempotency_key: impl Into<String>,
    ) -> Result<JfrogArtifactReleaseProposal> {
        MissionJfrogArtifactConsumer::new(self.registration().scope().clone())
            .compile_release_decision_proposal(self.registration(), projection, idempotency_key)
    }

    pub fn record_release_decision(
        &self,
        log: &mut JfrogArtifactRecordingLog,
        proposal: &JfrogArtifactReleaseProposal,
    ) -> Result<RecordedJfrogArtifactResult> {
        if proposal.registration_id != *self.registration().id()
            || proposal.registration_revision != self.registration().registration_revision()
            || proposal.registration_digest != *self.registration().registration_digest()
        {
            return Err(JfrogArtifactoryResultError::RegistrationDrift);
        }
        MissionJfrogArtifactConsumer::new(self.registration().scope().clone())
            .record_release_decision(log, proposal)
    }

    pub fn revoke_registration(&mut self) -> Result<()> {
        self.provider.registration_mut().revoke()
    }

    pub fn reverse_registration(&mut self) -> Result<()> {
        self.provider.registration_mut().reverse()
    }

    pub fn restore_registration(&mut self) -> Result<()> {
        self.provider.registration_mut().restore()
    }
}
