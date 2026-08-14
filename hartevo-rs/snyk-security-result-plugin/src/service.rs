//! Typed Snyk service and reversible registration boundary.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::{RecordedSecurityResult, SecurityResultProposal, SecurityResultRecordingLog};
use crate::model::{
    Digest, PermissionSnapshot, PluginVersion, RegistrationId, RegistrationStatus, SecretReference,
    SnykScope,
};
use crate::provider::{ProjectSnapshotProjection, SnykProvider, SnykTransport};
use crate::{
    CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID, Result,
    SERVICE_ID, SnykProviderError, SnykSecurityResultError, contract_digest, validate_text,
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
            return Err(SnykSecurityResultError::InvalidRegistration);
        }
        validate_text(&self.release, "providerRelease", 128)
    }
}

/// A version/contract/provider/permission/scope/secret-bound registration.
/// Only the opaque secret digest is serializable.
#[derive(Clone, Eq, PartialEq)]
pub struct SnykRegistration {
    id: RegistrationId,
    plugin_version: PluginVersion,
    contract_version: String,
    contract_digest: Digest,
    provider: ProviderIdentity,
    permission_snapshot: PermissionSnapshot,
    scope: SnykScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    binding_digest: Digest,
}

impl SnykRegistration {
    pub fn new(
        id: RegistrationId,
        scope: SnykScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        provider: ProviderIdentity,
        registration_revision: u64,
    ) -> Result<Self> {
        let mut registration = Self {
            id,
            plugin_version: PluginVersion::V1,
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::from_hex(CONTRACT_DIGEST)?,
            provider,
            permission_snapshot,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            binding_digest: Digest::from_text("unsealed-snyk-registration"),
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
            return Err(SnykSecurityResultError::InvalidRegistration);
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

    pub fn scope(&self) -> &SnykScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    /// Revoke the opaque host-owned credential binding without exposing or
    /// resolving its underlying API token or OAuth material.
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

    pub fn is_active(&self) -> bool {
        self.status == RegistrationStatus::Active && !self.secret_reference.is_revoked()
    }

    /// Revocation blocks future reads but keeps the registration for audit.
    pub fn revoke(&mut self) -> Result<()> {
        match self.status {
            RegistrationStatus::Active | RegistrationStatus::Revoked => {
                self.status = RegistrationStatus::Revoked;
                Ok(())
            }
            RegistrationStatus::Reversed => Err(SnykSecurityResultError::RegistrationReversed),
        }
    }

    /// Reversal is the explicit, non-deleting unmount path.
    pub fn reverse(&mut self) -> Result<()> {
        self.status = RegistrationStatus::Reversed;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<()> {
        match self.status {
            RegistrationStatus::Revoked => {
                self.status = RegistrationStatus::Active;
                Ok(())
            }
            RegistrationStatus::Active => Ok(()),
            RegistrationStatus::Reversed => Err(SnykSecurityResultError::RegistrationReversed),
        }
    }

    fn calculate_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "snyk-registration-binding/v1",
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

impl fmt::Debug for SnykRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnykRegistration")
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

impl Serialize for SnykRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SnykRegistration", 14)?;
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
    pub binding_digest: Digest,
    pub scope_digest: Digest,
    pub registration_revision: u64,
    pub receipt_digest: Digest,
}

impl RegistrationReceipt {
    fn for_registration(registration: &SnykRegistration) -> Self {
        let mut receipt = Self {
            registration_id: registration.id.clone(),
            binding_digest: registration.binding_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            registration_revision: registration.registration_revision,
            receipt_digest: Digest::from_text("unsealed-snyk-registration-receipt"),
        };
        receipt.receipt_digest = Digest::from_serialized(&(
            receipt.registration_id.as_str(),
            receipt.binding_digest.as_str(),
            receipt.scope_digest.as_str(),
            receipt.registration_revision,
        ));
        receipt
    }
}

#[derive(Clone, Debug, Default)]
pub struct SnykRegistrationRegistry {
    registrations: BTreeMap<RegistrationId, SnykRegistration>,
}

impl SnykRegistrationRegistry {
    pub fn register(&mut self, registration: SnykRegistration) -> Result<RegistrationReceipt> {
        registration.validate()?;
        if self.registrations.contains_key(registration.id()) {
            return Err(SnykSecurityResultError::RegistrationAlreadyExists);
        }
        let receipt = RegistrationReceipt::for_registration(&registration);
        self.registrations
            .insert(registration.id.clone(), registration);
        Ok(receipt)
    }

    pub fn get(&self, id: &RegistrationId) -> Result<&SnykRegistration> {
        self.registrations
            .get(id)
            .ok_or(SnykSecurityResultError::RegistrationUnknown)
    }

    pub fn get_mut(&mut self, id: &RegistrationId) -> Result<&mut SnykRegistration> {
        self.registrations
            .get_mut(id)
            .ok_or(SnykSecurityResultError::RegistrationUnknown)
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

    pub fn iter(&self) -> impl Iterator<Item = &SnykRegistration> {
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
    pub can_ignore: bool,
    pub can_remediate: bool,
    pub can_import_project: bool,
    pub can_delete_project: bool,
    pub can_export_source: bool,
    pub can_retain_dependency_graph: bool,
    pub can_adopt_outcome: bool,
}

#[derive(Debug)]
pub struct SnykSecurityResultService<T> {
    provider: SnykProvider<T>,
}

impl<T: SnykTransport> SnykSecurityResultService<T> {
    pub fn new(
        registration: SnykRegistration,
        transport: T,
    ) -> std::result::Result<Self, SnykProviderError> {
        Ok(Self {
            provider: SnykProvider::new(registration, transport)?,
        })
    }

    pub fn provider(&self) -> &SnykProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut SnykProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &SnykRegistration {
        self.provider.registration()
    }

    pub fn registration_mut(&mut self) -> &mut SnykRegistration {
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
            can_ignore: false,
            can_remediate: false,
            can_import_project: false,
            can_delete_project: false,
            can_export_source: false,
            can_retain_dependency_graph: false,
            can_adopt_outcome: false,
        }
    }

    pub fn read_project_snapshot(
        &mut self,
        request_id: impl Into<String>,
    ) -> std::result::Result<ProjectSnapshotProjection, SnykProviderError> {
        self.provider.read_project_snapshot(request_id)
    }

    pub fn read_snapshot(
        &mut self,
        request_id: impl Into<String>,
    ) -> std::result::Result<ProjectSnapshotProjection, SnykProviderError> {
        self.provider.read_snapshot(request_id)
    }

    pub fn compile_security_result_proposal(
        &self,
        projection: &ProjectSnapshotProjection,
        idempotency_key: impl Into<String>,
    ) -> Result<SecurityResultProposal> {
        crate::MissionSnykSecurityConsumer::new(self.registration().scope().clone())
            .compile_security_result_proposal(projection, idempotency_key)
    }

    pub fn record_security_result(
        &self,
        log: &mut SecurityResultRecordingLog,
        proposal: &SecurityResultProposal,
    ) -> Result<RecordedSecurityResult> {
        crate::MissionSnykSecurityConsumer::new(self.registration().scope().clone())
            .record_security_result(proposal, log)
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
