//! Typed service and reversible registration boundary.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::{AirbyteSyncResultProposal, MissionAirbyteSyncConsumer};
use crate::model::{
    AirbyteScope, Digest, PermissionSnapshot, PluginVersion, RegistrationId, RegistrationStatus,
    SecretReference,
};
use crate::model::{CatalogProjection, SyncAttemptProjection};
use crate::provider::{AirbyteCloudProvider, AirbyteProviderError, AirbyteTransport};
use crate::{
    AirbyteSyncResultError, CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_VERSION,
    PROVIDER_API_REVISION, PROVIDER_ID, Result, SERVICE_ID, contract_digest, validate_text,
};

/// Provider identity is metadata only; it never grants native execution.
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
        let release = release.into();
        validate_text(&release, "providerRelease", 128)?;
        let identity = Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            release,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.api_revision != PROVIDER_API_REVISION
            || self.provider_revision == 0
        {
            return Err(AirbyteSyncResultError::InvalidRegistration);
        }
        validate_text(&self.release, "providerRelease", 128)
    }
}

/// A version/contract/provider/permission/scope/secret-bound registration.
/// The secret handle itself is never serialized; only its digest is retained
/// in the safe registration view.
#[derive(Clone, Eq, PartialEq)]
pub struct AirbyteRegistration {
    id: RegistrationId,
    plugin_version: PluginVersion,
    contract_version: String,
    contract_digest: Digest,
    provider: ProviderIdentity,
    permission_snapshot: PermissionSnapshot,
    scope: AirbyteScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    binding_digest: Digest,
}

impl AirbyteRegistration {
    pub fn new(
        id: RegistrationId,
        scope: AirbyteScope,
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
            binding_digest: Digest::from_text("unsealed-airbyte-registration"),
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
            return Err(AirbyteSyncResultError::InvalidRegistration);
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

    pub fn scope(&self) -> &AirbyteScope {
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

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn is_active(&self) -> bool {
        self.status == RegistrationStatus::Active
    }

    /// Revocation is idempotent and blocks future reads.
    pub fn revoke(&mut self) -> Result<()> {
        match self.status {
            RegistrationStatus::Active | RegistrationStatus::Revoked => {
                self.status = RegistrationStatus::Revoked;
                Ok(())
            }
            RegistrationStatus::Reversed => Err(AirbyteSyncResultError::RegistrationReversed),
        }
    }

    /// Reversal is the explicit unmount path. It is irreversible for this
    /// registration handle and does not delete historical evidence.
    pub fn reverse(&mut self) -> Result<()> {
        self.status = RegistrationStatus::Reversed;
        Ok(())
    }

    /// A revoked registration can be restored only before it is reversed.
    pub fn restore(&mut self) -> Result<()> {
        match self.status {
            RegistrationStatus::Revoked => {
                self.status = RegistrationStatus::Active;
                Ok(())
            }
            RegistrationStatus::Active => Ok(()),
            RegistrationStatus::Reversed => Err(AirbyteSyncResultError::RegistrationReversed),
        }
    }

    fn calculate_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "airbyte-registration-binding/v1",
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

impl fmt::Debug for AirbyteRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AirbyteRegistration")
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

impl Serialize for AirbyteRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AirbyteRegistration", 13)?;
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
    fn for_registration(registration: &AirbyteRegistration) -> Self {
        let mut receipt = Self {
            registration_id: registration.id.clone(),
            binding_digest: registration.binding_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            registration_revision: registration.registration_revision,
            receipt_digest: Digest::from_text("unsealed-airbyte-registration-receipt"),
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

/// Small in-process registry proving mount/revoke/reverse operations are
/// scope-bound and reversible without granting provider execution authority.
#[derive(Clone, Debug, Default)]
pub struct AirbyteRegistrationRegistry {
    registrations: BTreeMap<RegistrationId, AirbyteRegistration>,
}

impl AirbyteRegistrationRegistry {
    pub fn register(&mut self, registration: AirbyteRegistration) -> Result<RegistrationReceipt> {
        registration.validate()?;
        if self.registrations.contains_key(registration.id()) {
            return Err(AirbyteSyncResultError::RegistrationAlreadyExists);
        }
        let receipt = RegistrationReceipt::for_registration(&registration);
        self.registrations
            .insert(registration.id.clone(), registration);
        Ok(receipt)
    }

    pub fn get(&self, id: &RegistrationId) -> Result<&AirbyteRegistration> {
        self.registrations
            .get(id)
            .ok_or(AirbyteSyncResultError::RegistrationUnknown)
    }

    pub fn get_mut(&mut self, id: &RegistrationId) -> Result<&mut AirbyteRegistration> {
        self.registrations
            .get_mut(id)
            .ok_or(AirbyteSyncResultError::RegistrationUnknown)
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

    pub fn iter(&self) -> impl Iterator<Item = &AirbyteRegistration> {
        self.registrations.values()
    }
}

/// The typed Airbyte service. It delegates only bounded reads to the provider
/// and emits proposals/recordings through the Mission consumer seam.
#[derive(Debug)]
pub struct AirbyteSyncResultService<T> {
    provider: AirbyteCloudProvider<T>,
}

impl<T: AirbyteTransport> AirbyteSyncResultService<T> {
    pub fn new(
        registration: AirbyteRegistration,
        transport: T,
    ) -> std::result::Result<Self, AirbyteProviderError> {
        Ok(Self {
            provider: AirbyteCloudProvider::new(registration, transport)?,
        })
    }

    pub fn provider(&self) -> &AirbyteCloudProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AirbyteCloudProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AirbyteRegistration {
        self.provider.registration()
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
            can_trigger_sync: false,
            can_cancel_sync: false,
            can_mutate_connection: false,
            can_mutate_credential: false,
            can_adopt_outcome: false,
        }
    }

    pub fn read_connection_stream_catalog(
        &mut self,
        page_size: usize,
    ) -> std::result::Result<crate::CatalogProjection, AirbyteProviderError> {
        self.provider.read_catalog(page_size)
    }

    pub fn read_sync_attempt(
        &mut self,
        idempotency_key: &str,
    ) -> std::result::Result<crate::SyncAttemptProjection, AirbyteProviderError> {
        self.provider.read_attempt(idempotency_key)
    }

    pub fn compile_sync_result_proposal(
        &self,
        catalog: &CatalogProjection,
        attempt: &SyncAttemptProjection,
        idempotency_key: &str,
    ) -> Result<AirbyteSyncResultProposal> {
        MissionAirbyteSyncConsumer::new(self.registration().scope().clone()).compile_proposal(
            catalog,
            attempt,
            idempotency_key,
        )
    }

    pub fn record_sync_result(
        &self,
        log: &mut crate::SyncResultRecordingLog,
        proposal: &AirbyteSyncResultProposal,
    ) -> Result<crate::RecordedSyncResult> {
        MissionAirbyteSyncConsumer::new(self.registration().scope().clone()).record(log, proposal)
    }

    pub fn revoke_registration(&mut self) -> Result<()> {
        self.provider.registration_mut().revoke()
    }

    pub fn reverse_registration(&mut self) -> Result<()> {
        self.provider.registration_mut().reverse()
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub can_trigger_sync: bool,
    pub can_cancel_sync: bool,
    pub can_mutate_connection: bool,
    pub can_mutate_credential: bool,
    pub can_adopt_outcome: bool,
}
