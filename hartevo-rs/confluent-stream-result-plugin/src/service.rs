//! Typed service metadata, provider/API/permission/scope/revision-bound
//! registration, and the Layer-1 service facade.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::{
    ConfluentStreamResultProposal, MissionConfluentStreamConsumer, RecordedStreamResult,
    StreamResultRecordingLog,
};
use crate::model::{
    ConfluentScope, Digest, PermissionSnapshot, PluginVersion, RegistrationId, RegistrationStatus,
    SecretReference,
};
use crate::provider::{ConfluentProvider, ConfluentProviderError, ConfluentTransport};
use crate::{
    CONTRACT_DIGEST, CONTRACT_VERSION, ConfluentStreamResultError, PLUGIN_VERSION,
    PROVIDER_API_REVISION, PROVIDER_ID, Result, SERVICE_ID, contract_digest, validate_text,
};

/// Provider metadata is descriptive and digest-bound; it never grants native
/// execution authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderIdentity {
    pub provider_id: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub release: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
}

impl ProviderIdentity {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        validate_text(&release, "providerRelease", 128)?;
        if provider_revision == 0 {
            return Err(ConfluentStreamResultError::InvalidRegistration);
        }
        let api_digest = Digest::from_parts(
            "confluent-api-revision/v1",
            &[("api_revision", PROVIDER_API_REVISION.to_owned())],
        );
        let mut identity = Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            release,
            provider_digest: Digest::from_text("unsealed-confluent-provider"),
            api_digest,
        };
        identity.provider_digest = identity.calculate_provider_digest();
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.api_revision != PROVIDER_API_REVISION
            || self.provider_revision == 0
            || self.api_digest
                != Digest::from_parts(
                    "confluent-api-revision/v1",
                    &[("api_revision", PROVIDER_API_REVISION.to_owned())],
                )
            || self.provider_digest != self.calculate_provider_digest()
        {
            return Err(ConfluentStreamResultError::InvalidRegistration);
        }
        validate_text(&self.release, "providerRelease", 128)
    }

    pub fn digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }

    fn calculate_provider_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.provider_id,
            self.provider_revision,
            &self.api_revision,
            &self.release,
            &self.api_digest,
        ))
    }
}

/// A reversible registration bound to every identity and revision that can
/// affect a Confluent observation.
#[derive(Clone, Eq, PartialEq)]
pub struct ConfluentRegistration {
    id: RegistrationId,
    plugin_version: PluginVersion,
    contract_version: String,
    contract_digest: Digest,
    provider: ProviderIdentity,
    permission_snapshot: PermissionSnapshot,
    scope: ConfluentScope,
    scope_digest: Digest,
    revision_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    binding_digest: Digest,
}

impl ConfluentRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: RegistrationId,
        scope: ConfluentScope,
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
            revision_digest: scope.revision_digest(),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            binding_digest: Digest::from_text("unsealed-confluent-registration"),
        };
        registration.binding_digest = registration.calculate_binding_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn validate(&self) -> Result<()> {
        self.id.validate()?;
        self.provider.validate()?;
        self.permission_snapshot.validate()?;
        self.scope.validate()?;
        self.secret_reference.validate()?;
        if self.plugin_version != PluginVersion::V1
            || self.plugin_version.to_string() != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest()
            || self.scope_digest != self.scope.digest()
            || self.revision_digest != self.scope.revision_digest()
            || self.registration_revision == 0
            || self.binding_digest != self.calculate_binding_digest()
        {
            return Err(ConfluentStreamResultError::InvalidRegistration);
        }
        Ok(())
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

    pub fn scope(&self) -> &ConfluentScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
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

    /// Revoke is idempotent and blocks future provider reads.
    pub fn revoke(&mut self) -> Result<()> {
        match self.status {
            RegistrationStatus::Active | RegistrationStatus::Revoked => {
                self.status = RegistrationStatus::Revoked;
                Ok(())
            }
            RegistrationStatus::Reversed => Err(ConfluentStreamResultError::RegistrationReversed),
        }
    }

    /// Reverse is the explicit unmount path and does not erase recordings.
    pub fn reverse(&mut self) -> Result<()> {
        self.status = RegistrationStatus::Reversed;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<()> {
        match self.status {
            RegistrationStatus::Active => Ok(()),
            RegistrationStatus::Revoked => {
                self.status = RegistrationStatus::Active;
                Ok(())
            }
            RegistrationStatus::Reversed => Err(ConfluentStreamResultError::RegistrationReversed),
        }
    }

    fn calculate_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "confluent-registration-binding/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("plugin_version", self.plugin_version.to_string()),
                ("contract_version", self.contract_version.clone()),
                ("contract_digest", self.contract_digest.as_str().to_owned()),
                (
                    "provider_digest",
                    self.provider.digest().as_str().to_owned(),
                ),
                ("api_digest", self.provider.api_digest().as_str().to_owned()),
                (
                    "permission_digest",
                    self.permission_snapshot.digest().as_str().to_owned(),
                ),
                ("scope_digest", self.scope_digest.as_str().to_owned()),
                ("revision_digest", self.revision_digest.as_str().to_owned()),
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

impl fmt::Debug for ConfluentRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfluentRegistration")
            .field("id", &self.id)
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider", &self.provider)
            .field("permission_digest", &self.permission_snapshot.digest())
            .field("scope_digest", &self.scope_digest)
            .field("revision_digest", &self.revision_digest)
            .field("scope", &self.scope)
            .field("secret_reference", &self.secret_reference)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("binding_digest", &self.binding_digest)
            .finish()
    }
}

impl Serialize for ConfluentRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ConfluentRegistration", 15)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("provider", &self.provider)?;
        state.serialize_field("permissionSnapshot", &self.permission_snapshot)?;
        state.serialize_field("scope", &self.scope)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("revisionDigest", &self.revision_digest)?;
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
    pub revision_digest: Digest,
    pub registration_revision: u64,
    pub receipt_digest: Digest,
}

impl RegistrationReceipt {
    fn for_registration(registration: &ConfluentRegistration) -> Self {
        let mut receipt = Self {
            registration_id: registration.id.clone(),
            binding_digest: registration.binding_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            revision_digest: registration.revision_digest.clone(),
            registration_revision: registration.registration_revision,
            receipt_digest: Digest::from_text("unsealed-confluent-registration-receipt"),
        };
        receipt.receipt_digest = Digest::from_serialized(&(
            &receipt.registration_id,
            &receipt.binding_digest,
            &receipt.scope_digest,
            &receipt.revision_digest,
            receipt.registration_revision,
        ));
        receipt
    }
}

#[derive(Clone, Debug, Default)]
pub struct ConfluentRegistrationRegistry {
    registrations: BTreeMap<RegistrationId, ConfluentRegistration>,
}

impl ConfluentRegistrationRegistry {
    pub fn register(&mut self, registration: ConfluentRegistration) -> Result<RegistrationReceipt> {
        registration.validate()?;
        if self.registrations.contains_key(registration.id()) {
            return Err(ConfluentStreamResultError::RegistrationAlreadyExists);
        }
        let receipt = RegistrationReceipt::for_registration(&registration);
        self.registrations
            .insert(registration.id.clone(), registration);
        Ok(receipt)
    }

    pub fn get(&self, id: &RegistrationId) -> Result<&ConfluentRegistration> {
        self.registrations
            .get(id)
            .ok_or(ConfluentStreamResultError::RegistrationUnknown)
    }

    pub fn get_mut(&mut self, id: &RegistrationId) -> Result<&mut ConfluentRegistration> {
        self.registrations
            .get_mut(id)
            .ok_or(ConfluentStreamResultError::RegistrationUnknown)
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

    pub fn iter(&self) -> impl Iterator<Item = &ConfluentRegistration> {
        self.registrations.values()
    }
}

/// The typed Layer-1 service facade. Its methods expose only bounded reads,
/// review proposals, and an idempotent in-process recording seam.
#[derive(Debug)]
pub struct ConfluentStreamResultService<T> {
    provider: ConfluentProvider<T>,
}

impl<T: ConfluentTransport> ConfluentStreamResultService<T> {
    pub fn new(
        registration: ConfluentRegistration,
        transport: T,
    ) -> std::result::Result<Self, ConfluentProviderError> {
        Ok(Self {
            provider: ConfluentProvider::new(registration, transport)?,
        })
    }

    pub fn provider(&self) -> &ConfluentProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut ConfluentProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &ConfluentRegistration {
        self.provider.registration()
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription::layer_one()
    }

    pub fn read_connector_status(
        &mut self,
    ) -> std::result::Result<crate::ConnectorStatusProjection, ConfluentProviderError> {
        self.provider.read_connector_status()
    }

    pub fn read_consumer_group_lag(
        &mut self,
        page_size: usize,
    ) -> std::result::Result<crate::ConsumerGroupLagProjection, ConfluentProviderError> {
        self.provider.read_consumer_group_lag(page_size)
    }

    pub fn read_metric_window(
        &mut self,
    ) -> std::result::Result<crate::MetricProjection, ConfluentProviderError> {
        self.provider.read_metric_window()
    }

    pub fn compile_stream_result_proposal(
        &self,
        connector: &crate::ConnectorStatusProjection,
        group: &crate::ConsumerGroupLagProjection,
        metrics: &crate::MetricProjection,
        idempotency_key: &str,
    ) -> Result<ConfluentStreamResultProposal> {
        if !self.registration().is_active() {
            return Err(ConfluentStreamResultError::RegistrationRevoked);
        }
        let consumer = MissionConfluentStreamConsumer::new(self.registration().scope().clone());
        consumer.compile_proposal(
            self.registration().binding_digest().clone(),
            connector,
            group,
            metrics,
            idempotency_key,
        )
    }

    pub fn record_stream_result(
        &self,
        log: &mut StreamResultRecordingLog,
        proposal: &ConfluentStreamResultProposal,
    ) -> Result<RecordedStreamResult> {
        if !self.registration().is_active() {
            return Err(ConfluentStreamResultError::RegistrationRevoked);
        }
        let consumer = MissionConfluentStreamConsumer::new(self.registration().scope().clone());
        consumer.record(log, proposal)
    }

    pub fn revoke_registration(&mut self) -> Result<()> {
        self.provider.registration_mut().revoke()
    }

    pub fn reverse_registration(&mut self) -> Result<()> {
        self.provider.registration_mut().reverse()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub can_read_connector_status: bool,
    pub can_read_consumer_group_lag: bool,
    pub can_read_metric_window: bool,
    pub can_access_kafka_records: bool,
    pub can_produce: bool,
    pub can_consume: bool,
    pub can_mutate_topics: bool,
    pub can_mutate_acls: bool,
    pub can_mutate_connectors: bool,
    pub can_query_arbitrary_metrics: bool,
    pub can_register_generic_events: bool,
    pub can_adopt_outcome: bool,
}

impl CapabilityDescription {
    fn layer_one() -> Self {
        Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            can_read_connector_status: true,
            can_read_consumer_group_lag: true,
            can_read_metric_window: true,
            can_access_kafka_records: false,
            can_produce: false,
            can_consume: false,
            can_mutate_topics: false,
            can_mutate_acls: false,
            can_mutate_connectors: false,
            can_query_arbitrary_metrics: false,
            can_register_generic_events: false,
            can_adopt_outcome: false,
        }
    }
}
