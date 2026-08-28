//! Typed Buildkite service and reversible registration boundary.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::{
    BuildkitePipelineResultProposal, BuildkitePipelineResultRecordingLog,
    MissionBuildkitePipelineConsumer, RecordedBuildkitePipelineResult,
};
use crate::model::{
    AnnotationsProjection, ArtifactMetadataProjection, BuildkitePipelineResultEvidence,
    BuildkiteScope, BuildsProjection, Digest, JobsProjection, PermissionSnapshot, PluginVersion,
    RegistrationId, SecretReference,
};
use crate::provider::{BuildkiteProvider, BuildkiteProviderError, BuildkiteTransport};
use crate::{
    BuildkitePipelineResultError, CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_VERSION,
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
        validate_text(&release, "providerRelease", 128, false)?;
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
            return Err(BuildkitePipelineResultError::InvalidRegistration);
        }
        validate_text(&self.release, "providerRelease", 128, false)
    }
}

pub type BuildkiteProviderIdentity = ProviderIdentity;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

/// A version/contract/provider/permission/scope/secret-bound registration.
/// The secret handle itself is never serialized.
#[derive(Clone, Eq, PartialEq)]
pub struct BuildkiteRegistration {
    id: RegistrationId,
    plugin_version: PluginVersion,
    contract_version: String,
    contract_digest: Digest,
    provider: ProviderIdentity,
    permission_snapshot: PermissionSnapshot,
    scope: BuildkiteScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    binding_digest: Digest,
}

impl BuildkiteRegistration {
    pub fn new(
        id: RegistrationId,
        scope: BuildkiteScope,
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
            binding_digest: Digest::from_text("unsealed-buildkite-registration"),
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
            return Err(BuildkitePipelineResultError::InvalidRegistration);
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

    pub fn scope(&self) -> &BuildkiteScope {
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

    /// Revocation blocks future reads but preserves the registration and its
    /// transition evidence for audit.
    pub fn revoke(&mut self) -> Result<()> {
        match self.status {
            RegistrationStatus::Active | RegistrationStatus::Revoked => {
                self.status = RegistrationStatus::Revoked;
                Ok(())
            }
            RegistrationStatus::Reversed => Err(BuildkitePipelineResultError::RegistrationReversed),
        }
    }

    /// Reversal is the explicit unmount path and does not delete evidence.
    pub fn reverse(&mut self) -> Result<()> {
        self.status = RegistrationStatus::Reversed;
        Ok(())
    }

    /// Restore is allowed only before reversal.
    pub fn restore(&mut self) -> Result<()> {
        match self.status {
            RegistrationStatus::Revoked | RegistrationStatus::Active => {
                self.status = RegistrationStatus::Active;
                Ok(())
            }
            RegistrationStatus::Reversed => Err(BuildkitePipelineResultError::RegistrationReversed),
        }
    }

    pub fn revocation_evidence(&self) -> RegistrationTransitionEvidence {
        RegistrationTransitionEvidence::for_registration(self)
    }

    fn calculate_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "buildkite-registration-binding/v1",
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

impl fmt::Debug for BuildkiteRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BuildkiteRegistration")
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

impl Serialize for BuildkiteRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("BuildkiteRegistration", 14)?;
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
pub struct RegistrationTransitionEvidence {
    pub registration_id: RegistrationId,
    pub status: RegistrationStatus,
    pub registration_revision: u64,
    pub binding_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub transition_digest: Digest,
}

impl RegistrationTransitionEvidence {
    fn for_registration(registration: &BuildkiteRegistration) -> Self {
        let mut evidence = Self {
            registration_id: registration.id.clone(),
            status: registration.status,
            registration_revision: registration.registration_revision,
            binding_digest: registration.binding_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            secret_reference_digest: registration.secret_reference.reference_digest().clone(),
            transition_digest: Digest::from_text("unsealed-buildkite-transition"),
        };
        evidence.transition_digest = Digest::from_serialized(&(
            &evidence.registration_id,
            evidence.status,
            evidence.registration_revision,
            &evidence.binding_digest,
            &evidence.scope_digest,
            &evidence.secret_reference_digest,
        ));
        evidence
    }

    pub fn validate(&self) -> Result<()> {
        self.registration_id.validate()?;
        self.binding_digest.validate()?;
        self.scope_digest.validate()?;
        self.secret_reference_digest.validate()?;
        if self.registration_revision == 0
            || self.transition_digest
                != Digest::from_serialized(&(
                    &self.registration_id,
                    self.status,
                    self.registration_revision,
                    &self.binding_digest,
                    &self.scope_digest,
                    &self.secret_reference_digest,
                ))
        {
            return Err(BuildkitePipelineResultError::TamperedEvidence);
        }
        Ok(())
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
    fn for_registration(registration: &BuildkiteRegistration) -> Self {
        let transition = registration.revocation_evidence();
        let mut receipt = Self {
            registration_id: registration.id.clone(),
            status: registration.status,
            binding_digest: registration.binding_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            registration_revision: registration.registration_revision,
            transition_digest: transition.transition_digest,
            receipt_digest: Digest::from_text("unsealed-buildkite-registration-receipt"),
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

/// In-process registration registry proving reversible mount/revoke/reverse
/// operations without giving a generic CI registry any authority.
#[derive(Clone, Debug, Default)]
pub struct BuildkiteRegistrationRegistry {
    registrations: BTreeMap<RegistrationId, BuildkiteRegistration>,
}

impl BuildkiteRegistrationRegistry {
    pub fn register(&mut self, registration: BuildkiteRegistration) -> Result<RegistrationReceipt> {
        registration.validate()?;
        if self.registrations.contains_key(registration.id()) {
            return Err(BuildkitePipelineResultError::RegistrationAlreadyExists);
        }
        let receipt = RegistrationReceipt::for_registration(&registration);
        self.registrations
            .insert(registration.id.clone(), registration);
        Ok(receipt)
    }

    pub fn get(&self, id: &RegistrationId) -> Result<&BuildkiteRegistration> {
        self.registrations
            .get(id)
            .ok_or(BuildkitePipelineResultError::RegistrationUnknown)
    }

    pub fn get_mut(&mut self, id: &RegistrationId) -> Result<&mut BuildkiteRegistration> {
        self.registrations
            .get_mut(id)
            .ok_or(BuildkitePipelineResultError::RegistrationUnknown)
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

    pub fn iter(&self) -> impl Iterator<Item = &BuildkiteRegistration> {
        self.registrations.values()
    }
}

/// Typed Buildkite service.  It delegates only bounded reads and proposal /
/// recording operations below kernel authority.
#[derive(Debug)]
pub struct BuildkitePipelineResultService<T> {
    provider: BuildkiteProvider<T>,
}

impl<T: BuildkiteTransport> BuildkitePipelineResultService<T> {
    pub fn new(
        registration: BuildkiteRegistration,
        transport: T,
    ) -> std::result::Result<Self, BuildkiteProviderError> {
        Ok(Self {
            provider: BuildkiteProvider::new(registration, transport)?,
        })
    }

    pub fn provider(&self) -> &BuildkiteProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut BuildkiteProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &BuildkiteRegistration {
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
            can_create_build: false,
            can_rebuild_build: false,
            can_retry_job: false,
            can_cancel_build: false,
            can_mutate_annotation: false,
            can_read_raw_logs: false,
            can_read_raw_artifacts: false,
            can_adopt_outcome: false,
        }
    }

    pub fn read_builds(
        &mut self,
        page_size: usize,
    ) -> std::result::Result<BuildsProjection, BuildkiteProviderError> {
        self.provider.read_builds(page_size)
    }

    pub fn read_jobs(
        &mut self,
        page_size: usize,
    ) -> std::result::Result<JobsProjection, BuildkiteProviderError> {
        self.provider.read_jobs(page_size)
    }

    pub fn read_annotations(
        &mut self,
        page_size: usize,
    ) -> std::result::Result<AnnotationsProjection, BuildkiteProviderError> {
        self.provider.read_annotations(page_size)
    }

    pub fn read_artifact_metadata(
        &mut self,
        page_size: usize,
    ) -> std::result::Result<ArtifactMetadataProjection, BuildkiteProviderError> {
        self.provider.read_artifact_metadata(page_size)
    }

    pub fn read_pipeline_result(
        &mut self,
        page_size: usize,
        idempotency_key: &str,
    ) -> std::result::Result<BuildkitePipelineResultEvidence, BuildkiteProviderError> {
        self.provider
            .read_pipeline_result(page_size, idempotency_key)
    }

    pub fn compile_pipeline_result_proposal(
        &self,
        evidence: &BuildkitePipelineResultEvidence,
        idempotency_key: &str,
    ) -> Result<BuildkitePipelineResultProposal> {
        MissionBuildkitePipelineConsumer::new(self.registration().scope().clone())
            .compile_proposal(evidence, idempotency_key)
    }

    pub fn record_pipeline_result(
        &self,
        log: &mut BuildkitePipelineResultRecordingLog,
        proposal: &BuildkitePipelineResultProposal,
    ) -> Result<RecordedBuildkitePipelineResult> {
        MissionBuildkitePipelineConsumer::new(self.registration().scope().clone())
            .record(log, proposal)
    }

    pub fn revoke_registration(&mut self) -> Result<()> {
        self.provider.registration_mut().revoke()
    }

    pub fn reverse_registration(&mut self) -> Result<()> {
        self.provider.registration_mut().reverse()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub can_create_build: bool,
    pub can_rebuild_build: bool,
    pub can_retry_job: bool,
    pub can_cancel_build: bool,
    pub can_mutate_annotation: bool,
    pub can_read_raw_logs: bool,
    pub can_read_raw_artifacts: bool,
    pub can_adopt_outcome: bool,
}
