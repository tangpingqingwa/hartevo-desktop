//! Service, registration, proposal, verification, and recording seams.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use crate::consumer::MissionAzureDataFactoryConsumer;
use crate::model::{
    AzureDataFactoryScope, Digest, PipelineMetadata, PipelineRunMetadata, PipelineStatus,
    ProviderResponseReceipt, Revision, SecretReference, TransportProvenance, api_digest,
    canonical_digest, evidence_policy_digest, plugin_version_digest, provider_digest,
};
use crate::provider::{
    AzureDataFactoryProvider, AzureDataFactoryTransport, ProviderReadSet, ProviderTransportError,
};
use crate::{
    API_REVISION, API_VERSION, AzureDataFactoryPipelineResultError, CONSUMER_ID, CONTRACT_DIGEST,
    CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, PROVIDER_VERSION, Result, SERVICE_ID,
    contract_digest, validate_contract,
};

const NO_EVIDENCE_DIGEST: &str = "azure-data-factory/no-evidence/v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

impl RegistrationStatus {
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransitionEvidence {
    pub previous_status: RegistrationStatus,
    pub status: RegistrationStatus,
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub revision: Revision,
    pub transition_digest: Digest,
}

impl RegistrationTransitionEvidence {
    fn new(
        previous_status: RegistrationStatus,
        status: RegistrationStatus,
        previous_registration_digest: Digest,
        registration_digest: Digest,
        revision: Revision,
    ) -> Self {
        let transition_digest = canonical_digest(&(
            "azure-data-factory-registration-transition/v1",
            previous_status,
            status,
            &previous_registration_digest,
            &registration_digest,
            revision,
        ));
        Self {
            previous_status,
            status,
            previous_registration_digest,
            registration_digest,
            revision,
            transition_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.previous_registration_digest.validate()?;
        self.registration_digest.validate()?;
        self.transition_digest.validate()?;
        let expected = canonical_digest(&(
            "azure-data-factory-registration-transition/v1",
            self.previous_status,
            self.status,
            &self.previous_registration_digest,
            &self.registration_digest,
            self.revision,
        ));
        if expected == self.transition_digest {
            Ok(())
        } else {
            Err(AzureDataFactoryPipelineResultError::Tampered)
        }
    }
}

/// Reversible registration of every identity and evidence fence used by the
/// provider. The actual SecretReference is private and skipped by serde.
#[derive(Clone, Debug)]
pub struct AzureDataFactoryRegistration {
    pub id: crate::model::RegistrationId,
    pub plugin_id: String,
    pub plugin_version: String,
    pub version_digest: Digest,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_digest: Digest,
    pub api_version: String,
    pub api_revision: String,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub secret_reference_digest: Digest,
    pub evidence_policy_digest: Digest,
    pub evidence_digest: Digest,
    pub revision: Revision,
    pub status: RegistrationStatus,
    pub registration_digest: Digest,
    secret_reference: SecretReference,
}

impl Serialize for AzureDataFactoryRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AzureDataFactoryRegistration", 23)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("pluginId", &self.plugin_id)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("versionDigest", &self.version_digest)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerVersion", &self.provider_version)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiVersion", &self.api_version)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("projectDigest", &self.project_digest)?;
        state.serialize_field("missionDigest", &self.mission_digest)?;
        state.serialize_field("workProductDigest", &self.work_product_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest)?;
        state.serialize_field("evidencePolicyDigest", &self.evidence_policy_digest)?;
        state.serialize_field("evidenceDigest", &self.evidence_digest)?;
        state.serialize_field("revision", &self.revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

impl AzureDataFactoryRegistration {
    pub fn new(
        scope: &AzureDataFactoryScope,
        secret_reference: SecretReference,
        provider_version: impl Into<String>,
    ) -> Result<Self> {
        validate_contract()?;
        scope.validate()?;
        secret_reference.validate()?;
        if secret_reference.tenant_digest() != scope.tenant_digest() {
            return Err(AzureDataFactoryPipelineResultError::ScopeMismatch);
        }
        let provider_version = provider_version.into();
        if provider_version != PROVIDER_VERSION {
            return Err(AzureDataFactoryPipelineResultError::InvalidRegistration);
        }
        let id = crate::model::RegistrationId::new(format!(
            "adf-{}",
            &scope.scope_digest().as_str()[..16]
        ))?;
        let mut registration = Self {
            id,
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            version_digest: plugin_version_digest(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_version,
            provider_digest: provider_digest(),
            api_version: API_VERSION.to_owned(),
            api_revision: API_REVISION.to_owned(),
            api_digest: api_digest(),
            permission_digest: scope.permissions().digest().clone(),
            scope_digest: scope.scope_digest().clone(),
            project_digest: scope.project_digest().clone(),
            mission_digest: scope.mission_digest().clone(),
            work_product_digest: scope.work_product_digest().clone(),
            secret_reference_digest: secret_reference.digest(),
            evidence_policy_digest: evidence_policy_digest(),
            evidence_digest: Digest::from_text(NO_EVIDENCE_DIGEST),
            revision: Revision::new(1)?,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("pending"),
            secret_reference,
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            "azure-data-factory-registration/v1",
            (
                &self.id,
                &self.plugin_id,
                &self.plugin_version,
                &self.version_digest,
                &self.contract_version,
                &self.contract_digest,
                &self.provider_id,
                &self.provider_version,
            ),
            (
                &self.provider_digest,
                &self.api_version,
                &self.api_revision,
                &self.api_digest,
                &self.permission_digest,
                &self.scope_digest,
                &self.project_digest,
                &self.mission_digest,
            ),
            (
                &self.work_product_digest,
                &self.secret_reference_digest,
                &self.evidence_policy_digest,
                &self.evidence_digest,
            ),
            self.revision,
            self.status,
        ))
    }

    pub fn validate(
        &self,
        scope: &AzureDataFactoryScope,
        secret_reference: &SecretReference,
    ) -> Result<()> {
        scope.validate()?;
        secret_reference.validate()?;
        for digest in [
            &self.version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.project_digest,
            &self.mission_digest,
            &self.work_product_digest,
            &self.secret_reference_digest,
            &self.evidence_policy_digest,
            &self.evidence_digest,
            &self.registration_digest,
        ] {
            digest.validate()?;
        }
        if self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.version_digest != plugin_version_digest()
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.provider_id != PROVIDER_ID
            || self.provider_version != PROVIDER_VERSION
            || self.provider_digest != provider_digest()
            || self.api_version != API_VERSION
            || self.api_revision != API_REVISION
            || self.api_digest != api_digest()
            || self.permission_digest != *scope.permissions().digest()
            || self.scope_digest != *scope.scope_digest()
            || self.project_digest != *scope.project_digest()
            || self.mission_digest != *scope.mission_digest()
            || self.work_product_digest != *scope.work_product_digest()
            || self.secret_reference_digest != secret_reference.digest()
            || self.evidence_policy_digest != evidence_policy_digest()
            || self.evidence_digest != Digest::from_text(NO_EVIDENCE_DIGEST)
            || secret_reference.tenant_digest() != scope.tenant_digest()
            || self.registration_digest != self.compute_digest()
        {
            return Err(AzureDataFactoryPipelineResultError::InvalidRegistration);
        }
        Ok(())
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.status.is_active()
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn evidence_binding_digest(&self, evidence_digest: &Digest) -> Digest {
        canonical_digest(&(
            "azure-data-factory-registration-evidence-binding/v1",
            &self.registration_digest,
            evidence_digest,
        ))
    }

    fn transition(&mut self, status: RegistrationStatus) -> Result<RegistrationTransitionEvidence> {
        let previous_status = self.status;
        if previous_status == status {
            return Err(match status {
                RegistrationStatus::Active => {
                    AzureDataFactoryPipelineResultError::InvalidRegistration
                }
                RegistrationStatus::Revoked => {
                    AzureDataFactoryPipelineResultError::RegistrationRevoked
                }
                RegistrationStatus::Reversed => {
                    AzureDataFactoryPipelineResultError::RegistrationReversed
                }
            });
        }
        let previous_registration_digest = self.registration_digest.clone();
        self.revision = Revision::new(self.revision.get() + 1)?;
        self.status = status;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            status,
            previous_registration_digest,
            self.registration_digest.clone(),
            self.revision,
        ))
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status != RegistrationStatus::Active {
            return Err(AzureDataFactoryPipelineResultError::RegistrationRevoked);
        }
        self.transition(RegistrationStatus::Revoked)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status != RegistrationStatus::Revoked {
            return Err(AzureDataFactoryPipelineResultError::RegistrationNotRevoked);
        }
        self.transition(RegistrationStatus::Active)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationStatus::Reversed {
            return Err(AzureDataFactoryPipelineResultError::RegistrationReversed);
        }
        self.transition(RegistrationStatus::Reversed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureDataFactoryCapabilities {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub triggers_pipelines: bool,
    pub cancels_pipelines: bool,
    pub reruns_pipelines: bool,
    pub mutates_factory: bool,
    pub reads_raw_logs: bool,
    pub reads_raw_artifacts: bool,
    pub reads_raw_activity_input_output: bool,
    pub resolves_secrets: bool,
    pub kernel_authority: bool,
    pub outcome_authority: bool,
}

impl Default for AzureDataFactoryCapabilities {
    fn default() -> Self {
        Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            operations: vec![
                "Pipelines - Get".to_owned(),
                "Pipeline Runs - Get".to_owned(),
                "Activity Runs - Query By Pipeline Run".to_owned(),
            ],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            triggers_pipelines: false,
            cancels_pipelines: false,
            reruns_pipelines: false,
            mutates_factory: false,
            reads_raw_logs: false,
            reads_raw_artifacts: false,
            reads_raw_activity_input_output: false,
            resolves_secrets: false,
            kernel_authority: false,
            outcome_authority: false,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureDataFactoryEvidence {
    pub plugin_id: String,
    pub plugin_version: String,
    pub version_digest: Digest,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub service_id: String,
    pub provider_id: String,
    pub provider_digest: Digest,
    pub api_version: String,
    pub api_revision: String,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_policy_digest: Digest,
    pub evidence_binding_digest: Digest,
    pub pipeline: Option<PipelineMetadata>,
    pub pipeline_run: Option<PipelineRunMetadata>,
    pub activity_runs: Vec<crate::model::ActivityRunMetadata>,
    pub receipts: Vec<ProviderResponseReceipt>,
    pub continuation_digest: Option<Digest>,
    pub complete: bool,
    pub status: PipelineStatus,
    pub provenance: TransportProvenance,
    pub redacted: bool,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub kernel_authority: bool,
    pub outcome_authority: bool,
    pub failure_code: Option<String>,
    pub evidence_digest: Digest,
}

impl AzureDataFactoryEvidence {
    fn digest(&self) -> Digest {
        canonical_digest(&(
            "azure-data-factory-evidence/v1",
            (
                &self.plugin_id,
                &self.plugin_version,
                &self.version_digest,
                &self.contract_version,
                &self.contract_digest,
                &self.service_id,
                &self.provider_id,
                &self.provider_digest,
            ),
            (
                &self.api_version,
                &self.api_revision,
                &self.api_digest,
                &self.permission_digest,
                &self.scope_digest,
                &self.project_digest,
                &self.mission_digest,
                &self.work_product_digest,
            ),
            (
                &self.secret_reference_digest,
                &self.registration_digest,
                &self.evidence_policy_digest,
            ),
            (
                &self.pipeline,
                &self.pipeline_run,
                &self.activity_runs,
                &self.receipts,
                &self.continuation_digest,
                self.complete,
            ),
            (
                self.status,
                self.provenance,
                self.redacted,
                self.read_only,
                self.proposal_only,
                self.connected,
                self.native,
                self.first_party,
            ),
            (
                self.provider_receipt,
                self.kernel_authority,
                self.outcome_authority,
                &self.failure_code,
            ),
        ))
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.evidence_digest != self.digest()
            || self.evidence_binding_digest
                != canonical_digest(&(
                    "azure-data-factory-registration-evidence-binding/v1",
                    &self.registration_digest,
                    &self.evidence_digest,
                ))
            || !self.redacted
            || !self.read_only
            || !self.proposal_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.kernel_authority
            || self.outcome_authority
            || self.activity_runs.len() > crate::MAX_ACTIVITIES
        {
            return Err(AzureDataFactoryPipelineResultError::Tampered);
        }
        if let Some(pipeline) = &self.pipeline {
            pipeline.validate()?;
        }
        if let Some(pipeline_run) = &self.pipeline_run {
            pipeline_run.validate()?;
        }
        for activity in &self.activity_runs {
            activity.validate()?;
        }
        for receipt in &self.receipts {
            receipt.validate()?;
        }
        Ok(())
    }

    #[must_use]
    pub fn can_be_adopted(&self) -> bool {
        false
    }

    #[must_use]
    pub fn is_review_only(&self) -> bool {
        true
    }
}

pub type AzureDataFactoryPipelineResultEvidence = AzureDataFactoryEvidence;
pub type AzureDataFactoryPipelineResultServiceError = AzureDataFactoryPipelineResultError;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureDataFactoryPipelineResultProposal {
    pub evidence: AzureDataFactoryEvidence,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub evidence_binding_digest: Digest,
    pub proposal_only: bool,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_authority: bool,
    pub proposal_digest: Digest,
}

impl AzureDataFactoryPipelineResultProposal {
    fn digest(&self) -> Digest {
        canonical_digest(&(
            "azure-data-factory-proposal/v1",
            &self.evidence,
            &self.scope_digest,
            &self.registration_digest,
            &self.evidence_digest,
            &self.evidence_binding_digest,
            self.proposal_only,
            self.read_only,
            self.connected,
            self.native,
            self.first_party,
            self.provider_receipt,
            self.outcome_authority,
        ))
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.proposal_digest != self.digest()
            || self.evidence_digest != self.evidence.evidence_digest
            || self.scope_digest != self.evidence.scope_digest
            || self.registration_digest != self.evidence.registration_digest
            || self.evidence_binding_digest != self.evidence.evidence_binding_digest
            || !self.proposal_only
            || !self.read_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_authority
        {
            return Err(AzureDataFactoryPipelineResultError::Tampered);
        }
        self.evidence.validate_integrity()
    }

    #[must_use]
    pub fn can_be_adopted(&self) -> bool {
        false
    }

    #[must_use]
    pub fn is_review_only(&self) -> bool {
        true
    }
}

pub type PipelineResultProposal = AzureDataFactoryPipelineResultProposal;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureDataFactoryPipelineResultRecord {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub record_digest: Digest,
    pub status: PipelineStatus,
    pub recorded: bool,
    pub replayed: bool,
    pub durable_native_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub outcome_authority: bool,
}

impl AzureDataFactoryPipelineResultRecord {
    pub(crate) fn new(
        proposal: &AzureDataFactoryPipelineResultProposal,
        idempotency_key: &str,
        replayed: bool,
    ) -> Self {
        let idempotency_key_digest = Digest::from_text(idempotency_key);
        let mut record = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            idempotency_key_digest,
            record_digest: Digest::from_text("pending"),
            status: proposal.evidence.status,
            recorded: true,
            replayed,
            durable_native_receipt: false,
            connected: false,
            native: false,
            outcome_authority: false,
        };
        record.record_digest = canonical_digest(&(
            "azure-data-factory-record/v1",
            &record.proposal_digest,
            &record.evidence_digest,
            &record.scope_digest,
            &record.registration_digest,
            &record.idempotency_key_digest,
            record.status,
            record.recorded,
            record.replayed,
            record.durable_native_receipt,
            record.connected,
            record.native,
            record.outcome_authority,
        ));
        record
    }

    pub(crate) fn replay_of(
        proposal: &AzureDataFactoryPipelineResultProposal,
        idempotency_key: &str,
    ) -> Self {
        Self::new(proposal, idempotency_key, true)
    }

    pub(crate) fn new_from_consumer(
        proposal: &AzureDataFactoryPipelineResultProposal,
        idempotency_key: &str,
    ) -> Self {
        Self::new(proposal, idempotency_key, false)
    }

    pub fn validate(&self) -> Result<()> {
        let expected = canonical_digest(&(
            "azure-data-factory-record/v1",
            &self.proposal_digest,
            &self.evidence_digest,
            &self.scope_digest,
            &self.registration_digest,
            &self.idempotency_key_digest,
            self.status,
            self.recorded,
            self.replayed,
            self.durable_native_receipt,
            self.connected,
            self.native,
            self.outcome_authority,
        ));
        if self.record_digest == expected
            && self.recorded
            && !self.durable_native_receipt
            && !self.connected
            && !self.native
            && !self.outcome_authority
        {
            Ok(())
        } else {
            Err(AzureDataFactoryPipelineResultError::Tampered)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationReport {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub verification_digest: Digest,
    pub valid: bool,
    pub review_eligible: bool,
    pub independent_native_readback: bool,
    pub connected: bool,
    pub native: bool,
    pub outcome_authority: bool,
}

impl VerificationReport {
    fn new(proposal: &AzureDataFactoryPipelineResultProposal, valid: bool) -> Self {
        let verification_digest = canonical_digest(&(
            "azure-data-factory-verification/v1",
            &proposal.proposal_digest,
            &proposal.evidence_digest,
            valid,
            true,
            false,
            false,
            false,
            false,
        ));
        Self {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            verification_digest,
            valid,
            review_eligible: valid
                && proposal.evidence.complete
                && !matches!(
                    proposal.evidence.status,
                    PipelineStatus::Partial
                        | PipelineStatus::AccessLost
                        | PipelineStatus::ProviderUnknown
                        | PipelineStatus::Tampered
                        | PipelineStatus::Revoked
                ),
            independent_native_readback: false,
            connected: false,
            native: false,
            outcome_authority: false,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AzureDataFactoryServiceError {
    #[error("registration is revoked or reversed")]
    RegistrationUnavailable,
    #[error("SecretReference is revoked")]
    SecretRevoked,
    #[error("scope or registration drifted")]
    RegistrationDrift,
    #[error("proposal or evidence integrity failed")]
    EvidenceMismatch,
    #[error("recording replay conflict")]
    ReplayConflict,
    #[error("provider failure: {0}")]
    Provider(String),
}

/// Typed Layer-1 service over a provider seam.
pub struct AzureDataFactoryPipelineResultService<T: AzureDataFactoryTransport> {
    provider: AzureDataFactoryProvider<T>,
    registration: AzureDataFactoryRegistration,
    capabilities: AzureDataFactoryCapabilities,
    records: BTreeMap<Digest, AzureDataFactoryPipelineResultRecord>,
}

impl<T: AzureDataFactoryTransport> fmt::Debug for AzureDataFactoryPipelineResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureDataFactoryPipelineResultService")
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("capabilities", &self.capabilities)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl<T: AzureDataFactoryTransport> AzureDataFactoryPipelineResultService<T> {
    pub fn new(provider: AzureDataFactoryProvider<T>) -> Result<Self> {
        let registration = AzureDataFactoryRegistration::new(
            provider.scope(),
            provider.secret_reference().clone(),
            PROVIDER_VERSION,
        )?;
        registration.validate(provider.scope(), provider.secret_reference())?;
        Ok(Self {
            provider,
            registration,
            capabilities: AzureDataFactoryCapabilities::default(),
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn provider(&self) -> &AzureDataFactoryProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AzureDataFactoryProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn registration(&self) -> &AzureDataFactoryRegistration {
        &self.registration
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> &AzureDataFactoryCapabilities {
        &self.capabilities
    }

    pub fn consumer(&self) -> Result<MissionAzureDataFactoryConsumer> {
        self.ensure_registration()?;
        Ok(MissionAzureDataFactoryConsumer::new(
            self.provider.scope().clone(),
        ))
    }

    fn ensure_registration(&self) -> Result<()> {
        self.registration
            .validate(self.provider.scope(), self.provider.secret_reference())?;
        if !self.registration.is_active() {
            return Err(if self.registration.status == RegistrationStatus::Revoked {
                AzureDataFactoryPipelineResultError::RegistrationRevoked
            } else {
                AzureDataFactoryPipelineResultError::RegistrationReversed
            });
        }
        Ok(())
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn propose(&mut self) -> Result<AzureDataFactoryPipelineResultProposal> {
        let read_set = match self.ensure_registration() {
            Ok(()) => self.provider.read_bounded(),
            Err(error) => {
                return Ok(self.proposal_from_failure(status_for_error(&error), error_code(&error)));
            }
        };
        match read_set {
            Ok(read_set) => Ok(self.proposal_from_read_set(read_set)),
            Err(error) => {
                Ok(self.proposal_from_failure(status_for_error(&error), error_code(&error)))
            }
        }
    }

    pub fn read(&mut self) -> Result<AzureDataFactoryPipelineResultProposal> {
        self.propose()
    }

    fn proposal_from_read_set(
        &self,
        read_set: ProviderReadSet,
    ) -> AzureDataFactoryPipelineResultProposal {
        let status = if read_set.complete {
            read_set.pipeline_run.status
        } else {
            PipelineStatus::Partial
        };
        let evidence = self.evidence_template(
            Some(read_set.pipeline),
            Some(read_set.pipeline_run),
            read_set.activities,
            read_set.receipts,
            read_set.continuation_digest,
            read_set.complete,
            status,
            read_set.provenance,
            None,
        );
        Self::proposal_from_evidence(evidence)
    }

    fn proposal_from_failure(
        &self,
        status: PipelineStatus,
        failure_code: &'static str,
    ) -> AzureDataFactoryPipelineResultProposal {
        let evidence = self.evidence_template(
            None,
            None,
            Vec::new(),
            Vec::new(),
            None,
            false,
            status,
            self.provider.transport_provenance(),
            Some(failure_code.to_owned()),
        );
        Self::proposal_from_evidence(evidence)
    }

    fn evidence_template(
        &self,
        pipeline: Option<PipelineMetadata>,
        pipeline_run: Option<PipelineRunMetadata>,
        activity_runs: Vec<crate::model::ActivityRunMetadata>,
        receipts: Vec<ProviderResponseReceipt>,
        continuation_digest: Option<Digest>,
        complete: bool,
        status: PipelineStatus,
        provenance: TransportProvenance,
        failure_code: Option<String>,
    ) -> AzureDataFactoryEvidence {
        let mut evidence = AzureDataFactoryEvidence {
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            version_digest: plugin_version_digest(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_digest: provider_digest(),
            api_version: API_VERSION.to_owned(),
            api_revision: API_REVISION.to_owned(),
            api_digest: api_digest(),
            permission_digest: self.provider.scope().permissions().digest().clone(),
            scope_digest: self.provider.scope().scope_digest().clone(),
            project_digest: self.provider.scope().project_digest().clone(),
            mission_digest: self.provider.scope().mission_digest().clone(),
            work_product_digest: self.provider.scope().work_product_digest().clone(),
            secret_reference_digest: self.provider.secret_reference().digest(),
            registration_digest: self.registration.registration_digest.clone(),
            evidence_policy_digest: evidence_policy_digest(),
            evidence_binding_digest: Digest::from_text("pending"),
            pipeline,
            pipeline_run,
            activity_runs,
            receipts,
            continuation_digest,
            complete,
            status,
            provenance,
            redacted: true,
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            kernel_authority: false,
            outcome_authority: false,
            failure_code,
            evidence_digest: Digest::from_text("pending"),
        };
        evidence.evidence_digest = evidence.digest();
        evidence.evidence_binding_digest = self
            .registration
            .evidence_binding_digest(&evidence.evidence_digest);
        evidence
    }

    fn proposal_from_evidence(
        evidence: AzureDataFactoryEvidence,
    ) -> AzureDataFactoryPipelineResultProposal {
        let mut proposal = AzureDataFactoryPipelineResultProposal {
            scope_digest: evidence.scope_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            evidence_binding_digest: evidence.evidence_binding_digest.clone(),
            proposal_only: true,
            read_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_authority: false,
            proposal_digest: Digest::from_text("pending"),
            evidence,
        };
        proposal.proposal_digest = proposal.digest();
        proposal
    }

    pub fn verify(&self, proposal: &AzureDataFactoryPipelineResultProposal) -> VerificationReport {
        let valid = self.ensure_registration().is_ok()
            && proposal.validate_integrity().is_ok()
            && proposal.scope_digest == *self.provider.scope().scope_digest()
            && proposal.registration_digest == self.registration.registration_digest;
        VerificationReport::new(proposal, valid)
    }

    pub fn record(
        &mut self,
        proposal: &AzureDataFactoryPipelineResultProposal,
        idempotency_key: &str,
    ) -> Result<AzureDataFactoryPipelineResultRecord> {
        if idempotency_key.trim().is_empty() {
            return Err(AzureDataFactoryPipelineResultError::InvalidScope);
        }
        proposal.validate_integrity()?;
        if proposal.scope_digest != *self.provider.scope().scope_digest() {
            return Err(AzureDataFactoryPipelineResultError::ScopeMismatch);
        }
        if proposal.registration_digest != self.registration.registration_digest {
            return Err(AzureDataFactoryPipelineResultError::RegistrationRevoked);
        }
        let key_digest = Digest::from_text(idempotency_key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest == proposal.proposal_digest {
                return Ok(AzureDataFactoryPipelineResultRecord::new(
                    proposal,
                    idempotency_key,
                    true,
                ));
            }
            return Err(AzureDataFactoryPipelineResultError::ReplayConflict);
        }
        let record = AzureDataFactoryPipelineResultRecord::new(proposal, idempotency_key, false);
        record.validate()?;
        self.records.insert(key_digest, record.clone());
        Ok(record)
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }
}

fn status_for_error(error: &AzureDataFactoryPipelineResultError) -> PipelineStatus {
    match error {
        AzureDataFactoryPipelineResultError::RegistrationRevoked
        | AzureDataFactoryPipelineResultError::RegistrationReversed
        | AzureDataFactoryPipelineResultError::SecretRevoked => PipelineStatus::Revoked,
        AzureDataFactoryPipelineResultError::AccessLost
        | AzureDataFactoryPipelineResultError::Transport(
            ProviderTransportError::AccessLost
            | ProviderTransportError::HttpStatus {
                status_code: 401 | 403 | 404,
            },
        ) => PipelineStatus::AccessLost,
        AzureDataFactoryPipelineResultError::Tampered
        | AzureDataFactoryPipelineResultError::RedactionViolation
        | AzureDataFactoryPipelineResultError::ContinuationMismatch
        | AzureDataFactoryPipelineResultError::InvalidProviderResponse
        | AzureDataFactoryPipelineResultError::PaginationLoop => PipelineStatus::Tampered,
        AzureDataFactoryPipelineResultError::PaginationLimit
        | AzureDataFactoryPipelineResultError::ResponseTooLarge => PipelineStatus::Partial,
        _ => PipelineStatus::ProviderUnknown,
    }
}

fn error_code(error: &AzureDataFactoryPipelineResultError) -> &'static str {
    match error {
        AzureDataFactoryPipelineResultError::RegistrationRevoked => "registration_revoked",
        AzureDataFactoryPipelineResultError::RegistrationReversed => "registration_reversed",
        AzureDataFactoryPipelineResultError::SecretRevoked => "secret_revoked",
        AzureDataFactoryPipelineResultError::AccessLost
        | AzureDataFactoryPipelineResultError::Transport(
            ProviderTransportError::AccessLost
            | ProviderTransportError::HttpStatus {
                status_code: 401 | 403 | 404,
            },
        ) => "access_lost",
        AzureDataFactoryPipelineResultError::Transport(ProviderTransportError::BlockedEnv) => {
            "BLOCKED_ENV"
        }
        AzureDataFactoryPipelineResultError::Transport(ProviderTransportError::Timeout) => {
            "timed_out"
        }
        AzureDataFactoryPipelineResultError::Tampered
        | AzureDataFactoryPipelineResultError::RedactionViolation
        | AzureDataFactoryPipelineResultError::ContinuationMismatch
        | AzureDataFactoryPipelineResultError::InvalidProviderResponse
        | AzureDataFactoryPipelineResultError::PaginationLoop => "tampered",
        AzureDataFactoryPipelineResultError::PaginationLimit
        | AzureDataFactoryPipelineResultError::ResponseTooLarge => "partial",
        _ => "provider_unknown",
    }
}
