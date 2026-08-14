use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    WORKATO_RECIPE_RESULT_CONSUMER_ID, WORKATO_RECIPE_RESULT_CONTRACT_VERSION,
    WORKATO_RECIPE_RESULT_PLUGIN_VERSION, WORKATO_RECIPE_RESULT_PROVIDER_ID,
    WORKATO_RECIPE_RESULT_SCHEMA_VERSION, WORKATO_RECIPE_RESULT_SERVICE_ID,
    model::{
        JobProjection, JobStatus, ModelError, RegistrationState, Revision, SecretReference,
        WorkatoOperation, WorkatoRegistration, WorkatoResultStatus, WorkatoScope,
    },
    provider::{
        JobPageRequest, ProviderError, ProviderErrorEvidence, ProviderProvenance, ProviderRead,
        RecipeVersionPageRequest, RetryAttempt, WorkatoProvider, WorkatoProviderDefinition,
        WorkatoReadReceipt, WorkatoTransport,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkatoServiceError {
    #[error("Workato registration is inactive")]
    RegistrationInactive,
    #[error("Workato registration is revoked or reversed")]
    RegistrationRevoked,
    #[error("Workato SecretReference is revoked")]
    SecretRevoked,
    #[error("Workato scope or permission fence does not match")]
    ScopeMismatch,
    #[error("provider evidence is not bound to the active registration")]
    EvidenceRegistrationMismatch,
    #[error("provider evidence was tampered with or its digest is stale")]
    EvidenceTampered,
    #[error("provider failure cannot be safely projected")]
    FatalProviderFailure,
    #[error("the same retry identity was recorded with different evidence")]
    DuplicateRerun,
    #[error("Layer 1 has no external effect authority")]
    EffectAuthorityUnavailable,
    #[error("Layer 1 has no independent provider read-back authority")]
    ReadBackUnavailable,
    #[error("provider definition is invalid")]
    ProviderDefinition(#[from] crate::ProviderDefinitionError),
    #[error("contract validation failed: {0}")]
    Contract(String),
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkatoServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: crate::Digest,
    pub layer: u8,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub live_execution: bool,
    pub scheduler_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub operations: Vec<WorkatoOperation>,
}

impl WorkatoServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            schema_version: WORKATO_RECIPE_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: WORKATO_RECIPE_RESULT_CONTRACT_VERSION.to_owned(),
            plugin_version: WORKATO_RECIPE_RESULT_PLUGIN_VERSION.to_owned(),
            service_id: WORKATO_RECIPE_RESULT_SERVICE_ID.to_owned(),
            provider_id: WORKATO_RECIPE_RESULT_PROVIDER_ID.to_owned(),
            consumer_id: WORKATO_RECIPE_RESULT_CONSUMER_ID.to_owned(),
            contract_digest: crate::contract_digest(),
            layer: 1,
            read_only: true,
            proposal_only: true,
            recording_only: true,
            live_execution: false,
            scheduler_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            operations: vec![
                WorkatoOperation::GetRecipe,
                WorkatoOperation::ListRecipeVersions,
                WorkatoOperation::GetRecipeVersion,
                WorkatoOperation::ListJobs,
                WorkatoOperation::GetJob,
            ],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkatoResultEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub scope_digest: crate::Digest,
    pub permission_digest: crate::Digest,
    pub consent_digest: crate::Digest,
    pub mission_revision: Revision,
    pub provider_digest: crate::Digest,
    pub capability_digest: crate::Digest,
    pub registration_digest: crate::Digest,
    pub provenance: ProviderProvenance,
    pub recipe: Option<crate::RecipeProjection>,
    pub recipe_version: Option<crate::RecipeVersionProjection>,
    pub job: Option<JobProjection>,
    pub steps: Vec<crate::StepProjection>,
    pub retries: Vec<RetryAttempt>,
    pub receipts: Vec<WorkatoReadReceipt>,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub status: WorkatoResultStatus,
    pub runtime_data_redacted: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_native_receipt: bool,
    pub effect_authority: bool,
    pub independent_read_back: bool,
    pub evidence_digest: crate::Digest,
}

impl WorkatoResultEvidence {
    #[allow(clippy::too_many_arguments)]
    fn new(
        scope: &WorkatoScope,
        registration: &WorkatoRegistration,
        provider_definition: &WorkatoProviderDefinition,
        recipe: Option<crate::RecipeProjection>,
        recipe_version: Option<crate::RecipeVersionProjection>,
        job: Option<JobProjection>,
        steps: Vec<crate::StepProjection>,
        retries: Vec<RetryAttempt>,
        receipts: Vec<WorkatoReadReceipt>,
        provider_errors: Vec<ProviderErrorEvidence>,
        status: WorkatoResultStatus,
    ) -> Self {
        let mut evidence = Self {
            schema_version: WORKATO_RECIPE_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: WORKATO_RECIPE_RESULT_CONTRACT_VERSION.to_owned(),
            scope_digest: scope.scope_digest(),
            permission_digest: scope.permission().permission_digest().clone(),
            consent_digest: scope.mission().consent().digest().clone(),
            mission_revision: scope.mission().mission_revision(),
            provider_digest: provider_definition.provider_digest(),
            capability_digest: provider_definition.capability_digest.clone(),
            registration_digest: registration.registration_digest.clone(),
            provenance: provider_definition.provenance,
            recipe,
            recipe_version,
            job,
            steps,
            retries,
            receipts,
            provider_errors,
            status,
            runtime_data_redacted: true,
            connected: false,
            native: false,
            first_party: false,
            durable_native_receipt: false,
            effect_authority: false,
            independent_read_back: false,
            evidence_digest: crate::Digest::from_text("uninitialized-workato-evidence"),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }

    pub fn compute_digest(&self) -> crate::Digest {
        let mut fields = vec![
            self.schema_version.clone(),
            self.contract_version.clone(),
            self.scope_digest.as_str().to_owned(),
            self.permission_digest.as_str().to_owned(),
            self.consent_digest.as_str().to_owned(),
            self.mission_revision.get().to_string(),
            self.provider_digest.as_str().to_owned(),
            self.capability_digest.as_str().to_owned(),
            self.registration_digest.as_str().to_owned(),
            format!("{:?}", self.provenance),
            format!("{:?}", self.status),
            self.runtime_data_redacted.to_string(),
            self.connected.to_string(),
            self.native.to_string(),
            self.first_party.to_string(),
            self.durable_native_receipt.to_string(),
            self.effect_authority.to_string(),
            self.independent_read_back.to_string(),
        ];
        if let Some(recipe) = &self.recipe {
            fields.push(recipe.projection_digest.as_str().to_owned());
        }
        if let Some(version) = &self.recipe_version {
            fields.push(version.projection_digest.as_str().to_owned());
        }
        if let Some(job) = &self.job {
            fields.push(job.projection_digest.as_str().to_owned());
        }
        fields.extend(
            self.steps
                .iter()
                .map(|step| step.projection_digest.as_str().to_owned()),
        );
        fields.extend(
            self.retries
                .iter()
                .map(|retry| retry.error_digest.as_str().to_owned()),
        );
        fields.extend(
            self.receipts
                .iter()
                .map(|receipt| receipt.response_digest.as_str().to_owned()),
        );
        fields.extend(
            self.provider_errors
                .iter()
                .map(|error| error.diagnostic_digest.as_str().to_owned()),
        );
        crate::Digest::from_fields("workato-result-evidence/v1", &fields)
    }

    pub fn is_non_native(&self) -> bool {
        !self.connected
            && !self.native
            && !self.first_party
            && !self.durable_native_receipt
            && !self.effect_authority
            && !self.independent_read_back
            && self.runtime_data_redacted
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkatoResultProposal {
    pub schema_version: String,
    pub contract_version: String,
    pub scope_digest: crate::Digest,
    pub mission_id: crate::MissionId,
    pub project_id: crate::ProjectId,
    pub work_product_id: crate::WorkProductId,
    pub mission_revision: Revision,
    pub status: WorkatoResultStatus,
    pub evidence_digest: crate::Digest,
    pub registration_digest: crate::Digest,
    pub provider_digest: crate::Digest,
    pub consent_digest: crate::Digest,
    pub evidence: WorkatoResultEvidence,
    pub connected: bool,
    pub native: bool,
    pub adopted_outcome: bool,
    pub proposal_digest: crate::Digest,
}

impl WorkatoResultProposal {
    fn new(scope: &WorkatoScope, evidence: WorkatoResultEvidence) -> Self {
        let mut proposal = Self {
            schema_version: WORKATO_RECIPE_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: WORKATO_RECIPE_RESULT_CONTRACT_VERSION.to_owned(),
            scope_digest: scope.scope_digest(),
            mission_id: scope.mission().mission_id().clone(),
            project_id: scope.mission().project_id().clone(),
            work_product_id: scope.mission().work_product_id().clone(),
            mission_revision: scope.mission().mission_revision(),
            status: evidence.status,
            evidence_digest: evidence.evidence_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            provider_digest: evidence.provider_digest.clone(),
            consent_digest: evidence.consent_digest.clone(),
            evidence,
            connected: false,
            native: false,
            adopted_outcome: false,
            proposal_digest: crate::Digest::from_text("uninitialized-workato-proposal"),
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    pub fn compute_digest(&self) -> crate::Digest {
        crate::Digest::from_fields(
            "workato-result-proposal/v1",
            &[
                self.schema_version.clone(),
                self.contract_version.clone(),
                self.scope_digest.as_str().to_owned(),
                self.mission_id.as_str().to_owned(),
                self.project_id.as_str().to_owned(),
                self.work_product_id.as_str().to_owned(),
                self.mission_revision.get().to_string(),
                format!("{:?}", self.status),
                self.evidence_digest.as_str().to_owned(),
                self.registration_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.consent_digest.as_str().to_owned(),
                self.connected.to_string(),
                self.native.to_string(),
                self.adopted_outcome.to_string(),
            ],
        )
    }

    pub fn is_non_native(&self) -> bool {
        !self.connected && !self.native && !self.adopted_outcome && self.evidence.is_non_native()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkatoRecordingReceipt {
    pub recording_digest: crate::Digest,
    pub evidence_digest: crate::Digest,
    pub registration_digest: crate::Digest,
    pub retry_key_digest: crate::Digest,
    pub replayed: bool,
    pub durable_native: bool,
    pub connected: bool,
    pub native: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkatoVerificationProjection {
    pub evidence_digest: crate::Digest,
    pub bounded_evidence_verified: bool,
    pub independent_read_back: bool,
    pub adoption: AdoptionDisposition,
    pub connected: bool,
    pub native: bool,
    pub adopted_outcome: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionDisposition {
    Layer2Required,
    BlockedByProjection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkatoEffectKind {
    ForceRun,
    RepeatJob,
    ResumeJob,
    StartRecipe,
    StopRecipe,
    PollNow,
    ResetTrigger,
    MutateConnection,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkatoEffectProposal {
    pub kind: WorkatoEffectKind,
    pub scope_digest: crate::Digest,
    pub consent_digest: crate::Digest,
    pub available: bool,
    pub native: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkatoReadBackRequest {
    pub scope_digest: crate::Digest,
    pub job_digest: crate::Digest,
    pub source_proposal_digest: crate::Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkatoReadBackProjection {
    pub request: WorkatoReadBackRequest,
    pub available: bool,
    pub native: bool,
    pub reason: String,
}

pub struct WorkatoRecipeResultService<T> {
    provider: WorkatoProvider<T>,
    scope: WorkatoScope,
    secret_reference: SecretReference,
    definition: WorkatoServiceDefinition,
    registration: WorkatoRegistration,
    recordings: BTreeMap<crate::Digest, crate::Digest>,
}

impl<T: WorkatoTransport> fmt::Debug for WorkatoRecipeResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkatoRecipeResultService")
            .field("scope_digest", &self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .field("recording_count", &self.recordings.len())
            .finish()
    }
}

impl<T: WorkatoTransport> WorkatoRecipeResultService<T> {
    pub fn new(
        scope: WorkatoScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, WorkatoServiceError> {
        let provider = WorkatoProvider::new(transport, WORKATO_RECIPE_RESULT_PLUGIN_VERSION)?;
        Self::with_provider(scope, secret_reference, provider)
    }

    pub fn with_provider(
        scope: WorkatoScope,
        secret_reference: SecretReference,
        provider: WorkatoProvider<T>,
    ) -> Result<Self, WorkatoServiceError> {
        let definition = WorkatoServiceDefinition::layer1();
        let registration = WorkatoRegistration::new(
            &scope,
            &secret_reference,
            crate::Digest::from_text(WORKATO_RECIPE_RESULT_PLUGIN_VERSION),
            definition.contract_digest.clone(),
            provider.definition().provider_digest(),
            provider.definition().capability_digest.clone(),
        )?;
        Ok(Self {
            provider,
            scope,
            secret_reference,
            definition,
            registration,
            recordings: BTreeMap::new(),
        })
    }

    pub fn definition(&self) -> &WorkatoServiceDefinition {
        &self.definition
    }

    pub fn scope(&self) -> &WorkatoScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &WorkatoProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut WorkatoProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &WorkatoRegistration {
        &self.registration
    }

    pub fn consent(&self) -> &crate::ConsentScope {
        self.scope.mission().consent()
    }

    pub fn read_result(&mut self) -> Result<WorkatoResultEvidence, WorkatoServiceError> {
        self.ensure_active()?;
        let mut receipts = Vec::new();
        let mut retries = Vec::new();
        let mut errors = Vec::new();

        let recipe = match self
            .provider
            .read_recipe(&self.scope, &self.secret_reference)
        {
            Ok(read) => {
                let value = read.value;
                receipts.extend(read.receipts);
                retries.extend(read.retries);
                Some(value)
            }
            Err(error) => {
                if !error.kind().is_transport()
                    || error.kind() == crate::ProviderErrorKind::MalformedResponse
                {
                    return Err(error.into());
                }
                Self::append_provider_error(&error, &mut receipts, &mut retries, &mut errors);
                return self.failure_evidence(receipts, retries, errors, None, None, None);
            }
        };

        let recipe_version = match self
            .provider
            .read_recipe_version(&self.scope, &self.secret_reference)
        {
            Ok(read) => {
                let value = read.value.clone();
                receipts.extend(read.receipts);
                retries.extend(read.retries);
                Some(value)
            }
            Err(error) => {
                if !error.kind().is_transport()
                    || error.kind() == crate::ProviderErrorKind::MalformedResponse
                {
                    return Err(error.into());
                }
                Self::append_provider_error(&error, &mut receipts, &mut retries, &mut errors);
                return self.failure_evidence(receipts, retries, errors, recipe, None, None);
            }
        };

        let job_read = match self.provider.read_job(&self.scope, &self.secret_reference) {
            Ok(read) => read,
            Err(error) => {
                if !error.kind().is_transport()
                    || error.kind() == crate::ProviderErrorKind::MalformedResponse
                {
                    return Err(error.into());
                }
                Self::append_provider_error(&error, &mut receipts, &mut retries, &mut errors);
                return self.failure_evidence(
                    receipts,
                    retries,
                    errors,
                    recipe,
                    recipe_version,
                    None,
                );
            }
        };
        let job = job_read.value.clone();
        let steps = job.steps.clone();
        receipts.extend(job_read.receipts);
        retries.extend(job_read.retries);
        let status = result_status_for_job(&job);
        Ok(WorkatoResultEvidence::new(
            &self.scope,
            &self.registration,
            self.provider.definition(),
            recipe,
            recipe_version,
            Some(job),
            steps,
            retries,
            receipts,
            errors,
            status,
        ))
    }

    pub fn read_job_result(&mut self) -> Result<WorkatoResultEvidence, WorkatoServiceError> {
        self.read_result()
    }

    pub fn read_recipe_versions(
        &mut self,
        page: RecipeVersionPageRequest,
    ) -> Result<ProviderRead<Vec<crate::RecipeVersionProjection>>, WorkatoServiceError> {
        self.ensure_active()?;
        Ok(self
            .provider
            .read_recipe_versions(&self.scope, &self.secret_reference, page)?)
    }

    pub fn list_jobs(
        &mut self,
        page: JobPageRequest,
    ) -> Result<ProviderRead<crate::JobPageProjection>, WorkatoServiceError> {
        self.ensure_active()?;
        Ok(self
            .provider
            .list_jobs(&self.scope, &self.secret_reference, page)?)
    }

    pub fn compile_result_proposal(
        &self,
        evidence: &WorkatoResultEvidence,
    ) -> Result<WorkatoResultProposal, WorkatoServiceError> {
        self.ensure_active()?;
        self.validate_evidence(evidence)?;
        Ok(WorkatoResultProposal::new(&self.scope, evidence.clone()))
    }

    pub fn compile_proposal(
        &self,
        evidence: &WorkatoResultEvidence,
    ) -> Result<WorkatoResultProposal, WorkatoServiceError> {
        self.compile_result_proposal(evidence)
    }

    pub fn record_redacted_receipt(
        &mut self,
        evidence: &WorkatoResultEvidence,
    ) -> Result<WorkatoRecordingReceipt, WorkatoServiceError> {
        self.ensure_active()?;
        self.validate_evidence(evidence)?;
        let retry_key_digest = self.scope.job().retry_key_digest();
        let replayed = match self.recordings.get(&retry_key_digest) {
            None => {
                self.recordings
                    .insert(retry_key_digest.clone(), evidence.evidence_digest.clone());
                false
            }
            Some(existing) if existing == &evidence.evidence_digest => true,
            Some(_) => return Err(WorkatoServiceError::DuplicateRerun),
        };
        let recording_digest = crate::Digest::from_fields(
            "workato-recording-receipt/v1",
            &[
                evidence.evidence_digest.as_str().to_owned(),
                evidence.registration_digest.as_str().to_owned(),
                retry_key_digest.as_str().to_owned(),
                replayed.to_string(),
            ],
        );
        Ok(WorkatoRecordingReceipt {
            recording_digest,
            evidence_digest: evidence.evidence_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            retry_key_digest,
            replayed,
            durable_native: false,
            connected: false,
            native: false,
        })
    }

    pub fn record_result_receipt(
        &mut self,
        evidence: &WorkatoResultEvidence,
    ) -> Result<WorkatoRecordingReceipt, WorkatoServiceError> {
        self.record_redacted_receipt(evidence)
    }

    pub fn verify_bounded_evidence(
        &self,
        evidence: &WorkatoResultEvidence,
    ) -> Result<WorkatoVerificationProjection, WorkatoServiceError> {
        self.ensure_active()?;
        self.validate_evidence(evidence)?;
        let bounded_evidence_verified = matches!(
            evidence.status,
            WorkatoResultStatus::Completed | WorkatoResultStatus::Failed
        ) && evidence.provider_errors.is_empty()
            && evidence.runtime_data_redacted;
        Ok(WorkatoVerificationProjection {
            evidence_digest: evidence.evidence_digest.clone(),
            bounded_evidence_verified,
            independent_read_back: false,
            adoption: if bounded_evidence_verified {
                AdoptionDisposition::Layer2Required
            } else {
                AdoptionDisposition::BlockedByProjection
            },
            connected: false,
            native: false,
            adopted_outcome: false,
        })
    }

    pub fn propose_effect(
        &self,
        kind: WorkatoEffectKind,
    ) -> Result<WorkatoEffectProposal, WorkatoServiceError> {
        let _proposal = WorkatoEffectProposal {
            kind,
            scope_digest: self.scope.scope_digest(),
            consent_digest: self.scope.mission().consent().digest().clone(),
            available: false,
            native: false,
        };
        Err(WorkatoServiceError::EffectAuthorityUnavailable)
    }

    pub fn read_back(
        &self,
        request: WorkatoReadBackRequest,
    ) -> Result<WorkatoReadBackProjection, WorkatoServiceError> {
        let _projection = WorkatoReadBackProjection {
            request,
            available: false,
            native: false,
            reason: "Layer 2 independent provider read-back required".to_owned(),
        };
        Err(WorkatoServiceError::ReadBackUnavailable)
    }

    pub fn unmount(&mut self) -> Result<crate::RegistrationTransition, WorkatoServiceError> {
        Ok(self.registration.unmount()?)
    }

    pub fn remount(&mut self) -> Result<crate::RegistrationTransition, WorkatoServiceError> {
        if self.secret_reference.is_revoked() {
            return Err(WorkatoServiceError::SecretRevoked);
        }
        Ok(self.registration.remount()?)
    }

    pub fn revoke(&mut self) -> Result<crate::RegistrationTransition, WorkatoServiceError> {
        if self.secret_reference.is_revoked() {
            return Err(WorkatoServiceError::SecretRevoked);
        }
        self.secret_reference.revoke()?;
        Ok(self.registration.revoke()?)
    }

    pub fn reverse(&mut self) -> Result<crate::RegistrationTransition, WorkatoServiceError> {
        Ok(self.registration.reverse()?)
    }

    fn ensure_active(&self) -> Result<(), WorkatoServiceError> {
        if self.secret_reference.is_revoked() {
            return Err(WorkatoServiceError::SecretRevoked);
        }
        if !self.registration.is_active() {
            return if matches!(
                self.registration.state,
                RegistrationState::Revoked | RegistrationState::Reversed
            ) {
                Err(WorkatoServiceError::RegistrationRevoked)
            } else {
                Err(WorkatoServiceError::RegistrationInactive)
            };
        }
        if self.registration.scope_digest != self.scope.scope_digest() {
            return Err(WorkatoServiceError::ScopeMismatch);
        }
        Ok(())
    }

    fn validate_evidence(
        &self,
        evidence: &WorkatoResultEvidence,
    ) -> Result<(), WorkatoServiceError> {
        if evidence.schema_version != WORKATO_RECIPE_RESULT_SCHEMA_VERSION
            || evidence.contract_version != WORKATO_RECIPE_RESULT_CONTRACT_VERSION
            || evidence.scope_digest != self.scope.scope_digest()
            || evidence.permission_digest != *self.scope.permission().permission_digest()
            || evidence.consent_digest != *self.scope.mission().consent().digest()
            || evidence.mission_revision != self.scope.mission().mission_revision()
            || evidence.provider_digest != self.provider.definition().provider_digest()
            || evidence.capability_digest != self.provider.definition().capability_digest
            || evidence.registration_digest != self.registration.registration_digest
            || evidence.provenance != self.provider.provenance()
            || evidence.evidence_digest != evidence.compute_digest()
            || !evidence.is_non_native()
        {
            return Err(WorkatoServiceError::EvidenceTampered);
        }
        if let Some(recipe) = &evidence.recipe
            && recipe.recipe_id != *self.scope.recipe()
        {
            return Err(WorkatoServiceError::ScopeMismatch);
        }
        if let Some(version) = &evidence.recipe_version
            && (version.recipe_id != *self.scope.recipe()
                || version.version_id != *self.scope.recipe_version().version_id()
                || version.version_number != self.scope.recipe_version().version_number())
        {
            return Err(WorkatoServiceError::ScopeMismatch);
        }
        if let Some(job) = &evidence.job
            && (job.identity != *self.scope.job()
                || job.recipe_id != *self.scope.recipe()
                || job.recipe_version != *self.scope.recipe_version()
                || job.steps != evidence.steps
                || job.step_count != evidence.steps.len()
                || job.failed_step_count
                    != evidence
                        .steps
                        .iter()
                        .filter(|step| step.status == crate::StepStatus::Failed)
                        .count()
                || result_status_for_job(job) != evidence.status)
        {
            return Err(WorkatoServiceError::ScopeMismatch);
        }
        if evidence.steps.len() > crate::model::MAX_STEPS
            || evidence.steps.iter().any(|step| {
                !self.scope.step_scope().allows(&step.step_id) || !step.runtime_data_redacted
            })
            || evidence.receipts.iter().any(|receipt| {
                !receipt.redacted_request
                    || !receipt.redacted_result
                    || receipt.connected
                    || receipt.native
                    || receipt.first_party
            })
        {
            return Err(WorkatoServiceError::EvidenceTampered);
        }
        Ok(())
    }

    fn append_provider_error(
        error: &ProviderError,
        receipts: &mut Vec<WorkatoReadReceipt>,
        retries: &mut Vec<RetryAttempt>,
        errors: &mut Vec<ProviderErrorEvidence>,
    ) {
        receipts.extend(error.receipts.clone());
        retries.extend(error.retries.clone());
        errors.push(error.evidence.clone());
    }

    fn failure_evidence(
        &self,
        receipts: Vec<WorkatoReadReceipt>,
        retries: Vec<RetryAttempt>,
        errors: Vec<ProviderErrorEvidence>,
        recipe: Option<crate::RecipeProjection>,
        recipe_version: Option<crate::RecipeVersionProjection>,
        job: Option<JobProjection>,
    ) -> Result<WorkatoResultEvidence, WorkatoServiceError> {
        let status = errors
            .last()
            .map_or(WorkatoResultStatus::ProviderUnknown, |error| {
                project_provider_error(error.kind)
            });
        Ok(WorkatoResultEvidence::new(
            &self.scope,
            &self.registration,
            self.provider.definition(),
            recipe,
            recipe_version,
            job,
            Vec::new(),
            retries,
            receipts,
            errors,
            status,
        ))
    }
}

fn result_status_for_job(job: &JobProjection) -> WorkatoResultStatus {
    if job.retention == crate::RetentionState::RetentionGap {
        return WorkatoResultStatus::RetentionGap;
    }
    match job.status {
        JobStatus::Completed => WorkatoResultStatus::Completed,
        JobStatus::Failed => WorkatoResultStatus::Failed,
        JobStatus::Processing => WorkatoResultStatus::Processing,
        JobStatus::Paused => WorkatoResultStatus::Paused,
        JobStatus::Aborted => WorkatoResultStatus::Aborted,
        JobStatus::Retried => WorkatoResultStatus::Retried,
        JobStatus::Partial => WorkatoResultStatus::Partial,
        JobStatus::ProviderUnknown => WorkatoResultStatus::ProviderUnknown,
    }
}

fn project_provider_error(kind: crate::ProviderErrorKind) -> WorkatoResultStatus {
    match kind {
        crate::ProviderErrorKind::NotFound | crate::ProviderErrorKind::RetentionGap => {
            WorkatoResultStatus::RetentionGap
        }
        crate::ProviderErrorKind::Unauthorized | crate::ProviderErrorKind::Forbidden => {
            WorkatoResultStatus::AccessLost
        }
        _ => WorkatoResultStatus::ProviderUnknown,
    }
}
