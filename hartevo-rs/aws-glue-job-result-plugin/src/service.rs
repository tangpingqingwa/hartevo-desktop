//! Bounded AWS Glue job-run proposal, recording, and verification service.

use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_GLUE_JOB_RESULT_API_REVISION, AWS_GLUE_JOB_RESULT_CONSUMER_ID,
    AWS_GLUE_JOB_RESULT_CONTRACT_VERSION, AWS_GLUE_JOB_RESULT_PROVIDER_ID,
    AWS_GLUE_JOB_RESULT_SCHEMA_VERSION, AWS_GLUE_JOB_RESULT_SERVICE_ID, Layer1Authority,
    model::{
        AdoptionAvailability, AttemptNumber, AwsGlueJobResultRequest, AwsGlueRegistration,
        AwsGlueScope, Digest, EvidenceDigests, GlueJobRunState, JobDefinitionMetadata,
        JobRunEvidence, JobRunRead, ModelError, OpaquePageCursor, PartialReason, PermissionFence,
        ProviderErrorEvidence, ProviderErrorKind, ProviderProvenance, ResultBounds,
        ResultProjection, ResultStatus, RetryProjection, SecretReference, TimeoutProjection,
    },
    provider::{
        AwsGlueProvider, AwsGlueProviderDefinition, AwsGlueProviderTransport,
        GetJobDefinitionRequest, GetJobDefinitionResponse, GetJobRunRequest, GetJobRunResponse,
        GetJobRunsRequest, GetJobRunsResponse, ProviderDefinitionError, ProviderFence,
        TransportError, is_access_loss,
    },
};

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RetryPolicyError {
    #[error("retry attempts must be between one and four")]
    InvalidAttempts,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RetryPolicy {
    max_attempts: u8,
}

impl RetryPolicy {
    pub fn new(max_attempts: u8) -> Result<Self, RetryPolicyError> {
        if !(1..=4).contains(&max_attempts) {
            Err(RetryPolicyError::InvalidAttempts)
        } else {
            Ok(Self { max_attempts })
        }
    }

    pub const fn max_attempts(self) -> u8 {
        self.max_attempts
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self { max_attempts: 3 }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsGlueJobResultServiceError {
    #[error("AWS Glue registration is revoked or tampered")]
    RegistrationRevoked,
    #[error("AWS Glue SecretReference is revoked or scope-bound incorrectly")]
    SecretRevoked,
    #[error("AWS Glue request is outside the account/region/catalog/job scope")]
    ScopeMismatch,
    #[error("AWS Glue job-run identity does not match the request")]
    RunMismatch,
    #[error("AWS Glue attempt does not match the requested attempt fence")]
    AttemptMismatch,
    #[error("AWS Glue provider response fence does not match the request")]
    FenceViolation,
    #[error("AWS Glue provider response was tampered with or its digest is stale")]
    TamperedEvidence,
    #[error("AWS Glue provider response is not newest-first")]
    PaginationOrderViolation,
    #[error("AWS Glue cursor is not bound to the request or is unavailable")]
    CursorBindingViolation,
    #[error("AWS Glue provider returned a repeated cursor")]
    PageLoop,
    #[error("AWS Glue provider response shape exceeds the safe Layer-1 shape")]
    InvalidResponseShape,
    #[error("AWS Glue provider definition is invalid")]
    ProviderDefinition(#[from] ProviderDefinitionError),
    #[error("AWS Glue provider transport failed with {kind:?} ({status_code:?})")]
    Provider {
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        diagnostic_digest: Digest,
    },
    #[error("AWS Glue model error: {0}")]
    Model(#[from] ModelError),
    #[error("AWS Glue proposal or receipt is stale or tampered")]
    ProposalTampered,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RetryEvidence {
    pub operation: String,
    pub provider_attempt: u8,
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ServiceCapabilities {
    pub schema_version: &'static str,
    pub contract_version: &'static str,
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub consumer_id: &'static str,
    pub operations: [&'static str; 7],
    pub provider_operations: [&'static str; 3],
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub durable_receipt: bool,
    pub start_job_run: bool,
    pub stop_job_run: bool,
    pub raw_arguments: bool,
    pub raw_logs: bool,
    pub data_rows: bool,
    pub transformation_authority: bool,
    pub data_quality_authority: bool,
    pub outcome_authority: bool,
}

impl ServiceCapabilities {
    pub const fn layer_one() -> Self {
        Self {
            schema_version: AWS_GLUE_JOB_RESULT_SCHEMA_VERSION,
            contract_version: AWS_GLUE_JOB_RESULT_CONTRACT_VERSION,
            service_id: AWS_GLUE_JOB_RESULT_SERVICE_ID,
            provider_id: AWS_GLUE_JOB_RESULT_PROVIDER_ID,
            consumer_id: AWS_GLUE_JOB_RESULT_CONSUMER_ID,
            operations: [
                "describe_capabilities",
                "register",
                "revoke_registration",
                "read_bounded",
                "propose",
                "record",
                "verify",
            ],
            provider_operations: ["GetJobRun", "GetJobRuns", "GetJob"],
            read_only: true,
            proposal_only: true,
            live_execution: false,
            connected: false,
            native: false,
            durable_receipt: false,
            start_job_run: false,
            stop_job_run: false,
            raw_arguments: false,
            raw_logs: false,
            data_rows: false,
            transformation_authority: false,
            data_quality_authority: false,
            outcome_authority: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsGlueJobResultEvidence {
    pub projection: ResultProjection,
    pub status: ResultStatus,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub mission_id: crate::MissionId,
    pub project_id: crate::ProjectId,
    pub work_product_id: crate::WorkProductId,
    pub work_product_revision: crate::Revision,
    pub runs: Vec<JobRunEvidence>,
    pub job_definition: Option<JobDefinitionMetadata>,
    pub pages_observed: u8,
    pub page_cursor_digests: Vec<Digest>,
    pub retries: Vec<RetryEvidence>,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub retry_projection: RetryProjection,
    pub timeout_projection: TimeoutProjection,
    pub truncated: bool,
    pub ordering_unproven: bool,
    pub digests: EvidenceDigests,
    pub provider_provenance: ProviderProvenance,
    pub authority: Layer1Authority,
    pub adoption: AdoptionAvailability,
}

impl AwsGlueJobResultEvidence {
    pub fn evidence_digest(&self) -> &Digest {
        &self.digests.evidence_digest
    }

    pub fn validate_integrity(&self) -> Result<(), AwsGlueJobResultServiceError> {
        if self.status != self.projection.status()
            || self.authority != Layer1Authority
            || self.adoption != AdoptionAvailability::NotAdoptedLayer2
        {
            return Err(AwsGlueJobResultServiceError::TamperedEvidence);
        }
        for run in &self.runs {
            run.validate_digest()
                .map_err(|_| AwsGlueJobResultServiceError::TamperedEvidence)?;
        }
        if let Some(definition) = &self.job_definition {
            definition
                .validate_digest()
                .map_err(|_| AwsGlueJobResultServiceError::TamperedEvidence)?;
        }
        self.retry_projection
            .validate_digest()
            .map_err(|_| AwsGlueJobResultServiceError::TamperedEvidence)?;
        let expected_run_digest = run_set_digest(&self.runs);
        let expected_api_digest = api_revision_digest();
        let expected_job_digest = self.runs.first().map(|run| {
            Digest::from_fields(
                "aws-glue-job-digest/v1",
                &[run.reference.job_name.as_str().to_owned()],
            )
        });
        if self.digests.contract_digest != crate::contract_digest()
            || self.digests.scope_digest != self.scope_digest
            || self.digests.permission_digest != self.permission_digest
            || Digest::parse(self.digests.job_digest.as_str().to_owned()).is_err()
            || expected_job_digest.is_some_and(|digest| self.digests.job_digest != digest)
            || self.digests.run_digest != expected_run_digest
            || self.digests.api_digest != expected_api_digest
            || Digest::parse(self.digests.provider_digest.as_str().to_owned()).is_err()
        {
            return Err(AwsGlueJobResultServiceError::TamperedEvidence);
        }
        let expected = compute_evidence_digest(
            self.projection,
            &self.request_digest,
            &self.scope_digest,
            &self.permission_digest,
            &self.consent_digest,
            &self.mission_id,
            &self.project_id,
            &self.work_product_id,
            self.work_product_revision,
            self.job_definition.as_ref(),
            self.pages_observed,
            &self.page_cursor_digests,
            &self.retries,
            &self.provider_errors,
            &self.retry_projection,
            &self.timeout_projection,
            self.truncated,
            self.ordering_unproven,
            self.provider_provenance,
            &self.digests.contract_digest,
            &self.digests.provider_digest,
            &self.digests.api_digest,
            &self.digests.job_digest,
            &self.digests.run_digest,
        );
        if expected == self.digests.evidence_digest {
            Ok(())
        } else {
            Err(AwsGlueJobResultServiceError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsGlueJobResultProposal {
    pub request: AwsGlueJobResultRequest,
    pub projection: ResultProjection,
    pub evidence: AwsGlueJobResultEvidence,
    pub registration_digest: Digest,
    pub registration_revision: crate::Revision,
    pub provider_definition_digest: Digest,
    pub proposal_digest: Digest,
}

impl AwsGlueJobResultProposal {
    pub fn status(&self) -> ResultStatus {
        self.projection.status()
    }

    pub const fn is_adopted(&self) -> bool {
        false
    }

    pub fn validate_integrity(&self) -> Result<(), AwsGlueJobResultServiceError> {
        self.request
            .validate_digest()
            .map_err(|_| AwsGlueJobResultServiceError::ProposalTampered)?;
        if self.evidence.request_digest != self.request.request_digest
            || self.evidence.projection != self.projection
            || self.evidence.status != self.projection.status()
            || self.evidence.digests.provider_digest != self.provider_definition_digest
        {
            return Err(AwsGlueJobResultServiceError::ProposalTampered);
        }
        self.evidence.validate_integrity()?;
        let expected = proposal_digest(
            &self.registration_digest,
            self.registration_revision,
            &self.provider_definition_digest,
            &self.request.request_digest,
            self.projection,
            &self.evidence,
        );
        if expected == self.proposal_digest {
            Ok(())
        } else {
            Err(AwsGlueJobResultServiceError::ProposalTampered)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsGlueJobResultReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub contract_digest: Digest,
    pub provider_definition_digest: Digest,
    pub api_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub job_digest: Digest,
    pub run_digest: Digest,
    pub status: ResultStatus,
    pub observed_at: Option<crate::Timestamp>,
    pub durable: bool,
    pub connected: bool,
    pub native: bool,
    pub authority: Layer1Authority,
    pub adoption: AdoptionAvailability,
    pub receipt_digest: Digest,
}

pub type RedactedReceipt = AwsGlueJobResultReceipt;

impl AwsGlueJobResultReceipt {
    pub fn validate_digest(&self) -> Result<(), AwsGlueJobResultServiceError> {
        let expected = receipt_digest(self);
        if expected == self.receipt_digest {
            Ok(())
        } else {
            Err(AwsGlueJobResultServiceError::ProposalTampered)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerificationReport {
    pub verified: bool,
    pub receipt_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_revision: crate::Revision,
    pub connected: bool,
    pub native: bool,
}

pub struct AwsGlueJobResultService<T> {
    scope: AwsGlueScope,
    secret_reference: SecretReference,
    provider: AwsGlueProvider<T>,
    registration: AwsGlueRegistration,
    retry_policy: RetryPolicy,
}

impl<T: AwsGlueProviderTransport> fmt::Debug for AwsGlueJobResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsGlueJobResultService")
            .field("scope", &self.scope)
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider.definition())
            .field("registration", &self.registration)
            .field("retry_policy", &self.retry_policy)
            .finish_non_exhaustive()
    }
}

impl<T: AwsGlueProviderTransport> AwsGlueJobResultService<T> {
    pub fn new(
        scope: AwsGlueScope,
        secret_reference: SecretReference,
        provider: AwsGlueProvider<T>,
        retry_policy: RetryPolicy,
    ) -> Result<Self, AwsGlueJobResultServiceError> {
        if secret_reference.is_revoked() || secret_reference.scope_digest() != &scope.scope_digest()
        {
            return Err(AwsGlueJobResultServiceError::SecretRevoked);
        }
        if provider.definition().native
            || provider.definition().connected
            || provider.provenance().is_native()
            || provider.provenance().is_connected()
            || provider.provenance().is_first_party()
        {
            return Err(AwsGlueJobResultServiceError::ProviderDefinition(
                ProviderDefinitionError::NativeProviderForbidden,
            ));
        }
        let registration = AwsGlueRegistration::new(
            &scope,
            &secret_reference,
            provider.definition().provider_id.clone(),
            provider.definition().provider_version.clone(),
            api_revision_digest(),
            provider.provider_digest(),
        )?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            registration,
            retry_policy,
        })
    }

    pub fn capabilities(&self) -> ServiceCapabilities {
        ServiceCapabilities::layer_one()
    }

    pub fn scope(&self) -> &AwsGlueScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &AwsGlueProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsGlueProvider<T> {
        &mut self.provider
    }

    pub fn provider_definition(&self) -> &AwsGlueProviderDefinition {
        self.provider.definition()
    }

    pub fn registration(&self) -> &AwsGlueRegistration {
        &self.registration
    }

    pub fn retry_policy(&self) -> RetryPolicy {
        self.retry_policy
    }

    pub fn is_active(&self) -> bool {
        self.registration.state == crate::RegistrationState::Active
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<crate::RegistrationTransition, AwsGlueJobResultServiceError> {
        self.registration
            .revoke()
            .map_err(|_| AwsGlueJobResultServiceError::RegistrationRevoked)
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<crate::RegistrationTransition, AwsGlueJobResultServiceError> {
        self.registration
            .restore()
            .map_err(|_| AwsGlueJobResultServiceError::RegistrationRevoked)
    }

    pub fn revoke_secret(&mut self) -> Result<(), AwsGlueJobResultServiceError> {
        self.secret_reference
            .revoke()
            .map_err(|_| AwsGlueJobResultServiceError::SecretRevoked)
    }

    pub fn restore_secret(&mut self) -> Result<(), AwsGlueJobResultServiceError> {
        self.secret_reference
            .restore()
            .map_err(|_| AwsGlueJobResultServiceError::SecretRevoked)
    }

    pub fn propose(
        &mut self,
        request: AwsGlueJobResultRequest,
    ) -> Result<AwsGlueJobResultProposal, AwsGlueJobResultServiceError> {
        self.ensure_active()?;
        request
            .validate_digest()
            .map_err(|_| AwsGlueJobResultServiceError::ProposalTampered)?;
        if request.work_product_revision != self.scope.work_product_revision()
            || !self.scope.contains_job(&request.job_name)
        {
            return Err(AwsGlueJobResultServiceError::ScopeMismatch);
        }
        let provider_definition_digest = self.provider.provider_digest();
        let fence = ProviderFence::from_scope(
            &self.scope,
            &self.secret_reference,
            request.job_name.clone(),
        );
        let mut accumulator = EvidenceAccumulator::new(
            &request,
            fence,
            self.provider.provenance(),
            provider_definition_digest.clone(),
            self.retry_policy,
        );
        let projection = match &request.read {
            JobRunRead::GetJobRun {
                run_id,
                expected_attempt,
            } => self.read_job_run(
                &request,
                run_id.clone(),
                *expected_attempt,
                &mut accumulator,
            )?,
            JobRunRead::GetJobRuns { expected_attempt } => {
                self.read_job_runs(&request, *expected_attempt, &mut accumulator)?
            }
        };
        let mut projection = projection;
        if request.include_job_definition && accumulator.job_definition.is_none() {
            let definition_request = GetJobDefinitionRequest::new(
                &self.scope,
                &self.secret_reference,
                request.job_name.clone(),
            );
            match self.get_job_definition_with_retry(&definition_request, &mut accumulator) {
                Ok(response) => {
                    Self::validate_definition_response(&definition_request, &response)?;
                    accumulator.job_definition = Some(response.job_definition);
                }
                Err(_error) => {
                    if matches!(projection, ResultProjection::Succeeded)
                        || matches!(
                            projection,
                            ResultProjection::Starting
                                | ResultProjection::Running
                                | ResultProjection::Stopping
                                | ResultProjection::Stopped
                        )
                    {
                        projection =
                            ResultProjection::Partial(PartialReason::DefinitionUnavailable);
                    }
                }
            }
        }
        if accumulator.ordering_unproven && !matches!(projection, ResultProjection::FinalError) {
            projection = ResultProjection::Partial(PartialReason::OrderingUnproven);
        } else if let Some(reason) = accumulator.partial_reason
            && !matches!(projection, ResultProjection::FinalError)
        {
            projection = ResultProjection::Partial(reason);
        }
        let evidence = accumulator.finish(projection);
        let proposal_digest = proposal_digest(
            &self.registration.registration_digest,
            self.registration.revision,
            &provider_definition_digest,
            &request.request_digest,
            projection,
            &evidence,
        );
        Ok(AwsGlueJobResultProposal {
            request,
            projection,
            evidence,
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.revision,
            provider_definition_digest,
            proposal_digest,
        })
    }

    pub fn read_bounded(
        &mut self,
        request: AwsGlueJobResultRequest,
    ) -> Result<AwsGlueJobResultProposal, AwsGlueJobResultServiceError> {
        self.propose(request)
    }

    pub fn record(
        &self,
        proposal: &AwsGlueJobResultProposal,
    ) -> Result<AwsGlueJobResultReceipt, AwsGlueJobResultServiceError> {
        self.ensure_active()?;
        self.validate_proposal(proposal)?;
        let receipt = AwsGlueJobResultReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.digests.evidence_digest.clone(),
            contract_digest: crate::contract_digest(),
            provider_definition_digest: proposal.provider_definition_digest.clone(),
            api_digest: self.registration.api_digest.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            scope_digest: proposal.evidence.scope_digest.clone(),
            permission_digest: proposal.evidence.permission_digest.clone(),
            job_digest: proposal.evidence.digests.job_digest.clone(),
            run_digest: proposal.evidence.digests.run_digest.clone(),
            status: proposal.status(),
            observed_at: proposal
                .evidence
                .runs
                .iter()
                .flat_map(|run| [run.started_at, run.completed_at])
                .flatten()
                .max_by_key(|timestamp| timestamp.seconds()),
            durable: false,
            connected: false,
            native: false,
            authority: crate::Layer1Authority,
            adoption: AdoptionAvailability::NotAdoptedLayer2,
            receipt_digest: Digest::from_text("uninitialized-receipt"),
        };
        let mut receipt = receipt;
        receipt.receipt_digest = receipt_digest(&receipt);
        Ok(receipt)
    }

    pub fn verify(
        &self,
        receipt: &AwsGlueJobResultReceipt,
    ) -> Result<VerificationReport, AwsGlueJobResultServiceError> {
        self.ensure_active()?;
        receipt.validate_digest()?;
        if receipt.contract_digest != crate::contract_digest()
            || receipt.registration_digest != self.registration.registration_digest
            || receipt.scope_digest != self.scope.scope_digest()
            || receipt.permission_digest != *self.scope.permission_digest()
            || receipt.provider_definition_digest != self.provider.provider_digest()
            || receipt.api_digest != self.registration.api_digest
            || receipt.connected
            || receipt.native
            || receipt.durable
            || receipt.authority != Layer1Authority
            || receipt.adoption != AdoptionAvailability::NotAdoptedLayer2
        {
            return Err(AwsGlueJobResultServiceError::ProposalTampered);
        }
        Ok(VerificationReport {
            verified: true,
            receipt_digest: receipt.receipt_digest.clone(),
            proposal_digest: receipt.proposal_digest.clone(),
            evidence_digest: receipt.evidence_digest.clone(),
            registration_revision: self.registration.revision,
            connected: false,
            native: false,
        })
    }

    fn ensure_active(&self) -> Result<(), AwsGlueJobResultServiceError> {
        self.registration
            .ensure_active()
            .map_err(|_| AwsGlueJobResultServiceError::RegistrationRevoked)?;
        if self.secret_reference.is_revoked()
            || self.secret_reference.scope_digest() != &self.scope.scope_digest()
        {
            Err(AwsGlueJobResultServiceError::SecretRevoked)
        } else {
            Ok(())
        }
    }

    fn validate_proposal(
        &self,
        proposal: &AwsGlueJobResultProposal,
    ) -> Result<(), AwsGlueJobResultServiceError> {
        proposal
            .request
            .validate_digest()
            .map_err(|_| AwsGlueJobResultServiceError::ProposalTampered)?;
        let expected_job_digest = Digest::from_fields(
            "aws-glue-job-digest/v1",
            &[proposal.request.job_name.as_str().to_owned()],
        );
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.revision
            || proposal.request.work_product_revision != self.scope.work_product_revision()
            || proposal.evidence.scope_digest != self.scope.scope_digest()
            || proposal.evidence.permission_digest != *self.scope.permission_digest()
            || proposal.evidence.consent_digest != *self.scope.consent_digest()
            || proposal.evidence.mission_id != *self.scope.mission_id()
            || proposal.evidence.project_id != *self.scope.project_id()
            || proposal.evidence.work_product_id != *self.scope.work_product_id()
            || proposal.provider_definition_digest != self.provider.provider_digest()
            || proposal.evidence.request_digest != proposal.request.request_digest
            || proposal.evidence.digests.contract_digest != crate::contract_digest()
            || proposal.evidence.digests.provider_digest != self.provider.provider_digest()
            || proposal.evidence.digests.api_digest != self.registration.api_digest
            || proposal.evidence.digests.scope_digest != self.scope.scope_digest()
            || proposal.evidence.digests.permission_digest != *self.scope.permission_digest()
            || proposal.evidence.digests.job_digest != expected_job_digest
            || proposal.evidence.provider_provenance != self.provider.provenance()
            || proposal.evidence.authority != Layer1Authority
            || proposal.evidence.adoption != AdoptionAvailability::NotAdoptedLayer2
        {
            return Err(AwsGlueJobResultServiceError::FenceViolation);
        }
        proposal.validate_integrity()
    }

    fn read_job_run(
        &mut self,
        request: &AwsGlueJobResultRequest,
        run_id: crate::RunId,
        expected_attempt: Option<AttemptNumber>,
        accumulator: &mut EvidenceAccumulator,
    ) -> Result<ResultProjection, AwsGlueJobResultServiceError> {
        let provider_request = GetJobRunRequest::new(
            &self.scope,
            &self.secret_reference,
            request.job_name.clone(),
            run_id,
            expected_attempt,
        );
        let response = match self.get_job_run_with_retry(&provider_request, accumulator) {
            Ok(response) => response,
            Err(error) => return Ok(accumulator.projection_for_error(&error)),
        };
        Self::validate_job_run_response(&provider_request, &response)?;
        accumulator.add_job_run(response.job_run.clone(), response.job_definition.clone());
        Ok(projection_for_job_run(&response.job_run))
    }

    fn read_job_runs(
        &mut self,
        request: &AwsGlueJobResultRequest,
        expected_attempt: Option<AttemptNumber>,
        accumulator: &mut EvidenceAccumulator,
    ) -> Result<ResultProjection, AwsGlueJobResultServiceError> {
        let mut page_number = 1_u8;
        let mut cursor: Option<OpaquePageCursor> = None;
        let mut seen_cursors = BTreeSet::new();
        let mut projection = ResultProjection::ProviderUnknown;
        loop {
            let provider_request = GetJobRunsRequest::new(
                &self.scope,
                &self.secret_reference,
                request.job_name.clone(),
                request.bounds,
                page_number,
                cursor.clone(),
            );
            let response = match self.get_job_runs_with_retry(&provider_request, accumulator) {
                Ok(response) => response,
                Err(error) => return Ok(accumulator.projection_for_error(&error)),
            };
            Self::validate_job_runs_response(&provider_request, &response)?;
            accumulator.add_page(&response, expected_attempt)?;
            if let Some(run) = accumulator.runs.first() {
                projection = projection_for_job_run(run);
            }
            let Some(next_cursor) = response.next_cursor.clone() else {
                break;
            };
            if accumulator.runs.len() >= request.bounds.max_runs() as usize {
                accumulator.truncated = true;
                accumulator.partial_reason = Some(PartialReason::RunCap);
                break;
            }
            if !seen_cursors.insert(next_cursor.token_digest().clone()) {
                return Err(AwsGlueJobResultServiceError::PageLoop);
            }
            if page_number >= request.bounds.max_pages() {
                accumulator.truncated = true;
                accumulator.partial_reason = Some(PartialReason::PageCap);
                projection = ResultProjection::Partial(PartialReason::PageCap);
                break;
            }
            page_number = page_number.saturating_add(1);
            cursor = Some(next_cursor);
        }
        if accumulator.runs.is_empty() {
            Ok(ResultProjection::ProviderUnknown)
        } else {
            Ok(projection)
        }
    }

    fn get_job_run_with_retry(
        &mut self,
        request: &GetJobRunRequest,
        accumulator: &mut EvidenceAccumulator,
    ) -> Result<GetJobRunResponse, TransportError> {
        for attempt in 1..=self.retry_policy.max_attempts() {
            accumulator.provider_attempts = attempt;
            match self.provider.get_job_run(request) {
                Ok(response) => return Ok(response),
                Err(error) if error.retryable && attempt < self.retry_policy.max_attempts() => {
                    accumulator.record_retry("GetJobRun", attempt, &error);
                }
                Err(error) => {
                    accumulator.record_final_error(&error, attempt);
                    return Err(error);
                }
            }
        }
        unreachable!("bounded retry loop always returns")
    }

    fn get_job_runs_with_retry(
        &mut self,
        request: &GetJobRunsRequest,
        accumulator: &mut EvidenceAccumulator,
    ) -> Result<GetJobRunsResponse, TransportError> {
        for attempt in 1..=self.retry_policy.max_attempts() {
            accumulator.provider_attempts = accumulator.provider_attempts.max(attempt);
            match self.provider.get_job_runs(request) {
                Ok(response) => return Ok(response),
                Err(error) if error.retryable && attempt < self.retry_policy.max_attempts() => {
                    accumulator.record_retry("GetJobRuns", attempt, &error);
                }
                Err(error) => {
                    accumulator.record_final_error(&error, attempt);
                    return Err(error);
                }
            }
        }
        unreachable!("bounded retry loop always returns")
    }

    fn get_job_definition_with_retry(
        &mut self,
        request: &GetJobDefinitionRequest,
        accumulator: &mut EvidenceAccumulator,
    ) -> Result<GetJobDefinitionResponse, TransportError> {
        for attempt in 1..=self.retry_policy.max_attempts() {
            accumulator.provider_attempts = accumulator.provider_attempts.max(attempt);
            match self.provider.get_job_definition(request) {
                Ok(response) => return Ok(response),
                Err(error) if error.retryable && attempt < self.retry_policy.max_attempts() => {
                    accumulator.record_retry("GetJob", attempt, &error);
                }
                Err(error) => {
                    accumulator.record_final_error(&error, attempt);
                    return Err(error);
                }
            }
        }
        unreachable!("bounded retry loop always returns")
    }

    fn validate_job_run_response(
        request: &GetJobRunRequest,
        response: &GetJobRunResponse,
    ) -> Result<(), AwsGlueJobResultServiceError> {
        response
            .validate_digest()
            .map_err(|_| AwsGlueJobResultServiceError::TamperedEvidence)?;
        if response.observed_fence != request.fence {
            return Err(AwsGlueJobResultServiceError::FenceViolation);
        }
        validate_run_identity(
            &response.job_run,
            &request.fence,
            Some(&request.run_id),
            request.expected_attempt,
        )?;
        if let Some(definition) = &response.job_definition
            && definition.job_name != request.fence.job_name
        {
            return Err(AwsGlueJobResultServiceError::ScopeMismatch);
        }
        Ok(())
    }

    fn validate_job_runs_response(
        request: &GetJobRunsRequest,
        response: &GetJobRunsResponse,
    ) -> Result<(), AwsGlueJobResultServiceError> {
        response
            .validate_digest()
            .map_err(|_| AwsGlueJobResultServiceError::TamperedEvidence)?;
        if response.observed_fence != request.fence {
            return Err(AwsGlueJobResultServiceError::FenceViolation);
        }
        if !response.newest_first {
            return Err(AwsGlueJobResultServiceError::PaginationOrderViolation);
        }
        if response.observed_cursor_binding_digest != request.cursor_binding_digest {
            return Err(AwsGlueJobResultServiceError::CursorBindingViolation);
        }
        if request
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.binding_digest() != Some(&request.cursor_binding_digest))
        {
            return Err(AwsGlueJobResultServiceError::CursorBindingViolation);
        }
        if response
            .next_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.binding_digest() != Some(&request.cursor_binding_digest))
        {
            return Err(AwsGlueJobResultServiceError::CursorBindingViolation);
        }
        if let Some(definition) = &response.job_definition
            && definition.job_name != request.fence.job_name
        {
            return Err(AwsGlueJobResultServiceError::ScopeMismatch);
        }
        for run in &response.job_runs {
            validate_run_identity(run, &request.fence, None, None)?;
        }
        Ok(())
    }

    fn validate_definition_response(
        request: &GetJobDefinitionRequest,
        response: &GetJobDefinitionResponse,
    ) -> Result<(), AwsGlueJobResultServiceError> {
        response
            .validate_digest()
            .map_err(|_| AwsGlueJobResultServiceError::TamperedEvidence)?;
        if response.observed_fence != request.fence
            || response.job_definition.job_name != request.fence.job_name
        {
            return Err(AwsGlueJobResultServiceError::FenceViolation);
        }
        Ok(())
    }
}

fn validate_run_identity(
    run: &JobRunEvidence,
    fence: &ProviderFence,
    expected_run_id: Option<&crate::RunId>,
    expected_attempt: Option<AttemptNumber>,
) -> Result<(), AwsGlueJobResultServiceError> {
    if run.reference.account_id != fence.account_id
        || run.reference.region != fence.region
        || run.reference.catalog_id != fence.catalog_id
        || run.reference.job_name != fence.job_name
    {
        return Err(AwsGlueJobResultServiceError::ScopeMismatch);
    }
    if expected_run_id.is_some_and(|run_id| run.reference.run_id != *run_id) {
        return Err(AwsGlueJobResultServiceError::RunMismatch);
    }
    if expected_attempt.is_some_and(|attempt| run.reference.attempt != Some(attempt)) {
        return Err(AwsGlueJobResultServiceError::AttemptMismatch);
    }
    Ok(())
}

fn projection_for_job_run(run: &JobRunEvidence) -> ResultProjection {
    if run.is_timeout() {
        return ResultProjection::Timeout;
    }
    match run.state {
        GlueJobRunState::Starting => ResultProjection::Starting,
        GlueJobRunState::Running => ResultProjection::Running,
        GlueJobRunState::Stopping => ResultProjection::Stopping,
        GlueJobRunState::Stopped => ResultProjection::Stopped,
        GlueJobRunState::Succeeded => ResultProjection::Succeeded,
        GlueJobRunState::Failed => ResultProjection::Failed,
        GlueJobRunState::Timeout => ResultProjection::Timeout,
        GlueJobRunState::Unknown => ResultProjection::ProviderUnknown,
    }
}

fn projection_for_provider_error(error: &TransportError) -> ResultProjection {
    if error.kind == ProviderErrorKind::Timeout {
        ResultProjection::Timeout
    } else if is_access_loss(error.kind) {
        ResultProjection::AccessLost
    } else if matches!(
        error.kind,
        ProviderErrorKind::BadRequest
            | ProviderErrorKind::Conflict
            | ProviderErrorKind::Tampered
            | ProviderErrorKind::Truncated
            | ProviderErrorKind::CursorBinding
            | ProviderErrorKind::ScopeMismatch
    ) {
        ResultProjection::FinalError
    } else {
        ResultProjection::ProviderUnknown
    }
}

fn proposal_digest(
    registration_digest: &Digest,
    registration_revision: crate::Revision,
    provider_definition_digest: &Digest,
    request_digest: &Digest,
    projection: ResultProjection,
    evidence: &AwsGlueJobResultEvidence,
) -> Digest {
    Digest::from_fields(
        "aws-glue-job-result-proposal/v1",
        &[
            registration_digest.as_str().to_owned(),
            registration_revision.get().to_string(),
            provider_definition_digest.as_str().to_owned(),
            request_digest.as_str().to_owned(),
            format!("{projection:?}"),
            evidence.digests.evidence_digest.as_str().to_owned(),
        ],
    )
}

fn api_revision_digest() -> Digest {
    Digest::from_fields(
        "aws-glue-api-revision/v1",
        &[AWS_GLUE_JOB_RESULT_API_REVISION.to_owned()],
    )
}

fn run_set_digest(runs: &[JobRunEvidence]) -> Digest {
    Digest::from_fields(
        "aws-glue-run-set-digest/v1",
        &runs
            .iter()
            .map(|run| run.run_digest.as_str().to_owned())
            .collect::<Vec<_>>(),
    )
}

fn receipt_digest(receipt: &AwsGlueJobResultReceipt) -> Digest {
    Digest::from_fields(
        "aws-glue-job-result-receipt/v1",
        &[
            receipt.proposal_digest.as_str().to_owned(),
            receipt.evidence_digest.as_str().to_owned(),
            receipt.contract_digest.as_str().to_owned(),
            receipt.provider_definition_digest.as_str().to_owned(),
            receipt.api_digest.as_str().to_owned(),
            receipt.registration_digest.as_str().to_owned(),
            receipt.scope_digest.as_str().to_owned(),
            receipt.permission_digest.as_str().to_owned(),
            receipt.job_digest.as_str().to_owned(),
            receipt.run_digest.as_str().to_owned(),
            format!("{:?}", receipt.status),
            receipt.observed_at.map_or_else(
                || "none".to_owned(),
                |timestamp| timestamp.seconds().to_string(),
            ),
            receipt.durable.to_string(),
            receipt.connected.to_string(),
            receipt.native.to_string(),
            format!("{:?}", receipt.adoption),
        ],
    )
}

fn compute_evidence_digest(
    projection: ResultProjection,
    request_digest: &Digest,
    scope_digest: &Digest,
    permission_digest: &Digest,
    consent_digest: &Digest,
    mission_id: &crate::MissionId,
    project_id: &crate::ProjectId,
    work_product_id: &crate::WorkProductId,
    work_product_revision: crate::Revision,
    job_definition: Option<&JobDefinitionMetadata>,
    pages_observed: u8,
    page_cursor_digests: &[Digest],
    retries: &[RetryEvidence],
    provider_errors: &[ProviderErrorEvidence],
    retry_projection: &RetryProjection,
    timeout_projection: &TimeoutProjection,
    truncated: bool,
    ordering_unproven: bool,
    provider_provenance: ProviderProvenance,
    contract_digest: &Digest,
    provider_digest: &Digest,
    api_digest: &Digest,
    job_digest: &Digest,
    run_digest: &Digest,
) -> Digest {
    let page_digest = Digest::from_fields(
        "aws-glue-page-cursors/v1",
        &page_cursor_digests
            .iter()
            .map(|digest| digest.as_str().to_owned())
            .collect::<Vec<_>>(),
    );
    let retry_digest = Digest::from_fields(
        "aws-glue-retry-evidence/v1",
        &retries
            .iter()
            .map(|retry| {
                format!(
                    "{}:{}:{:?}:{}:{}",
                    retry.operation,
                    retry.provider_attempt,
                    retry.kind,
                    retry.status_code.map_or(0, u16::from),
                    retry.error_digest.as_str()
                )
            })
            .collect::<Vec<_>>(),
    );
    let provider_error_digest = Digest::from_fields(
        "aws-glue-provider-errors/v1",
        &provider_errors
            .iter()
            .map(|error| {
                format!(
                    "{:?}:{:?}:{}:{}:{}",
                    error.kind,
                    error.status_code,
                    error.retryable,
                    error.provider_attempt,
                    error.error_digest.as_str()
                )
            })
            .collect::<Vec<_>>(),
    );
    Digest::from_fields(
        "aws-glue-job-result-evidence/v1",
        &[
            format!("{projection:?}"),
            request_digest.as_str().to_owned(),
            scope_digest.as_str().to_owned(),
            permission_digest.as_str().to_owned(),
            consent_digest.as_str().to_owned(),
            mission_id.as_str().to_owned(),
            project_id.as_str().to_owned(),
            work_product_id.as_str().to_owned(),
            work_product_revision.get().to_string(),
            contract_digest.as_str().to_owned(),
            provider_digest.as_str().to_owned(),
            api_digest.as_str().to_owned(),
            job_digest.as_str().to_owned(),
            run_digest.as_str().to_owned(),
            job_definition.map_or_else(
                || "none".to_owned(),
                |definition| definition.definition_digest.as_str().to_owned(),
            ),
            pages_observed.to_string(),
            page_digest.as_str().to_owned(),
            retry_digest.as_str().to_owned(),
            provider_error_digest.as_str().to_owned(),
            format!(
                "{}:{}:{}:{}:{}",
                retry_projection.provider_attempts,
                retry_projection.provider_retry_count,
                retry_projection.job_attempts.len(),
                retry_projection.retried,
                retry_projection.retry_digest.as_str()
            ),
            format!("{timeout_projection:?}"),
            truncated.to_string(),
            ordering_unproven.to_string(),
            format!("{provider_provenance:?}"),
        ],
    )
}

struct EvidenceAccumulator {
    request_digest: Digest,
    fence: PermissionFence,
    provider_fence: ProviderFence,
    bounds: ResultBounds,
    provider_provenance: ProviderProvenance,
    provider_definition_digest: Digest,
    runs: Vec<JobRunEvidence>,
    job_definition: Option<JobDefinitionMetadata>,
    pages_observed: u8,
    page_cursor_digests: Vec<Digest>,
    retries: Vec<RetryEvidence>,
    provider_errors: Vec<ProviderErrorEvidence>,
    provider_attempts: u8,
    ordering_unproven: bool,
    truncated: bool,
    partial_reason: Option<PartialReason>,
    last_started_at: Option<crate::Timestamp>,
}

impl EvidenceAccumulator {
    fn new(
        request: &AwsGlueJobResultRequest,
        provider_fence: ProviderFence,
        provider_provenance: ProviderProvenance,
        provider_definition_digest: Digest,
        _retry_policy: RetryPolicy,
    ) -> Self {
        Self {
            request_digest: request.request_digest.clone(),
            fence: PermissionFence {
                account_id: provider_fence.account_id.clone(),
                region: provider_fence.region.clone(),
                catalog_id: provider_fence.catalog_id.clone(),
                scope_digest: provider_fence.scope_digest.clone(),
                permission_digest: provider_fence.permission_digest.clone(),
                consent_digest: provider_fence.consent_digest.clone(),
                mission_id: provider_fence.mission_id.clone(),
                project_id: provider_fence.project_id.clone(),
                work_product_id: provider_fence.work_product_id.clone(),
                work_product_revision: provider_fence.work_product_revision,
            },
            provider_fence,
            bounds: request.bounds,
            provider_provenance,
            provider_definition_digest,
            runs: Vec::new(),
            job_definition: None,
            pages_observed: 0,
            page_cursor_digests: Vec::new(),
            retries: Vec::new(),
            provider_errors: Vec::new(),
            provider_attempts: 0,
            ordering_unproven: false,
            truncated: false,
            partial_reason: None,
            last_started_at: None,
        }
    }

    fn add_job_run(&mut self, run: JobRunEvidence, definition: Option<JobDefinitionMetadata>) {
        self.pages_observed = 1;
        self.last_started_at = run.started_at;
        self.runs.push(run);
        if definition.is_some() {
            self.job_definition = definition;
        }
    }

    fn add_page(
        &mut self,
        response: &GetJobRunsResponse,
        expected_attempt: Option<AttemptNumber>,
    ) -> Result<(), AwsGlueJobResultServiceError> {
        self.pages_observed = self.pages_observed.saturating_add(1);
        if let Some(cursor) = &response.next_cursor {
            self.page_cursor_digests.push(cursor.token_digest().clone());
        }
        if response.job_runs.len() > self.bounds.page_size() as usize {
            self.truncated = true;
            self.partial_reason = Some(PartialReason::Truncated);
        }
        for run in response
            .job_runs
            .iter()
            .take(self.bounds.page_size() as usize)
        {
            if expected_attempt.is_some_and(|attempt| run.reference.attempt != Some(attempt)) {
                return Err(AwsGlueJobResultServiceError::AttemptMismatch);
            }
            if let Some(started_at) = run.started_at {
                if self
                    .last_started_at
                    .is_some_and(|previous| started_at.seconds() > previous.seconds())
                {
                    return Err(AwsGlueJobResultServiceError::PaginationOrderViolation);
                }
                self.last_started_at = Some(started_at);
            } else {
                self.ordering_unproven = true;
            }
            if self.runs.len() >= self.bounds.max_runs() as usize {
                self.truncated = true;
                self.partial_reason = Some(PartialReason::RunCap);
                break;
            }
            self.runs.push(run.clone());
        }
        if response.job_definition.is_some() {
            self.job_definition.clone_from(&response.job_definition);
        }
        Ok(())
    }

    fn record_retry(&mut self, operation: &str, provider_attempt: u8, error: &TransportError) {
        self.retries.push(RetryEvidence {
            operation: operation.to_owned(),
            provider_attempt,
            kind: error.kind,
            status_code: error.status_code,
            error_digest: error.diagnostic_digest().clone(),
        });
    }

    fn record_final_error(&mut self, error: &TransportError, provider_attempt: u8) {
        self.provider_errors.push(ProviderErrorEvidence::new(
            error.kind,
            error.status_code,
            error.retryable,
            provider_attempt,
            error.diagnostic_digest(),
        ));
    }

    fn projection_for_error(&self, error: &TransportError) -> ResultProjection {
        let projection = projection_for_provider_error(error);
        if !self.runs.is_empty() && projection == ResultProjection::Timeout {
            ResultProjection::Partial(PartialReason::Timeout)
        } else {
            projection
        }
    }

    fn finish(self, projection: ResultProjection) -> AwsGlueJobResultEvidence {
        let job_digest = Digest::from_fields(
            "aws-glue-job-digest/v1",
            &[self.provider_fence.job_name.as_str().to_owned()],
        );
        let run_digest = run_set_digest(&self.runs);
        let retry_projection = RetryProjection::new(
            self.provider_attempts,
            self.retries.len() as u8,
            self.runs
                .iter()
                .filter_map(|run| run.reference.attempt)
                .collect(),
        );
        let timeout_projection = if self
            .provider_errors
            .iter()
            .any(|error| error.kind == ProviderErrorKind::Timeout)
        {
            TimeoutProjection::ProviderTimeout
        } else if self.runs.iter().any(JobRunEvidence::is_timeout) {
            TimeoutProjection::RunTimeout
        } else if self.runs.iter().any(|run| {
            matches!(
                run.state,
                GlueJobRunState::Starting | GlueJobRunState::Running | GlueJobRunState::Stopping
            )
        }) {
            TimeoutProjection::Bounded {
                timeout_seconds: self.bounds.timeout_seconds(),
            }
        } else {
            TimeoutProjection::NotObserved
        };
        let contract_digest = crate::contract_digest();
        let provider_digest = self.provider_definition_digest.clone();
        let api_digest = api_revision_digest();
        let evidence_digest = compute_evidence_digest(
            projection,
            &self.request_digest,
            &self.fence.scope_digest,
            &self.fence.permission_digest,
            &self.fence.consent_digest,
            &self.fence.mission_id,
            &self.fence.project_id,
            &self.fence.work_product_id,
            self.fence.work_product_revision,
            self.job_definition.as_ref(),
            self.pages_observed,
            &self.page_cursor_digests,
            &self.retries,
            &self.provider_errors,
            &retry_projection,
            &timeout_projection,
            self.truncated,
            self.ordering_unproven,
            self.provider_provenance,
            &contract_digest,
            &provider_digest,
            &api_digest,
            &job_digest,
            &run_digest,
        );
        AwsGlueJobResultEvidence {
            projection,
            status: projection.status(),
            request_digest: self.request_digest,
            scope_digest: self.fence.scope_digest.clone(),
            permission_digest: self.fence.permission_digest.clone(),
            consent_digest: self.fence.consent_digest.clone(),
            mission_id: self.fence.mission_id.clone(),
            project_id: self.fence.project_id.clone(),
            work_product_id: self.fence.work_product_id.clone(),
            work_product_revision: self.fence.work_product_revision,
            runs: self.runs,
            job_definition: self.job_definition,
            pages_observed: self.pages_observed,
            page_cursor_digests: self.page_cursor_digests,
            retries: self.retries,
            provider_errors: self.provider_errors,
            retry_projection,
            timeout_projection,
            truncated: self.truncated,
            ordering_unproven: self.ordering_unproven,
            digests: EvidenceDigests {
                contract_digest,
                provider_digest,
                api_digest,
                scope_digest: self.fence.scope_digest,
                permission_digest: self.fence.permission_digest,
                job_digest,
                run_digest,
                evidence_digest,
            },
            provider_provenance: self.provider_provenance,
            authority: Layer1Authority,
            adoption: AdoptionAvailability::NotAdoptedLayer2,
        }
    }
}
