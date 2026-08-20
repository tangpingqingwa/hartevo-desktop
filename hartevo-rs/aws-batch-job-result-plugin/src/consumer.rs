//! Mission-scoped AWS Batch evidence consumer.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::AwsBatchError;
use crate::model::{
    AccessLossEvidence, AwsBatchScope, BatchEvidence, BatchEvidencePage, Digest, EvidenceStatus,
    JobId, JobSummary, MAX_JOBS, MAX_PAGES, PartialReason, ProviderProvenance,
};
use crate::provider::{
    AwsBatchProvider, AwsBatchRegistration, AwsBatchTransport, AwsBatchTransportError,
    BatchApiOperation, DescribeJobsRequest, ListJobsRequest, OpaquePageToken,
};
use crate::service::AwsBatchObservationReceipt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsBatchReadRequest {
    pub scope_digest: Digest,
    pub describe_job_ids: Vec<JobId>,
    pub list_request: Option<ListJobsRequest>,
    pub request_digest: Digest,
}

impl AwsBatchReadRequest {
    pub fn new(scope: &AwsBatchScope, describe_job_ids: Vec<JobId>) -> Result<Self, AwsBatchError> {
        if describe_job_ids.is_empty() || describe_job_ids.len() > MAX_JOBS {
            return Err(AwsBatchError::ResponseBoundExceeded);
        }
        let mut request = Self {
            scope_digest: scope.digest(),
            describe_job_ids,
            list_request: None,
            request_digest: Digest::from_text("pending-batch-read-request-digest"),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    pub fn describe_jobs(
        scope: &AwsBatchScope,
        describe_job_ids: Vec<JobId>,
    ) -> Result<Self, AwsBatchError> {
        Self::new(scope, describe_job_ids)
    }

    pub fn for_list(
        scope: &AwsBatchScope,
        list_request: ListJobsRequest,
    ) -> Result<Self, AwsBatchError> {
        list_request.validate(scope)?;
        let mut request = Self {
            scope_digest: scope.digest(),
            describe_job_ids: vec![scope.job_id.clone()],
            list_request: Some(list_request),
            request_digest: Digest::from_text("pending-batch-read-request-digest"),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    pub fn with_list_request(
        mut self,
        scope: &AwsBatchScope,
        list_request: ListJobsRequest,
    ) -> Result<Self, AwsBatchError> {
        list_request.validate(scope)?;
        if self.scope_digest != scope.digest() {
            return Err(AwsBatchError::ScopeMismatch);
        }
        self.list_request = Some(list_request);
        self.request_digest = self.compute_digest();
        Ok(self)
    }

    pub fn with_describe_jobs(mut self, ids: Vec<JobId>) -> Result<Self, AwsBatchError> {
        if ids.is_empty() || ids.len() > MAX_JOBS {
            return Err(AwsBatchError::ResponseBoundExceeded);
        }
        self.describe_job_ids = ids;
        self.request_digest = self.compute_digest();
        Ok(self)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-batch-read-request/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.describe_job_ids
                    .iter()
                    .map(|job| job.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
                self.list_request
                    .as_ref()
                    .map_or_else(String::new, |request| {
                        request.request_digest.as_str().to_owned()
                    }),
            ],
        )
    }

    pub fn validate(&self, scope: &AwsBatchScope) -> Result<(), AwsBatchError> {
        if self.scope_digest != scope.digest()
            || self.describe_job_ids.is_empty()
            || self.describe_job_ids.len() > MAX_JOBS
            || self.request_digest != self.compute_digest()
        {
            return Err(AwsBatchError::ScopeMismatch);
        }
        if let Some(list_request) = &self.list_request {
            list_request.validate(scope)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct MissionAwsBatchObservation {
    pub status: EvidenceStatus,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub workload_correctness_authority: bool,
    pub durable_provider_receipt: bool,
    pub independent_output_readback: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
}

impl MissionAwsBatchObservation {
    fn from_evidence(evidence: &BatchEvidence) -> Self {
        Self {
            status: evidence.status.clone(),
            provenance: evidence.provenance,
            connected: false,
            native: false,
            workload_correctness_authority: false,
            durable_provider_receipt: false,
            independent_output_readback: false,
            outcome_authority: false,
            work_product_adoption: false,
        }
    }

    pub fn validate(&self) -> Result<(), AwsBatchError> {
        if self.connected
            || self.native
            || self.workload_correctness_authority
            || self.durable_provider_receipt
            || self.independent_output_readback
            || self.outcome_authority
            || self.work_product_adoption
        {
            return Err(AwsBatchError::ContractDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAwsBatchReadResult {
    pub evidence: BatchEvidence,
    pub observation: MissionAwsBatchObservation,
    pub receipt: AwsBatchObservationReceipt,
}

impl MissionAwsBatchReadResult {
    pub fn validate(&self, scope: &AwsBatchScope) -> Result<(), AwsBatchError> {
        self.evidence
            .validate_for(scope)
            .map_err(|_| AwsBatchError::TamperedEvidence)?;
        self.observation.validate()?;
        self.receipt.validate()?;
        if self.receipt.evidence_digest != self.evidence.evidence_digest
            || self.receipt.scope_digest != self.evidence.scope_digest
            || self.receipt.registration_digest != self.evidence.registration_digest
        {
            return Err(AwsBatchError::TamperedEvidence);
        }
        Ok(())
    }
}

pub struct MissionAwsBatchConsumer {
    scope: AwsBatchScope,
    registration: AwsBatchRegistration,
}

impl std::fmt::Debug for MissionAwsBatchConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionAwsBatchConsumer")
            .field("scope", &self.scope)
            .field("registration", &self.registration)
            .finish()
    }
}

impl MissionAwsBatchConsumer {
    pub fn new(
        scope: AwsBatchScope,
        registration: AwsBatchRegistration,
    ) -> Result<Self, AwsBatchError> {
        if registration.scope() != &scope {
            return Err(AwsBatchError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
        })
    }

    pub fn with_registration(
        scope: AwsBatchScope,
        registration: AwsBatchRegistration,
    ) -> Result<Self, AwsBatchError> {
        Self::new(scope, registration)
    }

    pub fn scope(&self) -> &AwsBatchScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsBatchRegistration {
        &self.registration
    }

    #[allow(clippy::too_many_lines)]
    pub fn read<T: AwsBatchTransport>(
        &self,
        provider: &mut AwsBatchProvider<T>,
        request: &AwsBatchReadRequest,
    ) -> Result<MissionAwsBatchReadResult, AwsBatchError> {
        request.validate(&self.scope)?;
        let provider_registration = provider
            .registration()
            .ok_or(AwsBatchError::RegistrationMissing)?;
        if provider_registration.registration_digest() != self.registration.registration_digest()
            || provider_registration.scope() != &self.scope
        {
            return Err(AwsBatchError::ScopeMismatch);
        }
        provider_registration
            .validate_for(provider.provider_revision(), provider.provider_digest())?;
        if !provider_registration.is_active() || !self.registration.is_active() {
            return Err(AwsBatchError::RegistrationRevoked);
        }

        let mut pages = Vec::new();
        let mut list_summaries = Vec::new();
        let mut jobs = Vec::new();
        let mut describe_ids = request.describe_job_ids.clone();
        let mut partial_reason = None;
        let mut access_loss = None;
        let mut seen_tokens = BTreeSet::new();

        if let Some(mut list_request) = request.list_request.clone() {
            loop {
                if pages.len() >= usize::from(MAX_PAGES) {
                    partial_reason.get_or_insert(PartialReason::PageLimitReached);
                    break;
                }
                let page_number = list_request.page_number;
                match provider.list_jobs(&list_request) {
                    Ok(page) => {
                        self.validate_summaries(&page.summaries, &list_request)?;
                        pages.push(BatchEvidencePage {
                            operation: "ListJobs".to_owned(),
                            request_digest: list_request.request_digest.clone(),
                            response_digest: page.response_digest.clone(),
                            page_number,
                            page_token_digest: list_request
                                .page_token
                                .as_ref()
                                .map(OpaquePageToken::digest),
                        });
                        if page.partial {
                            partial_reason.get_or_insert(PartialReason::ProviderMarkedPartial);
                        }
                        if page
                            .summaries
                            .iter()
                            .any(|summary| summary.status.is_unknown())
                        {
                            partial_reason.get_or_insert(PartialReason::UnknownStatus);
                        }
                        for summary in page.summaries {
                            if list_summaries.len() >= MAX_JOBS {
                                partial_reason.get_or_insert(PartialReason::JobLimitReached);
                                break;
                            }
                            describe_ids.push(summary.job_id.clone());
                            list_summaries.push(summary);
                        }
                        if let Some(loss) = page.access_loss {
                            access_loss = Some(loss);
                            partial_reason.get_or_insert(PartialReason::AccessLoss);
                            break;
                        }
                        match page.next_page {
                            Some(token) => {
                                let token_digest = token.digest();
                                if !seen_tokens.insert(token_digest.as_str().to_owned()) {
                                    return Err(AwsBatchError::PageLoop);
                                }
                                if pages.len() >= usize::from(MAX_PAGES) {
                                    partial_reason.get_or_insert(PartialReason::PageLimitReached);
                                    break;
                                }
                                list_request = list_request.next_page(token)?;
                            }
                            None => break,
                        }
                    }
                    Err(AwsBatchError::Transport(error)) if error.is_access_loss() => {
                        access_loss = Some(Self::access_loss(&error, "ListJobs", page_number)?);
                        partial_reason.get_or_insert(PartialReason::AccessLoss);
                        pages.push(Self::synthetic_page(
                            BatchApiOperation::ListJobs,
                            &list_request.binding(),
                            &error,
                        ));
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
        }

        describe_ids = Self::deduplicate_ids(describe_ids);
        let describe_batches = DescribeJobsRequest::batch(&self.scope, describe_ids)?;
        for describe_request in describe_batches {
            if pages.len() >= usize::from(MAX_PAGES) {
                partial_reason.get_or_insert(PartialReason::PageLimitReached);
                break;
            }
            let page_number = describe_request.page_number;
            match provider.describe_jobs(&describe_request) {
                Ok(page) => {
                    for job in &page.jobs {
                        job.validate_against(&self.scope)
                            .map_err(|_| AwsBatchError::ScopeMismatch)?;
                        if job.status.is_unknown() {
                            partial_reason.get_or_insert(PartialReason::UnknownStatus);
                        }
                    }
                    pages.push(BatchEvidencePage {
                        operation: "DescribeJobs".to_owned(),
                        request_digest: describe_request.request_digest.clone(),
                        response_digest: page.response_digest.clone(),
                        page_number,
                        page_token_digest: None,
                    });
                    if page.partial {
                        partial_reason.get_or_insert(PartialReason::ProviderMarkedPartial);
                    }
                    jobs.extend(page.jobs);
                    if let Some(loss) = page.access_loss {
                        access_loss = Some(loss);
                        partial_reason.get_or_insert(PartialReason::AccessLoss);
                        break;
                    }
                }
                Err(AwsBatchError::Transport(error)) if error.is_access_loss() => {
                    access_loss = Some(Self::access_loss(&error, "DescribeJobs", page_number)?);
                    partial_reason.get_or_insert(PartialReason::AccessLoss);
                    pages.push(Self::synthetic_page(
                        BatchApiOperation::DescribeJobs,
                        &describe_request.binding(),
                        &error,
                    ));
                    break;
                }
                Err(error) => return Err(error),
            }
        }

        if jobs.len() > MAX_JOBS {
            jobs.truncate(MAX_JOBS);
            partial_reason.get_or_insert(PartialReason::JobLimitReached);
        }
        if pages.is_empty() {
            return Err(AwsBatchError::ResponseBoundExceeded);
        }
        let status = if access_loss.is_some() {
            EvidenceStatus::AccessLost
        } else if partial_reason.is_some() {
            EvidenceStatus::Partial
        } else {
            EvidenceStatus::Complete
        };
        let evidence = BatchEvidence::new(
            provider.provider_revision().to_owned(),
            provider.provider_digest().clone(),
            crate::api_digest(),
            self.registration.permission_digest().clone(),
            self.scope.digest(),
            self.scope.job_digest(),
            self.scope.attempt_digest(),
            self.registration.registration_digest().clone(),
            self.registration.secret_reference().credential_revision(),
            request.request_digest.clone(),
            pages,
            list_summaries,
            jobs,
            provider.provenance(),
            status,
            partial_reason,
            access_loss,
        )
        .map_err(AwsBatchError::from)?;
        let observation = MissionAwsBatchObservation::from_evidence(&evidence);
        let receipt = AwsBatchObservationReceipt::from_evidence(&evidence)?;
        Ok(MissionAwsBatchReadResult {
            evidence,
            observation,
            receipt,
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn consume_evidence(
        &self,
        evidence: BatchEvidence,
    ) -> Result<MissionAwsBatchObservation, AwsBatchError> {
        if !self.registration.is_active() {
            return Err(AwsBatchError::RegistrationRevoked);
        }
        evidence
            .validate_for(&self.scope)
            .map_err(|_| AwsBatchError::TamperedEvidence)?;
        if evidence.registration_digest != *self.registration.registration_digest() {
            return Err(AwsBatchError::StaleEvidence);
        }
        Ok(MissionAwsBatchObservation::from_evidence(&evidence))
    }

    fn validate_summaries(
        &self,
        summaries: &[JobSummary],
        request: &ListJobsRequest,
    ) -> Result<(), AwsBatchError> {
        for summary in summaries {
            summary.validate()?;
            if summary.job_queue_id != self.scope.job_queue_id
                || summary.job_definition_id != self.scope.job_definition_id
            {
                return Err(AwsBatchError::ScopeMismatch);
            }
            match &request.target {
                crate::provider::ListJobsTarget::JobQueue(_) => {
                    let allowed = summary.job_id == self.scope.job_id
                        || summary.parent_job_id.as_ref() == self.scope.array_job_id.as_ref()
                        || summary.parent_job_id.as_ref() == self.scope.multi_node_job_id.as_ref();
                    if !allowed {
                        return Err(AwsBatchError::ScopeMismatch);
                    }
                }
                crate::provider::ListJobsTarget::ArrayJob(parent)
                | crate::provider::ListJobsTarget::MultiNodeJob(parent) => {
                    if summary.parent_job_id.as_ref() != Some(parent) {
                        return Err(AwsBatchError::ScopeMismatch);
                    }
                }
            }
        }
        Ok(())
    }

    fn deduplicate_ids(ids: Vec<JobId>) -> Vec<JobId> {
        let mut seen = BTreeSet::new();
        ids.into_iter()
            .filter(|id| seen.insert(id.as_str().to_owned()))
            .take(MAX_JOBS)
            .collect()
    }

    fn access_loss(
        error: &AwsBatchTransportError,
        operation: &str,
        after_page: u16,
    ) -> Result<AccessLossEvidence, AwsBatchError> {
        AccessLossEvidence::new(
            error.access_loss_kind(),
            error.provider_code(),
            operation.to_owned(),
            after_page,
        )
        .map_err(AwsBatchError::from)
    }

    fn synthetic_page(
        operation: BatchApiOperation,
        binding: &crate::provider::PageBinding,
        error: &AwsBatchTransportError,
    ) -> BatchEvidencePage {
        BatchEvidencePage {
            operation: match operation {
                BatchApiOperation::DescribeJobs => "DescribeJobs".to_owned(),
                BatchApiOperation::ListJobs => "ListJobs".to_owned(),
            },
            request_digest: binding.request_digest.clone(),
            response_digest: Digest::from_text(error.provider_code()),
            page_number: binding.page_number,
            page_token_digest: binding.page_token_digest.clone(),
        }
    }
}
