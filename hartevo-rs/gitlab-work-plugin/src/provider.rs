//! GitLab provider implementation for bounded reads and proposal inputs.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    ApprovalEntry, ApprovalProjection, ApprovalState, CONTRACT_VERSION, Capability, CommitSha,
    Digest, GitLabHost, GitLabProjectId, GitLabScope, GitLabWorkService, GlobalGitLabId, IssueIid,
    IssueProjection, IssueState, JobId, JobProjection, JobStatus, MAX_APPROVERS, MAX_JOBS,
    MAX_REPLAY_ENTRIES, MAX_STATUS_LENGTH, MAX_TITLE_LENGTH, MergeRequestIid,
    MergeRequestProjection, MergeRequestState, MergeStatus, ModelError, PROVIDER_ID, PipelineId,
    PipelineProjection, PipelineResultProposal, PipelineStatus, ProviderFence, ProviderProvenance,
    ProviderRequestReceipt, ProviderRevision, RateLimitObservation, RefName, Registration,
    RegistrationRequest, SERVICE_VERSION, SecretReference, UntrustedWebhookSignal, WebhookEnvelope,
    WebhookVerificationReceipt, WorkProposal, WorkProposalKind, WorkProposalSubject,
    digest_serializable,
};
use crate::transport::{
    GitLabWorkTransport, RequestOperation, TransportError, TransportRequest, TransportResponse,
    request_fingerprint, response_digest,
};
use crate::webhook::{WebhookSignatureVerifier, WebhookVerifierError};

const DEFAULT_MAX_PAGES: u16 = 16;
const DEFAULT_MAX_ITEMS: usize = 256;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 1_048_576;
const DEFAULT_PER_PAGE: u16 = 50;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PaginationBounds {
    pub max_pages: u16,
    pub max_items: usize,
    pub max_response_bytes: usize,
    pub per_page: u16,
}

impl Default for PaginationBounds {
    fn default() -> Self {
        Self {
            max_pages: DEFAULT_MAX_PAGES,
            max_items: DEFAULT_MAX_ITEMS,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            per_page: DEFAULT_PER_PAGE,
        }
    }
}

impl PaginationBounds {
    pub fn new(
        max_pages: u16,
        max_items: usize,
        max_response_bytes: usize,
        per_page: u16,
    ) -> Result<Self, GitLabWorkError> {
        if max_pages == 0 || max_items == 0 || max_response_bytes == 0 || per_page == 0 {
            return Err(GitLabWorkError::InvalidBounds);
        }
        if max_pages > 128 || max_items > MAX_JOBS || max_response_bytes > 8 * 1_048_576 {
            return Err(GitLabWorkError::InvalidBounds);
        }
        Ok(Self {
            max_pages,
            max_items,
            max_response_bytes,
            per_page,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRead<T> {
    pub value: T,
    pub receipts: Vec<ProviderRequestReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergeRequestRead {
    pub merge_request: MergeRequestProjection,
    pub approval: ApprovalProjection,
    pub receipts: Vec<ProviderRequestReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipelineResultRead {
    pub pipeline: PipelineProjection,
    pub receipts: Vec<ProviderRequestReceipt>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationProbeStatus {
    BlockedEnv,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationProbe {
    pub status: RegistrationProbeStatus,
    pub registration_fence: Digest,
    pub scope_fence: Digest,
    pub host: GitLabHost,
    pub provider_provenance: ProviderProvenance,
    pub native_credentials_resolved: bool,
    pub live_https_verified: bool,
}

#[derive(Debug, Error)]
pub enum GitLabWorkError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("registration is missing")]
    RegistrationMissing,
    #[error("an active registration already exists")]
    RegistrationAlreadyActive,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration contract version does not match the plugin")]
    ContractVersionMismatch,
    #[error("registration contract digest does not match the checked contract")]
    ContractDigestMismatch,
    #[error("registration provider id does not match GitLab Work")]
    ProviderIdMismatch,
    #[error("registration host does not match its scope")]
    RegistrationHostMismatch,
    #[error("requested capability is not registered")]
    CapabilityNotRegistered,
    #[error("requested GitLab scope does not match the active registration")]
    ScopeMismatch,
    #[error("projection registration fence is stale or revoked")]
    StaleProjection,
    #[error("pagination bounds are invalid")]
    InvalidBounds,
    #[error("provider response exceeds the configured byte bound")]
    ResponseTooLarge { actual: usize, maximum: usize },
    #[error("provider response redirected across the registered origin")]
    CrossOriginRedirect {
        expected_origin: String,
        actual_origin: String,
    },
    #[error("provider response has HTTP status {status}")]
    ProviderStatus {
        status: u16,
        receipt: Box<ProviderRequestReceipt>,
    },
    #[error("provider rate limit was returned")]
    RateLimited {
        receipt: Box<ProviderRequestReceipt>,
    },
    #[error("provider response is missing its revision header")]
    MissingProviderRevision,
    #[error("provider revision changed across a bounded read")]
    ProviderRevisionMismatch,
    #[error("provider response body is malformed or outside the typed contract")]
    MalformedResponse,
    #[error("provider response field is missing: {field}")]
    MissingResponseField { field: &'static str },
    #[error("provider project id does not match the registered numeric project")]
    ProjectIdMismatch,
    #[error("provider Issue IID does not match the registered project-scoped IID")]
    IssueIidMismatch,
    #[error("provider Merge Request IID does not match the registered project-scoped IID")]
    MergeRequestIidMismatch,
    #[error("provider global id is invalid")]
    InvalidGlobalId,
    #[error("provider commit SHA does not match the registered SHA fence: {field}")]
    ShaFenceMismatch { field: &'static str },
    #[error("pipeline SHA does not match the registered head SHA")]
    PipelineShaMismatch,
    #[error("pipeline job is outside the registered pipeline scope")]
    JobScopeMismatch,
    #[error("pipeline job expected by the scope was not returned")]
    JobMissing,
    #[error("approval response is internally inconsistent")]
    ApprovalMismatch,
    #[error("provider pagination cursor did not advance")]
    PaginationLoop,
    #[error("provider pagination exceeded the configured page bound")]
    PageLimitExceeded,
    #[error("provider projection exceeded the configured item bound")]
    ItemLimitExceeded,
    #[error("webhook origin is not the registered origin")]
    WebhookOriginMismatch,
    #[error("webhook project id is not the registered project")]
    WebhookProjectMismatch,
    #[error("webhook timestamp is outside the allowed replay window")]
    WebhookTimestampOutsideWindow,
    #[error("webhook delivery has already been observed")]
    WebhookReplay,
    #[error("webhook signature verification failed")]
    WebhookSignatureInvalid,
    #[error("webhook signature verifier is unavailable")]
    WebhookVerifierUnavailable,
    #[error("webhook replay fence is full")]
    WebhookReplayWindowFull,
    #[error("pipeline proposal requires source, target and head SHA fences")]
    PipelineShaFenceUnavailable,
    #[error("proposal serialization failed")]
    ProposalSerialization,
}

#[derive(Clone, Debug)]
struct Authorization {
    host: GitLabHost,
    registration_fence: Digest,
    provider_revision: ProviderRevision,
    credential: SecretReference,
    provenance: ProviderProvenance,
}

#[derive(Clone, Debug)]
struct JsonResponse {
    value: Value,
    receipt: ProviderRequestReceipt,
    provider_revision: ProviderRevision,
    next_page: Option<u16>,
}

#[derive(Debug)]
pub struct GitLabWorkProvider<T> {
    service: GitLabWorkService,
    transport: T,
    registration: Option<Registration>,
    seen_webhook_deliveries: BTreeSet<String>,
}

impl<T: GitLabWorkTransport> GitLabWorkProvider<T> {
    pub fn new(transport: T) -> Self {
        let service = GitLabWorkService::new(transport.provenance());
        Self {
            service,
            transport,
            registration: None,
            seen_webhook_deliveries: BTreeSet::new(),
        }
    }

    pub fn service(&self) -> &GitLabWorkService {
        &self.service
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn registration(&self) -> Option<&Registration> {
        self.registration.as_ref()
    }

    pub fn register(
        &mut self,
        request: RegistrationRequest,
    ) -> Result<Registration, GitLabWorkError> {
        if self.registration.is_some() {
            return Err(GitLabWorkError::RegistrationAlreadyActive);
        }
        if request.contract_version != CONTRACT_VERSION {
            return Err(GitLabWorkError::ContractVersionMismatch);
        }
        if request.contract_digest != crate::contract_digest() {
            return Err(GitLabWorkError::ContractDigestMismatch);
        }
        if request.provider_id != PROVIDER_ID {
            return Err(GitLabWorkError::ProviderIdMismatch);
        }
        if request.host != request.scope.host {
            return Err(GitLabWorkError::RegistrationHostMismatch);
        }
        let registration = Registration::from_request(request);
        self.registration = Some(registration.clone());
        Ok(registration)
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<crate::model::RegistrationChangeReceipt, GitLabWorkError> {
        let registration = self
            .registration
            .as_mut()
            .ok_or(GitLabWorkError::RegistrationMissing)?;
        registration.revoke().map_err(GitLabWorkError::Model)
    }

    pub fn reinstate_registration(
        &mut self,
    ) -> Result<crate::model::RegistrationChangeReceipt, GitLabWorkError> {
        let registration = self
            .registration
            .as_mut()
            .ok_or(GitLabWorkError::RegistrationMissing)?;
        registration.reinstate().map_err(GitLabWorkError::Model)
    }

    pub fn describe_capabilities(&self) -> Vec<crate::model::CapabilityDescription> {
        self.service.describe_capabilities()
    }

    pub fn probe_registration(&self) -> Result<RegistrationProbe, GitLabWorkError> {
        let registration = self.active_registration()?;
        Ok(RegistrationProbe {
            status: RegistrationProbeStatus::BlockedEnv,
            registration_fence: registration.registration_fence(),
            scope_fence: registration.binding().scope.fence(),
            host: registration.binding().host.clone(),
            provider_provenance: self.service.provider_provenance,
            native_credentials_resolved: false,
            live_https_verified: false,
        })
    }

    pub fn read_issue_graph(
        &mut self,
        scope: &GitLabScope,
        bounds: PaginationBounds,
    ) -> Result<ProviderRead<IssueProjection>, GitLabWorkError> {
        let auth = self.authorize(scope, Capability::ReadIssueGraph)?;
        let iid = scope
            .issue_iid
            .ok_or(GitLabWorkError::MissingResponseField { field: "issue_iid" })?;
        let request = TransportRequest::new(
            RequestOperation::Issue,
            format!("/api/v4/projects/{}/issues/{}", scope.project_id, iid),
            BTreeMap::new(),
            1,
            bounds.per_page,
            scope.fence(),
        )?;
        let response = self.execute_json(&auth, &request, &bounds)?;
        let wire = parse_value::<IssueWire>(&response.value)?;
        let projection = Self::issue_projection(&auth, scope, response.provider_revision, wire)?;
        Ok(ProviderRead {
            value: projection,
            receipts: vec![response.receipt],
        })
    }

    pub fn read_merge_request(
        &mut self,
        scope: &GitLabScope,
        bounds: PaginationBounds,
    ) -> Result<MergeRequestRead, GitLabWorkError> {
        let auth = self.authorize(scope, Capability::ReadMergeRequest)?;
        let iid = scope
            .merge_request_iid
            .ok_or(GitLabWorkError::MissingResponseField {
                field: "merge_request_iid",
            })?;
        let merge_request_request = TransportRequest::new(
            RequestOperation::MergeRequest,
            format!(
                "/api/v4/projects/{}/merge_requests/{}",
                scope.project_id, iid
            ),
            BTreeMap::new(),
            1,
            bounds.per_page,
            scope.fence(),
        )?;
        let merge_request_response = self.execute_json(&auth, &merge_request_request, &bounds)?;
        let wire = parse_value::<MergeRequestWire>(&merge_request_response.value)?;
        let merge_request = Self::merge_request_projection(
            &auth,
            scope,
            merge_request_response.provider_revision.clone(),
            wire,
        )?;

        let approvals_request = TransportRequest::new(
            RequestOperation::Approvals,
            format!(
                "/api/v4/projects/{}/merge_requests/{}/approvals",
                scope.project_id, iid
            ),
            BTreeMap::new(),
            1,
            bounds.per_page,
            scope.fence(),
        )?;
        let approvals_response = self.execute_json(&auth, &approvals_request, &bounds)?;
        if approvals_response.provider_revision != merge_request.provider_revision {
            return Err(GitLabWorkError::ProviderRevisionMismatch);
        }
        let approval_wire = parse_value::<ApprovalWire>(&approvals_response.value)?;
        let approval = Self::approval_projection(
            &auth,
            scope,
            approvals_response.provider_revision,
            approval_wire,
        )?;
        Ok(MergeRequestRead {
            merge_request,
            approval,
            receipts: vec![merge_request_response.receipt, approvals_response.receipt],
        })
    }

    #[allow(clippy::too_many_lines)]
    pub fn read_pipeline_result(
        &mut self,
        scope: &GitLabScope,
        bounds: PaginationBounds,
    ) -> Result<PipelineResultRead, GitLabWorkError> {
        let auth = self.authorize(scope, Capability::ReadPipelineResult)?;
        let pipeline_id = scope
            .pipeline_id
            .ok_or(GitLabWorkError::MissingResponseField {
                field: "pipeline_id",
            })?;
        let pipeline_request = TransportRequest::new(
            RequestOperation::Pipeline,
            format!(
                "/api/v4/projects/{}/pipelines/{}",
                scope.project_id, pipeline_id
            ),
            BTreeMap::new(),
            1,
            bounds.per_page,
            scope.fence(),
        )?;
        let pipeline_response = self.execute_json(&auth, &pipeline_request, &bounds)?;
        let pipeline_wire = parse_value::<PipelineWire>(&pipeline_response.value)?;
        let (pipeline_id, pipeline_sha, pipeline_ref, pipeline_status, updated_at) =
            Self::validate_pipeline(scope, pipeline_wire)?;

        let mut receipts = vec![pipeline_response.receipt];
        let mut jobs = Vec::new();
        let mut page = 1_u16;
        let mut pages_used = 0_u16;
        let mut provider_revision = pipeline_response.provider_revision;
        loop {
            if pages_used >= bounds.max_pages {
                return Err(GitLabWorkError::PageLimitExceeded);
            }
            pages_used = pages_used.saturating_add(1);
            let jobs_request = TransportRequest::new(
                RequestOperation::PipelineJobs,
                format!(
                    "/api/v4/projects/{}/pipelines/{}/jobs",
                    scope.project_id, pipeline_id
                ),
                BTreeMap::from([
                    ("page".to_owned(), page.to_string()),
                    ("per_page".to_owned(), bounds.per_page.to_string()),
                ]),
                page,
                bounds.per_page,
                scope.fence(),
            )?;
            let jobs_response = self.execute_json(&auth, &jobs_request, &bounds)?;
            if jobs_response.provider_revision != provider_revision {
                return Err(GitLabWorkError::ProviderRevisionMismatch);
            }
            provider_revision = jobs_response.provider_revision.clone();
            let wire_jobs = parse_value::<Vec<JobWire>>(&jobs_response.value)?;
            if jobs.len().saturating_add(wire_jobs.len()) > bounds.max_items {
                return Err(GitLabWorkError::ItemLimitExceeded);
            }
            for wire_job in wire_jobs {
                jobs.push(Self::job_projection(
                    &provider_revision,
                    pipeline_id,
                    &pipeline_sha,
                    wire_job,
                )?);
            }
            receipts.push(jobs_response.receipt);
            match jobs_response.next_page {
                Some(next_page) if next_page <= page => {
                    return Err(GitLabWorkError::PaginationLoop);
                }
                Some(next_page) => page = next_page,
                None => break,
            }
        }

        if scope
            .job_ids
            .iter()
            .any(|expected| !jobs.iter().any(|job| job.id == *expected))
        {
            return Err(GitLabWorkError::JobMissing);
        }
        let projection = PipelineProjection {
            scope: scope.clone(),
            scope_fence: scope.fence(),
            registration_fence: auth.registration_fence,
            provider_revision,
            provenance: auth.provenance,
            project_id: scope.project_id,
            pipeline_id,
            sha: pipeline_sha,
            ref_name: pipeline_ref,
            status: pipeline_status,
            jobs,
            updated_at,
        };
        Ok(PipelineResultRead {
            pipeline: projection,
            receipts,
        })
    }

    pub fn verify_webhook_envelope<V: WebhookSignatureVerifier>(
        &mut self,
        envelope: &WebhookEnvelope,
        now_unix_seconds: i64,
        max_skew_seconds: i64,
        verifier: &V,
    ) -> Result<UntrustedWebhookSignal, GitLabWorkError> {
        let scope = self
            .registration
            .as_ref()
            .ok_or(GitLabWorkError::RegistrationMissing)?
            .binding()
            .scope
            .clone();
        let auth = self.authorize(&scope, Capability::VerifyWebhookEnvelope)?;
        if envelope.host != auth.host {
            return Err(GitLabWorkError::WebhookOriginMismatch);
        }
        if envelope.project_id != scope.project_id {
            return Err(GitLabWorkError::WebhookProjectMismatch);
        }
        if max_skew_seconds < 0
            || now_unix_seconds
                .saturating_sub(envelope.timestamp)
                .unsigned_abs()
                > max_skew_seconds.cast_unsigned()
        {
            return Err(GitLabWorkError::WebhookTimestampOutsideWindow);
        }
        if self.seen_webhook_deliveries.contains(&envelope.delivery_id) {
            return Err(GitLabWorkError::WebhookReplay);
        }
        if self.seen_webhook_deliveries.len() >= MAX_REPLAY_ENTRIES {
            return Err(GitLabWorkError::WebhookReplayWindowFull);
        }
        let is_verified =
            verifier
                .verify(&auth.credential, envelope)
                .map_err(|error| match error {
                    WebhookVerifierError::Unavailable => {
                        GitLabWorkError::WebhookVerifierUnavailable
                    }
                })?;
        if !is_verified {
            return Err(GitLabWorkError::WebhookSignatureInvalid);
        }
        self.seen_webhook_deliveries
            .insert(envelope.delivery_id.clone());
        let receipt = WebhookVerificationReceipt {
            delivery_id: envelope.delivery_id.clone(),
            project_id: envelope.project_id,
            origin: auth.host.origin().to_owned(),
            payload_digest: envelope.payload_digest.clone(),
            signature_digest: envelope.signature_digest.clone(),
            timestamp: envelope.timestamp,
            verified: true,
            accepted_as_truth: false,
            requires_readback: true,
            provider_provenance: auth.provenance,
        };
        Ok(UntrustedWebhookSignal {
            event_name: envelope.event_name.clone(),
            delivery_id: envelope.delivery_id.clone(),
            scope_fence: scope.fence(),
            provider_revision: auth.provider_revision,
            receipt,
            change_signal_only: true,
            accepted_as_truth: false,
        })
    }

    pub fn current_provider_fence(
        &self,
        scope: &GitLabScope,
        projection_registration_fence: Option<&Digest>,
        provider_revision: ProviderRevision,
    ) -> Result<ProviderFence, GitLabWorkError> {
        let auth = self.authorize(scope, Capability::DescribeCapabilities)?;
        if let Some(projection_registration_fence) = projection_registration_fence
            && projection_registration_fence != &auth.registration_fence
        {
            return Err(GitLabWorkError::StaleProjection);
        }
        Ok(Self::provider_fence(&auth, scope, provider_revision))
    }

    pub fn compile_issue_proposal(
        &self,
        projection: &IssueProjection,
    ) -> Result<WorkProposal, GitLabWorkError> {
        let provider_fence = self.current_provider_fence(
            &projection.scope,
            Some(&projection.registration_fence),
            projection.provider_revision.clone(),
        )?;
        let subject = WorkProposalSubject::Issue(Box::new(projection.clone()));
        let proposal_material = (
            WorkProposalKind::IssueObservation,
            &projection.scope,
            &projection.scope.mission,
            &provider_fence,
            &projection.scope.sha_fence(),
            &subject,
        );
        let proposal_digest = digest_serializable(&proposal_material);
        Ok(WorkProposal {
            kind: WorkProposalKind::IssueObservation,
            scope: projection.scope.clone(),
            mission_scope: projection.scope.mission.clone(),
            provider_fence,
            sha_fence: projection.scope.sha_fence(),
            subject,
            non_mutating: true,
            creates_effect: false,
            adopts_work_product: false,
            native_evidence: false,
            proposal_digest,
        })
    }

    pub fn compile_merge_request_proposal(
        &self,
        read: &MergeRequestRead,
    ) -> Result<WorkProposal, GitLabWorkError> {
        if read.merge_request.scope_fence != read.approval.scope_fence
            || read.merge_request.registration_fence != read.approval.registration_fence
            || read.merge_request.provider_revision != read.approval.provider_revision
        {
            return Err(GitLabWorkError::ProviderRevisionMismatch);
        }
        let provider_fence = self.current_provider_fence(
            &read.merge_request.scope,
            Some(&read.merge_request.registration_fence),
            read.merge_request.provider_revision.clone(),
        )?;
        let subject = WorkProposalSubject::MergeRequest {
            merge_request: Box::new(read.merge_request.clone()),
            approval: Box::new(read.approval.clone()),
        };
        let proposal_material = (
            WorkProposalKind::MergeRequestObservation,
            &read.merge_request.scope,
            &read.merge_request.scope.mission,
            &provider_fence,
            &read.merge_request.scope.sha_fence(),
            &subject,
        );
        let proposal_digest = digest_serializable(&proposal_material);
        Ok(WorkProposal {
            kind: WorkProposalKind::MergeRequestObservation,
            scope: read.merge_request.scope.clone(),
            mission_scope: read.merge_request.scope.mission.clone(),
            provider_fence,
            sha_fence: read.merge_request.scope.sha_fence(),
            subject,
            non_mutating: true,
            creates_effect: false,
            adopts_work_product: false,
            native_evidence: false,
            proposal_digest,
        })
    }

    pub fn compile_pipeline_result_proposal(
        &self,
        read: &PipelineResultRead,
    ) -> Result<PipelineResultProposal, GitLabWorkError> {
        let sha_fence = read.pipeline.scope.sha_fence();
        if sha_fence.source_sha.is_none()
            || sha_fence.target_sha.is_none()
            || sha_fence.head_sha.is_none()
        {
            return Err(GitLabWorkError::PipelineShaFenceUnavailable);
        }
        if read.pipeline.sha != sha_fence.head_sha.clone().expect("checked above") {
            return Err(GitLabWorkError::PipelineShaMismatch);
        }
        let provider_fence = self.current_provider_fence(
            &read.pipeline.scope,
            Some(&read.pipeline.registration_fence),
            read.pipeline.provider_revision.clone(),
        )?;
        let proposal_material = (
            &read.pipeline.scope,
            &read.pipeline.scope.mission,
            &provider_fence,
            &sha_fence,
            &read.pipeline,
        );
        let proposal_digest = digest_serializable(&proposal_material);
        Ok(PipelineResultProposal {
            scope: read.pipeline.scope.clone(),
            mission_scope: read.pipeline.scope.mission.clone(),
            provider_fence,
            sha_fence,
            pipeline: read.pipeline.clone(),
            non_mutating: true,
            creates_effect: false,
            adopts_work_product: false,
            native_evidence: false,
            proposal_digest,
        })
    }

    fn active_registration(&self) -> Result<&Registration, GitLabWorkError> {
        let registration = self
            .registration
            .as_ref()
            .ok_or(GitLabWorkError::RegistrationMissing)?;
        if !registration.is_active() {
            return Err(GitLabWorkError::RegistrationRevoked);
        }
        Ok(registration)
    }

    fn authorize(
        &self,
        scope: &GitLabScope,
        capability: Capability,
    ) -> Result<Authorization, GitLabWorkError> {
        let registration = self.active_registration()?;
        if registration.binding().scope.fence() != scope.fence() {
            return Err(GitLabWorkError::ScopeMismatch);
        }
        if !registration.binding().capabilities.contains(&capability) {
            return Err(GitLabWorkError::CapabilityNotRegistered);
        }
        Ok(Authorization {
            host: registration.binding().host.clone(),
            registration_fence: registration.registration_fence(),
            provider_revision: registration.binding().provider_revision.clone(),
            credential: registration.binding().secret_reference.clone(),
            provenance: self.service.provider_provenance,
        })
    }

    fn provider_fence(
        auth: &Authorization,
        scope: &GitLabScope,
        provider_revision: ProviderRevision,
    ) -> ProviderFence {
        ProviderFence {
            provider_id: PROVIDER_ID.to_owned(),
            service_version: SERVICE_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            registration_fence: auth.registration_fence.clone(),
            host: auth.host.clone(),
            scope_fence: scope.fence(),
            provider_revision,
            provenance: auth.provenance,
        }
    }

    fn execute_json(
        &mut self,
        auth: &Authorization,
        request: &TransportRequest,
        bounds: &PaginationBounds,
    ) -> Result<JsonResponse, GitLabWorkError> {
        let response = self.transport.execute(request.clone(), &auth.credential)?;
        if response.body_len() > bounds.max_response_bytes {
            return Err(GitLabWorkError::ResponseTooLarge {
                actual: response.body_len(),
                maximum: bounds.max_response_bytes,
            });
        }
        let actual_origin = crate::model::url_origin(response.final_url())?;
        if actual_origin != auth.host.origin() {
            return Err(GitLabWorkError::CrossOriginRedirect {
                expected_origin: auth.host.origin().to_owned(),
                actual_origin,
            });
        }
        let receipt = Self::receipt(request, &response, actual_origin);
        if response.status() == 429 {
            return Err(GitLabWorkError::RateLimited {
                receipt: Box::new(receipt),
            });
        }
        if !(200..300).contains(&response.status()) {
            return Err(GitLabWorkError::ProviderStatus {
                status: response.status(),
                receipt: Box::new(receipt),
            });
        }
        let provider_revision = response
            .header("x-gitlab-provider-revision")
            .or_else(|| response.header("etag"))
            .ok_or(GitLabWorkError::MissingProviderRevision)
            .and_then(|value| ProviderRevision::parse(value).map_err(GitLabWorkError::Model))?;
        let value = serde_json::from_slice(response.body())
            .map_err(|_| GitLabWorkError::MalformedResponse)?;
        let next_page = parse_next_page(&response)?;
        Ok(JsonResponse {
            value,
            receipt,
            provider_revision,
            next_page,
        })
    }

    fn receipt(
        request: &TransportRequest,
        response: &TransportResponse,
        final_origin: String,
    ) -> ProviderRequestReceipt {
        ProviderRequestReceipt {
            operation: request.operation.as_str().to_owned(),
            request_fingerprint: request_fingerprint(request),
            path: request.path.clone(),
            query: request
                .query
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            page: request.page,
            response_status: response.status(),
            response_size: response.body_len(),
            response_digest: response_digest(response),
            final_origin,
            rate_limit: rate_limit(response),
            raw_payload_retained: false,
            credential_material_retained: false,
        }
    }

    fn issue_projection(
        auth: &Authorization,
        scope: &GitLabScope,
        provider_revision: ProviderRevision,
        wire: IssueWire,
    ) -> Result<IssueProjection, GitLabWorkError> {
        let project_id = positive_project_id(wire.project_id)?;
        if project_id != scope.project_id {
            return Err(GitLabWorkError::ProjectIdMismatch);
        }
        let iid = positive_issue_iid(wire.iid)?;
        if Some(iid) != scope.issue_iid {
            return Err(GitLabWorkError::IssueIidMismatch);
        }
        let global_id = positive_global_id(wire.id)?;
        let title = bounded_text(wire.title, "issue title", MAX_TITLE_LENGTH)?;
        let web_url = validate_link(&auth.host, wire.web_url)?;
        Ok(IssueProjection {
            scope: scope.clone(),
            scope_fence: scope.fence(),
            registration_fence: auth.registration_fence.clone(),
            provider_revision,
            provenance: auth.provenance,
            project_id,
            iid,
            global_id,
            title,
            state: parse_issue_state(&wire.state),
            updated_at: bounded_optional_text(wire.updated_at, "issue updated_at")?,
            web_url,
        })
    }

    fn merge_request_projection(
        auth: &Authorization,
        scope: &GitLabScope,
        provider_revision: ProviderRevision,
        wire: MergeRequestWire,
    ) -> Result<MergeRequestProjection, GitLabWorkError> {
        let project_id = positive_project_id(wire.project_id)?;
        if project_id != scope.project_id {
            return Err(GitLabWorkError::ProjectIdMismatch);
        }
        let iid = positive_merge_request_iid(wire.iid)?;
        if Some(iid) != scope.merge_request_iid {
            return Err(GitLabWorkError::MergeRequestIidMismatch);
        }
        let global_id = positive_global_id(wire.id)?;
        let source_ref = RefName::parse(wire.source_branch).map_err(GitLabWorkError::Model)?;
        let target_ref = RefName::parse(wire.target_branch).map_err(GitLabWorkError::Model)?;
        if Some(source_ref.clone()) != scope.source_ref
            || Some(target_ref.clone()) != scope.target_ref
        {
            return Err(GitLabWorkError::ShaFenceMismatch {
                field: "source/target ref",
            });
        }
        let diff_refs = wire
            .diff_refs
            .ok_or(GitLabWorkError::MissingResponseField { field: "diff_refs" })?;
        let source_sha = CommitSha::parse(diff_refs.start).map_err(GitLabWorkError::Model)?;
        let target_sha = CommitSha::parse(diff_refs.base).map_err(GitLabWorkError::Model)?;
        let head_sha = CommitSha::parse(diff_refs.head).map_err(GitLabWorkError::Model)?;
        if Some(source_sha.clone()) != scope.source_sha {
            return Err(GitLabWorkError::ShaFenceMismatch {
                field: "source_sha",
            });
        }
        if Some(target_sha.clone()) != scope.target_sha {
            return Err(GitLabWorkError::ShaFenceMismatch {
                field: "target_sha",
            });
        }
        if Some(head_sha.clone()) != scope.head_sha
            || wire.sha.as_deref() != Some(head_sha.as_str())
        {
            return Err(GitLabWorkError::ShaFenceMismatch { field: "head_sha" });
        }
        Ok(MergeRequestProjection {
            scope: scope.clone(),
            scope_fence: scope.fence(),
            registration_fence: auth.registration_fence.clone(),
            provider_revision,
            provenance: auth.provenance,
            project_id,
            iid,
            global_id,
            title: bounded_text(wire.title, "merge request title", MAX_TITLE_LENGTH)?,
            state: parse_merge_request_state(&wire.state),
            draft: wire.draft,
            source_ref,
            target_ref,
            source_sha,
            target_sha,
            head_sha,
            merge_status: parse_merge_status(wire.merge_status.as_deref().unwrap_or("unknown")),
            merge_status_detail: bounded_text(
                wire.detailed_merge_status
                    .or(wire.merge_status)
                    .unwrap_or_else(|| "unknown".to_owned()),
                "merge status detail",
                MAX_STATUS_LENGTH,
            )?,
            updated_at: bounded_optional_text(wire.updated_at, "merge request updated_at")?,
            web_url: validate_link(&auth.host, wire.web_url)?,
        })
    }

    fn approval_projection(
        auth: &Authorization,
        scope: &GitLabScope,
        provider_revision: ProviderRevision,
        wire: ApprovalWire,
    ) -> Result<ApprovalProjection, GitLabWorkError> {
        let project_id = positive_project_id(wire.project_id)?;
        let iid = positive_merge_request_iid(wire.iid)?;
        if project_id != scope.project_id || Some(iid) != scope.merge_request_iid {
            return Err(GitLabWorkError::ApprovalMismatch);
        }
        let required = wire.approvals_before_merge.unwrap_or(0);
        let approvals_left = wire
            .approvals_left
            .ok_or(GitLabWorkError::MissingResponseField {
                field: "approvals_left",
            })?;
        if approvals_left > required {
            return Err(GitLabWorkError::ApprovalMismatch);
        }
        let state = if approvals_left == 0 {
            if wire.approved == Some(false) {
                return Err(GitLabWorkError::ApprovalMismatch);
            }
            ApprovalState::Approved
        } else {
            if wire.approved == Some(true) {
                return Err(GitLabWorkError::ApprovalMismatch);
            }
            ApprovalState::NeedsApproval
        };
        if wire.approved_by.len() > MAX_APPROVERS {
            return Err(GitLabWorkError::ItemLimitExceeded);
        }
        let approvers = wire
            .approved_by
            .into_iter()
            .map(|approved_by| {
                let user_id = approved_by
                    .user
                    .and_then(|user| user.id)
                    .ok_or(GitLabWorkError::MalformedResponse)
                    .and_then(|id| {
                        crate::model::ProviderUserId::parse(id.to_string())
                            .map_err(GitLabWorkError::Model)
                    })?;
                Ok(ApprovalEntry {
                    user_id,
                    approved_at: bounded_optional_text(
                        approved_by.approved_at,
                        "approval timestamp",
                    )?,
                })
            })
            .collect::<Result<Vec<_>, GitLabWorkError>>()?;
        Ok(ApprovalProjection {
            scope: scope.clone(),
            scope_fence: scope.fence(),
            registration_fence: auth.registration_fence.clone(),
            provider_revision,
            provenance: auth.provenance,
            project_id,
            merge_request_iid: iid,
            state,
            required,
            approvals_left,
            approvers,
        })
    }

    fn validate_pipeline(
        scope: &GitLabScope,
        wire: PipelineWire,
    ) -> Result<
        (
            PipelineId,
            CommitSha,
            RefName,
            PipelineStatus,
            Option<String>,
        ),
        GitLabWorkError,
    > {
        let project_id = positive_project_id(wire.project_id)?;
        if project_id != scope.project_id {
            return Err(GitLabWorkError::ProjectIdMismatch);
        }
        let pipeline_id = PipelineId::new(wire.id).map_err(GitLabWorkError::Model)?;
        if Some(pipeline_id) != scope.pipeline_id {
            return Err(GitLabWorkError::JobScopeMismatch);
        }
        let sha = CommitSha::parse(wire.sha).map_err(GitLabWorkError::Model)?;
        if Some(sha.clone()) != scope.head_sha {
            return Err(GitLabWorkError::PipelineShaMismatch);
        }
        let ref_name = RefName::parse(wire.ref_name).map_err(GitLabWorkError::Model)?;
        Ok((
            pipeline_id,
            sha,
            ref_name,
            parse_pipeline_status(&wire.status),
            bounded_optional_text(wire.updated_at, "pipeline updated_at")?,
        ))
    }

    fn job_projection(
        provider_revision: &ProviderRevision,
        pipeline_id: PipelineId,
        pipeline_sha: &CommitSha,
        wire: JobWire,
    ) -> Result<JobProjection, GitLabWorkError> {
        if let Some(link) = wire.pipeline.as_ref()
            && link.id != pipeline_id.get()
        {
            return Err(GitLabWorkError::JobScopeMismatch);
        }
        let sha = wire
            .commit
            .and_then(|commit| commit.id)
            .map(|value| CommitSha::parse(value).map_err(GitLabWorkError::Model))
            .transpose()?;
        if sha.as_ref().is_some_and(|value| value != pipeline_sha) {
            return Err(GitLabWorkError::PipelineShaMismatch);
        }
        Ok(JobProjection {
            id: JobId::new(wire.id).map_err(GitLabWorkError::Model)?,
            name: bounded_text(wire.name, "job name", MAX_TITLE_LENGTH)?,
            stage: bounded_text(wire.stage, "job stage", MAX_STATUS_LENGTH)?,
            status: parse_job_status(&wire.status),
            sha,
            provider_revision: provider_revision.clone(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct IssueWire {
    id: u64,
    iid: u64,
    project_id: u64,
    title: String,
    state: String,
    #[serde(default)]
    updated_at: Option<String>,
    #[serde(default)]
    web_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MergeRequestWire {
    id: u64,
    iid: u64,
    project_id: u64,
    title: String,
    state: String,
    #[serde(default)]
    draft: bool,
    source_branch: String,
    target_branch: String,
    sha: Option<String>,
    diff_refs: Option<DiffRefsWire>,
    merge_status: Option<String>,
    detailed_merge_status: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
    #[serde(default)]
    web_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DiffRefsWire {
    #[serde(rename = "base_sha")]
    base: String,
    #[serde(rename = "start_sha")]
    start: String,
    #[serde(rename = "head_sha")]
    head: String,
}

#[derive(Debug, Deserialize)]
struct ApprovalWire {
    project_id: u64,
    iid: u64,
    approvals_before_merge: Option<u32>,
    approvals_left: Option<u32>,
    approved: Option<bool>,
    #[serde(default)]
    approved_by: Vec<ApprovedByWire>,
}

#[derive(Debug, Deserialize)]
struct ApprovedByWire {
    user: Option<ApprovalUserWire>,
    #[serde(default)]
    approved_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApprovalUserWire {
    id: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct PipelineWire {
    id: u64,
    project_id: u64,
    sha: String,
    #[serde(rename = "ref")]
    ref_name: String,
    status: String,
    #[serde(default)]
    updated_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JobWire {
    id: u64,
    name: String,
    stage: String,
    status: String,
    #[serde(default)]
    commit: Option<JobCommitWire>,
    #[serde(default)]
    pipeline: Option<JobPipelineLinkWire>,
}

#[derive(Debug, Deserialize)]
struct JobCommitWire {
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JobPipelineLinkWire {
    id: u64,
}

fn parse_value<T: for<'de> Deserialize<'de>>(value: &Value) -> Result<T, GitLabWorkError> {
    serde_json::from_value(value.clone()).map_err(|_| GitLabWorkError::MalformedResponse)
}

fn positive_project_id(value: u64) -> Result<GitLabProjectId, GitLabWorkError> {
    GitLabProjectId::new(value).map_err(GitLabWorkError::Model)
}

fn positive_issue_iid(value: u64) -> Result<IssueIid, GitLabWorkError> {
    IssueIid::new(value).map_err(GitLabWorkError::Model)
}

fn positive_merge_request_iid(value: u64) -> Result<MergeRequestIid, GitLabWorkError> {
    MergeRequestIid::new(value).map_err(GitLabWorkError::Model)
}

fn positive_global_id(value: u64) -> Result<GlobalGitLabId, GitLabWorkError> {
    GlobalGitLabId::new(value).map_err(|_| GitLabWorkError::InvalidGlobalId)
}

fn bounded_text(
    value: String,
    _field: &'static str,
    maximum: usize,
) -> Result<String, GitLabWorkError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(GitLabWorkError::MalformedResponse);
    }
    Ok(value)
}

fn bounded_optional_text(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<String>, GitLabWorkError> {
    value
        .map(|value| bounded_text(value, field, MAX_STATUS_LENGTH))
        .transpose()
}

fn validate_link(
    host: &GitLabHost,
    value: Option<String>,
) -> Result<Option<String>, GitLabWorkError> {
    value
        .map(|url| {
            if host.matches_url(&url).map_err(GitLabWorkError::Model)? {
                Ok(url)
            } else {
                Err(GitLabWorkError::CrossOriginRedirect {
                    expected_origin: host.origin().to_owned(),
                    actual_origin: crate::model::url_origin(&url)?,
                })
            }
        })
        .transpose()
}

fn parse_issue_state(value: &str) -> IssueState {
    match value {
        "opened" => IssueState::Opened,
        "closed" => IssueState::Closed,
        _ => IssueState::Unknown,
    }
}

fn parse_merge_request_state(value: &str) -> MergeRequestState {
    match value {
        "opened" => MergeRequestState::Opened,
        "closed" => MergeRequestState::Closed,
        "merged" => MergeRequestState::Merged,
        "locked" => MergeRequestState::Locked,
        _ => MergeRequestState::Unknown,
    }
}

fn parse_merge_status(value: &str) -> MergeStatus {
    match value {
        "can_be_merged" => MergeStatus::CanBeMerged,
        "cannot_be_merged" => MergeStatus::CannotBeMerged,
        "checking" => MergeStatus::Checking,
        _ => MergeStatus::Unknown,
    }
}

fn parse_pipeline_status(value: &str) -> PipelineStatus {
    match value {
        "created" => PipelineStatus::Created,
        "pending" => PipelineStatus::Pending,
        "running" => PipelineStatus::Running,
        "success" => PipelineStatus::Success,
        "failed" => PipelineStatus::Failed,
        "canceled" => PipelineStatus::Canceled,
        "skipped" => PipelineStatus::Skipped,
        "manual" => PipelineStatus::Manual,
        "scheduled" => PipelineStatus::Scheduled,
        _ => PipelineStatus::Unknown,
    }
}

fn parse_job_status(value: &str) -> JobStatus {
    match value {
        "created" => JobStatus::Created,
        "pending" => JobStatus::Pending,
        "running" => JobStatus::Running,
        "success" => JobStatus::Success,
        "failed" => JobStatus::Failed,
        "canceled" => JobStatus::Canceled,
        "skipped" => JobStatus::Skipped,
        "manual" => JobStatus::Manual,
        "waiting_for_resource" => JobStatus::WaitingForResource,
        "preparing" => JobStatus::Preparing,
        _ => JobStatus::Unknown,
    }
}

fn parse_next_page(response: &TransportResponse) -> Result<Option<u16>, GitLabWorkError> {
    let Some(value) = response.header("x-next-page") else {
        return Ok(None);
    };
    if value.is_empty() || value == "0" {
        return Ok(None);
    }
    let page = value
        .parse::<u16>()
        .map_err(|_| GitLabWorkError::MalformedResponse)?;
    if page == 0 { Ok(None) } else { Ok(Some(page)) }
}

fn parse_optional_u64(response: &TransportResponse, names: &[&str]) -> Option<u64> {
    names
        .iter()
        .find_map(|name| response.header(name).and_then(|value| value.parse().ok()))
}

fn rate_limit(response: &TransportResponse) -> RateLimitObservation {
    RateLimitObservation {
        remaining: parse_optional_u64(response, &["ratelimit-remaining", "x-ratelimit-remaining"]),
        reset_at: parse_optional_u64(response, &["ratelimit-reset", "x-ratelimit-reset"]),
        retry_after_seconds: parse_optional_u64(response, &["retry-after"]),
    }
}

impl fmt::Display for RegistrationProbeStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlockedEnv => formatter.write_str("BLOCKED_ENV"),
        }
    }
}
