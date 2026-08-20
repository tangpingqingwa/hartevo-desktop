//! Scope-bound, non-native AWS Batch provider and transport recordings.

use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;

use crate::model::{
    AccessLossEvidence, AccessLossKind, AwsBatchScope, Digest, JobId, JobProjection, JobStatus,
    JobSummary, MAX_JOBS, MAX_PAGE_SIZE, MAX_PAGES, ModelError, ProviderProvenance,
    digest_serializable, validate_text,
};
use crate::{
    AWS_BATCH_JOB_RESULT_API_REVISION, AWS_BATCH_JOB_RESULT_API_VERSION,
    AWS_BATCH_JOB_RESULT_CONTRACT_VERSION, AWS_BATCH_JOB_RESULT_PLUGIN_VERSION,
    AWS_BATCH_JOB_RESULT_PROVIDER_ID, AwsBatchError, api_digest, contract_digest,
    permission_digest, version_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchApiOperation {
    DescribeJobs,
    ListJobs,
}

pub type AwsBatchApiOperation = BatchApiOperation;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwsBatchTransportError {
    #[error("BLOCKED_ENV: native AWS Batch transport is unavailable")]
    BlockedEnv,
    #[error("AWS Batch returned HTTP 400")]
    BadRequest,
    #[error("AWS Batch returned HTTP 401")]
    Unauthorized,
    #[error("AWS Batch returned HTTP 403")]
    AccessDenied,
    #[error("AWS Batch returned HTTP 404")]
    NotFound,
    #[error("AWS Batch returned HTTP 409")]
    Conflict,
    #[error("AWS Batch request was throttled with HTTP 429")]
    Throttled,
    #[error("AWS Batch returned HTTP {0}")]
    HttpStatus(u16),
    #[error("AWS Batch provider returned a server error")]
    ServerError,
    #[error("AWS Batch request timed out")]
    Timeout,
    #[error("AWS Batch response was malformed")]
    MalformedResponse,
    #[error("invalid normalized AWS Batch request: {0}")]
    InvalidRequest(String),
    #[error("recording AWS Batch response queue is exhausted")]
    QueueExhausted,
}

impl AwsBatchTransportError {
    pub const fn from_http_status(status: u16) -> Self {
        match status {
            400 => Self::BadRequest,
            401 => Self::Unauthorized,
            403 => Self::AccessDenied,
            404 => Self::NotFound,
            409 => Self::Conflict,
            429 => Self::Throttled,
            500..=599 => Self::ServerError,
            _ => Self::HttpStatus(status),
        }
    }

    pub const fn http_status(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::AccessDenied => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::Throttled => Some(429),
            Self::HttpStatus(status) => Some(*status),
            Self::ServerError => Some(500),
            Self::BlockedEnv
            | Self::Timeout
            | Self::MalformedResponse
            | Self::InvalidRequest(_)
            | Self::QueueExhausted => None,
        }
    }

    pub const fn access_loss_kind(&self) -> AccessLossKind {
        match self {
            Self::BlockedEnv => AccessLossKind::BlockedEnv,
            Self::BadRequest => AccessLossKind::BadRequest,
            Self::Unauthorized => AccessLossKind::Unauthorized,
            Self::AccessDenied => AccessLossKind::AccessDenied,
            Self::NotFound => AccessLossKind::NotFound,
            Self::Conflict => AccessLossKind::Conflict,
            Self::Throttled => AccessLossKind::Throttled,
            Self::HttpStatus(status) if *status >= 500 => AccessLossKind::ProviderUnavailable,
            Self::HttpStatus(_) | Self::ServerError => AccessLossKind::ProviderUnavailable,
            Self::Timeout => AccessLossKind::Timeout,
            Self::MalformedResponse => AccessLossKind::MalformedResponse,
            Self::InvalidRequest(_) | Self::QueueExhausted => AccessLossKind::Unknown,
        }
    }

    pub fn provider_code(&self) -> String {
        match self {
            Self::BlockedEnv => "BLOCKED_ENV".to_owned(),
            Self::BadRequest => "HTTP_400".to_owned(),
            Self::Unauthorized => "HTTP_401".to_owned(),
            Self::AccessDenied => "HTTP_403".to_owned(),
            Self::NotFound => "HTTP_404".to_owned(),
            Self::Conflict => "HTTP_409".to_owned(),
            Self::Throttled => "HTTP_429".to_owned(),
            Self::HttpStatus(status) => format!("HTTP_{status}"),
            Self::ServerError => "HTTP_500".to_owned(),
            Self::Timeout => "TIMEOUT".to_owned(),
            Self::MalformedResponse => "MALFORMED_RESPONSE".to_owned(),
            Self::InvalidRequest(_) => "INVALID_REQUEST".to_owned(),
            Self::QueueExhausted => "QUEUE_EXHAUSTED".to_owned(),
        }
    }

    pub const fn is_access_loss(&self) -> bool {
        !matches!(self, Self::InvalidRequest(_) | Self::QueueExhausted)
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaquePageToken {
    token: String,
}

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let token = value.into();
        if token.is_empty() || token.len() > crate::AWS_BATCH_MAX_IDENTIFIER_LENGTH {
            return Err(ModelError::BoundExceeded {
                field: "opaque page token",
            });
        }
        if token.chars().any(char::is_control) {
            return Err(ModelError::InvalidText {
                field: "opaque page token",
            });
        }
        Ok(Self { token })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-batch-page-token/v1",
            std::slice::from_ref(&self.token),
        )
    }

    pub fn is_empty(&self) -> bool {
        self.token.is_empty()
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "OpaquePageToken({})", self.digest())
    }
}

/// Serialization intentionally exposes only the token digest. The provider
/// token itself remains usable inside the transport seam but cannot enter a
/// receipt, debug log, or durable JSON projection.
impl Serialize for OpaquePageToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.digest().as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ListJobsTarget {
    JobQueue(crate::model::JobQueueId),
    ArrayJob(JobId),
    MultiNodeJob(JobId),
}

impl ListJobsTarget {
    pub fn digest(&self) -> Digest {
        match self {
            Self::JobQueue(value) => {
                Digest::from_fields("aws-batch-list-target/v1", &["queue", value.as_str()])
            }
            Self::ArrayJob(value) => {
                Digest::from_fields("aws-batch-list-target/v1", &["array", value.as_str()])
            }
            Self::MultiNodeJob(value) => {
                Digest::from_fields("aws-batch-list-target/v1", &["mnp", value.as_str()])
            }
        }
    }

    pub fn validate_for(&self, scope: &AwsBatchScope) -> Result<(), ModelError> {
        match self {
            Self::JobQueue(queue) if queue == &scope.job_queue_id => Ok(()),
            Self::ArrayJob(job) if scope.array_job_id.as_ref() == Some(job) => Ok(()),
            Self::MultiNodeJob(job) if scope.multi_node_job_id.as_ref() == Some(job) => Ok(()),
            _ => Err(ModelError::InvalidValue {
                field: "ListJobs target fence",
            }),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchFilter {
    pub status: Option<JobStatus>,
    pub filter_digest: Digest,
}

impl Default for BatchFilter {
    fn default() -> Self {
        Self::default_with_digest()
    }
}

impl BatchFilter {
    pub fn all() -> Self {
        Self::default_with_digest()
    }

    fn default_with_digest() -> Self {
        let mut filter = Self {
            status: None,
            filter_digest: Digest::from_text("pending-filter-digest"),
        };
        filter.filter_digest = filter.compute_digest();
        filter
    }

    #[must_use]
    pub fn with_status(mut self, status: JobStatus) -> Self {
        self.status = Some(status);
        self.filter_digest = self.compute_digest();
        self
    }

    #[must_use]
    pub fn with_job_status(self, status: JobStatus) -> Self {
        self.with_status(status)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-batch-filter/v1",
            &[self
                .status
                .map_or_else(String::new, |value| format!("{value:?}"))],
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.filter_digest != self.compute_digest() {
            return Err(ModelError::InvalidDigest {
                field: "Batch filter",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageBinding {
    pub operation: BatchApiOperation,
    pub scope_digest: Digest,
    pub target_digest: Option<Digest>,
    pub filter_digest: Option<Digest>,
    pub page_number: u16,
    pub page_size: u16,
    pub page_token_digest: Option<Digest>,
    pub request_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescribeJobsRequest {
    pub operation: BatchApiOperation,
    pub scope_digest: Digest,
    pub job_ids: Vec<JobId>,
    pub page_number: u16,
    pub page_size: u16,
    pub request_digest: Digest,
}

impl DescribeJobsRequest {
    pub fn new(scope: &AwsBatchScope, job_ids: Vec<JobId>) -> Result<Self, ModelError> {
        if job_ids.is_empty() || job_ids.len() > crate::AWS_BATCH_MAX_DESCRIBE_JOBS {
            return Err(ModelError::BoundExceeded {
                field: "DescribeJobs ids (maximum 100)",
            });
        }
        let page_size = u16::try_from(job_ids.len()).map_err(|_| ModelError::BoundExceeded {
            field: "DescribeJobs page size",
        })?;
        let mut request = Self {
            operation: BatchApiOperation::DescribeJobs,
            scope_digest: scope.digest(),
            job_ids,
            page_number: 1,
            page_size,
            request_digest: Digest::from_text("pending-describe-request-digest"),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn batch(scope: &AwsBatchScope, job_ids: Vec<JobId>) -> Result<Vec<Self>, ModelError> {
        if job_ids.is_empty() || job_ids.len() > MAX_JOBS {
            return Err(ModelError::BoundExceeded {
                field: "DescribeJobs total ids",
            });
        }
        job_ids
            .chunks(crate::AWS_BATCH_MAX_DESCRIBE_JOBS)
            .map(|chunk| Self::new(scope, chunk.to_vec()))
            .collect()
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-batch-describe-jobs-request/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.job_ids
                    .iter()
                    .map(JobId::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
                self.page_number.to_string(),
                self.page_size.to_string(),
            ],
        )
    }

    pub fn binding(&self) -> PageBinding {
        PageBinding {
            operation: self.operation,
            scope_digest: self.scope_digest.clone(),
            target_digest: None,
            filter_digest: None,
            page_number: self.page_number,
            page_size: self.page_size,
            page_token_digest: None,
            request_digest: self.request_digest.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.operation != BatchApiOperation::DescribeJobs
            || self.job_ids.is_empty()
            || self.job_ids.len() > crate::AWS_BATCH_MAX_DESCRIBE_JOBS
            || self.page_number != 1
            || self.request_digest != self.compute_digest()
        {
            return Err(ModelError::InvalidValue {
                field: "DescribeJobs request",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListJobsRequest {
    pub operation: BatchApiOperation,
    pub scope_digest: Digest,
    pub target: ListJobsTarget,
    pub filter: BatchFilter,
    pub page_number: u16,
    pub page_size: u16,
    pub page_token: Option<OpaquePageToken>,
    pub request_digest: Digest,
}

impl ListJobsRequest {
    pub fn new(
        scope: &AwsBatchScope,
        target: ListJobsTarget,
        filter: BatchFilter,
        page_size: u16,
    ) -> Result<Self, ModelError> {
        target.validate_for(scope)?;
        filter.validate()?;
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(ModelError::BoundExceeded {
                field: "ListJobs page size",
            });
        }
        let mut request = Self {
            operation: BatchApiOperation::ListJobs,
            scope_digest: scope.digest(),
            target,
            filter,
            page_number: 1,
            page_size,
            page_token: None,
            request_digest: Digest::from_text("pending-list-request-digest"),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    pub fn for_queue(
        scope: &AwsBatchScope,
        filter: BatchFilter,
        page_size: u16,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            ListJobsTarget::JobQueue(scope.job_queue_id.clone()),
            filter,
            page_size,
        )
    }

    pub fn for_array(
        scope: &AwsBatchScope,
        filter: BatchFilter,
        page_size: u16,
    ) -> Result<Self, ModelError> {
        let parent = scope.array_job_id.clone().ok_or(ModelError::InvalidValue {
            field: "array ListJobs fence",
        })?;
        Self::new(scope, ListJobsTarget::ArrayJob(parent), filter, page_size)
    }

    pub fn for_mnp(
        scope: &AwsBatchScope,
        filter: BatchFilter,
        page_size: u16,
    ) -> Result<Self, ModelError> {
        let parent = scope
            .multi_node_job_id
            .clone()
            .ok_or(ModelError::InvalidValue {
                field: "multi-node ListJobs fence",
            })?;
        Self::new(
            scope,
            ListJobsTarget::MultiNodeJob(parent),
            filter,
            page_size,
        )
    }

    pub fn next_page(&self, token: OpaquePageToken) -> Result<Self, ModelError> {
        if self.page_number >= MAX_PAGES {
            return Err(ModelError::BoundExceeded {
                field: "ListJobs pages",
            });
        }
        let mut request = Self {
            operation: self.operation,
            scope_digest: self.scope_digest.clone(),
            target: self.target.clone(),
            filter: self.filter.clone(),
            page_number: self.page_number + 1,
            page_size: self.page_size,
            page_token: Some(token),
            request_digest: Digest::from_text("pending-list-request-digest"),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-batch-list-jobs-request/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.target.digest().as_str().to_owned(),
                self.filter.filter_digest.as_str().to_owned(),
                self.page_number.to_string(),
                self.page_size.to_string(),
                self.page_token
                    .as_ref()
                    .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
            ],
        )
    }

    pub fn binding(&self) -> PageBinding {
        PageBinding {
            operation: self.operation,
            scope_digest: self.scope_digest.clone(),
            target_digest: Some(self.target.digest()),
            filter_digest: Some(self.filter.filter_digest.clone()),
            page_number: self.page_number,
            page_size: self.page_size,
            page_token_digest: self.page_token.as_ref().map(OpaquePageToken::digest),
            request_digest: self.request_digest.clone(),
        }
    }

    pub fn validate(&self, scope: &AwsBatchScope) -> Result<(), ModelError> {
        if self.operation != BatchApiOperation::ListJobs
            || self.scope_digest != scope.digest()
            || self.target.validate_for(scope).is_err()
            || self.filter.validate().is_err()
            || self.page_number == 0
            || self.page_number > MAX_PAGES
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.request_digest != self.compute_digest()
        {
            return Err(ModelError::InvalidValue {
                field: "ListJobs request",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescribeJobsPage {
    pub binding: PageBinding,
    pub jobs: Vec<JobProjection>,
    pub partial: bool,
    pub access_loss: Option<AccessLossEvidence>,
    pub provider_revision: String,
    pub response_digest: Digest,
}

impl DescribeJobsPage {
    pub fn new(
        request: &DescribeJobsRequest,
        jobs: Vec<JobProjection>,
        partial: bool,
        provider_revision: impl Into<String>,
    ) -> Result<Self, ModelError> {
        request.validate()?;
        if jobs.len() > request.job_ids.len() || jobs.len() > crate::AWS_BATCH_MAX_DESCRIBE_JOBS {
            return Err(ModelError::BoundExceeded {
                field: "DescribeJobs response",
            });
        }
        for job in &jobs {
            job.validate()?;
        }
        let provider_revision = provider_revision.into();
        validate_revision(&provider_revision)?;
        let mut page = Self {
            binding: request.binding(),
            jobs,
            partial,
            access_loss: None,
            provider_revision,
            response_digest: Digest::from_text("pending-describe-response-digest"),
        };
        page.response_digest = page.compute_digest()?;
        Ok(page)
    }

    pub fn with_access_loss(mut self, loss: AccessLossEvidence) -> Result<Self, ModelError> {
        self.partial = true;
        self.access_loss = Some(loss);
        self.response_digest = self.compute_digest()?;
        Ok(self)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            &self.binding,
            &self.jobs,
            self.partial,
            &self.access_loss,
            &self.provider_revision,
        ))
    }

    pub fn validate_for(&self, request: &DescribeJobsRequest) -> Result<(), ModelError> {
        request.validate()?;
        if self.binding != request.binding()
            || self.jobs.len() > request.job_ids.len()
            || self
                .jobs
                .iter()
                .any(|job| !request.job_ids.iter().any(|job_id| job_id == &job.job_id))
            || self.jobs.iter().any(|job| job.validate().is_err())
            || self.response_digest != self.compute_digest()?
        {
            return Err(ModelError::InvalidValue {
                field: "DescribeJobs page binding",
            });
        }
        if let Some(loss) = &self.access_loss {
            loss.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListJobsPage {
    pub binding: PageBinding,
    pub summaries: Vec<JobSummary>,
    pub next_page: Option<OpaquePageToken>,
    pub partial: bool,
    pub access_loss: Option<AccessLossEvidence>,
    pub provider_revision: String,
    pub response_digest: Digest,
}

impl ListJobsPage {
    pub fn new(
        request: &ListJobsRequest,
        summaries: Vec<JobSummary>,
        next_page: Option<OpaquePageToken>,
        partial: bool,
        provider_revision: impl Into<String>,
    ) -> Result<Self, ModelError> {
        if summaries.len() > usize::from(request.page_size) {
            return Err(ModelError::BoundExceeded {
                field: "ListJobs response",
            });
        }
        request.validate_scope_digest_only()?;
        for summary in &summaries {
            summary.validate()?;
        }
        let provider_revision = provider_revision.into();
        validate_revision(&provider_revision)?;
        let mut page = Self {
            binding: request.binding(),
            summaries,
            next_page,
            partial,
            access_loss: None,
            provider_revision,
            response_digest: Digest::from_text("pending-list-response-digest"),
        };
        page.response_digest = page.compute_digest()?;
        Ok(page)
    }

    pub fn with_access_loss(mut self, loss: AccessLossEvidence) -> Result<Self, ModelError> {
        self.partial = true;
        self.access_loss = Some(loss);
        self.response_digest = self.compute_digest()?;
        Ok(self)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            &self.binding,
            &self.summaries,
            &self.next_page,
            self.partial,
            &self.access_loss,
            &self.provider_revision,
        ))
    }

    pub fn validate_for(&self, request: &ListJobsRequest) -> Result<(), ModelError> {
        request.validate_scope_digest_only()?;
        if self.binding != request.binding()
            || self.summaries.len() > usize::from(request.page_size)
            || self
                .next_page
                .as_ref()
                .is_some_and(OpaquePageToken::is_empty)
            || self
                .summaries
                .iter()
                .any(|summary| summary.validate().is_err())
            || self.response_digest != self.compute_digest()?
        {
            return Err(ModelError::InvalidValue {
                field: "ListJobs page binding",
            });
        }
        if let Some(loss) = &self.access_loss {
            loss.validate()?;
        }
        Ok(())
    }
}

impl ListJobsRequest {
    fn validate_scope_digest_only(&self) -> Result<(), ModelError> {
        if self.operation != BatchApiOperation::ListJobs
            || self.page_number == 0
            || self.page_number > MAX_PAGES
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.filter.validate().is_err()
            || self.request_digest != self.compute_digest()
        {
            return Err(ModelError::InvalidValue {
                field: "ListJobs page request",
            });
        }
        Ok(())
    }
}

fn validate_revision(value: &str) -> Result<(), ModelError> {
    validate_text(value, "provider revision")
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedDescribeJobsRequest {
    pub operation: BatchApiOperation,
    pub scope_digest: Digest,
    pub job_id_digests: Vec<Digest>,
    pub page_number: u16,
    pub page_size: u16,
    pub request_digest: Digest,
}

impl From<&DescribeJobsRequest> for RecordedDescribeJobsRequest {
    fn from(request: &DescribeJobsRequest) -> Self {
        Self {
            operation: request.operation,
            scope_digest: request.scope_digest.clone(),
            job_id_digests: request
                .job_ids
                .iter()
                .map(|job| Digest::from_text(job.as_str()))
                .collect(),
            page_number: request.page_number,
            page_size: request.page_size,
            request_digest: request.request_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedListJobsRequest {
    pub operation: BatchApiOperation,
    pub scope_digest: Digest,
    pub target_digest: Digest,
    pub filter_digest: Digest,
    pub page_number: u16,
    pub page_size: u16,
    pub page_token_digest: Option<Digest>,
    pub request_digest: Digest,
}

impl From<&ListJobsRequest> for RecordedListJobsRequest {
    fn from(request: &ListJobsRequest) -> Self {
        Self {
            operation: request.operation,
            scope_digest: request.scope_digest.clone(),
            target_digest: request.target.digest(),
            filter_digest: request.filter.filter_digest.clone(),
            page_number: request.page_number,
            page_size: request.page_size,
            page_token_digest: request.page_token.as_ref().map(OpaquePageToken::digest),
            request_digest: request.request_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordedAwsBatchRequest {
    Describe(RecordedDescribeJobsRequest),
    List(RecordedListJobsRequest),
}

pub trait AwsBatchTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn describe_jobs(
        &mut self,
        request: &DescribeJobsRequest,
    ) -> Result<DescribeJobsPage, AwsBatchTransportError>;

    fn list_jobs(
        &mut self,
        request: &ListJobsRequest,
    ) -> Result<ListJobsPage, AwsBatchTransportError>;

    fn is_native(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug)]
pub struct RecordingAwsBatchTransport {
    describe_responses: VecDeque<Result<DescribeJobsPage, AwsBatchTransportError>>,
    list_responses: VecDeque<Result<ListJobsPage, AwsBatchTransportError>>,
    requests: Vec<RecordedAwsBatchRequest>,
    provenance: ProviderProvenance,
}

impl Default for RecordingAwsBatchTransport {
    fn default() -> Self {
        Self::new(std::iter::empty())
    }
}

impl RecordingAwsBatchTransport {
    pub fn new(
        responses: impl IntoIterator<Item = Result<DescribeJobsPage, AwsBatchTransportError>>,
    ) -> Self {
        Self {
            describe_responses: responses.into_iter().collect(),
            list_responses: VecDeque::new(),
            requests: Vec::new(),
            provenance: ProviderProvenance::Recording,
        }
    }

    pub fn new_with_list_responses(
        describe_responses: impl IntoIterator<Item = Result<DescribeJobsPage, AwsBatchTransportError>>,
        list_responses: impl IntoIterator<Item = Result<ListJobsPage, AwsBatchTransportError>>,
    ) -> Self {
        Self {
            describe_responses: describe_responses.into_iter().collect(),
            list_responses: list_responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: ProviderProvenance::Recording,
        }
    }

    pub fn fixture(
        responses: impl IntoIterator<Item = Result<DescribeJobsPage, AwsBatchTransportError>>,
    ) -> Self {
        Self {
            describe_responses: responses.into_iter().collect(),
            list_responses: VecDeque::new(),
            requests: Vec::new(),
            provenance: ProviderProvenance::Fixture,
        }
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: ProviderProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    pub fn push_describe_response(
        &mut self,
        response: Result<DescribeJobsPage, AwsBatchTransportError>,
    ) {
        self.describe_responses.push_back(response);
    }

    pub fn push_list_response(&mut self, response: Result<ListJobsPage, AwsBatchTransportError>) {
        self.list_responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedAwsBatchRequest] {
        &self.requests
    }

    pub fn call_count(&self) -> usize {
        self.requests.len()
    }

    pub fn describe_requests(&self) -> Vec<&RecordedDescribeJobsRequest> {
        self.requests
            .iter()
            .filter_map(|request| match request {
                RecordedAwsBatchRequest::Describe(value) => Some(value),
                RecordedAwsBatchRequest::List(_) => None,
            })
            .collect()
    }

    pub fn list_requests(&self) -> Vec<&RecordedListJobsRequest> {
        self.requests
            .iter()
            .filter_map(|request| match request {
                RecordedAwsBatchRequest::Describe(_) => None,
                RecordedAwsBatchRequest::List(value) => Some(value),
            })
            .collect()
    }

    pub fn remaining_describe_responses(&self) -> usize {
        self.describe_responses.len()
    }

    pub fn remaining_list_responses(&self) -> usize {
        self.list_responses.len()
    }
}

impl AwsBatchTransport for RecordingAwsBatchTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn describe_jobs(
        &mut self,
        request: &DescribeJobsRequest,
    ) -> Result<DescribeJobsPage, AwsBatchTransportError> {
        self.requests
            .push(RecordedAwsBatchRequest::Describe(request.into()));
        self.describe_responses
            .pop_front()
            .ok_or(AwsBatchTransportError::QueueExhausted)?
    }

    fn list_jobs(
        &mut self,
        request: &ListJobsRequest,
    ) -> Result<ListJobsPage, AwsBatchTransportError> {
        self.requests
            .push(RecordedAwsBatchRequest::List(request.into()));
        self.list_responses
            .pop_front()
            .ok_or(AwsBatchTransportError::QueueExhausted)?
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAwsBatchTransport;

impl AwsBatchTransport for BlockedEnvAwsBatchTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn describe_jobs(
        &mut self,
        _request: &DescribeJobsRequest,
    ) -> Result<DescribeJobsPage, AwsBatchTransportError> {
        Err(AwsBatchTransportError::BlockedEnv)
    }

    fn list_jobs(
        &mut self,
        _request: &ListJobsRequest,
    ) -> Result<ListJobsPage, AwsBatchTransportError> {
        Err(AwsBatchTransportError::BlockedEnv)
    }
}

/// Deterministic loopback evidence proves only that the normalized seam can
/// be exercised. An empty result is not a native AWS assertion.
#[derive(Clone, Copy, Debug, Default)]
pub struct LoopbackAwsBatchTransport;

impl AwsBatchTransport for LoopbackAwsBatchTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }

    fn describe_jobs(
        &mut self,
        request: &DescribeJobsRequest,
    ) -> Result<DescribeJobsPage, AwsBatchTransportError> {
        DescribeJobsPage::new(
            request,
            Vec::new(),
            false,
            AWS_BATCH_JOB_RESULT_API_REVISION,
        )
        .map_err(|error| AwsBatchTransportError::InvalidRequest(error.to_string()))
    }

    fn list_jobs(
        &mut self,
        request: &ListJobsRequest,
    ) -> Result<ListJobsPage, AwsBatchTransportError> {
        ListJobsPage::new(
            request,
            Vec::new(),
            None,
            false,
            AWS_BATCH_JOB_RESULT_API_REVISION,
        )
        .map_err(|error| AwsBatchTransportError::InvalidRequest(error.to_string()))
    }
}

pub type FakeAwsBatchTransport = LoopbackAwsBatchTransport;
pub type FixtureAwsBatchTransport = RecordingAwsBatchTransport;
pub type RecordingTransport = RecordingAwsBatchTransport;
pub type BlockedEnvTransport = BlockedEnvAwsBatchTransport;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsBatchRegistrationRequest {
    pub plugin_version: String,
    pub contract_version: String,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope: AwsBatchScope,
    pub secret_reference: crate::model::SigV4SecretReference,
}

impl AwsBatchRegistrationRequest {
    pub fn new(
        scope: AwsBatchScope,
        secret_reference: crate::model::SigV4SecretReference,
        provider_revision: impl Into<String>,
        provider_digest: Digest,
        api_digest_value: Digest,
        permission_digest_value: Digest,
    ) -> Result<Self, AwsBatchError> {
        let provider_revision = provider_revision.into();
        if provider_revision.trim().is_empty()
            || provider_revision.chars().any(char::is_control)
            || !secret_reference.is_for_scope(&scope)
            || scope.permission_digest != permission_digest()
            || permission_digest_value != permission_digest()
        {
            return Err(AwsBatchError::InvalidRegistration);
        }
        Ok(Self {
            plugin_version: AWS_BATCH_JOB_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: AWS_BATCH_JOB_RESULT_CONTRACT_VERSION.to_owned(),
            version_digest: version_digest(),
            contract_digest: contract_digest(),
            provider_revision,
            provider_digest,
            api_digest: api_digest_value,
            permission_digest: permission_digest_value,
            scope,
            secret_reference,
        })
    }

    pub fn baseline(
        scope: AwsBatchScope,
        secret_reference: crate::model::SigV4SecretReference,
    ) -> Result<Self, AwsBatchError> {
        Self::new(
            scope,
            secret_reference,
            AWS_BATCH_JOB_RESULT_API_REVISION,
            provider_digest(),
            api_digest(),
            permission_digest(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsBatchRegistration {
    plugin_version: String,
    contract_version: String,
    version_digest: Digest,
    contract_digest: Digest,
    provider_revision: String,
    provider_digest: Digest,
    api_digest: Digest,
    permission_digest: Digest,
    scope: AwsBatchScope,
    secret_reference: crate::model::SigV4SecretReference,
    job_digest: Digest,
    attempt_digest: Digest,
    registration_digest: Digest,
    state: RegistrationState,
    revocation_revision: Option<crate::model::Revision>,
}

impl AwsBatchRegistration {
    fn new(request: AwsBatchRegistrationRequest) -> Result<Self, AwsBatchError> {
        if request.plugin_version != AWS_BATCH_JOB_RESULT_PLUGIN_VERSION
            || request.contract_version != AWS_BATCH_JOB_RESULT_CONTRACT_VERSION
            || request.version_digest != version_digest()
            || request.contract_digest != contract_digest()
            || request.api_digest != api_digest()
            || request.permission_digest != request.scope.permission_digest
            || request.permission_digest != permission_digest()
            || !request.secret_reference.is_for_scope(&request.scope)
        {
            return Err(AwsBatchError::InvalidRegistration);
        }
        let job_digest = request.scope.job_digest();
        let attempt_digest = request.scope.attempt_digest();
        let registration_digest = Digest::from_fields(
            "hartevo.aws-batch-registration/v1",
            &[
                request.plugin_version.clone(),
                request.contract_version.clone(),
                request.version_digest.as_str().to_owned(),
                request.contract_digest.as_str().to_owned(),
                request.provider_revision.clone(),
                request.provider_digest.as_str().to_owned(),
                request.api_digest.as_str().to_owned(),
                request.permission_digest.as_str().to_owned(),
                request.scope.digest().as_str().to_owned(),
                job_digest.as_str().to_owned(),
                attempt_digest.as_str().to_owned(),
                request
                    .secret_reference
                    .reference_digest()
                    .as_str()
                    .to_owned(),
            ],
        );
        Ok(Self {
            plugin_version: request.plugin_version,
            contract_version: request.contract_version,
            version_digest: request.version_digest,
            contract_digest: request.contract_digest,
            provider_revision: request.provider_revision,
            provider_digest: request.provider_digest,
            api_digest: request.api_digest,
            permission_digest: request.permission_digest,
            scope: request.scope,
            secret_reference: request.secret_reference,
            job_digest,
            attempt_digest,
            registration_digest,
            state: RegistrationState::Active,
            revocation_revision: None,
        })
    }

    pub fn validate_for(
        &self,
        provider_revision: &str,
        provider_digest_value: &Digest,
    ) -> Result<(), AwsBatchError> {
        if self.plugin_version != AWS_BATCH_JOB_RESULT_PLUGIN_VERSION
            || self.contract_version != AWS_BATCH_JOB_RESULT_CONTRACT_VERSION
            || self.version_digest != version_digest()
            || self.contract_digest != contract_digest()
            || self.provider_revision != provider_revision
            || &self.provider_digest != provider_digest_value
            || self.api_digest != api_digest()
            || self.permission_digest != self.scope.permission_digest
            || self.permission_digest != permission_digest()
            || self.job_digest != self.scope.job_digest()
            || self.attempt_digest != self.scope.attempt_digest()
            || !self.secret_reference.is_for_scope(&self.scope)
        {
            return Err(AwsBatchError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn revoke(&mut self, revision: crate::model::Revision) -> Result<(), AwsBatchError> {
        if self.state == RegistrationState::Revoked {
            return Err(AwsBatchError::RegistrationRevoked);
        }
        self.state = RegistrationState::Revoked;
        self.revocation_revision = Some(revision);
        Ok(())
    }

    pub const fn state(&self) -> RegistrationState {
        self.state
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn scope(&self) -> &AwsBatchScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &crate::model::SigV4SecretReference {
        &self.secret_reference
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn version_digest(&self) -> &Digest {
        &self.version_digest
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_revision(&self) -> &str {
        &self.provider_revision
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn job_digest(&self) -> &Digest {
        &self.job_digest
    }

    pub fn attempt_digest(&self) -> &Digest {
        &self.attempt_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn revocation_revision(&self) -> Option<crate::model::Revision> {
        self.revocation_revision
    }
}

pub fn provider_digest() -> Digest {
    provider_digest_for_revision(AWS_BATCH_JOB_RESULT_API_REVISION)
}

pub fn provider_digest_for_revision(provider_revision: &str) -> Digest {
    Digest::from_fields(
        "hartevo.aws-batch-provider/v1",
        &[
            AWS_BATCH_JOB_RESULT_PROVIDER_ID.to_owned(),
            provider_revision.to_owned(),
            AWS_BATCH_JOB_RESULT_API_VERSION.to_owned(),
            "DescribeJobs".to_owned(),
            "ListJobs".to_owned(),
            "batch:DescribeJobs".to_owned(),
            "batch:ListJobs".to_owned(),
        ],
    )
}

pub struct AwsBatchProvider<T> {
    transport: T,
    provider_revision: String,
    provider_digest: Digest,
    provenance: ProviderProvenance,
    registration: Option<AwsBatchRegistration>,
}

impl<T: fmt::Debug> fmt::Debug for AwsBatchProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsBatchProvider")
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("provenance", &self.provenance)
            .field("registration", &self.registration)
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T: AwsBatchTransport> AwsBatchProvider<T> {
    pub fn new(
        transport: T,
        provider_revision: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, AwsBatchError> {
        let provider_revision = provider_revision.into();
        if provider_revision.trim().is_empty()
            || provider_revision.chars().any(char::is_control)
            || transport.is_native()
            || provenance.is_native()
        {
            return Err(AwsBatchError::ProviderDrift);
        }
        Ok(Self {
            provider_digest: provider_digest_for_revision(&provider_revision),
            transport,
            provider_revision,
            provenance,
            registration: None,
        })
    }

    pub fn baseline(transport: T) -> Result<Self, AwsBatchError> {
        let provenance = transport.provenance();
        Self::new(transport, AWS_BATCH_JOB_RESULT_API_REVISION, provenance)
    }

    pub fn register(
        &mut self,
        request: AwsBatchRegistrationRequest,
    ) -> Result<AwsBatchRegistration, AwsBatchError> {
        if request.provider_revision != self.provider_revision
            || request.provider_digest != self.provider_digest
        {
            return Err(AwsBatchError::ProviderDrift);
        }
        let registration = AwsBatchRegistration::new(request)?;
        registration.validate_for(&self.provider_revision, &self.provider_digest)?;
        self.registration = Some(registration.clone());
        Ok(registration)
    }

    pub fn register_scope(
        &mut self,
        scope: AwsBatchScope,
        secret_reference: crate::model::SigV4SecretReference,
    ) -> Result<AwsBatchRegistration, AwsBatchError> {
        let request = AwsBatchRegistrationRequest::new(
            scope,
            secret_reference,
            self.provider_revision.clone(),
            self.provider_digest.clone(),
            api_digest(),
            permission_digest(),
        )?;
        self.register(request)
    }

    pub fn revoke_registration(
        &mut self,
        revision: crate::model::Revision,
    ) -> Result<(), AwsBatchError> {
        self.registration_mut()?.revoke(revision)
    }

    pub fn registration(&self) -> Option<&AwsBatchRegistration> {
        self.registration.as_ref()
    }

    pub fn registration_mut(&mut self) -> Result<&mut AwsBatchRegistration, AwsBatchError> {
        self.registration
            .as_mut()
            .ok_or(AwsBatchError::RegistrationMissing)
    }

    pub fn provider_revision(&self) -> &str {
        &self.provider_revision
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub const fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn describe_jobs(
        &mut self,
        request: &DescribeJobsRequest,
    ) -> Result<DescribeJobsPage, AwsBatchError> {
        self.ensure_request_scope(&request.scope_digest, BatchApiOperation::DescribeJobs)?;
        request.validate()?;
        let page = self.transport.describe_jobs(request)?;
        page.validate_for(request)
            .map_err(|_| AwsBatchError::PageBindingMismatch)?;
        if page.provider_revision != self.provider_revision {
            return Err(AwsBatchError::ProviderDrift);
        }
        Ok(page)
    }

    pub fn list_jobs(&mut self, request: &ListJobsRequest) -> Result<ListJobsPage, AwsBatchError> {
        let scope = self
            .registration
            .as_ref()
            .ok_or(AwsBatchError::RegistrationMissing)?
            .scope()
            .clone();
        self.ensure_request_scope(&request.scope_digest, BatchApiOperation::ListJobs)?;
        request.validate(&scope)?;
        let page = self.transport.list_jobs(request)?;
        page.validate_for(request)
            .map_err(|_| AwsBatchError::PageBindingMismatch)?;
        if page.provider_revision != self.provider_revision {
            return Err(AwsBatchError::ProviderDrift);
        }
        Ok(page)
    }

    fn ensure_request_scope(
        &self,
        scope_digest: &Digest,
        operation: BatchApiOperation,
    ) -> Result<(), AwsBatchError> {
        let registration = self
            .registration
            .as_ref()
            .ok_or(AwsBatchError::RegistrationMissing)?;
        if !registration.is_active() {
            return Err(AwsBatchError::RegistrationRevoked);
        }
        registration.validate_for(&self.provider_revision, &self.provider_digest)?;
        if registration.scope().digest() != *scope_digest {
            return Err(AwsBatchError::ScopeMismatch);
        }
        if matches!(operation, BatchApiOperation::DescribeJobs) {
            // The concrete request validates the 100-ID DescribeJobs fence.
        }
        Ok(())
    }
}
