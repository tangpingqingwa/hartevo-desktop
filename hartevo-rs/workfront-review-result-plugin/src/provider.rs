//! Typed Workfront read seam and honest recording/fixture transports.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::error::{Result, WorkfrontReviewResultError, WorkfrontTransportError};
use crate::model::{
    ApprovalSnapshot, Cursor, Digest, ProjectSnapshot, ReviewSnapshot, TaskSnapshot,
    TransportProvenance, WorkfrontReviewScope,
};
use crate::{API_REVISION, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES, PROVIDER_ID};

pub type TransportResult<T> = std::result::Result<T, WorkfrontTransportError>;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkfrontOperation {
    ReadProject,
    ReadTask,
    ReadReview,
    ReadApproval,
}

impl WorkfrontOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadProject => "read_project",
            Self::ReadTask => "read_task",
            Self::ReadReview => "read_review",
            Self::ReadApproval => "read_approval",
        }
    }
}

/// A bounded, digest-only request. `http_path` is available for a recording
/// fixture but is never retained in a proposal or receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkfrontReadRequest {
    pub operation: WorkfrontOperation,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub page_size: u16,
    pub page: u16,
    pub cursor: Option<Cursor>,
    pub observed_at: DateTime<Utc>,
}

impl WorkfrontReadRequest {
    pub fn new(
        operation: WorkfrontOperation,
        scope: &WorkfrontReviewScope,
        registration_digest: &Digest,
        page_size: u16,
        page: u16,
        cursor: Option<Cursor>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE || page == 0 || page > MAX_PAGES {
            return Err(WorkfrontReviewResultError::InvalidRequest);
        }
        registration_digest.validate()?;
        if let Some(cursor) = &cursor
            && (cursor.scope_digest() != &scope.digest() || cursor.page() >= page)
        {
            return Err(WorkfrontReviewResultError::CursorMismatch);
        }
        Ok(Self {
            operation,
            scope_digest: scope.digest(),
            registration_digest: registration_digest.clone(),
            page_size,
            page,
            cursor,
            observed_at,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "workfront-read-request/v1",
            &[
                ("operation", self.operation.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("page_size", self.page_size.to_string()),
                ("page", self.page.to_string()),
                (
                    "cursor",
                    self.cursor
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        )
    }

    pub fn path(&self, scope: &WorkfrontReviewScope) -> Result<String> {
        if self.scope_digest != scope.digest() {
            return Err(WorkfrontReviewResultError::ScopeMismatch);
        }
        let path = match self.operation {
            WorkfrontOperation::ReadProject => format!(
                "/attask/api/v15.0/project/{}?fields=ID,status,lastUpdatedDate",
                scope.project().as_str()
            ),
            WorkfrontOperation::ReadTask => format!(
                "/attask/api/v15.0/task/{}?fields=ID,status,percentComplete,lastUpdatedDate",
                scope.task().as_str()
            ),
            WorkfrontOperation::ReadReview => format!(
                "/attask/api/v15.0/document/{}/review/{}?fields=ID,status,decisionDate,submittedDate",
                scope.document().as_str(),
                scope.review().as_str()
            ),
            WorkfrontOperation::ReadApproval => format!(
                "/attask/api/v15.0/proofapproval/{}?fields=ID,status,decisionDate",
                scope.approval().as_str()
            ),
        };
        Ok(path)
    }

    pub fn path_digest(&self, scope: &WorkfrontReviewScope) -> Result<Digest> {
        Ok(Digest::from_text(self.path(scope)?))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectReadResponse {
    pub request_digest: Digest,
    pub project: ProjectSnapshot,
    pub response_bytes: u64,
    pub next_cursor: Option<Cursor>,
    pub response_digest: Digest,
    pub provenance: TransportProvenance,
}

impl ProjectReadResponse {
    pub fn new(
        request: &WorkfrontReadRequest,
        project: ProjectSnapshot,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if request.operation != WorkfrontOperation::ReadProject
            || response_bytes == 0
            || response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(WorkfrontReviewResultError::InvalidResponse);
        }
        let response_digest =
            calculate_project_response_digest(request, &project, next_cursor.as_ref());
        Ok(Self {
            request_digest: request.digest(),
            project,
            response_bytes,
            next_cursor,
            response_digest,
            provenance,
        })
    }

    pub fn with_declared_digest(mut self, response_digest: Digest) -> Self {
        self.response_digest = response_digest;
        self
    }

    pub fn validate(&self, request: &WorkfrontReadRequest) -> Result<()> {
        if self.request_digest != request.digest()
            || self.response_bytes == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.provenance.is_connected()
            || self.provenance.is_native()
            || self.provenance.is_first_party()
            || self.response_digest
                != calculate_project_response_digest(
                    request,
                    &self.project,
                    self.next_cursor.as_ref(),
                )
        {
            return Err(WorkfrontReviewResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskReadResponse {
    pub request_digest: Digest,
    pub task: TaskSnapshot,
    pub response_bytes: u64,
    pub next_cursor: Option<Cursor>,
    pub response_digest: Digest,
    pub provenance: TransportProvenance,
}

impl TaskReadResponse {
    pub fn new(
        request: &WorkfrontReadRequest,
        task: TaskSnapshot,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if request.operation != WorkfrontOperation::ReadTask
            || response_bytes == 0
            || response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(WorkfrontReviewResultError::InvalidResponse);
        }
        let response_digest = calculate_task_response_digest(request, &task, next_cursor.as_ref());
        Ok(Self {
            request_digest: request.digest(),
            task,
            response_bytes,
            next_cursor,
            response_digest,
            provenance,
        })
    }

    pub fn with_declared_digest(mut self, response_digest: Digest) -> Self {
        self.response_digest = response_digest;
        self
    }

    pub fn validate(&self, request: &WorkfrontReadRequest) -> Result<()> {
        if self.request_digest != request.digest()
            || self.response_bytes == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.provenance.is_connected()
            || self.provenance.is_native()
            || self.provenance.is_first_party()
            || self.response_digest
                != calculate_task_response_digest(request, &self.task, self.next_cursor.as_ref())
        {
            return Err(WorkfrontReviewResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewReadResponse {
    pub request_digest: Digest,
    pub review: ReviewSnapshot,
    pub response_bytes: u64,
    pub next_cursor: Option<Cursor>,
    pub response_digest: Digest,
    pub provenance: TransportProvenance,
}

impl ReviewReadResponse {
    pub fn new(
        request: &WorkfrontReadRequest,
        review: ReviewSnapshot,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if request.operation != WorkfrontOperation::ReadReview
            || response_bytes == 0
            || response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(WorkfrontReviewResultError::InvalidResponse);
        }
        let response_digest =
            calculate_review_response_digest(request, &review, next_cursor.as_ref());
        Ok(Self {
            request_digest: request.digest(),
            review,
            response_bytes,
            next_cursor,
            response_digest,
            provenance,
        })
    }

    pub fn with_declared_digest(mut self, response_digest: Digest) -> Self {
        self.response_digest = response_digest;
        self
    }

    pub fn validate(&self, request: &WorkfrontReadRequest) -> Result<()> {
        if self.request_digest != request.digest()
            || self.response_bytes == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.provenance.is_connected()
            || self.provenance.is_native()
            || self.provenance.is_first_party()
            || self.response_digest
                != calculate_review_response_digest(
                    request,
                    &self.review,
                    self.next_cursor.as_ref(),
                )
        {
            return Err(WorkfrontReviewResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalReadResponse {
    pub request_digest: Digest,
    pub approval: ApprovalSnapshot,
    pub response_bytes: u64,
    pub next_cursor: Option<Cursor>,
    pub response_digest: Digest,
    pub provenance: TransportProvenance,
}

impl ApprovalReadResponse {
    pub fn new(
        request: &WorkfrontReadRequest,
        approval: ApprovalSnapshot,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if request.operation != WorkfrontOperation::ReadApproval
            || response_bytes == 0
            || response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(WorkfrontReviewResultError::InvalidResponse);
        }
        let response_digest =
            calculate_approval_response_digest(request, &approval, next_cursor.as_ref());
        Ok(Self {
            request_digest: request.digest(),
            approval,
            response_bytes,
            next_cursor,
            response_digest,
            provenance,
        })
    }

    pub fn with_declared_digest(mut self, response_digest: Digest) -> Self {
        self.response_digest = response_digest;
        self
    }

    pub fn validate(&self, request: &WorkfrontReadRequest) -> Result<()> {
        if self.request_digest != request.digest()
            || self.response_bytes == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.provenance.is_connected()
            || self.provenance.is_native()
            || self.provenance.is_first_party()
            || self.response_digest
                != calculate_approval_response_digest(
                    request,
                    &self.approval,
                    self.next_cursor.as_ref(),
                )
        {
            return Err(WorkfrontReviewResultError::TamperedEvidence);
        }
        Ok(())
    }
}

fn cursor_part(cursor: Option<&Cursor>) -> String {
    cursor
        .as_ref()
        .map_or_else(String::new, |value| value.digest().as_str().to_owned())
}

fn calculate_project_response_digest(
    request: &WorkfrontReadRequest,
    project: &ProjectSnapshot,
    next_cursor: Option<&Cursor>,
) -> Digest {
    Digest::from_parts(
        "workfront-project-response/v1",
        &[
            ("request", request.digest().as_str().to_owned()),
            ("project", project.digest().as_str().to_owned()),
            ("cursor", cursor_part(next_cursor)),
        ],
    )
}

fn calculate_task_response_digest(
    request: &WorkfrontReadRequest,
    task: &TaskSnapshot,
    next_cursor: Option<&Cursor>,
) -> Digest {
    Digest::from_parts(
        "workfront-task-response/v1",
        &[
            ("request", request.digest().as_str().to_owned()),
            ("task", task.digest().as_str().to_owned()),
            ("cursor", cursor_part(next_cursor)),
        ],
    )
}

fn calculate_review_response_digest(
    request: &WorkfrontReadRequest,
    review: &ReviewSnapshot,
    next_cursor: Option<&Cursor>,
) -> Digest {
    Digest::from_parts(
        "workfront-review-response/v1",
        &[
            ("request", request.digest().as_str().to_owned()),
            ("review", review.digest().as_str().to_owned()),
            ("cursor", cursor_part(next_cursor)),
        ],
    )
}

fn calculate_approval_response_digest(
    request: &WorkfrontReadRequest,
    approval: &ApprovalSnapshot,
    next_cursor: Option<&Cursor>,
) -> Digest {
    Digest::from_parts(
        "workfront-approval-response/v1",
        &[
            ("request", request.digest().as_str().to_owned()),
            ("approval", approval.digest().as_str().to_owned()),
            ("cursor", cursor_part(next_cursor)),
        ],
    )
}

/// Provider definition is fixed to the non-native Layer-1 recording seam.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkfrontProviderDefinition {
    pub provider_id: String,
    pub api_revision: String,
    pub provider_release: String,
    pub provider_revision: u64,
    pub provider_digest: Digest,
    pub operations: Vec<WorkfrontOperation>,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub external_writes: bool,
}

impl WorkfrontProviderDefinition {
    pub fn recording() -> Self {
        let provider_id = PROVIDER_ID.to_owned();
        let api_revision = API_REVISION.to_owned();
        let provider_release = "1.0.0".to_owned();
        let operations = vec![
            WorkfrontOperation::ReadProject,
            WorkfrontOperation::ReadTask,
            WorkfrontOperation::ReadReview,
            WorkfrontOperation::ReadApproval,
        ];
        let provider_digest = Digest::from_parts(
            "workfront-provider/v1",
            &[
                ("id", provider_id.clone()),
                ("api", api_revision.clone()),
                ("release", provider_release.clone()),
                (
                    "operations",
                    operations
                        .iter()
                        .map(|operation| operation.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        Self {
            provider_id,
            api_revision,
            provider_release,
            provider_revision: 1,
            provider_digest,
            operations,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            external_writes: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::recording();
        if self != &expected {
            return Err(WorkfrontReviewResultError::ProviderDrift);
        }
        Ok(())
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }
}

/// Typed provider over an explicitly supplied non-native transport.
pub struct WorkfrontProvider<T> {
    transport: T,
    definition: WorkfrontProviderDefinition,
}

impl<T: WorkfrontTransport> fmt::Debug for WorkfrontProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkfrontProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: WorkfrontTransport> WorkfrontProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        let definition = WorkfrontProviderDefinition::recording();
        definition.validate()?;
        if transport.provenance().is_connected()
            || transport.provenance().is_native()
            || transport.provenance().is_first_party()
        {
            return Err(WorkfrontReviewResultError::ProviderDrift);
        }
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &WorkfrontProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn read_project(&mut self, request: &WorkfrontReadRequest) -> Result<ProjectReadResponse> {
        if request.operation != WorkfrontOperation::ReadProject {
            return Err(WorkfrontReviewResultError::InvalidRequest);
        }
        self.transport.read_project(request).map_err(Into::into)
    }

    pub fn read_task(&mut self, request: &WorkfrontReadRequest) -> Result<TaskReadResponse> {
        if request.operation != WorkfrontOperation::ReadTask {
            return Err(WorkfrontReviewResultError::InvalidRequest);
        }
        self.transport.read_task(request).map_err(Into::into)
    }

    pub fn read_review(&mut self, request: &WorkfrontReadRequest) -> Result<ReviewReadResponse> {
        if request.operation != WorkfrontOperation::ReadReview {
            return Err(WorkfrontReviewResultError::InvalidRequest);
        }
        self.transport.read_review(request).map_err(Into::into)
    }

    pub fn read_approval(
        &mut self,
        request: &WorkfrontReadRequest,
    ) -> Result<ApprovalReadResponse> {
        if request.operation != WorkfrontOperation::ReadApproval {
            return Err(WorkfrontReviewResultError::InvalidRequest);
        }
        self.transport.read_approval(request).map_err(Into::into)
    }
}

pub trait WorkfrontTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;
    fn read_project(
        &mut self,
        request: &WorkfrontReadRequest,
    ) -> TransportResult<ProjectReadResponse>;
    fn read_task(&mut self, request: &WorkfrontReadRequest) -> TransportResult<TaskReadResponse>;
    fn read_review(
        &mut self,
        request: &WorkfrontReadRequest,
    ) -> TransportResult<ReviewReadResponse>;
    fn read_approval(
        &mut self,
        request: &WorkfrontReadRequest,
    ) -> TransportResult<ApprovalReadResponse>;
}

#[derive(Debug, Default)]
pub struct RecordingTransport {
    projects: VecDeque<TransportResult<ProjectReadResponse>>,
    tasks: VecDeque<TransportResult<TaskReadResponse>>,
    reviews: VecDeque<TransportResult<ReviewReadResponse>>,
    approvals: VecDeque<TransportResult<ApprovalReadResponse>>,
}

impl RecordingTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_project_response(&mut self, response: TransportResult<ProjectReadResponse>) {
        self.projects.push_back(response);
    }

    pub fn push_task_response(&mut self, response: TransportResult<TaskReadResponse>) {
        self.tasks.push_back(response);
    }

    pub fn push_review_response(&mut self, response: TransportResult<ReviewReadResponse>) {
        self.reviews.push_back(response);
    }

    pub fn push_approval_response(&mut self, response: TransportResult<ApprovalReadResponse>) {
        self.approvals.push_back(response);
    }

    fn pop<T>(queue: &mut VecDeque<TransportResult<T>>) -> TransportResult<T> {
        queue
            .pop_front()
            .unwrap_or(Err(WorkfrontTransportError::Unknown))
    }
}

impl WorkfrontTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn read_project(
        &mut self,
        _request: &WorkfrontReadRequest,
    ) -> TransportResult<ProjectReadResponse> {
        Self::pop(&mut self.projects)
    }

    fn read_task(&mut self, _request: &WorkfrontReadRequest) -> TransportResult<TaskReadResponse> {
        Self::pop(&mut self.tasks)
    }

    fn read_review(
        &mut self,
        _request: &WorkfrontReadRequest,
    ) -> TransportResult<ReviewReadResponse> {
        Self::pop(&mut self.reviews)
    }

    fn read_approval(
        &mut self,
        _request: &WorkfrontReadRequest,
    ) -> TransportResult<ApprovalReadResponse> {
        Self::pop(&mut self.approvals)
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: WorkfrontReviewScope,
    observed_at: DateTime<Utc>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &WorkfrontReviewScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }

    fn validate_scope(&self, request: &WorkfrontReadRequest) -> TransportResult<()> {
        if request.scope_digest != self.scope.digest() {
            return Err(WorkfrontTransportError::InvalidResponse);
        }
        Ok(())
    }
}

impl WorkfrontTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn read_project(
        &mut self,
        request: &WorkfrontReadRequest,
    ) -> TransportResult<ProjectReadResponse> {
        self.validate_scope(request)?;
        let snapshot = ProjectSnapshot::new(
            self.scope.project().clone(),
            crate::model::ProjectStatus::Active,
            self.scope.revision_fences().project.get(),
            self.observed_at,
        )
        .map_err(|_| WorkfrontTransportError::InvalidResponse)?;
        ProjectReadResponse::new(request, snapshot, None, 768, self.provenance())
            .map_err(|_| WorkfrontTransportError::InvalidResponse)
    }

    fn read_task(&mut self, request: &WorkfrontReadRequest) -> TransportResult<TaskReadResponse> {
        self.validate_scope(request)?;
        let snapshot = TaskSnapshot::new(
            self.scope.task().clone(),
            crate::model::TaskStatus::InProgress,
            75,
            self.scope.revision_fences().task.get(),
            self.observed_at,
        )
        .map_err(|_| WorkfrontTransportError::InvalidResponse)?;
        TaskReadResponse::new(request, snapshot, None, 768, self.provenance())
            .map_err(|_| WorkfrontTransportError::InvalidResponse)
    }

    fn read_review(
        &mut self,
        request: &WorkfrontReadRequest,
    ) -> TransportResult<ReviewReadResponse> {
        self.validate_scope(request)?;
        let snapshot = ReviewSnapshot::new(
            self.scope.review().clone(),
            crate::model::ReviewStatus::Approved,
            self.scope.revision_fences().review.get(),
            Some(self.observed_at - chrono::Duration::hours(2)),
            Some(self.observed_at - chrono::Duration::hours(1)),
            ["creative-approver"],
        )
        .map_err(|_| WorkfrontTransportError::InvalidResponse)?;
        ReviewReadResponse::new(request, snapshot, None, 768, self.provenance())
            .map_err(|_| WorkfrontTransportError::InvalidResponse)
    }

    fn read_approval(
        &mut self,
        request: &WorkfrontReadRequest,
    ) -> TransportResult<ApprovalReadResponse> {
        self.validate_scope(request)?;
        let snapshot = ApprovalSnapshot::new(
            self.scope.approval().clone(),
            crate::model::ApprovalStatus::Approved,
            self.scope.revision_fences().approval.get(),
            Some(self.observed_at - chrono::Duration::minutes(30)),
            ["approver"],
        )
        .map_err(|_| WorkfrontTransportError::InvalidResponse)?;
        ApprovalReadResponse::new(request, snapshot, None, 768, self.provenance())
            .map_err(|_| WorkfrontTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    fixture: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &WorkfrontReviewScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            fixture: FixtureTransport::for_scope(scope, observed_at),
        }
    }
}

impl WorkfrontTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn read_project(
        &mut self,
        request: &WorkfrontReadRequest,
    ) -> TransportResult<ProjectReadResponse> {
        let mut response = self.fixture.read_project(request)?;
        response.provenance = self.provenance();
        Ok(response)
    }

    fn read_task(&mut self, request: &WorkfrontReadRequest) -> TransportResult<TaskReadResponse> {
        let mut response = self.fixture.read_task(request)?;
        response.provenance = self.provenance();
        Ok(response)
    }

    fn read_review(
        &mut self,
        request: &WorkfrontReadRequest,
    ) -> TransportResult<ReviewReadResponse> {
        let mut response = self.fixture.read_review(request)?;
        response.provenance = self.provenance();
        Ok(response)
    }

    fn read_approval(
        &mut self,
        request: &WorkfrontReadRequest,
    ) -> TransportResult<ApprovalReadResponse> {
        let mut response = self.fixture.read_approval(request)?;
        response.provenance = self.provenance();
        Ok(response)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl WorkfrontTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read_project(
        &mut self,
        _request: &WorkfrontReadRequest,
    ) -> TransportResult<ProjectReadResponse> {
        Err(WorkfrontTransportError::BlockedEnv)
    }

    fn read_task(&mut self, _request: &WorkfrontReadRequest) -> TransportResult<TaskReadResponse> {
        Err(WorkfrontTransportError::BlockedEnv)
    }

    fn read_review(
        &mut self,
        _request: &WorkfrontReadRequest,
    ) -> TransportResult<ReviewReadResponse> {
        Err(WorkfrontTransportError::BlockedEnv)
    }

    fn read_approval(
        &mut self,
        _request: &WorkfrontReadRequest,
    ) -> TransportResult<ApprovalReadResponse> {
        Err(WorkfrontTransportError::BlockedEnv)
    }
}
