use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    WORKATO_RECIPE_RESULT_PROVIDER_ID, WORKATO_RECIPE_RESULT_SCHEMA_VERSION,
    model::{
        FolderId, JobHandle, JobIdentity, JobProjection, JobStatus, MAX_CURSOR_BYTES,
        MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES, MAX_RETRY_ATTEMPTS, MAX_STEPS, ModelError,
        ProviderId, READ_RATE_PER_MINUTE, RecipeId, RecipeVersionBinding, RecipeVersionId,
        RetentionState, RetryIdentity, Revision, SecretReference, StepId, StepProjection,
        StepStatus, WorkatoOperation, WorkatoProjectId, WorkatoScope, WorkspaceId, digest_optional,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty")]
    EmptyVersion,
    #[error("Layer 1 cannot register a native provider")]
    NativeProviderForbidden,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkatoProviderDefinition {
    pub schema_version: String,
    pub provider_id: ProviderId,
    pub provider_version: String,
    pub capability_digest: crate::Digest,
    pub provenance: ProviderProvenance,
    pub operations: Vec<WorkatoOperation>,
    pub read_rate_per_minute: u16,
    pub max_retry_attempts: u8,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub external_writes: bool,
}

impl WorkatoProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.trim().is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        if provenance.is_native() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let provider_id = ProviderId::new(WORKATO_RECIPE_RESULT_PROVIDER_ID)?;
        let operations = vec![
            WorkatoOperation::GetRecipe,
            WorkatoOperation::ListRecipeVersions,
            WorkatoOperation::GetRecipeVersion,
            WorkatoOperation::ListJobs,
            WorkatoOperation::GetJob,
        ];
        let capability_digest = crate::Digest::from_fields(
            "workato-provider-capability/v1",
            &[
                WORKATO_RECIPE_RESULT_SCHEMA_VERSION.to_owned(),
                WORKATO_RECIPE_RESULT_PROVIDER_ID.to_owned(),
                provider_version.clone(),
                format!("{provenance:?}"),
                format!("{operations:?}"),
                READ_RATE_PER_MINUTE.to_string(),
                MAX_RETRY_ATTEMPTS.to_string(),
                "native=false".to_owned(),
                "connected=false".to_owned(),
                "external_writes=false".to_owned(),
            ],
        );
        Ok(Self {
            schema_version: WORKATO_RECIPE_RESULT_SCHEMA_VERSION.to_owned(),
            provider_id,
            provider_version,
            capability_digest,
            provenance,
            operations,
            read_rate_per_minute: READ_RATE_PER_MINUTE,
            max_retry_attempts: MAX_RETRY_ATTEMPTS,
            native: false,
            connected: false,
            first_party: false,
            external_writes: false,
        })
    }

    pub fn provider_digest(&self) -> crate::Digest {
        crate::Digest::from_fields(
            "workato-provider-definition/v1",
            &[
                self.schema_version.clone(),
                self.provider_id.as_str().to_owned(),
                self.provider_version.clone(),
                self.capability_digest.as_str().to_owned(),
                format!("{:?}", self.provenance),
                format!("{:?}", self.operations),
                self.read_rate_per_minute.to_string(),
                self.max_retry_attempts.to_string(),
                self.native.to_string(),
                self.connected.to_string(),
                self.first_party.to_string(),
                self.external_writes.to_string(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    RateLimited,
    RateBudgetExceeded,
    Unauthorized,
    Forbidden,
    NotFound,
    Timeout,
    ServerFailure,
    MalformedResponse,
    RetentionGap,
    BlockedEnv,
    Conflict,
    Unknown,
    SecretRevoked,
    SecretScopeMismatch,
    PermissionMismatch,
    ScopeMismatch,
    RecipeMismatch,
    RecipeVersionMismatch,
    JobMismatch,
    RetryMismatch,
    AmbiguousRerun,
    StepMismatch,
    PageBoundExceeded,
    CursorBoundExceeded,
    ResponseTooLarge,
}

impl ProviderErrorKind {
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::RateLimited | Self::Timeout | Self::ServerFailure
        )
    }

    pub const fn is_transport(self) -> bool {
        matches!(
            self,
            Self::RateLimited
                | Self::RateBudgetExceeded
                | Self::Unauthorized
                | Self::Forbidden
                | Self::NotFound
                | Self::Timeout
                | Self::ServerFailure
                | Self::MalformedResponse
                | Self::RetentionGap
                | Self::BlockedEnv
                | Self::Conflict
                | Self::Unknown
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("Workato transport error: {kind:?}")]
pub struct TransportError {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
    pub diagnostic_digest: crate::Digest,
}

impl TransportError {
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            kind,
            status_code,
            retry_after_seconds: None,
            diagnostic_digest: crate::Digest::from_bytes(diagnostic.as_ref()),
        }
    }

    pub fn with_retry_after(mut self, seconds: u64) -> Self {
        self.retry_after_seconds = Some(seconds);
        self
    }

    pub fn rate_limited() -> Self {
        Self::new(ProviderErrorKind::RateLimited, Some(429), "rate-limited")
    }

    pub fn timeout() -> Self {
        Self::new(ProviderErrorKind::Timeout, None, "timeout")
    }

    pub fn server_failure() -> Self {
        Self::new(
            ProviderErrorKind::ServerFailure,
            Some(500),
            "server-failure",
        )
    }

    pub fn unauthorized() -> Self {
        Self::new(ProviderErrorKind::Unauthorized, Some(401), "unauthorized")
    }

    pub fn forbidden() -> Self {
        Self::new(ProviderErrorKind::Forbidden, Some(403), "forbidden")
    }

    pub fn not_found() -> Self {
        Self::new(ProviderErrorKind::NotFound, Some(404), "not-found")
    }

    pub fn retention_gap() -> Self {
        Self::new(ProviderErrorKind::RetentionGap, Some(404), "retention-gap")
    }

    pub fn blocked_env() -> Self {
        Self::new(ProviderErrorKind::BlockedEnv, None, "BLOCKED_ENV")
    }

    pub const fn retryable(&self) -> bool {
        self.kind.retryable()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub blocked_env: bool,
    pub diagnostic_digest: crate::Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RetryAttempt {
    pub operation: WorkatoOperation,
    pub attempt: u8,
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub error_digest: crate::Digest,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("Workato provider error: {evidence:?}")]
pub struct ProviderError {
    pub evidence: ProviderErrorEvidence,
    pub receipts: Vec<WorkatoReadReceipt>,
    pub retries: Vec<RetryAttempt>,
}

impl ProviderError {
    fn validation(kind: ProviderErrorKind, diagnostic: impl AsRef<[u8]>) -> Self {
        let diagnostic_digest = crate::Digest::from_bytes(diagnostic.as_ref());
        Self {
            evidence: ProviderErrorEvidence {
                kind,
                status_code: None,
                retryable: kind.retryable(),
                blocked_env: kind == ProviderErrorKind::BlockedEnv,
                diagnostic_digest,
            },
            receipts: Vec::new(),
            retries: Vec::new(),
        }
    }

    pub const fn kind(&self) -> ProviderErrorKind {
        self.evidence.kind
    }

    pub fn evidence(&self) -> &ProviderErrorEvidence {
        &self.evidence
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkatoReadReceipt {
    pub operation: WorkatoOperation,
    pub method: String,
    pub path_digest: crate::Digest,
    pub request_digest: crate::Digest,
    pub response_status: Option<u16>,
    pub response_bytes: usize,
    pub response_digest: crate::Digest,
    pub attempt: u8,
    pub redacted_request: bool,
    pub redacted_result: bool,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRead<T> {
    pub value: T,
    pub receipts: Vec<WorkatoReadReceipt>,
    pub retries: Vec<RetryAttempt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipeVersionPageRequest {
    pub page: u32,
    pub per_page: u32,
}

impl RecipeVersionPageRequest {
    pub fn new(page: u32, per_page: u32) -> Result<Self, ModelError> {
        if page == 0 || page > MAX_PAGES || !(1..=MAX_PAGE_SIZE).contains(&per_page) {
            Err(ModelError::InvalidBounds)
        } else {
            Ok(Self { page, per_page })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatusFilter {
    Succeeded,
    Failed,
    Pending,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobPageRequest {
    pub page: u32,
    pub per_page: u32,
    pub offset_job_id: Option<JobHandle>,
    pub prev: bool,
    pub status: Option<JobStatusFilter>,
}

impl JobPageRequest {
    pub fn new(
        page: u32,
        per_page: u32,
        offset_job_id: Option<JobHandle>,
        prev: bool,
        status: Option<JobStatusFilter>,
    ) -> Result<Self, ModelError> {
        if page == 0 || page > MAX_PAGES || !(1..=MAX_PAGE_SIZE).contains(&per_page) {
            return Err(ModelError::InvalidBounds);
        }
        if offset_job_id
            .as_ref()
            .is_some_and(|value| value.as_str().len() > MAX_CURSOR_BYTES)
        {
            return Err(ModelError::InvalidCursor);
        }
        Ok(Self {
            page,
            per_page,
            offset_job_id,
            prev,
            status,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkatoReadRequest {
    GetRecipe {
        scope_digest: crate::Digest,
        workspace: WorkspaceId,
        project: WorkatoProjectId,
        folder: FolderId,
        recipe: RecipeId,
    },
    ListRecipeVersions {
        scope_digest: crate::Digest,
        workspace: WorkspaceId,
        project: WorkatoProjectId,
        folder: FolderId,
        recipe: RecipeId,
        page: u32,
        per_page: u32,
    },
    GetRecipeVersion {
        scope_digest: crate::Digest,
        workspace: WorkspaceId,
        project: WorkatoProjectId,
        folder: FolderId,
        recipe: RecipeId,
        version: RecipeVersionId,
    },
    ListJobs {
        scope_digest: crate::Digest,
        workspace: WorkspaceId,
        project: WorkatoProjectId,
        folder: FolderId,
        recipe: RecipeId,
        page: u32,
        per_page: u32,
        offset_job_id: Option<JobHandle>,
        prev: bool,
        status: Option<JobStatusFilter>,
    },
    GetJob {
        scope_digest: crate::Digest,
        workspace: WorkspaceId,
        project: WorkatoProjectId,
        folder: FolderId,
        recipe: RecipeId,
        job: JobHandle,
    },
}

impl WorkatoReadRequest {
    fn get_recipe(scope: &WorkatoScope) -> Self {
        Self::GetRecipe {
            scope_digest: scope.scope_digest(),
            workspace: scope.workspace().clone(),
            project: scope.project().clone(),
            folder: scope.folder().clone(),
            recipe: scope.recipe().clone(),
        }
    }

    fn list_recipe_versions(scope: &WorkatoScope, page: &RecipeVersionPageRequest) -> Self {
        Self::ListRecipeVersions {
            scope_digest: scope.scope_digest(),
            workspace: scope.workspace().clone(),
            project: scope.project().clone(),
            folder: scope.folder().clone(),
            recipe: scope.recipe().clone(),
            page: page.page,
            per_page: page.per_page,
        }
    }

    fn get_recipe_version(scope: &WorkatoScope) -> Self {
        Self::GetRecipeVersion {
            scope_digest: scope.scope_digest(),
            workspace: scope.workspace().clone(),
            project: scope.project().clone(),
            folder: scope.folder().clone(),
            recipe: scope.recipe().clone(),
            version: scope.recipe_version().version_id().clone(),
        }
    }

    fn list_jobs(scope: &WorkatoScope, page: &JobPageRequest) -> Self {
        Self::ListJobs {
            scope_digest: scope.scope_digest(),
            workspace: scope.workspace().clone(),
            project: scope.project().clone(),
            folder: scope.folder().clone(),
            recipe: scope.recipe().clone(),
            page: page.page,
            per_page: page.per_page,
            offset_job_id: page.offset_job_id.clone(),
            prev: page.prev,
            status: page.status,
        }
    }

    fn get_job(scope: &WorkatoScope) -> Self {
        Self::GetJob {
            scope_digest: scope.scope_digest(),
            workspace: scope.workspace().clone(),
            project: scope.project().clone(),
            folder: scope.folder().clone(),
            recipe: scope.recipe().clone(),
            job: scope.job().job_handle().clone(),
        }
    }

    pub const fn operation(&self) -> WorkatoOperation {
        match self {
            Self::GetRecipe { .. } => WorkatoOperation::GetRecipe,
            Self::ListRecipeVersions { .. } => WorkatoOperation::ListRecipeVersions,
            Self::GetRecipeVersion { .. } => WorkatoOperation::GetRecipeVersion,
            Self::ListJobs { .. } => WorkatoOperation::ListJobs,
            Self::GetJob { .. } => WorkatoOperation::GetJob,
        }
    }

    pub const fn method(&self) -> &'static str {
        "GET"
    }

    pub const fn path_template(&self) -> &'static str {
        match self {
            Self::GetRecipe { .. } => "/api/recipes/:recipe_id",
            Self::ListRecipeVersions { .. } => "/api/recipes/:recipe_id/versions",
            Self::GetRecipeVersion { .. } => "/api/recipes/:recipe_id/versions/:id",
            Self::ListJobs { .. } => "/api/recipes/:recipe_id/jobs",
            Self::GetJob { .. } => "/api/recipes/:recipe_id/jobs/:job_handle",
        }
    }

    fn scope_digest(&self) -> &crate::Digest {
        match self {
            Self::GetRecipe { scope_digest, .. }
            | Self::ListRecipeVersions { scope_digest, .. }
            | Self::GetRecipeVersion { scope_digest, .. }
            | Self::ListJobs { scope_digest, .. }
            | Self::GetJob { scope_digest, .. } => scope_digest,
        }
    }

    fn request_digest(&self) -> crate::Digest {
        crate::Digest::from_fields(
            "workato-read-request/v1",
            &[
                format!("{:?}", self.operation()),
                self.path_template().to_owned(),
                self.scope_digest().as_str().to_owned(),
                format!("{self:?}"),
            ],
        )
    }

    fn validate(&self) -> Result<(), ProviderError> {
        match self {
            Self::ListRecipeVersions { page, per_page, .. }
            | Self::ListJobs { page, per_page, .. }
                if *page == 0 || *page > MAX_PAGES || !(1..=MAX_PAGE_SIZE).contains(per_page) =>
            {
                Err(ProviderError::validation(
                    ProviderErrorKind::PageBoundExceeded,
                    "page-bound",
                ))
            }
            Self::ListJobs {
                offset_job_id: Some(offset),
                ..
            } if offset.as_str().len() > MAX_CURSOR_BYTES => Err(ProviderError::validation(
                ProviderErrorKind::CursorBoundExceeded,
                "cursor-bound",
            )),
            _ => Ok(()),
        }
    }
}

pub struct RawRecipe {
    pub workspace_id: String,
    pub project_id: String,
    pub folder_id: String,
    pub recipe_id: String,
    pub name: String,
    pub status: String,
    pub revision: u64,
    pub provider_revision: u64,
}

impl fmt::Debug for RawRecipe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawRecipe")
            .field("workspace_id", &self.workspace_id)
            .field("project_id", &self.project_id)
            .field("folder_id", &self.folder_id)
            .field("recipe_id", &self.recipe_id)
            .field("name", &"<redacted>")
            .field("status", &self.status)
            .field("revision", &self.revision)
            .field("provider_revision", &self.provider_revision)
            .finish()
    }
}

pub struct RawRecipeVersion {
    pub recipe_id: String,
    pub version_id: String,
    pub version_number: u64,
    pub revision: u64,
    pub comment: String,
    pub author: String,
    pub created_at: String,
    pub updated_at: String,
    pub provider_revision: u64,
}

impl fmt::Debug for RawRecipeVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawRecipeVersion")
            .field("recipe_id", &self.recipe_id)
            .field("version_id", &self.version_id)
            .field("version_number", &self.version_number)
            .field("revision", &self.revision)
            .field("comment", &"<redacted>")
            .field("author", &"<redacted>")
            .field("created_at", &"<redacted>")
            .field("updated_at", &"<redacted>")
            .field("provider_revision", &self.provider_revision)
            .finish()
    }
}

pub struct RawStep {
    pub step_id: String,
    pub ordinal: u32,
    pub kind: String,
    pub status: String,
    pub error: Option<String>,
    pub duration_ms: Option<u64>,
    pub retry_number: u32,
    pub input_payload: Option<String>,
    pub output_payload: Option<String>,
    pub runtime_datapills: Vec<String>,
}

impl fmt::Debug for RawStep {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawStep")
            .field("step_id", &self.step_id)
            .field("ordinal", &self.ordinal)
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("error", &self.error.as_ref().map(|_| "<redacted>"))
            .field("duration_ms", &self.duration_ms)
            .field("retry_number", &self.retry_number)
            .field("input_payload", &"<redacted>")
            .field("output_payload", &"<redacted>")
            .field("runtime_datapills", &"<redacted>")
            .finish()
    }
}

pub struct RawJob {
    pub workspace_id: String,
    pub project_id: String,
    pub folder_id: String,
    pub recipe_id: String,
    pub job_handle: String,
    pub recipe_version_id: String,
    pub recipe_version_number: u64,
    pub status: String,
    pub retry_number: u32,
    pub root_job_handle: String,
    pub parent_job_handle: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub tasks_used: Option<u64>,
    pub steps: Vec<RawStep>,
    pub retention_gap: bool,
    pub provider_revision: u64,
}

impl fmt::Debug for RawJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawJob")
            .field("workspace_id", &self.workspace_id)
            .field("project_id", &self.project_id)
            .field("folder_id", &self.folder_id)
            .field("recipe_id", &self.recipe_id)
            .field("job_handle", &self.job_handle)
            .field("recipe_version_id", &self.recipe_version_id)
            .field("recipe_version_number", &self.recipe_version_number)
            .field("status", &self.status)
            .field("retry_number", &self.retry_number)
            .field("root_job_handle", &self.root_job_handle)
            .field("parent_job_handle", &self.parent_job_handle)
            .field(
                "started_at",
                &self.started_at.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "completed_at",
                &self.completed_at.as_ref().map(|_| "<redacted>"),
            )
            .field("duration_ms", &self.duration_ms)
            .field("tasks_used", &self.tasks_used)
            .field("step_count", &self.steps.len())
            .field("retention_gap", &self.retention_gap)
            .field("provider_revision", &self.provider_revision)
            .finish()
    }
}

pub enum WorkatoResponseBody {
    Recipe(RawRecipe),
    RecipeVersions(Vec<RawRecipeVersion>),
    RecipeVersion(RawRecipeVersion),
    Jobs(Vec<RawJob>),
    Job(RawJob),
}

impl fmt::Debug for WorkatoResponseBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Recipe(_) => "Recipe",
            Self::RecipeVersions(items) => {
                return formatter
                    .debug_struct("RecipeVersions")
                    .field("count", &items.len())
                    .finish();
            }
            Self::RecipeVersion(_) => "RecipeVersion",
            Self::Jobs(items) => {
                return formatter
                    .debug_struct("Jobs")
                    .field("count", &items.len())
                    .finish();
            }
            Self::Job(_) => "Job",
        };
        formatter.write_str(label)
    }
}

pub struct WorkatoResponse {
    pub status_code: u16,
    pub response_bytes: usize,
    pub response_digest: crate::Digest,
    pub body: WorkatoResponseBody,
}

impl fmt::Debug for WorkatoResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkatoResponse")
            .field("status_code", &self.status_code)
            .field("response_bytes", &self.response_bytes)
            .field("response_digest", &self.response_digest)
            .field("body", &self.body)
            .finish()
    }
}

pub trait WorkatoTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;
    fn get(&mut self, request: WorkatoReadRequest) -> Result<WorkatoResponse, TransportError>;
}

struct QueuedTransport {
    provenance: ProviderProvenance,
    queue: VecDeque<Result<WorkatoResponse, TransportError>>,
    requests: Vec<WorkatoReadRequest>,
}

impl QueuedTransport {
    fn new(
        provenance: ProviderProvenance,
        responses: impl IntoIterator<Item = Result<WorkatoResponse, TransportError>>,
    ) -> Self {
        Self {
            provenance,
            queue: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    fn get(&mut self, request: WorkatoReadRequest) -> Result<WorkatoResponse, TransportError> {
        self.requests.push(request);
        self.queue.pop_front().unwrap_or_else(|| {
            Err(TransportError::new(
                ProviderErrorKind::Unknown,
                None,
                "fixture exhausted",
            ))
        })
    }

    fn requests(&self) -> &[WorkatoReadRequest] {
        &self.requests
    }
}

macro_rules! queued_transport {
    ($name:ident, $provenance:expr) => {
        pub struct $name {
            inner: QueuedTransport,
        }

        impl $name {
            pub fn new(
                responses: impl IntoIterator<Item = Result<WorkatoResponse, TransportError>>,
            ) -> Self {
                Self {
                    inner: QueuedTransport::new($provenance, responses),
                }
            }

            pub fn from_responses(responses: impl IntoIterator<Item = WorkatoResponse>) -> Self {
                Self::new(responses.into_iter().map(Ok))
            }

            pub fn recorded_requests(&self) -> &[WorkatoReadRequest] {
                self.inner.requests()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("provenance", &self.inner.provenance)
                    .field("queued_responses", &self.inner.queue.len())
                    .field("request_count", &self.inner.requests.len())
                    .finish()
            }
        }

        impl WorkatoTransport for $name {
            fn provenance(&self) -> ProviderProvenance {
                self.inner.provenance
            }

            fn get(
                &mut self,
                request: WorkatoReadRequest,
            ) -> Result<WorkatoResponse, TransportError> {
                self.inner.get(request)
            }
        }
    };
}

queued_transport!(FixtureTransport, ProviderProvenance::Fixture);
queued_transport!(RecordingTransport, ProviderProvenance::Recording);
queued_transport!(LoopbackTransport, ProviderProvenance::Loopback);

pub type FixtureWorkatoTransport = FixtureTransport;
pub type RecordingWorkatoTransport = RecordingTransport;
pub type LoopbackWorkatoTransport = LoopbackTransport;

pub struct BlockedEnvTransport {
    requests: Vec<WorkatoReadRequest>,
}

impl BlockedEnvTransport {
    pub fn new() -> Self {
        Self {
            requests: Vec::new(),
        }
    }

    pub fn recorded_requests(&self) -> &[WorkatoReadRequest] {
        &self.requests
    }
}

impl Default for BlockedEnvTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for BlockedEnvTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlockedEnvTransport")
            .field("request_count", &self.requests.len())
            .finish()
    }
}

impl WorkatoTransport for BlockedEnvTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn get(&mut self, request: WorkatoReadRequest) -> Result<WorkatoResponse, TransportError> {
        self.requests.push(request);
        Err(TransportError::blocked_env())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    max_attempts: u8,
}

impl RetryPolicy {
    pub fn new(max_attempts: u8) -> Result<Self, ModelError> {
        if !(1..=MAX_RETRY_ATTEMPTS).contains(&max_attempts) {
            Err(ModelError::InvalidBounds)
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
        Self {
            max_attempts: MAX_RETRY_ATTEMPTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReadBudget {
    limit: u16,
    used: u16,
}

impl ReadBudget {
    const fn new(limit: u16) -> Self {
        Self { limit, used: 0 }
    }

    fn charge(&mut self) -> bool {
        if self.used >= self.limit {
            false
        } else {
            self.used += 1;
            true
        }
    }

    fn reset(&mut self) {
        self.used = 0;
    }
}

struct FetchedResponse {
    response: WorkatoResponse,
    receipts: Vec<WorkatoReadReceipt>,
    retries: Vec<RetryAttempt>,
}

pub struct WorkatoProvider<T> {
    definition: WorkatoProviderDefinition,
    transport: T,
    retry_policy: RetryPolicy,
    read_budget: ReadBudget,
}

impl<T: WorkatoTransport> fmt::Debug for WorkatoProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkatoProvider")
            .field("definition", &self.definition)
            .field("transport", &self.transport)
            .field("retry_policy", &self.retry_policy)
            .field("read_budget", &self.read_budget)
            .finish()
    }
}

impl<T: WorkatoTransport> WorkatoProvider<T> {
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
    ) -> Result<Self, ProviderDefinitionError> {
        let provenance = transport.provenance();
        Ok(Self {
            definition: WorkatoProviderDefinition::new(provider_version, provenance)?,
            transport,
            retry_policy: RetryPolicy::default(),
            read_budget: ReadBudget::new(READ_RATE_PER_MINUTE),
        })
    }

    pub fn with_retry_policy(
        transport: T,
        provider_version: impl Into<String>,
        retry_policy: RetryPolicy,
    ) -> Result<Self, ProviderDefinitionError> {
        let mut provider = Self::new(transport, provider_version)?;
        provider.retry_policy = retry_policy;
        Ok(provider)
    }

    pub fn definition(&self) -> &WorkatoProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.definition.provenance
    }

    pub fn provider_digest(&self) -> crate::Digest {
        self.definition.provider_digest()
    }

    pub fn capability_digest(&self) -> &crate::Digest {
        &self.definition.capability_digest
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn reset_read_budget(&mut self) {
        self.read_budget.reset();
    }

    pub fn read_recipe(
        &mut self,
        scope: &WorkatoScope,
        secret: &SecretReference,
    ) -> Result<ProviderRead<crate::RecipeProjection>, ProviderError> {
        Self::ensure_scope(scope, secret, WorkatoOperation::GetRecipe)?;
        let fetched = self.fetch(WorkatoReadRequest::get_recipe(scope))?;
        let raw = match fetched.response.body {
            WorkatoResponseBody::Recipe(raw) => raw,
            _ => {
                return Err(ProviderError::validation(
                    ProviderErrorKind::MalformedResponse,
                    "recipe-shape",
                ));
            }
        };
        let value = Self::normalize_recipe(scope, raw)?;
        Ok(ProviderRead {
            value,
            receipts: fetched.receipts,
            retries: fetched.retries,
        })
    }

    pub fn read_recipe_versions(
        &mut self,
        scope: &WorkatoScope,
        secret: &SecretReference,
        page: RecipeVersionPageRequest,
    ) -> Result<ProviderRead<Vec<crate::RecipeVersionProjection>>, ProviderError> {
        Self::ensure_scope(scope, secret, WorkatoOperation::ListRecipeVersions)?;
        let request = WorkatoReadRequest::list_recipe_versions(scope, &page);
        let fetched = self.fetch(request)?;
        let raw_versions = match fetched.response.body {
            WorkatoResponseBody::RecipeVersions(raw_versions) => raw_versions,
            _ => {
                return Err(ProviderError::validation(
                    ProviderErrorKind::MalformedResponse,
                    "recipe-version-list-shape",
                ));
            }
        };
        if raw_versions.len() > page.per_page as usize {
            return Err(ProviderError::validation(
                ProviderErrorKind::PageBoundExceeded,
                "recipe-version-list-size",
            ));
        }
        let mut values = Vec::with_capacity(raw_versions.len());
        for raw in raw_versions {
            values.push(Self::normalize_recipe_version(scope, raw)?);
        }
        Ok(ProviderRead {
            value: values,
            receipts: fetched.receipts,
            retries: fetched.retries,
        })
    }

    pub fn read_recipe_version(
        &mut self,
        scope: &WorkatoScope,
        secret: &SecretReference,
    ) -> Result<ProviderRead<crate::RecipeVersionProjection>, ProviderError> {
        Self::ensure_scope(scope, secret, WorkatoOperation::GetRecipeVersion)?;
        let fetched = self.fetch(WorkatoReadRequest::get_recipe_version(scope))?;
        let raw = match fetched.response.body {
            WorkatoResponseBody::RecipeVersion(raw) => raw,
            _ => {
                return Err(ProviderError::validation(
                    ProviderErrorKind::MalformedResponse,
                    "recipe-version-shape",
                ));
            }
        };
        let value = Self::normalize_recipe_version(scope, raw)?;
        Ok(ProviderRead {
            value,
            receipts: fetched.receipts,
            retries: fetched.retries,
        })
    }

    pub fn list_jobs(
        &mut self,
        scope: &WorkatoScope,
        secret: &SecretReference,
        page: JobPageRequest,
    ) -> Result<ProviderRead<JobPageProjection>, ProviderError> {
        Self::ensure_scope(scope, secret, WorkatoOperation::ListJobs)?;
        let request = WorkatoReadRequest::list_jobs(scope, &page);
        let fetched = self.fetch(request)?;
        let raw_jobs = match fetched.response.body {
            WorkatoResponseBody::Jobs(raw_jobs) => raw_jobs,
            _ => {
                return Err(ProviderError::validation(
                    ProviderErrorKind::MalformedResponse,
                    "job-list-shape",
                ));
            }
        };
        if raw_jobs.len() > page.per_page as usize {
            return Err(ProviderError::validation(
                ProviderErrorKind::PageBoundExceeded,
                "job-list-size",
            ));
        }
        let mut items = Vec::with_capacity(raw_jobs.len());
        for raw in raw_jobs {
            items.push(Self::normalize_job_summary(scope, raw)?);
        }
        Ok(ProviderRead {
            value: JobPageProjection {
                page: page.page,
                per_page: page.per_page,
                items,
            },
            receipts: fetched.receipts,
            retries: fetched.retries,
        })
    }

    pub fn read_job(
        &mut self,
        scope: &WorkatoScope,
        secret: &SecretReference,
    ) -> Result<ProviderRead<JobProjection>, ProviderError> {
        Self::ensure_scope(scope, secret, WorkatoOperation::GetJob)?;
        let fetched = self.fetch(WorkatoReadRequest::get_job(scope))?;
        let raw = match fetched.response.body {
            WorkatoResponseBody::Job(raw) => raw,
            _ => {
                return Err(ProviderError::validation(
                    ProviderErrorKind::MalformedResponse,
                    "job-shape",
                ));
            }
        };
        let (value, _) = Self::normalize_job(scope, raw)?;
        Ok(ProviderRead {
            value,
            receipts: fetched.receipts,
            retries: fetched.retries,
        })
    }

    fn ensure_scope(
        scope: &WorkatoScope,
        secret: &SecretReference,
        operation: WorkatoOperation,
    ) -> Result<(), ProviderError> {
        if secret.is_revoked() {
            return Err(ProviderError::validation(
                ProviderErrorKind::SecretRevoked,
                "secret-revoked",
            ));
        }
        if secret.scope_digest() != &scope.scope_digest() {
            return Err(ProviderError::validation(
                ProviderErrorKind::SecretScopeMismatch,
                "secret-scope",
            ));
        }
        if !scope.permission().allows(operation) {
            return Err(ProviderError::validation(
                ProviderErrorKind::PermissionMismatch,
                "permission",
            ));
        }
        Ok(())
    }

    fn fetch(&mut self, request: WorkatoReadRequest) -> Result<FetchedResponse, ProviderError> {
        request.validate()?;
        let operation = request.operation();
        let request_digest = request.request_digest();
        let path_digest = crate::Digest::from_text(request.path_template());
        let mut receipts = Vec::new();
        let mut retries = Vec::new();
        for attempt in 1..=self.retry_policy.max_attempts {
            if !self.read_budget.charge() {
                return Err(ProviderError {
                    evidence: ProviderErrorEvidence {
                        kind: ProviderErrorKind::RateBudgetExceeded,
                        status_code: Some(429),
                        retryable: false,
                        blocked_env: false,
                        diagnostic_digest: crate::Digest::from_text("read-budget-exceeded"),
                    },
                    receipts,
                    retries,
                });
            }
            match self.transport.get(request.clone()) {
                Ok(response) => {
                    let receipt = WorkatoReadReceipt {
                        operation,
                        method: request.method().to_owned(),
                        path_digest: path_digest.clone(),
                        request_digest: request_digest.clone(),
                        response_status: Some(response.status_code),
                        response_bytes: response.response_bytes,
                        response_digest: response.response_digest.clone(),
                        attempt,
                        redacted_request: true,
                        redacted_result: true,
                        provenance: self.provenance(),
                        connected: false,
                        native: false,
                        first_party: false,
                    };
                    receipts.push(receipt);
                    if !(200..300).contains(&response.status_code) {
                        let kind = match response.status_code {
                            401 => ProviderErrorKind::Unauthorized,
                            403 => ProviderErrorKind::Forbidden,
                            404 => ProviderErrorKind::NotFound,
                            409 => ProviderErrorKind::Conflict,
                            429 => ProviderErrorKind::RateLimited,
                            status if status >= 500 => ProviderErrorKind::ServerFailure,
                            _ => ProviderErrorKind::Unknown,
                        };
                        return Err(ProviderError {
                            evidence: ProviderErrorEvidence {
                                kind,
                                status_code: Some(response.status_code),
                                retryable: kind.retryable(),
                                blocked_env: false,
                                diagnostic_digest: response.response_digest,
                            },
                            receipts,
                            retries,
                        });
                    }
                    if response.response_bytes > MAX_RESPONSE_BYTES {
                        return Err(ProviderError {
                            evidence: ProviderErrorEvidence {
                                kind: ProviderErrorKind::ResponseTooLarge,
                                status_code: Some(response.status_code),
                                retryable: false,
                                blocked_env: false,
                                diagnostic_digest: response.response_digest,
                            },
                            receipts,
                            retries,
                        });
                    }
                    return Ok(FetchedResponse {
                        response,
                        receipts,
                        retries,
                    });
                }
                Err(error) => {
                    receipts.push(WorkatoReadReceipt {
                        operation,
                        method: request.method().to_owned(),
                        path_digest: path_digest.clone(),
                        request_digest: request_digest.clone(),
                        response_status: error.status_code,
                        response_bytes: 0,
                        response_digest: error.diagnostic_digest.clone(),
                        attempt,
                        redacted_request: true,
                        redacted_result: true,
                        provenance: self.provenance(),
                        connected: false,
                        native: false,
                        first_party: false,
                    });
                    if error.retryable() && attempt < self.retry_policy.max_attempts {
                        retries.push(RetryAttempt {
                            operation,
                            attempt,
                            kind: error.kind,
                            status_code: error.status_code,
                            error_digest: error.diagnostic_digest,
                        });
                        continue;
                    }
                    return Err(ProviderError {
                        evidence: ProviderErrorEvidence {
                            kind: error.kind,
                            status_code: error.status_code,
                            retryable: error.retryable(),
                            blocked_env: error.kind == ProviderErrorKind::BlockedEnv,
                            diagnostic_digest: error.diagnostic_digest,
                        },
                        receipts,
                        retries,
                    });
                }
            }
        }
        Err(ProviderError::validation(
            ProviderErrorKind::Unknown,
            "retry-exhausted",
        ))
    }

    fn normalize_recipe(
        scope: &WorkatoScope,
        raw: RawRecipe,
    ) -> Result<crate::RecipeProjection, ProviderError> {
        if raw.workspace_id != scope.workspace().as_str()
            || raw.project_id != scope.project().as_str()
            || raw.folder_id != scope.folder().as_str()
            || raw.recipe_id != scope.recipe().as_str()
        {
            return Err(ProviderError::validation(
                ProviderErrorKind::ScopeMismatch,
                "recipe-scope",
            ));
        }
        let recipe_revision = Revision::new(raw.revision).map_err(|_| {
            ProviderError::validation(ProviderErrorKind::MalformedResponse, "recipe-revision")
        })?;
        let provider_revision = Revision::new(raw.provider_revision).map_err(|_| {
            ProviderError::validation(ProviderErrorKind::MalformedResponse, "provider-revision")
        })?;
        let recipe_id = RecipeId::new(raw.recipe_id).map_err(|_| {
            ProviderError::validation(ProviderErrorKind::MalformedResponse, "recipe-id")
        })?;
        let workspace_digest = crate::Digest::from_text(raw.workspace_id);
        let project_digest = crate::Digest::from_text(raw.project_id);
        let folder_digest = crate::Digest::from_text(raw.folder_id);
        let name_digest = crate::Digest::from_text(raw.name);
        let status_digest = crate::Digest::from_text(raw.status);
        let provider_revision_digest =
            crate::Digest::from_text(provider_revision.get().to_string());
        let projection_digest = crate::Digest::from_fields(
            "workato-recipe-projection/v1",
            &[
                recipe_id.as_str().to_owned(),
                workspace_digest.as_str().to_owned(),
                project_digest.as_str().to_owned(),
                folder_digest.as_str().to_owned(),
                recipe_revision.get().to_string(),
                name_digest.as_str().to_owned(),
                status_digest.as_str().to_owned(),
                provider_revision_digest.as_str().to_owned(),
            ],
        );
        Ok(crate::RecipeProjection {
            recipe_id,
            workspace_digest,
            project_digest,
            folder_digest,
            recipe_revision,
            name_digest,
            status_digest,
            provider_revision_digest,
            projection_digest,
        })
    }

    fn normalize_recipe_version(
        scope: &WorkatoScope,
        raw: RawRecipeVersion,
    ) -> Result<crate::RecipeVersionProjection, ProviderError> {
        if raw.recipe_id != scope.recipe().as_str() {
            return Err(ProviderError::validation(
                ProviderErrorKind::RecipeMismatch,
                "recipe-version-recipe",
            ));
        }
        if raw.version_id != scope.recipe_version().version_id().as_str()
            || raw.version_number != scope.recipe_version().version_number()
        {
            return Err(ProviderError::validation(
                ProviderErrorKind::RecipeVersionMismatch,
                "recipe-version-binding",
            ));
        }
        let revision = Revision::new(raw.revision).map_err(|_| {
            ProviderError::validation(ProviderErrorKind::MalformedResponse, "version-revision")
        })?;
        let provider_revision = Revision::new(raw.provider_revision).map_err(|_| {
            ProviderError::validation(ProviderErrorKind::MalformedResponse, "provider-revision")
        })?;
        let recipe_id = RecipeId::new(raw.recipe_id).map_err(|_| {
            ProviderError::validation(ProviderErrorKind::MalformedResponse, "recipe-id")
        })?;
        let version_id = RecipeVersionId::new(raw.version_id).map_err(|_| {
            ProviderError::validation(ProviderErrorKind::MalformedResponse, "version-id")
        })?;
        let comment_digest = crate::Digest::from_text(raw.comment);
        let author_digest = crate::Digest::from_text(raw.author);
        let created_at_digest = crate::Digest::from_text(raw.created_at);
        let updated_at_digest = crate::Digest::from_text(raw.updated_at);
        let provider_revision_digest =
            crate::Digest::from_text(provider_revision.get().to_string());
        let projection_digest = crate::Digest::from_fields(
            "workato-recipe-version-projection/v1",
            &[
                recipe_id.as_str().to_owned(),
                version_id.as_str().to_owned(),
                raw.version_number.to_string(),
                revision.get().to_string(),
                comment_digest.as_str().to_owned(),
                author_digest.as_str().to_owned(),
                created_at_digest.as_str().to_owned(),
                updated_at_digest.as_str().to_owned(),
                provider_revision_digest.as_str().to_owned(),
            ],
        );
        Ok(crate::RecipeVersionProjection {
            recipe_id,
            version_id,
            version_number: raw.version_number,
            revision,
            comment_digest,
            author_digest,
            created_at_digest,
            updated_at_digest,
            provider_revision_digest,
            projection_digest,
        })
    }

    fn normalize_job(
        scope: &WorkatoScope,
        raw: RawJob,
    ) -> Result<(JobProjection, Vec<StepProjection>), ProviderError> {
        if raw.workspace_id != scope.workspace().as_str()
            || raw.project_id != scope.project().as_str()
            || raw.folder_id != scope.folder().as_str()
            || raw.recipe_id != scope.recipe().as_str()
        {
            return Err(ProviderError::validation(
                ProviderErrorKind::ScopeMismatch,
                "job-scope",
            ));
        }
        if raw.recipe_version_id != scope.recipe_version().version_id().as_str()
            || raw.recipe_version_number != scope.recipe_version().version_number()
        {
            return Err(ProviderError::validation(
                ProviderErrorKind::RecipeVersionMismatch,
                "job-version-binding",
            ));
        }
        let job_handle = JobHandle::new(raw.job_handle).map_err(|_| {
            ProviderError::validation(ProviderErrorKind::MalformedResponse, "job-handle")
        })?;
        let root_job_handle = JobHandle::new(raw.root_job_handle).map_err(|_| {
            ProviderError::validation(ProviderErrorKind::MalformedResponse, "root-job-handle")
        })?;
        let parent_job_handle = raw
            .parent_job_handle
            .map(JobHandle::new)
            .transpose()
            .map_err(|_| {
                ProviderError::validation(ProviderErrorKind::MalformedResponse, "parent-job-handle")
            })?;
        let retry = RetryIdentity::new(root_job_handle, raw.retry_number, parent_job_handle)
            .map_err(|_| {
                ProviderError::validation(ProviderErrorKind::AmbiguousRerun, "retry-identity")
            })?;
        let identity = JobIdentity::new(job_handle, retry).map_err(|_| {
            ProviderError::validation(ProviderErrorKind::AmbiguousRerun, "job-identity")
        })?;
        if !crate::model::scope_identity_matches(scope, &identity) {
            return Err(ProviderError::validation(
                ProviderErrorKind::RetryMismatch,
                "job-retry-binding",
            ));
        }
        if raw.retry_number as usize > crate::model::MAX_RETRIES {
            return Err(ProviderError::validation(
                ProviderErrorKind::PageBoundExceeded,
                "retry-bound",
            ));
        }
        if raw.retention_gap {
            return Ok((
                JobProjection {
                    identity,
                    recipe_id: scope.recipe().clone(),
                    recipe_version: scope.recipe_version().clone(),
                    status: JobStatus::ProviderUnknown,
                    retention: RetentionState::RetentionGap,
                    started_at_digest: None,
                    completed_at_digest: None,
                    duration_ms: None,
                    tasks_used: None,
                    step_count: 0,
                    failed_step_count: 0,
                    steps: Vec::new(),
                    runtime_data_redacted: true,
                    provider_revision_digest: crate::Digest::from_text("retention-gap"),
                    projection_digest: crate::Digest::from_text("retention-gap"),
                },
                Vec::new(),
            ));
        }
        if raw.steps.len() > MAX_STEPS {
            return Err(ProviderError::validation(
                ProviderErrorKind::PageBoundExceeded,
                "step-bound",
            ));
        }
        let status = normalize_job_status(&raw.status);
        let step_scope = scope.step_scope();
        let mut seen_steps = std::collections::BTreeSet::new();
        let mut steps = Vec::with_capacity(raw.steps.len());
        for raw_step in raw.steps {
            let step_id = StepId::new(raw_step.step_id).map_err(|_| {
                ProviderError::validation(ProviderErrorKind::MalformedResponse, "step-id")
            })?;
            if !step_scope.allows(&step_id) {
                return Err(ProviderError::validation(
                    ProviderErrorKind::StepMismatch,
                    "step-scope",
                ));
            }
            if !seen_steps.insert(step_id.clone()) {
                return Err(ProviderError::validation(
                    ProviderErrorKind::MalformedResponse,
                    "duplicate-step",
                ));
            }
            let step_status = normalize_step_status(&raw_step.status);
            let kind_digest = crate::Digest::from_text(raw_step.kind);
            let error_digest = digest_optional(raw_step.error.as_deref());
            let projection_digest = crate::Digest::from_fields(
                "workato-step-projection/v1",
                &[
                    step_id.as_str().to_owned(),
                    raw_step.ordinal.to_string(),
                    format!("{step_status:?}"),
                    kind_digest.as_str().to_owned(),
                    error_digest
                        .as_ref()
                        .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
                    raw_step
                        .duration_ms
                        .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                    raw_step.retry_number.to_string(),
                    "runtime_data_redacted=true".to_owned(),
                ],
            );
            steps.push(StepProjection {
                step_id,
                ordinal: raw_step.ordinal,
                status: step_status,
                kind_digest,
                error_digest,
                duration_ms: raw_step.duration_ms,
                retry_number: raw_step.retry_number,
                runtime_data_redacted: true,
                projection_digest,
            });
        }
        let failed_step_count = steps
            .iter()
            .filter(|step| step.status == StepStatus::Failed)
            .count();
        let recipe_version = RecipeVersionBinding::new(
            RecipeVersionId::new(raw.recipe_version_id).map_err(|_| {
                ProviderError::validation(ProviderErrorKind::MalformedResponse, "version-id")
            })?,
            raw.recipe_version_number,
            scope.recipe_version().revision(),
        )
        .map_err(|_| {
            ProviderError::validation(ProviderErrorKind::MalformedResponse, "version-binding")
        })?;
        let provider_revision = Revision::new(raw.provider_revision).map_err(|_| {
            ProviderError::validation(ProviderErrorKind::MalformedResponse, "provider-revision")
        })?;
        let provider_revision_digest =
            crate::Digest::from_text(provider_revision.get().to_string());
        let started_at_digest = digest_optional(raw.started_at.as_deref());
        let completed_at_digest = digest_optional(raw.completed_at.as_deref());
        let step_digest = crate::Digest::from_fields(
            "workato-step-set/v1",
            &steps
                .iter()
                .map(|step| step.projection_digest.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        let projection_digest = crate::Digest::from_fields(
            "workato-job-projection/v1",
            &[
                identity.digest().as_str().to_owned(),
                scope.recipe().as_str().to_owned(),
                recipe_version.digest().as_str().to_owned(),
                format!("{status:?}"),
                format!("{:?}", RetentionState::Present),
                started_at_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
                completed_at_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
                raw.duration_ms
                    .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                raw.tasks_used
                    .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                step_digest.as_str().to_owned(),
                provider_revision_digest.as_str().to_owned(),
                "runtime_data_redacted=true".to_owned(),
            ],
        );
        Ok((
            JobProjection {
                identity,
                recipe_id: scope.recipe().clone(),
                recipe_version,
                status,
                retention: RetentionState::Present,
                started_at_digest,
                completed_at_digest,
                duration_ms: raw.duration_ms,
                tasks_used: raw.tasks_used,
                step_count: steps.len(),
                failed_step_count,
                steps: steps.clone(),
                runtime_data_redacted: true,
                provider_revision_digest,
                projection_digest,
            },
            steps,
        ))
    }

    fn normalize_job_summary(
        scope: &WorkatoScope,
        raw: RawJob,
    ) -> Result<JobSummaryProjection, ProviderError> {
        if raw.workspace_id != scope.workspace().as_str()
            || raw.project_id != scope.project().as_str()
            || raw.folder_id != scope.folder().as_str()
            || raw.recipe_id != scope.recipe().as_str()
        {
            return Err(ProviderError::validation(
                ProviderErrorKind::ScopeMismatch,
                "job-list-scope",
            ));
        }
        let job_handle = JobHandle::new(raw.job_handle).map_err(|_| {
            ProviderError::validation(ProviderErrorKind::MalformedResponse, "job-handle")
        })?;
        let root_job_handle = JobHandle::new(raw.root_job_handle).map_err(|_| {
            ProviderError::validation(ProviderErrorKind::MalformedResponse, "root-job-handle")
        })?;
        let parent_job_handle = raw
            .parent_job_handle
            .map(JobHandle::new)
            .transpose()
            .map_err(|_| {
                ProviderError::validation(ProviderErrorKind::MalformedResponse, "parent-job-handle")
            })?;
        let retry = RetryIdentity::new(root_job_handle, raw.retry_number, parent_job_handle)
            .map_err(|_| {
                ProviderError::validation(ProviderErrorKind::AmbiguousRerun, "retry-identity")
            })?;
        if raw.retry_number as usize > crate::model::MAX_RETRIES {
            return Err(ProviderError::validation(
                ProviderErrorKind::PageBoundExceeded,
                "retry-bound",
            ));
        }
        let identity = JobIdentity::new(job_handle, retry).map_err(|_| {
            ProviderError::validation(ProviderErrorKind::AmbiguousRerun, "job-identity")
        })?;
        let recipe_version = RecipeVersionBinding::new(
            RecipeVersionId::new(raw.recipe_version_id).map_err(|_| {
                ProviderError::validation(ProviderErrorKind::MalformedResponse, "version-id")
            })?,
            raw.recipe_version_number,
            Revision::new(raw.provider_revision).map_err(|_| {
                ProviderError::validation(ProviderErrorKind::MalformedResponse, "version-revision")
            })?,
        )
        .map_err(|_| {
            ProviderError::validation(ProviderErrorKind::MalformedResponse, "version-binding")
        })?;
        Ok(JobSummaryProjection {
            identity,
            recipe_version,
            status: normalize_job_status(&raw.status),
            retention: if raw.retention_gap {
                RetentionState::RetentionGap
            } else {
                RetentionState::Present
            },
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JobSummaryProjection {
    pub identity: JobIdentity,
    pub recipe_version: RecipeVersionBinding,
    pub status: JobStatus,
    pub retention: RetentionState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JobPageProjection {
    pub page: u32,
    pub per_page: u32,
    pub items: Vec<JobSummaryProjection>,
}

fn normalize_job_status(value: &str) -> JobStatus {
    match value.to_ascii_lowercase().as_str() {
        "completed" | "succeeded" | "success" => JobStatus::Completed,
        "failed" | "failure" => JobStatus::Failed,
        "processing" | "pending" | "running" => JobStatus::Processing,
        "paused" => JobStatus::Paused,
        "aborted" | "abort" => JobStatus::Aborted,
        "retried" | "rerun" | "repeated" => JobStatus::Retried,
        "partial" | "incomplete" | "truncated" => JobStatus::Partial,
        _ => JobStatus::ProviderUnknown,
    }
}

fn normalize_step_status(value: &str) -> StepStatus {
    match value.to_ascii_lowercase().as_str() {
        "completed" | "succeeded" | "success" => StepStatus::Completed,
        "failed" | "failure" => StepStatus::Failed,
        "processing" | "pending" | "running" => StepStatus::Processing,
        "paused" => StepStatus::Paused,
        "aborted" | "abort" => StepStatus::Aborted,
        "skipped" | "condition_not_met" => StepStatus::Skipped,
        "retried" | "rerun" | "repeated" => StepStatus::Retried,
        _ => StepStatus::ProviderUnknown,
    }
}
