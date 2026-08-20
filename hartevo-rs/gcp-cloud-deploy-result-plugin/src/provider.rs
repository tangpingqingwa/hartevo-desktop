use std::{collections::VecDeque, fmt};

use thiserror::Error;

use crate::{
    GCP_CLOUD_DEPLOY_API_VERSION, GCP_CLOUD_DEPLOY_PROVIDER_ID,
    GCP_CLOUD_DEPLOY_PROVIDER_VERSION_TEXT, MAX_RESPONSE_BYTES,
    model::{
        CloudDeployPhase, Digest, GcpCloudDeployApiVersion, GcpCloudDeployPermission,
        GcpCloudDeployScope, JobRunId, JobRunPage, JobRunSnapshot, ListOperation, ModelError,
        PageCursor, PermissionScope, ProviderErrorKind, ProviderErrorSummary, ProviderProvenance,
        ReleasePage, ReleaseSnapshot, RolloutId, RolloutPage, RolloutSnapshot,
        validate_job_run_order,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcpCloudDeployReadOperation {
    GetRelease,
    ListReleases,
    GetRollout,
    ListRollouts,
    GetJobRun,
    ListJobRuns,
}

impl GcpCloudDeployReadOperation {
    const fn list_operation(self) -> Option<ListOperation> {
        match self {
            Self::ListReleases => Some(ListOperation::Releases),
            Self::ListRollouts => Some(ListOperation::Rollouts),
            Self::ListJobRuns => Some(ListOperation::JobRuns),
            Self::GetRelease | Self::GetRollout | Self::GetJobRun => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpCloudDeployReadRequest {
    operation: GcpCloudDeployReadOperation,
    scope_digest: Digest,
    permission_digest: Digest,
    project_id: String,
    location: String,
    pipeline_id: String,
    release_id: String,
    rollout_id: Option<RolloutId>,
    job_run_id: Option<JobRunId>,
    cursor: Option<PageCursor>,
    native_execution: bool,
}

impl GcpCloudDeployReadRequest {
    fn new(
        scope: &GcpCloudDeployScope,
        operation: GcpCloudDeployReadOperation,
        rollout_id: Option<RolloutId>,
        job_run_id: Option<JobRunId>,
        cursor: Option<PageCursor>,
    ) -> Self {
        Self {
            operation,
            scope_digest: scope.digest(),
            permission_digest: scope.permissions().digest(),
            project_id: scope.project_id().as_str().to_owned(),
            location: scope.location().as_str().to_owned(),
            pipeline_id: scope.pipeline_id().as_str().to_owned(),
            release_id: scope.release_id().as_str().to_owned(),
            rollout_id,
            job_run_id,
            cursor,
            native_execution: false,
        }
    }

    pub fn operation(&self) -> GcpCloudDeployReadOperation {
        self.operation
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn path(&self) -> String {
        let base = format!(
            "/{GCP_CLOUD_DEPLOY_API_VERSION}/projects/{}/locations/{}/deliveryPipelines/{}",
            self.project_id, self.location, self.pipeline_id
        );
        match self.operation {
            GcpCloudDeployReadOperation::GetRelease => {
                format!("{base}/releases/{}", self.release_id)
            }
            GcpCloudDeployReadOperation::ListReleases => format!("{base}/releases"),
            GcpCloudDeployReadOperation::GetRollout => format!(
                "{base}/releases/{}/rollouts/{}",
                self.release_id,
                self.rollout_id
                    .as_ref()
                    .map_or("missing", RolloutId::as_str)
            ),
            GcpCloudDeployReadOperation::ListRollouts => {
                format!("{base}/releases/{}/rollouts", self.release_id)
            }
            GcpCloudDeployReadOperation::GetJobRun => format!(
                "{base}/releases/{}/rollouts/{}/jobRuns/{}",
                self.release_id,
                self.rollout_id
                    .as_ref()
                    .map_or("missing", RolloutId::as_str),
                self.job_run_id.as_ref().map_or("missing", JobRunId::as_str)
            ),
            GcpCloudDeployReadOperation::ListJobRuns => format!(
                "{base}/releases/{}/rollouts/{}/jobRuns",
                self.release_id,
                self.rollout_id
                    .as_ref()
                    .map_or("missing", RolloutId::as_str)
            ),
        }
    }

    pub fn cursor(&self) -> Option<&PageCursor> {
        self.cursor.as_ref()
    }

    pub const fn native_execution(&self) -> bool {
        self.native_execution
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GcpCloudDeployResponse {
    Release(ReleaseSnapshot),
    Releases(ReleasePage),
    Rollout(RolloutSnapshot),
    Rollouts(RolloutPage),
    JobRun(JobRunSnapshot),
    JobRuns(JobRunPage),
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GcpCloudDeployTransportError {
    #[error("HTTP status {status} with digest-only detail")]
    HttpStatus { status: u16, detail_digest: Digest },
    #[error("bounded transport timeout with digest-only detail")]
    Timeout { detail_digest: Digest },
    #[error("bounded transport failure with digest-only detail")]
    Transport { detail_digest: Digest },
    #[error("malformed response with digest-only detail")]
    Malformed { detail_digest: Digest },
    #[error("environment is blocked with digest-only detail")]
    BlockedEnv { detail_digest: Digest },
}

impl GcpCloudDeployTransportError {
    pub fn http_status(status: u16, detail: impl AsRef<str>) -> Self {
        Self::HttpStatus {
            status,
            detail_digest: Digest::from_text(detail.as_ref()),
        }
    }

    pub fn timeout(detail: impl AsRef<str>) -> Self {
        Self::Timeout {
            detail_digest: Digest::from_text(detail.as_ref()),
        }
    }

    pub fn transport(detail: impl AsRef<str>) -> Self {
        Self::Transport {
            detail_digest: Digest::from_text(detail.as_ref()),
        }
    }

    pub fn malformed(detail: impl AsRef<str>) -> Self {
        Self::Malformed {
            detail_digest: Digest::from_text(detail.as_ref()),
        }
    }

    pub fn blocked_env(detail: impl AsRef<str>) -> Self {
        Self::BlockedEnv {
            detail_digest: Digest::from_text(detail.as_ref()),
        }
    }

    pub const fn status(&self) -> Option<u16> {
        match self {
            Self::HttpStatus { status, .. } => Some(*status),
            Self::Timeout { .. }
            | Self::Transport { .. }
            | Self::Malformed { .. }
            | Self::BlockedEnv { .. } => None,
        }
    }

    pub fn detail_digest(&self) -> &Digest {
        match self {
            Self::HttpStatus { detail_digest, .. }
            | Self::Timeout { detail_digest }
            | Self::Transport { detail_digest }
            | Self::Malformed { detail_digest }
            | Self::BlockedEnv { detail_digest } => detail_digest,
        }
    }
}

pub trait GcpCloudDeployTransport: fmt::Debug {
    fn execute(
        &mut self,
        request: &GcpCloudDeployReadRequest,
    ) -> Result<GcpCloudDeployResponse, GcpCloudDeployTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpCloudDeployProviderDefinition {
    api_version: GcpCloudDeployApiVersion,
    provider_version: String,
    permissions: PermissionScope,
    provenance: ProviderProvenance,
    provider_digest: Digest,
}

impl GcpCloudDeployProviderDefinition {
    pub fn layer1(provenance: ProviderProvenance) -> Result<Self, ModelError> {
        Self::new(
            GcpCloudDeployApiVersion::V1,
            GCP_CLOUD_DEPLOY_PROVIDER_VERSION_TEXT,
            PermissionScope::least_privilege(),
            provenance,
        )
    }

    pub fn new(
        api_version: GcpCloudDeployApiVersion,
        provider_version: impl Into<String>,
        permissions: PermissionScope,
        provenance: ProviderProvenance,
    ) -> Result<Self, ModelError> {
        let provider_version = provider_version.into();
        if api_version.as_str() != GCP_CLOUD_DEPLOY_API_VERSION
            || provider_version != GCP_CLOUD_DEPLOY_PROVIDER_VERSION_TEXT
        {
            return Err(ModelError::InvalidApiVersion);
        }
        permissions.validate()?;
        let provider_digest = Digest::from_fields(
            "gcp-cloud-deploy-provider/v1",
            &[
                GCP_CLOUD_DEPLOY_PROVIDER_ID.to_owned(),
                provider_version.clone(),
                api_version.as_str().to_owned(),
                permissions.digest().as_str().to_owned(),
                provenance.as_str().to_owned(),
                "read_only".to_owned(),
                "no_https".to_owned(),
                "no_readback".to_owned(),
            ],
        );
        Ok(Self {
            api_version,
            provider_version,
            permissions,
            provenance,
            provider_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.api_version != GcpCloudDeployApiVersion::V1
            || self.provider_version != GCP_CLOUD_DEPLOY_PROVIDER_VERSION_TEXT
            || self.permissions.validate().is_err()
        {
            Err(ModelError::InvalidApiVersion)
        } else {
            Ok(())
        }
    }

    pub const fn api_version(&self) -> GcpCloudDeployApiVersion {
        self.api_version
    }

    pub fn provider_version(&self) -> &str {
        &self.provider_version
    }

    pub fn permissions(&self) -> &PermissionScope {
        &self.permissions
    }

    pub const fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn https_transport(&self) -> bool {
        false
    }

    pub const fn readback(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GcpCloudDeployProviderError {
    #[error("provider scope digest mismatch")]
    ScopeMismatch,
    #[error("provider permission digest mismatch")]
    PermissionMismatch,
    #[error("cursor binding mismatch")]
    CursorMismatch,
    #[error("release identity is outside the registered release fence")]
    ReleaseMismatch,
    #[error("rollout identity is outside the registered release fence")]
    RolloutMismatch,
    #[error("job-run identity is outside the registered rollout fence")]
    JobRunMismatch,
    #[error("target fence is stale")]
    StaleTarget,
    #[error("commit fence is stale")]
    StaleCommit,
    #[error("provider returned an unexpected response kind")]
    UnexpectedResponse,
    #[error("provider returned an invalid bounded response")]
    InvalidResponse,
    #[error("provider transport error: {0:?}")]
    Transport(ProviderErrorSummary),
}

impl GcpCloudDeployProviderError {
    pub fn summary(&self) -> ProviderErrorSummary {
        match self {
            Self::ScopeMismatch | Self::PermissionMismatch | Self::ReleaseMismatch => {
                ProviderErrorSummary::new(
                    ProviderErrorKind::ScopeMismatch,
                    None,
                    Digest::from_text(self.to_string()),
                )
            }
            Self::CursorMismatch => ProviderErrorSummary::new(
                ProviderErrorKind::CursorMismatch,
                None,
                Digest::from_text(self.to_string()),
            ),
            Self::RolloutMismatch | Self::JobRunMismatch => ProviderErrorSummary::new(
                ProviderErrorKind::ScopeMismatch,
                None,
                Digest::from_text(self.to_string()),
            ),
            Self::StaleTarget => ProviderErrorSummary::new(
                ProviderErrorKind::StaleTarget,
                None,
                Digest::from_text(self.to_string()),
            ),
            Self::StaleCommit => ProviderErrorSummary::new(
                ProviderErrorKind::StaleCommit,
                None,
                Digest::from_text(self.to_string()),
            ),
            Self::UnexpectedResponse | Self::InvalidResponse => ProviderErrorSummary::new(
                ProviderErrorKind::Malformed,
                None,
                Digest::from_text(self.to_string()),
            ),
            Self::Transport(summary) => summary.clone(),
        }
    }
}

fn transport_summary(error: &GcpCloudDeployTransportError) -> ProviderErrorSummary {
    let kind = match error {
        GcpCloudDeployTransportError::HttpStatus { status: 401, .. } => {
            ProviderErrorKind::Unauthorized
        }
        GcpCloudDeployTransportError::HttpStatus { status: 403, .. } => {
            ProviderErrorKind::Forbidden
        }
        GcpCloudDeployTransportError::HttpStatus { status: 404, .. } => ProviderErrorKind::NotFound,
        GcpCloudDeployTransportError::HttpStatus { status: 409, .. } => ProviderErrorKind::Conflict,
        GcpCloudDeployTransportError::HttpStatus { status: 429, .. } => {
            ProviderErrorKind::RateLimited
        }
        GcpCloudDeployTransportError::HttpStatus { status, .. } if *status >= 500 => {
            ProviderErrorKind::Server
        }
        GcpCloudDeployTransportError::HttpStatus { .. } => ProviderErrorKind::Unknown,
        GcpCloudDeployTransportError::Timeout { .. } => ProviderErrorKind::Timeout,
        GcpCloudDeployTransportError::Transport { .. } => ProviderErrorKind::Transport,
        GcpCloudDeployTransportError::Malformed { .. } => ProviderErrorKind::Malformed,
        GcpCloudDeployTransportError::BlockedEnv { .. } => ProviderErrorKind::BlockedEnv,
    };
    ProviderErrorSummary::new(kind, error.status(), error.detail_digest().clone())
}

#[derive(Debug)]
pub struct GcpCloudDeployProvider<T> {
    transport: T,
    scope: GcpCloudDeployScope,
    definition: GcpCloudDeployProviderDefinition,
}

impl<T> GcpCloudDeployProvider<T>
where
    T: GcpCloudDeployTransport,
{
    pub fn new(
        transport: T,
        scope: GcpCloudDeployScope,
        provenance: ProviderProvenance,
    ) -> Result<Self, GcpCloudDeployProviderError> {
        let definition = GcpCloudDeployProviderDefinition::layer1(provenance)
            .map_err(|_| GcpCloudDeployProviderError::InvalidResponse)?;
        Self::with_definition(transport, scope, definition)
    }

    pub fn with_definition(
        transport: T,
        scope: GcpCloudDeployScope,
        definition: GcpCloudDeployProviderDefinition,
    ) -> Result<Self, GcpCloudDeployProviderError> {
        scope
            .validate()
            .map_err(|_| GcpCloudDeployProviderError::ScopeMismatch)?;
        definition
            .validate()
            .map_err(|_| GcpCloudDeployProviderError::InvalidResponse)?;
        if definition.permissions() != scope.permissions() {
            return Err(GcpCloudDeployProviderError::PermissionMismatch);
        }
        Ok(Self {
            transport,
            scope,
            definition,
        })
    }

    pub fn scope(&self) -> &GcpCloudDeployScope {
        &self.scope
    }

    pub fn definition(&self) -> &GcpCloudDeployProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> &Digest {
        self.definition.provider_digest()
    }

    pub fn scope_digest(&self) -> Digest {
        self.scope.digest()
    }

    pub fn permission_digest(&self) -> Digest {
        self.scope.permissions().digest()
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn https_transport(&self) -> bool {
        false
    }

    pub const fn readback(&self) -> bool {
        false
    }

    fn execute(
        &mut self,
        request: GcpCloudDeployReadRequest,
    ) -> Result<GcpCloudDeployResponse, GcpCloudDeployProviderError> {
        if request.scope_digest != self.scope.digest() {
            return Err(GcpCloudDeployProviderError::ScopeMismatch);
        }
        if request.permission_digest != self.scope.permissions().digest() {
            return Err(GcpCloudDeployProviderError::PermissionMismatch);
        }
        if let (Some(operation), Some(cursor)) =
            (request.operation.list_operation(), request.cursor())
            && !cursor.matches(&self.scope, operation)
        {
            return Err(GcpCloudDeployProviderError::CursorMismatch);
        }
        self.transport
            .execute(&request)
            .map_err(|error| GcpCloudDeployProviderError::Transport(transport_summary(&error)))
    }

    pub fn get_release(&mut self) -> Result<ReleaseSnapshot, GcpCloudDeployProviderError> {
        let response = self.execute(GcpCloudDeployReadRequest::new(
            &self.scope,
            GcpCloudDeployReadOperation::GetRelease,
            None,
            None,
            None,
        ))?;
        match response {
            GcpCloudDeployResponse::Release(snapshot) => {
                self.validate_release(&snapshot)?;
                Ok(snapshot)
            }
            _ => Err(GcpCloudDeployProviderError::UnexpectedResponse),
        }
    }

    pub fn list_releases(
        &mut self,
        cursor: Option<PageCursor>,
    ) -> Result<ReleasePage, GcpCloudDeployProviderError> {
        let response = self.execute(GcpCloudDeployReadRequest::new(
            &self.scope,
            GcpCloudDeployReadOperation::ListReleases,
            None,
            None,
            cursor,
        ))?;
        match response {
            GcpCloudDeployResponse::Releases(page) => {
                self.validate_release_page(&page)?;
                Ok(page)
            }
            _ => Err(GcpCloudDeployProviderError::UnexpectedResponse),
        }
    }

    pub fn get_rollout(
        &mut self,
        rollout_id: RolloutId,
    ) -> Result<RolloutSnapshot, GcpCloudDeployProviderError> {
        let response = self.execute(GcpCloudDeployReadRequest::new(
            &self.scope,
            GcpCloudDeployReadOperation::GetRollout,
            Some(rollout_id.clone()),
            None,
            None,
        ))?;
        match response {
            GcpCloudDeployResponse::Rollout(snapshot) => {
                if snapshot.identity().rollout_id() != &rollout_id {
                    return Err(GcpCloudDeployProviderError::RolloutMismatch);
                }
                self.validate_rollout(&snapshot)?;
                Ok(snapshot)
            }
            _ => Err(GcpCloudDeployProviderError::UnexpectedResponse),
        }
    }

    pub fn list_rollouts(
        &mut self,
        cursor: Option<PageCursor>,
    ) -> Result<RolloutPage, GcpCloudDeployProviderError> {
        let response = self.execute(GcpCloudDeployReadRequest::new(
            &self.scope,
            GcpCloudDeployReadOperation::ListRollouts,
            None,
            None,
            cursor,
        ))?;
        match response {
            GcpCloudDeployResponse::Rollouts(page) => {
                self.validate_rollout_page(&page)?;
                Ok(page)
            }
            _ => Err(GcpCloudDeployProviderError::UnexpectedResponse),
        }
    }

    pub fn get_job_run(
        &mut self,
        rollout_id: RolloutId,
        job_run_id: JobRunId,
    ) -> Result<JobRunSnapshot, GcpCloudDeployProviderError> {
        let response = self.execute(GcpCloudDeployReadRequest::new(
            &self.scope,
            GcpCloudDeployReadOperation::GetJobRun,
            Some(rollout_id.clone()),
            Some(job_run_id.clone()),
            None,
        ))?;
        match response {
            GcpCloudDeployResponse::JobRun(snapshot) => {
                if snapshot.identity().rollout().rollout_id() != &rollout_id
                    || snapshot.identity().job_run_id() != &job_run_id
                {
                    return Err(GcpCloudDeployProviderError::JobRunMismatch);
                }
                self.validate_job_run(&snapshot)?;
                Ok(snapshot)
            }
            _ => Err(GcpCloudDeployProviderError::UnexpectedResponse),
        }
    }

    pub fn list_job_runs(
        &mut self,
        rollout_id: RolloutId,
        cursor: Option<PageCursor>,
    ) -> Result<JobRunPage, GcpCloudDeployProviderError> {
        let response = self.execute(GcpCloudDeployReadRequest::new(
            &self.scope,
            GcpCloudDeployReadOperation::ListJobRuns,
            Some(rollout_id.clone()),
            None,
            cursor,
        ))?;
        match response {
            GcpCloudDeployResponse::JobRuns(page) => {
                for item in page.items() {
                    if item.identity().rollout().rollout_id() != &rollout_id {
                        return Err(GcpCloudDeployProviderError::JobRunMismatch);
                    }
                    self.validate_job_run(item)?;
                }
                validate_job_run_order(page.items())
                    .map_err(|_| GcpCloudDeployProviderError::InvalidResponse)?;
                if let Some(cursor) = page.next_cursor()
                    && !cursor.matches(&self.scope, ListOperation::JobRuns)
                {
                    return Err(GcpCloudDeployProviderError::CursorMismatch);
                }
                Ok(page)
            }
            _ => Err(GcpCloudDeployProviderError::UnexpectedResponse),
        }
    }

    fn validate_release(
        &self,
        snapshot: &ReleaseSnapshot,
    ) -> Result<(), GcpCloudDeployProviderError> {
        if snapshot.identity() != &self.scope.release_identity() {
            return Err(GcpCloudDeployProviderError::ReleaseMismatch);
        }
        if snapshot.target_id() != self.scope.target_id() {
            return Err(GcpCloudDeployProviderError::StaleTarget);
        }
        if snapshot.commit_id() != self.scope.commit_id() {
            return Err(GcpCloudDeployProviderError::StaleCommit);
        }
        snapshot
            .validate_digest()
            .map_err(|_| GcpCloudDeployProviderError::InvalidResponse)
    }

    fn validate_release_page(&self, page: &ReleasePage) -> Result<(), GcpCloudDeployProviderError> {
        for item in page.items() {
            self.validate_release(item)?;
        }
        if let Some(cursor) = page.next_cursor()
            && !cursor.matches(&self.scope, ListOperation::Releases)
        {
            return Err(GcpCloudDeployProviderError::CursorMismatch);
        }
        Ok(())
    }

    fn validate_rollout(
        &self,
        snapshot: &RolloutSnapshot,
    ) -> Result<(), GcpCloudDeployProviderError> {
        if snapshot.identity().release() != &self.scope.release_identity() {
            return Err(GcpCloudDeployProviderError::RolloutMismatch);
        }
        if snapshot.target_id() != self.scope.target_id() {
            return Err(GcpCloudDeployProviderError::StaleTarget);
        }
        if snapshot.commit_id() != self.scope.commit_id() {
            return Err(GcpCloudDeployProviderError::StaleCommit);
        }
        snapshot
            .validate_digest()
            .map_err(|_| GcpCloudDeployProviderError::InvalidResponse)
    }

    fn validate_rollout_page(&self, page: &RolloutPage) -> Result<(), GcpCloudDeployProviderError> {
        for item in page.items() {
            self.validate_rollout(item)?;
        }
        if let Some(cursor) = page.next_cursor()
            && !cursor.matches(&self.scope, ListOperation::Rollouts)
        {
            return Err(GcpCloudDeployProviderError::CursorMismatch);
        }
        Ok(())
    }

    fn validate_job_run(
        &self,
        snapshot: &JobRunSnapshot,
    ) -> Result<(), GcpCloudDeployProviderError> {
        if snapshot.identity().rollout().release() != &self.scope.release_identity() {
            return Err(GcpCloudDeployProviderError::JobRunMismatch);
        }
        if snapshot.target_id() != self.scope.target_id() {
            return Err(GcpCloudDeployProviderError::StaleTarget);
        }
        if snapshot.commit_id() != self.scope.commit_id() {
            return Err(GcpCloudDeployProviderError::StaleCommit);
        }
        snapshot
            .validate_digest()
            .map_err(|_| GcpCloudDeployProviderError::InvalidResponse)
    }
}

#[derive(Debug, Default)]
pub struct RecordingGcpCloudDeployTransport {
    responses: VecDeque<Result<GcpCloudDeployResponse, GcpCloudDeployTransportError>>,
    requests: Vec<GcpCloudDeployReadRequest>,
}

impl RecordingGcpCloudDeployTransport {
    pub fn push_response(
        &mut self,
        response: Result<GcpCloudDeployResponse, GcpCloudDeployTransportError>,
    ) {
        self.responses.push_back(response);
    }

    pub fn push_error(&mut self, error: GcpCloudDeployTransportError) {
        self.push_response(Err(error));
    }

    pub fn requests(&self) -> &[GcpCloudDeployReadRequest] {
        &self.requests
    }
}

impl GcpCloudDeployTransport for RecordingGcpCloudDeployTransport {
    fn execute(
        &mut self,
        request: &GcpCloudDeployReadRequest,
    ) -> Result<GcpCloudDeployResponse, GcpCloudDeployTransportError> {
        self.requests.push(request.clone());
        self.responses.pop_front().unwrap_or_else(|| {
            Err(GcpCloudDeployTransportError::timeout(
                "recording response queue exhausted",
            ))
        })
    }
}

#[derive(Debug, Default)]
pub struct BlockedEnvGcpCloudDeployTransport;

impl GcpCloudDeployTransport for BlockedEnvGcpCloudDeployTransport {
    fn execute(
        &mut self,
        _request: &GcpCloudDeployReadRequest,
    ) -> Result<GcpCloudDeployResponse, GcpCloudDeployTransportError> {
        Err(GcpCloudDeployTransportError::blocked_env(
            "native environment unavailable",
        ))
    }
}

pub type FixtureGcpCloudDeployTransport = RecordingGcpCloudDeployTransport;
pub type FakeGcpCloudDeployTransport = RecordingGcpCloudDeployTransport;
pub type LoopbackGcpCloudDeployTransport = RecordingGcpCloudDeployTransport;

#[allow(dead_code)]
fn _keep_phase_type_reachable(_: CloudDeployPhase, _: GcpCloudDeployPermission) {}

#[allow(dead_code)]
fn _keep_bounds_reachable(_: usize, _: usize, _: usize, _: usize) -> usize {
    MAX_RESPONSE_BYTES
}
