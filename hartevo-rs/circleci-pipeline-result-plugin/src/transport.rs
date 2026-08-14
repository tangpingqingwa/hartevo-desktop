use std::fmt;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::error::{CircleCiPipelineResultError, CircleCiProviderError};
use crate::model::{
    CircleCiPageToken, CircleCiPermissionSnapshot, CircleCiPipelineReadRequest, CircleCiProvenance,
    CircleCiScope, Digest, canonical_digest, digest_parts,
};

/// Credential material is intentionally confined to the resolver/transport
/// call boundary. It is never serialized, returned in evidence, or exposed in
/// Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretMaterial {
    kind: crate::CircleCiCredentialKind,
    value: String,
}

impl SecretMaterial {
    pub(crate) fn new(kind: crate::CircleCiCredentialKind, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }

    pub fn kind(&self) -> crate::CircleCiCredentialKind {
        self.kind
    }

    pub(crate) fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretMaterial")
            .field("kind", &self.kind)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CircleCiEndpoint {
    Pipeline,
    Workflows,
    Jobs,
    Approvals,
    ArtifactMetadata,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CircleCiTransportOutcome {
    Success,
    Failure { error: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CircleCiTransportOperation {
    pub endpoint: CircleCiEndpoint,
    pub page_token_digest: Option<Digest>,
    pub attempt: u32,
    pub retry_after_seconds: Option<u64>,
    pub outcome: CircleCiTransportOutcome,
    pub provenance: CircleCiProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CircleCiTransportReceipt {
    pub endpoint: CircleCiEndpoint,
    pub endpoint_digest: Digest,
    pub attempt: u32,
    pub response_digest: Digest,
    pub retry_after_seconds: Option<u64>,
    pub provenance: CircleCiProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CircleCiPipelineResponse {
    pub pipeline: RawPipeline,
    pub receipt: CircleCiTransportReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CircleCiPage<T> {
    pub items: Vec<T>,
    pub next_page_token: Option<CircleCiPageToken>,
    pub receipt: CircleCiTransportReceipt,
}

/// Raw fixture payload retained only inside a fake/recording/loopback
/// transport. The provider validates its payload digest before projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawPipeline {
    pub host: String,
    pub organization: String,
    pub project_slug: String,
    pub pipeline_id: String,
    pub attempt_id: String,
    pub number: u64,
    pub status: String,
    pub commit_sha: String,
    pub branch: Option<String>,
    pub tag: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub revision: u64,
    pub permission_digest: Digest,
    pub payload_digest: Digest,
}

impl RawPipeline {
    pub fn new(
        scope: &CircleCiScope,
        status: impl Into<String>,
    ) -> Result<Self, CircleCiPipelineResultError> {
        let mut value = Self {
            host: scope.host.as_str().to_owned(),
            organization: scope.organization.clone(),
            project_slug: scope.project_slug.clone(),
            pipeline_id: scope.pipeline_id.clone(),
            attempt_id: scope.attempt_id.clone(),
            number: 1,
            status: status.into(),
            commit_sha: scope.commit_sha.clone(),
            branch: Some(String::from("main")),
            tag: None,
            created_at: String::from("2026-08-14T10:00:00Z"),
            updated_at: String::from("2026-08-14T10:01:00Z"),
            revision: scope.revisions.pipeline,
            permission_digest: String::new(),
            payload_digest: String::new(),
        };
        CircleCiPermissionSnapshot::all_read(scope.revisions.permission)
            .expect("fixture permission revision")
            .digest()
            .clone_into(&mut value.permission_digest);
        value.refresh_digest();
        Ok(value)
    }

    pub fn refresh_digest(&mut self) {
        self.payload_digest = digest_without_field(self);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawWorkflow {
    pub host: String,
    pub organization: String,
    pub project_slug: String,
    pub pipeline_id: String,
    pub workflow_id: String,
    pub status: String,
    pub approval: String,
    pub name: String,
    pub commit_sha: String,
    pub created_at: String,
    pub stopped_at: Option<String>,
    pub revision: u64,
    pub payload_digest: Digest,
}

impl RawWorkflow {
    pub fn new(
        scope: &CircleCiScope,
        status: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, CircleCiPipelineResultError> {
        let mut value = Self {
            host: scope.host.as_str().to_owned(),
            organization: scope.organization.clone(),
            project_slug: scope.project_slug.clone(),
            pipeline_id: scope.pipeline_id.clone(),
            workflow_id: scope.workflow_id.clone(),
            status: status.into(),
            approval: String::from("not_required"),
            name: name.into(),
            commit_sha: scope.commit_sha.clone(),
            created_at: String::from("2026-08-14T10:00:01Z"),
            stopped_at: None,
            revision: scope.revisions.workflow,
            payload_digest: String::new(),
        };
        value.refresh_digest();
        Ok(value)
    }

    pub fn refresh_digest(&mut self) {
        self.payload_digest = digest_without_field(self);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawJob {
    pub host: String,
    pub organization: String,
    pub project_slug: String,
    pub pipeline_id: String,
    pub workflow_id: String,
    pub job_number: u64,
    pub attempt_id: String,
    pub status: String,
    pub approval: String,
    pub name: String,
    pub commit_sha: String,
    pub started_at: Option<String>,
    pub stopped_at: Option<String>,
    pub revision: u64,
    pub payload_digest: Digest,
}

impl RawJob {
    pub fn new(
        scope: &CircleCiScope,
        status: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, CircleCiPipelineResultError> {
        let mut value = Self {
            host: scope.host.as_str().to_owned(),
            organization: scope.organization.clone(),
            project_slug: scope.project_slug.clone(),
            pipeline_id: scope.pipeline_id.clone(),
            workflow_id: scope.workflow_id.clone(),
            job_number: scope.job_number,
            attempt_id: scope.attempt_id.clone(),
            status: status.into(),
            approval: String::from("not_required"),
            name: name.into(),
            commit_sha: scope.commit_sha.clone(),
            started_at: Some(String::from("2026-08-14T10:00:02Z")),
            stopped_at: None,
            revision: scope.revisions.job,
            payload_digest: String::new(),
        };
        value.refresh_digest();
        Ok(value)
    }

    pub fn refresh_digest(&mut self) {
        self.payload_digest = digest_without_field(self);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawApproval {
    pub host: String,
    pub organization: String,
    pub project_slug: String,
    pub pipeline_id: String,
    pub workflow_id: String,
    pub job_number: u64,
    pub attempt_id: String,
    pub state: String,
    pub revision: u64,
    pub payload_digest: Digest,
}

impl RawApproval {
    pub fn new(
        scope: &CircleCiScope,
        state: impl Into<String>,
    ) -> Result<Self, CircleCiPipelineResultError> {
        let mut value = Self {
            host: scope.host.as_str().to_owned(),
            organization: scope.organization.clone(),
            project_slug: scope.project_slug.clone(),
            pipeline_id: scope.pipeline_id.clone(),
            workflow_id: scope.workflow_id.clone(),
            job_number: scope.job_number,
            attempt_id: scope.attempt_id.clone(),
            state: state.into(),
            revision: scope.revisions.job,
            payload_digest: String::new(),
        };
        value.refresh_digest();
        Ok(value)
    }

    pub fn refresh_digest(&mut self) {
        self.payload_digest = digest_without_field(self);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawArtifactMetadata {
    pub host: String,
    pub organization: String,
    pub project_slug: String,
    pub pipeline_id: String,
    pub workflow_id: String,
    pub job_number: u64,
    pub attempt_id: String,
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
    pub media_type: Option<String>,
    pub content_digest: Option<Digest>,
    pub revision: u64,
    pub payload_digest: Digest,
}

impl RawArtifactMetadata {
    pub fn new(
        scope: &CircleCiScope,
        name: impl Into<String>,
        path: impl Into<String>,
        size_bytes: u64,
    ) -> Result<Self, CircleCiPipelineResultError> {
        let name = name.into();
        let path = path.into();
        let mut value = Self {
            host: scope.host.as_str().to_owned(),
            organization: scope.organization.clone(),
            project_slug: scope.project_slug.clone(),
            pipeline_id: scope.pipeline_id.clone(),
            workflow_id: scope.workflow_id.clone(),
            job_number: scope.job_number,
            attempt_id: scope.attempt_id.clone(),
            // A fixture has not downloaded artifact bytes. A real provider
            // may project a server-supplied digest only when CircleCI exposes
            // it as metadata; the default fixture intentionally leaves it
            // absent.
            content_digest: None,
            name,
            path,
            size_bytes,
            media_type: Some(String::from("application/octet-stream")),
            revision: scope.revisions.job,
            payload_digest: String::new(),
        };
        value.refresh_digest();
        Ok(value)
    }

    pub fn refresh_digest(&mut self) {
        self.payload_digest = digest_without_field(self);
    }
}

fn digest_without_field<T>(value: &T) -> Digest
where
    T: Serialize + Clone,
{
    let mut value = serde_json::to_value(value).expect("raw fixture serializes");
    if let Some(object) = value.as_object_mut() {
        object.remove("payloadDigest");
    }
    canonical_digest(&value)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureFailure {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited { retry_after_seconds: Option<u64> },
    Timeout,
    ServerFailure { status: u16 },
    AccessLost,
    MalformedResponse,
}

impl FixtureFailure {
    fn provider_error(&self) -> CircleCiProviderError {
        match self {
            Self::BadRequest => CircleCiProviderError::BadRequest,
            Self::Unauthorized => CircleCiProviderError::Unauthorized,
            Self::Forbidden => CircleCiProviderError::Forbidden,
            Self::NotFound => CircleCiProviderError::NotFound,
            Self::Conflict => CircleCiProviderError::Conflict,
            Self::RateLimited {
                retry_after_seconds,
            } => CircleCiProviderError::RateLimited {
                retry_after_seconds: *retry_after_seconds,
            },
            Self::Timeout => CircleCiProviderError::Timeout,
            Self::ServerFailure { status } => {
                CircleCiProviderError::ServerFailure { status: *status }
            }
            Self::AccessLost => CircleCiProviderError::AccessLost,
            Self::MalformedResponse => CircleCiProviderError::MalformedResponse,
        }
    }

    fn retry_after_seconds(&self) -> Option<u64> {
        match self {
            Self::RateLimited {
                retry_after_seconds,
            } => *retry_after_seconds,
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct CircleCiFixture {
    pipeline: RawPipeline,
    workflow_pages: Vec<Vec<RawWorkflow>>,
    job_pages: Vec<Vec<RawJob>>,
    approval_pages: Vec<Vec<RawApproval>>,
    artifact_pages: Vec<Vec<RawArtifactMetadata>>,
    failure: Option<FixtureFailure>,
    access_lost: bool,
    cursor_loop: bool,
    permission_digest: Digest,
}

impl fmt::Debug for CircleCiFixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CircleCiFixture")
            .field("pipeline", &"<redacted>")
            .field(
                "workflow_count",
                &self.workflow_pages.iter().map(Vec::len).sum::<usize>(),
            )
            .field(
                "job_count",
                &self.job_pages.iter().map(Vec::len).sum::<usize>(),
            )
            .field(
                "approval_count",
                &self.approval_pages.iter().map(Vec::len).sum::<usize>(),
            )
            .field(
                "artifact_count",
                &self.artifact_pages.iter().map(Vec::len).sum::<usize>(),
            )
            .field("permission_digest", &self.permission_digest)
            .field("failure", &self.failure)
            .field("access_lost", &self.access_lost)
            .field("cursor_loop", &self.cursor_loop)
            .finish()
    }
}

impl CircleCiFixture {
    pub fn new(pipeline: RawPipeline) -> Self {
        let permission_digest = pipeline.permission_digest.clone();
        Self {
            pipeline,
            workflow_pages: vec![Vec::new()],
            job_pages: vec![Vec::new()],
            approval_pages: vec![Vec::new()],
            artifact_pages: vec![Vec::new()],
            failure: None,
            access_lost: false,
            cursor_loop: false,
            permission_digest,
        }
    }

    #[must_use]
    pub fn with_workflows(mut self, values: Vec<RawWorkflow>) -> Self {
        self.workflow_pages = vec![values];
        self
    }

    #[must_use]
    pub fn with_workflow_pages(mut self, values: Vec<Vec<RawWorkflow>>) -> Self {
        self.workflow_pages = nonempty_pages(values);
        self
    }

    #[must_use]
    pub fn with_jobs(mut self, values: Vec<RawJob>) -> Self {
        self.job_pages = vec![values];
        self
    }

    #[must_use]
    pub fn with_job_pages(mut self, values: Vec<Vec<RawJob>>) -> Self {
        self.job_pages = nonempty_pages(values);
        self
    }

    #[must_use]
    pub fn with_approvals(mut self, values: Vec<RawApproval>) -> Self {
        self.approval_pages = vec![values];
        self
    }

    #[must_use]
    pub fn with_approval_pages(mut self, values: Vec<Vec<RawApproval>>) -> Self {
        self.approval_pages = nonempty_pages(values);
        self
    }

    #[must_use]
    pub fn with_artifact_metadata(mut self, values: Vec<RawArtifactMetadata>) -> Self {
        self.artifact_pages = vec![values];
        self
    }

    #[must_use]
    pub fn with_artifact_metadata_pages(mut self, values: Vec<Vec<RawArtifactMetadata>>) -> Self {
        self.artifact_pages = nonempty_pages(values);
        self
    }

    #[must_use]
    pub fn with_failure(mut self, failure: FixtureFailure) -> Self {
        self.failure = Some(failure);
        self
    }

    pub fn set_access_lost(&mut self, access_lost: bool) {
        self.access_lost = access_lost;
    }

    pub fn set_cursor_loop(&mut self, cursor_loop: bool) {
        self.cursor_loop = cursor_loop;
    }

    pub fn set_permission_digest(&mut self, permission_digest: impl Into<String>) {
        self.permission_digest = permission_digest.into();
        self.pipeline.permission_digest = self.permission_digest.clone();
        self.pipeline.refresh_digest();
    }

    pub fn pipeline_mut(&mut self) -> &mut RawPipeline {
        &mut self.pipeline
    }

    pub fn workflows_mut(&mut self) -> &mut Vec<Vec<RawWorkflow>> {
        &mut self.workflow_pages
    }

    pub fn jobs_mut(&mut self) -> &mut Vec<Vec<RawJob>> {
        &mut self.job_pages
    }

    pub fn approvals_mut(&mut self) -> &mut Vec<Vec<RawApproval>> {
        &mut self.approval_pages
    }

    pub fn artifacts_mut(&mut self) -> &mut Vec<Vec<RawArtifactMetadata>> {
        &mut self.artifact_pages
    }
}

fn nonempty_pages<T>(values: Vec<Vec<T>>) -> Vec<Vec<T>> {
    if values.is_empty() {
        vec![Vec::new()]
    } else {
        values
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureMode {
    Fixture,
    Recording,
    Loopback,
}

impl FixtureMode {
    const fn provenance(self) -> CircleCiProvenance {
        match self {
            Self::Fixture => CircleCiProvenance::Fixture,
            Self::Recording => CircleCiProvenance::Recording,
            Self::Loopback => CircleCiProvenance::Loopback,
        }
    }
}

#[derive(Clone)]
struct FixtureState {
    fixture: CircleCiFixture,
    mode: FixtureMode,
    operations: Vec<CircleCiTransportOperation>,
}

/// Deterministic fake transport used for fixture, recording, and loopback
/// evidence. It has no network path and therefore never claims Connected.
#[derive(Clone)]
pub struct CircleCiFixtureTransport {
    state: Arc<Mutex<FixtureState>>,
}

impl fmt::Debug for CircleCiFixtureTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CircleCiFixtureTransport")
            .field("provenance", &self.provenance())
            .field("operations", &self.operations().len())
            .finish()
    }
}

impl CircleCiFixtureTransport {
    pub fn fixture(fixture: CircleCiFixture) -> Self {
        Self::new(fixture, FixtureMode::Fixture)
    }

    pub fn recording(fixture: CircleCiFixture) -> Self {
        Self::new(fixture, FixtureMode::Recording)
    }

    pub fn loopback(fixture: CircleCiFixture) -> Self {
        Self::new(fixture, FixtureMode::Loopback)
    }

    fn new(fixture: CircleCiFixture, mode: FixtureMode) -> Self {
        Self {
            state: Arc::new(Mutex::new(FixtureState {
                fixture,
                mode,
                operations: Vec::new(),
            })),
        }
    }

    pub fn update_fixture(&self, update: impl FnOnce(&mut CircleCiFixture)) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        update(&mut state.fixture);
    }

    pub fn operations(&self) -> Vec<CircleCiTransportOperation> {
        self.state
            .lock()
            .map_or_else(|_| Vec::new(), |state| state.operations.clone())
    }

    fn provenance(&self) -> CircleCiProvenance {
        self.state
            .lock()
            .map_or(CircleCiProvenance::BlockedEnv, |state| {
                state.mode.provenance()
            })
    }

    fn call<T>(
        &self,
        endpoint: CircleCiEndpoint,
        page_token: Option<&CircleCiPageToken>,
        build: impl FnOnce(&CircleCiFixture, FixtureMode) -> Result<T, CircleCiProviderError>,
    ) -> Result<(T, CircleCiProvenance), CircleCiProviderError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CircleCiProviderError::TransportUnavailable)?;
        let provenance = state.mode.provenance();
        let page_token_digest = page_token.map(|value| value.digest().to_owned());
        let attempt = u32::try_from(
            state
                .operations
                .iter()
                .filter(|operation| operation.endpoint == endpoint)
                .count(),
        )
        .unwrap_or(u32::MAX)
        .saturating_add(1);
        let result = if state.fixture.access_lost {
            Err(CircleCiProviderError::AccessLost)
        } else if let Some(failure) = state.fixture.failure.clone() {
            Err(failure.provider_error())
        } else {
            build(&state.fixture, state.mode)
        };
        let (outcome, retry_after_seconds) = match &result {
            Ok(_) => (CircleCiTransportOutcome::Success, None),
            Err(error) => (
                CircleCiTransportOutcome::Failure {
                    error: provider_error_label(error),
                },
                state
                    .fixture
                    .failure
                    .as_ref()
                    .and_then(FixtureFailure::retry_after_seconds),
            ),
        };
        state.operations.push(CircleCiTransportOperation {
            endpoint,
            page_token_digest,
            attempt,
            retry_after_seconds,
            outcome,
            provenance,
            native_transport: false,
            native_connected: false,
        });
        result.map(|value| (value, provenance))
    }
}

fn provider_error_label(error: &CircleCiProviderError) -> String {
    match error {
        CircleCiProviderError::BadRequest => String::from("bad_request"),
        CircleCiProviderError::Unauthorized => String::from("unauthorized"),
        CircleCiProviderError::Forbidden => String::from("forbidden"),
        CircleCiProviderError::NotFound => String::from("not_found"),
        CircleCiProviderError::Conflict => String::from("conflict"),
        CircleCiProviderError::RateLimited { .. } => String::from("rate_limited"),
        CircleCiProviderError::Timeout => String::from("timeout"),
        CircleCiProviderError::ServerFailure { status } => format!("server_failure_{status}"),
        CircleCiProviderError::BlockedEnv => String::from("blocked_env"),
        CircleCiProviderError::MalformedResponse => String::from("malformed_response"),
        CircleCiProviderError::AccessLost => String::from("access_lost"),
        CircleCiProviderError::TransportUnavailable => String::from("transport_unavailable"),
    }
}

fn page_index(
    token: Option<&CircleCiPageToken>,
    endpoint: CircleCiEndpoint,
) -> Result<usize, CircleCiProviderError> {
    let Some(token) = token else {
        return Ok(0);
    };
    let prefix = match endpoint {
        CircleCiEndpoint::Workflows => "workflows",
        CircleCiEndpoint::Jobs => "jobs",
        CircleCiEndpoint::Approvals => "approvals",
        CircleCiEndpoint::ArtifactMetadata => "artifacts",
        CircleCiEndpoint::Pipeline => return Err(CircleCiProviderError::MalformedResponse),
    };
    let Some(index) = token.raw().strip_prefix(&format!("{prefix}:")) else {
        return Err(CircleCiProviderError::MalformedResponse);
    };
    index
        .parse::<usize>()
        .map_err(|_| CircleCiProviderError::MalformedResponse)
}

fn next_page_token(
    endpoint: CircleCiEndpoint,
    index: usize,
    page_count: usize,
    cursor_loop: bool,
) -> Option<CircleCiPageToken> {
    if cursor_loop {
        return CircleCiPageToken::new("circleci-loop-token").ok();
    }
    if index + 1 >= page_count {
        return None;
    }
    let prefix = match endpoint {
        CircleCiEndpoint::Workflows => "workflows",
        CircleCiEndpoint::Jobs => "jobs",
        CircleCiEndpoint::Approvals => "approvals",
        CircleCiEndpoint::ArtifactMetadata => "artifacts",
        CircleCiEndpoint::Pipeline => return None,
    };
    CircleCiPageToken::new(format!("{prefix}:{}", index + 1)).ok()
}

fn endpoint_digest(scope: &CircleCiScope, endpoint: CircleCiEndpoint) -> Digest {
    digest_parts([
        scope.host.as_str(),
        &scope.organization,
        &scope.project_slug,
        &scope.pipeline_id,
        &format!("{endpoint:?}"),
    ])
}

fn receipt<T: Serialize>(
    scope: &CircleCiScope,
    endpoint: CircleCiEndpoint,
    attempt: u32,
    response: &T,
    provenance: CircleCiProvenance,
) -> CircleCiTransportReceipt {
    CircleCiTransportReceipt {
        endpoint,
        endpoint_digest: endpoint_digest(scope, endpoint),
        attempt,
        response_digest: canonical_digest(response),
        retry_after_seconds: None,
        provenance,
        native_transport: false,
        native_connected: false,
    }
}

pub trait CircleCiTransport: Clone + fmt::Debug {
    fn provenance(&self) -> CircleCiProvenance;

    fn fetch_pipeline(
        &self,
        request: &CircleCiPipelineReadRequest,
        secret: &SecretMaterial,
    ) -> Result<CircleCiPipelineResponse, CircleCiProviderError>;

    fn fetch_workflows(
        &self,
        scope: &CircleCiScope,
        page_token: Option<&CircleCiPageToken>,
        secret: &SecretMaterial,
    ) -> Result<CircleCiPage<RawWorkflow>, CircleCiProviderError>;

    fn fetch_jobs(
        &self,
        scope: &CircleCiScope,
        page_token: Option<&CircleCiPageToken>,
        secret: &SecretMaterial,
    ) -> Result<CircleCiPage<RawJob>, CircleCiProviderError>;

    fn fetch_approvals(
        &self,
        scope: &CircleCiScope,
        page_token: Option<&CircleCiPageToken>,
        secret: &SecretMaterial,
    ) -> Result<CircleCiPage<RawApproval>, CircleCiProviderError>;

    fn fetch_artifact_metadata(
        &self,
        scope: &CircleCiScope,
        page_token: Option<&CircleCiPageToken>,
        secret: &SecretMaterial,
    ) -> Result<CircleCiPage<RawArtifactMetadata>, CircleCiProviderError>;

    fn operations(&self) -> Vec<CircleCiTransportOperation>;
}

impl CircleCiTransport for CircleCiFixtureTransport {
    fn provenance(&self) -> CircleCiProvenance {
        self.provenance()
    }

    fn fetch_pipeline(
        &self,
        request: &CircleCiPipelineReadRequest,
        secret: &SecretMaterial,
    ) -> Result<CircleCiPipelineResponse, CircleCiProviderError> {
        let _ = secret.value();
        let (pipeline, provenance) =
            self.call(CircleCiEndpoint::Pipeline, None, |fixture, _mode| {
                if fixture.pipeline.host.is_empty() {
                    return Err(CircleCiProviderError::MalformedResponse);
                }
                Ok(fixture.pipeline.clone())
            })?;
        let attempt = self
            .operations()
            .last()
            .map_or(1, |operation| operation.attempt);
        Ok(CircleCiPipelineResponse {
            receipt: receipt(
                &request.scope,
                CircleCiEndpoint::Pipeline,
                attempt,
                &pipeline,
                provenance,
            ),
            pipeline,
        })
    }

    fn fetch_workflows(
        &self,
        scope: &CircleCiScope,
        page_token: Option<&CircleCiPageToken>,
        secret: &SecretMaterial,
    ) -> Result<CircleCiPage<RawWorkflow>, CircleCiProviderError> {
        let _ = secret.value();
        let (page, provenance) =
            self.call(CircleCiEndpoint::Workflows, page_token, |fixture, _mode| {
                let index = if fixture.cursor_loop {
                    0
                } else {
                    page_index(page_token, CircleCiEndpoint::Workflows)?
                };
                let values = fixture
                    .workflow_pages
                    .get(index)
                    .ok_or(CircleCiProviderError::MalformedResponse)?
                    .clone();
                Ok((
                    values,
                    index,
                    fixture.workflow_pages.len(),
                    fixture.cursor_loop,
                ))
            })?;
        let (values, index, page_count, cursor_loop) = page;
        let attempt = self
            .operations()
            .last()
            .map_or(1, |operation| operation.attempt);
        Ok(CircleCiPage {
            next_page_token: next_page_token(
                CircleCiEndpoint::Workflows,
                index,
                page_count,
                cursor_loop,
            ),
            receipt: receipt(
                scope,
                CircleCiEndpoint::Workflows,
                attempt,
                &values,
                provenance,
            ),
            items: values,
        })
    }

    fn fetch_jobs(
        &self,
        scope: &CircleCiScope,
        page_token: Option<&CircleCiPageToken>,
        secret: &SecretMaterial,
    ) -> Result<CircleCiPage<RawJob>, CircleCiProviderError> {
        let _ = secret.value();
        let (page, provenance) =
            self.call(CircleCiEndpoint::Jobs, page_token, |fixture, _mode| {
                let index = if fixture.cursor_loop {
                    0
                } else {
                    page_index(page_token, CircleCiEndpoint::Jobs)?
                };
                let values = fixture
                    .job_pages
                    .get(index)
                    .ok_or(CircleCiProviderError::MalformedResponse)?
                    .clone();
                Ok((values, index, fixture.job_pages.len(), fixture.cursor_loop))
            })?;
        let (values, index, page_count, cursor_loop) = page;
        let attempt = self
            .operations()
            .last()
            .map_or(1, |operation| operation.attempt);
        Ok(CircleCiPage {
            next_page_token: next_page_token(
                CircleCiEndpoint::Jobs,
                index,
                page_count,
                cursor_loop,
            ),
            receipt: receipt(scope, CircleCiEndpoint::Jobs, attempt, &values, provenance),
            items: values,
        })
    }

    fn fetch_approvals(
        &self,
        scope: &CircleCiScope,
        page_token: Option<&CircleCiPageToken>,
        secret: &SecretMaterial,
    ) -> Result<CircleCiPage<RawApproval>, CircleCiProviderError> {
        let _ = secret.value();
        let (page, provenance) =
            self.call(CircleCiEndpoint::Approvals, page_token, |fixture, _mode| {
                let index = if fixture.cursor_loop {
                    0
                } else {
                    page_index(page_token, CircleCiEndpoint::Approvals)?
                };
                let values = fixture
                    .approval_pages
                    .get(index)
                    .ok_or(CircleCiProviderError::MalformedResponse)?
                    .clone();
                Ok((
                    values,
                    index,
                    fixture.approval_pages.len(),
                    fixture.cursor_loop,
                ))
            })?;
        let (values, index, page_count, cursor_loop) = page;
        let attempt = self
            .operations()
            .last()
            .map_or(1, |operation| operation.attempt);
        Ok(CircleCiPage {
            next_page_token: next_page_token(
                CircleCiEndpoint::Approvals,
                index,
                page_count,
                cursor_loop,
            ),
            receipt: receipt(
                scope,
                CircleCiEndpoint::Approvals,
                attempt,
                &values,
                provenance,
            ),
            items: values,
        })
    }

    fn fetch_artifact_metadata(
        &self,
        scope: &CircleCiScope,
        page_token: Option<&CircleCiPageToken>,
        secret: &SecretMaterial,
    ) -> Result<CircleCiPage<RawArtifactMetadata>, CircleCiProviderError> {
        let _ = secret.value();
        let (page, provenance) = self.call(
            CircleCiEndpoint::ArtifactMetadata,
            page_token,
            |fixture, _mode| {
                let index = if fixture.cursor_loop {
                    0
                } else {
                    page_index(page_token, CircleCiEndpoint::ArtifactMetadata)?
                };
                let values = fixture
                    .artifact_pages
                    .get(index)
                    .ok_or(CircleCiProviderError::MalformedResponse)?
                    .clone();
                Ok((
                    values,
                    index,
                    fixture.artifact_pages.len(),
                    fixture.cursor_loop,
                ))
            },
        )?;
        let (values, index, page_count, cursor_loop) = page;
        let attempt = self
            .operations()
            .last()
            .map_or(1, |operation| operation.attempt);
        Ok(CircleCiPage {
            next_page_token: next_page_token(
                CircleCiEndpoint::ArtifactMetadata,
                index,
                page_count,
                cursor_loop,
            ),
            receipt: receipt(
                scope,
                CircleCiEndpoint::ArtifactMetadata,
                attempt,
                &values,
                provenance,
            ),
            items: values,
        })
    }

    fn operations(&self) -> Vec<CircleCiTransportOperation> {
        self.operations()
    }
}

pub type FakeCircleCiTransport = CircleCiFixtureTransport;
pub type RecordingCircleCiTransport = CircleCiFixtureTransport;
pub type LoopbackCircleCiTransport = CircleCiFixtureTransport;
