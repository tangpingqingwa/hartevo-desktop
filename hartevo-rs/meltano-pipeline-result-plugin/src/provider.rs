use std::{collections::VecDeque, fmt};

use serde::Serialize;

use crate::error::{MeltanoPipelineResultError, MeltanoTransportError, Result};
use crate::model::{
    ALLOWLISTED_READ_OPERATIONS, Digest, FORBIDDEN_OPERATIONS, MeltanoConfigMetadata,
    MeltanoCursor, MeltanoEvidenceState, MeltanoJobId, MeltanoJobMetadata, MeltanoJobStatus,
    MeltanoPermissionSnapshot, MeltanoPipelineMetadata, MeltanoPipelineResultScope,
    MeltanoPipelineStatus, MeltanoPluginName, MeltanoRateLimitReceipt, MeltanoRetryReceipt,
    MeltanoStateId, MeltanoStateMetadata, MeltanoTransportProvenance, canonical_digest,
};
use crate::{
    MAX_METADATA_ITEMS, MAX_PAGE_SIZE, MAX_RESPONSE_BYTES, PROVIDER_API_REVISION, PROVIDER_ID,
};

pub const LIST_PIPELINES_OPERATION: &str = "list_pipelines";
pub const READ_PIPELINE_METADATA_OPERATION: &str = "read_pipeline_metadata";
pub const LIST_JOBS_OPERATION: &str = "list_jobs";
pub const READ_JOB_METADATA_OPERATION: &str = "read_job_metadata";
pub const READ_STATE_METADATA_OPERATION: &str = "read_state_metadata";
pub const READ_CONFIG_DIGEST_OPERATION: &str = "read_config_digest";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeltanoReadOperation {
    ListPipelines,
    ReadPipelineMetadata,
    ListJobs,
    ReadJobMetadata,
    ReadStateMetadata,
    ReadConfigDigest,
}

impl MeltanoReadOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListPipelines => LIST_PIPELINES_OPERATION,
            Self::ReadPipelineMetadata => READ_PIPELINE_METADATA_OPERATION,
            Self::ListJobs => LIST_JOBS_OPERATION,
            Self::ReadJobMetadata => READ_JOB_METADATA_OPERATION,
            Self::ReadStateMetadata => READ_STATE_METADATA_OPERATION,
            Self::ReadConfigDigest => READ_CONFIG_DIGEST_OPERATION,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MeltanoPipelineReadRequest {
    pub operation: MeltanoReadOperation,
    pub scope_digest: Digest,
    pub workspace_digest: Digest,
    pub cloud_project_digest: Digest,
    pub environment_digest: Digest,
    pub pipeline_digest: Digest,
    pub job_digest: Option<Digest>,
    pub plugin_digest: Option<Digest>,
    pub state_id_digest: Option<Digest>,
    pub page_size: u16,
    pub page_number: u16,
    pub cursor_digest: Option<Digest>,
    pub idempotency_digest: Digest,
    pub request_digest: Digest,
    scope: MeltanoPipelineResultScope,
    cursor: Option<MeltanoCursor>,
}

impl MeltanoPipelineReadRequest {
    pub fn for_scope(
        scope: &MeltanoPipelineResultScope,
        idempotency_key: impl Into<String>,
    ) -> Result<Self> {
        Self::new(
            scope,
            MeltanoReadOperation::ReadPipelineMetadata,
            MAX_PAGE_SIZE,
            1,
            None,
            idempotency_key,
        )
    }

    pub fn for_job(
        scope: &MeltanoPipelineResultScope,
        idempotency_key: impl Into<String>,
    ) -> Result<Self> {
        Self::new(
            scope,
            MeltanoReadOperation::ReadJobMetadata,
            MAX_PAGE_SIZE,
            1,
            None,
            idempotency_key,
        )
    }

    pub fn for_state(
        scope: &MeltanoPipelineResultScope,
        idempotency_key: impl Into<String>,
    ) -> Result<Self> {
        Self::new(
            scope,
            MeltanoReadOperation::ReadStateMetadata,
            MAX_PAGE_SIZE,
            1,
            None,
            idempotency_key,
        )
    }

    pub fn for_config(
        scope: &MeltanoPipelineResultScope,
        idempotency_key: impl Into<String>,
    ) -> Result<Self> {
        Self::new(
            scope,
            MeltanoReadOperation::ReadConfigDigest,
            MAX_PAGE_SIZE,
            1,
            None,
            idempotency_key,
        )
    }

    pub fn new(
        scope: &MeltanoPipelineResultScope,
        operation: MeltanoReadOperation,
        page_size: u16,
        page_number: u16,
        cursor: Option<MeltanoCursor>,
        idempotency_key: impl Into<String>,
    ) -> Result<Self> {
        scope.validate()?;
        let idempotency_key = idempotency_key.into();
        if !valid_request_key(&idempotency_key)
            || page_size == 0
            || page_size > MAX_PAGE_SIZE
            || page_number == 0
        {
            return Err(MeltanoPipelineResultError::InvalidRequest);
        }
        if let Some(cursor) = &cursor {
            cursor.validate_for_scope(scope)?;
        }
        let mut request = Self {
            operation,
            scope_digest: scope.digest(),
            workspace_digest: scope.workspace().digest(),
            cloud_project_digest: scope.cloud_project().digest(),
            environment_digest: scope.environment().digest(),
            pipeline_digest: scope.pipeline().digest(),
            job_digest: scope.job().map(MeltanoJobId::digest),
            plugin_digest: scope.plugin().map(MeltanoPluginName::digest),
            state_id_digest: scope.state_id().map(MeltanoStateId::digest),
            page_size,
            page_number,
            cursor_digest: cursor.as_ref().map(MeltanoCursor::digest),
            idempotency_digest: Digest::from_parts(
                "meltano-idempotency-key/v1",
                &[("key", idempotency_key)],
            ),
            request_digest: Digest::from_text("pending"),
            scope: scope.clone(),
            cursor,
        };
        request.request_digest = request.calculate_digest();
        Ok(request)
    }

    pub fn with_cursor(mut self, cursor: MeltanoCursor) -> Result<Self> {
        cursor.validate_for_scope(&self.scope)?;
        self.cursor_digest = Some(cursor.digest());
        self.cursor = Some(cursor);
        self.request_digest = self.calculate_digest();
        Ok(self)
    }

    fn calculate_digest(&self) -> Digest {
        canonical_digest(&RequestFingerprint {
            operation: self.operation,
            scope_digest: &self.scope_digest,
            workspace_digest: &self.workspace_digest,
            cloud_project_digest: &self.cloud_project_digest,
            environment_digest: &self.environment_digest,
            pipeline_digest: &self.pipeline_digest,
            job_digest: self.job_digest.as_ref(),
            plugin_digest: self.plugin_digest.as_ref(),
            state_id_digest: self.state_id_digest.as_ref(),
            page_size: self.page_size,
            page_number: self.page_number,
            cursor_digest: self.cursor_digest.as_ref(),
            idempotency_digest: &self.idempotency_digest,
        })
    }

    pub fn validate(&self, scope: &MeltanoPipelineResultScope) -> Result<()> {
        scope.validate()?;
        self.scope_digest.validate()?;
        self.idempotency_digest.validate()?;
        self.request_digest.validate()?;
        if self.scope_digest != scope.digest()
            || self.workspace_digest != scope.workspace().digest()
            || self.cloud_project_digest != scope.cloud_project().digest()
            || self.environment_digest != scope.environment().digest()
            || self.pipeline_digest != scope.pipeline().digest()
            || self.job_digest != scope.job().map(MeltanoJobId::digest)
            || self.plugin_digest != scope.plugin().map(MeltanoPluginName::digest)
            || self.state_id_digest != scope.state_id().map(MeltanoStateId::digest)
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.page_number == 0
            || self.request_digest != self.calculate_digest()
        {
            return Err(MeltanoPipelineResultError::ScopeMismatch);
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate_for_scope(scope)?;
            if self.cursor_digest != Some(cursor.digest()) {
                return Err(MeltanoPipelineResultError::RevisionMismatch);
            }
        } else if self.cursor_digest.is_some() {
            return Err(MeltanoPipelineResultError::TamperedEvidence);
        }
        match self.operation {
            MeltanoReadOperation::ReadJobMetadata if scope.job().is_none() => {
                Err(MeltanoPipelineResultError::InvalidRequest)
            }
            MeltanoReadOperation::ReadStateMetadata if scope.state_id().is_none() => {
                Err(MeltanoPipelineResultError::InvalidRequest)
            }
            MeltanoReadOperation::ReadConfigDigest if scope.plugin().is_none() => {
                Err(MeltanoPipelineResultError::InvalidRequest)
            }
            _ => Ok(()),
        }
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn scope(&self) -> &MeltanoPipelineResultScope {
        &self.scope
    }

    #[must_use]
    pub const fn operation(&self) -> MeltanoReadOperation {
        self.operation
    }

    #[must_use]
    pub fn cursor(&self) -> Option<&MeltanoCursor> {
        self.cursor.as_ref()
    }
}

#[derive(Serialize)]
struct RequestFingerprint<'a> {
    operation: MeltanoReadOperation,
    scope_digest: &'a Digest,
    workspace_digest: &'a Digest,
    cloud_project_digest: &'a Digest,
    environment_digest: &'a Digest,
    pipeline_digest: &'a Digest,
    job_digest: Option<&'a Digest>,
    plugin_digest: Option<&'a Digest>,
    state_id_digest: Option<&'a Digest>,
    page_size: u16,
    page_number: u16,
    cursor_digest: Option<&'a Digest>,
    idempotency_digest: &'a Digest,
}

fn valid_request_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MeltanoPipelineResultResponse {
    pub operation: MeltanoReadOperation,
    pub pipeline: Option<MeltanoPipelineMetadata>,
    pub job: Option<MeltanoJobMetadata>,
    pub state_metadata: Option<MeltanoStateMetadata>,
    pub config: Option<MeltanoConfigMetadata>,
    pub next_cursor: Option<MeltanoCursor>,
    pub has_more: bool,
    pub retry: Option<crate::model::MeltanoRetryReceipt>,
    pub rate_limit: Option<crate::model::MeltanoRateLimitReceipt>,
    pub status_code: u16,
    pub response_bytes: u64,
    pub transport: MeltanoTransportProvenance,
    pub response_digest: Digest,
}

impl MeltanoPipelineResultResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &MeltanoPipelineReadRequest,
        pipeline: Option<MeltanoPipelineMetadata>,
        job: Option<MeltanoJobMetadata>,
        state_metadata: Option<MeltanoStateMetadata>,
        config: Option<MeltanoConfigMetadata>,
        next_cursor: Option<MeltanoCursor>,
        has_more: bool,
        status_code: u16,
        response_bytes: u64,
        transport: MeltanoTransportProvenance,
    ) -> Result<Self> {
        request.validate(request.scope())?;
        if response_bytes > MAX_RESPONSE_BYTES
            || usize::from(pipeline.is_some()) + usize::from(job.is_some()) > MAX_METADATA_ITEMS
        {
            return Err(MeltanoPipelineResultError::BoundsExceeded);
        }
        if let Some(cursor) = &next_cursor {
            cursor.validate_for_scope(request.scope())?;
        }
        if let Some(value) = &pipeline {
            value.validate()?;
        }
        if let Some(value) = &job {
            value.validate()?;
        }
        if let Some(value) = &state_metadata {
            value.validate()?;
        }
        if let Some(value) = &config {
            value.validate()?;
        }
        let mut response = Self {
            operation: request.operation(),
            pipeline,
            job,
            state_metadata,
            config,
            next_cursor,
            has_more,
            retry: None,
            rate_limit: None,
            status_code,
            response_bytes,
            transport,
            response_digest: Digest::from_text("pending"),
        };
        response.response_digest = response.calculate_digest(request);
        Ok(response)
    }

    pub fn with_receipts(
        mut self,
        request: &MeltanoPipelineReadRequest,
        retry: Option<MeltanoRetryReceipt>,
        rate_limit: Option<MeltanoRateLimitReceipt>,
    ) -> Result<Self> {
        request.validate(request.scope())?;
        retry
            .as_ref()
            .map(MeltanoRetryReceipt::validate)
            .transpose()?;
        rate_limit
            .as_ref()
            .map(MeltanoRateLimitReceipt::validate)
            .transpose()?;
        self.retry = retry;
        self.rate_limit = rate_limit;
        self.response_digest = self.calculate_digest(request);
        Ok(self)
    }

    fn calculate_digest(&self, request: &MeltanoPipelineReadRequest) -> Digest {
        canonical_digest(&ResponseFingerprint {
            request_digest: request.request_digest(),
            operation: self.operation,
            pipeline: self.pipeline.as_ref(),
            job: self.job.as_ref(),
            state_metadata: self.state_metadata.as_ref(),
            config: self.config.as_ref(),
            next_cursor: self.next_cursor.as_ref(),
            has_more: self.has_more,
            retry: self.retry.as_ref(),
            rate_limit: self.rate_limit.as_ref(),
            status_code: self.status_code,
            response_bytes: self.response_bytes,
            transport: self.transport,
        })
    }

    pub(crate) fn rebind_transport(
        mut self,
        request: &MeltanoPipelineReadRequest,
        transport: MeltanoTransportProvenance,
    ) -> Self {
        self.transport = transport;
        self.response_digest = self.calculate_digest(request);
        self
    }

    pub fn validate(&self, request: &MeltanoPipelineReadRequest) -> Result<()> {
        request.validate(request.scope())?;
        if self.operation != request.operation()
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.response_digest != self.calculate_digest(request)
        {
            return Err(MeltanoPipelineResultError::TamperedEvidence);
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_for_scope(request.scope())?;
        }
        if self.has_more && self.next_cursor.is_none() {
            return Err(MeltanoPipelineResultError::PartialEvidence);
        }
        if let Some(value) = &self.pipeline {
            value.validate()?;
            if value.pipeline_digest != request.pipeline_digest {
                return Err(MeltanoPipelineResultError::ScopeMismatch);
            }
        }
        if let Some(value) = &self.job {
            value.validate()?;
            if Some(value.job_digest.clone()) != request.job_digest {
                return Err(MeltanoPipelineResultError::ScopeMismatch);
            }
        }
        if let Some(value) = &self.state_metadata {
            value.validate()?;
            if Some(value.state_id_digest.clone()) != request.state_id_digest {
                return Err(MeltanoPipelineResultError::ScopeMismatch);
            }
        }
        if let Some(value) = &self.config {
            value.validate()?;
            if value.plugin_digest.is_none() || value.plugin_digest != request.plugin_digest {
                return Err(MeltanoPipelineResultError::ScopeMismatch);
            }
        }
        self.retry
            .as_ref()
            .map(MeltanoRetryReceipt::validate)
            .transpose()?;
        self.rate_limit
            .as_ref()
            .map(MeltanoRateLimitReceipt::validate)
            .transpose()?;
        match self.operation {
            MeltanoReadOperation::ReadPipelineMetadata if self.pipeline.is_none() => {
                return Err(MeltanoPipelineResultError::InvalidResponse);
            }
            MeltanoReadOperation::ReadJobMetadata if self.job.is_none() => {
                return Err(MeltanoPipelineResultError::InvalidResponse);
            }
            MeltanoReadOperation::ReadStateMetadata if self.state_metadata.is_none() => {
                return Err(MeltanoPipelineResultError::InvalidResponse);
            }
            MeltanoReadOperation::ReadConfigDigest if self.config.is_none() => {
                return Err(MeltanoPipelineResultError::InvalidResponse);
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ResponseFingerprint<'a> {
    request_digest: &'a Digest,
    operation: MeltanoReadOperation,
    pipeline: Option<&'a MeltanoPipelineMetadata>,
    job: Option<&'a MeltanoJobMetadata>,
    state_metadata: Option<&'a MeltanoStateMetadata>,
    config: Option<&'a MeltanoConfigMetadata>,
    next_cursor: Option<&'a MeltanoCursor>,
    has_more: bool,
    retry: Option<&'a crate::model::MeltanoRetryReceipt>,
    rate_limit: Option<&'a crate::model::MeltanoRateLimitReceipt>,
    status_code: u16,
    response_bytes: u64,
    transport: MeltanoTransportProvenance,
}

pub trait MeltanoTransport: fmt::Debug {
    fn read(
        &mut self,
        request: &MeltanoPipelineReadRequest,
    ) -> std::result::Result<MeltanoPipelineResultResponse, MeltanoTransportError>;

    fn provenance(&self) -> MeltanoTransportProvenance;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecordedMeltanoRequest {
    pub operation: MeltanoReadOperation,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub idempotency_digest: Digest,
    pub page_size: u16,
    pub page_number: u16,
    pub cursor_digest: Option<Digest>,
}

impl RecordedMeltanoRequest {
    fn from_request(request: &MeltanoPipelineReadRequest) -> Self {
        Self {
            operation: request.operation,
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest.clone(),
            idempotency_digest: request.idempotency_digest.clone(),
            page_size: request.page_size,
            page_number: request.page_number,
            cursor_digest: request.cursor_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingTransport {
    responses: VecDeque<std::result::Result<MeltanoPipelineResultResponse, MeltanoTransportError>>,
    requests: Vec<RecordedMeltanoRequest>,
}

impl RecordingTransport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_response(&mut self, response: MeltanoPipelineResultResponse) {
        self.responses.push_back(Ok(response));
    }

    pub fn push_error(&mut self, error: MeltanoTransportError) {
        self.responses.push_back(Err(error));
    }

    #[must_use]
    pub fn requests(&self) -> &[RecordedMeltanoRequest] {
        &self.requests
    }
}

impl MeltanoTransport for RecordingTransport {
    fn read(
        &mut self,
        request: &MeltanoPipelineReadRequest,
    ) -> std::result::Result<MeltanoPipelineResultResponse, MeltanoTransportError> {
        self.requests
            .push(RecordedMeltanoRequest::from_request(request));
        self.responses
            .pop_front()
            .unwrap_or(Err(MeltanoTransportError::InvalidResponse))
    }

    fn provenance(&self) -> MeltanoTransportProvenance {
        MeltanoTransportProvenance::Recording
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    response: MeltanoPipelineResultResponse,
}

impl FixtureTransport {
    #[must_use]
    pub fn new(response: MeltanoPipelineResultResponse) -> Self {
        Self { response }
    }
}

impl MeltanoTransport for FixtureTransport {
    fn read(
        &mut self,
        _request: &MeltanoPipelineReadRequest,
    ) -> std::result::Result<MeltanoPipelineResultResponse, MeltanoTransportError> {
        Ok(self.response.clone())
    }

    fn provenance(&self) -> MeltanoTransportProvenance {
        MeltanoTransportProvenance::Fixture
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoopbackTransport;

impl LoopbackTransport {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl MeltanoTransport for LoopbackTransport {
    fn read(
        &mut self,
        request: &MeltanoPipelineReadRequest,
    ) -> std::result::Result<MeltanoPipelineResultResponse, MeltanoTransportError> {
        let scope = request.scope();
        let pipeline = MeltanoPipelineMetadata::for_scope(scope, MeltanoPipelineStatus::Ready)
            .map_err(|_| MeltanoTransportError::InvalidResponse)?;
        let job = scope
            .job()
            .map(|_| MeltanoJobMetadata::for_scope(scope, MeltanoJobStatus::Complete))
            .transpose()
            .map_err(|_| MeltanoTransportError::InvalidResponse)?;
        let state_metadata = scope
            .state_id()
            .map(|state_id| {
                MeltanoStateMetadata::new(
                    state_id,
                    Digest::from_text("loopback-singer-state"),
                    1,
                    0,
                    true,
                    0,
                )
            })
            .transpose()
            .map_err(|_| MeltanoTransportError::InvalidResponse)?;
        let config = scope
            .plugin()
            .map(|plugin| {
                MeltanoConfigMetadata::new(
                    Digest::from_text("loopback-config"),
                    0,
                    0,
                    Some(plugin.digest()),
                    scope.state_id().map(MeltanoStateId::digest),
                    0,
                )
            })
            .transpose()
            .map_err(|_| MeltanoTransportError::InvalidResponse)?;
        let (pipeline, job, state_metadata, config) = match request.operation() {
            MeltanoReadOperation::ListPipelines | MeltanoReadOperation::ReadPipelineMetadata => {
                (Some(pipeline), None, None, None)
            }
            MeltanoReadOperation::ListJobs | MeltanoReadOperation::ReadJobMetadata => {
                (None, job, None, None)
            }
            MeltanoReadOperation::ReadStateMetadata => (None, None, state_metadata, None),
            MeltanoReadOperation::ReadConfigDigest => (None, None, None, config),
        };
        MeltanoPipelineResultResponse::new(
            request,
            pipeline,
            job,
            state_metadata,
            config,
            None,
            false,
            200,
            512,
            MeltanoTransportProvenance::Loopback,
        )
        .map_err(|_| MeltanoTransportError::InvalidResponse)
    }

    fn provenance(&self) -> MeltanoTransportProvenance {
        MeltanoTransportProvenance::Loopback
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl MeltanoTransport for BlockedEnvTransport {
    fn read(
        &mut self,
        _request: &MeltanoPipelineReadRequest,
    ) -> std::result::Result<MeltanoPipelineResultResponse, MeltanoTransportError> {
        Err(MeltanoTransportError::BlockedEnv)
    }

    fn provenance(&self) -> MeltanoTransportProvenance {
        MeltanoTransportProvenance::BlockedEnv
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MeltanoProviderDefinition {
    pub id: String,
    pub api_revision: String,
    pub operations: Vec<String>,
    pub permissions: MeltanoPermissionSnapshot,
    pub max_requests_per_minute: u16,
    pub max_response_bytes: u64,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
    pub provider_digest: Digest,
}

impl Default for MeltanoProviderDefinition {
    fn default() -> Self {
        Self::layer_one()
    }
}

impl MeltanoProviderDefinition {
    #[must_use]
    pub fn layer_one() -> Self {
        let mut definition = Self {
            id: PROVIDER_ID.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            operations: ALLOWLISTED_READ_OPERATIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            permissions: MeltanoPermissionSnapshot::layer_one(),
            max_requests_per_minute: 60,
            max_response_bytes: MAX_RESPONSE_BYTES,
            connected: false,
            native: false,
            first_party: false,
            durable_provider_receipt: false,
            provider_digest: Digest::from_text("pending"),
        };
        definition.provider_digest = definition.calculate_digest();
        definition
    }

    fn calculate_digest(&self) -> Digest {
        canonical_digest(&ProviderFingerprint {
            id: &self.id,
            api_revision: &self.api_revision,
            operations: &self.operations,
            permissions: &self.permissions,
            max_requests_per_minute: self.max_requests_per_minute,
            max_response_bytes: self.max_response_bytes,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            durable_provider_receipt: self.durable_provider_receipt,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.permissions.validate()?;
        if self.id != PROVIDER_ID
            || self.api_revision != PROVIDER_API_REVISION
            || self.operations != ALLOWLISTED_READ_OPERATIONS
            || self
                .operations
                .iter()
                .any(|operation| FORBIDDEN_OPERATIONS.contains(&operation.as_str()))
            || self.connected
            || self.native
            || self.first_party
            || self.durable_provider_receipt
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.provider_digest != self.calculate_digest()
        {
            return Err(MeltanoPipelineResultError::ProviderDrift);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.provider_digest.clone()
    }
}

#[derive(Serialize)]
struct ProviderFingerprint<'a> {
    id: &'a str,
    api_revision: &'a str,
    operations: &'a [String],
    permissions: &'a MeltanoPermissionSnapshot,
    max_requests_per_minute: u16,
    max_response_bytes: u64,
    connected: bool,
    native: bool,
    first_party: bool,
    durable_provider_receipt: bool,
}

pub type MeltanoProviderError = MeltanoPipelineResultError;

pub struct MeltanoProvider<T: MeltanoTransport> {
    transport: T,
    definition: MeltanoProviderDefinition,
}

impl<T: MeltanoTransport> fmt::Debug for MeltanoProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MeltanoProvider")
            .field("definition", &self.definition)
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T: MeltanoTransport> MeltanoProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_definition(transport, MeltanoProviderDefinition::layer_one())
    }

    pub fn with_definition(transport: T, definition: MeltanoProviderDefinition) -> Result<Self> {
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn read(
        &mut self,
        request: &MeltanoPipelineReadRequest,
    ) -> Result<MeltanoPipelineResultResponse> {
        request.validate(request.scope())?;
        self.definition.validate()?;
        let response = self.transport.read(request)?;
        let response = response.rebind_transport(request, self.transport.provenance());
        response.validate(request)?;
        Ok(response)
    }

    #[must_use]
    pub fn definition(&self) -> &MeltanoProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    #[must_use]
    pub fn provenance(&self) -> MeltanoTransportProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn first_party(&self) -> bool {
        false
    }
}

#[allow(dead_code)]
const _PROVIDER_BOUNDARY_STATES: [MeltanoEvidenceState; 3] = [
    MeltanoEvidenceState::Queued,
    MeltanoEvidenceState::Running,
    MeltanoEvidenceState::Success,
];
