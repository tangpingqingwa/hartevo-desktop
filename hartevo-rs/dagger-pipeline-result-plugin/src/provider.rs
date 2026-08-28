use std::{collections::VecDeque, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::error::{DaggerPipelineResultError, DaggerTransportError, Result};
use crate::model::{
    ALLOWLISTED_READ_OPERATIONS, DaggerArtifactId, DaggerArtifactKind, DaggerArtifactMetadata,
    DaggerCommit, DaggerEvidenceState, DaggerExecutionId, DaggerPermissionSnapshot,
    DaggerPipelineResultMetadata, DaggerPipelineScope, DaggerRunStatus, Digest,
    FORBIDDEN_OPERATIONS, TransportProvenance, canonical_digest,
};
use crate::{
    MAX_METADATA_ITEMS, MAX_PAGE_SIZE, MAX_RESPONSE_BYTES, PROVIDER_API_REVISION, PROVIDER_ID,
};

pub const READ_MODULE_METADATA_OPERATION: &str = "read_module_metadata";
pub const READ_PIPELINE_RESULT_OPERATION: &str = "read_pipeline_result";
pub const READ_ARTIFACT_METADATA_OPERATION: &str = "read_artifact_metadata";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DaggerPipelineReadRequest {
    pub scope_digest: Digest,
    pub module_digest: Digest,
    pub pipeline_digest: Digest,
    pub function_digest: Digest,
    pub container_digest: Digest,
    pub commit_digest: Option<Digest>,
    pub artifact_digest: Option<Digest>,
    pub page_size: u16,
    pub page_number: u16,
    pub idempotency_digest: Digest,
    pub request_digest: Digest,
    scope: DaggerPipelineScope,
    execution: Option<DaggerExecutionId>,
}

impl DaggerPipelineReadRequest {
    pub fn for_scope(
        scope: &DaggerPipelineScope,
        idempotency_key: impl Into<String>,
    ) -> Result<Self> {
        Self::new(scope, MAX_PAGE_SIZE, 1, idempotency_key)
    }

    pub fn new(
        scope: &DaggerPipelineScope,
        page_size: u16,
        page_number: u16,
        idempotency_key: impl Into<String>,
    ) -> Result<Self> {
        scope.validate()?;
        let idempotency_key = idempotency_key.into();
        if !valid_request_key(&idempotency_key) {
            return Err(DaggerPipelineResultError::InvalidRequest);
        }
        if page_size == 0 || page_size > MAX_PAGE_SIZE || page_number == 0 {
            return Err(DaggerPipelineResultError::InvalidRequest);
        }
        let idempotency_digest =
            Digest::from_parts("dagger-idempotency-key/v1", &[("key", idempotency_key)]);
        let mut request = Self {
            scope_digest: scope.digest(),
            module_digest: scope.module().digest(),
            pipeline_digest: scope.pipeline().digest(),
            function_digest: scope.function().digest(),
            container_digest: scope.container().digest(),
            commit_digest: scope.commit().map(DaggerCommit::digest),
            artifact_digest: scope.artifact().map(DaggerArtifactId::digest),
            page_size,
            page_number,
            idempotency_digest,
            request_digest: Digest::from_text("pending"),
            scope: scope.clone(),
            execution: None,
        };
        request.request_digest = request.calculate_digest();
        Ok(request)
    }

    #[must_use]
    pub fn with_execution(mut self, execution: DaggerExecutionId) -> Self {
        self.execution = Some(execution);
        self.request_digest = self.calculate_digest();
        self
    }

    fn calculate_digest(&self) -> Digest {
        canonical_digest(&RequestFingerprint {
            scope_digest: &self.scope_digest,
            module_digest: &self.module_digest,
            pipeline_digest: &self.pipeline_digest,
            function_digest: &self.function_digest,
            container_digest: &self.container_digest,
            commit_digest: self.commit_digest.as_ref(),
            artifact_digest: self.artifact_digest.as_ref(),
            page_size: self.page_size,
            page_number: self.page_number,
            idempotency_digest: &self.idempotency_digest,
            execution: self.execution.as_ref(),
        })
    }

    pub fn validate(&self, scope: &DaggerPipelineScope) -> Result<()> {
        scope.validate()?;
        self.scope_digest.validate()?;
        self.idempotency_digest.validate()?;
        self.request_digest.validate()?;
        if self.scope_digest != scope.digest()
            || self.module_digest != scope.module().digest()
            || self.pipeline_digest != scope.pipeline().digest()
            || self.function_digest != scope.function().digest()
            || self.container_digest != scope.container().digest()
            || self.commit_digest != scope.commit().map(DaggerCommit::digest)
            || self.artifact_digest != scope.artifact().map(DaggerArtifactId::digest)
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.page_number == 0
            || self.request_digest != self.calculate_digest()
        {
            return Err(DaggerPipelineResultError::ScopeMismatch);
        }
        if let Some(execution) = &self.execution {
            execution.validate()?;
        }
        Ok(())
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn scope(&self) -> &DaggerPipelineScope {
        &self.scope
    }

    #[must_use]
    pub fn execution(&self) -> Option<&DaggerExecutionId> {
        self.execution.as_ref()
    }
}

#[derive(Serialize)]
struct RequestFingerprint<'a> {
    scope_digest: &'a Digest,
    module_digest: &'a Digest,
    pipeline_digest: &'a Digest,
    function_digest: &'a Digest,
    container_digest: &'a Digest,
    commit_digest: Option<&'a Digest>,
    artifact_digest: Option<&'a Digest>,
    page_size: u16,
    page_number: u16,
    idempotency_digest: &'a Digest,
    execution: Option<&'a DaggerExecutionId>,
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
pub struct DaggerPipelineResultResponse {
    pub result: DaggerPipelineResultMetadata,
    pub artifacts: Vec<DaggerArtifactMetadata>,
    pub status_code: u16,
    pub response_bytes: u64,
    pub transport: TransportProvenance,
    pub response_digest: Digest,
}

impl DaggerPipelineResultResponse {
    pub fn new(
        request: &DaggerPipelineReadRequest,
        result: DaggerPipelineResultMetadata,
        artifacts: Vec<DaggerArtifactMetadata>,
        status_code: u16,
        response_bytes: u64,
        transport: TransportProvenance,
    ) -> Result<Self> {
        if artifacts.len() > MAX_METADATA_ITEMS
            || response_bytes > MAX_RESPONSE_BYTES
            || usize::from(result.artifact_count) != artifacts.len()
        {
            return Err(DaggerPipelineResultError::BoundsExceeded);
        }
        result.validate()?;
        for artifact in &artifacts {
            artifact.validate()?;
        }
        let mut response = Self {
            result,
            artifacts,
            status_code,
            response_bytes,
            transport,
            response_digest: Digest::from_text("pending"),
        };
        response.response_digest = response.calculate_digest(request);
        Ok(response)
    }

    fn calculate_digest(&self, request: &DaggerPipelineReadRequest) -> Digest {
        canonical_digest(&ResponseFingerprint {
            request_digest: request.request_digest(),
            result: &self.result,
            artifacts: &self.artifacts,
            status_code: self.status_code,
            response_bytes: self.response_bytes,
            transport: self.transport,
        })
    }

    pub(crate) fn rebind_transport(
        mut self,
        request: &DaggerPipelineReadRequest,
        transport: TransportProvenance,
    ) -> Self {
        self.transport = transport;
        self.response_digest = self.calculate_digest(request);
        self
    }

    pub fn validate(&self, request: &DaggerPipelineReadRequest) -> Result<()> {
        request.validate(request.scope())?;
        if self.artifacts.len() > MAX_METADATA_ITEMS
            || self.response_bytes > MAX_RESPONSE_BYTES
            || usize::from(self.result.artifact_count) != self.artifacts.len()
            || self.response_digest != self.calculate_digest(request)
        {
            return Err(DaggerPipelineResultError::TamperedEvidence);
        }
        self.result.validate()?;
        for artifact in &self.artifacts {
            artifact.validate()?;
        }
        if self.result.pipeline_digest != request.pipeline_digest
            || self.result.function_digest != request.function_digest
            || self.result.container_digest != request.container_digest
            || self.result.commit_digest != request.commit_digest
            || request
                .execution()
                .is_some_and(|execution| self.result.execution != *execution)
            || request.scope().artifact().is_some_and(|artifact| {
                !self
                    .artifacts
                    .iter()
                    .any(|metadata| metadata.artifact == *artifact)
            })
        {
            return Err(DaggerPipelineResultError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ResponseFingerprint<'a> {
    request_digest: &'a Digest,
    result: &'a DaggerPipelineResultMetadata,
    artifacts: &'a [DaggerArtifactMetadata],
    status_code: u16,
    response_bytes: u64,
    transport: TransportProvenance,
}

pub trait DaggerTransport: fmt::Debug {
    fn read(
        &mut self,
        request: &DaggerPipelineReadRequest,
    ) -> std::result::Result<DaggerPipelineResultResponse, DaggerTransportError>;

    fn provenance(&self) -> TransportProvenance;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecordedDaggerRequest {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub idempotency_digest: Digest,
    pub page_size: u16,
    pub page_number: u16,
}

impl RecordedDaggerRequest {
    fn from_request(request: &DaggerPipelineReadRequest) -> Self {
        Self {
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest.clone(),
            idempotency_digest: request.idempotency_digest.clone(),
            page_size: request.page_size,
            page_number: request.page_number,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingTransport {
    responses: VecDeque<std::result::Result<DaggerPipelineResultResponse, DaggerTransportError>>,
    requests: Vec<RecordedDaggerRequest>,
}

impl RecordingTransport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_response(&mut self, response: DaggerPipelineResultResponse) {
        self.responses.push_back(Ok(response));
    }

    pub fn push_error(&mut self, error: DaggerTransportError) {
        self.responses.push_back(Err(error));
    }

    #[must_use]
    pub fn requests(&self) -> &[RecordedDaggerRequest] {
        &self.requests
    }
}

impl DaggerTransport for RecordingTransport {
    fn read(
        &mut self,
        request: &DaggerPipelineReadRequest,
    ) -> std::result::Result<DaggerPipelineResultResponse, DaggerTransportError> {
        self.requests
            .push(RecordedDaggerRequest::from_request(request));
        self.responses
            .pop_front()
            .unwrap_or(Err(DaggerTransportError::InvalidResponse))
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    response: DaggerPipelineResultResponse,
}

impl FixtureTransport {
    #[must_use]
    pub fn new(response: DaggerPipelineResultResponse) -> Self {
        Self { response }
    }
}

impl DaggerTransport for FixtureTransport {
    fn read(
        &mut self,
        _request: &DaggerPipelineReadRequest,
    ) -> std::result::Result<DaggerPipelineResultResponse, DaggerTransportError> {
        Ok(self.response.clone())
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
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

impl DaggerTransport for LoopbackTransport {
    fn read(
        &mut self,
        request: &DaggerPipelineReadRequest,
    ) -> std::result::Result<DaggerPipelineResultResponse, DaggerTransportError> {
        let execution = request.execution().cloned().unwrap_or_else(|| {
            DaggerExecutionId::new(format!(
                "execution-{}",
                &request.request_digest().as_str()[..12]
            ))
            .expect("loopback execution id")
        });
        let artifact_id = request.scope().artifact().cloned().unwrap_or_else(|| {
            DaggerArtifactId::new("loopback-artifact").expect("loopback artifact id")
        });
        let artifact = DaggerArtifactMetadata::new(
            artifact_id,
            DaggerArtifactKind::OciImage,
            Digest::from_text("loopback-artifact-content").as_str(),
            0,
            "application/vnd.oci.image.manifest.v1+json",
            0,
        )
        .map_err(|_| DaggerTransportError::InvalidResponse)?;
        let result = DaggerPipelineResultMetadata::new(
            request.scope(),
            execution,
            DaggerRunStatus::Succeeded,
            0,
            Some(0),
            Some(0),
            1,
        )
        .map_err(|_| DaggerTransportError::InvalidResponse)?;
        DaggerPipelineResultResponse::new(
            request,
            result,
            vec![artifact],
            200,
            512,
            TransportProvenance::Loopback,
        )
        .map_err(|_| DaggerTransportError::InvalidResponse)
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl DaggerTransport for BlockedEnvTransport {
    fn read(
        &mut self,
        _request: &DaggerPipelineReadRequest,
    ) -> std::result::Result<DaggerPipelineResultResponse, DaggerTransportError> {
        Err(DaggerTransportError::BlockedEnv)
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DaggerProviderDefinition {
    pub id: String,
    pub api_revision: String,
    pub operations: Vec<String>,
    pub permissions: DaggerPermissionSnapshot,
    pub max_requests_per_minute: u16,
    pub max_response_bytes: u64,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
    pub provider_digest: Digest,
}

impl Default for DaggerProviderDefinition {
    fn default() -> Self {
        Self::layer_one()
    }
}

impl DaggerProviderDefinition {
    #[must_use]
    pub fn layer_one() -> Self {
        let mut definition = Self {
            id: PROVIDER_ID.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            operations: ALLOWLISTED_READ_OPERATIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            permissions: DaggerPermissionSnapshot::layer_one(),
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
            return Err(DaggerPipelineResultError::ProviderDrift);
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
    permissions: &'a DaggerPermissionSnapshot,
    max_requests_per_minute: u16,
    max_response_bytes: u64,
    connected: bool,
    native: bool,
    first_party: bool,
    durable_provider_receipt: bool,
}

pub type DaggerProviderError = DaggerPipelineResultError;

pub struct DaggerProvider<T: DaggerTransport> {
    transport: T,
    definition: DaggerProviderDefinition,
}

impl<T: DaggerTransport> fmt::Debug for DaggerProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaggerProvider")
            .field("definition", &self.definition)
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T: DaggerTransport> DaggerProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_definition(transport, DaggerProviderDefinition::layer_one())
    }

    pub fn with_definition(transport: T, definition: DaggerProviderDefinition) -> Result<Self> {
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn read(
        &mut self,
        request: &DaggerPipelineReadRequest,
    ) -> Result<DaggerPipelineResultResponse> {
        request.validate(request.scope())?;
        self.definition.validate()?;
        let response = self.transport.read(request)?;
        let response = response.rebind_transport(request, self.transport.provenance());
        response.validate(request)?;
        Ok(response)
    }

    #[must_use]
    pub fn definition(&self) -> &DaggerProviderDefinition {
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
    pub fn provenance(&self) -> TransportProvenance {
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
}

#[allow(dead_code)]
const _PROVIDER_BOUNDARY_STATES: [DaggerEvidenceState; 3] = [
    DaggerEvidenceState::Queued,
    DaggerEvidenceState::Running,
    DaggerEvidenceState::Succeeded,
];

#[derive(Debug, Error)]
#[error("Dagger provider operation is not available in Layer 1")]
pub struct DaggerProviderOperationUnavailable;
