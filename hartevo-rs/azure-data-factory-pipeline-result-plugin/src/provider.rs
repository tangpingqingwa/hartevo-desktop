//! Provider and transport seams for the allowlisted Azure Data Factory reads.
//!
//! There is intentionally no HTTP implementation here. The four transport
//! modes are explicit fixture, recording, loopback, and `BLOCKED_ENV` seams;
//! each reports non-native, non-connected, non-first-party provenance.

use std::{collections::BTreeSet, collections::VecDeque, fmt};

use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    ActivityRunMetadata, AzureDataFactoryScope, Digest, OpaqueContinuation, PipelineMetadata,
    PipelineRunMetadata, ProviderResponseReceipt, SecretReference, TransportProvenance, api_digest,
    canonical_digest, evidence_policy_digest, provider_digest,
};
use crate::{
    API_ORIGIN, API_REVISION, API_VERSION, AzureDataFactoryPipelineResultError, MAX_ACTIVITIES,
    MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES, PROVIDER_ID, PROVIDER_VERSION, Result,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AzureDataFactoryOperation {
    PipelinesGet,
    PipelineRunsGet,
    ActivityRunsQueryByPipelineRun,
}

impl AzureDataFactoryOperation {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PipelinesGet => "Pipelines - Get",
            Self::PipelineRunsGet => "Pipeline Runs - Get",
            Self::ActivityRunsQueryByPipelineRun => "Activity Runs - Query By Pipeline Run",
        }
    }

    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            Self::PipelinesGet | Self::PipelineRunsGet => "GET",
            Self::ActivityRunsQueryByPipelineRun => "POST",
        }
    }

    #[must_use]
    pub const fn path_template(self) -> &'static str {
        match self {
            Self::PipelinesGet => {
                "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataFactory/factories/{factoryName}/pipelines/{pipelineName}"
            }
            Self::PipelineRunsGet => {
                "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/microsoft.DataFactory/factories/{factoryName}/pipelineruns/{runId}"
            }
            Self::ActivityRunsQueryByPipelineRun => {
                "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/microsoft.DataFactory/factories/{factoryName}/pipelineruns/{runId}/queryActivityruns"
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureDataFactoryRequest {
    pub operation: AzureDataFactoryOperation,
    pub method: String,
    pub origin: String,
    pub path_template: String,
    pub api_version: String,
    pub provider_revision: String,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub pipeline_digest: Digest,
    pub pipeline_run_digest: Digest,
    pub activity_window_digest: Option<Digest>,
    pub continuation_digest: Option<Digest>,
    pub page: usize,
    pub page_size: usize,
    pub request_digest: Digest,
}

pub type GetPipelineRequest = AzureDataFactoryRequest;
pub type GetPipelineRunRequest = AzureDataFactoryRequest;
pub type ActivityRunsQueryRequest = AzureDataFactoryRequest;

impl AzureDataFactoryRequest {
    fn build(
        operation: AzureDataFactoryOperation,
        scope: &AzureDataFactoryScope,
        continuation: Option<&OpaqueContinuation>,
    ) -> Result<Self> {
        if let Some(cursor) = continuation {
            cursor.validate(scope)?;
        }
        let continuation_digest = continuation.map(|cursor| cursor.digest().clone());
        let page = continuation.map_or(1, OpaqueContinuation::page);
        let activity_window_digest = matches!(
            operation,
            AzureDataFactoryOperation::ActivityRunsQueryByPipelineRun
        )
        .then(|| scope.activity_window().digest().clone());
        let pipeline_digest = Digest::from_text(scope.pipeline_name().as_str());
        let pipeline_run_digest = Digest::from_text(scope.pipeline_run_id().as_str());
        let request_digest = canonical_digest(&(
            "azure-data-factory-request/v1",
            operation,
            operation.method(),
            API_ORIGIN,
            operation.path_template(),
            API_VERSION,
            API_REVISION,
            scope.scope_digest(),
            scope.permissions().digest(),
            &pipeline_digest,
            &pipeline_run_digest,
            &activity_window_digest,
            &continuation_digest,
            page,
            MAX_PAGE_SIZE,
        ));
        Ok(Self {
            operation,
            method: operation.method().to_owned(),
            origin: API_ORIGIN.to_owned(),
            path_template: operation.path_template().to_owned(),
            api_version: API_VERSION.to_owned(),
            provider_revision: API_REVISION.to_owned(),
            scope_digest: scope.scope_digest().clone(),
            permission_digest: scope.permissions().digest().clone(),
            pipeline_digest,
            pipeline_run_digest,
            activity_window_digest,
            continuation_digest,
            page,
            page_size: MAX_PAGE_SIZE,
            request_digest,
        })
    }

    pub fn get_pipeline(scope: &AzureDataFactoryScope) -> Result<GetPipelineRequest> {
        Self::build(AzureDataFactoryOperation::PipelinesGet, scope, None)
    }

    pub fn get_pipeline_run(scope: &AzureDataFactoryScope) -> Result<GetPipelineRunRequest> {
        Self::build(AzureDataFactoryOperation::PipelineRunsGet, scope, None)
    }

    pub fn query_activity_runs(
        scope: &AzureDataFactoryScope,
        continuation: Option<&OpaqueContinuation>,
    ) -> Result<ActivityRunsQueryRequest> {
        Self::build(
            AzureDataFactoryOperation::ActivityRunsQueryByPipelineRun,
            scope,
            continuation,
        )
    }

    pub fn validate(&self) -> Result<()> {
        self.scope_digest.validate()?;
        self.permission_digest.validate()?;
        self.pipeline_digest.validate()?;
        self.pipeline_run_digest.validate()?;
        if let Some(digest) = &self.activity_window_digest {
            digest.validate()?;
        }
        if let Some(digest) = &self.continuation_digest {
            digest.validate()?;
        }
        self.request_digest.validate()?;
        if self.page == 0
            || self.page > MAX_PAGES
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
        {
            return Err(AzureDataFactoryPipelineResultError::PaginationLimit);
        }
        let expected_request_digest = canonical_digest(&(
            "azure-data-factory-request/v1",
            self.operation,
            &self.method,
            &self.origin,
            &self.path_template,
            &self.api_version,
            &self.provider_revision,
            &self.scope_digest,
            &self.permission_digest,
            &self.pipeline_digest,
            &self.pipeline_run_digest,
            &self.activity_window_digest,
            &self.continuation_digest,
            self.page,
            self.page_size,
        ));
        if self.request_digest != expected_request_digest {
            return Err(AzureDataFactoryPipelineResultError::Tampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderTransportError {
    #[error("native Azure Data Factory environment is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Azure Data Factory access was lost")]
    AccessLost,
    #[error("Azure Data Factory transport timed out")]
    Timeout,
    #[error("Azure Data Factory provider is unknown")]
    ProviderUnknown,
    #[error("Azure Data Factory returned HTTP status {status_code}")]
    HttpStatus { status_code: u16 },
}

pub type TransportError = ProviderTransportError;
pub type AzureDataFactoryProviderError = AzureDataFactoryPipelineResultError;
pub type AzureDataFactoryTransportError = ProviderTransportError;

pub trait AzureDataFactoryTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn execute(
        &mut self,
        request: &AzureDataFactoryRequest,
    ) -> std::result::Result<AzureDataFactoryResponse, ProviderTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetPipelineResponse {
    pub status_code: u16,
    pub pipeline: PipelineMetadata,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub declared_response_digest: Digest,
    pub scope_digest: Digest,
    pub provenance: TransportProvenance,
}

impl GetPipelineResponse {
    pub fn new(
        request: &GetPipelineRequest,
        pipeline: PipelineMetadata,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if request.operation != AzureDataFactoryOperation::PipelinesGet {
            return Err(AzureDataFactoryPipelineResultError::InvalidProviderResponse);
        }
        pipeline.validate()?;
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(AzureDataFactoryPipelineResultError::ResponseTooLarge);
        }
        let response_digest = canonical_digest(&(
            "azure-data-factory-get-pipeline-response/v1",
            &pipeline,
            response_bytes,
            &request.scope_digest,
        ));
        Ok(Self {
            status_code: 200,
            pipeline,
            response_bytes,
            response_digest: response_digest.clone(),
            declared_response_digest: response_digest,
            scope_digest: request.scope_digest.clone(),
            provenance,
        })
    }

    #[must_use]
    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.declared_response_digest = digest;
        self
    }

    fn validate(&self, request: &GetPipelineRequest) -> Result<()> {
        if self.status_code != 200 || self.scope_digest != request.scope_digest {
            return Err(AzureDataFactoryPipelineResultError::InvalidProviderResponse);
        }
        self.pipeline.validate()?;
        let expected = canonical_digest(&(
            "azure-data-factory-get-pipeline-response/v1",
            &self.pipeline,
            self.response_bytes,
            &request.scope_digest,
        ));
        if self.response_digest != expected || self.declared_response_digest != expected {
            return Err(AzureDataFactoryPipelineResultError::Tampered);
        }
        Ok(())
    }

    fn receipt(&self, request: &AzureDataFactoryRequest) -> ProviderResponseReceipt {
        ProviderResponseReceipt {
            operation: request.operation.name().to_owned(),
            method: request.method.clone(),
            path_template: request.path_template.clone(),
            api_version: request.api_version.clone(),
            provider_revision: request.provider_revision.clone(),
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            continuation_digest: None,
            request_digest: request.request_digest.clone(),
            response_status: self.status_code,
            response_bytes: self.response_bytes,
            response_digest: self.response_digest.clone(),
            provenance: self.provenance,
            redacted: true,
        }
    }
}

pub type PipelineResponse = GetPipelineResponse;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetPipelineRunResponse {
    pub status_code: u16,
    pub pipeline_run: PipelineRunMetadata,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub declared_response_digest: Digest,
    pub scope_digest: Digest,
    pub provenance: TransportProvenance,
}

impl GetPipelineRunResponse {
    pub fn new(
        request: &GetPipelineRunRequest,
        pipeline_run: PipelineRunMetadata,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if request.operation != AzureDataFactoryOperation::PipelineRunsGet {
            return Err(AzureDataFactoryPipelineResultError::InvalidProviderResponse);
        }
        pipeline_run.validate()?;
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(AzureDataFactoryPipelineResultError::ResponseTooLarge);
        }
        let response_digest = canonical_digest(&(
            "azure-data-factory-get-pipeline-run-response/v1",
            &pipeline_run,
            response_bytes,
            &request.scope_digest,
        ));
        Ok(Self {
            status_code: 200,
            pipeline_run,
            response_bytes,
            response_digest: response_digest.clone(),
            declared_response_digest: response_digest,
            scope_digest: request.scope_digest.clone(),
            provenance,
        })
    }

    #[must_use]
    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.declared_response_digest = digest;
        self
    }

    fn validate(&self, request: &GetPipelineRunRequest) -> Result<()> {
        if self.status_code != 200 || self.scope_digest != request.scope_digest {
            return Err(AzureDataFactoryPipelineResultError::InvalidProviderResponse);
        }
        self.pipeline_run.validate()?;
        let expected = canonical_digest(&(
            "azure-data-factory-get-pipeline-run-response/v1",
            &self.pipeline_run,
            self.response_bytes,
            &request.scope_digest,
        ));
        if self.response_digest != expected || self.declared_response_digest != expected {
            return Err(AzureDataFactoryPipelineResultError::Tampered);
        }
        Ok(())
    }

    fn receipt(&self, request: &AzureDataFactoryRequest) -> ProviderResponseReceipt {
        ProviderResponseReceipt {
            operation: request.operation.name().to_owned(),
            method: request.method.clone(),
            path_template: request.path_template.clone(),
            api_version: request.api_version.clone(),
            provider_revision: request.provider_revision.clone(),
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            continuation_digest: None,
            request_digest: request.request_digest.clone(),
            response_status: self.status_code,
            response_bytes: self.response_bytes,
            response_digest: self.response_digest.clone(),
            provenance: self.provenance,
            redacted: true,
        }
    }
}

pub type PipelineRunResponse = GetPipelineRunResponse;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivityRunsQueryResponse {
    pub status_code: u16,
    pub page: usize,
    pub activities: Vec<ActivityRunMetadata>,
    pub next_continuation: Option<OpaqueContinuation>,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub declared_response_digest: Digest,
    pub scope_digest: Digest,
    pub provenance: TransportProvenance,
}

impl ActivityRunsQueryResponse {
    pub fn new(
        request: &ActivityRunsQueryRequest,
        activities: Vec<ActivityRunMetadata>,
        next_continuation: Option<OpaqueContinuation>,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if request.operation != AzureDataFactoryOperation::ActivityRunsQueryByPipelineRun {
            return Err(AzureDataFactoryPipelineResultError::InvalidProviderResponse);
        }
        if activities.len() > MAX_ACTIVITIES || response_bytes > MAX_RESPONSE_BYTES {
            return Err(AzureDataFactoryPipelineResultError::ResponseTooLarge);
        }
        if let Some(cursor) = &next_continuation
            && cursor.page() != request.page + 1
        {
            return Err(AzureDataFactoryPipelineResultError::ContinuationMismatch);
        }
        for activity in &activities {
            activity.validate()?;
        }
        let response_digest = canonical_digest(&(
            "azure-data-factory-query-activity-runs-response/v1",
            request.page,
            &activities,
            &next_continuation,
            response_bytes,
            &request.scope_digest,
        ));
        Ok(Self {
            status_code: 200,
            page: request.page,
            activities,
            next_continuation,
            response_bytes,
            response_digest: response_digest.clone(),
            declared_response_digest: response_digest,
            scope_digest: request.scope_digest.clone(),
            provenance,
        })
    }

    #[must_use]
    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.declared_response_digest = digest;
        self
    }

    fn validate(&self, request: &ActivityRunsQueryRequest) -> Result<()> {
        if self.status_code != 200
            || self.page != request.page
            || self.scope_digest != request.scope_digest
            || self.activities.len() > MAX_ACTIVITIES
        {
            return Err(AzureDataFactoryPipelineResultError::InvalidProviderResponse);
        }
        for activity in &self.activities {
            activity.validate()?;
        }
        if let Some(cursor) = &self.next_continuation {
            cursor.validate_scope_digest(&request.scope_digest, request.page + 1)?;
        }
        let expected = canonical_digest(&(
            "azure-data-factory-query-activity-runs-response/v1",
            request.page,
            &self.activities,
            &self.next_continuation,
            self.response_bytes,
            &request.scope_digest,
        ));
        if self.response_digest != expected || self.declared_response_digest != expected {
            return Err(AzureDataFactoryPipelineResultError::Tampered);
        }
        Ok(())
    }

    fn receipt(&self, request: &AzureDataFactoryRequest) -> ProviderResponseReceipt {
        ProviderResponseReceipt {
            operation: request.operation.name().to_owned(),
            method: request.method.clone(),
            path_template: request.path_template.clone(),
            api_version: request.api_version.clone(),
            provider_revision: request.provider_revision.clone(),
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            continuation_digest: request.continuation_digest.clone(),
            request_digest: request.request_digest.clone(),
            response_status: self.status_code,
            response_bytes: self.response_bytes,
            response_digest: self.response_digest.clone(),
            provenance: self.provenance,
            redacted: true,
        }
    }
}

pub type ActivityRunsResponse = ActivityRunsQueryResponse;

impl OpaqueContinuation {
    pub(crate) fn validate_scope_digest(
        &self,
        scope_digest: &Digest,
        expected_page: usize,
    ) -> Result<()> {
        self.digest().validate()?;
        self.binding_digest().validate()?;
        if self.page() != expected_page || expected_page == 0 || expected_page > MAX_PAGES {
            return Err(AzureDataFactoryPipelineResultError::ContinuationMismatch);
        }
        let _ = scope_digest;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AzureDataFactoryResponse {
    Pipeline(GetPipelineResponse),
    PipelineRun(GetPipelineRunResponse),
    ActivityRuns(ActivityRunsQueryResponse),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedRequest {
    pub operation: AzureDataFactoryOperation,
    pub method: String,
    pub path_template: String,
    pub scope_digest: Digest,
    pub continuation_digest: Option<Digest>,
    pub request_digest: Digest,
}

impl From<&AzureDataFactoryRequest> for RecordedRequest {
    fn from(request: &AzureDataFactoryRequest) -> Self {
        Self {
            operation: request.operation,
            method: request.method.clone(),
            path_template: request.path_template.clone(),
            scope_digest: request.scope_digest.clone(),
            continuation_digest: request.continuation_digest.clone(),
            request_digest: request.request_digest.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    pipeline: GetPipelineResponse,
    pipeline_run: GetPipelineRunResponse,
    activity_pages: VecDeque<ActivityRunsQueryResponse>,
}

impl FixtureTransport {
    #[must_use]
    pub fn new(
        pipeline: GetPipelineResponse,
        pipeline_run: GetPipelineRunResponse,
        activity_pages: impl IntoIterator<Item = ActivityRunsQueryResponse>,
    ) -> Self {
        Self {
            pipeline,
            pipeline_run,
            activity_pages: activity_pages.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn for_scope(scope: &AzureDataFactoryScope) -> Self {
        let observed_at = Utc
            .timestamp_opt(1_780_000_000, 0)
            .single()
            .expect("fixture timestamp is valid");
        let pipeline_request = AzureDataFactoryRequest::get_pipeline(scope).expect("request");
        let pipeline = GetPipelineResponse::new(
            &pipeline_request,
            PipelineMetadata::fixture(scope, observed_at),
            512,
            TransportProvenance::Fixture,
        )
        .expect("pipeline fixture");
        let run_request = AzureDataFactoryRequest::get_pipeline_run(scope).expect("request");
        let pipeline_run = GetPipelineRunResponse::new(
            &run_request,
            PipelineRunMetadata::fixture(scope, observed_at),
            768,
            TransportProvenance::Fixture,
        )
        .expect("pipeline-run fixture");
        let activity_request =
            AzureDataFactoryRequest::query_activity_runs(scope, None).expect("request");
        let activities = vec![
            ActivityRunMetadata::fixture(0, observed_at),
            ActivityRunMetadata::fixture(1, observed_at),
        ];
        let activity = ActivityRunsQueryResponse::new(
            &activity_request,
            activities,
            None,
            768,
            TransportProvenance::Fixture,
        )
        .expect("activity fixture");
        Self::new(pipeline, pipeline_run, [activity])
    }
}

impl AzureDataFactoryTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        request: &AzureDataFactoryRequest,
    ) -> std::result::Result<AzureDataFactoryResponse, ProviderTransportError> {
        match request.operation {
            AzureDataFactoryOperation::PipelinesGet => {
                Ok(AzureDataFactoryResponse::Pipeline(self.pipeline.clone()))
            }
            AzureDataFactoryOperation::PipelineRunsGet => Ok(
                AzureDataFactoryResponse::PipelineRun(self.pipeline_run.clone()),
            ),
            AzureDataFactoryOperation::ActivityRunsQueryByPipelineRun => self
                .activity_pages
                .pop_front()
                .map(AzureDataFactoryResponse::ActivityRuns)
                .ok_or(ProviderTransportError::ProviderUnknown),
        }
    }
}

pub type FakeTransport = FixtureTransport;

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    inner: FixtureTransport,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    #[must_use]
    pub fn new(
        pipeline: GetPipelineResponse,
        pipeline_run: GetPipelineRunResponse,
        activity_pages: impl IntoIterator<Item = ActivityRunsQueryResponse>,
    ) -> Self {
        Self {
            inner: FixtureTransport::new(pipeline, pipeline_run, activity_pages),
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn for_scope(scope: &AzureDataFactoryScope) -> Self {
        let fixture = FixtureTransport::for_scope(scope);
        Self {
            inner: fixture,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl AzureDataFactoryTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &AzureDataFactoryRequest,
    ) -> std::result::Result<AzureDataFactoryResponse, ProviderTransportError> {
        self.requests.push(request.into());
        self.inner.execute(request).map(|response| match response {
            AzureDataFactoryResponse::Pipeline(mut response) => {
                response.provenance = TransportProvenance::Recording;
                AzureDataFactoryResponse::Pipeline(response)
            }
            AzureDataFactoryResponse::PipelineRun(mut response) => {
                response.provenance = TransportProvenance::Recording;
                AzureDataFactoryResponse::PipelineRun(response)
            }
            AzureDataFactoryResponse::ActivityRuns(mut response) => {
                response.provenance = TransportProvenance::Recording;
                AzureDataFactoryResponse::ActivityRuns(response)
            }
        })
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: FixtureTransport,
    requests: Vec<RecordedRequest>,
}

impl LoopbackTransport {
    #[must_use]
    pub fn for_scope(scope: &AzureDataFactoryScope) -> Self {
        Self {
            inner: FixtureTransport::for_scope(scope),
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl AzureDataFactoryTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        request: &AzureDataFactoryRequest,
    ) -> std::result::Result<AzureDataFactoryResponse, ProviderTransportError> {
        self.requests.push(request.into());
        self.inner.execute(request).map(|response| match response {
            AzureDataFactoryResponse::Pipeline(mut response) => {
                response.provenance = TransportProvenance::Loopback;
                AzureDataFactoryResponse::Pipeline(response)
            }
            AzureDataFactoryResponse::PipelineRun(mut response) => {
                response.provenance = TransportProvenance::Loopback;
                AzureDataFactoryResponse::PipelineRun(response)
            }
            AzureDataFactoryResponse::ActivityRuns(mut response) => {
                response.provenance = TransportProvenance::Loopback;
                AzureDataFactoryResponse::ActivityRuns(response)
            }
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AzureDataFactoryTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &AzureDataFactoryRequest,
    ) -> std::result::Result<AzureDataFactoryResponse, ProviderTransportError> {
        Err(ProviderTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureDataFactoryProviderDefinition {
    pub id: String,
    pub version: String,
    pub api_version: String,
    pub api_revision: String,
    pub origin: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub transport_provenance: Vec<TransportProvenance>,
    pub native_https: bool,
    pub native_entra_resolution: bool,
    pub connected: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub external_writes: bool,
}

impl Default for AzureDataFactoryProviderDefinition {
    fn default() -> Self {
        Self {
            id: PROVIDER_ID.to_owned(),
            version: PROVIDER_VERSION.to_owned(),
            api_version: API_VERSION.to_owned(),
            api_revision: API_REVISION.to_owned(),
            origin: API_ORIGIN.to_owned(),
            operations: [
                AzureDataFactoryOperation::PipelinesGet,
                AzureDataFactoryOperation::PipelineRunsGet,
                AzureDataFactoryOperation::ActivityRunsQueryByPipelineRun,
            ]
            .into_iter()
            .map(|operation| operation.name().to_owned())
            .collect(),
            permissions: crate::model::PermissionScope::least_privilege()
                .permissions()
                .iter()
                .map(|permission| permission.api_action().to_owned())
                .collect(),
            transport_provenance: vec![
                TransportProvenance::Fixture,
                TransportProvenance::Recording,
                TransportProvenance::Loopback,
                TransportProvenance::BlockedEnv,
            ],
            native_https: false,
            native_entra_resolution: false,
            connected: false,
            first_party: false,
            provider_receipt: false,
            external_writes: false,
        }
    }
}

pub type ProviderDefinition = AzureDataFactoryProviderDefinition;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderReadSet {
    pub pipeline: PipelineMetadata,
    pub pipeline_run: PipelineRunMetadata,
    pub activities: Vec<ActivityRunMetadata>,
    pub receipts: Vec<ProviderResponseReceipt>,
    pub complete: bool,
    pub continuation_digest: Option<Digest>,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
}

impl ProviderReadSet {
    pub fn validate(&self) -> Result<()> {
        self.pipeline.validate()?;
        self.pipeline_run.validate()?;
        if self.activities.len() > MAX_ACTIVITIES || self.receipts.len() > MAX_PAGES + 2 {
            return Err(AzureDataFactoryPipelineResultError::ResponseTooLarge);
        }
        for activity in &self.activities {
            activity.validate()?;
        }
        for receipt in &self.receipts {
            receipt.validate()?;
        }
        if let Some(digest) = &self.continuation_digest {
            digest.validate()?;
        }
        let expected = canonical_digest(&(
            "azure-data-factory-provider-read-set/v1",
            &self.pipeline,
            &self.pipeline_run,
            &self.activities,
            &self.receipts,
            self.complete,
            &self.continuation_digest,
            self.provenance,
        ));
        if expected == self.evidence_digest {
            Ok(())
        } else {
            Err(AzureDataFactoryPipelineResultError::Tampered)
        }
    }
}

/// Typed read-only provider bound to one exact scope and opaque secret.
pub struct AzureDataFactoryProvider<T: AzureDataFactoryTransport> {
    scope: AzureDataFactoryScope,
    secret_reference: SecretReference,
    transport: T,
    definition: AzureDataFactoryProviderDefinition,
}

impl<T: AzureDataFactoryTransport> fmt::Debug for AzureDataFactoryProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureDataFactoryProvider")
            .field("scope_digest", self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("transport_provenance", &self.transport.provenance())
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: AzureDataFactoryTransport> AzureDataFactoryProvider<T> {
    pub fn new(
        scope: AzureDataFactoryScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self> {
        scope.validate()?;
        secret_reference.validate()?;
        if secret_reference.tenant_digest() != scope.tenant_digest() {
            return Err(AzureDataFactoryPipelineResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            secret_reference,
            transport,
            definition: AzureDataFactoryProviderDefinition::default(),
        })
    }

    #[must_use]
    pub fn scope(&self) -> &AzureDataFactoryScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    #[must_use]
    pub fn transport_provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        provider_digest()
    }

    #[must_use]
    pub fn api_digest(&self) -> Digest {
        api_digest()
    }

    #[must_use]
    pub fn definition(&self) -> &AzureDataFactoryProviderDefinition {
        &self.definition
    }

    fn ensure_readable(&self) -> Result<()> {
        self.scope.validate()?;
        self.secret_reference.validate()?;
        if self.secret_reference.is_revoked() {
            return Err(AzureDataFactoryPipelineResultError::SecretRevoked);
        }
        Ok(())
    }

    pub fn read_pipeline(&mut self) -> Result<(PipelineMetadata, ProviderResponseReceipt)> {
        self.ensure_readable()?;
        let request = AzureDataFactoryRequest::get_pipeline(&self.scope)?;
        request.validate()?;
        let response = self
            .transport
            .execute(&request)
            .map_err(AzureDataFactoryPipelineResultError::Transport)?;
        match response {
            AzureDataFactoryResponse::Pipeline(response) => {
                if response.provenance != self.transport.provenance() {
                    return Err(AzureDataFactoryPipelineResultError::InvalidProviderResponse);
                }
                response.validate(&request)?;
                Ok((response.pipeline.clone(), response.receipt(&request)))
            }
            _ => Err(AzureDataFactoryPipelineResultError::InvalidProviderResponse),
        }
    }

    pub fn read_pipeline_run(&mut self) -> Result<(PipelineRunMetadata, ProviderResponseReceipt)> {
        self.ensure_readable()?;
        let request = AzureDataFactoryRequest::get_pipeline_run(&self.scope)?;
        request.validate()?;
        let response = self
            .transport
            .execute(&request)
            .map_err(AzureDataFactoryPipelineResultError::Transport)?;
        match response {
            AzureDataFactoryResponse::PipelineRun(response) => {
                if response.provenance != self.transport.provenance() {
                    return Err(AzureDataFactoryPipelineResultError::InvalidProviderResponse);
                }
                response.validate(&request)?;
                Ok((response.pipeline_run.clone(), response.receipt(&request)))
            }
            _ => Err(AzureDataFactoryPipelineResultError::InvalidProviderResponse),
        }
    }

    pub fn query_activity_runs(
        &mut self,
        continuation: Option<&OpaqueContinuation>,
    ) -> Result<(ActivityRunsQueryResponse, ProviderResponseReceipt)> {
        self.ensure_readable()?;
        let request = AzureDataFactoryRequest::query_activity_runs(&self.scope, continuation)?;
        request.validate()?;
        let response = self
            .transport
            .execute(&request)
            .map_err(AzureDataFactoryPipelineResultError::Transport)?;
        match response {
            AzureDataFactoryResponse::ActivityRuns(response) => {
                if response.provenance != self.transport.provenance() {
                    return Err(AzureDataFactoryPipelineResultError::InvalidProviderResponse);
                }
                response.validate(&request)?;
                Ok((response.clone(), response.receipt(&request)))
            }
            _ => Err(AzureDataFactoryPipelineResultError::InvalidProviderResponse),
        }
    }

    pub fn read_bounded(&mut self) -> Result<ProviderReadSet> {
        self.ensure_readable()?;
        let (pipeline, pipeline_receipt) = self.read_pipeline()?;
        let (pipeline_run, pipeline_run_receipt) = self.read_pipeline_run()?;
        let mut activities = Vec::new();
        let mut receipts = vec![pipeline_receipt, pipeline_run_receipt];
        let mut continuation = None;
        let mut seen = BTreeSet::new();
        let mut complete = false;
        for _ in 0..MAX_PAGES {
            let (page, receipt) = self.query_activity_runs(continuation.as_ref())?;
            receipts.push(receipt);
            activities.extend(page.activities);
            if activities.len() > MAX_ACTIVITIES {
                activities.truncate(MAX_ACTIVITIES);
                continuation = page.next_continuation;
                break;
            }
            if let Some(next) = page.next_continuation {
                if !seen.insert(next.digest().clone()) {
                    return Err(AzureDataFactoryPipelineResultError::PaginationLoop);
                }
                continuation = Some(next);
            } else {
                complete = true;
                continuation = None;
                break;
            }
        }
        if continuation.is_some() && !complete {
            complete = false;
        }
        let continuation_digest = continuation.as_ref().map(|cursor| cursor.digest().clone());
        let provenance = self.transport.provenance();
        let evidence_digest = canonical_digest(&(
            "azure-data-factory-provider-read-set/v1",
            &pipeline,
            &pipeline_run,
            &activities,
            &receipts,
            complete,
            &continuation_digest,
            provenance,
        ));
        let result = ProviderReadSet {
            pipeline,
            pipeline_run,
            activities,
            receipts,
            complete,
            continuation_digest,
            provenance,
            evidence_digest,
        };
        result.validate()?;
        Ok(result)
    }
}

#[allow(dead_code)]
fn _provider_policy_digest() -> Digest {
    evidence_policy_digest()
}
