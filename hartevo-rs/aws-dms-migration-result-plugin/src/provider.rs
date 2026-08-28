//! Layer-1 AWS DMS provider and deterministic transport seams.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use crate::error::{AwsDmsMigrationError, AwsDmsTransportError, Result};
use crate::model::{
    AssessmentResultMetadata, AwsDmsMigrationReadRequest, AwsDmsScope, DatabaseEngine,
    DescribeReplicationTaskAssessmentResultsRequest,
    DescribeReplicationTaskAssessmentResultsResponse, DescribeReplicationTasksRequest,
    DescribeReplicationTasksResponse, DescribeReplicationsRequest, DescribeReplicationsResponse,
    DmsOperation, FullLoadProgress, MigrationType, OpaqueMarker, ReplicationIdentityValue,
    ReplicationMetadata, ReplicationState, ReplicationTaskMetadata, ReplicationTaskState,
    TransportProvenance,
};
use crate::{AWS_DMS_API_REVISION, AWS_DMS_PROVIDER_ID, AWS_DMS_PROVIDER_VERSION};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsDmsProviderDefinition {
    pub id: String,
    pub version: String,
    pub api_revision: String,
    pub provider_digest: crate::Digest,
    pub api_digest: crate::Digest,
}

impl Default for AwsDmsProviderDefinition {
    fn default() -> Self {
        Self::baseline()
    }
}

impl AwsDmsProviderDefinition {
    pub fn baseline() -> Self {
        let id = AWS_DMS_PROVIDER_ID.to_owned();
        let version = AWS_DMS_PROVIDER_VERSION.to_owned();
        let api_revision = AWS_DMS_API_REVISION.to_owned();
        let api_digest = crate::Digest::from_parts(
            "aws-dms-api/v1",
            &[
                ("revision", api_revision.clone()),
                (
                    "operations",
                    [
                        DmsOperation::DescribeReplicationTasks,
                        DmsOperation::DescribeReplications,
                        DmsOperation::DescribeReplicationTaskAssessmentResults,
                    ]
                    .into_iter()
                    .map(DmsOperation::as_str)
                    .collect::<Vec<_>>()
                    .join("\n"),
                ),
            ],
        );
        let provider_digest = crate::Digest::from_parts(
            "aws-dms-provider/v1",
            &[
                ("id", id.clone()),
                ("version", version.clone()),
                ("api", api_digest.as_str().to_owned()),
            ],
        );
        Self {
            id,
            version,
            api_revision,
            provider_digest,
            api_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let baseline = Self::baseline();
        if self.id != baseline.id
            || self.version != baseline.version
            || self.api_revision != baseline.api_revision
            || self.provider_digest != baseline.provider_digest
            || self.api_digest != baseline.api_digest
        {
            return Err(AwsDmsMigrationError::ProviderDrift);
        }
        self.provider_digest.validate("provider digest")?;
        self.api_digest.validate("API digest")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: DmsOperation,
    pub request_digest: crate::Digest,
    pub page_number: u16,
    pub marker_digest: Option<crate::Digest>,
}

pub trait AwsDmsTransport: fmt::Debug + Send {
    fn provenance(&self) -> TransportProvenance;

    fn describe_replication_tasks(
        &mut self,
        request: &DescribeReplicationTasksRequest,
    ) -> std::result::Result<DescribeReplicationTasksResponse, AwsDmsTransportError>;

    fn describe_replications(
        &mut self,
        request: &DescribeReplicationsRequest,
    ) -> std::result::Result<DescribeReplicationsResponse, AwsDmsTransportError>;

    fn describe_assessment_results(
        &mut self,
        request: &DescribeReplicationTaskAssessmentResultsRequest,
    ) -> std::result::Result<DescribeReplicationTaskAssessmentResultsResponse, AwsDmsTransportError>;
}

pub struct AwsDmsProvider<T: AwsDmsTransport> {
    transport: T,
    definition: AwsDmsProviderDefinition,
}

impl<T: AwsDmsTransport> fmt::Debug for AwsDmsProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsDmsProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.provenance())
            .finish()
    }
}

impl<T: AwsDmsTransport> AwsDmsProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_definition(transport, AwsDmsProviderDefinition::baseline())
    }

    pub fn with_definition(transport: T, definition: AwsDmsProviderDefinition) -> Result<Self> {
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsDmsProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn describe_replication_tasks(
        &mut self,
        request: &DescribeReplicationTasksRequest,
    ) -> std::result::Result<DescribeReplicationTasksResponse, AwsDmsTransportError> {
        let response = self.transport.describe_replication_tasks(request)?;
        validate_task_response(request, &response, self.provenance())
            .map_err(|_| AwsDmsTransportError::InvalidResponse)?;
        Ok(response)
    }

    pub fn describe_replications(
        &mut self,
        request: &DescribeReplicationsRequest,
    ) -> std::result::Result<DescribeReplicationsResponse, AwsDmsTransportError> {
        let response = self.transport.describe_replications(request)?;
        validate_replication_response(request, &response, self.provenance())
            .map_err(|_| AwsDmsTransportError::InvalidResponse)?;
        Ok(response)
    }

    pub fn describe_assessment_results(
        &mut self,
        request: &DescribeReplicationTaskAssessmentResultsRequest,
    ) -> std::result::Result<DescribeReplicationTaskAssessmentResultsResponse, AwsDmsTransportError>
    {
        let response = self.transport.describe_assessment_results(request)?;
        validate_assessment_response(request, &response, self.provenance())
            .map_err(|_| AwsDmsTransportError::InvalidResponse)?;
        Ok(response)
    }
}

fn validate_task_response(
    request: &DescribeReplicationTasksRequest,
    response: &DescribeReplicationTasksResponse,
    provenance: TransportProvenance,
) -> Result<()> {
    if response.request_digest != request.request_digest
        || response.provenance != provenance
        || response.response_bytes > crate::MAX_RESPONSE_BYTES
    {
        return Err(AwsDmsMigrationError::TamperedEvidence);
    }
    response.validate_integrity(request)?;
    Ok(())
}

fn validate_replication_response(
    request: &DescribeReplicationsRequest,
    response: &DescribeReplicationsResponse,
    provenance: TransportProvenance,
) -> Result<()> {
    if response.request_digest != request.request_digest
        || response.provenance != provenance
        || response.response_bytes > crate::MAX_RESPONSE_BYTES
    {
        return Err(AwsDmsMigrationError::TamperedEvidence);
    }
    response.validate_integrity(request)?;
    Ok(())
}

fn validate_assessment_response(
    request: &DescribeReplicationTaskAssessmentResultsRequest,
    response: &DescribeReplicationTaskAssessmentResultsResponse,
    provenance: TransportProvenance,
) -> Result<()> {
    if response.request_digest != request.request_digest
        || response.provenance != provenance
        || response.response_bytes > crate::MAX_RESPONSE_BYTES
    {
        return Err(AwsDmsMigrationError::TamperedEvidence);
    }
    response.validate_integrity(request)?;
    Ok(())
}

#[derive(Clone, Debug, Default)]
struct QueuedTransport {
    task_responses:
        VecDeque<std::result::Result<DescribeReplicationTasksResponse, AwsDmsTransportError>>,
    replication_responses:
        VecDeque<std::result::Result<DescribeReplicationsResponse, AwsDmsTransportError>>,
    assessment_responses: VecDeque<
        std::result::Result<DescribeReplicationTaskAssessmentResultsResponse, AwsDmsTransportError>,
    >,
    requests: Vec<RecordedRequest>,
}

impl QueuedTransport {
    fn push_task(
        &mut self,
        response: std::result::Result<DescribeReplicationTasksResponse, AwsDmsTransportError>,
    ) {
        self.task_responses.push_back(response);
    }

    fn push_replication(
        &mut self,
        response: std::result::Result<DescribeReplicationsResponse, AwsDmsTransportError>,
    ) {
        self.replication_responses.push_back(response);
    }

    fn push_assessment(
        &mut self,
        response: std::result::Result<
            DescribeReplicationTaskAssessmentResultsResponse,
            AwsDmsTransportError,
        >,
    ) {
        self.assessment_responses.push_back(response);
    }

    fn record(
        &mut self,
        operation: DmsOperation,
        request_digest: &crate::Digest,
        page: u16,
        marker: Option<&OpaqueMarker>,
    ) {
        self.requests.push(RecordedRequest {
            operation,
            request_digest: request_digest.clone(),
            page_number: page,
            marker_digest: marker.map(|value| value.token_digest().clone()),
        });
    }

    fn next_task(
        &mut self,
    ) -> std::result::Result<DescribeReplicationTasksResponse, AwsDmsTransportError> {
        self.task_responses
            .pop_front()
            .unwrap_or(Err(AwsDmsTransportError::Timeout))
    }

    fn next_replication(
        &mut self,
    ) -> std::result::Result<DescribeReplicationsResponse, AwsDmsTransportError> {
        self.replication_responses
            .pop_front()
            .unwrap_or(Err(AwsDmsTransportError::Timeout))
    }

    fn next_assessment(
        &mut self,
    ) -> std::result::Result<DescribeReplicationTaskAssessmentResultsResponse, AwsDmsTransportError>
    {
        self.assessment_responses
            .pop_front()
            .unwrap_or(Err(AwsDmsTransportError::Timeout))
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingTransport {
    inner: QueuedTransport,
}

impl RecordingTransport {
    pub fn push_task_response(
        &mut self,
        response: std::result::Result<DescribeReplicationTasksResponse, AwsDmsTransportError>,
    ) {
        self.inner.push_task(response);
    }

    pub fn push_replication_response(
        &mut self,
        response: std::result::Result<DescribeReplicationsResponse, AwsDmsTransportError>,
    ) {
        self.inner.push_replication(response);
    }

    pub fn push_assessment_response(
        &mut self,
        response: std::result::Result<
            DescribeReplicationTaskAssessmentResultsResponse,
            AwsDmsTransportError,
        >,
    ) {
        self.inner.push_assessment(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.inner.requests
    }
}

impl AwsDmsTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn describe_replication_tasks(
        &mut self,
        request: &DescribeReplicationTasksRequest,
    ) -> std::result::Result<DescribeReplicationTasksResponse, AwsDmsTransportError> {
        self.inner.record(
            DmsOperation::DescribeReplicationTasks,
            &request.request_digest,
            request.page_number,
            request.marker.as_ref(),
        );
        self.inner.next_task()
    }

    fn describe_replications(
        &mut self,
        request: &DescribeReplicationsRequest,
    ) -> std::result::Result<DescribeReplicationsResponse, AwsDmsTransportError> {
        self.inner.record(
            DmsOperation::DescribeReplications,
            &request.request_digest,
            request.page_number,
            request.marker.as_ref(),
        );
        self.inner.next_replication()
    }

    fn describe_assessment_results(
        &mut self,
        request: &DescribeReplicationTaskAssessmentResultsRequest,
    ) -> std::result::Result<DescribeReplicationTaskAssessmentResultsResponse, AwsDmsTransportError>
    {
        self.inner.record(
            DmsOperation::DescribeReplicationTaskAssessmentResults,
            &request.request_digest,
            request.page_number,
            request.marker.as_ref(),
        );
        self.inner.next_assessment()
    }
}

#[derive(Clone, Debug, Default)]
pub struct FixtureTransport {
    inner: QueuedTransport,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsDmsScope, observed_at: DateTime<Utc>) -> Result<Self> {
        let base = AwsDmsMigrationReadRequest::for_scope(scope, 25, 1)?;
        let task_request = base.tasks_request(scope, None, 1)?;
        let replication_request = base.replications_request(scope, None, 1)?;
        let assessment_request = base.assessment_request(scope, None, 1)?;
        let assessment = AssessmentResultMetadata::new(
            scope,
            crate::AssessmentStatus::Passed,
            observed_at,
            Some(b"fixture-assessment-report"),
        )?;
        let task = ReplicationTaskMetadata::new(
            scope,
            ReplicationTaskState::Running,
            if scope.replication().kind() == crate::ReplicationKind::Serverless {
                MigrationType::Serverless
            } else {
                MigrationType::FullLoadAndCdc
            },
            FullLoadProgress::new(42, 3, 5, 0, 4_096)?,
            None,
            observed_at,
            Some(assessment.clone()),
        )?;
        let replication = ReplicationMetadata::new(
            scope,
            ReplicationState::Running,
            task.migration_type,
            observed_at,
        )?;
        let mut transport = Self::default();
        transport
            .inner
            .push_task(Ok(DescribeReplicationTasksResponse::new(
                &task_request,
                scope,
                vec![task],
                None,
                512,
                TransportProvenance::Fixture,
            )?));
        transport
            .inner
            .push_replication(Ok(DescribeReplicationsResponse::new(
                &replication_request,
                scope,
                vec![replication],
                None,
                512,
                TransportProvenance::Fixture,
            )?));
        transport
            .inner
            .push_assessment(Ok(DescribeReplicationTaskAssessmentResultsResponse::new(
                &assessment_request,
                scope,
                vec![assessment],
                None,
                512,
                TransportProvenance::Fixture,
            )?));
        Ok(transport)
    }

    pub fn push_task_response(
        &mut self,
        response: std::result::Result<DescribeReplicationTasksResponse, AwsDmsTransportError>,
    ) {
        self.inner.push_task(response);
    }

    pub fn push_replication_response(
        &mut self,
        response: std::result::Result<DescribeReplicationsResponse, AwsDmsTransportError>,
    ) {
        self.inner.push_replication(response);
    }

    pub fn push_assessment_response(
        &mut self,
        response: std::result::Result<
            DescribeReplicationTaskAssessmentResultsResponse,
            AwsDmsTransportError,
        >,
    ) {
        self.inner.push_assessment(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.inner.requests
    }
}

impl AwsDmsTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn describe_replication_tasks(
        &mut self,
        request: &DescribeReplicationTasksRequest,
    ) -> std::result::Result<DescribeReplicationTasksResponse, AwsDmsTransportError> {
        self.inner.record(
            DmsOperation::DescribeReplicationTasks,
            &request.request_digest,
            request.page_number,
            request.marker.as_ref(),
        );
        self.inner.next_task()
    }

    fn describe_replications(
        &mut self,
        request: &DescribeReplicationsRequest,
    ) -> std::result::Result<DescribeReplicationsResponse, AwsDmsTransportError> {
        self.inner.record(
            DmsOperation::DescribeReplications,
            &request.request_digest,
            request.page_number,
            request.marker.as_ref(),
        );
        self.inner.next_replication()
    }

    fn describe_assessment_results(
        &mut self,
        request: &DescribeReplicationTaskAssessmentResultsRequest,
    ) -> std::result::Result<DescribeReplicationTaskAssessmentResultsResponse, AwsDmsTransportError>
    {
        self.inner.record(
            DmsOperation::DescribeReplicationTaskAssessmentResults,
            &request.request_digest,
            request.page_number,
            request.marker.as_ref(),
        );
        self.inner.next_assessment()
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoopbackTransport {
    inner: QueuedTransport,
}

impl LoopbackTransport {
    pub fn push_task_response(
        &mut self,
        response: std::result::Result<DescribeReplicationTasksResponse, AwsDmsTransportError>,
    ) {
        self.inner.push_task(response);
    }

    pub fn push_replication_response(
        &mut self,
        response: std::result::Result<DescribeReplicationsResponse, AwsDmsTransportError>,
    ) {
        self.inner.push_replication(response);
    }

    pub fn push_assessment_response(
        &mut self,
        response: std::result::Result<
            DescribeReplicationTaskAssessmentResultsResponse,
            AwsDmsTransportError,
        >,
    ) {
        self.inner.push_assessment(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.inner.requests
    }
}

impl AwsDmsTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn describe_replication_tasks(
        &mut self,
        request: &DescribeReplicationTasksRequest,
    ) -> std::result::Result<DescribeReplicationTasksResponse, AwsDmsTransportError> {
        self.inner.record(
            DmsOperation::DescribeReplicationTasks,
            &request.request_digest,
            request.page_number,
            request.marker.as_ref(),
        );
        self.inner.next_task()
    }

    fn describe_replications(
        &mut self,
        request: &DescribeReplicationsRequest,
    ) -> std::result::Result<DescribeReplicationsResponse, AwsDmsTransportError> {
        self.inner.record(
            DmsOperation::DescribeReplications,
            &request.request_digest,
            request.page_number,
            request.marker.as_ref(),
        );
        self.inner.next_replication()
    }

    fn describe_assessment_results(
        &mut self,
        request: &DescribeReplicationTaskAssessmentResultsRequest,
    ) -> std::result::Result<DescribeReplicationTaskAssessmentResultsResponse, AwsDmsTransportError>
    {
        self.inner.record(
            DmsOperation::DescribeReplicationTaskAssessmentResults,
            &request.request_digest,
            request.page_number,
            request.marker.as_ref(),
        );
        self.inner.next_assessment()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsDmsTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn describe_replication_tasks(
        &mut self,
        _request: &DescribeReplicationTasksRequest,
    ) -> std::result::Result<DescribeReplicationTasksResponse, AwsDmsTransportError> {
        Err(AwsDmsTransportError::BlockedEnv)
    }

    fn describe_replications(
        &mut self,
        _request: &DescribeReplicationsRequest,
    ) -> std::result::Result<DescribeReplicationsResponse, AwsDmsTransportError> {
        Err(AwsDmsTransportError::BlockedEnv)
    }

    fn describe_assessment_results(
        &mut self,
        _request: &DescribeReplicationTaskAssessmentResultsRequest,
    ) -> std::result::Result<DescribeReplicationTaskAssessmentResultsResponse, AwsDmsTransportError>
    {
        Err(AwsDmsTransportError::BlockedEnv)
    }
}

pub type RecordingDmsTransport = RecordingTransport;
pub type FixtureDmsTransport = FixtureTransport;
pub type LoopbackDmsTransport = LoopbackTransport;
pub type BlockedEnvDmsTransport = BlockedEnvTransport;

pub type ProviderProvenance = TransportProvenance;

pub fn is_access_loss(error: &AwsDmsTransportError) -> bool {
    error.is_access_loss()
}

// Keep these names available to callers that use the AWS API spelling.
pub type DescribeReplicationTaskAssessmentResults =
    DescribeReplicationTaskAssessmentResultsResponse;

// This function is intentionally unused by live code; it documents that the
// provider does not accept endpoint credentials as a model value.
#[allow(dead_code)]
fn _endpoint_engine_is_metadata_only(engine: &DatabaseEngine) -> crate::Digest {
    engine.digest()
}

// Make the bounded time import part of this module's public fixture contract.
#[allow(dead_code)]
fn _fixture_window_end(start: DateTime<Utc>) -> DateTime<Utc> {
    start + Duration::hours(24)
}

// Keep the identity import visible in generated API docs without storing it.
#[allow(dead_code)]
fn _replication_kind(identity: &ReplicationIdentityValue) -> crate::ReplicationKind {
    identity.kind()
}
