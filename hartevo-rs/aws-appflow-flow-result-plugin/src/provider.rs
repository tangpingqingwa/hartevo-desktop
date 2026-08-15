use std::{collections::VecDeque, fmt};

use serde::Serialize;

use crate::error::{AwsAppFlowTransportError, Result};
use crate::model::{
    AppFlowOperation, AwsAppFlowScope, BoundedCounter, DescribeFlowExecutionRecordsRequest,
    DescribeFlowExecutionRecordsResponse, DescribeFlowRequest, DescribeFlowResponse, Digest,
    ErrorClass, ExecutionRecordProjection, ExecutionStatus, FlowArn, FlowDefinitionProjection,
    FlowListItemProjection, ListFlowsRequest, ListFlowsResponse, PermissionSnapshot,
    TimingProjection, TransportProvenance,
};
use crate::{PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsAppFlowProviderDefinition {
    pub id: String,
    pub version: String,
    pub api_revision: String,
    pub operations: Vec<AppFlowOperation>,
    pub permission_digest: Digest,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl AwsAppFlowProviderDefinition {
    pub fn layer_one() -> Self {
        let permission_digest = PermissionSnapshot::for_layer_one(1).digest;
        let operations = vec![
            AppFlowOperation::ListFlows,
            AppFlowOperation::DescribeFlow,
            AppFlowOperation::DescribeFlowExecutionRecords,
        ];
        let provider_digest = Digest::from_serializable(&(
            PROVIDER_ID,
            PLUGIN_VERSION,
            PROVIDER_API_REVISION,
            &operations,
            &permission_digest,
            false,
            false,
            false,
            false,
        ));
        Self {
            id: PROVIDER_ID.to_owned(),
            version: PLUGIN_VERSION.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            operations,
            permission_digest,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self != &Self::layer_one() {
            return Err(crate::error::AwsAppFlowResultError::PermissionDrift);
        }
        Ok(())
    }
}

/// The only provider seam available to Layer 1. Implementations are fixtures,
/// recordings, loopbacks, or BLOCKED_ENV; there is no native HTTP transport.
pub trait AwsAppFlowTransport: fmt::Debug {
    fn list_flows(
        &mut self,
        request: &ListFlowsRequest,
    ) -> std::result::Result<ListFlowsResponse, AwsAppFlowTransportError>;

    fn describe_flow(
        &mut self,
        request: &DescribeFlowRequest,
    ) -> std::result::Result<DescribeFlowResponse, AwsAppFlowTransportError>;

    fn describe_flow_execution_records(
        &mut self,
        request: &DescribeFlowExecutionRecordsRequest,
    ) -> std::result::Result<DescribeFlowExecutionRecordsResponse, AwsAppFlowTransportError>;

    fn provenance(&self) -> TransportProvenance;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedRequest {
    pub operation: AppFlowOperation,
    pub request_digest: Digest,
    pub path_digest: Digest,
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    list_responses: VecDeque<std::result::Result<ListFlowsResponse, AwsAppFlowTransportError>>,
    describe_responses:
        VecDeque<std::result::Result<DescribeFlowResponse, AwsAppFlowTransportError>>,
    records_responses: VecDeque<
        std::result::Result<DescribeFlowExecutionRecordsResponse, AwsAppFlowTransportError>,
    >,
    requests: Vec<RecordedRequest>,
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::with_provenance(TransportProvenance::Recording)
    }
}

impl RecordingTransport {
    pub fn with_provenance(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            list_responses: VecDeque::new(),
            describe_responses: VecDeque::new(),
            records_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_list_flows_response(
        &mut self,
        response: std::result::Result<ListFlowsResponse, AwsAppFlowTransportError>,
    ) {
        self.list_responses.push_back(response);
    }

    pub fn push_describe_flow_response(
        &mut self,
        response: std::result::Result<DescribeFlowResponse, AwsAppFlowTransportError>,
    ) {
        self.describe_responses.push_back(response);
    }

    pub fn push_execution_records_response(
        &mut self,
        response: std::result::Result<
            DescribeFlowExecutionRecordsResponse,
            AwsAppFlowTransportError,
        >,
    ) {
        self.records_responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    fn record_request(&mut self, operation: AppFlowOperation, digest: Digest, path: String) {
        self.requests.push(RecordedRequest {
            operation,
            request_digest: digest,
            path_digest: Digest::from_text(path),
        });
    }

    fn pop<T>(
        queue: &mut VecDeque<std::result::Result<T, AwsAppFlowTransportError>>,
    ) -> std::result::Result<T, AwsAppFlowTransportError> {
        queue
            .pop_front()
            .unwrap_or(Err(AwsAppFlowTransportError::RecordingExhausted))
    }
}

impl AwsAppFlowTransport for RecordingTransport {
    fn list_flows(
        &mut self,
        request: &ListFlowsRequest,
    ) -> std::result::Result<ListFlowsResponse, AwsAppFlowTransportError> {
        self.record_request(
            AppFlowOperation::ListFlows,
            request.request_digest(),
            request.path_and_query(),
        );
        Self::pop(&mut self.list_responses)
    }

    fn describe_flow(
        &mut self,
        request: &DescribeFlowRequest,
    ) -> std::result::Result<DescribeFlowResponse, AwsAppFlowTransportError> {
        self.record_request(
            AppFlowOperation::DescribeFlow,
            request.request_digest(),
            request.path_and_query(),
        );
        Self::pop(&mut self.describe_responses)
    }

    fn describe_flow_execution_records(
        &mut self,
        request: &DescribeFlowExecutionRecordsRequest,
    ) -> std::result::Result<DescribeFlowExecutionRecordsResponse, AwsAppFlowTransportError> {
        self.record_request(
            AppFlowOperation::DescribeFlowExecutionRecords,
            request.request_digest(),
            request.path_and_query(),
        );
        Self::pop(&mut self.records_responses)
    }

    fn provenance(&self) -> TransportProvenance {
        self.provenance.clone()
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    inner: RecordingTransport,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsAppFlowScope, started_at_ms: u64) -> Result<Self> {
        Ok(Self {
            inner: prepared_transport(scope, started_at_ms, TransportProvenance::Fixture)?,
        })
    }

    pub fn from_recording(inner: RecordingTransport) -> Self {
        Self { inner }
    }
}

impl AwsAppFlowTransport for FixtureTransport {
    fn list_flows(
        &mut self,
        request: &ListFlowsRequest,
    ) -> std::result::Result<ListFlowsResponse, AwsAppFlowTransportError> {
        self.inner.list_flows(request)
    }

    fn describe_flow(
        &mut self,
        request: &DescribeFlowRequest,
    ) -> std::result::Result<DescribeFlowResponse, AwsAppFlowTransportError> {
        self.inner.describe_flow(request)
    }

    fn describe_flow_execution_records(
        &mut self,
        request: &DescribeFlowExecutionRecordsRequest,
    ) -> std::result::Result<DescribeFlowExecutionRecordsResponse, AwsAppFlowTransportError> {
        self.inner.describe_flow_execution_records(request)
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: RecordingTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsAppFlowScope, started_at_ms: u64) -> Result<Self> {
        Ok(Self {
            inner: prepared_transport(scope, started_at_ms, TransportProvenance::Loopback)?,
        })
    }
}

impl AwsAppFlowTransport for LoopbackTransport {
    fn list_flows(
        &mut self,
        request: &ListFlowsRequest,
    ) -> std::result::Result<ListFlowsResponse, AwsAppFlowTransportError> {
        self.inner.list_flows(request)
    }

    fn describe_flow(
        &mut self,
        request: &DescribeFlowRequest,
    ) -> std::result::Result<DescribeFlowResponse, AwsAppFlowTransportError> {
        self.inner.describe_flow(request)
    }

    fn describe_flow_execution_records(
        &mut self,
        request: &DescribeFlowExecutionRecordsRequest,
    ) -> std::result::Result<DescribeFlowExecutionRecordsResponse, AwsAppFlowTransportError> {
        self.inner.describe_flow_execution_records(request)
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsAppFlowTransport for BlockedEnvTransport {
    fn list_flows(
        &mut self,
        _request: &ListFlowsRequest,
    ) -> std::result::Result<ListFlowsResponse, AwsAppFlowTransportError> {
        Err(AwsAppFlowTransportError::BlockedEnv)
    }

    fn describe_flow(
        &mut self,
        _request: &DescribeFlowRequest,
    ) -> std::result::Result<DescribeFlowResponse, AwsAppFlowTransportError> {
        Err(AwsAppFlowTransportError::BlockedEnv)
    }

    fn describe_flow_execution_records(
        &mut self,
        _request: &DescribeFlowExecutionRecordsRequest,
    ) -> std::result::Result<DescribeFlowExecutionRecordsResponse, AwsAppFlowTransportError> {
        Err(AwsAppFlowTransportError::BlockedEnv)
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }
}

/// Typed provider wrapper. It records only request digests and never performs
/// native SigV4 resolution or an external write.
#[derive(Debug)]
pub struct AwsAppFlowProvider<T: AwsAppFlowTransport> {
    transport: T,
    definition: AwsAppFlowProviderDefinition,
}

impl<T: AwsAppFlowTransport> AwsAppFlowProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        let definition = AwsAppFlowProviderDefinition::layer_one();
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsAppFlowProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn connected(&self) -> bool {
        false
    }

    pub fn native(&self) -> bool {
        false
    }

    pub fn first_party(&self) -> bool {
        false
    }

    pub fn provider_receipt(&self) -> bool {
        false
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn list_flows(
        &mut self,
        request: &ListFlowsRequest,
    ) -> std::result::Result<ListFlowsResponse, AwsAppFlowTransportError> {
        self.transport.list_flows(request)
    }

    pub fn describe_flow(
        &mut self,
        request: &DescribeFlowRequest,
    ) -> std::result::Result<DescribeFlowResponse, AwsAppFlowTransportError> {
        self.transport.describe_flow(request)
    }

    pub fn describe_flow_execution_records(
        &mut self,
        request: &DescribeFlowExecutionRecordsRequest,
    ) -> std::result::Result<DescribeFlowExecutionRecordsResponse, AwsAppFlowTransportError> {
        self.transport.describe_flow_execution_records(request)
    }
}

impl Default for AwsAppFlowProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("BLOCKED_ENV provider definition is static")
    }
}

fn prepared_transport(
    scope: &AwsAppFlowScope,
    started_at_ms: u64,
    provenance: TransportProvenance,
) -> Result<RecordingTransport> {
    let list_request = ListFlowsRequest::new(scope, crate::MAX_PAGE_SIZE, None)?;
    let flow_arn = FlowArn::new(format!(
        "arn:aws:appflow:{}:{}:flow/{}",
        scope.region().as_str(),
        scope.account().as_str(),
        scope.flow().as_str()
    ))?;
    flow_arn.validate()?;
    let flow_arn_digest = flow_arn.digest();
    let list_item = FlowListItemProjection {
        flow_digest: scope.flow_digest(),
        flow_arn_digest: flow_arn_digest.clone(),
        source_digest: scope.source_digest().clone(),
        target_digest: scope.target_digest().clone(),
        trigger: scope.trigger().clone(),
        status: crate::model::FlowStatus::Active,
        flow_revision: scope.flow_revision(),
        updated_at_ms: Some(started_at_ms.saturating_sub(1_000)),
        last_execution_status: Some(ExecutionStatus::Successful),
    };
    let list_response = ListFlowsResponse::new(
        &list_request,
        vec![list_item],
        None,
        512,
        provenance.clone(),
    )?;

    let describe_request = DescribeFlowRequest::new(scope)?;
    let flow = FlowDefinitionProjection {
        flow_digest: scope.flow_digest(),
        flow_arn_digest,
        source_digest: scope.source_digest().clone(),
        target_digest: scope.target_digest().clone(),
        trigger: scope.trigger().clone(),
        status: crate::model::FlowStatus::Active,
        flow_revision: scope.flow_revision(),
        updated_at_ms: Some(started_at_ms.saturating_sub(1_000)),
    };
    let describe_response =
        DescribeFlowResponse::new(&describe_request, flow, 512, provenance.clone())?;

    let records_request =
        DescribeFlowExecutionRecordsRequest::new(scope, crate::MAX_PAGE_SIZE, None)?;
    let record = ExecutionRecordProjection {
        execution_digest: scope.execution_digest(),
        flow_digest: scope.flow_digest(),
        source_digest: scope.source_digest().clone(),
        target_digest: scope.target_digest().clone(),
        trigger: scope.trigger().clone(),
        status: ExecutionStatus::Successful,
        timing: TimingProjection::new(Some(started_at_ms), Some(started_at_ms + 2_000))?,
        records_processed: BoundedCounter::from_raw(24),
        bytes_processed: BoundedCounter::from_raw(4_096),
        bytes_written: BoundedCounter::from_raw(4_096),
        put_failures: BoundedCounter::from_raw(0),
        error_class: ErrorClass::None,
        flow_revision: scope.flow_revision(),
        execution_revision: scope.execution_revision(),
    };
    let records_response = DescribeFlowExecutionRecordsResponse::new(
        &records_request,
        vec![record],
        None,
        512,
        provenance,
    )?;

    let mut transport = RecordingTransport::with_provenance(TransportProvenance::Recording);
    transport.push_list_flows_response(Ok(list_response));
    transport.push_describe_flow_response(Ok(describe_response));
    transport.push_execution_records_response(Ok(records_response));
    Ok(transport)
}
