//! Typed, bounded CloudFormation provider seams.
//!
//! The transport trait deliberately has exactly the five read operations in
//! the Layer-1 contract. It has no signer, credential resolver, HTTP client,
//! mutation method, template payload, or arbitrary operation escape hatch.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use crate::error::{AwsCloudFormationDriftError, AwsCloudFormationTransportError, Result};
use crate::model::{
    AwsCloudFormationDriftScope, CloudFormationOperation, CloudFormationStackStatus,
    DescribeStackDriftDetectionStatusRequest, DescribeStackDriftDetectionStatusResponse,
    DescribeStackEventsRequest, DescribeStackEventsResponse, DescribeStackResourceDriftsRequest,
    DescribeStackResourceDriftsResponse, DescribeStacksRequest, DescribeStacksResponse,
    DetectStackDriftRequest, DetectStackDriftResponse, DriftDetectionStatus, ResourceDrift,
    ResourceDriftStatus, StackDriftStatus, StackEvent, StackSummary, TransportProvenance,
};
use crate::{CONTRACT_VERSION, LAYER1_PERMISSIONS, PROVIDER_API_REVISION, PROVIDER_ID};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudFormationProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub contract_version: String,
    pub release: String,
    pub capability_digest: crate::model::Digest,
    pub provider_digest: crate::model::Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl AwsCloudFormationProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0 || release.is_empty() || release.len() > 128 {
            return Err(AwsCloudFormationDriftError::ProviderDrift);
        }
        let capability_digest = crate::model::Digest::from_parts(
            "aws-cloudformation-provider-capabilities/v1",
            &LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .collect::<Vec<_>>(),
        );
        let provider_digest = crate::model::Digest::from_parts(
            "aws-cloudformation-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("provider_revision", provider_revision.to_string()),
                ("api_revision", PROVIDER_API_REVISION.to_owned()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
                ("release", release.clone()),
                ("capability", capability_digest.to_string()),
            ],
        );
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            release,
            capability_digest,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        })
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(self.provider_revision, self.release.clone())?;
        if self.provider_id != PROVIDER_ID
            || self.api_revision != PROVIDER_API_REVISION
            || self.contract_version != CONTRACT_VERSION
            || self.provider_revision == 0
            || self.release.is_empty()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provider_digest != expected.provider_digest
            || self.capability_digest != expected.capability_digest
        {
            return Err(AwsCloudFormationDriftError::ProviderDrift);
        }
        Ok(())
    }
}

pub trait AwsCloudFormationTransport: Send {
    fn provenance(&self) -> TransportProvenance;

    fn describe_stacks(
        &mut self,
        request: &DescribeStacksRequest,
    ) -> std::result::Result<DescribeStacksResponse, AwsCloudFormationTransportError>;

    fn describe_stack_events(
        &mut self,
        request: &DescribeStackEventsRequest,
    ) -> std::result::Result<DescribeStackEventsResponse, AwsCloudFormationTransportError>;

    fn detect_stack_drift(
        &mut self,
        request: &DetectStackDriftRequest,
    ) -> std::result::Result<DetectStackDriftResponse, AwsCloudFormationTransportError>;

    fn describe_stack_drift_detection_status(
        &mut self,
        request: &DescribeStackDriftDetectionStatusRequest,
    ) -> std::result::Result<
        DescribeStackDriftDetectionStatusResponse,
        AwsCloudFormationTransportError,
    >;

    fn describe_stack_resource_drifts(
        &mut self,
        request: &DescribeStackResourceDriftsRequest,
    ) -> std::result::Result<DescribeStackResourceDriftsResponse, AwsCloudFormationTransportError>;
}

pub struct AwsCloudFormationProvider<T> {
    transport: T,
    definition: AwsCloudFormationProviderDefinition,
}

impl<T: AwsCloudFormationTransport> fmt::Debug for AwsCloudFormationProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCloudFormationProvider")
            .field("definition", &self.definition)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AwsCloudFormationTransport> AwsCloudFormationProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, "layer1-recording")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self> {
        let definition = AwsCloudFormationProviderDefinition::new(provider_revision, release)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsCloudFormationProviderDefinition {
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

    pub fn into_transport(self) -> T {
        self.transport
    }

    pub fn describe_stacks(
        &mut self,
        request: &DescribeStacksRequest,
    ) -> std::result::Result<DescribeStacksResponse, AwsCloudFormationTransportError> {
        let response = self.transport.describe_stacks(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsCloudFormationTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.first_party
            || response.provider_receipt
        {
            return Err(AwsCloudFormationTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn describe_stack_events(
        &mut self,
        request: &DescribeStackEventsRequest,
    ) -> std::result::Result<DescribeStackEventsResponse, AwsCloudFormationTransportError> {
        let response = self.transport.describe_stack_events(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsCloudFormationTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.first_party
            || response.provider_receipt
        {
            return Err(AwsCloudFormationTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn detect_stack_drift(
        &mut self,
        request: &DetectStackDriftRequest,
    ) -> std::result::Result<DetectStackDriftResponse, AwsCloudFormationTransportError> {
        let response = self.transport.detect_stack_drift(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsCloudFormationTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.first_party
            || response.provider_receipt
        {
            return Err(AwsCloudFormationTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn describe_stack_drift_detection_status(
        &mut self,
        request: &DescribeStackDriftDetectionStatusRequest,
    ) -> std::result::Result<
        DescribeStackDriftDetectionStatusResponse,
        AwsCloudFormationTransportError,
    > {
        let response = self
            .transport
            .describe_stack_drift_detection_status(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsCloudFormationTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.first_party
            || response.provider_receipt
        {
            return Err(AwsCloudFormationTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn describe_stack_resource_drifts(
        &mut self,
        request: &DescribeStackResourceDriftsRequest,
    ) -> std::result::Result<DescribeStackResourceDriftsResponse, AwsCloudFormationTransportError>
    {
        let response = self.transport.describe_stack_resource_drifts(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsCloudFormationTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.first_party
            || response.provider_receipt
        {
            return Err(AwsCloudFormationTransportError::InvalidResponse);
        }
        Ok(response)
    }
}

impl Default for AwsCloudFormationProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked AWS CloudFormation provider definition")
    }
}

impl<T: AwsCloudFormationTransport> AwsCloudFormationProvider<T> {
    pub fn from_registration(
        registration: &crate::service::AwsCloudFormationDriftRegistration,
        transport: T,
    ) -> Result<Self> {
        let provider = Self::with_identity(
            transport,
            registration.provider_revision(),
            registration.provider_release().to_owned(),
        )?;
        if provider.definition.provider_digest != *registration.provider_digest() {
            return Err(AwsCloudFormationDriftError::ProviderDrift);
        }
        Ok(provider)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordedRequestKind {
    DescribeStacks,
    DescribeStackEvents,
    DetectStackDrift,
    DescribeStackDriftDetectionStatus,
    DescribeStackResourceDrifts,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: RecordedRequestKind,
    pub request_digest: crate::model::Digest,
    pub scope_digest: crate::model::Digest,
    pub page_number: Option<u16>,
}

#[derive(Clone, Debug)]
pub struct QueuedTransport {
    provenance: TransportProvenance,
    describe_stacks_responses:
        VecDeque<std::result::Result<DescribeStacksResponse, AwsCloudFormationTransportError>>,
    describe_stack_events_responses:
        VecDeque<std::result::Result<DescribeStackEventsResponse, AwsCloudFormationTransportError>>,
    detect_stack_drift_responses:
        VecDeque<std::result::Result<DetectStackDriftResponse, AwsCloudFormationTransportError>>,
    detection_status_responses: VecDeque<
        std::result::Result<
            DescribeStackDriftDetectionStatusResponse,
            AwsCloudFormationTransportError,
        >,
    >,
    resource_drift_responses: VecDeque<
        std::result::Result<DescribeStackResourceDriftsResponse, AwsCloudFormationTransportError>,
    >,
    requests: Vec<RecordedRequest>,
    fixture_scope: Option<AwsCloudFormationDriftScope>,
    observed_at: DateTime<Utc>,
}

impl QueuedTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            describe_stacks_responses: VecDeque::new(),
            describe_stack_events_responses: VecDeque::new(),
            detect_stack_drift_responses: VecDeque::new(),
            detection_status_responses: VecDeque::new(),
            resource_drift_responses: VecDeque::new(),
            requests: Vec::new(),
            fixture_scope: None,
            observed_at: Utc::now(),
        }
    }

    pub fn fixture() -> Self {
        Self::new(TransportProvenance::Fixture)
    }

    pub fn loopback() -> Self {
        Self::new(TransportProvenance::Loopback)
    }

    pub fn for_scope(scope: &AwsCloudFormationDriftScope, observed_at: DateTime<Utc>) -> Self {
        let mut value = Self::fixture();
        value.fixture_scope = Some(scope.clone());
        value.observed_at = observed_at;
        value
    }

    pub fn loopback_for_scope(
        scope: &AwsCloudFormationDriftScope,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let mut value = Self::loopback();
        value.fixture_scope = Some(scope.clone());
        value.observed_at = observed_at;
        value
    }

    pub fn push_describe_stacks_response(
        &mut self,
        response: std::result::Result<DescribeStacksResponse, AwsCloudFormationTransportError>,
    ) {
        self.describe_stacks_responses.push_back(response);
    }

    pub fn push_describe_stack_events_response(
        &mut self,
        response: std::result::Result<DescribeStackEventsResponse, AwsCloudFormationTransportError>,
    ) {
        self.describe_stack_events_responses.push_back(response);
    }

    pub fn push_detect_stack_drift_response(
        &mut self,
        response: std::result::Result<DetectStackDriftResponse, AwsCloudFormationTransportError>,
    ) {
        self.detect_stack_drift_responses.push_back(response);
    }

    pub fn push_detection_status_response(
        &mut self,
        response: std::result::Result<
            DescribeStackDriftDetectionStatusResponse,
            AwsCloudFormationTransportError,
        >,
    ) {
        self.detection_status_responses.push_back(response);
    }

    pub fn push_describe_stack_drift_detection_status_response(
        &mut self,
        response: std::result::Result<
            DescribeStackDriftDetectionStatusResponse,
            AwsCloudFormationTransportError,
        >,
    ) {
        self.push_detection_status_response(response);
    }

    pub fn push_resource_drift_response(
        &mut self,
        response: std::result::Result<
            DescribeStackResourceDriftsResponse,
            AwsCloudFormationTransportError,
        >,
    ) {
        self.resource_drift_responses.push_back(response);
    }

    pub fn push_describe_stack_resource_drifts_response(
        &mut self,
        response: std::result::Result<
            DescribeStackResourceDriftsResponse,
            AwsCloudFormationTransportError,
        >,
    ) {
        self.push_resource_drift_response(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    fn fixture_stacks(
        &self,
        request: &DescribeStacksRequest,
    ) -> std::result::Result<DescribeStacksResponse, AwsCloudFormationTransportError> {
        let scope = self
            .fixture_scope
            .as_ref()
            .ok_or(AwsCloudFormationTransportError::InvalidResponse)?;
        let summary = StackSummary::new(
            scope,
            CloudFormationStackStatus::UpdateComplete,
            self.observed_at - Duration::days(1),
            Some(self.observed_at - Duration::hours(1)),
            None,
            Some(StackDriftStatus::InSync),
            Some(self.observed_at - Duration::hours(1)),
            None,
        )
        .map_err(|_| AwsCloudFormationTransportError::InvalidResponse)?;
        DescribeStacksResponse::new(request, vec![summary], None, 512, self.provenance)
            .map_err(|_| AwsCloudFormationTransportError::InvalidResponse)
    }

    fn fixture_events(
        &self,
        request: &DescribeStackEventsRequest,
    ) -> std::result::Result<DescribeStackEventsResponse, AwsCloudFormationTransportError> {
        let scope = self
            .fixture_scope
            .as_ref()
            .ok_or(AwsCloudFormationTransportError::InvalidResponse)?;
        let event = StackEvent::new(
            scope,
            "fixture-event-1",
            "Stack",
            "AWS::CloudFormation::Stack",
            CloudFormationStackStatus::UpdateComplete,
            self.observed_at,
            None,
        )
        .map_err(|_| AwsCloudFormationTransportError::InvalidResponse)?;
        DescribeStackEventsResponse::new(request, vec![event], None, 512, self.provenance)
            .map_err(|_| AwsCloudFormationTransportError::InvalidResponse)
    }

    fn fixture_detect(
        &self,
        request: &DetectStackDriftRequest,
    ) -> std::result::Result<DetectStackDriftResponse, AwsCloudFormationTransportError> {
        let detection_id = crate::model::StackDriftDetectionId::new("fixture-detection-1")
            .map_err(|_| AwsCloudFormationTransportError::InvalidResponse)?;
        DetectStackDriftResponse::new(request, detection_id, 256, self.provenance)
            .map_err(|_| AwsCloudFormationTransportError::InvalidResponse)
    }

    fn fixture_status(
        &self,
        request: &DescribeStackDriftDetectionStatusRequest,
    ) -> std::result::Result<
        DescribeStackDriftDetectionStatusResponse,
        AwsCloudFormationTransportError,
    > {
        DescribeStackDriftDetectionStatusResponse::new(
            request,
            DriftDetectionStatus::DetectionComplete,
            None,
            Some(0),
            Some(StackDriftStatus::InSync),
            self.observed_at,
            384,
            self.provenance,
        )
        .map_err(|_| AwsCloudFormationTransportError::InvalidResponse)
    }

    fn fixture_resources(
        &self,
        request: &DescribeStackResourceDriftsRequest,
    ) -> std::result::Result<DescribeStackResourceDriftsResponse, AwsCloudFormationTransportError>
    {
        let scope = self
            .fixture_scope
            .as_ref()
            .ok_or(AwsCloudFormationTransportError::InvalidResponse)?;
        let resource = ResourceDrift::new(
            scope,
            "FixtureResource",
            Some("fixture-physical-id"),
            "AWS::S3::Bucket",
            ResourceDriftStatus::InSync,
            self.observed_at,
            0,
            None,
        )
        .map_err(|_| AwsCloudFormationTransportError::InvalidResponse)?;
        DescribeStackResourceDriftsResponse::new(
            request,
            vec![resource],
            None,
            512,
            self.provenance,
        )
        .map_err(|_| AwsCloudFormationTransportError::InvalidResponse)
    }
}

impl Default for QueuedTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}

impl AwsCloudFormationTransport for QueuedTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn describe_stacks(
        &mut self,
        request: &DescribeStacksRequest,
    ) -> std::result::Result<DescribeStacksResponse, AwsCloudFormationTransportError> {
        self.requests.push(RecordedRequest {
            operation: RecordedRequestKind::DescribeStacks,
            request_digest: request.request_digest(),
            scope_digest: request.scope_digest.clone(),
            page_number: Some(request.page_number()),
        });
        self.describe_stacks_responses
            .pop_front()
            .unwrap_or_else(|| self.fixture_stacks(request))
    }

    fn describe_stack_events(
        &mut self,
        request: &DescribeStackEventsRequest,
    ) -> std::result::Result<DescribeStackEventsResponse, AwsCloudFormationTransportError> {
        self.requests.push(RecordedRequest {
            operation: RecordedRequestKind::DescribeStackEvents,
            request_digest: request.request_digest(),
            scope_digest: request.scope_digest.clone(),
            page_number: Some(request.page_number()),
        });
        self.describe_stack_events_responses
            .pop_front()
            .unwrap_or_else(|| self.fixture_events(request))
    }

    fn detect_stack_drift(
        &mut self,
        request: &DetectStackDriftRequest,
    ) -> std::result::Result<DetectStackDriftResponse, AwsCloudFormationTransportError> {
        self.requests.push(RecordedRequest {
            operation: RecordedRequestKind::DetectStackDrift,
            request_digest: request.request_digest(),
            scope_digest: request.scope_digest.clone(),
            page_number: None,
        });
        self.detect_stack_drift_responses
            .pop_front()
            .unwrap_or_else(|| self.fixture_detect(request))
    }

    fn describe_stack_drift_detection_status(
        &mut self,
        request: &DescribeStackDriftDetectionStatusRequest,
    ) -> std::result::Result<
        DescribeStackDriftDetectionStatusResponse,
        AwsCloudFormationTransportError,
    > {
        self.requests.push(RecordedRequest {
            operation: RecordedRequestKind::DescribeStackDriftDetectionStatus,
            request_digest: request.request_digest(),
            scope_digest: request.scope_digest.clone(),
            page_number: None,
        });
        self.detection_status_responses
            .pop_front()
            .unwrap_or_else(|| self.fixture_status(request))
    }

    fn describe_stack_resource_drifts(
        &mut self,
        request: &DescribeStackResourceDriftsRequest,
    ) -> std::result::Result<DescribeStackResourceDriftsResponse, AwsCloudFormationTransportError>
    {
        self.requests.push(RecordedRequest {
            operation: RecordedRequestKind::DescribeStackResourceDrifts,
            request_digest: request.request_digest(),
            scope_digest: request.scope_digest.clone(),
            page_number: Some(request.page_number()),
        });
        self.resource_drift_responses
            .pop_front()
            .unwrap_or_else(|| self.fixture_resources(request))
    }
}

#[derive(Clone, Debug)]
pub struct BlockedEnvTransport;

impl AwsCloudFormationTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn describe_stacks(
        &mut self,
        _request: &DescribeStacksRequest,
    ) -> std::result::Result<DescribeStacksResponse, AwsCloudFormationTransportError> {
        Err(AwsCloudFormationTransportError::BlockedEnv)
    }

    fn describe_stack_events(
        &mut self,
        _request: &DescribeStackEventsRequest,
    ) -> std::result::Result<DescribeStackEventsResponse, AwsCloudFormationTransportError> {
        Err(AwsCloudFormationTransportError::BlockedEnv)
    }

    fn detect_stack_drift(
        &mut self,
        _request: &DetectStackDriftRequest,
    ) -> std::result::Result<DetectStackDriftResponse, AwsCloudFormationTransportError> {
        Err(AwsCloudFormationTransportError::BlockedEnv)
    }

    fn describe_stack_drift_detection_status(
        &mut self,
        _request: &DescribeStackDriftDetectionStatusRequest,
    ) -> std::result::Result<
        DescribeStackDriftDetectionStatusResponse,
        AwsCloudFormationTransportError,
    > {
        Err(AwsCloudFormationTransportError::BlockedEnv)
    }

    fn describe_stack_resource_drifts(
        &mut self,
        _request: &DescribeStackResourceDriftsRequest,
    ) -> std::result::Result<DescribeStackResourceDriftsResponse, AwsCloudFormationTransportError>
    {
        Err(AwsCloudFormationTransportError::BlockedEnv)
    }
}

pub type RecordingTransport = QueuedTransport;
pub type FixtureTransport = QueuedTransport;
pub type LoopbackTransport = QueuedTransport;
pub type BlockedEnvAwsCloudFormationTransport = BlockedEnvTransport;
pub type AwsCloudFormationProviderDefinitionError = AwsCloudFormationDriftError;
pub type AwsCloudFormationProviderError = AwsCloudFormationTransportError;
pub type AwsCloudFormationTransportErrorAlias = AwsCloudFormationTransportError;
pub type ProviderProvenance = TransportProvenance;
pub type AwsCloudFormationOperation = CloudFormationOperation;
