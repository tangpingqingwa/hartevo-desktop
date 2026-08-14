use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
    fmt::Write as _,
};

use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::AwsFirehoseTransportError;
use crate::model::{
    AwsFirehoseDeliveryScope, AwsFirehoseProviderScope, DeliveryStreamName,
    DeliveryStreamObservation, DestinationHealth, DestinationId, DestinationObservation,
    DestinationType, Digest, StreamStatus, TransportProvenance,
};
use crate::{
    API_VERSION, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES, PROVIDER_API_REVISION, PROVIDER_ID,
    PROVIDER_VERSION,
};

pub type TransportResult<T> = std::result::Result<T, AwsFirehoseTransportError>;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AwsFirehoseOperation {
    ListDeliveryStreams,
    DescribeDeliveryStream,
}

impl AwsFirehoseOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListDeliveryStreams => "ListDeliveryStreams",
            Self::DescribeDeliveryStream => "DescribeDeliveryStream",
        }
    }
}

pub trait FirehoseScopeView {
    fn provider_scope(&self) -> &AwsFirehoseProviderScope;
}

impl FirehoseScopeView for AwsFirehoseProviderScope {
    fn provider_scope(&self) -> &AwsFirehoseProviderScope {
        self
    }
}

impl FirehoseScopeView for AwsFirehoseDeliveryScope {
    fn provider_scope(&self) -> &AwsFirehoseProviderScope {
        self.provider_scope()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueExclusiveStart {
    raw_token: String,
    token_digest: Digest,
    provider_scope_digest: Digest,
    limit: u16,
    page_number: u16,
    parent_request_digest: Digest,
}

impl OpaqueExclusiveStart {
    pub fn for_next_page(
        raw_token: impl Into<String>,
        request: &ListDeliveryStreamsRequest,
    ) -> std::result::Result<Self, AwsFirehoseTransportError> {
        let raw_token = raw_token.into();
        if raw_token.is_empty()
            || raw_token.len() > crate::MAX_CURSOR_BYTES
            || raw_token.trim() != raw_token
            || raw_token.chars().any(char::is_control)
        {
            return Err(AwsFirehoseTransportError::BadRequest);
        }
        let token_digest = Digest::from_parts(
            "aws-firehose-exclusive-start-token/v1",
            &[("token", raw_token.clone())],
        );
        Ok(Self {
            raw_token,
            token_digest,
            provider_scope_digest: request.provider_scope_digest().clone(),
            limit: request.limit(),
            page_number: request.page_number().saturating_add(1),
            parent_request_digest: request.request_digest().clone(),
        })
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub(crate) fn validate_against(&self, request: &ListDeliveryStreamsRequest) -> bool {
        self.provider_scope_digest == *request.provider_scope_digest()
            && self.limit == request.limit()
            && self.page_number == request.page_number().saturating_add(1)
            && self.parent_request_digest == *request.request_digest()
            && self.token_digest
                == Digest::from_parts(
                    "aws-firehose-exclusive-start-token/v1",
                    &[("token", self.raw_token.clone())],
                )
    }
}

impl fmt::Debug for OpaqueExclusiveStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueExclusiveStart")
            .field("token_digest", &self.token_digest)
            .field("page_number", &self.page_number)
            .finish_non_exhaustive()
    }
}

impl Serialize for OpaqueExclusiveStart {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("OpaqueExclusiveStart", 2)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListDeliveryStreamsRequest {
    provider_scope: AwsFirehoseProviderScope,
    limit: u16,
    cursor: Option<OpaqueExclusiveStart>,
    request_digest: Digest,
}

impl ListDeliveryStreamsRequest {
    pub fn new<S: FirehoseScopeView + ?Sized>(
        scope: &S,
        limit: u16,
        cursor: Option<OpaqueExclusiveStart>,
    ) -> std::result::Result<Self, AwsFirehoseTransportError> {
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(AwsFirehoseTransportError::BadRequest);
        }
        let provider_scope = scope.provider_scope().clone();
        if let Some(cursor) = &cursor {
            if cursor.provider_scope_digest != *provider_scope.digest()
                || cursor.limit != limit
                || cursor.page_number < 2
            {
                return Err(AwsFirehoseTransportError::BadRequest);
            }
        }
        let request_digest = Digest::from_parts(
            "aws-firehose-list-delivery-streams-request/v1",
            &[
                ("provider_scope", provider_scope.digest().to_string()),
                ("limit", limit.to_string()),
                (
                    "cursor",
                    cursor
                        .as_ref()
                        .map_or_else(String::new, |value| value.token_digest().to_string()),
                ),
                (
                    "page",
                    cursor
                        .as_ref()
                        .map_or_else(|| "1".to_owned(), |value| value.page_number.to_string()),
                ),
            ],
        );
        Ok(Self {
            provider_scope,
            limit,
            cursor,
            request_digest,
        })
    }

    pub fn provider_scope(&self) -> &AwsFirehoseProviderScope {
        &self.provider_scope
    }

    pub fn provider_scope_digest(&self) -> &Digest {
        self.provider_scope.digest()
    }

    pub const fn limit(&self) -> u16 {
        self.limit
    }

    pub fn cursor(&self) -> Option<&OpaqueExclusiveStart> {
        self.cursor.as_ref()
    }

    pub const fn page_number(&self) -> u16 {
        match &self.cursor {
            Some(cursor) => cursor.page_number,
            None => 1,
        }
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        let mut query = format!(
            "Limit={}&ExclusiveStartDeliveryStreamName={}",
            self.limit,
            self.cursor
                .as_ref()
                .map_or_else(String::new, |cursor| cursor.token_digest().to_string())
        );
        let _ = write!(
            query,
            "&account={}&region={}",
            self.provider_scope.account().as_str(),
            self.provider_scope.region().as_str()
        );
        format!("/?{query}")
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsFirehoseOperation::ListDeliveryStreams,
            provider_scope_digest: self.provider_scope_digest().clone(),
            stream_digest: self.provider_scope.target_stream().digest(),
            limit: Some(self.limit),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for ListDeliveryStreamsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListDeliveryStreamsRequest")
            .field("provider_scope_digest", self.provider_scope_digest())
            .field("limit", &self.limit)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListDeliveryStreamsResponse {
    pub provider_scope_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub stream_names: Vec<DeliveryStreamName>,
    pub next_cursor: Option<OpaqueExclusiveStart>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl ListDeliveryStreamsResponse {
    pub fn new(
        request: &ListDeliveryStreamsRequest,
        stream_names: Vec<DeliveryStreamName>,
        next_cursor: Option<OpaqueExclusiveStart>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> TransportResult<Self> {
        let response = Self {
            provider_scope_digest: request.provider_scope_digest().clone(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            stream_names,
            next_cursor,
            response_bytes,
            provenance,
            response_digest: Digest::from_text("pending-firehose-list-response"),
        };
        response.validate_shape(request)?;
        Ok(Self {
            response_digest: response.compute_digest(),
            ..response
        })
    }

    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn validate_integrity(&self, request: &ListDeliveryStreamsRequest) -> TransportResult<()> {
        self.validate_shape(request)?;
        if self.response_digest != self.compute_digest() {
            return Err(AwsFirehoseTransportError::InvalidResponse);
        }
        Ok(())
    }

    fn validate_shape(&self, request: &ListDeliveryStreamsRequest) -> TransportResult<()> {
        if self.provider_scope_digest != *request.provider_scope_digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || !self.provenance.is_non_native()
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.stream_names.len() > request.limit() as usize
        {
            return Err(AwsFirehoseTransportError::InvalidResponse);
        }
        let mut seen = BTreeSet::new();
        for name in &self.stream_names {
            if !seen.insert(name.clone()) {
                return Err(AwsFirehoseTransportError::InvalidResponse);
            }
        }
        if let Some(cursor) = &self.next_cursor
            && !cursor.validate_against(request)
        {
            return Err(AwsFirehoseTransportError::InvalidResponse);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-firehose-list-delivery-streams-response/v1",
            &[
                ("provider_scope", self.provider_scope_digest.to_string()),
                ("request", self.request_digest.to_string()),
                ("page", self.page_number.to_string()),
                (
                    "streams",
                    self.stream_names
                        .iter()
                        .map(DeliveryStreamName::digest)
                        .map(|digest| digest.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| cursor.token_digest().to_string()),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribeDeliveryStreamRequest {
    provider_scope: AwsFirehoseProviderScope,
    request_digest: Digest,
}

impl DescribeDeliveryStreamRequest {
    pub fn new<S: FirehoseScopeView + ?Sized>(scope: &S) -> Self {
        let provider_scope = scope.provider_scope().clone();
        let request_digest = Digest::from_parts(
            "aws-firehose-describe-delivery-stream-request/v1",
            &[
                ("provider_scope", provider_scope.digest().to_string()),
                (
                    "stream",
                    provider_scope.target_stream().digest().to_string(),
                ),
                (
                    "version",
                    provider_scope.stream_version_id().digest().to_string(),
                ),
                (
                    "source_revision",
                    provider_scope.source_revision().get().to_string(),
                ),
            ],
        );
        Self {
            provider_scope,
            request_digest,
        }
    }

    pub fn provider_scope(&self) -> &AwsFirehoseProviderScope {
        &self.provider_scope
    }

    pub fn provider_scope_digest(&self) -> &Digest {
        self.provider_scope.digest()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/deliveryStreams/{}?account={}&region={}",
            self.provider_scope.target_stream().as_str(),
            self.provider_scope.account().as_str(),
            self.provider_scope.region().as_str()
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsFirehoseOperation::DescribeDeliveryStream,
            provider_scope_digest: self.provider_scope_digest().clone(),
            stream_digest: self.provider_scope.target_stream().digest(),
            limit: None,
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for DescribeDeliveryStreamRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribeDeliveryStreamRequest")
            .field("provider_scope_digest", self.provider_scope_digest())
            .field("request_digest", &self.request_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeDeliveryStreamResponse {
    pub provider_scope_digest: Digest,
    pub request_digest: Digest,
    pub observation: DeliveryStreamObservation,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl DescribeDeliveryStreamResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &DescribeDeliveryStreamRequest,
        observation: DeliveryStreamObservation,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> TransportResult<Self> {
        let response = Self {
            provider_scope_digest: request.provider_scope_digest().clone(),
            request_digest: request.request_digest().clone(),
            observation,
            response_bytes,
            provenance,
            response_digest: Digest::from_text("pending-firehose-describe-response"),
        };
        response.validate_shape(request)?;
        Ok(Self {
            response_digest: response.compute_digest(),
            ..response
        })
    }

    pub fn validate_integrity(
        &self,
        request: &DescribeDeliveryStreamRequest,
    ) -> TransportResult<()> {
        self.validate_shape(request)?;
        if self.response_digest != self.compute_digest() {
            return Err(AwsFirehoseTransportError::InvalidResponse);
        }
        Ok(())
    }

    fn validate_shape(&self, request: &DescribeDeliveryStreamRequest) -> TransportResult<()> {
        if self.provider_scope_digest != *request.provider_scope_digest()
            || self.request_digest != *request.request_digest()
            || self.observation.stream_name != *request.provider_scope().target_stream()
            || self.observation.destinations.is_empty()
            || self.response_bytes > MAX_RESPONSE_BYTES
            || !self.provenance.is_non_native()
        {
            return Err(AwsFirehoseTransportError::InvalidResponse);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-firehose-describe-delivery-stream-response/v1",
            &[
                ("provider_scope", self.provider_scope_digest.to_string()),
                ("request", self.request_digest.to_string()),
                ("observation", self.observation.digest().to_string()),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsFirehoseOperation,
    pub provider_scope_digest: Digest,
    pub stream_digest: Digest,
    pub limit: Option<u16>,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
}

pub trait AwsFirehoseTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_delivery_streams(
        &mut self,
        request: &ListDeliveryStreamsRequest,
    ) -> TransportResult<ListDeliveryStreamsResponse>;

    fn describe_delivery_stream(
        &mut self,
        request: &DescribeDeliveryStreamRequest,
    ) -> TransportResult<DescribeDeliveryStreamResponse>;
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsFirehoseTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_delivery_streams(
        &mut self,
        _request: &ListDeliveryStreamsRequest,
    ) -> TransportResult<ListDeliveryStreamsResponse> {
        Err(AwsFirehoseTransportError::BlockedEnv)
    }

    fn describe_delivery_stream(
        &mut self,
        _request: &DescribeDeliveryStreamRequest,
    ) -> TransportResult<DescribeDeliveryStreamResponse> {
        Err(AwsFirehoseTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    provider_scope: AwsFirehoseProviderScope,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsFirehoseDeliveryScope) -> Self {
        Self {
            provider_scope: scope.provider_scope().clone(),
        }
    }

    pub fn for_provider_scope(scope: &AwsFirehoseProviderScope) -> Self {
        Self {
            provider_scope: scope.clone(),
        }
    }

    fn observation(&self) -> crate::error::Result<DeliveryStreamObservation> {
        let configuration_fingerprint = Digest::from_parts(
            "aws-firehose-fixture-configuration/v1",
            &[("scope", self.provider_scope.digest().to_string())],
        );
        let encryption_fingerprint = Some(Digest::from_parts(
            "aws-firehose-fixture-encryption/v1",
            &[("scope", self.provider_scope.digest().to_string())],
        ));
        let destination = DestinationObservation::new(
            DestinationId::new("destination-1")?,
            DestinationType::ExtendedS3,
            DestinationHealth::Healthy,
            configuration_fingerprint.clone(),
            encryption_fingerprint.clone(),
        )?;
        DeliveryStreamObservation::new(
            self.provider_scope.target_stream().clone(),
            StreamStatus::Active,
            self.provider_scope.stream_version_id().clone(),
            self.provider_scope.source_revision(),
            vec![destination],
            encryption_fingerprint,
            configuration_fingerprint,
        )
    }
}

impl AwsFirehoseTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn list_delivery_streams(
        &mut self,
        request: &ListDeliveryStreamsRequest,
    ) -> TransportResult<ListDeliveryStreamsResponse> {
        let names = if request.cursor().is_none() {
            vec![self.provider_scope.target_stream().clone()]
        } else {
            Vec::new()
        };
        ListDeliveryStreamsResponse::new(request, names, None, 512, self.provenance())
    }

    fn describe_delivery_stream(
        &mut self,
        request: &DescribeDeliveryStreamRequest,
    ) -> TransportResult<DescribeDeliveryStreamResponse> {
        DescribeDeliveryStreamResponse::new(
            request,
            self.observation()
                .map_err(|_| AwsFirehoseTransportError::InvalidResponse)?,
            768,
            self.provenance(),
        )
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    provider_scope: AwsFirehoseProviderScope,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsFirehoseDeliveryScope) -> Self {
        Self {
            provider_scope: scope.provider_scope().clone(),
        }
    }
}

impl AwsFirehoseTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn list_delivery_streams(
        &mut self,
        request: &ListDeliveryStreamsRequest,
    ) -> TransportResult<ListDeliveryStreamsResponse> {
        let names = if request.cursor().is_none() {
            vec![self.provider_scope.target_stream().clone()]
        } else {
            Vec::new()
        };
        ListDeliveryStreamsResponse::new(request, names, None, 512, self.provenance())
    }

    fn describe_delivery_stream(
        &mut self,
        request: &DescribeDeliveryStreamRequest,
    ) -> TransportResult<DescribeDeliveryStreamResponse> {
        let configuration_fingerprint = Digest::from_parts(
            "aws-firehose-loopback-configuration/v1",
            &[("scope", self.provider_scope.digest().to_string())],
        );
        let destination = DestinationObservation::new(
            DestinationId::new("destination-loopback")
                .map_err(|_| AwsFirehoseTransportError::InvalidResponse)?,
            DestinationType::HttpEndpoint,
            DestinationHealth::Healthy,
            configuration_fingerprint.clone(),
            None,
        )
        .map_err(|_| AwsFirehoseTransportError::InvalidResponse)?;
        let observation = DeliveryStreamObservation::new(
            self.provider_scope.target_stream().clone(),
            StreamStatus::Active,
            self.provider_scope.stream_version_id().clone(),
            self.provider_scope.source_revision(),
            vec![destination],
            None,
            configuration_fingerprint,
        )
        .map_err(|_| AwsFirehoseTransportError::InvalidResponse)?;
        DescribeDeliveryStreamResponse::new(request, observation, 640, self.provenance())
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    list_responses: VecDeque<TransportResult<ListDeliveryStreamsResponse>>,
    describe_responses: VecDeque<TransportResult<DescribeDeliveryStreamResponse>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            list_responses: VecDeque::new(),
            describe_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_list_response(&mut self, response: TransportResult<ListDeliveryStreamsResponse>) {
        self.list_responses.push_back(response);
    }

    pub fn push_describe_response(
        &mut self,
        response: TransportResult<DescribeDeliveryStreamResponse>,
    ) {
        self.describe_responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}

impl AwsFirehoseTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn list_delivery_streams(
        &mut self,
        request: &ListDeliveryStreamsRequest,
    ) -> TransportResult<ListDeliveryStreamsResponse> {
        self.requests.push(request.recorded_request());
        self.list_responses
            .pop_front()
            .unwrap_or(Err(AwsFirehoseTransportError::InvalidResponse))
    }

    fn describe_delivery_stream(
        &mut self,
        request: &DescribeDeliveryStreamRequest,
    ) -> TransportResult<DescribeDeliveryStreamResponse> {
        self.requests.push(request.recorded_request());
        self.describe_responses
            .pop_front()
            .unwrap_or(Err(AwsFirehoseTransportError::InvalidResponse))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsFirehoseProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub api_version: String,
    pub api_revision: String,
    pub operations: Vec<AwsFirehoseOperation>,
    pub allowed_permissions: Vec<String>,
    pub accepted_provenance: Vec<TransportProvenance>,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub provider_receipt: bool,
    pub provider_digest: Digest,
}

impl AwsFirehoseProviderDefinition {
    pub fn new() -> Self {
        let mut definition = Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PROVIDER_VERSION.to_owned(),
            api_version: API_VERSION.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            operations: vec![
                AwsFirehoseOperation::ListDeliveryStreams,
                AwsFirehoseOperation::DescribeDeliveryStream,
            ],
            allowed_permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            accepted_provenance: vec![
                TransportProvenance::Recording,
                TransportProvenance::Fixture,
                TransportProvenance::Loopback,
                TransportProvenance::BlockedEnv,
            ],
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            provider_receipt: false,
            provider_digest: Digest::from_text("pending-firehose-provider-definition"),
        };
        definition.provider_digest = definition.compute_digest();
        definition
    }

    pub fn validate(&self) -> crate::error::Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.provider_version != PROVIDER_VERSION
            || self.api_version != API_VERSION
            || self.api_revision != PROVIDER_API_REVISION
            || self.operations
                != vec![
                    AwsFirehoseOperation::ListDeliveryStreams,
                    AwsFirehoseOperation::DescribeDeliveryStream,
                ]
            || self.allowed_permissions
                != crate::LAYER1_PERMISSIONS
                    .iter()
                    .map(|permission| (*permission).to_owned())
                    .collect::<Vec<_>>()
            || self.accepted_provenance
                != vec![
                    TransportProvenance::Recording,
                    TransportProvenance::Fixture,
                    TransportProvenance::Loopback,
                    TransportProvenance::BlockedEnv,
                ]
            || self.connected
            || self.native
            || self.first_party
            || self.external_writes
            || self.provider_receipt
            || self.provider_digest != self.compute_digest()
        {
            return Err(crate::error::AwsFirehoseError::ProviderDrift);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-firehose-provider-definition/v1",
            &[
                ("provider_id", self.provider_id.clone()),
                ("provider_version", self.provider_version.clone()),
                ("api_version", self.api_version.clone()),
                ("api_revision", self.api_revision.clone()),
                (
                    "operations",
                    self.operations
                        .iter()
                        .map(|operation| operation.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("permissions", self.allowed_permissions.join(",")),
                (
                    "provenance",
                    self.accepted_provenance
                        .iter()
                        .map(|value| value.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("writes", self.external_writes.to_string()),
                ("receipt", self.provider_receipt.to_string()),
            ],
        )
    }
}

impl Default for AwsFirehoseProviderDefinition {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AwsFirehoseProvider<T> {
    transport: T,
    definition: AwsFirehoseProviderDefinition,
}

impl<T: fmt::Debug> fmt::Debug for AwsFirehoseProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsFirehoseProvider")
            .field("transport", &self.transport)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: AwsFirehoseTransport> AwsFirehoseProvider<T> {
    pub fn new(transport: T) -> crate::error::Result<Self> {
        let definition = AwsFirehoseProviderDefinition::new();
        definition.validate()?;
        if !definition
            .accepted_provenance
            .contains(&transport.provenance())
        {
            return Err(crate::error::AwsFirehoseError::ProviderDrift);
        }
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn with_definition(
        transport: T,
        definition: AwsFirehoseProviderDefinition,
    ) -> crate::error::Result<Self> {
        definition.validate()?;
        if !definition
            .accepted_provenance
            .contains(&transport.provenance())
        {
            return Err(crate::error::AwsFirehoseError::ProviderDrift);
        }
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn from_registration(
        registration: &crate::service::AwsFirehoseRegistration,
        transport: T,
    ) -> crate::error::Result<Self> {
        let provider = Self::new(transport)?;
        if provider.definition.provider_digest != *registration.provider_digest() {
            return Err(crate::error::AwsFirehoseError::ProviderDrift);
        }
        Ok(provider)
    }

    pub fn definition(&self) -> &AwsFirehoseProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn list_delivery_streams(
        &mut self,
        request: &ListDeliveryStreamsRequest,
    ) -> TransportResult<ListDeliveryStreamsResponse> {
        let response = self.transport.list_delivery_streams(request)?;
        response.validate_integrity(request)?;
        if response.provenance != self.provenance() || !response.provenance.is_non_native() {
            return Err(AwsFirehoseTransportError::InvalidResponse);
        }
        if response.stream_names.iter().any(|name| {
            !request
                .provider_scope()
                .allowlisted_streams()
                .contains(name)
        }) {
            return Err(AwsFirehoseTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn describe_delivery_stream(
        &mut self,
        request: &DescribeDeliveryStreamRequest,
    ) -> TransportResult<DescribeDeliveryStreamResponse> {
        let response = self.transport.describe_delivery_stream(request)?;
        response.validate_integrity(request)?;
        if response.provenance != self.provenance() || !response.provenance.is_non_native() {
            return Err(AwsFirehoseTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl Default for AwsFirehoseProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked AWS Firehose provider definition")
    }
}

pub type FixtureAwsFirehoseTransport = FixtureTransport;
pub type LoopbackAwsFirehoseTransport = LoopbackTransport;
pub type RecordingAwsFirehoseTransport = RecordingTransport;
pub type AwsFirehoseProviderDefinitionError = crate::error::AwsFirehoseError;

pub const _PROVIDER_BOUND: (&str, &str, u16) = (API_VERSION, PROVIDER_API_REVISION, MAX_PAGES);
