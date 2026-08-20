//! Bounded, non-native AWS Security Lake provider seams.
//!
//! No type in this module resolves credentials, signs requests, opens an HTTP
//! connection, or performs a Security Lake mutation. The four transport
//! implementations are fixture/recording/loopback/`BLOCKED_ENV` seams only.

use std::{collections::VecDeque, fmt};

use chrono::Utc;
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{AwsSecurityLakeError, AwsSecurityLakeTransportError, Result};
use crate::model::{
    AwsSecurityLakeOperation, GetDataLakeSourcesRequest, GetDataLakeSourcesResponse,
    ListDataLakeExceptionsRequest, ListDataLakeExceptionsResponse, ListDataLakesRequest,
    ListDataLakesResponse, ListLogSourcesRequest, ListLogSourcesResponse, OpaquePageToken,
    TransportProvenance,
};
use crate::service::AwsSecurityLakeRegistration;
use crate::{
    CONTRACT_VERSION, LAYER1_PERMISSIONS, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID,
};

pub type TransportResult<T> = std::result::Result<T, AwsSecurityLakeTransportError>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsSecurityLakeOperation,
    pub scope_digest: crate::model::Digest,
    pub filter_digest: crate::model::Digest,
    pub cursor_digest: Option<crate::model::Digest>,
    pub request_digest: crate::model::Digest,
    pub path_digest: crate::model::Digest,
}

fn recorded_request(
    operation: AwsSecurityLakeOperation,
    scope: &crate::model::AwsSecurityLakeScope,
    filter_digest: crate::model::Digest,
    cursor: Option<&OpaquePageToken>,
    request_digest: &crate::model::Digest,
    path: String,
) -> RecordedRequest {
    RecordedRequest {
        operation,
        scope_digest: scope.digest(),
        filter_digest,
        cursor_digest: cursor.map(|cursor| cursor.token_digest().clone()),
        request_digest: request_digest.clone(),
        path_digest: crate::model::Digest::from_text(path),
    }
}

/// The only transport interface available to the Layer-1 provider.
pub trait AwsSecurityLakeTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_data_lakes(
        &mut self,
        request: &ListDataLakesRequest,
    ) -> TransportResult<ListDataLakesResponse>;

    fn list_log_sources(
        &mut self,
        request: &ListLogSourcesRequest,
    ) -> TransportResult<ListLogSourcesResponse>;

    fn get_data_lake_sources(
        &mut self,
        request: &GetDataLakeSourcesRequest,
    ) -> TransportResult<GetDataLakeSourcesResponse>;

    fn list_data_lake_exceptions(
        &mut self,
        request: &ListDataLakeExceptionsRequest,
    ) -> TransportResult<ListDataLakeExceptionsResponse>;
}

#[derive(Clone, Debug)]
pub struct AwsSecurityLakeProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub release: String,
    pub capability_digest: crate::model::Digest,
    pub provider_digest: crate::model::Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl AwsSecurityLakeProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0 || release.is_empty() || release.len() > 128 {
            return Err(AwsSecurityLakeError::ProviderDrift);
        }
        let capability_digest = crate::model::Digest::from_parts(
            "aws-security-lake-provider-capabilities/v1",
            &LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .collect::<Vec<_>>(),
        );
        let provider_digest = crate::model::Digest::from_parts(
            "aws-security-lake-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("provider_revision", provider_revision.to_string()),
                ("api_revision", PROVIDER_API_REVISION.to_owned()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
                ("plugin_version", PLUGIN_VERSION.to_owned()),
                ("release", release.clone()),
                ("capability", capability_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
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
            || self.plugin_version != PLUGIN_VERSION
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.capability_digest != expected.capability_digest
            || self.provider_digest != expected.provider_digest
        {
            Err(AwsSecurityLakeError::ProviderDrift)
        } else {
            Ok(())
        }
    }
}

impl Serialize for AwsSecurityLakeProviderDefinition {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsSecurityLakeProviderDefinition", 12)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("release", &self.release)?;
        state.serialize_field("capabilityDigest", &self.capability_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("connected", &self.connected)?;
        state.serialize_field("native", &self.native)?;
        state.serialize_field("firstParty", &self.first_party)?;
        state.serialize_field("providerReceipt", &self.provider_receipt)?;
        state.end()
    }
}

pub struct AwsSecurityLakeProvider<T> {
    transport: T,
    definition: AwsSecurityLakeProviderDefinition,
}

impl<T: AwsSecurityLakeTransport> fmt::Debug for AwsSecurityLakeProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsSecurityLakeProvider")
            .field("definition", &self.definition)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AwsSecurityLakeTransport> AwsSecurityLakeProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, "layer1-recording")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self> {
        let definition = AwsSecurityLakeProviderDefinition::new(provider_revision, release)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn from_registration(
        registration: &AwsSecurityLakeRegistration,
        transport: T,
    ) -> Result<Self> {
        let provider = Self::with_identity(
            transport,
            registration.provider_revision(),
            registration.provider_release().to_owned(),
        )?;
        if provider.definition.provider_digest != *registration.provider_digest() {
            return Err(AwsSecurityLakeError::ProviderDrift);
        }
        Ok(provider)
    }

    pub fn definition(&self) -> &AwsSecurityLakeProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn list_data_lakes(
        &mut self,
        request: &ListDataLakesRequest,
    ) -> TransportResult<ListDataLakesResponse> {
        let response = self.transport.list_data_lakes(request)?;
        self.validate_response(response, request)
    }

    pub fn list_log_sources(
        &mut self,
        request: &ListLogSourcesRequest,
    ) -> TransportResult<ListLogSourcesResponse> {
        let response = self.transport.list_log_sources(request)?;
        self.validate_response(response, request)
    }

    pub fn get_data_lake_sources(
        &mut self,
        request: &GetDataLakeSourcesRequest,
    ) -> TransportResult<GetDataLakeSourcesResponse> {
        let response = self.transport.get_data_lake_sources(request)?;
        self.validate_response(response, request)
    }

    pub fn list_data_lake_exceptions(
        &mut self,
        request: &ListDataLakeExceptionsRequest,
    ) -> TransportResult<ListDataLakeExceptionsResponse> {
        let response = self.transport.list_data_lake_exceptions(request)?;
        self.validate_response(response, request)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    fn validate_response<R, Q>(&self, response: R, request: &Q) -> TransportResult<R>
    where
        R: ValidateAgainst<Q>,
    {
        response
            .validate_against(request, self.provenance())
            .map_err(|_| AwsSecurityLakeTransportError::InvalidResponse)
    }
}

impl Default for AwsSecurityLakeProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked Security Lake provider definition")
    }
}

trait ValidateAgainst<Q>: Sized {
    fn validate_against(self, request: &Q, provenance: TransportProvenance) -> Result<Self>;
}

impl ValidateAgainst<ListDataLakesRequest> for ListDataLakesResponse {
    fn validate_against(
        self,
        request: &ListDataLakesRequest,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        self.validate_integrity(request, Utc::now())?;
        if self.provenance != provenance {
            return Err(AwsSecurityLakeError::TamperedEvidence);
        }
        Ok(self)
    }
}

impl ValidateAgainst<ListLogSourcesRequest> for ListLogSourcesResponse {
    fn validate_against(
        self,
        request: &ListLogSourcesRequest,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        self.validate_integrity(request, Utc::now())?;
        if self.provenance != provenance {
            return Err(AwsSecurityLakeError::TamperedEvidence);
        }
        Ok(self)
    }
}

impl ValidateAgainst<GetDataLakeSourcesRequest> for GetDataLakeSourcesResponse {
    fn validate_against(
        self,
        request: &GetDataLakeSourcesRequest,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        self.validate_integrity(request, Utc::now())?;
        if self.provenance != provenance {
            return Err(AwsSecurityLakeError::TamperedEvidence);
        }
        Ok(self)
    }
}

impl ValidateAgainst<ListDataLakeExceptionsRequest> for ListDataLakeExceptionsResponse {
    fn validate_against(
        self,
        request: &ListDataLakeExceptionsRequest,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        self.validate_integrity(request, Utc::now())?;
        if self.provenance != provenance {
            return Err(AwsSecurityLakeError::TamperedEvidence);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Default)]
struct ResponseQueues {
    data_lakes: VecDeque<TransportResult<ListDataLakesResponse>>,
    log_sources: VecDeque<TransportResult<ListLogSourcesResponse>>,
    data_lake_sources: VecDeque<TransportResult<GetDataLakeSourcesResponse>>,
    exceptions: VecDeque<TransportResult<ListDataLakeExceptionsResponse>>,
}

macro_rules! queue_methods {
    ($type:ident) => {
        impl $type {
            pub fn push_list_data_lakes_response(
                &mut self,
                response: TransportResult<ListDataLakesResponse>,
            ) {
                self.queues.data_lakes.push_back(response);
            }

            pub fn push_list_log_sources_response(
                &mut self,
                response: TransportResult<ListLogSourcesResponse>,
            ) {
                self.queues.log_sources.push_back(response);
            }

            pub fn push_get_data_lake_sources_response(
                &mut self,
                response: TransportResult<GetDataLakeSourcesResponse>,
            ) {
                self.queues.data_lake_sources.push_back(response);
            }

            pub fn push_list_data_lake_exceptions_response(
                &mut self,
                response: TransportResult<ListDataLakeExceptionsResponse>,
            ) {
                self.queues.exceptions.push_back(response);
            }
        }
    };
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    queues: ResponseQueues,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            queues: ResponseQueues::default(),
            requests: Vec::new(),
        }
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

queue_methods!(RecordingTransport);

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    provenance: TransportProvenance,
    queues: ResponseQueues,
    requests: Vec<RecordedRequest>,
}

impl FixtureTransport {
    pub fn new() -> Self {
        Self {
            provenance: TransportProvenance::Fixture,
            queues: ResponseQueues::default(),
            requests: Vec::new(),
        }
    }

    pub fn fixture() -> Self {
        Self::new()
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl Default for FixtureTransport {
    fn default() -> Self {
        Self::new()
    }
}

queue_methods!(FixtureTransport);

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    queues: ResponseQueues,
    requests: Vec<RecordedRequest>,
}

impl LoopbackTransport {
    pub fn new() -> Self {
        Self {
            queues: ResponseQueues::default(),
            requests: Vec::new(),
        }
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl Default for LoopbackTransport {
    fn default() -> Self {
        Self::new()
    }
}

queue_methods!(LoopbackTransport);

fn pop_response<T>(queue: &mut VecDeque<TransportResult<T>>) -> TransportResult<T> {
    queue
        .pop_front()
        .unwrap_or(Err(AwsSecurityLakeTransportError::QueueExhausted))
}

impl AwsSecurityLakeTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn list_data_lakes(
        &mut self,
        request: &ListDataLakesRequest,
    ) -> TransportResult<ListDataLakesResponse> {
        self.requests.push(recorded_request(
            request.operation(),
            request.scope(),
            request.filter_digest(),
            request.cursor(),
            request.request_digest(),
            request.path_and_query(),
        ));
        pop_response(&mut self.queues.data_lakes)
    }

    fn list_log_sources(
        &mut self,
        request: &ListLogSourcesRequest,
    ) -> TransportResult<ListLogSourcesResponse> {
        self.requests.push(recorded_request(
            request.operation(),
            request.scope(),
            request.filter_digest(),
            request.cursor(),
            request.request_digest(),
            request.path_and_query(),
        ));
        pop_response(&mut self.queues.log_sources)
    }

    fn get_data_lake_sources(
        &mut self,
        request: &GetDataLakeSourcesRequest,
    ) -> TransportResult<GetDataLakeSourcesResponse> {
        self.requests.push(recorded_request(
            request.operation(),
            request.scope(),
            request.filter_digest(),
            request.cursor(),
            request.request_digest(),
            request.path_and_query(),
        ));
        pop_response(&mut self.queues.data_lake_sources)
    }

    fn list_data_lake_exceptions(
        &mut self,
        request: &ListDataLakeExceptionsRequest,
    ) -> TransportResult<ListDataLakeExceptionsResponse> {
        self.requests.push(recorded_request(
            request.operation(),
            request.scope(),
            request.filter_digest(),
            request.cursor(),
            request.request_digest(),
            request.path_and_query(),
        ));
        pop_response(&mut self.queues.exceptions)
    }
}

impl AwsSecurityLakeTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn list_data_lakes(
        &mut self,
        request: &ListDataLakesRequest,
    ) -> TransportResult<ListDataLakesResponse> {
        self.requests.push(recorded_request(
            request.operation(),
            request.scope(),
            request.filter_digest(),
            request.cursor(),
            request.request_digest(),
            request.path_and_query(),
        ));
        pop_response(&mut self.queues.data_lakes)
    }

    fn list_log_sources(
        &mut self,
        request: &ListLogSourcesRequest,
    ) -> TransportResult<ListLogSourcesResponse> {
        self.requests.push(recorded_request(
            request.operation(),
            request.scope(),
            request.filter_digest(),
            request.cursor(),
            request.request_digest(),
            request.path_and_query(),
        ));
        pop_response(&mut self.queues.log_sources)
    }

    fn get_data_lake_sources(
        &mut self,
        request: &GetDataLakeSourcesRequest,
    ) -> TransportResult<GetDataLakeSourcesResponse> {
        self.requests.push(recorded_request(
            request.operation(),
            request.scope(),
            request.filter_digest(),
            request.cursor(),
            request.request_digest(),
            request.path_and_query(),
        ));
        pop_response(&mut self.queues.data_lake_sources)
    }

    fn list_data_lake_exceptions(
        &mut self,
        request: &ListDataLakeExceptionsRequest,
    ) -> TransportResult<ListDataLakeExceptionsResponse> {
        self.requests.push(recorded_request(
            request.operation(),
            request.scope(),
            request.filter_digest(),
            request.cursor(),
            request.request_digest(),
            request.path_and_query(),
        ));
        pop_response(&mut self.queues.exceptions)
    }
}

impl AwsSecurityLakeTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn list_data_lakes(
        &mut self,
        request: &ListDataLakesRequest,
    ) -> TransportResult<ListDataLakesResponse> {
        self.requests.push(recorded_request(
            request.operation(),
            request.scope(),
            request.filter_digest(),
            request.cursor(),
            request.request_digest(),
            request.path_and_query(),
        ));
        pop_response(&mut self.queues.data_lakes)
    }

    fn list_log_sources(
        &mut self,
        request: &ListLogSourcesRequest,
    ) -> TransportResult<ListLogSourcesResponse> {
        self.requests.push(recorded_request(
            request.operation(),
            request.scope(),
            request.filter_digest(),
            request.cursor(),
            request.request_digest(),
            request.path_and_query(),
        ));
        pop_response(&mut self.queues.log_sources)
    }

    fn get_data_lake_sources(
        &mut self,
        request: &GetDataLakeSourcesRequest,
    ) -> TransportResult<GetDataLakeSourcesResponse> {
        self.requests.push(recorded_request(
            request.operation(),
            request.scope(),
            request.filter_digest(),
            request.cursor(),
            request.request_digest(),
            request.path_and_query(),
        ));
        pop_response(&mut self.queues.data_lake_sources)
    }

    fn list_data_lake_exceptions(
        &mut self,
        request: &ListDataLakeExceptionsRequest,
    ) -> TransportResult<ListDataLakeExceptionsResponse> {
        self.requests.push(recorded_request(
            request.operation(),
            request.scope(),
            request.filter_digest(),
            request.cursor(),
            request.request_digest(),
            request.path_and_query(),
        ));
        pop_response(&mut self.queues.exceptions)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsSecurityLakeTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_data_lakes(
        &mut self,
        _request: &ListDataLakesRequest,
    ) -> TransportResult<ListDataLakesResponse> {
        Err(AwsSecurityLakeTransportError::EnvironmentBlocked)
    }

    fn list_log_sources(
        &mut self,
        _request: &ListLogSourcesRequest,
    ) -> TransportResult<ListLogSourcesResponse> {
        Err(AwsSecurityLakeTransportError::EnvironmentBlocked)
    }

    fn get_data_lake_sources(
        &mut self,
        _request: &GetDataLakeSourcesRequest,
    ) -> TransportResult<GetDataLakeSourcesResponse> {
        Err(AwsSecurityLakeTransportError::EnvironmentBlocked)
    }

    fn list_data_lake_exceptions(
        &mut self,
        _request: &ListDataLakeExceptionsRequest,
    ) -> TransportResult<ListDataLakeExceptionsResponse> {
        Err(AwsSecurityLakeTransportError::EnvironmentBlocked)
    }
}

pub type AwsSecurityLakeProviderError = AwsSecurityLakeTransportError;
pub type BlockedEnvAwsSecurityLakeTransport = BlockedEnvTransport;
pub type FixtureAwsSecurityLakeTransport = FixtureTransport;
pub type LoopbackAwsSecurityLakeTransport = LoopbackTransport;
pub type RecordingAwsSecurityLakeTransport = RecordingTransport;
