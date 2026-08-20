use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{AwsAthenaQueryResultError, AwsAthenaTransportError, Result};
use crate::model::{
    AthenaExecutionState, AwsAthenaQueryResultScope, ColumnShape, ColumnType, Digest,
    OpaquePageToken, QueryExecutionId, QueryExecutionMetadata, QueryResultsProjection,
    ResultBounds, RowShape, TransportProvenance, result_page_binding_digest,
};
use crate::{
    CONTRACT_VERSION, LAYER1_PERMISSIONS, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AwsAthenaOperation {
    GetQueryExecution,
    GetQueryResults,
}

impl AwsAthenaOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetQueryExecution => "GetQueryExecution",
            Self::GetQueryResults => "GetQueryResults",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsAthenaOperation,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub execution_id_digest: Digest,
    pub page_token_digest: Option<Digest>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetQueryExecutionRequest {
    scope_digest: Digest,
    query_digest: Digest,
    execution_id: QueryExecutionId,
    request_digest: Digest,
}

impl GetQueryExecutionRequest {
    pub fn new(
        scope: &AwsAthenaQueryResultScope,
        query_digest: Digest,
        execution_id: QueryExecutionId,
    ) -> Result<Self> {
        query_digest.validate()?;
        execution_id.validate()?;
        let scope_digest = scope.digest();
        let request_digest = Digest::from_parts(
            "aws-athena-get-query-execution-request/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("query", query_digest.as_str().to_owned()),
                ("execution", execution_id.digest().as_str().to_owned()),
            ],
        );
        Ok(Self {
            scope_digest,
            query_digest,
            execution_id,
            request_digest,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn execution_id(&self) -> &QueryExecutionId {
        &self.execution_id
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsAthenaOperation::GetQueryExecution,
            request_digest: self.request_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            query_digest: self.query_digest.clone(),
            execution_id_digest: self.execution_id.digest(),
            page_token_digest: None,
        }
    }
}

impl fmt::Debug for GetQueryExecutionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetQueryExecutionRequest")
            .field("scope_digest", &self.scope_digest)
            .field("query_digest", &self.query_digest)
            .field("execution_id", &self.execution_id)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetQueryResultsRequest {
    scope_digest: Digest,
    query_digest: Digest,
    execution_id: QueryExecutionId,
    bounds: ResultBounds,
    page_token: Option<OpaquePageToken>,
    page_number: u16,
    binding_digest: Digest,
    request_digest: Digest,
}

impl GetQueryResultsRequest {
    pub fn new(
        scope: &AwsAthenaQueryResultScope,
        query_digest: Digest,
        execution_id: QueryExecutionId,
        bounds: ResultBounds,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self> {
        query_digest.validate()?;
        execution_id.validate()?;
        bounds.validate()?;
        let binding_digest =
            result_page_binding_digest(scope, &query_digest, &execution_id, bounds);
        let page_number = page_token.as_ref().map_or(1, OpaquePageToken::page_number);
        if let Some(token) = &page_token {
            token.validate_against(&binding_digest, page_number)?;
        }
        if page_number == 0 || page_number > bounds.max_pages() {
            return Err(AwsAthenaQueryResultError::InvalidRequest);
        }
        let scope_digest = scope.digest();
        let request_digest = Digest::from_parts(
            "aws-athena-get-query-results-request/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("query", query_digest.as_str().to_owned()),
                ("execution", execution_id.digest().as_str().to_owned()),
                ("binding", binding_digest.as_str().to_owned()),
                ("page", page_number.to_string()),
                (
                    "token",
                    page_token.as_ref().map_or_else(String::new, |token| {
                        token.token_digest().as_str().to_owned()
                    }),
                ),
                ("page_size", bounds.page_size().to_string()),
            ],
        );
        Ok(Self {
            scope_digest,
            query_digest,
            execution_id,
            bounds,
            page_token,
            page_number,
            binding_digest,
            request_digest,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    pub fn execution_id(&self) -> &QueryExecutionId {
        &self.execution_id
    }

    pub const fn bounds(&self) -> ResultBounds {
        self.bounds
    }

    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsAthenaOperation::GetQueryResults,
            request_digest: self.request_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            query_digest: self.query_digest.clone(),
            execution_id_digest: self.execution_id.digest(),
            page_token_digest: self
                .page_token
                .as_ref()
                .map(|token| token.token_digest().clone()),
        }
    }
}

impl fmt::Debug for GetQueryResultsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetQueryResultsRequest")
            .field("scope_digest", &self.scope_digest)
            .field("query_digest", &self.query_digest)
            .field("execution_id", &self.execution_id)
            .field("bounds", &self.bounds)
            .field("page_token", &self.page_token)
            .field("page_number", &self.page_number)
            .field("binding_digest", &self.binding_digest)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetQueryExecutionResponse {
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub request_digest: Digest,
    pub execution: QueryExecutionMetadata,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl GetQueryExecutionResponse {
    pub fn new(
        request: &GetQueryExecutionRequest,
        execution: QueryExecutionMetadata,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if provenance.is_native() {
            return Err(AwsAthenaQueryResultError::InvalidResponse);
        }
        let scope_digest = request.scope_digest.clone();
        let query_digest = request.query_digest.clone();
        execution
            .validate_against_digest(&scope_digest, &query_digest)
            .map_err(|_| AwsAthenaQueryResultError::ExecutionDrift)?;
        let mut response = Self {
            scope_digest,
            query_digest,
            request_digest: request.request_digest.clone(),
            execution,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-athena-get-query-execution-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, request: &GetQueryExecutionRequest) -> Result<()> {
        if self.scope_digest != *request.scope_digest()
            || self.query_digest != *request.query_digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
            || self.execution.execution_id() != request.execution_id()
        {
            return Err(AwsAthenaQueryResultError::EvidenceTampered);
        }
        self.execution
            .validate_against_digest(&self.scope_digest, &self.query_digest)
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-athena-get-query-execution-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("query", self.query_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("execution", self.execution.digest().as_str().to_owned()),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetQueryResultsResponse {
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub request_digest: Digest,
    pub execution_id_digest: Digest,
    pub page_number: u16,
    pub projection: QueryResultsProjection,
    pub next_page_token: Option<OpaquePageToken>,
    pub complete: bool,
    pub truncated: bool,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl GetQueryResultsResponse {
    pub fn new(
        request: &GetQueryResultsRequest,
        projection: QueryResultsProjection,
        next_page_token: Option<OpaquePageToken>,
        complete: bool,
        truncated: bool,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        projection.validate()?;
        if projection.row_count > u32::from(request.bounds().page_size()) {
            return Err(AwsAthenaQueryResultError::PartialEvidence);
        }
        if complete && next_page_token.is_some() {
            return Err(AwsAthenaQueryResultError::InvalidResponse);
        }
        if let Some(token) = &next_page_token {
            token.validate_against(&request.binding_digest, request.page_number() + 1)?;
        }
        let mut response = Self {
            scope_digest: request.scope_digest.clone(),
            query_digest: request.query_digest.clone(),
            request_digest: request.request_digest.clone(),
            execution_id_digest: request.execution_id.digest(),
            page_number: request.page_number,
            projection,
            next_page_token,
            complete,
            truncated,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-athena-get-query-results-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, request: &GetQueryResultsRequest) -> Result<()> {
        if self.scope_digest != *request.scope_digest()
            || self.query_digest != *request.query_digest()
            || self.request_digest != *request.request_digest()
            || self.execution_id_digest != request.execution_id.digest()
            || self.page_number != request.page_number()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsAthenaQueryResultError::EvidenceTampered);
        }
        self.projection.validate()?;
        if let Some(token) = &self.next_page_token {
            token.validate_against(&request.binding_digest, request.page_number() + 1)?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-athena-get-query-results-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("query", self.query_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("execution", self.execution_id_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "projection",
                    self.projection.shape_digest.as_str().to_owned(),
                ),
                (
                    "next_token",
                    self.next_page_token
                        .as_ref()
                        .map_or_else(String::new, |token| {
                            token.token_digest().as_str().to_owned()
                        }),
                ),
                ("complete", self.complete.to_string()),
                ("truncated", self.truncated.to_string()),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

fn validate_response_bytes(response_bytes: u64) -> Result<()> {
    if response_bytes > crate::MAX_RESPONSE_BYTES {
        Err(AwsAthenaQueryResultError::PartialEvidence)
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsAthenaProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub contract_version: String,
    pub release: String,
    pub capability_digest: Digest,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl AwsAthenaProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0 || release.is_empty() || release.len() > 128 {
            return Err(AwsAthenaQueryResultError::ProviderDrift);
        }
        let capability_digest = Digest::from_parts(
            "aws-athena-provider-capabilities/v1",
            &LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .collect::<Vec<_>>(),
        );
        let provider_digest = Digest::from_parts(
            "aws-athena-provider/v1",
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
            release,
            capability_digest,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(self.provider_revision, self.release.clone())?;
        if self.provider_id != PROVIDER_ID
            || self.api_revision != PROVIDER_API_REVISION
            || self.contract_version != CONTRACT_VERSION
            || self.connected
            || self.native
            || self.first_party
            || self.provider_digest != expected.provider_digest
        {
            Err(AwsAthenaQueryResultError::ProviderDrift)
        } else {
            Ok(())
        }
    }
}

impl Serialize for AwsAthenaProviderDefinition {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsAthenaProviderDefinition", 10)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("release", &self.release)?;
        state.serialize_field("capabilityDigest", &self.capability_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("connected", &self.connected)?;
        state.serialize_field("native", &self.native)?;
        state.serialize_field("firstParty", &self.first_party)?;
        state.end()
    }
}

pub trait AwsAthenaTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn get_query_execution(
        &mut self,
        request: &GetQueryExecutionRequest,
    ) -> std::result::Result<GetQueryExecutionResponse, AwsAthenaTransportError>;

    fn get_query_results(
        &mut self,
        request: &GetQueryResultsRequest,
    ) -> std::result::Result<GetQueryResultsResponse, AwsAthenaTransportError>;
}

pub struct AwsAthenaProvider<T> {
    transport: T,
    definition: AwsAthenaProviderDefinition,
}

impl<T: AwsAthenaTransport> fmt::Debug for AwsAthenaProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAthenaProvider")
            .field("definition", &self.definition)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AwsAthenaTransport> AwsAthenaProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, "layer1-recording")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self> {
        let definition = AwsAthenaProviderDefinition::new(provider_revision, release)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsAthenaProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn get_query_execution(
        &mut self,
        request: &GetQueryExecutionRequest,
    ) -> std::result::Result<GetQueryExecutionResponse, AwsAthenaTransportError> {
        let response = self.transport.get_query_execution(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsAthenaTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.first_party
            || response.provider_receipt
        {
            return Err(AwsAthenaTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn get_query_results(
        &mut self,
        request: &GetQueryResultsRequest,
    ) -> std::result::Result<GetQueryResultsResponse, AwsAthenaTransportError> {
        let response = self.transport.get_query_results(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsAthenaTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.first_party
            || response.provider_receipt
        {
            return Err(AwsAthenaTransportError::InvalidResponse);
        }
        Ok(response)
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
}

impl Default for AwsAthenaProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked Athena provider definition")
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    execution_responses:
        VecDeque<std::result::Result<GetQueryExecutionResponse, AwsAthenaTransportError>>,
    result_responses:
        VecDeque<std::result::Result<GetQueryResultsResponse, AwsAthenaTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            execution_responses: VecDeque::new(),
            result_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_execution_response(
        &mut self,
        response: std::result::Result<GetQueryExecutionResponse, AwsAthenaTransportError>,
    ) {
        self.execution_responses.push_back(response);
    }

    pub fn push_query_execution_response(
        &mut self,
        response: std::result::Result<GetQueryExecutionResponse, AwsAthenaTransportError>,
    ) {
        self.push_execution_response(response);
    }

    pub fn push_results_response(
        &mut self,
        response: std::result::Result<GetQueryResultsResponse, AwsAthenaTransportError>,
    ) {
        self.result_responses.push_back(response);
    }

    pub fn push_query_results_response(
        &mut self,
        response: std::result::Result<GetQueryResultsResponse, AwsAthenaTransportError>,
    ) {
        self.push_results_response(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    pub fn execution_calls(&self) -> usize {
        self.requests
            .iter()
            .filter(|request| request.operation == AwsAthenaOperation::GetQueryExecution)
            .count()
    }

    pub fn result_calls(&self) -> usize {
        self.requests
            .iter()
            .filter(|request| request.operation == AwsAthenaOperation::GetQueryResults)
            .count()
    }
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}

impl AwsAthenaTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn get_query_execution(
        &mut self,
        request: &GetQueryExecutionRequest,
    ) -> std::result::Result<GetQueryExecutionResponse, AwsAthenaTransportError> {
        self.requests.push(request.recorded_request());
        self.execution_responses
            .pop_front()
            .unwrap_or(Err(AwsAthenaTransportError::InvalidResponse))
    }

    fn get_query_results(
        &mut self,
        request: &GetQueryResultsRequest,
    ) -> std::result::Result<GetQueryResultsResponse, AwsAthenaTransportError> {
        self.requests.push(request.recorded_request());
        self.result_responses
            .pop_front()
            .unwrap_or(Err(AwsAthenaTransportError::InvalidResponse))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: AwsAthenaQueryResultScope,
    observed_at: DateTime<Utc>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsAthenaQueryResultScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }

    fn execution(&self, request: &GetQueryExecutionRequest) -> Result<QueryExecutionMetadata> {
        let _ = self.observed_at;
        QueryExecutionMetadata::new(
            &self.scope,
            request.query_digest().clone(),
            request.execution_id().clone(),
            AthenaExecutionState::Succeeded,
            Some(1_024),
            Some(75),
            Some("s3://fixture.invalid/athena/output"),
            None::<&str>,
            false,
        )
    }

    fn results(request: &GetQueryResultsRequest) -> Result<QueryResultsProjection> {
        let columns = vec![
            ColumnShape::new(1, "fixture_id", ColumnType::Integer, false)?,
            ColumnShape::new(2, "fixture_value", ColumnType::String, true)?,
        ];
        let row = RowShape::from_public_values(
            vec![ColumnType::Integer, ColumnType::String],
            [b"1".as_slice(), b"fixture-redacted".as_slice()],
        )?;
        let _ = request;
        QueryResultsProjection::new(columns, vec![row])
    }
}

impl AwsAthenaTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn get_query_execution(
        &mut self,
        request: &GetQueryExecutionRequest,
    ) -> std::result::Result<GetQueryExecutionResponse, AwsAthenaTransportError> {
        let metadata = self
            .execution(request)
            .map_err(|_| AwsAthenaTransportError::InvalidResponse)?;
        GetQueryExecutionResponse::new(request, metadata, 768, TransportProvenance::Fixture)
            .map_err(|_| AwsAthenaTransportError::InvalidResponse)
    }

    fn get_query_results(
        &mut self,
        request: &GetQueryResultsRequest,
    ) -> std::result::Result<GetQueryResultsResponse, AwsAthenaTransportError> {
        let projection =
            Self::results(request).map_err(|_| AwsAthenaTransportError::InvalidResponse)?;
        GetQueryResultsResponse::new(
            request,
            projection,
            None,
            true,
            false,
            512,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsAthenaTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsAthenaQueryResultScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: FixtureTransport::for_scope(scope, observed_at),
        }
    }
}

impl AwsAthenaTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn get_query_execution(
        &mut self,
        request: &GetQueryExecutionRequest,
    ) -> std::result::Result<GetQueryExecutionResponse, AwsAthenaTransportError> {
        let metadata = self
            .inner
            .execution(request)
            .map_err(|_| AwsAthenaTransportError::InvalidResponse)?;
        GetQueryExecutionResponse::new(request, metadata, 768, TransportProvenance::Loopback)
            .map_err(|_| AwsAthenaTransportError::InvalidResponse)
    }

    fn get_query_results(
        &mut self,
        request: &GetQueryResultsRequest,
    ) -> std::result::Result<GetQueryResultsResponse, AwsAthenaTransportError> {
        let projection = FixtureTransport::results(request)
            .map_err(|_| AwsAthenaTransportError::InvalidResponse)?;
        GetQueryResultsResponse::new(
            request,
            projection,
            None,
            true,
            false,
            512,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsAthenaTransportError::InvalidResponse)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsAthenaTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn get_query_execution(
        &mut self,
        _request: &GetQueryExecutionRequest,
    ) -> std::result::Result<GetQueryExecutionResponse, AwsAthenaTransportError> {
        Err(AwsAthenaTransportError::BlockedEnv)
    }

    fn get_query_results(
        &mut self,
        _request: &GetQueryResultsRequest,
    ) -> std::result::Result<GetQueryResultsResponse, AwsAthenaTransportError> {
        Err(AwsAthenaTransportError::BlockedEnv)
    }
}
