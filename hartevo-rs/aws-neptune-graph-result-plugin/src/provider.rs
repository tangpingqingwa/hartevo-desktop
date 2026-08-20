use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use zeroize::Zeroizing;

use crate::{
    API_REVISION, CONTRACT_VERSION, Digest, OpenCypherQuery, TransportProvenance,
    error::{AwsNeptuneGraphResultError, AwsNeptuneTransportError, Result},
    model::{AwsNeptuneGraphScope, GraphRowProjection},
};

/// The only provider operation exposed by this Layer-1 plugin.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsNeptuneOperation {
    ExecuteOpenCypherQuery,
}

impl AwsNeptuneOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExecuteOpenCypherQuery => "ExecuteOpenCypherQuery",
        }
    }
}

/// A provider transport seam.  Implementations in this crate are recording,
/// fixture, loopback, or blocked-environment only.
pub trait AwsNeptuneTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn execute_open_cypher_query(
        &mut self,
        request: &ExecuteOpenCypherQueryRequest,
    ) -> std::result::Result<ExecuteOpenCypherQueryResponse, AwsNeptuneTransportError>;
}

/// A bounded opaque pagination cursor.  Its token material is zeroized and
/// only its digest is serializable/debuggable.
pub struct OpaqueCursor {
    token: Zeroizing<String>,
    token_digest: Digest,
    scope_digest: Option<Digest>,
    query_digest: Option<Digest>,
    page_number: u16,
}

impl Clone for OpaqueCursor {
    fn clone(&self) -> Self {
        Self {
            token: Zeroizing::new(self.token.to_string()),
            token_digest: self.token_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            query_digest: self.query_digest.clone(),
            page_number: self.page_number,
        }
    }
}

impl PartialEq for OpaqueCursor {
    fn eq(&self, other: &Self) -> bool {
        self.token_digest == other.token_digest
            && self.scope_digest == other.scope_digest
            && self.query_digest == other.query_digest
            && self.page_number == other.page_number
    }
}

impl Eq for OpaqueCursor {}

impl OpaqueCursor {
    pub fn new(token: impl Into<String>) -> Result<Self> {
        let token = token.into();
        if token.is_empty() || token.len() > 4096 || token.chars().any(char::is_control) {
            return Err(AwsNeptuneGraphResultError::InvalidRequest);
        }
        Ok(Self {
            token_digest: Digest::from_text(&token),
            token: Zeroizing::new(token),
            scope_digest: None,
            query_digest: None,
            page_number: 0,
        })
    }

    pub fn for_request(
        token: impl Into<String>,
        request: &ExecuteOpenCypherQueryRequest,
        page_number: u16,
    ) -> Result<Self> {
        if page_number == 0 {
            return Err(AwsNeptuneGraphResultError::InvalidRequest);
        }
        let mut cursor = Self::new(token)?;
        cursor.scope_digest = Some(request.scope_digest.clone());
        cursor.query_digest = Some(request.query.query_digest().clone());
        cursor.page_number = page_number;
        Ok(cursor)
    }

    pub fn bind(
        &mut self,
        scope_digest: &Digest,
        query_digest: &Digest,
        page_number: u16,
    ) -> Result<()> {
        if page_number == 0 {
            return Err(AwsNeptuneGraphResultError::InvalidRequest);
        }
        if self.scope_digest.is_some() || self.query_digest.is_some() {
            return self.validate_against(scope_digest, query_digest, page_number);
        }
        self.scope_digest = Some(scope_digest.clone());
        self.query_digest = Some(query_digest.clone());
        self.page_number = page_number;
        Ok(())
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub(crate) fn validate_against(
        &self,
        scope_digest: &Digest,
        query_digest: &Digest,
        expected_page: u16,
    ) -> Result<()> {
        if self.scope_digest.as_ref() != Some(scope_digest)
            || self.query_digest.as_ref() != Some(query_digest)
            || self.page_number != expected_page
        {
            Err(AwsNeptuneGraphResultError::ResponseFenceMismatch)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("token_digest", &self.token_digest)
            .field("scope_digest", &self.scope_digest)
            .field("query_digest", &self.query_digest)
            .field("page_number", &self.page_number)
            .finish_non_exhaustive()
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("OpaqueCursor", 2)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.end()
    }
}

/// Request metadata passed to a transport; raw openCypher and parameter values
/// are intentionally absent from its serialized form.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecuteOpenCypherQueryRequest {
    query: OpenCypherQuery,
    scope_digest: Digest,
    page_number: u16,
    cursor: Option<OpaqueCursor>,
    request_digest: Digest,
}

impl ExecuteOpenCypherQueryRequest {
    pub fn new(scope: &AwsNeptuneGraphScope, query: OpenCypherQuery) -> Result<Self> {
        query
            .bind_to_scope(scope)
            .map_err(|_| AwsNeptuneGraphResultError::ScopeMismatch)?;
        let request = Self {
            query,
            scope_digest: scope.digest(),
            page_number: 1,
            cursor: None,
            request_digest: Digest::from_text("unsealed-neptune-request"),
        };
        Ok(request.with_recomputed_digest())
    }

    pub fn with_cursor(&self, mut cursor: OpaqueCursor) -> Result<Self> {
        let next_page = self
            .page_number
            .checked_add(1)
            .ok_or(AwsNeptuneGraphResultError::InvalidRequest)?;
        cursor.bind(&self.scope_digest, self.query.query_digest(), next_page)?;
        let mut request = self.clone();
        request.page_number = next_page;
        request.cursor = Some(cursor);
        Ok(request.with_recomputed_digest())
    }

    pub fn query(&self) -> &OpenCypherQuery {
        &self.query
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn cursor(&self) -> Option<&OpaqueCursor> {
        self.cursor.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsNeptuneOperation::ExecuteOpenCypherQuery,
            scope_digest: self.scope_digest.clone(),
            query_template_digest: self.query.template_digest().clone(),
            parameter_digest: self.query.parameter_digest().clone(),
            query_digest: self.query.query_digest().clone(),
            page_number: self.page_number,
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            row_limit: self.query.limits().max_rows,
            byte_limit: self.query.limits().max_bytes,
            timeout_ms: self.query.limits().timeout_ms,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(API_REVISION),
        }
    }

    fn with_recomputed_digest(mut self) -> Self {
        self.request_digest = Digest::from_parts(
            "aws-neptune-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("template", self.query.template_digest().as_str().to_owned()),
                (
                    "parameter",
                    self.query.parameter_digest().as_str().to_owned(),
                ),
                ("query", self.query.query_digest().as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "cursor",
                    self.cursor.as_ref().map_or_else(
                        || "none".to_owned(),
                        |cursor| cursor.token_digest().as_str().to_owned(),
                    ),
                ),
            ],
        );
        self
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.page_number == 0
            || self.request_digest != self.clone().with_recomputed_digest().request_digest
        {
            return Err(AwsNeptuneGraphResultError::TamperedEvidence);
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate_against(
                &self.scope_digest,
                self.query.query_digest(),
                self.page_number,
            )?;
        }
        Ok(())
    }
}

impl fmt::Debug for ExecuteOpenCypherQueryRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecuteOpenCypherQueryRequest")
            .field("scope_digest", &self.scope_digest)
            .field("query", &self.query)
            .field("page_number", &self.page_number)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl Serialize for ExecuteOpenCypherQueryRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ExecuteOpenCypherQueryRequest", 10)?;
        state.serialize_field(
            "operation",
            AwsNeptuneOperation::ExecuteOpenCypherQuery.as_str(),
        )?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("queryTemplateDigest", self.query.template_digest())?;
        state.serialize_field("parameterDigest", self.query.parameter_digest())?;
        state.serialize_field("queryDigest", self.query.query_digest())?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.serialize_field("cursor", &self.cursor)?;
        state.serialize_field("rowLimit", &self.query.limits().max_rows)?;
        state.serialize_field("byteLimit", &self.query.limits().max_bytes)?;
        state.serialize_field("timeoutMs", &self.query.limits().timeout_ms)?;
        state.end()
    }
}

/// A redacted provider request receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsNeptuneOperation,
    pub scope_digest: Digest,
    pub query_template_digest: Digest,
    pub parameter_digest: Digest,
    pub query_digest: Digest,
    pub page_number: u16,
    pub cursor_digest: Option<Digest>,
    pub row_limit: u32,
    pub byte_limit: u64,
    pub timeout_ms: u64,
    pub request_digest: Digest,
    pub path_digest: Digest,
}

/// One bounded provider page.  Its rows contain only redacted projections.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecuteOpenCypherQueryResponse {
    pub scope_digest: Digest,
    pub query_template_digest: Digest,
    pub parameter_digest: Digest,
    pub query_digest: Digest,
    pub page_number: u16,
    pub rows: Vec<GraphRowProjection>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: u64,
    pub elapsed_ms: u64,
    pub provenance: TransportProvenance,
    pub result_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl ExecuteOpenCypherQueryResponse {
    pub fn new(
        request: &ExecuteOpenCypherQueryRequest,
        rows: Vec<GraphRowProjection>,
        mut next_cursor: Option<OpaqueCursor>,
        response_bytes: u64,
        elapsed_ms: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        request.validate()?;
        for row in &rows {
            row.validate()?;
        }
        let row_bytes = rows.iter().try_fold(0_u64, |total, row| {
            total
                .checked_add(row.byte_size)
                .ok_or(AwsNeptuneGraphResultError::ResponseLimitExceeded)
        })?;
        if rows.len() as u32 > request.query.limits().max_rows
            || response_bytes > request.query.limits().max_bytes
            || row_bytes > response_bytes
        {
            return Err(AwsNeptuneGraphResultError::ResponseLimitExceeded);
        }
        if let Some(cursor) = &mut next_cursor {
            let next_page = request
                .page_number()
                .checked_add(1)
                .ok_or(AwsNeptuneGraphResultError::InvalidRequest)?;
            cursor.bind(
                request.scope_digest(),
                request.query.query_digest(),
                next_page,
            )?;
        }
        let result_digest = result_digest(request, &rows, response_bytes);
        Ok(Self {
            scope_digest: request.scope_digest.clone(),
            query_template_digest: request.query.template_digest().clone(),
            parameter_digest: request.query.parameter_digest().clone(),
            query_digest: request.query.query_digest().clone(),
            page_number: request.page_number(),
            rows,
            next_cursor,
            response_bytes,
            elapsed_ms,
            provenance,
            result_digest,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        })
    }

    pub fn with_declared_result_digest(mut self, result_digest: Digest) -> Self {
        self.result_digest = result_digest;
        self
    }

    pub fn validate_integrity(&self, request: &ExecuteOpenCypherQueryRequest) -> Result<()> {
        request.validate()?;
        if self.scope_digest != *request.scope_digest()
            || self.query_template_digest != *request.query.template_digest()
            || self.parameter_digest != *request.query.parameter_digest()
            || self.query_digest != *request.query.query_digest()
            || self.page_number != request.page_number()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.provenance.provider_receipt()
            || self.rows.len() as u32 > request.query.limits().max_rows
            || self.response_bytes > request.query.limits().max_bytes
        {
            return Err(AwsNeptuneGraphResultError::ResponseFenceMismatch);
        }
        if let Some(cursor) = &self.next_cursor {
            let next_page = request
                .page_number()
                .checked_add(1)
                .ok_or(AwsNeptuneGraphResultError::ResponseFenceMismatch)?;
            cursor.validate_against(
                request.scope_digest(),
                request.query.query_digest(),
                next_page,
            )?;
        }
        for row in &self.rows {
            row.validate()?;
        }
        let row_bytes = self.rows.iter().try_fold(0_u64, |total, row| {
            total
                .checked_add(row.byte_size)
                .ok_or(AwsNeptuneGraphResultError::ResponseFenceMismatch)
        })?;
        if row_bytes > self.response_bytes {
            return Err(AwsNeptuneGraphResultError::ResponseFenceMismatch);
        }
        if self.result_digest != result_digest(request, &self.rows, self.response_bytes) {
            return Err(AwsNeptuneGraphResultError::ResultDigestMismatch);
        }
        Ok(())
    }
}

fn result_digest(
    request: &ExecuteOpenCypherQueryRequest,
    rows: &[GraphRowProjection],
    response_bytes: u64,
) -> Digest {
    Digest::from_parts(
        "aws-neptune-result-page/v1",
        &[
            ("query", request.query.query_digest().as_str().to_owned()),
            (
                "rows",
                rows.iter()
                    .map(|row| row.row_digest.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            ("bytes", response_bytes.to_string()),
            ("page", request.page_number().to_string()),
        ],
    )
}

/// Provider identity and honest provenance metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsNeptuneProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl AwsNeptuneProviderDefinition {
    fn new(provenance: TransportProvenance) -> Self {
        let provider_digest = Digest::from_parts(
            "aws-neptune-provider/v1",
            &[
                ("id", crate::PROVIDER_ID.to_owned()),
                ("version", crate::PLUGIN_VERSION.to_owned()),
                ("provenance", provenance.as_str().to_owned()),
            ],
        );
        Self {
            provider_id: crate::PROVIDER_ID.to_owned(),
            provider_version: crate::PLUGIN_VERSION.to_owned(),
            api_revision: API_REVISION.to_owned(),
            provider_digest,
            api_digest: Digest::from_text(API_REVISION),
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let expected_provider_digest = Digest::from_parts(
            "aws-neptune-provider/v1",
            &[
                ("id", crate::PROVIDER_ID.to_owned()),
                ("version", crate::PLUGIN_VERSION.to_owned()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        );
        if self.provider_id != crate::PROVIDER_ID
            || self.provider_version != crate::PLUGIN_VERSION
            || self.api_revision != API_REVISION
            || self.provider_digest != expected_provider_digest
            || self.api_digest != Digest::from_text(API_REVISION)
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.provenance.provider_receipt()
        {
            Err(AwsNeptuneGraphResultError::InvalidProvider)
        } else {
            Ok(())
        }
    }
}

impl Serialize for AwsNeptuneProviderDefinition {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsNeptuneProviderDefinition", 10)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerVersion", &self.provider_version)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("provenance", &self.provenance)?;
        state.serialize_field("connected", &false)?;
        state.serialize_field("native", &false)?;
        state.serialize_field("firstParty", &false)?;
        state.serialize_field("providerReceipt", &false)?;
        state.end()
    }
}

/// Typed Neptune provider wrapping one bounded transport seam.
pub struct AwsNeptuneProvider<T> {
    transport: T,
    definition: AwsNeptuneProviderDefinition,
}

impl<T: AwsNeptuneTransport> fmt::Debug for AwsNeptuneProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsNeptuneProvider")
            .field("definition", &self.definition)
            .finish_non_exhaustive()
    }
}

impl<T: AwsNeptuneTransport> AwsNeptuneProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        let definition = AwsNeptuneProviderDefinition::new(transport.provenance());
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsNeptuneProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.definition.provenance
    }

    pub fn execute_open_cypher_query(
        &mut self,
        request: &ExecuteOpenCypherQueryRequest,
    ) -> std::result::Result<ExecuteOpenCypherQueryResponse, AwsNeptuneTransportError> {
        self.transport.execute_open_cypher_query(request)
    }

    pub fn execute(
        &mut self,
        request: &ExecuteOpenCypherQueryRequest,
    ) -> std::result::Result<ExecuteOpenCypherQueryResponse, AwsNeptuneTransportError> {
        self.execute_open_cypher_query(request)
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

impl Default for AwsNeptuneProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked transport definition")
    }
}

/// A queued transport used to exercise request/response and tamper fences.
#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    responses:
        VecDeque<std::result::Result<ExecuteOpenCypherQueryResponse, AwsNeptuneTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_response(
        &mut self,
        response: std::result::Result<ExecuteOpenCypherQueryResponse, AwsNeptuneTransportError>,
    ) {
        self.responses.push_back(response);
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

impl AwsNeptuneTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn execute_open_cypher_query(
        &mut self,
        request: &ExecuteOpenCypherQueryRequest,
    ) -> std::result::Result<ExecuteOpenCypherQueryResponse, AwsNeptuneTransportError> {
        self.requests.push(request.recorded_request());
        self.responses
            .pop_front()
            .unwrap_or(Err(AwsNeptuneTransportError::Unknown))
    }
}

/// Deterministic redacted fixture transport.
#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope_digest: Digest,
    observed_at: DateTime<Utc>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsNeptuneGraphScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope_digest: scope.digest(),
            observed_at,
        }
    }
}

impl AwsNeptuneTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn execute_open_cypher_query(
        &mut self,
        request: &ExecuteOpenCypherQueryRequest,
    ) -> std::result::Result<ExecuteOpenCypherQueryResponse, AwsNeptuneTransportError> {
        if request.scope_digest() != &self.scope_digest {
            return Err(AwsNeptuneTransportError::Forbidden);
        }
        let row = GraphRowProjection::fixture(
            request.query().query_digest(),
            request.query().ast().is_relationship_query(),
        )
        .map_err(|_| AwsNeptuneTransportError::Unknown)?;
        ExecuteOpenCypherQueryResponse::new(
            request,
            vec![row],
            None,
            256,
            u64::from(self.observed_at.timestamp_subsec_millis()) + 1,
            self.provenance(),
        )
        .map_err(|_| AwsNeptuneTransportError::Unknown)
    }
}

/// Deterministic loopback transport; it never claims a live connection.
#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    fixture: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsNeptuneGraphScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            fixture: FixtureTransport::for_scope(scope, observed_at),
        }
    }
}

impl AwsNeptuneTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn execute_open_cypher_query(
        &mut self,
        request: &ExecuteOpenCypherQueryRequest,
    ) -> std::result::Result<ExecuteOpenCypherQueryResponse, AwsNeptuneTransportError> {
        let mut response = self.fixture.execute_open_cypher_query(request)?;
        response.provenance = self.provenance();
        Ok(response)
    }
}

/// Explicitly blocked native environment transport.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsNeptuneTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn execute_open_cypher_query(
        &mut self,
        _request: &ExecuteOpenCypherQueryRequest,
    ) -> std::result::Result<ExecuteOpenCypherQueryResponse, AwsNeptuneTransportError> {
        Err(AwsNeptuneTransportError::BlockedEnvironment)
    }
}

/// Compatibility alias for callers that use a fake/fixture name.
pub type FakeNeptuneTransport = FixtureTransport;

// Keep the dependency on the contract version visible in provider metadata;
// this is intentionally not a live request header.
#[allow(dead_code)]
const _CONTRACT_VERSION_FENCE: &str = CONTRACT_VERSION;
