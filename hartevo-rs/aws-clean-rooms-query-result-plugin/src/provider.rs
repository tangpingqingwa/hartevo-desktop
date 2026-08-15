//! Metadata-only AWS Clean Rooms provider seams.
//!
//! There is intentionally no AWS SDK, SigV4 signer, credential resolver, HTTP
//! client, SQL executor, protected-query start/update path, S3 client, or raw
//! member/result path in this Layer-1 crate.

use std::{collections::VecDeque, fmt, fmt::Write as _};

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use crate::error::{AwsCleanRoomsQueryResultError, AwsCleanRoomsTransportError, Result};
use crate::model::{
    AwsCleanRoomsQueryResultScope, Cursor, Digest, ProtectedQueryFilter, ProtectedQueryMetadata,
    ProtectedQueryMetadataInput, ProtectedQueryStatus, TransportProvenance,
    validate_response_bytes,
};
use crate::service::AwsCleanRoomsQueryResultRegistration;
use crate::{CONTRACT_VERSION, LAYER1_PERMISSIONS, PROVIDER_API_REVISION, PROVIDER_ID};

pub const LIST_PROTECTED_QUERIES_OPERATION_PATH: &str =
    "/memberships/{membershipIdentifier}/protectedQueries";
pub const GET_PROTECTED_QUERY_OPERATION_PATH: &str =
    "/memberships/{membershipIdentifier}/protectedQueries/{protectedQueryIdentifier}";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsCleanRoomsOperation {
    ListProtectedQueries,
    GetProtectedQuery,
}

impl AwsCleanRoomsOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListProtectedQueries => "ListProtectedQueries",
            Self::GetProtectedQuery => "GetProtectedQuery",
        }
    }
}

/// The only provider transport trait exposed by Layer 1.
pub trait AwsCleanRoomsTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_protected_queries(
        &mut self,
        request: &ListProtectedQueriesRequest,
    ) -> std::result::Result<ListProtectedQueriesResponse, AwsCleanRoomsTransportError>;

    fn get_protected_query(
        &mut self,
        request: &GetProtectedQueryRequest,
    ) -> std::result::Result<GetProtectedQueryResponse, AwsCleanRoomsTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsCleanRoomsOperation,
    pub scope_digest: Digest,
    pub filter_digest: Option<Digest>,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListProtectedQueriesRequest {
    scope: AwsCleanRoomsQueryResultScope,
    filter: ProtectedQueryFilter,
    cursor: Option<Cursor>,
    request_digest: Digest,
}

impl ListProtectedQueriesRequest {
    pub fn new(
        scope: &AwsCleanRoomsQueryResultScope,
        filter: ProtectedQueryFilter,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        scope.validate()?;
        filter.validate_against(scope)?;
        if let Some(cursor) = &cursor {
            cursor.validate_against(scope, &filter)?;
        }
        let request_digest = Digest::from_parts(
            "aws-clean-rooms-list-protected-queries-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("filter", filter.digest().as_str().to_owned()),
                (
                    "cursor",
                    cursor.as_ref().map_or_else(String::new, |value| {
                        value.token_digest().as_str().to_owned()
                    }),
                ),
                (
                    "page",
                    cursor
                        .as_ref()
                        .map_or_else(|| "1".to_owned(), |value| value.page_number().to_string()),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            filter,
            cursor,
            request_digest,
        })
    }

    pub fn scope(&self) -> &AwsCleanRoomsQueryResultScope {
        &self.scope
    }

    pub fn filter(&self) -> &ProtectedQueryFilter {
        &self.filter
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, Cursor::page_number)
    }

    /// The raw membership and next-token values never enter a request receipt
    /// or evidence projection; only their digests are used in this path.
    pub fn path_and_query(&self) -> String {
        let mut query = vec![
            ("maxResults", self.filter.max_results().to_string()),
            (
                "status",
                self.filter
                    .status()
                    .map_or_else(String::new, |status| status.as_str().to_owned()),
            ),
        ];
        if let Some(cursor) = &self.cursor {
            query.push(("nextToken", percent_encode(cursor.token_digest().as_str())));
        }
        let query = query
            .into_iter()
            .filter(|(_, value)| !value.is_empty())
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("&");
        format!(
            "/memberships/{}/protectedQueries?{}",
            percent_encode(&self.scope.membership().digest().as_str()[..16]),
            query
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsCleanRoomsOperation::ListProtectedQueries,
            scope_digest: self.scope.digest(),
            filter_digest: Some(self.filter.digest()),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for ListProtectedQueriesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListProtectedQueriesRequest")
            .field("scope_digest", &self.scope.digest())
            .field("filter", &self.filter)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetProtectedQueryRequest {
    scope: AwsCleanRoomsQueryResultScope,
    request_digest: Digest,
}

impl GetProtectedQueryRequest {
    pub fn for_scope(scope: &AwsCleanRoomsQueryResultScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-clean-rooms-get-protected-query-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    (
                        "membership",
                        scope.membership().digest().as_str().to_owned(),
                    ),
                    (
                        "protected_query",
                        scope.protected_query().digest().as_str().to_owned(),
                    ),
                ],
            ),
        })
    }

    pub fn scope(&self) -> &AwsCleanRoomsQueryResultScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/memberships/{}/protectedQueries/{}",
            percent_encode(&self.scope.membership().digest().as_str()[..16]),
            percent_encode(&self.scope.protected_query().digest().as_str()[..16]),
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsCleanRoomsOperation::GetProtectedQuery,
            scope_digest: self.scope.digest(),
            filter_digest: None,
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for GetProtectedQueryRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetProtectedQueryRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListProtectedQueriesResponse {
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub protected_queries: Vec<ProtectedQueryMetadata>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl ListProtectedQueriesResponse {
    pub fn new(
        request: &ListProtectedQueriesRequest,
        protected_queries: Vec<ProtectedQueryMetadata>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if protected_queries.len() > request.filter.max_results() as usize {
            return Err(AwsCleanRoomsQueryResultError::PartialEvidence);
        }
        for query in &protected_queries {
            query.validate_list_item_against(request.scope())?;
        }
        if let Some(cursor) = &next_cursor {
            cursor.validate_against(request.scope(), request.filter())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsCleanRoomsQueryResultError::CursorMismatch);
            }
        }
        let mut response = Self {
            scope_digest: request.scope().digest(),
            filter_digest: request.filter().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            protected_queries,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-clean-rooms-list-response"),
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

    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn validate_integrity(&self, request: &ListProtectedQueriesRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.filter_digest != request.filter().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.protected_queries.len() > request.filter.max_results() as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsCleanRoomsQueryResultError::TamperedEvidence);
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_against(request.scope(), request.filter())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsCleanRoomsQueryResultError::CursorMismatch);
            }
        }
        for query in &self.protected_queries {
            query.validate_list_item_against(request.scope())?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-clean-rooms-list-protected-queries-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("filter", self.filter_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "queries",
                    self.protected_queries
                        .iter()
                        .map(ProtectedQueryMetadata::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| {
                            cursor.token_digest().as_str().to_owned()
                        }),
                ),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetProtectedQueryResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub metadata: ProtectedQueryMetadata,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl GetProtectedQueryResponse {
    pub fn new(
        request: &GetProtectedQueryRequest,
        metadata: ProtectedQueryMetadata,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        metadata.validate_against(request.scope())?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            metadata,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-clean-rooms-get-response"),
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

    pub fn validate_integrity(&self, request: &GetProtectedQueryRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsCleanRoomsQueryResultError::TamperedEvidence);
        }
        self.metadata.validate_against(request.scope())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-clean-rooms-get-protected-query-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("metadata", self.metadata.digest().as_str().to_owned()),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug)]
pub struct AwsCleanRoomsProviderDefinition {
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

impl AwsCleanRoomsProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0 || release.is_empty() || release.len() > 128 {
            return Err(AwsCleanRoomsQueryResultError::ProviderDrift);
        }
        let capability_digest = Digest::from_parts(
            "aws-clean-rooms-provider-capabilities/v1",
            &LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .collect::<Vec<_>>(),
        );
        let provider_digest = Digest::from_parts(
            "aws-clean-rooms-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("provider_revision", provider_revision.to_string()),
                ("api_revision", PROVIDER_API_REVISION.to_owned()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
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
        if self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.api_revision != PROVIDER_API_REVISION
            || self.contract_version != CONTRACT_VERSION
            || self.release.is_empty()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_digest
                != Self::new(self.provider_revision, self.release.clone())?.provider_digest
        {
            Err(AwsCleanRoomsQueryResultError::ProviderDrift)
        } else {
            Ok(())
        }
    }
}

impl Serialize for AwsCleanRoomsProviderDefinition {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("AwsCleanRoomsProviderDefinition", 10)?;
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

pub struct AwsCleanRoomsProvider<T> {
    transport: T,
    definition: AwsCleanRoomsProviderDefinition,
}

impl<T: AwsCleanRoomsTransport> fmt::Debug for AwsCleanRoomsProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCleanRoomsProvider")
            .field("definition", &self.definition)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AwsCleanRoomsTransport> AwsCleanRoomsProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, "layer1-recording")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self> {
        let definition = AwsCleanRoomsProviderDefinition::new(provider_revision, release)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsCleanRoomsProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn list_protected_queries(
        &mut self,
        request: &ListProtectedQueriesRequest,
    ) -> std::result::Result<ListProtectedQueriesResponse, AwsCleanRoomsTransportError> {
        let response = self.transport.list_protected_queries(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsCleanRoomsTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.first_party
            || response.provider_receipt
        {
            return Err(AwsCleanRoomsTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn get_protected_query(
        &mut self,
        request: &GetProtectedQueryRequest,
    ) -> std::result::Result<GetProtectedQueryResponse, AwsCleanRoomsTransportError> {
        let response = self.transport.get_protected_query(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsCleanRoomsTransportError::InvalidResponse)?;
        if response.provenance != self.provenance()
            || response.connected
            || response.native
            || response.first_party
            || response.provider_receipt
        {
            return Err(AwsCleanRoomsTransportError::InvalidResponse);
        }
        Ok(response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl Default for AwsCleanRoomsProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked AWS Clean Rooms provider definition")
    }
}

impl<T: AwsCleanRoomsTransport> AwsCleanRoomsProvider<T> {
    pub fn from_registration(
        registration: &AwsCleanRoomsQueryResultRegistration,
        transport: T,
    ) -> Result<Self> {
        let provider = Self::with_identity(
            transport,
            registration.provider_revision(),
            registration.provider_release().to_owned(),
        )?;
        if provider.definition.provider_digest != *registration.provider_digest() {
            return Err(AwsCleanRoomsQueryResultError::ProviderDrift);
        }
        Ok(provider)
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    list_responses:
        VecDeque<std::result::Result<ListProtectedQueriesResponse, AwsCleanRoomsTransportError>>,
    get_responses:
        VecDeque<std::result::Result<GetProtectedQueryResponse, AwsCleanRoomsTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            list_responses: VecDeque::new(),
            get_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_list_response(
        &mut self,
        response: std::result::Result<ListProtectedQueriesResponse, AwsCleanRoomsTransportError>,
    ) {
        self.list_responses.push_back(response);
    }

    pub fn push_get_response(
        &mut self,
        response: std::result::Result<GetProtectedQueryResponse, AwsCleanRoomsTransportError>,
    ) {
        self.get_responses.push_back(response);
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

impl AwsCleanRoomsTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance.clone()
    }

    fn list_protected_queries(
        &mut self,
        request: &ListProtectedQueriesRequest,
    ) -> std::result::Result<ListProtectedQueriesResponse, AwsCleanRoomsTransportError> {
        self.requests.push(request.recorded_request());
        self.list_responses
            .pop_front()
            .unwrap_or(Err(AwsCleanRoomsTransportError::InvalidResponse))
    }

    fn get_protected_query(
        &mut self,
        request: &GetProtectedQueryRequest,
    ) -> std::result::Result<GetProtectedQueryResponse, AwsCleanRoomsTransportError> {
        self.requests.push(request.recorded_request());
        self.get_responses
            .pop_front()
            .unwrap_or(Err(AwsCleanRoomsTransportError::InvalidResponse))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: AwsCleanRoomsQueryResultScope,
    observed_at: DateTime<Utc>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsCleanRoomsQueryResultScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }

    fn metadata(&self) -> Result<ProtectedQueryMetadata> {
        ProtectedQueryMetadata::new(
            &self.scope,
            ProtectedQueryMetadataInput {
                status: ProtectedQueryStatus::Success,
                created_at: self.observed_at - Duration::hours(2),
                last_updated_at: Some(self.observed_at - Duration::minutes(30)),
                duration_millis: Some(1_250),
                billed_units: Some(3),
                sql_text: Some("SELECT COUNT(*) FROM protected_fixture".to_owned()),
                member_ids: vec!["fixture-member-a".to_owned(), "fixture-member-b".to_owned()],
                output_reference: Some(
                    "s3://clean-rooms-fixture-private/result/opaque-output".to_owned(),
                ),
                provider_error: None,
                query_compute_payer_account_id: Some("123456789012".to_owned()),
            },
        )
    }
}

impl AwsCleanRoomsTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn list_protected_queries(
        &mut self,
        request: &ListProtectedQueriesRequest,
    ) -> std::result::Result<ListProtectedQueriesResponse, AwsCleanRoomsTransportError> {
        let metadata = self
            .metadata()
            .map_err(|_| AwsCleanRoomsTransportError::InvalidResponse)?;
        ListProtectedQueriesResponse::new(
            request,
            vec![metadata],
            None,
            768,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsCleanRoomsTransportError::InvalidResponse)
    }

    fn get_protected_query(
        &mut self,
        request: &GetProtectedQueryRequest,
    ) -> std::result::Result<GetProtectedQueryResponse, AwsCleanRoomsTransportError> {
        let metadata = self
            .metadata()
            .map_err(|_| AwsCleanRoomsTransportError::InvalidResponse)?;
        GetProtectedQueryResponse::new(request, metadata, 768, TransportProvenance::Fixture)
            .map_err(|_| AwsCleanRoomsTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsCleanRoomsQueryResultScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: FixtureTransport::for_scope(scope, observed_at),
        }
    }
}

impl AwsCleanRoomsTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn list_protected_queries(
        &mut self,
        request: &ListProtectedQueriesRequest,
    ) -> std::result::Result<ListProtectedQueriesResponse, AwsCleanRoomsTransportError> {
        let metadata = self
            .inner
            .metadata()
            .map_err(|_| AwsCleanRoomsTransportError::InvalidResponse)?;
        ListProtectedQueriesResponse::new(
            request,
            vec![metadata],
            None,
            768,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsCleanRoomsTransportError::InvalidResponse)
    }

    fn get_protected_query(
        &mut self,
        request: &GetProtectedQueryRequest,
    ) -> std::result::Result<GetProtectedQueryResponse, AwsCleanRoomsTransportError> {
        let metadata = self
            .inner
            .metadata()
            .map_err(|_| AwsCleanRoomsTransportError::InvalidResponse)?;
        GetProtectedQueryResponse::new(request, metadata, 768, TransportProvenance::Loopback)
            .map_err(|_| AwsCleanRoomsTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsCleanRoomsTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_protected_queries(
        &mut self,
        _request: &ListProtectedQueriesRequest,
    ) -> std::result::Result<ListProtectedQueriesResponse, AwsCleanRoomsTransportError> {
        Err(AwsCleanRoomsTransportError::BlockedEnv)
    }

    fn get_protected_query(
        &mut self,
        _request: &GetProtectedQueryRequest,
    ) -> std::result::Result<GetProtectedQueryResponse, AwsCleanRoomsTransportError> {
        Err(AwsCleanRoomsTransportError::BlockedEnv)
    }
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            let _ = write!(encoded, "{byte:02X}");
        }
    }
    encoded
}
