use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    ApiHost, ApiVersion, AuthorId, AuthorMetadata, BoundedText, CitationDirection, CitationRecord,
    Digest, EndpointKind, HttpMethod, MAX_RESPONSE_BYTES, ModelError, NativeTransportProvenance,
    OpaqueCursor, PaperId, PaperMetadata, RecommendationPool, RecommendationRecord, ResearchQuery,
    SemanticScholarScope, VenueId,
};

pub type ProviderProvenance = NativeTransportProvenance;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TransportError {
    #[error("BLOCKED_ENV: native Semantic Scholar credentials or HTTPS transport are unavailable")]
    BlockedEnv,
    #[error("Semantic Scholar returned HTTP 400")]
    BadRequest,
    #[error("Semantic Scholar returned HTTP 401")]
    Unauthorized,
    #[error("Semantic Scholar returned HTTP 403")]
    Forbidden,
    #[error("Semantic Scholar returned HTTP 404")]
    NotFound,
    #[error("Semantic Scholar returned HTTP 429")]
    RateLimited { retry_after_seconds: Option<u32> },
    #[error("Semantic Scholar request timed out")]
    Timeout,
    #[error("Semantic Scholar response exceeded the bounded response limit")]
    ResponseTooLarge,
    #[error("Semantic Scholar response was malformed")]
    MalformedResponse,
    #[error("Semantic Scholar provider is unavailable")]
    Unavailable,
    #[error("Semantic Scholar provider returned an unknown bounded error")]
    ProviderUnknown,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderError {
    #[error("request method is not GET")]
    MethodNotAllowed,
    #[error("request host or API version does not match Semantic Scholar Academic Graph v1")]
    HostOrVersionMismatch,
    #[error("request endpoint is not in the Semantic Scholar Layer-1 allowlist")]
    EndpointNotAllowlisted,
    #[error("provider response is not bounded")]
    ResponseTooLarge,
    #[error("provider response digest or request binding is tampered")]
    ResponseTampered,
    #[error("provider response kind does not match the requested endpoint")]
    ResponseKindMismatch,
    #[error("transport failed: {0}")]
    Transport(#[from] TransportError),
    #[error("model validation failed: {0}")]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemanticScholarProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub api_host: ApiHost,
    pub api_version: ApiVersion,
    pub allowed_methods: Vec<HttpMethod>,
    pub allowed_endpoints: Vec<EndpointKind>,
    pub native: bool,
    pub connected: bool,
    pub capability_digest: Digest,
}

impl SemanticScholarProviderDefinition {
    pub fn layer1(provider_version: impl Into<String>) -> Result<Self, ModelError> {
        let provider_version = provider_version.into();
        if provider_version.trim().is_empty() || provider_version.len() > 64 {
            return Err(ModelError::InvalidRegistration);
        }
        let allowed_methods = vec![HttpMethod::Get];
        let allowed_endpoints = vec![
            EndpointKind::PaperSearch,
            EndpointKind::PaperBulkSearch,
            EndpointKind::PaperDetails,
            EndpointKind::PaperAuthors,
            EndpointKind::PaperCitations,
            EndpointKind::PaperReferences,
            EndpointKind::AuthorSearch,
            EndpointKind::AuthorDetails,
            EndpointKind::AuthorPapers,
            EndpointKind::Recommendations,
        ];
        let capability_digest = Digest::from_serializable(&(
            crate::SEMANTIC_SCHOLAR_PROVIDER_ID,
            &provider_version,
            ApiHost::SemanticScholar,
            ApiVersion::V1,
            &allowed_methods,
            &allowed_endpoints,
            false,
            false,
        ))?;
        Ok(Self {
            provider_id: String::from(crate::SEMANTIC_SCHOLAR_PROVIDER_ID),
            provider_version,
            api_host: ApiHost::SemanticScholar,
            api_version: ApiVersion::V1,
            allowed_methods,
            allowed_endpoints,
            native: false,
            connected: false,
            capability_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        let expected_digest = Digest::from_serializable(&(
            &self.provider_id,
            &self.provider_version,
            self.api_host,
            self.api_version,
            &self.allowed_methods,
            &self.allowed_endpoints,
            self.native,
            self.connected,
        ))?;
        if self.provider_id != crate::SEMANTIC_SCHOLAR_PROVIDER_ID
            || self.api_host != ApiHost::SemanticScholar
            || self.api_version != ApiVersion::V1
            || self.allowed_methods.as_slice() != [HttpMethod::Get]
            || self.native
            || self.connected
            || self.capability_digest != expected_digest
        {
            return Err(ProviderError::HostOrVersionMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.capability_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequestParameter {
    name: String,
    value: String,
}

impl RequestParameter {
    fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// A typed GET request. The request may carry a bounded query value to the
/// transport seam, but receipts and Debug output expose only its digest.
#[derive(Clone, Eq, PartialEq)]
pub struct ApiGetRequest {
    method: HttpMethod,
    host: ApiHost,
    api_version: ApiVersion,
    endpoint: EndpointKind,
    path: String,
    parameters: Vec<RequestParameter>,
    query_digest: Digest,
    scope_digest: Digest,
    registration_digest: Digest,
    credential_revision: crate::Revision,
    request_digest: Digest,
}

impl fmt::Debug for ApiGetRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiGetRequest")
            .field("method", &self.method)
            .field("host", &self.host)
            .field("api_version", &self.api_version)
            .field("endpoint", &self.endpoint)
            .field("path", &self.path)
            .field(
                "parameter_names",
                &self
                    .parameters
                    .iter()
                    .map(RequestParameter::name)
                    .collect::<Vec<_>>(),
            )
            .field("query_digest", &self.query_digest)
            .field("scope_digest", &self.scope_digest)
            .field("registration_digest", &self.registration_digest)
            .field("credential_revision", &self.credential_revision)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl ApiGetRequest {
    pub fn from_query(
        query: &ResearchQuery,
        scope: &SemanticScholarScope,
        registration_digest: Digest,
        credential_revision: crate::Revision,
    ) -> Result<Self, ModelError> {
        query.validate(scope)?;
        let query_digest = query.logical_digest()?;
        let endpoint = query.endpoint_kind();
        let (path, mut parameters) = route(query);
        let request_identity = RequestIdentity {
            method: HttpMethod::Get,
            host: scope.api_host(),
            api_version: scope.api_version(),
            endpoint,
            path: path.clone(),
            parameters: parameters.clone(),
            query_digest: query_digest.clone(),
            scope_digest: scope.scope_digest().clone(),
            registration_digest: registration_digest.clone(),
            credential_revision,
        };
        let request_digest = Digest::from_serializable(&request_identity)?;
        // Keep a deterministic order for transports and recordings.
        parameters.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(Self {
            method: HttpMethod::Get,
            host: scope.api_host(),
            api_version: scope.api_version(),
            endpoint,
            path,
            parameters,
            query_digest,
            scope_digest: scope.scope_digest().clone(),
            registration_digest,
            credential_revision,
            request_digest,
        })
    }

    #[must_use]
    pub const fn method(&self) -> HttpMethod {
        self.method
    }

    #[must_use]
    pub const fn host(&self) -> ApiHost {
        self.host
    }

    #[must_use]
    pub const fn api_version(&self) -> ApiVersion {
        self.api_version
    }

    #[must_use]
    pub const fn endpoint(&self) -> EndpointKind {
        self.endpoint
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn parameters(&self) -> &[RequestParameter] {
        &self.parameters
    }

    #[must_use]
    pub fn query_digest(&self) -> &Digest {
        &self.query_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    #[must_use]
    pub const fn credential_revision(&self) -> crate::Revision {
        self.credential_revision
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestIdentity {
    method: HttpMethod,
    host: ApiHost,
    api_version: ApiVersion,
    endpoint: EndpointKind,
    path: String,
    parameters: Vec<RequestParameter>,
    query_digest: Digest,
    scope_digest: Digest,
    registration_digest: Digest,
    credential_revision: crate::Revision,
}

fn route(query: &ResearchQuery) -> (String, Vec<RequestParameter>) {
    let mut parameters = Vec::new();
    let (path, fields, page) = match query {
        ResearchQuery::PaperSearch {
            query,
            fields,
            page,
        } => {
            parameters.push(RequestParameter::new("query", query.as_str()));
            (String::from("/graph/v1/paper/search"), fields, Some(page))
        }
        ResearchQuery::PaperBulkSearch {
            query,
            fields,
            page,
        } => {
            parameters.push(RequestParameter::new("query", query.as_str()));
            (
                String::from("/graph/v1/paper/search/bulk"),
                fields,
                Some(page),
            )
        }
        ResearchQuery::PaperDetails { paper_id, fields }
        | ResearchQuery::VenueMetadata { paper_id, fields } => (
            format!("/graph/v1/paper/{}", percent_encode(paper_id.as_str())),
            fields,
            None,
        ),
        ResearchQuery::PaperAuthors {
            paper_id,
            fields,
            page,
        } => (
            format!(
                "/graph/v1/paper/{}/authors",
                percent_encode(paper_id.as_str())
            ),
            fields,
            Some(page),
        ),
        ResearchQuery::PaperCitations {
            paper_id,
            fields,
            page,
        } => (
            format!(
                "/graph/v1/paper/{}/citations",
                percent_encode(paper_id.as_str())
            ),
            fields,
            Some(page),
        ),
        ResearchQuery::PaperReferences {
            paper_id,
            fields,
            page,
        } => (
            format!(
                "/graph/v1/paper/{}/references",
                percent_encode(paper_id.as_str())
            ),
            fields,
            Some(page),
        ),
        ResearchQuery::AuthorSearch {
            query,
            fields,
            page,
        } => {
            parameters.push(RequestParameter::new("query", query.as_str()));
            (String::from("/graph/v1/author/search"), fields, Some(page))
        }
        ResearchQuery::AuthorDetails { author_id, fields } => (
            format!("/graph/v1/author/{}", percent_encode(author_id.as_str())),
            fields,
            None,
        ),
        ResearchQuery::AuthorPapers {
            author_id,
            fields,
            page,
        } => (
            format!(
                "/graph/v1/author/{}/papers",
                percent_encode(author_id.as_str())
            ),
            fields,
            Some(page),
        ),
        ResearchQuery::Recommendations {
            paper_id,
            page,
            pool,
            fields,
        } => {
            parameters.push(RequestParameter::new("from", pool.api_name()));
            (
                format!(
                    "/recommendations/v1/papers/forpaper/{}",
                    percent_encode(paper_id.as_str())
                ),
                fields,
                Some(page),
            )
        }
    };
    parameters.push(RequestParameter::new("fields", fields.as_api_parameter()));
    if let Some(page) = page {
        parameters.push(RequestParameter::new("limit", page.limit().to_string()));
        if let Some(cursor) = page.cursor() {
            parameters.push(RequestParameter::new("token", cursor.as_str()));
        } else if page.offset() > 0 {
            parameters.push(RequestParameter::new("offset", page.offset().to_string()));
        }
    }
    parameters.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.value.cmp(&right.value))
    });
    (path, parameters)
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]));
            encoded.push(char::from(b"0123456789ABCDEF"[(byte & 0x0f) as usize]));
        }
    }
    encoded
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaperPage {
    pub request_digest: Digest,
    pub query_digest: Digest,
    pub scope_digest: Digest,
    pub records: Vec<PaperMetadata>,
    pub next_cursor: Option<OpaqueCursor>,
    pub complete: bool,
    pub response_bytes: usize,
    pub response_digest: Digest,
}

impl PaperPage {
    pub fn from_request(
        request: &ApiGetRequest,
        records: Vec<PaperMetadata>,
        next_cursor: Option<OpaqueCursor>,
        complete: bool,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        let response_digest = page_digest(
            "paper",
            request.request_digest(),
            request.query_digest(),
            request.scope_digest(),
            &records,
            next_cursor.as_ref(),
            complete,
            response_bytes,
        )?;
        Ok(Self {
            request_digest: request.request_digest().clone(),
            query_digest: request.query_digest().clone(),
            scope_digest: request.scope_digest().clone(),
            records,
            next_cursor,
            complete,
            response_bytes,
            response_digest,
        })
    }

    fn validate(&self) -> Result<(), ProviderError> {
        if self.response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::ResponseTooLarge);
        }
        for record in &self.records {
            record.validate()?;
        }
        let digest = page_digest(
            "paper",
            &self.request_digest,
            &self.query_digest,
            &self.scope_digest,
            &self.records,
            self.next_cursor.as_ref(),
            self.complete,
            self.response_bytes,
        )?;
        if digest != self.response_digest {
            return Err(ProviderError::ResponseTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorPage {
    pub request_digest: Digest,
    pub query_digest: Digest,
    pub scope_digest: Digest,
    pub records: Vec<AuthorMetadata>,
    pub next_cursor: Option<OpaqueCursor>,
    pub complete: bool,
    pub response_bytes: usize,
    pub response_digest: Digest,
}

impl AuthorPage {
    pub fn from_request(
        request: &ApiGetRequest,
        records: Vec<AuthorMetadata>,
        next_cursor: Option<OpaqueCursor>,
        complete: bool,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        let response_digest = page_digest(
            "author",
            request.request_digest(),
            request.query_digest(),
            request.scope_digest(),
            &records,
            next_cursor.as_ref(),
            complete,
            response_bytes,
        )?;
        Ok(Self {
            request_digest: request.request_digest().clone(),
            query_digest: request.query_digest().clone(),
            scope_digest: request.scope_digest().clone(),
            records,
            next_cursor,
            complete,
            response_bytes,
            response_digest,
        })
    }

    fn validate(&self) -> Result<(), ProviderError> {
        if self.response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::ResponseTooLarge);
        }
        for record in &self.records {
            record.validate()?;
        }
        let digest = page_digest(
            "author",
            &self.request_digest,
            &self.query_digest,
            &self.scope_digest,
            &self.records,
            self.next_cursor.as_ref(),
            self.complete,
            self.response_bytes,
        )?;
        if digest != self.response_digest {
            return Err(ProviderError::ResponseTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CitationPage {
    pub request_digest: Digest,
    pub query_digest: Digest,
    pub scope_digest: Digest,
    pub records: Vec<CitationRecord>,
    pub next_cursor: Option<OpaqueCursor>,
    pub complete: bool,
    pub response_bytes: usize,
    pub response_digest: Digest,
}

impl CitationPage {
    pub fn from_request(
        request: &ApiGetRequest,
        records: Vec<CitationRecord>,
        next_cursor: Option<OpaqueCursor>,
        complete: bool,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        let response_digest = page_digest(
            "citation",
            request.request_digest(),
            request.query_digest(),
            request.scope_digest(),
            &records,
            next_cursor.as_ref(),
            complete,
            response_bytes,
        )?;
        Ok(Self {
            request_digest: request.request_digest().clone(),
            query_digest: request.query_digest().clone(),
            scope_digest: request.scope_digest().clone(),
            records,
            next_cursor,
            complete,
            response_bytes,
            response_digest,
        })
    }

    fn validate(&self) -> Result<(), ProviderError> {
        if self.response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::ResponseTooLarge);
        }
        for record in &self.records {
            record.validate()?;
        }
        let digest = page_digest(
            "citation",
            &self.request_digest,
            &self.query_digest,
            &self.scope_digest,
            &self.records,
            self.next_cursor.as_ref(),
            self.complete,
            self.response_bytes,
        )?;
        if digest != self.response_digest {
            return Err(ProviderError::ResponseTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecommendationPage {
    pub request_digest: Digest,
    pub query_digest: Digest,
    pub scope_digest: Digest,
    pub records: Vec<RecommendationRecord>,
    pub next_cursor: Option<OpaqueCursor>,
    pub complete: bool,
    pub response_bytes: usize,
    pub response_digest: Digest,
}

impl RecommendationPage {
    pub fn from_request(
        request: &ApiGetRequest,
        records: Vec<RecommendationRecord>,
        next_cursor: Option<OpaqueCursor>,
        complete: bool,
        response_bytes: usize,
    ) -> Result<Self, ModelError> {
        let response_digest = page_digest(
            "recommendation",
            request.request_digest(),
            request.query_digest(),
            request.scope_digest(),
            &records,
            next_cursor.as_ref(),
            complete,
            response_bytes,
        )?;
        Ok(Self {
            request_digest: request.request_digest().clone(),
            query_digest: request.query_digest().clone(),
            scope_digest: request.scope_digest().clone(),
            records,
            next_cursor,
            complete,
            response_bytes,
            response_digest,
        })
    }

    fn validate(&self) -> Result<(), ProviderError> {
        if self.response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::ResponseTooLarge);
        }
        for record in &self.records {
            record.validate()?;
        }
        let digest = page_digest(
            "recommendation",
            &self.request_digest,
            &self.query_digest,
            &self.scope_digest,
            &self.records,
            self.next_cursor.as_ref(),
            self.complete,
            self.response_bytes,
        )?;
        if digest != self.response_digest {
            return Err(ProviderError::ResponseTampered);
        }
        Ok(())
    }
}

fn page_digest<T: Serialize>(
    kind: &str,
    request_digest: &Digest,
    query_digest: &Digest,
    scope_digest: &Digest,
    records: &[T],
    next_cursor: Option<&OpaqueCursor>,
    complete: bool,
    response_bytes: usize,
) -> Result<Digest, ModelError> {
    Digest::from_serializable(&(
        kind,
        request_digest,
        query_digest,
        scope_digest,
        records,
        next_cursor,
        complete,
        response_bytes,
    ))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseKind {
    Paper,
    Author,
    Citation,
    Recommendation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum SemanticScholarResponse {
    Paper(PaperPage),
    Author(AuthorPage),
    Citation(CitationPage),
    Recommendation(RecommendationPage),
}

impl SemanticScholarResponse {
    #[must_use]
    pub const fn kind(&self) -> ResponseKind {
        match self {
            Self::Paper(_) => ResponseKind::Paper,
            Self::Author(_) => ResponseKind::Author,
            Self::Citation(_) => ResponseKind::Citation,
            Self::Recommendation(_) => ResponseKind::Recommendation,
        }
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        match self {
            Self::Paper(page) => &page.request_digest,
            Self::Author(page) => &page.request_digest,
            Self::Citation(page) => &page.request_digest,
            Self::Recommendation(page) => &page.request_digest,
        }
    }

    #[must_use]
    pub fn query_digest(&self) -> &Digest {
        match self {
            Self::Paper(page) => &page.query_digest,
            Self::Author(page) => &page.query_digest,
            Self::Citation(page) => &page.query_digest,
            Self::Recommendation(page) => &page.query_digest,
        }
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        match self {
            Self::Paper(page) => &page.scope_digest,
            Self::Author(page) => &page.scope_digest,
            Self::Citation(page) => &page.scope_digest,
            Self::Recommendation(page) => &page.scope_digest,
        }
    }

    #[must_use]
    pub fn response_digest(&self) -> &Digest {
        match self {
            Self::Paper(page) => &page.response_digest,
            Self::Author(page) => &page.response_digest,
            Self::Citation(page) => &page.response_digest,
            Self::Recommendation(page) => &page.response_digest,
        }
    }

    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        match self {
            Self::Paper(page) => page.response_bytes,
            Self::Author(page) => page.response_bytes,
            Self::Citation(page) => page.response_bytes,
            Self::Recommendation(page) => page.response_bytes,
        }
    }

    #[must_use]
    pub const fn complete(&self) -> bool {
        match self {
            Self::Paper(page) => page.complete,
            Self::Author(page) => page.complete,
            Self::Citation(page) => page.complete,
            Self::Recommendation(page) => page.complete,
        }
    }

    #[must_use]
    pub fn next_cursor(&self) -> Option<&OpaqueCursor> {
        match self {
            Self::Paper(page) => page.next_cursor.as_ref(),
            Self::Author(page) => page.next_cursor.as_ref(),
            Self::Citation(page) => page.next_cursor.as_ref(),
            Self::Recommendation(page) => page.next_cursor.as_ref(),
        }
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        match self {
            Self::Paper(page) => page.records.len(),
            Self::Author(page) => page.records.len(),
            Self::Citation(page) => page.records.len(),
            Self::Recommendation(page) => page.records.len(),
        }
    }

    fn validate(&self) -> Result<(), ProviderError> {
        match self {
            Self::Paper(page) => page.validate(),
            Self::Author(page) => page.validate(),
            Self::Citation(page) => page.validate(),
            Self::Recommendation(page) => page.validate(),
        }
    }
}

pub trait SemanticScholarTransport: fmt::Debug {
    fn get(&mut self, request: &ApiGetRequest) -> Result<SemanticScholarResponse, TransportError>;

    fn provenance(&self) -> ProviderProvenance;
}

macro_rules! queue_transport {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone, Debug, Default)]
        pub struct $name {
            responses: VecDeque<Result<SemanticScholarResponse, TransportError>>,
            requests: Vec<ApiGetRequest>,
        }

        impl $name {
            pub fn push_response(&mut self, response: SemanticScholarResponse) {
                self.responses.push_back(Ok(response));
            }

            pub fn push_error(&mut self, error: TransportError) {
                self.responses.push_back(Err(error));
            }

            #[must_use]
            pub fn requests(&self) -> &[ApiGetRequest] {
                &self.requests
            }
        }

        impl SemanticScholarTransport for $name {
            fn get(
                &mut self,
                request: &ApiGetRequest,
            ) -> Result<SemanticScholarResponse, TransportError> {
                self.requests.push(request.clone());
                self.responses
                    .pop_front()
                    .unwrap_or(Err(TransportError::ProviderUnknown))
            }

            fn provenance(&self) -> ProviderProvenance {
                $provenance
            }
        }
    };
}

queue_transport!(
    RecordingSemanticScholarTransport,
    ProviderProvenance::Recording
);
queue_transport!(FixtureSemanticScholarTransport, ProviderProvenance::Fixture);
queue_transport!(FakeSemanticScholarTransport, ProviderProvenance::Fake);
queue_transport!(
    LoopbackSemanticScholarTransport,
    ProviderProvenance::Loopback
);

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl SemanticScholarTransport for BlockedEnvTransport {
    fn get(&mut self, _request: &ApiGetRequest) -> Result<SemanticScholarResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }
}

/// Layer-1 provider seam. It verifies typed redacted responses but never
/// resolves a key or performs native HTTPS itself.
pub struct SemanticScholarProvider<T: SemanticScholarTransport = RecordingSemanticScholarTransport>
{
    transport: T,
    definition: SemanticScholarProviderDefinition,
}

impl<T: SemanticScholarTransport> fmt::Debug for SemanticScholarProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SemanticScholarProvider")
            .field("transport_provenance", &self.provenance())
            .field("definition", &self.definition)
            .field("transport", &self.transport.provenance())
            .finish_non_exhaustive()
    }
}

impl<T: SemanticScholarTransport> SemanticScholarProvider<T> {
    pub fn new(transport: T, provider_version: impl Into<String>) -> Result<Self, ModelError> {
        let definition = SemanticScholarProviderDefinition::layer1(provider_version)?;
        Ok(Self {
            transport,
            definition,
        })
    }

    #[must_use]
    pub fn definition(&self) -> &SemanticScholarProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provenance(&self) -> ProviderProvenance {
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

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn get(
        &mut self,
        request: &ApiGetRequest,
    ) -> Result<SemanticScholarResponse, ProviderError> {
        self.definition.validate()?;
        if request.method() != HttpMethod::Get
            || request.host() != self.definition.api_host
            || request.api_version() != self.definition.api_version
        {
            return Err(ProviderError::HostOrVersionMismatch);
        }
        if !self
            .definition
            .allowed_endpoints
            .contains(&request.endpoint())
        {
            return Err(ProviderError::EndpointNotAllowlisted);
        }
        let response = self.transport.get(request)?;
        if response.response_bytes() > MAX_RESPONSE_BYTES {
            return Err(ProviderError::ResponseTooLarge);
        }
        if response.request_digest() != request.request_digest()
            || response.query_digest() != request.query_digest()
            || response.scope_digest() != request.scope_digest()
        {
            return Err(ProviderError::ResponseTampered);
        }
        if !response_kind_matches(request.endpoint(), response.kind()) {
            return Err(ProviderError::ResponseKindMismatch);
        }
        response.validate()?;
        Ok(response)
    }
}

fn response_kind_matches(endpoint: EndpointKind, response: ResponseKind) -> bool {
    match endpoint {
        EndpointKind::PaperSearch | EndpointKind::PaperBulkSearch | EndpointKind::PaperDetails => {
            matches!(response, ResponseKind::Paper)
        }
        EndpointKind::PaperAuthors | EndpointKind::AuthorSearch | EndpointKind::AuthorDetails => {
            matches!(response, ResponseKind::Author)
        }
        EndpointKind::AuthorPapers => matches!(response, ResponseKind::Paper),
        EndpointKind::PaperCitations | EndpointKind::PaperReferences => {
            matches!(response, ResponseKind::Citation)
        }
        EndpointKind::Recommendations => matches!(response, ResponseKind::Recommendation),
    }
}

// These imports are intentionally re-exported from the provider module so a
// consumer can build redacted fixtures without depending on private helpers.
pub use crate::model::{AuthorMetadataInput, PaperMetadataInput, VenueMetadataInput};

// Keep otherwise easy-to-miss API model names visible to rustdoc users.
#[allow(dead_code)]
fn _typed_api_surface(
    _author_id: Option<AuthorId>,
    _paper_id: Option<PaperId>,
    _venue_id: Option<VenueId>,
    _pool: Option<RecommendationPool>,
    _direction: Option<CitationDirection>,
    _text: Option<BoundedText>,
) {
}
