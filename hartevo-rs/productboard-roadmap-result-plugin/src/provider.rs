use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    Digest, MAX_ATTEMPTS, MAX_BACKOFF_SECONDS, MAX_ITEMS, MAX_PAGE_SIZE, MAX_RESPONSE_BYTES,
    ModelError, ProductboardRateLimitReceipt, ProductboardRegistration, ProductboardResourceKind,
    ProductboardRoadmapAggregate, ProductboardRoadmapItem, ProductboardRoadmapOperation,
    ProductboardRoadmapRequest, ProductboardRoadmapScope, ProductboardTransportProvenance,
    RegistrationRevocationReceipt, RegistrationState, Revision, SecretReference, canonical_digest,
    sha256_digest, validate_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ProductboardHttpMethod {
    Get,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductboardProviderRequest {
    pub method: ProductboardHttpMethod,
    pub host: String,
    pub path: String,
    pub operation: ProductboardRoadmapOperation,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub permission_digest: Digest,
    pub target_id_digest: Option<Digest>,
    pub page_token_digest: Option<Digest>,
    pub cursor_binding_digest: Option<Digest>,
    pub idempotency_key_digest: Digest,
    pub field_allowlist: Vec<String>,
    pub page_size: u16,
    pub attempt: u8,
    pub backoff_seconds: u32,
}

impl ProductboardProviderRequest {
    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        self.method == ProductboardHttpMethod::Get
            && self.host == crate::PRODUCTBOARD_API_HOST
            && path_is_allowlisted(&self.path)
            && operation_path_is_consistent(self.operation, &self.path)
            && self.page_size > 0
            && self.page_size <= MAX_PAGE_SIZE
            && self.attempt > 0
            && self.attempt <= MAX_ATTEMPTS
            && self.backoff_seconds <= MAX_BACKOFF_SECONDS
            && !self.field_allowlist.is_empty()
            && self.field_allowlist.iter().all(|field| {
                !field.is_empty()
                    && !field.contains('&')
                    && !field.contains('=')
                    && !field.to_ascii_lowercase().contains("content")
                    && !field.to_ascii_lowercase().contains("customer")
                    && !field.to_ascii_lowercase().contains("member")
                    && !field.to_ascii_lowercase().contains("owner")
                    && !field.to_ascii_lowercase().contains("email")
                    && !field.to_ascii_lowercase().contains("token")
            })
            && validate_digest(&self.scope_digest).is_ok()
            && validate_digest(&self.revision_digest).is_ok()
            && validate_digest(&self.permission_digest).is_ok()
            && validate_digest(&self.idempotency_key_digest).is_ok()
            && self
                .page_token_digest
                .as_ref()
                .is_none_or(|digest| validate_digest(digest).is_ok())
            && self
                .cursor_binding_digest
                .as_ref()
                .is_none_or(|digest| validate_digest(digest).is_ok())
    }
}

fn base_path(path: &str) -> &str {
    path.split_once('?').map_or(path, |(base, _)| base)
}

fn path_is_allowlisted(path: &str) -> bool {
    let path = base_path(path);
    if matches!(
        path,
        "/v2/notes" | "/v2/entities" | "/v2/notes/configurations" | "/v2/entities/configurations"
    ) {
        return true;
    }
    let segments: Vec<&str> = path.split('/').collect();
    match segments.len() {
        5 => {
            (segments[0].is_empty()
                && segments[1] == "v2"
                && segments[2] == "entities"
                && segments[3] == "configurations"
                && valid_path_id(segments[4]))
                || (segments[0].is_empty()
                    && segments[1] == "v2"
                    && (segments[2] == "notes" || segments[2] == "entities")
                    && valid_path_id(segments[3])
                    && segments[4] == "relationships")
        }
        4 => {
            segments[0].is_empty()
                && segments[1] == "v2"
                && segments[2] == "entities"
                && valid_path_id(segments[3])
                || segments[0].is_empty()
                    && segments[1] == "v2"
                    && segments[2] == "notes"
                    && valid_path_id(segments[3])
        }
        _ => false,
    }
}

fn valid_path_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-$~".contains(&byte))
}

fn operation_path_is_consistent(operation: ProductboardRoadmapOperation, path: &str) -> bool {
    let path = base_path(path);
    let segments: Vec<&str> = path.split('/').collect();
    match operation {
        ProductboardRoadmapOperation::WorkspaceMetadata
        | ProductboardRoadmapOperation::EntityCollection
        | ProductboardRoadmapOperation::RoadmapAggregate => path == "/v2/entities",
        ProductboardRoadmapOperation::EntityConfigurationMetadata => {
            path == "/v2/entities/configurations"
                || (segments.len() == 5 && segments[3] == "configurations")
        }
        ProductboardRoadmapOperation::NoteConfigurationMetadata => {
            path == "/v2/notes/configurations"
        }
        ProductboardRoadmapOperation::NoteCollection => path == "/v2/notes",
        ProductboardRoadmapOperation::NoteMetadata => segments.len() == 4 && segments[2] == "notes",
        ProductboardRoadmapOperation::NoteRelationships => {
            segments.len() == 5 && segments[2] == "notes" && segments[4] == "relationships"
        }
        ProductboardRoadmapOperation::InsightMetadata
        | ProductboardRoadmapOperation::FeatureMetadata
        | ProductboardRoadmapOperation::ComponentMetadata
        | ProductboardRoadmapOperation::InitiativeMetadata
        | ProductboardRoadmapOperation::ObjectiveMetadata
        | ProductboardRoadmapOperation::ReleaseMetadata => {
            segments.len() == 4 && segments[2] == "entities"
        }
        ProductboardRoadmapOperation::InsightRelationships
        | ProductboardRoadmapOperation::EntityRelationships => {
            segments.len() == 5 && segments[2] == "entities" && segments[4] == "relationships"
        }
    }
}

/// Raw bytes exist only at the deterministic transport boundary. The body is
/// never exposed through Debug, provider errors, evidence, or proposals.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductboardResponse {
    status: u16,
    body: Vec<u8>,
    rate_limit: ProductboardRateLimitReceipt,
}

impl fmt::Debug for ProductboardResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductboardResponse")
            .field("status", &self.status)
            .field("body", &"<redacted>")
            .field("body_bytes", &self.body.len())
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

impl ProductboardResponse {
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>, rate_limit: ProductboardRateLimitReceipt) -> Self {
        Self {
            status,
            body,
            rate_limit,
        }
    }

    #[must_use]
    pub fn json<T: Serialize>(status: u16, value: &T) -> Self {
        Self::json_with_rate_limit(status, value, ProductboardRateLimitReceipt::default())
    }

    #[must_use]
    pub fn json_with_rate_limit<T: Serialize>(
        status: u16,
        value: &T,
        rate_limit: ProductboardRateLimitReceipt,
    ) -> Self {
        let body = serde_json::to_vec(value).expect("Productboard fixture payload serializes");
        Self::new(status, body, rate_limit)
    }

    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub fn response_digest(&self) -> Digest {
        sha256_digest(&self.body)
    }

    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.body.len()
    }

    #[must_use]
    pub fn rate_limit(&self) -> &ProductboardRateLimitReceipt {
        &self.rate_limit
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProductboardTransportError {
    #[error("Productboard native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Productboard transport timed out")]
    Timeout,
    #[error("Productboard provider is unknown or unavailable")]
    ProviderUnknown,
    #[error("Productboard access was denied or credentials are unavailable")]
    AccessLoss,
    #[error("Productboard transport returned a partial response")]
    Partial,
}

pub trait ProductboardTransport: fmt::Debug {
    fn provenance(&self) -> ProductboardTransportProvenance;

    fn execute(
        &mut self,
        request: &ProductboardProviderRequest,
    ) -> Result<ProductboardResponse, ProductboardTransportError>;
}

#[derive(Clone, Debug)]
pub struct FixtureProductboardTransport {
    response: ProductboardResponse,
}

impl FixtureProductboardTransport {
    #[must_use]
    pub const fn new(response: ProductboardResponse) -> Self {
        Self { response }
    }
}

impl ProductboardTransport for FixtureProductboardTransport {
    fn provenance(&self) -> ProductboardTransportProvenance {
        ProductboardTransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        _request: &ProductboardProviderRequest,
    ) -> Result<ProductboardResponse, ProductboardTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct RecordingProductboardTransport {
    response: ProductboardResponse,
    requests: Vec<ProductboardProviderRequest>,
}

impl RecordingProductboardTransport {
    #[must_use]
    pub const fn new(response: ProductboardResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[ProductboardProviderRequest] {
        &self.requests
    }
}

impl ProductboardTransport for RecordingProductboardTransport {
    fn provenance(&self) -> ProductboardTransportProvenance {
        ProductboardTransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &ProductboardProviderRequest,
    ) -> Result<ProductboardResponse, ProductboardTransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct FakeProductboardTransport {
    responses: VecDeque<Result<ProductboardResponse, ProductboardTransportError>>,
    requests: Vec<ProductboardProviderRequest>,
}

impl FakeProductboardTransport {
    #[must_use]
    pub fn new(response: ProductboardResponse) -> Self {
        let mut transport = Self::default();
        transport.push_response(response);
        transport
    }

    pub fn push_response(&mut self, response: ProductboardResponse) {
        self.responses.push_back(Ok(response));
    }

    pub fn push_error(&mut self, error: ProductboardTransportError) {
        self.responses.push_back(Err(error));
    }

    #[must_use]
    pub fn requests(&self) -> &[ProductboardProviderRequest] {
        &self.requests
    }
}

impl ProductboardTransport for FakeProductboardTransport {
    fn provenance(&self) -> ProductboardTransportProvenance {
        ProductboardTransportProvenance::Fake
    }

    fn execute(
        &mut self,
        request: &ProductboardProviderRequest,
    ) -> Result<ProductboardResponse, ProductboardTransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or(Err(ProductboardTransportError::ProviderUnknown))
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackProductboardTransport {
    response: ProductboardResponse,
}

impl LoopbackProductboardTransport {
    #[must_use]
    pub const fn new(response: ProductboardResponse) -> Self {
        Self { response }
    }
}

impl ProductboardTransport for LoopbackProductboardTransport {
    fn provenance(&self) -> ProductboardTransportProvenance {
        ProductboardTransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        _request: &ProductboardProviderRequest,
    ) -> Result<ProductboardResponse, ProductboardTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvProductboardTransport;

impl ProductboardTransport for BlockedEnvProductboardTransport {
    fn provenance(&self) -> ProductboardTransportProvenance {
        ProductboardTransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &ProductboardProviderRequest,
    ) -> Result<ProductboardResponse, ProductboardTransportError> {
        Err(ProductboardTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductboardProviderDefinition {
    pub provider_id: String,
    pub version: String,
    pub api_revision: String,
    pub base_url: String,
    pub documentation: String,
    pub provenance: ProductboardTransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub read_allowlist: Vec<String>,
    pub max_requests_per_minute: u16,
    pub max_response_bytes: usize,
    pub max_items: usize,
    pub max_page_size: u16,
    pub read_only: bool,
}

impl ProductboardProviderDefinition {
    #[must_use]
    pub fn layer1(provenance: ProductboardTransportProvenance) -> Self {
        Self {
            provider_id: crate::PRODUCTBOARD_PROVIDER_ID.to_owned(),
            version: crate::PRODUCTBOARD_PROVIDER_VERSION.to_owned(),
            api_revision: crate::PRODUCTBOARD_PROVIDER_API_REVISION.to_owned(),
            base_url: crate::PRODUCTBOARD_API_BASE_URL.to_owned(),
            documentation: crate::PRODUCTBOARD_API_DOCUMENTATION_URL.to_owned(),
            provenance,
            connected: false,
            native: false,
            first_party: false,
            read_allowlist: vec![
                "GET /v2/notes/configurations".to_owned(),
                "GET /v2/entities/configurations".to_owned(),
                "GET /v2/entities/configurations/{type}".to_owned(),
                "GET /v2/notes".to_owned(),
                "GET /v2/notes/{note_id}".to_owned(),
                "GET /v2/notes/{note_id}/relationships".to_owned(),
                "GET /v2/entities".to_owned(),
                "GET /v2/entities/{entity_id}".to_owned(),
                "GET /v2/entities/{entity_id}/relationships".to_owned(),
            ],
            max_requests_per_minute: crate::MAX_REQUESTS_PER_MINUTE,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_items: MAX_ITEMS,
            max_page_size: MAX_PAGE_SIZE,
            read_only: true,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.provider_id != crate::PRODUCTBOARD_PROVIDER_ID
            || self.version != crate::PRODUCTBOARD_PROVIDER_VERSION
            || self.api_revision != crate::PRODUCTBOARD_PROVIDER_API_REVISION
            || self.base_url != crate::PRODUCTBOARD_API_BASE_URL
            || self.documentation != crate::PRODUCTBOARD_API_DOCUMENTATION_URL
            || self.connected
            || self.native
            || self.first_party
            || !self.read_only
            || self.max_requests_per_minute != crate::MAX_REQUESTS_PER_MINUTE
            || self.max_response_bytes != MAX_RESPONSE_BYTES
            || self.max_items != MAX_ITEMS
            || self.max_page_size != MAX_PAGE_SIZE
            || self.read_allowlist != Self::layer1(self.provenance).read_allowlist
        {
            Err(ModelError::InvalidScope("provider definition drift"))
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProductboardProviderError {
    #[error("Productboard registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Productboard Public API token reference is revoked")]
    SecretRevoked,
    #[error("Productboard provider request is invalid or outside the exact scope")]
    RequestInvalid,
    #[error("Productboard provider response crossed the exact scope fence")]
    ScopeMismatch,
    #[error("Productboard provider response crossed the revision fence")]
    RevisionMismatch,
    #[error("Productboard provider response was malformed or tampered")]
    ResponseTampered {
        request_digest: Digest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: ProductboardRateLimitReceipt,
        status: Option<u16>,
    },
    #[error("Productboard provider response exceeded the bounded response size")]
    ResponseTooLarge {
        request_digest: Digest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: ProductboardRateLimitReceipt,
    },
    #[error("Productboard provider rate limit exhausted")]
    RateLimited {
        request_digest: Digest,
        response_digest: Option<Digest>,
        response_bytes: usize,
        rate_limit: ProductboardRateLimitReceipt,
        status: Option<u16>,
    },
    #[error("Productboard provider request timed out")]
    Timeout {
        request_digest: Digest,
        response_digest: Option<Digest>,
        response_bytes: usize,
        rate_limit: ProductboardRateLimitReceipt,
    },
    #[error("Productboard provider access was lost")]
    AccessLoss {
        request_digest: Digest,
        response_digest: Option<Digest>,
        response_bytes: usize,
        rate_limit: ProductboardRateLimitReceipt,
        status: Option<u16>,
    },
    #[error("Productboard provider is unknown or unavailable")]
    ProviderUnknown {
        request_digest: Digest,
        response_digest: Option<Digest>,
        response_bytes: usize,
        rate_limit: ProductboardRateLimitReceipt,
        status: Option<u16>,
    },
    #[error("Productboard native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv { request_digest: Digest },
    #[error("Productboard transport returned a partial response")]
    Partial {
        request_digest: Digest,
        response_digest: Option<Digest>,
        response_bytes: usize,
        rate_limit: ProductboardRateLimitReceipt,
        status: Option<u16>,
    },
    #[error(transparent)]
    Model(#[from] ModelError),
}

impl ProductboardProviderError {
    #[must_use]
    pub fn request(&self) -> Option<&ProductboardProviderRequest> {
        None
    }

    #[must_use]
    pub fn metadata(&self) -> Option<(Digest, usize, ProductboardRateLimitReceipt, Option<u16>)> {
        match self {
            Self::ResponseTampered {
                response_digest,
                response_bytes,
                rate_limit,
                status,
                ..
            }
            | Self::AccessLoss {
                response_digest: Some(response_digest),
                response_bytes,
                rate_limit,
                status,
                ..
            } => Some((
                response_digest.clone(),
                *response_bytes,
                rate_limit.clone(),
                *status,
            )),
            Self::ResponseTooLarge {
                response_digest,
                response_bytes,
                rate_limit,
                ..
            } => Some((
                response_digest.clone(),
                *response_bytes,
                rate_limit.clone(),
                None,
            )),
            Self::RateLimited {
                response_digest,
                response_bytes,
                rate_limit,
                status,
                ..
            }
            | Self::ProviderUnknown {
                response_digest,
                response_bytes,
                rate_limit,
                status,
                ..
            }
            | Self::Partial {
                response_digest,
                response_bytes,
                rate_limit,
                status,
                ..
            } => response_digest
                .clone()
                .map(|digest| (digest, *response_bytes, rate_limit.clone(), *status)),
            Self::Timeout {
                response_digest,
                response_bytes,
                rate_limit,
                ..
            } => response_digest
                .clone()
                .map(|digest| (digest, *response_bytes, rate_limit.clone(), None)),
            _ => None,
        }
    }

    #[must_use]
    pub fn request_digest(&self) -> Option<Digest> {
        match self {
            Self::ResponseTampered { request_digest, .. }
            | Self::ResponseTooLarge { request_digest, .. }
            | Self::RateLimited { request_digest, .. }
            | Self::Timeout { request_digest, .. }
            | Self::AccessLoss { request_digest, .. }
            | Self::ProviderUnknown { request_digest, .. }
            | Self::BlockedEnv { request_digest }
            | Self::Partial { request_digest, .. } => Some(request_digest.clone()),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProductboardProviderRead {
    pub aggregate: ProductboardRoadmapAggregate,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub rate_limit: ProductboardRateLimitReceipt,
    pub status: u16,
    pub provenance: ProductboardTransportProvenance,
}

pub struct ProductboardRoadmapProvider<T: ProductboardTransport> {
    scope: ProductboardRoadmapScope,
    secret_reference: SecretReference,
    transport: T,
    definition: ProductboardProviderDefinition,
    registration: ProductboardRegistration,
}

impl<T: ProductboardTransport> fmt::Debug for ProductboardRoadmapProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductboardRoadmapProvider")
            .field("scope", &self.scope)
            .field("secret_reference", &self.secret_reference)
            .field("transport", &self.transport)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .finish()
    }
}

impl<T: ProductboardTransport> ProductboardRoadmapProvider<T> {
    pub fn new(
        scope: ProductboardRoadmapScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, ProductboardProviderError> {
        scope.validate()?;
        let definition = ProductboardProviderDefinition::layer1(transport.provenance());
        definition.validate()?;
        let provider_digest = definition.provider_digest();
        let registration =
            ProductboardRegistration::bind(&scope, &secret_reference, provider_digest);
        Ok(Self {
            scope,
            secret_reference,
            transport,
            definition,
            registration,
        })
    }

    pub fn with_registration(
        scope: ProductboardRoadmapScope,
        secret_reference: SecretReference,
        transport: T,
        registration: ProductboardRegistration,
    ) -> Result<Self, ProductboardProviderError> {
        scope.validate()?;
        let definition = ProductboardProviderDefinition::layer1(transport.provenance());
        definition.validate()?;
        registration.validate(&scope, &secret_reference, &definition.provider_digest())?;
        Ok(Self {
            scope,
            secret_reference,
            transport,
            definition,
            registration,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &ProductboardRoadmapScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &ProductboardProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    #[must_use]
    pub fn registration(&self) -> &ProductboardRegistration {
        &self.registration
    }

    #[must_use]
    pub fn transport_provenance(&self) -> ProductboardTransportProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(&mut self) -> Result<ProductboardProviderRead, ProductboardProviderError> {
        let key = crate::IdempotencyKey::new("productboard-default-read")?;
        let request = ProductboardRoadmapRequest::roadmap(&self.scope, &key)?;
        self.read_request(&request)
    }

    pub fn read_request(
        &mut self,
        request: &ProductboardRoadmapRequest,
    ) -> Result<ProductboardProviderRead, ProductboardProviderError> {
        self.ensure_available()?;
        request
            .validate(&self.scope)
            .map_err(|_| ProductboardProviderError::RequestInvalid)?;
        if !self
            .scope
            .permissions()
            .has(request.operation().permission())
        {
            return Err(ProductboardProviderError::RequestInvalid);
        }
        let provider_request = self.provider_request(request);
        if !provider_request.is_allowlisted() {
            return Err(ProductboardProviderError::RequestInvalid);
        }
        let provenance = self.transport.provenance();
        let response = match self.transport.execute(&provider_request) {
            Ok(response) => response,
            Err(error) => return Err(Self::transport_error(&provider_request, error)),
        };
        response
            .rate_limit()
            .validate()
            .map_err(ProductboardProviderError::from)?;
        let request_digest = request.request_digest();
        let response_digest = response.response_digest();
        let response_bytes = response.response_bytes();
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProductboardProviderError::ResponseTooLarge {
                request_digest,
                response_digest,
                response_bytes,
                rate_limit: response.rate_limit().clone(),
            });
        }
        if response.status() == 429 {
            return Err(ProductboardProviderError::RateLimited {
                request_digest,
                response_digest: Some(response_digest),
                response_bytes,
                rate_limit: response.rate_limit().clone(),
                status: Some(response.status()),
            });
        }
        if response.status() == 401 || response.status() == 403 {
            return Err(ProductboardProviderError::AccessLoss {
                request_digest,
                response_digest: Some(response_digest),
                response_bytes,
                rate_limit: response.rate_limit().clone(),
                status: Some(response.status()),
            });
        }
        if response.status() == 408 || response.status() == 504 {
            return Err(ProductboardProviderError::Timeout {
                request_digest,
                response_digest: Some(response_digest),
                response_bytes,
                rate_limit: response.rate_limit().clone(),
            });
        }
        if !(200..300).contains(&response.status()) {
            return Err(ProductboardProviderError::ProviderUnknown {
                request_digest,
                response_digest: Some(response_digest),
                response_bytes,
                rate_limit: response.rate_limit().clone(),
                status: Some(response.status()),
            });
        }
        let value: Value = serde_json::from_slice(&response.body).map_err(|_| {
            ProductboardProviderError::ResponseTampered {
                request_digest: request_digest.clone(),
                response_digest: response_digest.clone(),
                response_bytes,
                rate_limit: response.rate_limit().clone(),
                status: Some(response.status()),
            }
        })?;
        let aggregate = self.aggregate_from_value(request, &value, response.status(), &response)?;
        Ok(ProductboardProviderRead {
            aggregate,
            response_digest,
            response_bytes,
            rate_limit: response.rate_limit().clone(),
            status: response.status(),
            provenance,
        })
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocationReceipt, ProductboardProviderError> {
        self.registration
            .revoke()
            .map_err(ProductboardProviderError::from)
    }

    pub fn restore(&mut self) -> Result<(), ProductboardProviderError> {
        self.registration
            .restore()
            .map_err(ProductboardProviderError::from)
    }

    pub fn revoke_secret(&mut self) -> Result<(), ProductboardProviderError> {
        self.secret_reference
            .revoke()
            .map_err(ProductboardProviderError::from)
    }

    pub fn restore_secret(&mut self) -> Result<(), ProductboardProviderError> {
        self.secret_reference
            .restore()
            .map_err(ProductboardProviderError::from)
    }

    fn ensure_available(&self) -> Result<(), ProductboardProviderError> {
        self.definition.validate()?;
        if self.registration.state != RegistrationState::Active {
            return Err(ProductboardProviderError::RegistrationRevoked);
        }
        self.registration
            .validate(&self.scope, &self.secret_reference, &self.provider_digest())
            .map_err(|_| ProductboardProviderError::RegistrationRevoked)?;
        if self.secret_reference.is_revoked() {
            return Err(ProductboardProviderError::SecretRevoked);
        }
        Ok(())
    }

    fn provider_request(
        &self,
        request: &ProductboardRoadmapRequest,
    ) -> ProductboardProviderRequest {
        let path = match request.operation() {
            ProductboardRoadmapOperation::WorkspaceMetadata
            | ProductboardRoadmapOperation::EntityCollection
            | ProductboardRoadmapOperation::RoadmapAggregate => "/v2/entities".to_owned(),
            ProductboardRoadmapOperation::EntityConfigurationMetadata => {
                "/v2/entities/configurations".to_owned()
            }
            ProductboardRoadmapOperation::NoteConfigurationMetadata => {
                "/v2/notes/configurations".to_owned()
            }
            ProductboardRoadmapOperation::NoteCollection => "/v2/notes".to_owned(),
            ProductboardRoadmapOperation::NoteMetadata
            | ProductboardRoadmapOperation::NoteRelationships => {
                let suffix =
                    if request.operation() == ProductboardRoadmapOperation::NoteRelationships {
                        "/relationships"
                    } else {
                        ""
                    };
                format!("/v2/notes/{}{suffix}", self.scope.note().as_str())
            }
            ProductboardRoadmapOperation::InsightMetadata
            | ProductboardRoadmapOperation::FeatureMetadata
            | ProductboardRoadmapOperation::ComponentMetadata
            | ProductboardRoadmapOperation::InitiativeMetadata
            | ProductboardRoadmapOperation::ObjectiveMetadata
            | ProductboardRoadmapOperation::ReleaseMetadata
            | ProductboardRoadmapOperation::InsightRelationships
            | ProductboardRoadmapOperation::EntityRelationships => {
                let id = request.operation().target_kind().map_or_else(
                    || self.scope.feature().as_str(),
                    |kind| self.scope.resource_id(kind),
                );
                let suffix = matches!(
                    request.operation(),
                    ProductboardRoadmapOperation::InsightRelationships
                        | ProductboardRoadmapOperation::EntityRelationships
                )
                .then_some("/relationships")
                .unwrap_or("");
                format!("/v2/entities/{id}{suffix}")
            }
        };
        ProductboardProviderRequest {
            method: ProductboardHttpMethod::Get,
            host: crate::PRODUCTBOARD_API_HOST.to_owned(),
            path,
            operation: request.operation(),
            scope_digest: request.scope_digest().clone(),
            revision_digest: request.revision_digest().clone(),
            permission_digest: request.permission_digest().clone(),
            target_id_digest: request.target_id_digest().cloned(),
            page_token_digest: request.page_token_digest().cloned(),
            cursor_binding_digest: request.cursor_binding().cloned(),
            idempotency_key_digest: request.idempotency_key_digest().clone(),
            field_allowlist: request.field_allowlist.clone(),
            page_size: request.page_size(),
            attempt: 1,
            backoff_seconds: 0,
        }
    }

    fn transport_error(
        request: &ProductboardProviderRequest,
        error: ProductboardTransportError,
    ) -> ProductboardProviderError {
        let request_digest = canonical_digest(request);
        match error {
            ProductboardTransportError::BlockedEnv => {
                ProductboardProviderError::BlockedEnv { request_digest }
            }
            ProductboardTransportError::Timeout => ProductboardProviderError::Timeout {
                request_digest,
                response_digest: None,
                response_bytes: 0,
                rate_limit: ProductboardRateLimitReceipt::default(),
            },
            ProductboardTransportError::AccessLoss => ProductboardProviderError::AccessLoss {
                request_digest,
                response_digest: None,
                response_bytes: 0,
                rate_limit: ProductboardRateLimitReceipt::default(),
                status: None,
            },
            ProductboardTransportError::ProviderUnknown => {
                ProductboardProviderError::ProviderUnknown {
                    request_digest,
                    response_digest: None,
                    response_bytes: 0,
                    rate_limit: ProductboardRateLimitReceipt::default(),
                    status: None,
                }
            }
            ProductboardTransportError::Partial => ProductboardProviderError::Partial {
                request_digest,
                response_digest: None,
                response_bytes: 0,
                rate_limit: ProductboardRateLimitReceipt::default(),
                status: None,
            },
        }
    }

    fn aggregate_from_value(
        &self,
        request: &ProductboardRoadmapRequest,
        value: &Value,
        status: u16,
        response: &ProductboardResponse,
    ) -> Result<ProductboardRoadmapAggregate, ProductboardProviderError> {
        let raw_items = extract_items(value, request.operation());
        let mut items = Vec::new();
        for raw_item in raw_items.iter().take(MAX_ITEMS + 1) {
            self.validate_scope_fields(raw_item, request.operation())?;
            let item = self.item_from_value(request, raw_item)?;
            if !self.item_is_within_scope(request.operation(), &item) {
                return Err(ProductboardProviderError::ScopeMismatch);
            }
            items.push(item);
        }
        if items.len() > MAX_ITEMS {
            return Err(Self::tampered(request, response, status));
        }
        if request.operation().target_kind().is_some()
            && !request.operation().is_collection()
            && items.len() != 1
        {
            return Err(Self::tampered(request, response, status));
        }
        if let Some(expected_target) = request.target_id_digest() {
            if items
                .first()
                .is_none_or(|item| &item.id_digest != expected_target)
            {
                return Err(ProductboardProviderError::ScopeMismatch);
            }
        }
        let partial = status == 206
            || value
                .get("partial")
                .and_then(Value::as_bool)
                .unwrap_or(false);
        let total_count = value
            .get("total")
            .or_else(|| value.get("totalCount"))
            .or_else(|| value.get("total_count"))
            .and_then(value_as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(items.len() as u32);
        let next_page_token = value
            .get("next_page_token")
            .or_else(|| value.get("nextPageToken"))
            .or_else(|| value.get("links").and_then(|links| links.get("next")))
            .and_then(|next| {
                next.as_str()
                    .or_else(|| next.get("href").and_then(Value::as_str))
            });
        let (next_page_token_digest, cursor_binding_digest) = match next_page_token {
            Some(token) => (
                Some(sha256_digest(
                    format!("productboard-page-token/v1|{token}").as_bytes(),
                )),
                Some(request.cursor_binding_digest()),
            ),
            None => (None, None),
        };
        let archived = value
            .get("archived")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| !items.is_empty() && items.iter().all(|item| item.archived));
        let relationship_digest = (!items.is_empty()).then(|| {
            canonical_digest(
                &items
                    .iter()
                    .filter_map(|item| item.relationship_digest.as_ref())
                    .collect::<Vec<_>>(),
            )
        });
        ProductboardRoadmapAggregate::new(
            request.operation(),
            items,
            total_count,
            partial,
            request.target_id_digest().cloned(),
            next_page_token_digest,
            cursor_binding_digest,
        )
        .map(|aggregate| {
            aggregate
                .with_archived(archived)
                .with_relationship_digest(relationship_digest)
        })
        .map_err(ProductboardProviderError::from)
    }

    fn item_from_value(
        &self,
        request: &ProductboardRoadmapRequest,
        value: &Value,
    ) -> Result<ProductboardRoadmapItem, ProductboardProviderError> {
        let kind = value
            .get("kind")
            .or_else(|| value.get("type"))
            .or_else(|| value.get("entityType"))
            .and_then(Value::as_str)
            .and_then(parse_resource_kind)
            .unwrap_or_else(|| request.operation().resource_kind());
        let id = value
            .get("id")
            .or_else(|| value.get("uuid"))
            .or_else(|| value.get("entityId"))
            .or_else(|| value.get("noteId"))
            .and_then(Value::as_str)
            .or_else(|| {
                value
                    .get("target")
                    .and_then(|target| target.get("id"))
                    .and_then(Value::as_str)
            });
        let id_digest = match id {
            Some(id) => canonical_digest(&id),
            None if request.operation().target_kind().is_some() => request
                .target_id_digest()
                .cloned()
                .ok_or(ProductboardProviderError::ScopeMismatch)?,
            None => value
                .get("type")
                .and_then(Value::as_str)
                .map(canonical_digest)
                .ok_or(ProductboardProviderError::ScopeMismatch)?,
        };
        if request
            .target_id_digest()
            .is_some_and(|expected| expected != &id_digest)
        {
            return Err(ProductboardProviderError::ScopeMismatch);
        }
        let title_digest = value
            .get("name")
            .or_else(|| value.get("title"))
            .or_else(|| value.get("label"))
            .and_then(Value::as_str)
            .map(|title| sha256_digest(format!("productboard-title/v1|{title}").as_bytes()));
        let status_digest = value
            .get("status")
            .and_then(|status| {
                status
                    .as_str()
                    .or_else(|| status.get("name").and_then(Value::as_str))
                    .or_else(|| status.get("id").and_then(Value::as_str))
            })
            .map(|status| sha256_digest(format!("productboard-status/v1|{status}").as_bytes()));
        let archived = value
            .get("archived")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let child_count = value
            .get("children")
            .or_else(|| value.get("items"))
            .and_then(Value::as_array)
            .map_or(0, |children| {
                u16::try_from(children.len()).unwrap_or(u16::MAX)
            });
        let relationship_values = value
            .get("relationships")
            .or_else(|| value.get("links"))
            .and_then(Value::as_array);
        let relationship_count = relationship_values.map_or(0, |relationships| {
            u16::try_from(relationships.len()).unwrap_or(u16::MAX)
        });
        let relationship_digest = relationship_values.map(|relationships| {
            let fingerprints: Vec<Digest> = relationships
                .iter()
                .map(|relationship| {
                    let kind = relationship
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    let target = relationship
                        .get("target")
                        .and_then(|target| target.get("id"))
                        .and_then(Value::as_str)
                        .or_else(|| relationship.get("targetId").and_then(Value::as_str))
                        .unwrap_or("unknown");
                    canonical_digest(&(kind, target))
                })
                .collect();
            canonical_digest(&fingerprints)
        });
        let content_digest = ["content", "description", "customer", "owner", "members"]
            .iter()
            .find_map(|field| value.get(*field))
            .map(canonical_digest);
        let source_revision = value
            .get("revision")
            .or_else(|| value.get("version"))
            .and_then(value_as_u64)
            .unwrap_or_else(|| self.scope.scope_revision().get());
        if source_revision != self.scope.scope_revision().get() {
            return Err(ProductboardProviderError::RevisionMismatch);
        }
        let item = ProductboardRoadmapItem::new(
            kind,
            id_digest,
            title_digest,
            status_digest,
            child_count,
            Revision::new(source_revision).map_err(ProductboardProviderError::from)?,
        )?
        .with_archived(archived)
        .with_relationships(relationship_count, relationship_digest)
        .with_content_digest(content_digest);
        Ok(item)
    }

    fn validate_scope_fields(
        &self,
        value: &Value,
        operation: ProductboardRoadmapOperation,
    ) -> Result<(), ProductboardProviderError> {
        let exact_bindings = [
            ("workspace_id", self.scope.workspace().digest()),
            ("workspaceId", self.scope.workspace().digest()),
            (
                "entity_configuration_id",
                self.scope.entity_configuration().digest(),
            ),
            (
                "entityConfigurationId",
                self.scope.entity_configuration().digest(),
            ),
            ("note_id", self.scope.note().digest()),
            ("noteId", self.scope.note().digest()),
            ("insight_id", self.scope.insight().digest()),
            ("insightId", self.scope.insight().digest()),
            ("feature_id", self.scope.feature().digest()),
            ("featureId", self.scope.feature().digest()),
            ("component_id", self.scope.component().digest()),
            ("componentId", self.scope.component().digest()),
            ("initiative_id", self.scope.initiative().digest()),
            ("initiativeId", self.scope.initiative().digest()),
            ("objective_id", self.scope.objective().digest()),
            ("objectiveId", self.scope.objective().digest()),
            ("release_id", self.scope.release().digest()),
            ("releaseId", self.scope.release().digest()),
        ];
        for (field, expected_digest) in exact_bindings {
            if let Some(value) = value.get(field) {
                let Some(value) = value
                    .as_str()
                    .or_else(|| value.get("id").and_then(Value::as_str))
                else {
                    return Err(ProductboardProviderError::ScopeMismatch);
                };
                if canonical_digest(&value) != expected_digest {
                    return Err(ProductboardProviderError::ScopeMismatch);
                }
            }
        }
        if let Some(workspace) = value.get("workspace") {
            let Some(workspace) = workspace
                .as_str()
                .or_else(|| workspace.get("id").and_then(Value::as_str))
            else {
                return Err(ProductboardProviderError::ScopeMismatch);
            };
            if canonical_digest(&workspace) != self.scope.workspace().digest() {
                return Err(ProductboardProviderError::ScopeMismatch);
            }
        }
        if matches!(
            operation,
            ProductboardRoadmapOperation::NoteRelationships
                | ProductboardRoadmapOperation::InsightRelationships
                | ProductboardRoadmapOperation::EntityRelationships
        ) {
            if let Some(target) = value.get("target") {
                if let Some(target_id) = target
                    .get("id")
                    .and_then(Value::as_str)
                    .or_else(|| target.as_str())
                {
                    let allowed = [
                        self.scope.workspace().digest(),
                        self.scope.entity_configuration().digest(),
                        self.scope.note().digest(),
                        self.scope.insight().digest(),
                        self.scope.feature().digest(),
                        self.scope.component().digest(),
                        self.scope.initiative().digest(),
                        self.scope.objective().digest(),
                        self.scope.release().digest(),
                    ];
                    if !allowed.contains(&canonical_digest(&target_id)) {
                        return Err(ProductboardProviderError::ScopeMismatch);
                    }
                }
            }
        }
        Ok(())
    }

    fn item_is_within_scope(
        &self,
        operation: ProductboardRoadmapOperation,
        item: &ProductboardRoadmapItem,
    ) -> bool {
        let scoped = [
            (
                ProductboardResourceKind::Workspace,
                self.scope.workspace().digest(),
            ),
            (
                ProductboardResourceKind::EntityConfiguration,
                self.scope.entity_configuration().digest(),
            ),
            (ProductboardResourceKind::Note, self.scope.note().digest()),
            (
                ProductboardResourceKind::Insight,
                self.scope.insight().digest(),
            ),
            (
                ProductboardResourceKind::Feature,
                self.scope.feature().digest(),
            ),
            (
                ProductboardResourceKind::Component,
                self.scope.component().digest(),
            ),
            (
                ProductboardResourceKind::Initiative,
                self.scope.initiative().digest(),
            ),
            (
                ProductboardResourceKind::Objective,
                self.scope.objective().digest(),
            ),
            (
                ProductboardResourceKind::Release,
                self.scope.release().digest(),
            ),
        ];
        match operation {
            ProductboardRoadmapOperation::NoteCollection => {
                item.kind == ProductboardResourceKind::Note
                    && item.id_digest == self.scope.note().digest()
            }
            ProductboardRoadmapOperation::EntityCollection
            | ProductboardRoadmapOperation::RoadmapAggregate => {
                scoped.iter().any(|(kind, digest)| {
                    matches!(
                        kind,
                        ProductboardResourceKind::Insight
                            | ProductboardResourceKind::Feature
                            | ProductboardResourceKind::Component
                            | ProductboardResourceKind::Initiative
                            | ProductboardResourceKind::Objective
                            | ProductboardResourceKind::Release
                    ) && item.kind == *kind
                        && item.id_digest == *digest
                })
            }
            ProductboardRoadmapOperation::NoteRelationships
            | ProductboardRoadmapOperation::InsightRelationships
            | ProductboardRoadmapOperation::EntityRelationships => {
                scoped.iter().any(|(_, digest)| item.id_digest == *digest)
            }
            _ => true,
        }
    }

    fn tampered(
        request: &ProductboardRoadmapRequest,
        response: &ProductboardResponse,
        status: u16,
    ) -> ProductboardProviderError {
        ProductboardProviderError::ResponseTampered {
            request_digest: request.request_digest(),
            response_digest: response.response_digest(),
            response_bytes: response.response_bytes(),
            rate_limit: response.rate_limit().clone(),
            status: Some(status),
        }
    }
}

fn value_as_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse::<u64>().ok()))
}

fn extract_items(value: &Value, operation: ProductboardRoadmapOperation) -> Vec<&Value> {
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        return items.iter().collect();
    }
    if let Some(items) = value.get("data").and_then(Value::as_array) {
        return items.iter().collect();
    }
    if let Some(items) = value.get("results").and_then(Value::as_array) {
        return items.iter().collect();
    }
    if operation.is_collection() {
        for key in [
            "notes",
            "entities",
            "relationships",
            "configurations",
            "features",
            "initiatives",
            "objectives",
            "releases",
        ] {
            if let Some(items) = value.get(key).and_then(Value::as_array) {
                return items.iter().collect();
            }
        }
    }
    if let Some(data) = value.get("data") {
        if data.is_object() {
            return vec![data];
        }
    }
    if value.is_object() {
        vec![value]
    } else {
        Vec::new()
    }
}

fn parse_resource_kind(value: &str) -> Option<ProductboardResourceKind> {
    match value {
        "workspace" | "product" => Some(ProductboardResourceKind::Workspace),
        "configuration" | "entity_configuration" | "entityConfiguration" => {
            Some(ProductboardResourceKind::EntityConfiguration)
        }
        "note" | "textNote" | "conversationNote" | "opportunityNote" => {
            Some(ProductboardResourceKind::Note)
        }
        "insight" => Some(ProductboardResourceKind::Insight),
        "feature" | "subfeature" => Some(ProductboardResourceKind::Feature),
        "component" => Some(ProductboardResourceKind::Component),
        "initiative" => Some(ProductboardResourceKind::Initiative),
        "objective" | "keyResult" => Some(ProductboardResourceKind::Objective),
        "release" | "releaseGroup" => Some(ProductboardResourceKind::Release),
        "relationship" | "parent" | "child" | "link" => {
            Some(ProductboardResourceKind::Relationship)
        }
        _ => None,
    }
}

pub type ProductboardRoadmapProviderRequest = ProductboardProviderRequest;
pub type ProductboardHttpResponse = ProductboardResponse;
pub type ProductboardRoadmapResponse = ProductboardResponse;
pub type FixtureProductboardRoadmapTransport = FixtureProductboardTransport;
pub type RecordingProductboardRoadmapTransport = RecordingProductboardTransport;
pub type FakeProductboardRoadmapTransport = FakeProductboardTransport;
pub type LoopbackProductboardRoadmapTransport = LoopbackProductboardTransport;
pub type BlockedEnvProductboardRoadmapTransport = BlockedEnvProductboardTransport;
pub type ProductboardProvider<T> = ProductboardRoadmapProvider<T>;
