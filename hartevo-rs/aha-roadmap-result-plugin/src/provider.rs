use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    AhaRateLimitReceipt, AhaRegistration, AhaResourceKind, AhaRoadmapAggregate, AhaRoadmapItem,
    AhaRoadmapOperation, AhaRoadmapRequest, AhaRoadmapScope, AhaTransportProvenance, Digest,
    MAX_ATTEMPTS, MAX_BACKOFF_SECONDS, MAX_ITEMS, MAX_PAGE_SIZE, MAX_RESPONSE_BYTES, ModelError,
    RegistrationRevocationReceipt, RegistrationState, Revision, SecretReference, canonical_digest,
    sha256_digest, validate_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AhaHttpMethod {
    Get,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AhaProviderRequest {
    pub method: AhaHttpMethod,
    pub host: String,
    pub path: String,
    pub operation: AhaRoadmapOperation,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub permission_digest: Digest,
    pub target_id_digest: Option<Digest>,
    pub page_token_digest: Option<Digest>,
    pub cursor_binding_digest: Option<Digest>,
    pub idempotency_key_digest: Digest,
    pub page_size: u16,
    pub attempt: u8,
    pub backoff_seconds: u32,
}

impl AhaProviderRequest {
    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        self.method == AhaHttpMethod::Get
            && self.host.starts_with("https://")
            && self.host.ends_with(".aha.io")
            && path_is_allowlisted(&self.path)
            && operation_path_is_consistent(self.operation, &self.path)
            && self.page_size > 0
            && self.page_size <= MAX_PAGE_SIZE
            && self.attempt > 0
            && self.attempt <= MAX_ATTEMPTS
            && self.backoff_seconds <= MAX_BACKOFF_SECONDS
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

fn path_is_allowlisted(path: &str) -> bool {
    if path == "/api/v1/account" {
        return true;
    }
    let segments: Vec<&str> = path.split('/').collect();
    match segments.len() {
        5 => {
            segments[0].is_empty()
                && segments[1] == "api"
                && segments[2] == "v1"
                && matches!(
                    segments[3],
                    "products" | "initiatives" | "releases" | "features" | "requirements"
                )
                && !segments[4].is_empty()
        }
        6 => {
            segments[0].is_empty()
                && segments[1] == "api"
                && segments[2] == "v1"
                && !segments[4].is_empty()
                && ((segments[3] == "products" && segments[5] == "initiatives")
                    || (segments[3] == "releases" && segments[5] == "features")
                    || (segments[3] == "features" && segments[5] == "requirements"))
        }
        _ => false,
    }
}

fn operation_path_is_consistent(operation: AhaRoadmapOperation, path: &str) -> bool {
    let segments: Vec<&str> = path.split('/').collect();
    match operation {
        AhaRoadmapOperation::AccountMetadata => path == "/api/v1/account",
        AhaRoadmapOperation::WorkspaceMetadata | AhaRoadmapOperation::ProductLineMetadata => {
            segments.len() == 5 && segments[3] == "products"
        }
        AhaRoadmapOperation::InitiativeMetadata => {
            segments.len() == 5 && segments[3] == "initiatives"
        }
        AhaRoadmapOperation::ReleaseMetadata => segments.len() == 5 && segments[3] == "releases",
        AhaRoadmapOperation::FeatureMetadata => segments.len() == 5 && segments[3] == "features",
        AhaRoadmapOperation::RequirementMetadata => {
            segments.len() == 5 && segments[3] == "requirements"
        }
        AhaRoadmapOperation::RoadmapAggregate => {
            segments.len() == 6 && segments[3] == "products" && segments[5] == "initiatives"
        }
    }
}

/// Raw bytes exist only at the deterministic transport boundary. The body is
/// never exposed through Debug, provider errors, evidence, or proposals.
#[derive(Clone, Eq, PartialEq)]
pub struct AhaResponse {
    status: u16,
    body: Vec<u8>,
    rate_limit: AhaRateLimitReceipt,
}

impl fmt::Debug for AhaResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AhaResponse")
            .field("status", &self.status)
            .field("body", &"<redacted>")
            .field("body_bytes", &self.body.len())
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

impl AhaResponse {
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>, rate_limit: AhaRateLimitReceipt) -> Self {
        Self {
            status,
            body,
            rate_limit,
        }
    }

    #[must_use]
    pub fn json<T: Serialize>(status: u16, value: &T) -> Self {
        Self::json_with_rate_limit(status, value, AhaRateLimitReceipt::default())
    }

    #[must_use]
    pub fn json_with_rate_limit<T: Serialize>(
        status: u16,
        value: &T,
        rate_limit: AhaRateLimitReceipt,
    ) -> Self {
        let body = serde_json::to_vec(value).expect("Aha fixture payload serializes");
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
    pub fn rate_limit(&self) -> &AhaRateLimitReceipt {
        &self.rate_limit
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AhaTransportError {
    #[error("Aha native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Aha transport timed out")]
    Timeout,
    #[error("Aha provider is unknown or unavailable")]
    ProviderUnknown,
    #[error("Aha transport returned a partial response")]
    Partial,
}

pub trait AhaTransport: fmt::Debug {
    fn provenance(&self) -> AhaTransportProvenance;

    fn execute(&mut self, request: &AhaProviderRequest) -> Result<AhaResponse, AhaTransportError>;
}

#[derive(Clone, Debug)]
pub struct FixtureAhaTransport {
    response: AhaResponse,
}

impl FixtureAhaTransport {
    #[must_use]
    pub const fn new(response: AhaResponse) -> Self {
        Self { response }
    }
}

impl AhaTransport for FixtureAhaTransport {
    fn provenance(&self) -> AhaTransportProvenance {
        AhaTransportProvenance::Fixture
    }

    fn execute(&mut self, _request: &AhaProviderRequest) -> Result<AhaResponse, AhaTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct RecordingAhaTransport {
    response: AhaResponse,
    requests: Vec<AhaProviderRequest>,
}

impl RecordingAhaTransport {
    #[must_use]
    pub const fn new(response: AhaResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[AhaProviderRequest] {
        &self.requests
    }
}

impl AhaTransport for RecordingAhaTransport {
    fn provenance(&self) -> AhaTransportProvenance {
        AhaTransportProvenance::Recording
    }

    fn execute(&mut self, request: &AhaProviderRequest) -> Result<AhaResponse, AhaTransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct FakeAhaTransport {
    responses: VecDeque<Result<AhaResponse, AhaTransportError>>,
    requests: Vec<AhaProviderRequest>,
}

impl FakeAhaTransport {
    #[must_use]
    pub fn new(response: AhaResponse) -> Self {
        let mut transport = Self::default();
        transport.push_response(response);
        transport
    }

    pub fn push_response(&mut self, response: AhaResponse) {
        self.responses.push_back(Ok(response));
    }

    pub fn push_error(&mut self, error: AhaTransportError) {
        self.responses.push_back(Err(error));
    }

    #[must_use]
    pub fn requests(&self) -> &[AhaProviderRequest] {
        &self.requests
    }
}

impl AhaTransport for FakeAhaTransport {
    fn provenance(&self) -> AhaTransportProvenance {
        AhaTransportProvenance::Fake
    }

    fn execute(&mut self, request: &AhaProviderRequest) -> Result<AhaResponse, AhaTransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or(Err(AhaTransportError::ProviderUnknown))
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackAhaTransport {
    response: AhaResponse,
}

impl LoopbackAhaTransport {
    #[must_use]
    pub const fn new(response: AhaResponse) -> Self {
        Self { response }
    }
}

impl AhaTransport for LoopbackAhaTransport {
    fn provenance(&self) -> AhaTransportProvenance {
        AhaTransportProvenance::Loopback
    }

    fn execute(&mut self, _request: &AhaProviderRequest) -> Result<AhaResponse, AhaTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAhaTransport;

impl AhaTransport for BlockedEnvAhaTransport {
    fn provenance(&self) -> AhaTransportProvenance {
        AhaTransportProvenance::BlockedEnv
    }

    fn execute(&mut self, _request: &AhaProviderRequest) -> Result<AhaResponse, AhaTransportError> {
        Err(AhaTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AhaProviderDefinition {
    pub provider_id: String,
    pub version: String,
    pub api_revision: String,
    pub documentation: String,
    pub provenance: AhaTransportProvenance,
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

impl AhaProviderDefinition {
    #[must_use]
    pub fn layer1(provenance: AhaTransportProvenance) -> Self {
        Self {
            provider_id: crate::AHA_PROVIDER_ID.to_owned(),
            version: crate::AHA_PROVIDER_VERSION.to_owned(),
            api_revision: crate::AHA_PROVIDER_API_REVISION.to_owned(),
            documentation: crate::AHA_API_DOCUMENTATION_URL.to_owned(),
            provenance,
            connected: false,
            native: false,
            first_party: false,
            read_allowlist: vec![
                "GET /api/v1/account".to_owned(),
                "GET /api/v1/products/{workspace_id}".to_owned(),
                "GET /api/v1/products/{product_line_id}".to_owned(),
                "GET /api/v1/products/{product_line_id}/initiatives".to_owned(),
                "GET /api/v1/initiatives/{initiative_id}".to_owned(),
                "GET /api/v1/releases/{release_id}".to_owned(),
                "GET /api/v1/releases/{release_id}/features".to_owned(),
                "GET /api/v1/features/{feature_id}".to_owned(),
                "GET /api/v1/features/{feature_id}/requirements".to_owned(),
                "GET /api/v1/requirements/{requirement_id}".to_owned(),
            ],
            max_requests_per_minute: crate::MAX_REQUESTS_PER_MINUTE,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_items: MAX_ITEMS,
            max_page_size: MAX_PAGE_SIZE,
            read_only: true,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.provider_id != crate::AHA_PROVIDER_ID
            || self.version != crate::AHA_PROVIDER_VERSION
            || self.api_revision != crate::AHA_PROVIDER_API_REVISION
            || self.documentation != crate::AHA_API_DOCUMENTATION_URL
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
pub enum AhaProviderError {
    #[error("Aha registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Aha API-token reference is revoked")]
    SecretRevoked,
    #[error("Aha provider request is invalid or outside the exact scope")]
    RequestInvalid,
    #[error("Aha provider response crossed the exact scope fence")]
    ScopeMismatch,
    #[error("Aha provider response crossed the revision fence")]
    RevisionMismatch,
    #[error("Aha provider response was malformed or tampered")]
    ResponseTampered {
        request_digest: Digest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: AhaRateLimitReceipt,
        status: Option<u16>,
    },
    #[error("Aha provider response exceeded the bounded response size")]
    ResponseTooLarge {
        request_digest: Digest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: AhaRateLimitReceipt,
    },
    #[error("Aha provider rate limit exhausted")]
    RateLimited {
        request_digest: Digest,
        response_digest: Option<Digest>,
        response_bytes: usize,
        rate_limit: AhaRateLimitReceipt,
        status: Option<u16>,
    },
    #[error("Aha provider request timed out")]
    Timeout {
        request_digest: Digest,
        response_digest: Option<Digest>,
        response_bytes: usize,
        rate_limit: AhaRateLimitReceipt,
    },
    #[error("Aha provider is unknown or unavailable")]
    ProviderUnknown {
        request_digest: Digest,
        response_digest: Option<Digest>,
        response_bytes: usize,
        rate_limit: AhaRateLimitReceipt,
        status: Option<u16>,
    },
    #[error("Aha native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv { request_digest: Digest },
    #[error("Aha transport returned a partial response")]
    Partial {
        request_digest: Digest,
        response_digest: Option<Digest>,
        response_bytes: usize,
        rate_limit: AhaRateLimitReceipt,
        status: Option<u16>,
    },
    #[error(transparent)]
    Model(#[from] ModelError),
}

impl AhaProviderError {
    #[must_use]
    pub fn request(&self) -> Option<&AhaProviderRequest> {
        None
    }

    #[must_use]
    pub fn metadata(&self) -> Option<(Digest, usize, AhaRateLimitReceipt, Option<u16>)> {
        match self {
            Self::ResponseTampered {
                response_digest,
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
            | Self::ProviderUnknown { request_digest, .. }
            | Self::BlockedEnv { request_digest }
            | Self::Partial { request_digest, .. } => Some(request_digest.clone()),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AhaProviderRead {
    pub aggregate: AhaRoadmapAggregate,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub rate_limit: AhaRateLimitReceipt,
    pub status: u16,
    pub provenance: AhaTransportProvenance,
}

pub struct AhaRoadmapProvider<T: AhaTransport> {
    scope: AhaRoadmapScope,
    secret_reference: SecretReference,
    transport: T,
    definition: AhaProviderDefinition,
    registration: AhaRegistration,
}

impl<T: AhaTransport> fmt::Debug for AhaRoadmapProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AhaRoadmapProvider")
            .field("scope", &self.scope)
            .field("secret_reference", &self.secret_reference)
            .field("transport", &self.transport)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .finish()
    }
}

impl<T: AhaTransport> AhaRoadmapProvider<T> {
    pub fn new(
        scope: AhaRoadmapScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, AhaProviderError> {
        scope.validate()?;
        let definition = AhaProviderDefinition::layer1(transport.provenance());
        definition.validate()?;
        let provider_digest = definition.provider_digest();
        let registration = AhaRegistration::bind(&scope, &secret_reference, provider_digest);
        Ok(Self {
            scope,
            secret_reference,
            transport,
            definition,
            registration,
        })
    }

    pub fn with_registration(
        scope: AhaRoadmapScope,
        secret_reference: SecretReference,
        transport: T,
        registration: AhaRegistration,
    ) -> Result<Self, AhaProviderError> {
        scope.validate()?;
        let definition = AhaProviderDefinition::layer1(transport.provenance());
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
    pub fn scope(&self) -> &AhaRoadmapScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &AhaProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    #[must_use]
    pub fn registration(&self) -> &AhaRegistration {
        &self.registration
    }

    #[must_use]
    pub fn transport_provenance(&self) -> AhaTransportProvenance {
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

    pub fn read(&mut self) -> Result<AhaProviderRead, AhaProviderError> {
        let key = crate::IdempotencyKey::new("aha-default-read")?;
        let request = AhaRoadmapRequest::roadmap(&self.scope, &key)?;
        self.read_request(&request)
    }

    pub fn read_request(
        &mut self,
        request: &AhaRoadmapRequest,
    ) -> Result<AhaProviderRead, AhaProviderError> {
        self.ensure_available()?;
        request
            .validate(&self.scope)
            .map_err(|_| AhaProviderError::RequestInvalid)?;
        if !self
            .scope
            .permissions()
            .has(request.operation().permission())
        {
            return Err(AhaProviderError::RequestInvalid);
        }
        let provider_request = self.provider_request(request);
        if !provider_request.is_allowlisted() {
            return Err(AhaProviderError::RequestInvalid);
        }
        let provenance = self.transport.provenance();
        let response = match self.transport.execute(&provider_request) {
            Ok(response) => response,
            Err(error) => return Err(Self::transport_error(&provider_request, error)),
        };
        response
            .rate_limit()
            .validate()
            .map_err(AhaProviderError::from)?;
        let request_digest = request.request_digest();
        let response_digest = response.response_digest();
        let response_bytes = response.response_bytes();
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(AhaProviderError::ResponseTooLarge {
                request_digest,
                response_digest,
                response_bytes,
                rate_limit: response.rate_limit().clone(),
            });
        }
        if response.status() == 429 {
            return Err(AhaProviderError::RateLimited {
                request_digest,
                response_digest: Some(response_digest),
                response_bytes,
                rate_limit: response.rate_limit().clone(),
                status: Some(response.status()),
            });
        }
        if response.status() == 408 || response.status() == 504 {
            return Err(AhaProviderError::Timeout {
                request_digest,
                response_digest: Some(response_digest),
                response_bytes,
                rate_limit: response.rate_limit().clone(),
            });
        }
        if !(200..300).contains(&response.status()) {
            return Err(AhaProviderError::ProviderUnknown {
                request_digest,
                response_digest: Some(response_digest),
                response_bytes,
                rate_limit: response.rate_limit().clone(),
                status: Some(response.status()),
            });
        }
        let value: Value = serde_json::from_slice(&response.body).map_err(|_| {
            AhaProviderError::ResponseTampered {
                request_digest: request_digest.clone(),
                response_digest: response_digest.clone(),
                response_bytes,
                rate_limit: response.rate_limit().clone(),
                status: Some(response.status()),
            }
        })?;
        let aggregate = self.aggregate_from_value(request, &value, response.status(), &response)?;
        Ok(AhaProviderRead {
            aggregate,
            response_digest,
            response_bytes,
            rate_limit: response.rate_limit().clone(),
            status: response.status(),
            provenance,
        })
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocationReceipt, AhaProviderError> {
        self.registration.revoke().map_err(AhaProviderError::from)
    }

    pub fn restore(&mut self) -> Result<(), AhaProviderError> {
        self.registration.restore().map_err(AhaProviderError::from)
    }

    pub fn revoke_secret(&mut self) -> Result<(), AhaProviderError> {
        self.secret_reference
            .revoke()
            .map_err(AhaProviderError::from)
    }

    pub fn restore_secret(&mut self) -> Result<(), AhaProviderError> {
        self.secret_reference
            .restore()
            .map_err(AhaProviderError::from)
    }

    fn ensure_available(&self) -> Result<(), AhaProviderError> {
        self.definition.validate()?;
        if self.registration.state != RegistrationState::Active {
            return Err(AhaProviderError::RegistrationRevoked);
        }
        self.registration
            .validate(&self.scope, &self.secret_reference, &self.provider_digest())
            .map_err(|_| AhaProviderError::RegistrationRevoked)?;
        if self.secret_reference.is_revoked() {
            return Err(AhaProviderError::SecretRevoked);
        }
        Ok(())
    }

    fn provider_request(&self, request: &AhaRoadmapRequest) -> AhaProviderRequest {
        let path = match request.operation() {
            AhaRoadmapOperation::AccountMetadata => "/api/v1/account".to_owned(),
            AhaRoadmapOperation::WorkspaceMetadata => {
                format!("/api/v1/products/{}", self.scope.workspace().as_str())
            }
            AhaRoadmapOperation::ProductLineMetadata => {
                format!("/api/v1/products/{}", self.scope.product_line().as_str())
            }
            AhaRoadmapOperation::InitiativeMetadata => {
                format!("/api/v1/initiatives/{}", self.scope.initiative().as_str())
            }
            AhaRoadmapOperation::ReleaseMetadata => {
                format!("/api/v1/releases/{}", self.scope.release().as_str())
            }
            AhaRoadmapOperation::FeatureMetadata => {
                format!("/api/v1/features/{}", self.scope.feature().as_str())
            }
            AhaRoadmapOperation::RequirementMetadata => {
                format!("/api/v1/requirements/{}", self.scope.requirement().as_str())
            }
            AhaRoadmapOperation::RoadmapAggregate => format!(
                "/api/v1/products/{}/initiatives",
                self.scope.product_line().as_str()
            ),
        };
        AhaProviderRequest {
            method: AhaHttpMethod::Get,
            host: format!("https://{}.aha.io", self.scope.account().as_str()),
            path,
            operation: request.operation(),
            scope_digest: request.scope_digest().clone(),
            revision_digest: request.revision_digest().clone(),
            permission_digest: request.permission_digest().clone(),
            target_id_digest: request.target_id_digest().cloned(),
            page_token_digest: request.page_token_digest().cloned(),
            cursor_binding_digest: request.cursor_binding().cloned(),
            idempotency_key_digest: request.idempotency_key_digest().clone(),
            page_size: request.page_size(),
            attempt: 1,
            backoff_seconds: 0,
        }
    }

    fn transport_error(request: &AhaProviderRequest, error: AhaTransportError) -> AhaProviderError {
        let request_digest = canonical_digest(request);
        match error {
            AhaTransportError::BlockedEnv => AhaProviderError::BlockedEnv { request_digest },
            AhaTransportError::Timeout => AhaProviderError::Timeout {
                request_digest,
                response_digest: None,
                response_bytes: 0,
                rate_limit: AhaRateLimitReceipt::default(),
            },
            AhaTransportError::ProviderUnknown => AhaProviderError::ProviderUnknown {
                request_digest,
                response_digest: None,
                response_bytes: 0,
                rate_limit: AhaRateLimitReceipt::default(),
                status: None,
            },
            AhaTransportError::Partial => AhaProviderError::Partial {
                request_digest,
                response_digest: None,
                response_bytes: 0,
                rate_limit: AhaRateLimitReceipt::default(),
                status: None,
            },
        }
    }

    fn aggregate_from_value(
        &self,
        request: &AhaRoadmapRequest,
        value: &Value,
        status: u16,
        response: &AhaResponse,
    ) -> Result<AhaRoadmapAggregate, AhaProviderError> {
        let raw_items = extract_items(value, request.operation());
        let mut items = Vec::new();
        for raw_item in raw_items.iter().take(MAX_ITEMS + 1) {
            self.validate_scope_fields(raw_item)?;
            let item = self.item_from_value(request, raw_item)?;
            items.push(item);
        }
        if items.len() > MAX_ITEMS {
            return Err(AhaProviderError::ResponseTampered {
                request_digest: request.request_digest(),
                response_digest: response.response_digest(),
                response_bytes: response.response_bytes(),
                rate_limit: response.rate_limit().clone(),
                status: Some(status),
            });
        }
        if !request.operation().is_collection() && items.len() != 1 {
            return Err(AhaProviderError::ResponseTampered {
                request_digest: request.request_digest(),
                response_digest: response.response_digest(),
                response_bytes: response.response_bytes(),
                rate_limit: response.rate_limit().clone(),
                status: Some(status),
            });
        }
        if let Some(expected_target) = request.target_id_digest() {
            if items
                .first()
                .is_none_or(|item| &item.id_digest != expected_target)
            {
                return Err(AhaProviderError::ScopeMismatch);
            }
        }
        let partial = status == 206
            || value
                .get("partial")
                .and_then(Value::as_bool)
                .unwrap_or(false);
        let total_count = value
            .get("total")
            .or_else(|| value.get("total_count"))
            .and_then(value_as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(items.len() as u32);
        let next_page_token = value
            .get("next_page_token")
            .or_else(|| value.get("nextPageToken"))
            .and_then(Value::as_str);
        let (next_page_token_digest, cursor_binding_digest) = match next_page_token {
            Some(token) => (
                Some(sha256_digest(
                    format!("aha-page-token/v1|{token}").as_bytes(),
                )),
                Some(request.cursor_binding_digest()),
            ),
            None => (None, None),
        };
        AhaRoadmapAggregate::new(
            request.operation(),
            items,
            total_count,
            partial,
            request.target_id_digest().cloned(),
            next_page_token_digest,
            cursor_binding_digest,
        )
        .map_err(AhaProviderError::from)
    }

    fn item_from_value(
        &self,
        request: &AhaRoadmapRequest,
        value: &Value,
    ) -> Result<AhaRoadmapItem, AhaProviderError> {
        let kind = value
            .get("kind")
            .and_then(Value::as_str)
            .and_then(parse_resource_kind)
            .unwrap_or_else(|| request.operation().resource_kind());
        let id = value
            .get("id")
            .or_else(|| value.get("reference_num"))
            .or_else(|| value.get("referenceNumber"))
            .and_then(Value::as_str);
        let id_digest = match id {
            Some(id) => canonical_digest(&id),
            None => request
                .target_id_digest()
                .cloned()
                .ok_or(AhaProviderError::ScopeMismatch)?,
        };
        let expected_target = request.target_id_digest();
        if expected_target.is_some_and(|expected| expected != &id_digest) {
            return Err(AhaProviderError::ScopeMismatch);
        }
        let title_digest = value
            .get("name")
            .or_else(|| value.get("title"))
            .and_then(Value::as_str)
            .map(|title| sha256_digest(format!("aha-title/v1|{title}").as_bytes()));
        let status_digest = value
            .get("status")
            .and_then(|status| {
                status
                    .as_str()
                    .or_else(|| status.get("name").and_then(Value::as_str))
            })
            .map(|status| sha256_digest(format!("aha-status/v1|{status}").as_bytes()));
        let child_count = value
            .get("children")
            .and_then(Value::as_array)
            .map_or(0, |children| {
                u16::try_from(children.len()).unwrap_or(u16::MAX)
            });
        let source_revision = value
            .get("revision")
            .or_else(|| value.get("version"))
            .and_then(value_as_u64)
            .unwrap_or_else(|| self.scope.scope_revision().get());
        if source_revision != self.scope.scope_revision().get() {
            return Err(AhaProviderError::RevisionMismatch);
        }
        AhaRoadmapItem::new(
            kind,
            id_digest,
            title_digest,
            status_digest,
            child_count,
            Revision::new(source_revision).map_err(AhaProviderError::from)?,
        )
        .map_err(AhaProviderError::from)
    }

    fn validate_scope_fields(&self, value: &Value) -> Result<(), AhaProviderError> {
        let exact_bindings = [
            ("account_id", self.scope.account().digest()),
            ("accountId", self.scope.account().digest()),
            ("workspace_id", self.scope.workspace().digest()),
            ("workspaceId", self.scope.workspace().digest()),
            ("product_line_id", self.scope.product_line().digest()),
            ("productLineId", self.scope.product_line().digest()),
            ("initiative_id", self.scope.initiative().digest()),
            ("initiativeId", self.scope.initiative().digest()),
            ("release_id", self.scope.release().digest()),
            ("releaseId", self.scope.release().digest()),
            ("feature_id", self.scope.feature().digest()),
            ("featureId", self.scope.feature().digest()),
            ("requirement_id", self.scope.requirement().digest()),
            ("requirementId", self.scope.requirement().digest()),
        ];
        for (field, expected_digest) in exact_bindings {
            if let Some(value) = value.get(field) {
                let Some(value) = value.as_str() else {
                    return Err(AhaProviderError::ScopeMismatch);
                };
                if canonical_digest(&value) != expected_digest {
                    return Err(AhaProviderError::ScopeMismatch);
                }
            }
        }
        for field in ["product_id", "productId"] {
            if let Some(value) = value.get(field) {
                let Some(value) = value.as_str() else {
                    return Err(AhaProviderError::ScopeMismatch);
                };
                let digest = canonical_digest(&value);
                if digest != self.scope.workspace().digest()
                    && digest != self.scope.product_line().digest()
                {
                    return Err(AhaProviderError::ScopeMismatch);
                }
            }
        }
        Ok(())
    }
}

fn value_as_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse::<u64>().ok()))
}

fn extract_items(value: &Value, operation: AhaRoadmapOperation) -> Vec<&Value> {
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        return items.iter().collect();
    }
    if operation.is_collection() {
        for key in [
            "initiatives",
            "products",
            "releases",
            "features",
            "requirements",
        ] {
            if let Some(items) = value.get(key).and_then(Value::as_array) {
                return items.iter().collect();
            }
        }
    }
    if value.is_object() {
        vec![value]
    } else {
        Vec::new()
    }
}

fn parse_resource_kind(value: &str) -> Option<AhaResourceKind> {
    match value {
        "account" => Some(AhaResourceKind::Account),
        "workspace" => Some(AhaResourceKind::Workspace),
        "product_line" | "productLine" => Some(AhaResourceKind::ProductLine),
        "initiative" => Some(AhaResourceKind::Initiative),
        "release" => Some(AhaResourceKind::Release),
        "feature" => Some(AhaResourceKind::Feature),
        "requirement" => Some(AhaResourceKind::Requirement),
        _ => None,
    }
}

pub type AhaRoadmapProviderRequest = AhaProviderRequest;
pub type AhaHttpResponse = AhaResponse;
pub type AhaRoadmapResponse = AhaResponse;
pub type FixtureAhaRoadmapTransport = FixtureAhaTransport;
pub type RecordingAhaRoadmapTransport = RecordingAhaTransport;
pub type LoopbackAhaRoadmapTransport = LoopbackAhaTransport;
pub type BlockedEnvAhaRoadmapTransport = BlockedEnvAhaTransport;
