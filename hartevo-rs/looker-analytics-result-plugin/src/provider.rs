use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    Digest, EvidenceClassification, IdempotencyKey, LookerAnalyticsRequest, LookerAnalyticsScope,
    LookerMetadataAggregate, LookerMetadataItem, LookerOperation, LookerRateLimitReceipt,
    LookerRegistration, LookerResourceKind, LookerSearchKind, LookerTransportProvenance, MAX_ITEMS,
    MAX_REQUESTS_PER_MINUTE, MAX_RESPONSE_BYTES, ModelError, RegistrationState, Revision,
    SecretReference, canonical_digest, sha256_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LookerHttpMethod {
    Get,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LookerProviderRequest {
    pub method: LookerHttpMethod,
    pub host: String,
    pub path: String,
    pub operation: LookerOperation,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub target_id_digest: Option<Digest>,
    pub search_digest: Option<Digest>,
    pub page_token_digest: Option<Digest>,
    pub idempotency_key_digest: Digest,
    pub page_size: u16,
}

impl LookerProviderRequest {
    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        self.method == LookerHttpMethod::Get
            && (self.path.starts_with("/dashboards/")
                || self.path.starts_with("/looks/")
                || self.path.starts_with("/folders/")
                || self.path.starts_with("/content/")
                || self.path.starts_with("/queries/")
                || self.path.starts_with("/lookml_models/"))
            && !self.path.contains("run")
            && !self.path.contains("sql_runner")
            && !self.path.contains("scheduled")
            && self.page_size > 0
            && self.page_size <= crate::MAX_PAGE_SIZE
    }
}

/// Raw bytes exist only at this transport boundary. Debug output, errors,
/// provider reads, evidence, and proposals never expose the response body.
#[derive(Clone, Eq, PartialEq)]
pub struct LookerResponse {
    status: u16,
    body: Vec<u8>,
    rate_limit: LookerRateLimitReceipt,
}

impl fmt::Debug for LookerResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LookerResponse")
            .field("status", &self.status)
            .field("body", &"<redacted>")
            .field("body_bytes", &self.body.len())
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

impl LookerResponse {
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>, rate_limit: LookerRateLimitReceipt) -> Self {
        Self {
            status,
            body,
            rate_limit,
        }
    }

    #[must_use]
    pub fn json<T: Serialize>(status: u16, value: &T) -> Self {
        Self::json_with_rate_limit(status, value, LookerRateLimitReceipt::default())
    }

    #[must_use]
    pub fn json_with_rate_limit<T: Serialize>(
        status: u16,
        value: &T,
        rate_limit: LookerRateLimitReceipt,
    ) -> Self {
        let body = serde_json::to_vec(value).expect("Looker fixture payload serializes");
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
    pub fn rate_limit(&self) -> &LookerRateLimitReceipt {
        &self.rate_limit
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LookerTransportError {
    #[error("Looker native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Looker transport timed out")]
    Timeout,
    #[error("Looker access was denied or the session was unavailable")]
    AccessLost,
    #[error("Looker returned a partial transport response")]
    Partial,
    #[error("Looker provider returned an unknown transport failure")]
    ProviderUnknown,
}

pub trait LookerTransport: fmt::Debug {
    fn provenance(&self) -> LookerTransportProvenance;

    fn execute(
        &mut self,
        request: &LookerProviderRequest,
    ) -> Result<LookerResponse, LookerTransportError>;
}

#[derive(Clone, Debug)]
pub struct FixtureLookerTransport {
    response: LookerResponse,
}

impl FixtureLookerTransport {
    #[must_use]
    pub const fn new(response: LookerResponse) -> Self {
        Self { response }
    }
}

impl LookerTransport for FixtureLookerTransport {
    fn provenance(&self) -> LookerTransportProvenance {
        LookerTransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        _request: &LookerProviderRequest,
    ) -> Result<LookerResponse, LookerTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct RecordingLookerTransport {
    response: LookerResponse,
    requests: Vec<LookerProviderRequest>,
}

impl RecordingLookerTransport {
    #[must_use]
    pub const fn new(response: LookerResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[LookerProviderRequest] {
        &self.requests
    }
}

impl LookerTransport for RecordingLookerTransport {
    fn provenance(&self) -> LookerTransportProvenance {
        LookerTransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &LookerProviderRequest,
    ) -> Result<LookerResponse, LookerTransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct FakeLookerTransport {
    responses: VecDeque<Result<LookerResponse, LookerTransportError>>,
    requests: Vec<LookerProviderRequest>,
}

impl FakeLookerTransport {
    #[must_use]
    pub fn new(response: LookerResponse) -> Self {
        let mut transport = Self::default();
        transport.push_response(response);
        transport
    }

    pub fn push_response(&mut self, response: LookerResponse) {
        self.responses.push_back(Ok(response));
    }

    pub fn push_error(&mut self, error: LookerTransportError) {
        self.responses.push_back(Err(error));
    }

    #[must_use]
    pub fn requests(&self) -> &[LookerProviderRequest] {
        &self.requests
    }
}

impl LookerTransport for FakeLookerTransport {
    fn provenance(&self) -> LookerTransportProvenance {
        LookerTransportProvenance::Fake
    }

    fn execute(
        &mut self,
        request: &LookerProviderRequest,
    ) -> Result<LookerResponse, LookerTransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or(Err(LookerTransportError::ProviderUnknown))
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackLookerTransport {
    response: LookerResponse,
}

impl LoopbackLookerTransport {
    #[must_use]
    pub const fn new(response: LookerResponse) -> Self {
        Self { response }
    }
}

impl LookerTransport for LoopbackLookerTransport {
    fn provenance(&self) -> LookerTransportProvenance {
        LookerTransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        _request: &LookerProviderRequest,
    ) -> Result<LookerResponse, LookerTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvLookerTransport;

impl LookerTransport for BlockedEnvLookerTransport {
    fn provenance(&self) -> LookerTransportProvenance {
        LookerTransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &LookerProviderRequest,
    ) -> Result<LookerResponse, LookerTransportError> {
        Err(LookerTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LookerProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub documentation_url: String,
    pub capability_digest: Digest,
    pub provenance: LookerTransportProvenance,
    pub max_requests_per_minute: u16,
    pub max_response_bytes: usize,
    pub max_items: usize,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

impl LookerProviderDefinition {
    #[must_use]
    pub fn layer1(provenance: LookerTransportProvenance) -> Self {
        let capability_digest = canonical_digest(&(
            crate::LOOKER_ANALYTICS_RESULT_SCHEMA_VERSION,
            crate::LOOKER_PROVIDER_ID,
            crate::LOOKER_PROVIDER_API_REVISION,
            "get_dashboard_metadata",
            "get_look_metadata",
            "get_folder_metadata",
            "get_query_metadata",
            "get_model_explore_metadata",
            "search_dashboard_look_content_metadata",
            "aggregate_only",
        ));
        Self {
            schema_version: crate::LOOKER_ANALYTICS_RESULT_SCHEMA_VERSION.to_owned(),
            provider_id: crate::LOOKER_PROVIDER_ID.to_owned(),
            provider_version: crate::LOOKER_PROVIDER_VERSION.to_owned(),
            api_revision: crate::LOOKER_PROVIDER_API_REVISION.to_owned(),
            documentation_url: crate::LOOKER_API_DOCUMENTATION_URL.to_owned(),
            capability_digest,
            provenance,
            max_requests_per_minute: MAX_REQUESTS_PER_MINUTE,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_items: MAX_ITEMS,
            read_only: true,
            native: false,
            connected: false,
            first_party: false,
        }
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LookerProviderError {
    #[error("Looker registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Looker client-secret reference is revoked")]
    SecretRevoked,
    #[error("Looker consent is revoked or stale")]
    ConsentRevoked,
    #[error("Looker permission snapshot does not allow this operation")]
    PermissionDenied,
    #[error("Looker request is outside the exact registered scope")]
    ScopeMismatch,
    #[error("Looker request rate bound was exhausted")]
    RateLimited {
        request: LookerProviderRequest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: LookerRateLimitReceipt,
    },
    #[error("Looker returned HTTP status {status_code}")]
    HttpStatus {
        request: LookerProviderRequest,
        status_code: u16,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: LookerRateLimitReceipt,
    },
    #[error("Looker response exceeded the Layer-1 response bound")]
    ResponseTooLarge {
        request: LookerProviderRequest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: LookerRateLimitReceipt,
    },
    #[error("Looker response was malformed or outside metadata bounds")]
    MalformedResponse {
        request: LookerProviderRequest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: LookerRateLimitReceipt,
    },
    #[error("Looker rate-limit receipt is invalid")]
    InvalidRateLimitReceipt { request: LookerProviderRequest },
    #[error("Looker response failed the scope or revision fence")]
    ResponseTamper {
        request: LookerProviderRequest,
        response_digest: Digest,
        response_bytes: usize,
    },
    #[error("Looker transport failed")]
    Transport {
        request: LookerProviderRequest,
        error: LookerTransportError,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: LookerRateLimitReceipt,
    },
    #[error(transparent)]
    Model(#[from] ModelError),
}

impl LookerProviderError {
    #[must_use]
    pub fn request(&self) -> Option<&LookerProviderRequest> {
        match self {
            Self::RegistrationRevoked
            | Self::SecretRevoked
            | Self::ConsentRevoked
            | Self::PermissionDenied
            | Self::ScopeMismatch
            | Self::InvalidRateLimitReceipt { .. }
            | Self::Model(_) => None,
            Self::RateLimited { request, .. }
            | Self::HttpStatus { request, .. }
            | Self::ResponseTooLarge { request, .. }
            | Self::MalformedResponse { request, .. }
            | Self::ResponseTamper { request, .. }
            | Self::Transport { request, .. } => Some(request),
        }
    }

    #[must_use]
    pub fn metadata(&self) -> Option<(Digest, usize, LookerRateLimitReceipt, Option<u16>)> {
        match self {
            Self::RateLimited {
                response_digest,
                response_bytes,
                rate_limit,
                ..
            } => Some((
                response_digest.clone(),
                *response_bytes,
                rate_limit.clone(),
                Some(429),
            )),
            Self::HttpStatus {
                status_code,
                response_digest,
                response_bytes,
                rate_limit,
                ..
            } => Some((
                response_digest.clone(),
                *response_bytes,
                rate_limit.clone(),
                Some(*status_code),
            )),
            Self::ResponseTooLarge {
                response_digest,
                response_bytes,
                rate_limit,
                ..
            }
            | Self::MalformedResponse {
                response_digest,
                response_bytes,
                rate_limit,
                ..
            }
            | Self::Transport {
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
            Self::ResponseTamper {
                response_digest,
                response_bytes,
                ..
            } => Some((
                response_digest.clone(),
                *response_bytes,
                LookerRateLimitReceipt::default(),
                None,
            )),
            Self::InvalidRateLimitReceipt { .. }
            | Self::RegistrationRevoked
            | Self::SecretRevoked
            | Self::ConsentRevoked
            | Self::PermissionDenied
            | Self::ScopeMismatch
            | Self::Model(_) => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LookerProviderRead {
    pub request: LookerProviderRequest,
    pub aggregate: LookerMetadataAggregate,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub rate_limit: LookerRateLimitReceipt,
    pub provenance: LookerTransportProvenance,
    pub classification: EvidenceClassification,
}

/// Layer-1 typed provider for bounded Looker metadata reads. It has no HTTP
/// client and cannot run a query, return warehouse rows, or mutate content.
pub struct LookerProvider<T: LookerTransport> {
    scope: LookerAnalyticsScope,
    secret_reference: SecretReference,
    transport: T,
    definition: LookerProviderDefinition,
    registration: LookerRegistration,
    requests_issued: u16,
}

impl<T: LookerTransport> fmt::Debug for LookerProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LookerProvider")
            .field("scope_digest", self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("transport_provenance", &self.definition.provenance)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .field("requests_issued", &self.requests_issued)
            .finish_non_exhaustive()
    }
}

impl<T: LookerTransport> LookerProvider<T> {
    pub fn new(
        scope: LookerAnalyticsScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, LookerProviderError> {
        scope.validate()?;
        if secret_reference.is_revoked() {
            return Err(LookerProviderError::SecretRevoked);
        }
        let definition = LookerProviderDefinition::layer1(transport.provenance());
        let registration =
            LookerRegistration::bind(&scope, &secret_reference, definition.provider_digest());
        Ok(Self {
            scope,
            secret_reference,
            transport,
            definition,
            registration,
            requests_issued: 0,
        })
    }

    pub fn with_registration(
        scope: LookerAnalyticsScope,
        secret_reference: SecretReference,
        transport: T,
        registration: LookerRegistration,
    ) -> Result<Self, LookerProviderError> {
        scope.validate()?;
        let definition = LookerProviderDefinition::layer1(transport.provenance());
        registration
            .validate(&scope, &secret_reference, &definition.provider_digest())
            .map_err(|_| LookerProviderError::ScopeMismatch)?;
        Ok(Self {
            scope,
            secret_reference,
            transport,
            definition,
            registration,
            requests_issued: 0,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &LookerAnalyticsScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &LookerProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    #[must_use]
    pub fn registration(&self) -> &LookerRegistration {
        &self.registration
    }

    #[must_use]
    pub fn transport_provenance(&self) -> LookerTransportProvenance {
        self.definition.provenance
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(&mut self) -> Result<LookerProviderRead, LookerProviderError> {
        let key = IdempotencyKey::from_digest(sha256_digest(
            format!("looker-default-read|{}", self.scope.scope_digest()).as_bytes(),
        ))?;
        let request = LookerAnalyticsRequest::aggregate_metadata(&self.scope, &key)?;
        self.read_request(&request)
    }

    pub fn read_request(
        &mut self,
        request: &LookerAnalyticsRequest,
    ) -> Result<LookerProviderRead, LookerProviderError> {
        request.validate(&self.scope)?;
        self.ensure_ready(request.operation())?;
        let provider_request = self.build_request(request)?;
        if !provider_request.is_allowlisted() {
            return Err(LookerProviderError::ScopeMismatch);
        }
        if self.requests_issued >= self.definition.max_requests_per_minute {
            return Err(LookerProviderError::RateLimited {
                request: provider_request,
                response_digest: sha256_digest(b"looker-request-rate-budget"),
                response_bytes: 0,
                rate_limit: LookerRateLimitReceipt::new(
                    self.definition.max_requests_per_minute,
                    Some(0),
                    Some(60),
                    true,
                )
                .expect("bounded rate receipt"),
            });
        }
        self.requests_issued = self.requests_issued.saturating_add(1);
        let provenance = self.definition.provenance;
        let response = match self.transport.execute(&provider_request) {
            Ok(response) => response,
            Err(error) => {
                return Err(LookerProviderError::Transport {
                    request: provider_request,
                    error,
                    response_digest: sha256_digest(b"looker-transport-no-response"),
                    response_bytes: 0,
                    rate_limit: LookerRateLimitReceipt::default(),
                });
            }
        };
        if response.rate_limit().validate().is_err()
            || response.rate_limit().limit_per_minute > self.definition.max_requests_per_minute
        {
            return Err(LookerProviderError::InvalidRateLimitReceipt {
                request: provider_request,
            });
        }
        let response_digest = response.response_digest();
        let response_bytes = response.response_bytes();
        let rate_limit = response.rate_limit().clone();
        if rate_limit.exhausted {
            return Err(LookerProviderError::RateLimited {
                request: provider_request,
                response_digest,
                response_bytes,
                rate_limit,
            });
        }
        if !(200..=299).contains(&response.status()) {
            return Err(LookerProviderError::HttpStatus {
                request: provider_request,
                status_code: response.status(),
                response_digest,
                response_bytes,
                rate_limit,
            });
        }
        if response_bytes > self.definition.max_response_bytes {
            return Err(LookerProviderError::ResponseTooLarge {
                request: provider_request,
                response_digest,
                response_bytes,
                rate_limit,
            });
        }
        let payload: Value = match serde_json::from_slice(response.body.as_slice()) {
            Ok(payload) => payload,
            Err(_) => {
                return Err(LookerProviderError::MalformedResponse {
                    request: provider_request,
                    response_digest,
                    response_bytes,
                    rate_limit,
                });
            }
        };
        let aggregate = match normalize_metadata(&payload, request, &self.scope) {
            Ok(aggregate) => aggregate,
            Err(NormalizationFailure::Scope) => {
                return Err(LookerProviderError::ResponseTamper {
                    request: provider_request,
                    response_digest,
                    response_bytes,
                });
            }
            Err(NormalizationFailure::Malformed) => {
                return Err(LookerProviderError::MalformedResponse {
                    request: provider_request,
                    response_digest,
                    response_bytes,
                    rate_limit,
                });
            }
        };
        let partial = response.status() == 206 || aggregate.partial;
        let aggregate = aggregate.with_partial(partial);
        let normalized_digest =
            canonical_digest(&("looker-normalized-response/v1", &aggregate, &rate_limit));
        Ok(LookerProviderRead {
            request: provider_request,
            aggregate,
            response_digest: normalized_digest,
            response_bytes: serde_json::to_vec(&payload)
                .map_or(response_bytes, |bytes| bytes.len()),
            rate_limit,
            provenance,
            classification: provenance.into(),
        })
    }

    pub fn revoke(&mut self) -> Result<crate::RegistrationRevocationReceipt, LookerProviderError> {
        self.registration
            .revoke()
            .map_err(LookerProviderError::Model)
    }

    pub fn restore(&mut self) -> Result<(), LookerProviderError> {
        self.registration
            .restore()
            .map_err(LookerProviderError::Model)
    }

    pub fn revoke_secret(&mut self) -> Result<(), LookerProviderError> {
        self.secret_reference
            .revoke()
            .map_err(LookerProviderError::Model)
    }

    fn ensure_ready(&self, operation: LookerOperation) -> Result<(), LookerProviderError> {
        if self.registration.state != RegistrationState::Active {
            return Err(LookerProviderError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(LookerProviderError::SecretRevoked);
        }
        if !self.scope.consent().is_active() {
            return Err(LookerProviderError::ConsentRevoked);
        }
        if !self.scope.permissions().has(operation.permission()) {
            return Err(LookerProviderError::PermissionDenied);
        }
        self.registration
            .validate(&self.scope, &self.secret_reference, &self.provider_digest())
            .map_err(|_| LookerProviderError::RegistrationRevoked)
    }

    fn build_request(
        &self,
        request: &LookerAnalyticsRequest,
    ) -> Result<LookerProviderRequest, LookerProviderError> {
        let path = match request.operation() {
            LookerOperation::DashboardMetadata => format!(
                "/dashboards/{}",
                self.scope
                    .dashboard()
                    .ok_or(LookerProviderError::ScopeMismatch)?
                    .as_str()
            ),
            LookerOperation::LookMetadata => format!(
                "/looks/{}",
                self.scope
                    .look()
                    .ok_or(LookerProviderError::ScopeMismatch)?
                    .as_str()
            ),
            LookerOperation::FolderMetadata => format!(
                "/folders/{}",
                self.scope
                    .folder()
                    .ok_or(LookerProviderError::ScopeMismatch)?
                    .as_str()
            ),
            LookerOperation::QueryMetadata => format!(
                "/queries/{}",
                self.scope
                    .query()
                    .ok_or(LookerProviderError::ScopeMismatch)?
                    .as_str()
            ),
            LookerOperation::ModelMetadata => {
                format!("/lookml_models/{}", self.scope.model().as_str())
            }
            LookerOperation::ExploreMetadata => format!(
                "/lookml_models/{}/explores/{}",
                self.scope.model().as_str(),
                self.scope.explore().as_str()
            ),
            LookerOperation::SearchDashboards => "/dashboards/search".to_owned(),
            LookerOperation::SearchLooks => "/looks/search".to_owned(),
            LookerOperation::SearchContent | LookerOperation::AggregateMetadata => {
                "/content/search".to_owned()
            }
        };
        Ok(LookerProviderRequest {
            method: LookerHttpMethod::Get,
            host: self.scope.instance().host().to_owned(),
            path,
            operation: request.operation(),
            scope_digest: request.scope_digest().clone(),
            revision_digest: request.revision_digest().clone(),
            target_id_digest: request.target_id_digest().cloned(),
            search_digest: request.search_digest().cloned(),
            page_token_digest: request.page_token_digest().cloned(),
            idempotency_key_digest: request.idempotency_key_digest().clone(),
            page_size: request.page_size(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NormalizationFailure {
    Scope,
    Malformed,
}

fn normalize_metadata(
    payload: &Value,
    request: &LookerAnalyticsRequest,
    scope: &LookerAnalyticsScope,
) -> Result<LookerMetadataAggregate, NormalizationFailure> {
    let records = records(payload, request.operation());
    if records.len() > MAX_ITEMS {
        return Err(NormalizationFailure::Malformed);
    }
    let mut items = Vec::with_capacity(records.len());
    let mut source_revision: Option<Revision> = None;
    for (index, record) in records.iter().enumerate() {
        let object = record.as_object().ok_or(NormalizationFailure::Malformed)?;
        if !matches_scope(object, request, scope) {
            return Err(NormalizationFailure::Scope);
        }
        let id =
            extract_id(object, request.operation()).unwrap_or_else(|| format!("missing-{index}"));
        let id_digest = metadata_id_digest(&id);
        if request
            .target_id_digest()
            .is_some_and(|expected| expected != &id_digest)
        {
            return Err(NormalizationFailure::Scope);
        }
        let name_digest = extract_name(object)
            .map(|name| sha256_digest(format!("looker-metadata-name/v1|{name}").as_bytes()));
        let item_revision = extract_revision(object).unwrap_or(scope.scope_revision().get());
        let item_revision =
            Revision::new(item_revision).map_err(|_| NormalizationFailure::Malformed)?;
        if item_revision != scope.scope_revision() {
            return Err(NormalizationFailure::Scope);
        }
        if let Some(previous) = source_revision {
            if previous != item_revision {
                return Err(NormalizationFailure::Scope);
            }
        } else {
            source_revision = Some(item_revision);
        }
        items.push(
            LookerMetadataItem::new(
                request.operation().resource_kind(),
                id_digest,
                name_digest,
                bounded_count(object, &["child_count", "children"]),
                bounded_count(object, &["field_count", "fields", "dashboard_elements"]),
                item_revision,
            )
            .map_err(|_| NormalizationFailure::Malformed)?,
        );
    }
    let total_count = numeric_count(payload).unwrap_or(items.len() as u32);
    if total_count < items.len() as u32 {
        return Err(NormalizationFailure::Malformed);
    }
    let partial = payload
        .get("partial")
        .and_then(Value::as_bool)
        .or_else(|| {
            payload
                .get("complete")
                .and_then(Value::as_bool)
                .map(|value| !value)
        })
        .unwrap_or(false);
    LookerMetadataAggregate::new(
        request.operation(),
        items,
        total_count,
        partial,
        scope.date_window().digest(),
        payload
            .get("next_page_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .map(|token| sha256_digest(format!("looker-page-token/v1|{token}").as_bytes())),
    )
    .map_err(|_| NormalizationFailure::Malformed)
}

fn records(payload: &Value, operation: LookerOperation) -> Vec<&Value> {
    if let Some(items) = payload.get("items").and_then(Value::as_array) {
        return items.iter().collect();
    }
    if let Some(array) = payload.as_array() {
        return array.iter().collect();
    }
    if let Some(key) = operation.search_kind().map(search_key) {
        if let Some(items) = payload.get(key).and_then(Value::as_array) {
            return items.iter().collect();
        }
    }
    vec![payload]
}

const fn search_key(kind: LookerSearchKind) -> &'static str {
    match kind {
        LookerSearchKind::Dashboards => "dashboards",
        LookerSearchKind::Looks => "looks",
        LookerSearchKind::Content => "content",
    }
}

fn extract_id(
    object: &serde_json::Map<String, Value>,
    operation: LookerOperation,
) -> Option<String> {
    let keys: &[&str] = match operation.resource_kind() {
        LookerResourceKind::Dashboard => &["id", "dashboard_id"],
        LookerResourceKind::Look => &["id", "look_id"],
        LookerResourceKind::Folder => &["id", "folder_id"],
        LookerResourceKind::Query => &["id", "query_id"],
        LookerResourceKind::Model => &["name", "model", "model_name"],
        LookerResourceKind::Explore => &["name", "explore", "view"],
        LookerResourceKind::Content => &["id", "content_metadata_id", "content_id"],
    };
    keys.iter()
        .copied()
        .find_map(|key| value_as_identifier(object.get(key)))
}

fn extract_name(object: &serde_json::Map<String, Value>) -> Option<String> {
    ["title", "name", "label", "model", "view", "explore"]
        .into_iter()
        .find_map(|key| value_as_identifier(object.get(key)))
}

fn value_as_identifier(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(value))
            if !value.is_empty() && value.len() <= crate::MAX_IDENTIFIER_BYTES =>
        {
            Some(value.clone())
        }
        Some(Value::Number(value)) => Some(value.to_string()),
        _ => None,
    }
}

fn metadata_id_digest(value: &str) -> Digest {
    crate::Identifier::new(value).map_or_else(
        |_| sha256_digest(format!("looker-metadata-id/v1|{value}").as_bytes()),
        |identifier| identifier.digest(),
    )
}

fn extract_revision(object: &serde_json::Map<String, Value>) -> Option<u64> {
    object
        .get("revision")
        .and_then(Value::as_u64)
        .or_else(|| object.get("version").and_then(Value::as_u64))
}

fn numeric_count(payload: &Value) -> Option<u32> {
    payload
        .get("total_count")
        .and_then(Value::as_u64)
        .or_else(|| payload.get("total").and_then(Value::as_u64))
        .and_then(|value| u32::try_from(value).ok())
}

fn bounded_count(object: &serde_json::Map<String, Value>, keys: &[&str]) -> u16 {
    for key in keys {
        if let Some(value) = object.get(*key) {
            if let Some(count) = value.as_u64().and_then(|value| u16::try_from(value).ok()) {
                return count;
            }
            if let Some(items) = value.as_array() {
                return u16::try_from(items.len()).unwrap_or(u16::MAX);
            }
        }
    }
    0
}

fn matches_scope(
    object: &serde_json::Map<String, Value>,
    request: &LookerAnalyticsRequest,
    scope: &LookerAnalyticsScope,
) -> bool {
    if request.operation() == LookerOperation::SearchDashboards {
        if let (Some(dashboard), Some(response_id)) = (
            scope.dashboard(),
            value_as_identifier(object.get("id").or_else(|| object.get("dashboard_id"))),
        ) {
            if metadata_id_digest(&response_id) != dashboard.digest() {
                return false;
            }
        }
    }
    if request.operation() == LookerOperation::SearchLooks {
        if let (Some(look), Some(response_id)) = (
            scope.look(),
            value_as_identifier(object.get("id").or_else(|| object.get("look_id"))),
        ) {
            if metadata_id_digest(&response_id) != look.digest() {
                return false;
            }
        }
    }
    if let Some(folder) = scope.folder() {
        if let Some(folder_id) = value_as_identifier(object.get("folder_id")) {
            if metadata_id_digest(&folder_id) != folder.digest() {
                return false;
            }
        }
    }
    if matches!(
        request.operation(),
        LookerOperation::ModelMetadata | LookerOperation::ExploreMetadata
    ) {
        if let Some(model) = object
            .get("model")
            .and_then(Value::as_str)
            .or_else(|| object.get("model_name").and_then(Value::as_str))
        {
            if scope.model().as_str() != model {
                return false;
            }
        }
        if request.operation() == LookerOperation::ExploreMetadata {
            if let Some(explore) = object
                .get("explore")
                .and_then(Value::as_str)
                .or_else(|| object.get("view").and_then(Value::as_str))
            {
                if scope.explore().as_str() != explore {
                    return false;
                }
            }
        }
    }
    true
}

// Keep these aliases available to callers that prefer the shorter provider
// request/response vocabulary without exposing any raw payload type.
pub type LookerRequest = LookerProviderRequest;
pub type LookerHttpResponse = LookerResponse;
