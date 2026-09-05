use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    Digest, MAX_HISTORY_ENTRIES, MAX_PAGE_SIZE, MAX_PAGES_PER_OPERATION, MAX_PLAN_EVENT_SPECS,
    MAX_REQUESTS_PER_READ, MAX_RESPONSE_BYTES, SecretReference, SnowplowCursor,
    SnowplowEventSpecProjection, SnowplowHistoryOrder, SnowplowHistoryProjection,
    SnowplowModelError, SnowplowPageReceipt, SnowplowRateLimitReceipt, SnowplowRegistration,
    SnowplowTrackingPlanProjection, SnowplowTrackingPlanScope, SnowplowTrackingPlanStatus,
    SnowplowTransportProvenance, canonical_digest, sha256_digest,
};
use crate::{API_REVISION, CONTRACT_SCHEMA, PROVIDER_ID, SNOWPLOW_HOST};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SnowplowHttpMethod {
    Get,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnowplowOperation {
    GetTrackingPlan,
    ListEventSpecs,
    TrackingPlanHistory,
}

impl SnowplowOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetTrackingPlan => "get_tracking_plan",
            Self::ListEventSpecs => "list_event_specs",
            Self::TrackingPlanHistory => "tracking_plan_history",
        }
    }

    #[must_use]
    pub const fn path_template(self) -> &'static str {
        match self {
            Self::GetTrackingPlan => {
                "/api/msc/v1/organizations/{organizationId}/data-products/v2/{dataProductId}"
            }
            Self::ListEventSpecs => "/api/msc/v1/organizations/{organizationId}/event-specs/v1",
            Self::TrackingPlanHistory => {
                "/api/msc/v1/organizations/{organizationId}/data-products/v2/{dataProductId}/history"
            }
        }
    }

    #[must_use]
    pub const fn required_permission(self) -> &'static str {
        match self {
            Self::GetTrackingPlan => "snowplow.tracking_plan.read",
            Self::ListEventSpecs => "snowplow.event_spec.read",
            Self::TrackingPlanHistory => "snowplow.tracking_plan.history.read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowplowRequest {
    pub operation: SnowplowOperation,
    pub method: SnowplowHttpMethod,
    pub host: String,
    pub path: String,
    pub page_size: u16,
    pub page_number: u16,
    pub cursor_digest: Option<Digest>,
    pub before_digest: Option<Digest>,
    pub order: Option<SnowplowHistoryOrder>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
}

impl SnowplowRequest {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            self.operation,
            self.method,
            &self.host,
            &self.path,
            self.page_size,
            self.page_number,
            &self.cursor_digest,
            &self.before_digest,
            self.order,
            &self.scope_digest,
            &self.permission_digest,
            &self.secret_reference_digest,
        ))
    }

    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        self.method == SnowplowHttpMethod::Get
            && self.host == SNOWPLOW_HOST
            && self.path.starts_with("/api/msc/v1/organizations/")
            && !self.path.contains("snowplow-resource")
            && matches!(
                self.operation,
                SnowplowOperation::GetTrackingPlan
                    | SnowplowOperation::ListEventSpecs
                    | SnowplowOperation::TrackingPlanHistory
            )
            && self.page_size > 0
            && self.page_size <= MAX_PAGE_SIZE
            && self.page_number > 0
            && self.request_digest == self.digest()
    }
}

/// Raw provider bytes are held only while the typed parser runs. They are
/// skipped by serialization and never appear in Debug or provider evidence.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowplowApiResponse {
    pub status_code: u16,
    #[serde(skip)]
    body: Vec<u8>,
    pub rate_limit: SnowplowRateLimitReceipt,
    #[serde(skip)]
    declared_digest: Option<Digest>,
}

impl fmt::Debug for SnowplowApiResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnowplowApiResponse")
            .field("status_code", &self.status_code)
            .field("body_digest", &self.response_digest())
            .field("body_bytes", &self.body.len())
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

impl SnowplowApiResponse {
    #[must_use]
    pub fn json<T: Serialize>(status_code: u16, payload: &T) -> Self {
        Self::json_with_rate_limit(status_code, payload, SnowplowRateLimitReceipt::default())
    }

    #[must_use]
    pub fn json_with_rate_limit<T: Serialize>(
        status_code: u16,
        payload: &T,
        rate_limit: SnowplowRateLimitReceipt,
    ) -> Self {
        let body = serde_json::to_vec(payload).expect("Snowplow fixture payload serializes");
        Self {
            status_code,
            body,
            rate_limit,
            declared_digest: None,
        }
    }

    #[must_use]
    pub fn new(status_code: u16, body: Vec<u8>, rate_limit: SnowplowRateLimitReceipt) -> Self {
        Self {
            status_code,
            body,
            rate_limit,
            declared_digest: None,
        }
    }

    #[must_use]
    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.declared_digest = Some(digest);
        self
    }

    #[must_use]
    pub fn response_digest(&self) -> Digest {
        sha256_digest(&self.body)
    }

    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.body.len()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SnowplowTransportError {
    #[error("Snowplow native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Snowplow transport failed without a native response")]
    ProviderUnknown,
}

/// Layer-1 transport seam. No implementation in this crate opens native
/// HTTPS or resolves an opaque secret.
pub trait SnowplowTransport: fmt::Debug {
    fn provenance(&self) -> SnowplowTransportProvenance;

    fn execute(
        &mut self,
        request: &SnowplowRequest,
    ) -> Result<SnowplowApiResponse, SnowplowTransportError>;
}

#[derive(Clone, Debug)]
struct ResponseQueue {
    responses: VecDeque<SnowplowApiResponse>,
    last: Option<SnowplowApiResponse>,
}

impl ResponseQueue {
    fn new(response: SnowplowApiResponse) -> Self {
        Self {
            responses: VecDeque::from([response]),
            last: None,
        }
    }

    fn from_responses(responses: impl IntoIterator<Item = SnowplowApiResponse>) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            last: None,
        }
    }

    fn next(&mut self) -> Result<SnowplowApiResponse, SnowplowTransportError> {
        if let Some(response) = self.responses.pop_front() {
            self.last = Some(response.clone());
            Ok(response)
        } else if let Some(response) = &self.last {
            Ok(response.clone())
        } else {
            Err(SnowplowTransportError::ProviderUnknown)
        }
    }
}

#[derive(Clone, Debug)]
pub struct FixtureSnowplowTransport {
    queue: ResponseQueue,
}

impl FixtureSnowplowTransport {
    #[must_use]
    pub fn new(response: SnowplowApiResponse) -> Self {
        Self {
            queue: ResponseQueue::new(response),
        }
    }

    #[must_use]
    pub fn from_responses(responses: impl IntoIterator<Item = SnowplowApiResponse>) -> Self {
        Self {
            queue: ResponseQueue::from_responses(responses),
        }
    }
}

impl SnowplowTransport for FixtureSnowplowTransport {
    fn provenance(&self) -> SnowplowTransportProvenance {
        SnowplowTransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        _request: &SnowplowRequest,
    ) -> Result<SnowplowApiResponse, SnowplowTransportError> {
        self.queue.next()
    }
}

#[derive(Clone, Debug)]
pub struct RecordingSnowplowTransport {
    queue: ResponseQueue,
    requests: Vec<SnowplowRequest>,
}

impl RecordingSnowplowTransport {
    #[must_use]
    pub fn new(response: SnowplowApiResponse) -> Self {
        Self {
            queue: ResponseQueue::new(response),
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn from_responses(responses: impl IntoIterator<Item = SnowplowApiResponse>) -> Self {
        Self {
            queue: ResponseQueue::from_responses(responses),
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[SnowplowRequest] {
        &self.requests
    }
}

impl SnowplowTransport for RecordingSnowplowTransport {
    fn provenance(&self) -> SnowplowTransportProvenance {
        SnowplowTransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &SnowplowRequest,
    ) -> Result<SnowplowApiResponse, SnowplowTransportError> {
        self.requests.push(request.clone());
        self.queue.next()
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackSnowplowTransport {
    queue: ResponseQueue,
    requests: Vec<SnowplowRequest>,
}

impl LoopbackSnowplowTransport {
    #[must_use]
    pub fn new(response: SnowplowApiResponse) -> Self {
        Self {
            queue: ResponseQueue::new(response),
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn from_responses(responses: impl IntoIterator<Item = SnowplowApiResponse>) -> Self {
        Self {
            queue: ResponseQueue::from_responses(responses),
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[SnowplowRequest] {
        &self.requests
    }
}

impl SnowplowTransport for LoopbackSnowplowTransport {
    fn provenance(&self) -> SnowplowTransportProvenance {
        SnowplowTransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        request: &SnowplowRequest,
    ) -> Result<SnowplowApiResponse, SnowplowTransportError> {
        self.requests.push(request.clone());
        self.queue.next()
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvSnowplowTransport;

impl SnowplowTransport for BlockedEnvSnowplowTransport {
    fn provenance(&self) -> SnowplowTransportProvenance {
        SnowplowTransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &SnowplowRequest,
    ) -> Result<SnowplowApiResponse, SnowplowTransportError> {
        Err(SnowplowTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnowplowProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub capability_digest: Digest,
    pub permission_digest: Digest,
    pub provenance: SnowplowTransportProvenance,
    pub max_page_size: u16,
    pub max_pages_per_operation: u16,
    pub max_requests_per_read: u16,
    pub max_response_bytes: usize,
    pub read_only: bool,
    pub live_execution: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

impl SnowplowProviderDefinition {
    #[must_use]
    pub fn layer1(provenance: SnowplowTransportProvenance, permission_digest: Digest) -> Self {
        let capability_digest = canonical_digest(&(
            CONTRACT_SCHEMA,
            PROVIDER_ID,
            API_REVISION,
            SnowplowOperation::GetTrackingPlan.path_template(),
            SnowplowOperation::ListEventSpecs.path_template(),
            SnowplowOperation::TrackingPlanHistory.path_template(),
            "get_only",
            "digest_only",
        ));
        Self {
            schema_version: CONTRACT_SCHEMA.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: "1.0.0".to_owned(),
            api_revision: API_REVISION.to_owned(),
            capability_digest,
            permission_digest,
            provenance,
            max_page_size: MAX_PAGE_SIZE,
            max_pages_per_operation: MAX_PAGES_PER_OPERATION,
            max_requests_per_read: MAX_REQUESTS_PER_READ,
            max_response_bytes: MAX_RESPONSE_BYTES,
            read_only: true,
            live_execution: false,
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
pub enum SnowplowProviderError {
    #[error("Snowplow registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Snowplow SecretReference is revoked")]
    SecretRevoked,
    #[error("Snowplow read permission set is missing or drifted")]
    MissingPermission,
    #[error("Snowplow scope or cursor does not match the registration")]
    ScopeMismatch,
    #[error("Snowplow request budget was exhausted")]
    RequestBudgetExceeded,
    #[error("Snowplow rate limit was reached")]
    RateLimited {
        request: SnowplowRequest,
        status_code: u16,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: SnowplowRateLimitReceipt,
    },
    #[error("Snowplow provider returned HTTP status {status_code}")]
    HttpStatus {
        request: SnowplowRequest,
        status_code: u16,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: SnowplowRateLimitReceipt,
    },
    #[error("Snowplow provider response exceeded the Layer-1 bound")]
    ResponseTooLarge {
        request: SnowplowRequest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: SnowplowRateLimitReceipt,
    },
    #[error("Snowplow provider response was malformed or outside typed bounds")]
    MalformedResponse {
        request: SnowplowRequest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: SnowplowRateLimitReceipt,
    },
    #[error("Snowplow provider response failed its declared digest fence")]
    TamperedResponse {
        request: SnowplowRequest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: SnowplowRateLimitReceipt,
    },
    #[error("Snowplow cursor is stale or inconsistent")]
    StaleCursor,
    #[error("Snowplow transport failed")]
    Transport {
        request: SnowplowRequest,
        error: SnowplowTransportError,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: SnowplowRateLimitReceipt,
    },
    #[error(transparent)]
    Model(#[from] SnowplowModelError),
}

impl SnowplowProviderError {
    #[must_use]
    pub fn request(&self) -> Option<&SnowplowRequest> {
        match self {
            Self::RegistrationRevoked
            | Self::SecretRevoked
            | Self::MissingPermission
            | Self::ScopeMismatch
            | Self::RequestBudgetExceeded
            | Self::StaleCursor
            | Self::Model(_) => None,
            Self::RateLimited { request, .. }
            | Self::HttpStatus { request, .. }
            | Self::ResponseTooLarge { request, .. }
            | Self::MalformedResponse { request, .. }
            | Self::TamperedResponse { request, .. }
            | Self::Transport { request, .. } => Some(request),
        }
    }

    #[must_use]
    pub fn metadata(&self) -> Option<(Digest, usize, SnowplowRateLimitReceipt, Option<u16>)> {
        match self {
            Self::RateLimited {
                response_digest,
                response_bytes,
                rate_limit,
                status_code,
                ..
            }
            | Self::HttpStatus {
                response_digest,
                response_bytes,
                rate_limit,
                status_code,
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
            | Self::TamperedResponse {
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
            Self::RegistrationRevoked
            | Self::SecretRevoked
            | Self::MissingPermission
            | Self::ScopeMismatch
            | Self::RequestBudgetExceeded
            | Self::StaleCursor
            | Self::Model(_) => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnowplowProviderPage {
    pub request: SnowplowRequest,
    pub plan: Option<SnowplowTrackingPlanProjection>,
    pub event_specs: Vec<SnowplowEventSpecProjection>,
    pub history: Vec<SnowplowHistoryProjection>,
    pub next_cursor: Option<SnowplowCursor>,
    pub page_receipt: SnowplowPageReceipt,
    pub rate_limit: SnowplowRateLimitReceipt,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub provenance: SnowplowTransportProvenance,
}

impl SnowplowProviderPage {
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.plan
            .as_ref()
            .map_or(self.event_specs.len() + self.history.len(), |_| 1)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            &self.plan,
            &self.event_specs,
            &self.history,
            self.next_cursor.as_ref().map(SnowplowCursor::digest),
        ))
    }
}

/// Typed provider for bounded Snowplow Console GET evidence.
pub struct SnowplowProvider<T: SnowplowTransport> {
    scope: SnowplowTrackingPlanScope,
    secret_reference: SecretReference,
    transport: T,
    definition: SnowplowProviderDefinition,
    registration: SnowplowRegistration,
    requests_issued: u16,
}

impl<T: SnowplowTransport> fmt::Debug for SnowplowProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnowplowProvider")
            .field("scope_digest", self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("transport_provenance", &self.definition.provenance)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .field("requests_issued", &self.requests_issued)
            .finish_non_exhaustive()
    }
}

impl<T: SnowplowTransport> SnowplowProvider<T> {
    pub fn new(
        scope: SnowplowTrackingPlanScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, SnowplowProviderError> {
        scope.validate()?;
        if secret_reference.is_revoked() {
            return Err(SnowplowProviderError::SecretRevoked);
        }
        let definition = SnowplowProviderDefinition::layer1(
            transport.provenance(),
            scope.permissions().digest(),
        );
        let registration =
            SnowplowRegistration::bind(&scope, &secret_reference, definition.provider_digest());
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
        scope: SnowplowTrackingPlanScope,
        secret_reference: SecretReference,
        transport: T,
        registration: SnowplowRegistration,
    ) -> Result<Self, SnowplowProviderError> {
        scope.validate()?;
        let definition = SnowplowProviderDefinition::layer1(
            transport.provenance(),
            scope.permissions().digest(),
        );
        registration
            .validate(&scope, &secret_reference, &definition.provider_digest())
            .map_err(|_| SnowplowProviderError::ScopeMismatch)?;
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
    pub fn scope(&self) -> &SnowplowTrackingPlanScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &SnowplowProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    #[must_use]
    pub fn registration(&self) -> &SnowplowRegistration {
        &self.registration
    }

    #[must_use]
    pub fn transport_provenance(&self) -> SnowplowTransportProvenance {
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

    pub(crate) fn reset_read_budget(&mut self) {
        self.requests_issued = 0;
    }

    pub fn read_page(
        &mut self,
        operation: SnowplowOperation,
        page_size: u16,
        cursor: Option<SnowplowCursor>,
    ) -> Result<SnowplowProviderPage, SnowplowProviderError> {
        self.read_page_with_query(
            operation,
            page_size,
            cursor,
            None,
            SnowplowHistoryOrder::Desc,
        )
    }

    pub fn read_page_with_query(
        &mut self,
        operation: SnowplowOperation,
        page_size: u16,
        cursor: Option<SnowplowCursor>,
        before: Option<&str>,
        order: SnowplowHistoryOrder,
    ) -> Result<SnowplowProviderPage, SnowplowProviderError> {
        self.ensure_ready(operation)?;
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(SnowplowProviderError::Model(
                SnowplowModelError::InvalidPageSize,
            ));
        }
        if let Some(cursor) = &cursor {
            cursor
                .validate(self.scope.digest())
                .map_err(|_| SnowplowProviderError::StaleCursor)?;
        }
        if self.requests_issued >= MAX_REQUESTS_PER_READ {
            return Err(SnowplowProviderError::RequestBudgetExceeded);
        }
        self.requests_issued += 1;
        let request = self.build_request(operation, page_size, cursor.as_ref(), before, order);
        if !request.is_allowlisted() {
            return Err(SnowplowProviderError::ScopeMismatch);
        }
        let response = match self.transport.execute(&request) {
            Ok(response) => response,
            Err(error) => {
                return Err(SnowplowProviderError::Transport {
                    request,
                    error,
                    response_digest: sha256_digest(b"no-native-response"),
                    response_bytes: 0,
                    rate_limit: SnowplowRateLimitReceipt::default(),
                });
            }
        };
        let provenance = self.transport.provenance();
        let response_digest = response.response_digest();
        let response_bytes = response.response_bytes();
        let rate_limit = response.rate_limit.clone();
        rate_limit
            .validate()
            .map_err(|_| SnowplowProviderError::MalformedResponse {
                request: request.clone(),
                response_digest: response_digest.clone(),
                response_bytes,
                rate_limit: rate_limit.clone(),
            })?;
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(SnowplowProviderError::ResponseTooLarge {
                request,
                response_digest,
                response_bytes,
                rate_limit,
            });
        }
        if response.status_code == 429 || rate_limit.throttled {
            return Err(SnowplowProviderError::RateLimited {
                request,
                status_code: response.status_code,
                response_digest,
                response_bytes,
                rate_limit,
            });
        }
        if !(200..300).contains(&response.status_code) {
            return Err(SnowplowProviderError::HttpStatus {
                request,
                status_code: response.status_code,
                response_digest,
                response_bytes,
                rate_limit,
            });
        }
        let root: Value = serde_json::from_slice(&response.body).map_err(|_| {
            SnowplowProviderError::MalformedResponse {
                request: request.clone(),
                response_digest: response_digest.clone(),
                response_bytes,
                rate_limit: rate_limit.clone(),
            }
        })?;
        let page = parse_page(
            operation,
            &root,
            self.scope(),
            &request,
            response.status_code,
            response_digest.clone(),
            response_bytes,
            rate_limit.clone(),
            provenance,
        )
        .map_err(|kind| match kind {
            ParseFailure::Tamper => SnowplowProviderError::TamperedResponse {
                request: request.clone(),
                response_digest: response_digest.clone(),
                response_bytes,
                rate_limit: rate_limit.clone(),
            },
            ParseFailure::Malformed => SnowplowProviderError::MalformedResponse {
                request: request.clone(),
                response_digest: response_digest.clone(),
                response_bytes,
                rate_limit: rate_limit.clone(),
            },
            ParseFailure::Model(error) => SnowplowProviderError::MalformedResponse {
                request: request.clone(),
                response_digest: response_digest.clone(),
                response_bytes,
                rate_limit: rate_limit.clone(),
            }
            .with_model(error),
        })?;
        if response
            .declared_digest
            .as_ref()
            .is_some_and(|declared| declared != &page.digest())
        {
            return Err(SnowplowProviderError::TamperedResponse {
                request,
                response_digest,
                response_bytes,
                rate_limit,
            });
        }
        Ok(page)
    }

    pub fn read_tracking_plan(&mut self) -> Result<SnowplowProviderPage, SnowplowProviderError> {
        self.read_page(SnowplowOperation::GetTrackingPlan, 1, None)
    }

    pub fn read_event_specs(
        &mut self,
        page_size: u16,
        cursor: Option<SnowplowCursor>,
    ) -> Result<SnowplowProviderPage, SnowplowProviderError> {
        self.read_page(SnowplowOperation::ListEventSpecs, page_size, cursor)
    }

    pub fn read_history(
        &mut self,
        page_size: u16,
        cursor: Option<SnowplowCursor>,
        before: Option<&str>,
        order: SnowplowHistoryOrder,
    ) -> Result<SnowplowProviderPage, SnowplowProviderError> {
        self.read_page_with_query(
            SnowplowOperation::TrackingPlanHistory,
            page_size,
            cursor,
            before,
            order,
        )
    }

    pub fn bind_evidence_digest(&mut self, digest: Digest) -> Result<(), SnowplowProviderError> {
        self.registration.bind_evidence_digest(digest)?;
        Ok(())
    }

    pub fn revoke(
        &mut self,
    ) -> Result<crate::SnowplowRegistrationRevocationReceipt, SnowplowProviderError> {
        Ok(self.registration.revoke()?)
    }

    pub fn restore(&mut self) -> Result<(), SnowplowProviderError> {
        self.registration.restore()?;
        Ok(())
    }

    pub fn revoke_secret(&mut self) -> Result<(), SnowplowProviderError> {
        self.secret_reference.revoke()?;
        Ok(())
    }

    fn ensure_ready(&self, operation: SnowplowOperation) -> Result<(), SnowplowProviderError> {
        if self.registration.state != crate::SnowplowRegistrationState::Active {
            return Err(SnowplowProviderError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(SnowplowProviderError::SecretRevoked);
        }
        if !self
            .scope
            .permissions()
            .permissions()
            .iter()
            .any(|permission| permission.as_str() == operation.required_permission())
        {
            return Err(SnowplowProviderError::MissingPermission);
        }
        self.registration
            .validate(&self.scope, &self.secret_reference, &self.provider_digest())
            .map_err(|_| SnowplowProviderError::RegistrationRevoked)
    }

    fn build_request(
        &self,
        operation: SnowplowOperation,
        page_size: u16,
        cursor: Option<&SnowplowCursor>,
        before: Option<&str>,
        order: SnowplowHistoryOrder,
    ) -> SnowplowRequest {
        let organization_digest = self.scope.organization().digest();
        let plan_digest = self.scope.tracking_plan().digest();
        let cursor_digest = cursor.map(|value| value.cursor_digest.clone());
        let before_digest = before.map(|value| sha256_digest(value.as_bytes()));
        let page_number = cursor.map_or(1, SnowplowCursor::page_number);
        let path = match operation {
            SnowplowOperation::GetTrackingPlan => format!(
                "/api/msc/v1/organizations/{}/data-products/v2/{}?pageSize={}",
                &organization_digest[..16],
                &plan_digest[..16],
                page_size
            ),
            SnowplowOperation::ListEventSpecs => format!(
                "/api/msc/v1/organizations/{}/event-specs/v1?dataProductId={}&pageSize={}&cursor={}",
                &organization_digest[..16],
                &plan_digest[..16],
                page_size,
                cursor.map_or_else(
                    || "first".to_owned(),
                    |value| value.cursor_digest[..16].to_owned()
                )
            ),
            SnowplowOperation::TrackingPlanHistory => format!(
                "/api/msc/v1/organizations/{}/data-products/v2/{}/history?limit={}&offset={}&before={}&order={:?}",
                &organization_digest[..16],
                &plan_digest[..16],
                page_size,
                cursor.map_or(0, |value| {
                    usize::from(value.page_number.saturating_sub(1)) * page_size as usize
                }),
                before_digest
                    .as_deref()
                    .map_or("none", |value| &value[..16]),
                order
            ),
        };
        let mut request = SnowplowRequest {
            operation,
            method: SnowplowHttpMethod::Get,
            host: SNOWPLOW_HOST.to_owned(),
            path,
            page_size,
            page_number,
            cursor_digest,
            before_digest,
            order: Some(order).filter(|_| operation == SnowplowOperation::TrackingPlanHistory),
            scope_digest: self.scope.digest().clone(),
            permission_digest: self.scope.permissions().digest(),
            secret_reference_digest: self.secret_reference.digest(),
            request_digest: String::new(),
        };
        request.request_digest = request.digest();
        request
    }
}

impl SnowplowProviderError {
    fn with_model(self, error: SnowplowModelError) -> Self {
        match self {
            Self::MalformedResponse {
                request,
                response_digest,
                response_bytes,
                rate_limit,
            } => Self::Model(error).with_response_metadata(
                request,
                response_digest,
                response_bytes,
                rate_limit,
            ),
            other => other,
        }
    }

    fn with_response_metadata(
        self,
        request: SnowplowRequest,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: SnowplowRateLimitReceipt,
    ) -> Self {
        let _ = self;
        Self::MalformedResponse {
            request,
            response_digest,
            response_bytes,
            rate_limit,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ParseFailure {
    Malformed,
    Tamper,
    Model(SnowplowModelError),
}

fn parse_page(
    operation: SnowplowOperation,
    root: &Value,
    scope: &SnowplowTrackingPlanScope,
    request: &SnowplowRequest,
    status_code: u16,
    response_digest: Digest,
    response_bytes: usize,
    rate_limit: SnowplowRateLimitReceipt,
    provenance: SnowplowTransportProvenance,
) -> Result<SnowplowProviderPage, ParseFailure> {
    let items = data_items(root);
    let includes = root.get("includes");
    let (plan, event_specs, history) = match operation {
        SnowplowOperation::GetTrackingPlan => {
            let plan_value = items.first().ok_or(ParseFailure::Malformed)?;
            let plan = parse_plan(plan_value, scope).map_err(ParseFailure::Model)?;
            let event_specs = includes
                .and_then(|value| value.get("eventSpecs").or_else(|| value.get("event_specs")))
                .map(array_items)
                .unwrap_or_default()
                .into_iter()
                .map(|value| parse_event_spec(value, scope).map_err(ParseFailure::Model))
                .collect::<Result<Vec<_>, _>>()?;
            (Some(plan), event_specs, Vec::new())
        }
        SnowplowOperation::ListEventSpecs => {
            let event_specs = items
                .iter()
                .map(|value| parse_event_spec(value, scope).map_err(ParseFailure::Model))
                .collect::<Result<Vec<_>, _>>()?;
            (None, event_specs, Vec::new())
        }
        SnowplowOperation::TrackingPlanHistory => {
            let history = items
                .iter()
                .map(|value| parse_history(value, scope).map_err(ParseFailure::Model))
                .collect::<Result<Vec<_>, _>>()?;
            (None, Vec::new(), history)
        }
    };
    if event_specs.len() > MAX_PLAN_EVENT_SPECS || history.len() > MAX_HISTORY_ENTRIES {
        return Err(ParseFailure::Malformed);
    }
    let page_count = plan
        .as_ref()
        .map_or(event_specs.len() + history.len(), |_| 1);
    if page_count > usize::from(MAX_PAGE_SIZE) {
        return Err(ParseFailure::Malformed);
    }
    let next_token = next_token(
        operation,
        root,
        request.page_size,
        page_count,
        request.page_number,
    );
    let next_cursor = next_token
        .map(|token| SnowplowCursor::from_token(token, scope.digest(), request.page_number + 1))
        .transpose()
        .map_err(ParseFailure::Model)?;
    let page_digest = canonical_digest(&(
        &plan,
        &event_specs,
        &history,
        next_cursor.as_ref().map(SnowplowCursor::digest),
    ));
    let declared = declared_digest(root);
    if declared.is_some_and(|value| value != page_digest) {
        return Err(ParseFailure::Tamper);
    }
    let page_receipt = SnowplowPageReceipt {
        operation: operation.as_str().to_owned(),
        page_number: request.page_number,
        returned: page_count as u16,
        has_more: next_cursor.is_some(),
        cursor_digest: request.cursor_digest.clone(),
        response_digest: response_digest.clone(),
        status_code,
        redacted: true,
    };
    page_receipt.validate().map_err(ParseFailure::Model)?;
    Ok(SnowplowProviderPage {
        request: request.clone(),
        plan,
        event_specs,
        history,
        next_cursor,
        page_receipt,
        rate_limit,
        response_digest,
        response_bytes,
        provenance,
    })
}

fn data_items(root: &Value) -> Vec<&Value> {
    match root.get("data") {
        Some(Value::Array(values)) => values.iter().collect(),
        Some(Value::Object(_)) => root.get("data").into_iter().collect(),
        _ => Vec::new(),
    }
}

fn array_items(value: &Value) -> Vec<&Value> {
    match value {
        Value::Array(values) => values.iter().collect(),
        Value::Object(_) => vec![value],
        _ => Vec::new(),
    }
}

fn parse_plan(
    value: &Value,
    scope: &SnowplowTrackingPlanScope,
) -> Result<SnowplowTrackingPlanProjection, SnowplowModelError> {
    let id = string_field(value, &["id", "dataProductId", "data_product_id"])
        .ok_or(SnowplowModelError::InvalidText("tracking plan id"))?;
    let status = string_field(value, &["status"])
        .ok_or(SnowplowModelError::InvalidText("tracking plan status"))?;
    let revision = number_field(value, &["version", "revision"]).unwrap_or(1);
    let mut event_spec_digests = value
        .get("eventSpecs")
        .or_else(|| value.get("event_specs"))
        .or_else(|| value.get("tracking_scenarios"))
        .map(array_items)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|item| {
            item.as_str()
                .map(|id| sha256_digest(format!("snowplow-resource-id/v1|{id}").as_bytes()))
                .or_else(|| {
                    string_field(item, &["id", "eventSpecId", "event_spec_id"])
                        .map(|id| sha256_digest(format!("snowplow-resource-id/v1|{id}").as_bytes()))
                })
        })
        .collect::<Vec<_>>();
    event_spec_digests.sort_unstable();
    event_spec_digests.dedup();
    if event_spec_digests.len() > MAX_PLAN_EVENT_SPECS {
        return Err(SnowplowModelError::InvalidScope("plan event specs"));
    }
    let id_digest = sha256_digest(format!("snowplow-resource-id/v1|{id}").as_bytes());
    let schema_digest = schema_digest(value);
    let status = SnowplowTrackingPlanStatus::parse(&status)?;
    let revision_digest = canonical_digest(&(
        &id_digest,
        revision,
        status,
        &schema_digest,
        &event_spec_digests,
        scope.digest(),
    ));
    Ok(SnowplowTrackingPlanProjection {
        id_digest,
        status,
        revision,
        schema_digest,
        revision_digest,
        event_spec_digests,
    })
}

fn parse_event_spec(
    value: &Value,
    scope: &SnowplowTrackingPlanScope,
) -> Result<SnowplowEventSpecProjection, SnowplowModelError> {
    let id = string_field(value, &["id", "eventSpecId", "event_spec_id"])
        .ok_or(SnowplowModelError::InvalidText("event spec id"))?;
    let id_digest = sha256_digest(format!("snowplow-resource-id/v1|{id}").as_bytes());
    let tracking_plan_digest = string_field(
        value,
        &[
            "dataProductId",
            "data_product_id",
            "trackingPlanId",
            "tracking_plan_id",
        ],
    )
    .map(|id| sha256_digest(format!("snowplow-resource-id/v1|{id}").as_bytes()));
    let status = string_field(value, &["status"])
        .ok_or(SnowplowModelError::InvalidText("event spec status"))?;
    let status = SnowplowTrackingPlanStatus::parse(&status)?;
    let revision = number_field(value, &["version", "revision"]).unwrap_or(0);
    let schema_digest = schema_digest(value);
    let revision_digest = canonical_digest(&(
        &id_digest,
        &tracking_plan_digest,
        revision,
        status,
        &schema_digest,
        scope.digest(),
    ));
    Ok(SnowplowEventSpecProjection {
        id_digest,
        tracking_plan_digest,
        status,
        revision,
        schema_digest,
        revision_digest,
    })
}

fn parse_history(
    value: &Value,
    scope: &SnowplowTrackingPlanScope,
) -> Result<SnowplowHistoryProjection, SnowplowModelError> {
    let id = string_field(
        value,
        &[
            "eventSpecId",
            "event_spec_id",
            "dataProductId",
            "data_product_id",
            "id",
        ],
    )
    .ok_or(SnowplowModelError::InvalidText("history resource id"))?;
    let resource_digest = sha256_digest(format!("snowplow-resource-id/v1|{id}").as_bytes());
    let status = string_field(value, &["status"])
        .ok_or(SnowplowModelError::InvalidText("history status"))?;
    let status = SnowplowTrackingPlanStatus::parse(&status)?;
    let revision = number_field(value, &["version", "revision"]).unwrap_or(0);
    let schema_digest = schema_digest(value);
    let change_digest = canonical_digest(value);
    let revision_digest = canonical_digest(&(
        &resource_digest,
        revision,
        status,
        &schema_digest,
        &change_digest,
        scope.digest(),
    ));
    Ok(SnowplowHistoryProjection {
        resource_digest,
        revision,
        status,
        schema_digest,
        revision_digest,
        change_digest,
    })
}

fn schema_digest(value: &Value) -> Digest {
    let schema = value
        .get("event")
        .and_then(|event| event.get("schema").or_else(|| event.get("source")))
        .or_else(|| value.get("schema"))
        .or_else(|| value.get("schemaDigest"))
        .or_else(|| value.get("schema_digest"));
    match schema {
        Some(Value::String(value)) if valid_digest(value) => value.clone(),
        Some(value) => canonical_digest(value),
        None => canonical_digest(&(
            value.get("event"),
            value.get("entities"),
            value.get("dataProductId"),
            value.get("data_product_id"),
        )),
    }
}

fn string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str).map(str::to_owned))
}

fn number_field(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        value.get(*key).and_then(Value::as_u64).or_else(|| {
            value
                .get(*key)
                .and_then(Value::as_i64)
                .and_then(|value| value.try_into().ok())
        })
    })
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn declared_digest(root: &Value) -> Option<Digest> {
    ["evidenceDigest", "evidence_digest"]
        .iter()
        .find_map(|key| root.get(*key).and_then(Value::as_str).map(str::to_owned))
}

fn next_token(
    operation: SnowplowOperation,
    root: &Value,
    page_size: u16,
    returned: usize,
    page_number: u16,
) -> Option<String> {
    if operation == SnowplowOperation::GetTrackingPlan {
        return None;
    }
    let pagination = root.get("pagination").unwrap_or(root);
    for key in [
        "nextCursor",
        "next_cursor",
        "nextToken",
        "next_token",
        "nextOffset",
        "next_offset",
    ] {
        if let Some(value) = pagination.get(key) {
            if let Some(token) = value.as_str() {
                return Some(token.to_owned());
            }
            if let Some(offset) = value.as_u64() {
                return Some(offset.to_string());
            }
        }
    }
    let explicit_has_more = ["hasMore", "has_more", "hasNext", "has_next"]
        .iter()
        .find_map(|key| pagination.get(*key).and_then(Value::as_bool));
    if explicit_has_more == Some(false) {
        return None;
    }
    if explicit_has_more == Some(true) || returned == usize::from(page_size) {
        Some(format!("page-{}-offset-{}", page_number + 1, returned))
    } else {
        None
    }
}
