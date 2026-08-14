//! Read-only AWS Route 53 health-check provider boundary.
//!
//! The provider exposes exactly ListHealthChecks, GetHealthCheck, and
//! GetHealthCheckStatus. It has no signer, credential resolver, HTTP client,
//! DNS mutation method, or raw-provider-payload return type.

use std::{collections::VecDeque, fmt};

use chrono::{Duration, Utc};
use serde_json::Value;
use thiserror::Error;

use crate::{
    AWS_ROUTE53_HEALTH_API_REVISION, AWS_ROUTE53_HEALTH_PROVIDER_ID,
    AWS_ROUTE53_HEALTH_PROVIDER_VERSION,
    model::{
        AwsRegion, AwsRoute53HealthReadRequest, AwsRoute53HealthScope, Digest,
        GetHealthCheckResponse, GetHealthCheckStatusResponse, HealthCheckConfiguration,
        HealthCheckId, HealthCheckObservation, HealthCheckSummary, HealthCheckTarget,
        HealthCheckType, ListHealthChecksPage, ModelError, ObservationStatus, OpaqueMarker,
        PermissionAction, ProviderErrorEvidence, ProviderId, ProviderRevision, ReadOperation,
        Revision, TransportProvenance,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("AWS Route 53 provider model error: {0}")]
    Model(#[from] ModelError),
    #[error("AWS Route 53 provider revision is incompatible")]
    RevisionMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsRoute53ProviderIdentity {
    pub provider_id: ProviderId,
    pub version: String,
    pub api_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub provenance: TransportProvenance,
}

impl AwsRoute53ProviderIdentity {
    pub fn for_provenance(
        provenance: TransportProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_id = ProviderId::new(AWS_ROUTE53_HEALTH_PROVIDER_ID)?;
        let api_revision = ProviderRevision::new(AWS_ROUTE53_HEALTH_API_REVISION)?;
        let provider_digest = Digest::from_parts(
            "hartevo-aws-route53-provider/v1",
            &[
                provider_id.as_str().to_owned(),
                AWS_ROUTE53_HEALTH_PROVIDER_VERSION.to_owned(),
                api_revision.as_str().to_owned(),
            ],
        );
        let api_digest = Digest::from_parts(
            "hartevo-aws-route53-api-allowlist/v1",
            &[
                "ListHealthChecks".to_owned(),
                "GetHealthCheck".to_owned(),
                "GetHealthCheckStatus".to_owned(),
                "POST".to_owned(),
            ],
        );
        Ok(Self {
            provider_id,
            version: AWS_ROUTE53_HEALTH_PROVIDER_VERSION.to_owned(),
            api_revision,
            provider_digest,
            api_digest,
            provenance,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsRoute53ProviderDefinition {
    pub provider_id: ProviderId,
    pub provider_version: String,
    pub api_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub allowed_operations: [ReadOperation; 3],
    pub allowed_permission_actions: [PermissionAction; 3],
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl AwsRoute53ProviderDefinition {
    pub fn from_identity(
        identity: &AwsRoute53ProviderIdentity,
    ) -> Result<Self, ProviderDefinitionError> {
        Ok(Self {
            provider_id: identity.provider_id.clone(),
            provider_version: identity.version.clone(),
            api_revision: identity.api_revision.clone(),
            provider_digest: identity.provider_digest.clone(),
            api_digest: identity.api_digest.clone(),
            allowed_operations: [
                ReadOperation::ListHealthChecks,
                ReadOperation::GetHealthCheck,
                ReadOperation::GetHealthCheckStatus,
            ],
            allowed_permission_actions: [
                PermissionAction::ListHealthChecks,
                PermissionAction::GetHealthCheck,
                PermissionAction::GetHealthCheckStatus,
            ],
            provenance: identity.provenance,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        if self.connected || self.native || self.first_party {
            return Err(ProviderDefinitionError::RevisionMismatch);
        }
        if self.allowed_operations
            != [
                ReadOperation::ListHealthChecks,
                ReadOperation::GetHealthCheck,
                ReadOperation::GetHealthCheckStatus,
            ]
        {
            return Err(ProviderDefinitionError::RevisionMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportFailure {
    BadRequest,
    Unauthorized,
    AccessDenied,
    NotFound,
    Conflict,
    Throttled,
    Server,
    Timeout,
    BlockedEnv,
    Malformed,
}

impl TransportFailure {
    pub const fn status_code(self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::AccessDenied => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::Throttled => Some(429),
            Self::Server => Some(503),
            Self::Timeout | Self::BlockedEnv | Self::Malformed => None,
        }
    }

    pub const fn retryable(self) -> bool {
        matches!(self, Self::Throttled | Self::Server | Self::Timeout)
    }

    pub const fn category(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::AccessDenied => "access_denied",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::Throttled => "throttled",
            Self::Server => "server",
            Self::Timeout => "timeout",
            Self::BlockedEnv => "BLOCKED_ENV",
            Self::Malformed => "malformed",
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq, serde::Deserialize, serde::Serialize)]
#[error("AWS Route 53 transport failure: {failure:?}")]
#[serde(rename_all = "camelCase")]
pub struct TransportError {
    pub failure: TransportFailure,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

impl TransportError {
    pub fn new(failure: TransportFailure) -> Self {
        Self {
            status_code: failure.status_code(),
            error_digest: Digest::from_text(failure.category()),
            failure,
        }
    }

    pub fn from_status(status_code: u16) -> Self {
        let failure = match status_code {
            400 => TransportFailure::BadRequest,
            401 => TransportFailure::Unauthorized,
            403 => TransportFailure::AccessDenied,
            404 => TransportFailure::NotFound,
            409 => TransportFailure::Conflict,
            429 => TransportFailure::Throttled,
            500..=599 => TransportFailure::Server,
            _ => TransportFailure::Malformed,
        };
        Self::new(failure)
    }

    pub fn blocked_env() -> Self {
        Self::new(TransportFailure::BlockedEnv)
    }

    pub fn timeout() -> Self {
        Self::new(TransportFailure::Timeout)
    }

    pub fn malformed() -> Self {
        Self::new(TransportFailure::Malformed)
    }

    pub fn evidence(&self, operation: ReadOperation) -> ProviderErrorEvidence {
        ProviderErrorEvidence {
            operation,
            category: self.failure.category().to_owned(),
            status_code: self.status_code,
            error_digest: self.error_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderError {
    #[error("AWS Route 53 provider request model error: {0}")]
    Model(#[from] ModelError),
    #[error("AWS Route 53 provider transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("AWS Route 53 provider response binding or digest is invalid")]
    ResponseBinding,
    #[error("AWS Route 53 provider revision is incompatible")]
    ProviderRevision,
    #[error("AWS Route 53 provider JSON response is malformed")]
    MalformedResponse,
}

impl ProviderError {
    pub fn transport_failure(&self) -> Option<TransportFailure> {
        match self {
            Self::Transport(error) => Some(error.failure),
            Self::Model(_)
            | Self::ResponseBinding
            | Self::ProviderRevision
            | Self::MalformedResponse => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ListHealthChecksRequest {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub region: AwsRegion,
    pub page_size: u16,
    pub max_pages: u16,
    pub max_health_checks: u16,
    pub max_response_bytes: usize,
    pub max_requests_per_read: u16,
    pub max_retries: u8,
    pub marker: Option<OpaqueMarker>,
    query_digest: Digest,
    request_digest: Digest,
}

impl ListHealthChecksRequest {
    pub fn new(
        scope: &AwsRoute53HealthScope,
        read_request: &AwsRoute53HealthReadRequest,
        marker: Option<OpaqueMarker>,
    ) -> Result<Self, ModelError> {
        read_request.validate_against(scope)?;
        let query_digest = Digest::from_parts(
            "hartevo-aws-route53-list-health-checks-query/v1",
            &[
                read_request.scope_digest.to_string(),
                read_request.permission_digest.to_string(),
                scope.region.as_str().to_owned(),
                read_request.page_size.to_string(),
                read_request.max_pages.to_string(),
                read_request.max_health_checks.to_string(),
                read_request.max_response_bytes.to_string(),
                read_request.max_requests_per_read.to_string(),
                read_request.max_retries.to_string(),
            ],
        );
        let marker = marker
            .or_else(|| read_request.initial_marker.clone())
            .map(|marker| {
                if marker.is_bound()
                    && marker.binding_digest() != &query_digest
                    && marker.binding_digest() != &read_request.query_digest()
                {
                    return Err(ModelError::ScopeMismatch {
                        field: "Route 53 marker query binding",
                    });
                }
                Ok(marker.bind(&query_digest))
            })
            .transpose()?;
        let request_digest = Digest::from_parts(
            "hartevo-aws-route53-list-health-checks-request/v1",
            &[
                query_digest.to_string(),
                marker
                    .as_ref()
                    .map_or_else(String::new, |marker| marker.token_digest().to_string()),
            ],
        );
        Ok(Self {
            scope_digest: read_request.scope_digest.clone(),
            permission_digest: read_request.permission_digest.clone(),
            region: scope.region.clone(),
            page_size: read_request.page_size,
            max_pages: read_request.max_pages,
            max_health_checks: read_request.max_health_checks,
            max_response_bytes: read_request.max_response_bytes,
            max_requests_per_read: read_request.max_requests_per_read,
            max_retries: read_request.max_retries,
            marker,
            query_digest,
            request_digest,
        })
    }

    pub fn query_digest(&self) -> Digest {
        self.query_digest.clone()
    }

    pub fn request_digest(&self) -> Digest {
        self.request_digest.clone()
    }

    pub fn with_marker(&self, marker: Option<OpaqueMarker>) -> Result<Self, ModelError> {
        let marker = marker
            .map(|marker| bind_marker(marker, &self.query_digest))
            .transpose()?;
        let request_digest = Digest::from_parts(
            "hartevo-aws-route53-list-health-checks-request/v1",
            &[
                self.query_digest.to_string(),
                marker
                    .as_ref()
                    .map_or_else(String::new, |marker| marker.token_digest().to_string()),
            ],
        );
        let mut request = self.clone();
        request.marker = marker;
        request.request_digest = request_digest;
        Ok(request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct GetHealthCheckRequest {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub region: AwsRegion,
    pub health_check_id: HealthCheckId,
    pub max_response_bytes: usize,
    query_digest: Digest,
    request_digest: Digest,
}

impl GetHealthCheckRequest {
    pub fn new(
        scope: &AwsRoute53HealthScope,
        read_request: &AwsRoute53HealthReadRequest,
    ) -> Result<Self, ModelError> {
        read_request.validate_against(scope)?;
        let query_digest = Digest::from_parts(
            "hartevo-aws-route53-get-health-check-query/v1",
            &[
                read_request.scope_digest.to_string(),
                read_request.permission_digest.to_string(),
                scope.region.as_str().to_owned(),
                scope.health_check.id.as_str().to_owned(),
            ],
        );
        let request_digest = query_digest.clone();
        Ok(Self {
            scope_digest: read_request.scope_digest.clone(),
            permission_digest: read_request.permission_digest.clone(),
            region: scope.region.clone(),
            health_check_id: scope.health_check.id.clone(),
            max_response_bytes: read_request.max_response_bytes,
            query_digest,
            request_digest,
        })
    }

    pub fn query_digest(&self) -> Digest {
        self.query_digest.clone()
    }

    pub fn request_digest(&self) -> Digest {
        self.request_digest.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct GetHealthCheckStatusRequest {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub region: AwsRegion,
    pub health_check_id: HealthCheckId,
    pub since: chrono::DateTime<Utc>,
    pub until: chrono::DateTime<Utc>,
    pub max_observations: u16,
    pub max_response_bytes: usize,
    query_digest: Digest,
    request_digest: Digest,
}

impl GetHealthCheckStatusRequest {
    pub fn new(
        scope: &AwsRoute53HealthScope,
        read_request: &AwsRoute53HealthReadRequest,
    ) -> Result<Self, ModelError> {
        read_request.validate_against(scope)?;
        let until = read_request.as_of;
        let since = until - Duration::seconds(read_request.observation_window_seconds);
        let query_digest = Digest::from_parts(
            "hartevo-aws-route53-get-health-check-status-query/v1",
            &[
                read_request.scope_digest.to_string(),
                read_request.permission_digest.to_string(),
                scope.region.as_str().to_owned(),
                scope.health_check.id.as_str().to_owned(),
                since.to_rfc3339(),
                until.to_rfc3339(),
                read_request.max_observations.to_string(),
            ],
        );
        Ok(Self {
            scope_digest: read_request.scope_digest.clone(),
            permission_digest: read_request.permission_digest.clone(),
            region: scope.region.clone(),
            health_check_id: scope.health_check.id.clone(),
            since,
            until,
            max_observations: read_request.max_observations,
            max_response_bytes: read_request.max_response_bytes,
            request_digest: query_digest.clone(),
            query_digest,
        })
    }

    pub fn query_digest(&self) -> Digest {
        self.query_digest.clone()
    }

    pub fn request_digest(&self) -> Digest {
        self.request_digest.clone()
    }
}

fn bind_marker(marker: OpaqueMarker, query_digest: &Digest) -> Result<OpaqueMarker, ModelError> {
    if marker.is_bound() && marker.binding_digest() != query_digest {
        return Err(ModelError::ScopeMismatch {
            field: "Route 53 marker query binding",
        });
    }
    Ok(marker.bind(query_digest))
}

pub trait AwsRoute53HealthTransport: Send + fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_health_checks(
        &mut self,
        request: &ListHealthChecksRequest,
    ) -> Result<ListHealthChecksPage, TransportError>;

    fn get_health_check(
        &mut self,
        request: &GetHealthCheckRequest,
    ) -> Result<GetHealthCheckResponse, TransportError>;

    fn get_health_check_status(
        &mut self,
        request: &GetHealthCheckStatusRequest,
    ) -> Result<GetHealthCheckStatusResponse, TransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportCall {
    pub operation: ReadOperation,
    pub request_digest: Digest,
}

#[derive(Clone, Debug)]
pub struct RecordingAwsRoute53Transport {
    provenance: TransportProvenance,
    list_responses: VecDeque<Result<ListHealthChecksPage, TransportError>>,
    get_responses: VecDeque<Result<GetHealthCheckResponse, TransportError>>,
    status_responses: VecDeque<Result<GetHealthCheckStatusResponse, TransportError>>,
    calls: Vec<TransportCall>,
}

impl Default for RecordingAwsRoute53Transport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}

impl RecordingAwsRoute53Transport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            list_responses: VecDeque::new(),
            get_responses: VecDeque::new(),
            status_responses: VecDeque::new(),
            calls: Vec::new(),
        }
    }

    pub fn push_list_response(&mut self, response: Result<ListHealthChecksPage, TransportError>) {
        self.list_responses.push_back(response);
    }

    pub fn push_get_response(&mut self, response: Result<GetHealthCheckResponse, TransportError>) {
        self.get_responses.push_back(response);
    }

    pub fn push_status_response(
        &mut self,
        response: Result<GetHealthCheckStatusResponse, TransportError>,
    ) {
        self.status_responses.push_back(response);
    }

    pub fn push_list_health_checks_response(
        &mut self,
        response: Result<ListHealthChecksPage, TransportError>,
    ) {
        self.push_list_response(response);
    }

    pub fn push_get_health_check_response(
        &mut self,
        response: Result<GetHealthCheckResponse, TransportError>,
    ) {
        self.push_get_response(response);
    }

    pub fn push_get_health_check_status_response(
        &mut self,
        response: Result<GetHealthCheckStatusResponse, TransportError>,
    ) {
        self.push_status_response(response);
    }

    pub fn calls(&self) -> &[TransportCall] {
        &self.calls
    }

    fn pop<T>(queue: &mut VecDeque<Result<T, TransportError>>) -> Result<T, TransportError> {
        queue
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::malformed()))
    }
}

impl AwsRoute53HealthTransport for RecordingAwsRoute53Transport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn list_health_checks(
        &mut self,
        request: &ListHealthChecksRequest,
    ) -> Result<ListHealthChecksPage, TransportError> {
        self.calls.push(TransportCall {
            operation: ReadOperation::ListHealthChecks,
            request_digest: request.request_digest(),
        });
        Self::pop(&mut self.list_responses)
    }

    fn get_health_check(
        &mut self,
        request: &GetHealthCheckRequest,
    ) -> Result<GetHealthCheckResponse, TransportError> {
        self.calls.push(TransportCall {
            operation: ReadOperation::GetHealthCheck,
            request_digest: request.request_digest(),
        });
        Self::pop(&mut self.get_responses)
    }

    fn get_health_check_status(
        &mut self,
        request: &GetHealthCheckStatusRequest,
    ) -> Result<GetHealthCheckStatusResponse, TransportError> {
        self.calls.push(TransportCall {
            operation: ReadOperation::GetHealthCheckStatus,
            request_digest: request.request_digest(),
        });
        Self::pop(&mut self.status_responses)
    }
}

#[derive(Clone, Debug)]
pub struct FixtureAwsRoute53Transport {
    inner: RecordingAwsRoute53Transport,
}

impl Default for FixtureAwsRoute53Transport {
    fn default() -> Self {
        Self::new()
    }
}

impl FixtureAwsRoute53Transport {
    pub fn new() -> Self {
        Self {
            inner: RecordingAwsRoute53Transport::new(TransportProvenance::Fixture),
        }
    }

    pub fn for_scope(
        scope: &AwsRoute53HealthScope,
        at: chrono::DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        seeded_transport(scope, at, TransportProvenance::Fixture).map(|inner| Self { inner })
    }

    pub fn push_list_response(&mut self, response: Result<ListHealthChecksPage, TransportError>) {
        self.inner.push_list_response(response);
    }

    pub fn push_get_response(&mut self, response: Result<GetHealthCheckResponse, TransportError>) {
        self.inner.push_get_response(response);
    }

    pub fn push_status_response(
        &mut self,
        response: Result<GetHealthCheckStatusResponse, TransportError>,
    ) {
        self.inner.push_status_response(response);
    }

    pub fn calls(&self) -> &[TransportCall] {
        self.inner.calls()
    }
}

impl AwsRoute53HealthTransport for FixtureAwsRoute53Transport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn list_health_checks(
        &mut self,
        request: &ListHealthChecksRequest,
    ) -> Result<ListHealthChecksPage, TransportError> {
        self.inner.list_health_checks(request)
    }

    fn get_health_check(
        &mut self,
        request: &GetHealthCheckRequest,
    ) -> Result<GetHealthCheckResponse, TransportError> {
        self.inner.get_health_check(request)
    }

    fn get_health_check_status(
        &mut self,
        request: &GetHealthCheckStatusRequest,
    ) -> Result<GetHealthCheckStatusResponse, TransportError> {
        self.inner.get_health_check_status(request)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackAwsRoute53Transport {
    inner: RecordingAwsRoute53Transport,
}

impl Default for LoopbackAwsRoute53Transport {
    fn default() -> Self {
        Self::new()
    }
}

impl LoopbackAwsRoute53Transport {
    pub fn new() -> Self {
        Self {
            inner: RecordingAwsRoute53Transport::new(TransportProvenance::Loopback),
        }
    }

    pub fn for_scope(
        scope: &AwsRoute53HealthScope,
        at: chrono::DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        seeded_transport(scope, at, TransportProvenance::Loopback).map(|inner| Self { inner })
    }

    pub fn push_list_response(&mut self, response: Result<ListHealthChecksPage, TransportError>) {
        self.inner.push_list_response(response);
    }

    pub fn push_get_response(&mut self, response: Result<GetHealthCheckResponse, TransportError>) {
        self.inner.push_get_response(response);
    }

    pub fn push_status_response(
        &mut self,
        response: Result<GetHealthCheckStatusResponse, TransportError>,
    ) {
        self.inner.push_status_response(response);
    }

    pub fn calls(&self) -> &[TransportCall] {
        self.inner.calls()
    }
}

impl AwsRoute53HealthTransport for LoopbackAwsRoute53Transport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn list_health_checks(
        &mut self,
        request: &ListHealthChecksRequest,
    ) -> Result<ListHealthChecksPage, TransportError> {
        self.inner.list_health_checks(request)
    }

    fn get_health_check(
        &mut self,
        request: &GetHealthCheckRequest,
    ) -> Result<GetHealthCheckResponse, TransportError> {
        self.inner.get_health_check(request)
    }

    fn get_health_check_status(
        &mut self,
        request: &GetHealthCheckStatusRequest,
    ) -> Result<GetHealthCheckStatusResponse, TransportError> {
        self.inner.get_health_check_status(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvAwsRoute53Transport;

impl AwsRoute53HealthTransport for BlockedEnvAwsRoute53Transport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_health_checks(
        &mut self,
        _request: &ListHealthChecksRequest,
    ) -> Result<ListHealthChecksPage, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn get_health_check(
        &mut self,
        _request: &GetHealthCheckRequest,
    ) -> Result<GetHealthCheckResponse, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn get_health_check_status(
        &mut self,
        _request: &GetHealthCheckStatusRequest,
    ) -> Result<GetHealthCheckStatusResponse, TransportError> {
        Err(TransportError::blocked_env())
    }
}

fn seeded_transport(
    scope: &AwsRoute53HealthScope,
    at: chrono::DateTime<Utc>,
    provenance: TransportProvenance,
) -> Result<RecordingAwsRoute53Transport, ModelError> {
    let configuration = match &scope.health_check.target {
        HealthCheckTarget::Endpoint { .. } => HealthCheckConfiguration::new(
            HealthCheckType::Https,
            scope.health_check.target.clone(),
            Some(443),
            Option::<String>::None,
            30,
            3,
            [scope.region.clone()],
            false,
            true,
            0,
        )?,
        HealthCheckTarget::CloudWatchAlarm { .. } => HealthCheckConfiguration::new(
            HealthCheckType::CloudWatchMetric,
            scope.health_check.target.clone(),
            None,
            Option::<String>::None,
            30,
            3,
            [scope.region.clone()],
            false,
            false,
            0,
        )?,
        HealthCheckTarget::Calculated { child_count } => HealthCheckConfiguration::new(
            HealthCheckType::Calculated,
            scope.health_check.target.clone(),
            None,
            Option::<String>::None,
            30,
            3,
            [scope.region.clone()],
            false,
            false,
            *child_count,
        )?,
    };
    let summary = HealthCheckSummary::new(
        scope.health_check.id.clone(),
        scope.health_check.revision,
        "fixture-caller-reference",
        configuration,
    )?;
    let read_request =
        AwsRoute53HealthReadRequest::new(scope, crate::model::ReadBounds::default(), at, None)?;
    let list_request = ListHealthChecksRequest::new(scope, &read_request, None)?;
    let list_page = ListHealthChecksPage::new(
        &list_request,
        1,
        vec![summary.clone()],
        None,
        512,
        ProviderRevision::new(AWS_ROUTE53_HEALTH_API_REVISION)?,
    )?;
    let get_request = GetHealthCheckRequest::new(scope, &read_request)?;
    let get_response = GetHealthCheckResponse::new(
        &get_request,
        summary,
        512,
        ProviderRevision::new(AWS_ROUTE53_HEALTH_API_REVISION)?,
    )?;
    let status_request = GetHealthCheckStatusRequest::new(scope, &read_request)?;
    let observation = HealthCheckObservation::new(
        scope.region.clone(),
        "fixture-checker",
        ObservationStatus::Healthy,
        at - Duration::seconds(30),
        Option::<String>::None,
    )?;
    let status_response = GetHealthCheckStatusResponse::new(
        &status_request,
        vec![observation],
        512,
        ProviderRevision::new(AWS_ROUTE53_HEALTH_API_REVISION)?,
    )?;
    let mut transport = RecordingAwsRoute53Transport::new(provenance);
    transport.push_list_response(Ok(list_page));
    transport.push_get_response(Ok(get_response));
    transport.push_status_response(Ok(status_response));
    Ok(transport)
}

#[derive(Clone)]
pub struct AwsRoute53Provider<T = BlockedEnvAwsRoute53Transport> {
    transport: T,
    identity: AwsRoute53ProviderIdentity,
}

impl<T: fmt::Debug> fmt::Debug for AwsRoute53Provider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsRoute53Provider")
            .field("transport", &self.transport)
            .field("identity", &self.identity)
            .finish()
    }
}

impl Default for AwsRoute53Provider<BlockedEnvAwsRoute53Transport> {
    fn default() -> Self {
        Self::new(BlockedEnvAwsRoute53Transport).expect("static provider definition")
    }
}

impl<T: AwsRoute53HealthTransport> AwsRoute53Provider<T> {
    pub fn new(transport: T) -> Result<Self, ProviderDefinitionError> {
        let identity = AwsRoute53ProviderIdentity::for_provenance(transport.provenance())?;
        let definition = AwsRoute53ProviderDefinition::from_identity(&identity)?;
        definition.validate()?;
        Ok(Self {
            transport,
            identity,
        })
    }

    pub fn identity(&self) -> &AwsRoute53ProviderIdentity {
        &self.identity
    }

    pub fn definition(&self) -> AwsRoute53ProviderDefinition {
        AwsRoute53ProviderDefinition::from_identity(&self.identity)
            .expect("identity was validated during provider construction")
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn list_health_checks(
        &mut self,
        request: &ListHealthChecksRequest,
    ) -> Result<ListHealthChecksPage, ProviderError> {
        let page = self.transport.list_health_checks(request)?;
        if page.provider_revision != self.identity.api_revision {
            return Err(ProviderError::ProviderRevision);
        }
        page.validate_for(request)
            .map_err(|_| ProviderError::ResponseBinding)?;
        Ok(page)
    }

    pub fn get_health_check(
        &mut self,
        request: &GetHealthCheckRequest,
    ) -> Result<GetHealthCheckResponse, ProviderError> {
        let response = self.transport.get_health_check(request)?;
        if response.provider_revision != self.identity.api_revision {
            return Err(ProviderError::ProviderRevision);
        }
        response
            .validate_for(request)
            .map_err(|_| ProviderError::ResponseBinding)?;
        Ok(response)
    }

    pub fn get_health_check_status(
        &mut self,
        request: &GetHealthCheckStatusRequest,
    ) -> Result<GetHealthCheckStatusResponse, ProviderError> {
        let response = self.transport.get_health_check_status(request)?;
        if response.provider_revision != self.identity.api_revision {
            return Err(ProviderError::ProviderRevision);
        }
        response
            .validate_for(request)
            .map_err(|_| ProviderError::ResponseBinding)?;
        Ok(response)
    }

    pub fn parse_list_health_checks_json(
        &self,
        request: &ListHealthChecksRequest,
        page_number: u16,
        body: &[u8],
    ) -> Result<ListHealthChecksPage, ProviderError> {
        if body.len() > request.max_response_bytes {
            return Err(ProviderError::Model(ModelError::TooLarge {
                field: "Route 53 response",
            }));
        }
        let value =
            serde_json::from_slice::<Value>(body).map_err(|_| ProviderError::MalformedResponse)?;
        let entries = value
            .get("HealthChecks")
            .and_then(Value::as_array)
            .ok_or(ProviderError::MalformedResponse)?;
        let mut health_checks = Vec::with_capacity(entries.len());
        for entry in entries {
            health_checks.push(parse_summary(entry, &request.region)?);
        }
        let next_marker = value
            .get("NextMarker")
            .and_then(Value::as_str)
            .map(OpaqueMarker::new)
            .transpose()
            .map_err(ProviderError::Model)?;
        ListHealthChecksPage::new(
            request,
            page_number,
            health_checks,
            next_marker,
            body.len().max(1),
            self.identity.api_revision.clone(),
        )
        .map_err(ProviderError::Model)
    }

    pub fn parse_get_health_check_json(
        &self,
        request: &GetHealthCheckRequest,
        body: &[u8],
    ) -> Result<GetHealthCheckResponse, ProviderError> {
        if body.len() > request.max_response_bytes {
            return Err(ProviderError::Model(ModelError::TooLarge {
                field: "Route 53 response",
            }));
        }
        let value =
            serde_json::from_slice::<Value>(body).map_err(|_| ProviderError::MalformedResponse)?;
        let health_check = parse_summary(&value, &request.region)?;
        GetHealthCheckResponse::new(
            request,
            health_check,
            body.len().max(1),
            self.identity.api_revision.clone(),
        )
        .map_err(ProviderError::Model)
    }

    pub fn parse_get_health_check_status_json(
        &self,
        request: &GetHealthCheckStatusRequest,
        body: &[u8],
    ) -> Result<GetHealthCheckStatusResponse, ProviderError> {
        if body.len() > request.max_response_bytes {
            return Err(ProviderError::Model(ModelError::TooLarge {
                field: "Route 53 response",
            }));
        }
        let value =
            serde_json::from_slice::<Value>(body).map_err(|_| ProviderError::MalformedResponse)?;
        let entries = value
            .get("HealthCheckObservations")
            .and_then(Value::as_array)
            .ok_or(ProviderError::MalformedResponse)?;
        let mut observations = Vec::with_capacity(entries.len());
        for entry in entries {
            let region = entry
                .get("Region")
                .and_then(Value::as_str)
                .map(AwsRegion::new)
                .transpose()
                .map_err(ProviderError::Model)?
                .ok_or(ProviderError::MalformedResponse)?;
            let checker = entry
                .get("IPAddress")
                .and_then(Value::as_str)
                .ok_or(ProviderError::MalformedResponse)?;
            let report = entry
                .get("StatusReport")
                .and_then(Value::as_object)
                .ok_or(ProviderError::MalformedResponse)?;
            let status_text = report
                .get("Status")
                .and_then(Value::as_str)
                .ok_or(ProviderError::MalformedResponse)?;
            let checked_at = report
                .get("CheckedTime")
                .and_then(Value::as_str)
                .ok_or(ProviderError::MalformedResponse)?
                .parse()
                .map_err(|_| ProviderError::MalformedResponse)?;
            let status = ObservationStatus::parse_api(status_text).map_err(ProviderError::Model)?;
            let failure_detail = if matches!(status, ObservationStatus::Unhealthy) {
                Some(serde_json::to_string(report).map_err(|_| ProviderError::MalformedResponse)?)
            } else {
                None
            };
            observations.push(
                HealthCheckObservation::new(region, checker, status, checked_at, failure_detail)
                    .map_err(ProviderError::Model)?,
            );
        }
        GetHealthCheckStatusResponse::new(
            request,
            observations,
            body.len().max(1),
            self.identity.api_revision.clone(),
        )
        .map_err(ProviderError::Model)
    }
}

fn parse_summary(
    value: &Value,
    default_region: &AwsRegion,
) -> Result<HealthCheckSummary, ProviderError> {
    let id = value
        .get("Id")
        .and_then(Value::as_str)
        .map(HealthCheckId::new)
        .transpose()
        .map_err(ProviderError::Model)?
        .ok_or(ProviderError::MalformedResponse)?;
    let caller_reference = value
        .get("CallerReference")
        .and_then(Value::as_str)
        .ok_or(ProviderError::MalformedResponse)?;
    let revision = value
        .get("HealthCheckVersion")
        .and_then(Value::as_u64)
        .map(Revision::new)
        .transpose()
        .map_err(ProviderError::Model)?
        .unwrap_or(Revision::new(1).map_err(ProviderError::Model)?);
    let config_value = value
        .get("HealthCheckConfig")
        .ok_or(ProviderError::MalformedResponse)?;
    let configuration = parse_configuration(config_value, default_region)?;
    HealthCheckSummary::new(id, revision, caller_reference, configuration)
        .map_err(ProviderError::Model)
}

fn parse_configuration(
    value: &Value,
    default_region: &AwsRegion,
) -> Result<HealthCheckConfiguration, ProviderError> {
    let check_type = value
        .get("Type")
        .and_then(Value::as_str)
        .ok_or(ProviderError::MalformedResponse)
        .and_then(|value| HealthCheckType::parse_api(value).map_err(ProviderError::Model))?;
    let regions = value
        .get("Regions")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .map(|region| {
                    region
                        .as_str()
                        .ok_or(ProviderError::MalformedResponse)
                        .and_then(|region| AwsRegion::new(region).map_err(ProviderError::Model))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_else(|| vec![default_region.clone()]);
    let interval = value
        .get("RequestInterval")
        .and_then(Value::as_u64)
        .unwrap_or(30) as u16;
    let threshold = value
        .get("FailureThreshold")
        .and_then(Value::as_u64)
        .unwrap_or(3) as u16;
    let port = value
        .get("Port")
        .and_then(Value::as_u64)
        .map(|port| port as u16);
    let path = value.get("ResourcePath").and_then(Value::as_str);
    let measure_latency = value
        .get("MeasureLatency")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let enable_sni = value
        .get("EnableSNI")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let (target, child_count) = match check_type {
        HealthCheckType::Calculated => {
            let child_count = value
                .get("ChildHealthChecks")
                .and_then(Value::as_array)
                .map_or(1, |children| children.len() as u16);
            (
                HealthCheckTarget::calculated(child_count).map_err(ProviderError::Model)?,
                child_count,
            )
        }
        HealthCheckType::CloudWatchMetric => {
            let alarm = value
                .get("AlarmIdentifier")
                .and_then(Value::as_object)
                .ok_or(ProviderError::MalformedResponse)?;
            let name = alarm
                .get("Name")
                .and_then(Value::as_str)
                .ok_or(ProviderError::MalformedResponse)?;
            let region = alarm
                .get("Region")
                .and_then(Value::as_str)
                .map(AwsRegion::new)
                .transpose()
                .map_err(ProviderError::Model)?
                .unwrap_or_else(|| default_region.clone());
            (
                HealthCheckTarget::cloudwatch_alarm(name, region).map_err(ProviderError::Model)?,
                0,
            )
        }
        HealthCheckType::Http | HealthCheckType::Https | HealthCheckType::Tcp => {
            let endpoint = value
                .get("IPAddress")
                .or_else(|| value.get("FullyQualifiedDomainName"))
                .and_then(Value::as_str)
                .ok_or(ProviderError::MalformedResponse)?;
            (
                HealthCheckTarget::endpoint(endpoint).map_err(ProviderError::Model)?,
                0,
            )
        }
    };
    HealthCheckConfiguration::new(
        check_type,
        target,
        port,
        path,
        interval,
        threshold,
        regions,
        measure_latency,
        enable_sni,
        child_count,
    )
    .map_err(ProviderError::Model)
}

pub type AwsRoute53HealthProvider<T = BlockedEnvAwsRoute53Transport> = AwsRoute53Provider<T>;
pub type AwsRoute53HealthProviderIdentity = AwsRoute53ProviderIdentity;
pub type AwsRoute53HealthProviderDefinition = AwsRoute53ProviderDefinition;
pub type ProviderProvenance = TransportProvenance;
pub type BlockedEnvTransport = BlockedEnvAwsRoute53Transport;
pub type FixtureTransport = FixtureAwsRoute53Transport;
pub type LoopbackTransport = LoopbackAwsRoute53Transport;
pub type RecordingTransport = RecordingAwsRoute53Transport;
pub type FakeAwsRoute53Transport = FixtureAwsRoute53Transport;

pub fn is_access_loss(error: &TransportError) -> bool {
    matches!(
        error.failure,
        TransportFailure::Unauthorized
            | TransportFailure::AccessDenied
            | TransportFailure::NotFound
    )
}

pub fn is_throttle(error: &TransportError) -> bool {
    matches!(error.failure, TransportFailure::Throttled)
}

pub fn is_timeout(error: &TransportError) -> bool {
    matches!(error.failure, TransportFailure::Timeout)
}
