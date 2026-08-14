//! Deterministic transports for the Layer-1 Workday provider.
//!
//! There is intentionally no live HTTP implementation in this root. The
//! request records the official read seam and bounded metadata; a later host
//! layer may supply credential resolution and native transport authority.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::model::{
    ApiVersion, Digest, ProviderErrorKind, ProviderRevision, ReadBounds, SecretReference, TenantId,
    TransportProvenance, WorkdayEndpoint, WorkdayEventPayload, WorkdayReadRequest,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("Workday transport returned {kind:?}")]
pub struct TransportError {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub blocked_env: bool,
    diagnostic_digest: Digest,
}

impl TransportError {
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        let retryable = matches!(
            kind,
            ProviderErrorKind::RateLimited
                | ProviderErrorKind::ServerFailure
                | ProviderErrorKind::Timeout
        );
        Self {
            kind,
            status_code,
            retryable,
            blocked_env: kind == ProviderErrorKind::BlockedEnv,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    pub fn blocked_env() -> Self {
        Self::new(ProviderErrorKind::BlockedEnv, None, "BLOCKED_ENV")
    }

    pub fn access_denied() -> Self {
        Self::new(ProviderErrorKind::AccessDenied, Some(403), "access-denied")
    }

    pub fn not_found() -> Self {
        Self::new(ProviderErrorKind::NotFound, Some(404), "not-found")
    }

    pub fn server_failure() -> Self {
        Self::new(
            ProviderErrorKind::ServerFailure,
            Some(500),
            "server-failure",
        )
    }

    pub fn diagnostic_digest(&self) -> &Digest {
        &self.diagnostic_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkdayHttpRequest {
    pub method: &'static str,
    pub endpoint: WorkdayEndpoint,
    pub tenant_id: TenantId,
    pub api_version: ApiVersion,
    pub path_and_query: String,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub query_digest: Digest,
    pub bounds: ReadBounds,
    pub secret_reference_digest: Digest,
    pub credential_revision: crate::model::Revision,
}

impl WorkdayHttpRequest {
    pub(crate) fn from_read_request(
        request: &WorkdayReadRequest,
        secret: &SecretReference,
    ) -> Self {
        Self {
            method: "GET",
            endpoint: request.endpoint(),
            tenant_id: request.tenant_id().clone(),
            api_version: request.api_version().clone(),
            path_and_query: request.path_and_query(),
            scope_digest: request.scope_digest().clone(),
            consent_digest: request.consent_digest().clone(),
            query_digest: request.query_digest().clone(),
            bounds: request.bounds().clone(),
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
        }
    }
}

pub struct WorkdayHttpResponse {
    pub status_code: u16,
    pub api_version: ApiVersion,
    pub provider_revision: ProviderRevision,
    pub response_size: usize,
    pub observed_at: DateTime<Utc>,
    pub body: Option<WorkdayEventPayload>,
    pub response_digest: Digest,
}

impl fmt::Debug for WorkdayHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkdayHttpResponse")
            .field("status_code", &self.status_code)
            .field("api_version", &self.api_version)
            .field("provider_revision", &self.provider_revision)
            .field("response_size", &self.response_size)
            .field("observed_at", &self.observed_at)
            .field("body_present", &self.body.is_some())
            .field("response_digest", &self.response_digest)
            .finish()
    }
}

impl WorkdayHttpResponse {
    pub fn new(
        status_code: u16,
        api_version: ApiVersion,
        provider_revision: ProviderRevision,
        response_size: usize,
        observed_at: DateTime<Utc>,
        body: Option<WorkdayEventPayload>,
        response_digest: Digest,
    ) -> Self {
        Self {
            status_code,
            api_version,
            provider_revision,
            response_size,
            observed_at,
            body,
            response_digest,
        }
    }

    pub fn success(
        payload: WorkdayEventPayload,
        api_version: ApiVersion,
        provider_revision: ProviderRevision,
        response_size: usize,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let response_digest = Digest::from_fields(
            "workday-provider-response/v1",
            &[
                format!("{payload:?}"),
                response_size.to_string(),
                observed_at.to_rfc3339(),
            ],
        );
        Self::new(
            200,
            api_version,
            provider_revision,
            response_size,
            observed_at,
            Some(payload),
            response_digest,
        )
    }
}

pub trait WorkdayTransport: fmt::Debug {
    fn read(&mut self, request: &WorkdayHttpRequest)
    -> Result<WorkdayHttpResponse, TransportError>;

    fn provenance(&self) -> TransportProvenance;
}

#[derive(Debug, Default)]
pub struct RecordingWorkdayTransport {
    responses: VecDeque<Result<WorkdayHttpResponse, TransportError>>,
    requests: Vec<WorkdayHttpRequest>,
}

impl RecordingWorkdayTransport {
    pub fn push_response(&mut self, response: Result<WorkdayHttpResponse, TransportError>) {
        self.responses.push_back(response);
    }

    pub fn requests(&self) -> &[WorkdayHttpRequest] {
        &self.requests
    }

    pub fn call_count(&self) -> usize {
        self.requests.len()
    }
}

impl WorkdayTransport for RecordingWorkdayTransport {
    fn read(
        &mut self,
        request: &WorkdayHttpRequest,
    ) -> Result<WorkdayHttpResponse, TransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::blocked_env()))
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }
}

pub type FakeWorkdayTransport = RecordingWorkdayTransport;

#[derive(Debug)]
pub struct FixtureWorkdayTransport {
    response: WorkdayHttpResponse,
    requests: Vec<WorkdayHttpRequest>,
}

impl FixtureWorkdayTransport {
    pub fn new(response: WorkdayHttpResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    pub fn from_payload(
        payload: WorkdayEventPayload,
        api_version: ApiVersion,
        provider_revision: ProviderRevision,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self::new(WorkdayHttpResponse::success(
            payload,
            api_version,
            provider_revision,
            512,
            observed_at,
        ))
    }

    pub fn requests(&self) -> &[WorkdayHttpRequest] {
        &self.requests
    }
}

impl WorkdayTransport for FixtureWorkdayTransport {
    fn read(
        &mut self,
        request: &WorkdayHttpRequest,
    ) -> Result<WorkdayHttpResponse, TransportError> {
        self.requests.push(request.clone());
        Ok(WorkdayHttpResponse {
            status_code: self.response.status_code,
            api_version: self.response.api_version.clone(),
            provider_revision: self.response.provider_revision.clone(),
            response_size: self.response.response_size,
            observed_at: self.response.observed_at,
            body: self.response.body.clone(),
            response_digest: self.response.response_digest.clone(),
        })
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }
}

#[derive(Debug)]
pub struct LoopbackWorkdayTransport {
    fixture: FixtureWorkdayTransport,
}

impl LoopbackWorkdayTransport {
    pub fn from_payload(
        payload: WorkdayEventPayload,
        api_version: ApiVersion,
        provider_revision: ProviderRevision,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            fixture: FixtureWorkdayTransport::from_payload(
                payload,
                api_version,
                provider_revision,
                observed_at,
            ),
        }
    }

    pub fn requests(&self) -> &[WorkdayHttpRequest] {
        self.fixture.requests()
    }
}

impl WorkdayTransport for LoopbackWorkdayTransport {
    fn read(
        &mut self,
        request: &WorkdayHttpRequest,
    ) -> Result<WorkdayHttpResponse, TransportError> {
        self.fixture.read(request)
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvWorkdayTransport;

impl WorkdayTransport for BlockedEnvWorkdayTransport {
    fn read(
        &mut self,
        _request: &WorkdayHttpRequest,
    ) -> Result<WorkdayHttpResponse, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }
}
