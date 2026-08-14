//! Bounded Amplitude Dashboard REST transport/provider boundary.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    AmplitudeExperimentResultRead, AmplitudeExperimentScope, AmplitudeRegistration,
    AmplitudeResultError, AmplitudeResultPage, Digest, MAX_RESPONSE_BYTES, TransportProvenance,
    TransportStatus, canonical_digest, sha256_digest,
};

pub use crate::AmplitudeTransportError;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AmplitudeHttpMethod {
    Get,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmplitudeHttpRequest {
    pub method: AmplitudeHttpMethod,
    pub host: String,
    pub path: String,
    pub chart_id: String,
    pub page: u16,
    pub page_size: u16,
    pub project_id: String,
    pub experiment_id: String,
    pub segment_id: String,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
}

impl AmplitudeHttpRequest {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmplitudeHttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub provider_request_id: Option<String>,
    pub cost_units: u32,
    pub observed_at: DateTime<Utc>,
}

impl AmplitudeHttpResponse {
    /// Build a deterministic JSON response for a fixture or loopback transport.
    ///
    /// # Panics
    ///
    /// Panics only if the supplied `Serialize` implementation refuses to
    /// serialize. Contract fixture types are infallible here.
    #[must_use]
    pub fn json<T: Serialize>(
        status: u16,
        value: &T,
        observed_at: DateTime<Utc>,
        provider_request_id: Option<String>,
        cost_units: u32,
    ) -> Self {
        let body = serde_json::to_vec(value).expect("Amplitude fixture response serializes");
        Self {
            status,
            body,
            provider_request_id,
            cost_units,
            observed_at,
        }
    }
}

/// A deliberately small transport trait. Native HTTPS is a Layer-2 seam; the
/// Layer-1 provider only sees bounded typed requests and responses.
pub trait AmplitudeTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn execute(
        &mut self,
        request: &AmplitudeHttpRequest,
    ) -> Result<AmplitudeHttpResponse, AmplitudeTransportError>;
}

#[derive(Clone, Debug)]
pub struct FixtureAmplitudeTransport {
    response: AmplitudeHttpResponse,
}

impl FixtureAmplitudeTransport {
    #[must_use]
    pub fn new(response: AmplitudeHttpResponse) -> Self {
        Self { response }
    }
}

impl AmplitudeTransport for FixtureAmplitudeTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        _request: &AmplitudeHttpRequest,
    ) -> Result<AmplitudeHttpResponse, AmplitudeTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct FakeAmplitudeTransport {
    response: AmplitudeHttpResponse,
}

impl FakeAmplitudeTransport {
    #[must_use]
    pub fn new(response: AmplitudeHttpResponse) -> Self {
        Self { response }
    }
}

impl AmplitudeTransport for FakeAmplitudeTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fake
    }

    fn execute(
        &mut self,
        _request: &AmplitudeHttpRequest,
    ) -> Result<AmplitudeHttpResponse, AmplitudeTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct RecordedAmplitudeTransport {
    response: AmplitudeHttpResponse,
    requests: Vec<AmplitudeHttpRequest>,
}

impl RecordedAmplitudeTransport {
    #[must_use]
    pub fn new(response: AmplitudeHttpResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[AmplitudeHttpRequest] {
        &self.requests
    }
}

impl AmplitudeTransport for RecordedAmplitudeTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &AmplitudeHttpRequest,
    ) -> Result<AmplitudeHttpResponse, AmplitudeTransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackAmplitudeTransport {
    response: AmplitudeHttpResponse,
    requests: Vec<AmplitudeHttpRequest>,
}

impl LoopbackAmplitudeTransport {
    #[must_use]
    pub fn new(response: AmplitudeHttpResponse) -> Self {
        Self {
            response,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[AmplitudeHttpRequest] {
        &self.requests
    }
}

impl AmplitudeTransport for LoopbackAmplitudeTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        request: &AmplitudeHttpRequest,
    ) -> Result<AmplitudeHttpResponse, AmplitudeTransportError> {
        self.requests.push(request.clone());
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvAmplitudeTransport;

impl AmplitudeTransport for BlockedEnvAmplitudeTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &AmplitudeHttpRequest,
    ) -> Result<AmplitudeHttpResponse, AmplitudeTransportError> {
        Err(AmplitudeTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug)]
pub struct AmplitudeProviderRead {
    pub page: AmplitudeResultPage,
    pub request: AmplitudeHttpRequest,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub provider_request_id: Option<String>,
    pub cost_units: u32,
    pub observed_at: DateTime<Utc>,
    pub provenance: TransportProvenance,
}

#[derive(Debug)]
pub struct AmplitudeProvider<T: AmplitudeTransport> {
    scope: AmplitudeExperimentScope,
    transport: T,
    registration: AmplitudeRegistration,
}

impl<T: AmplitudeTransport> AmplitudeProvider<T> {
    pub fn new(
        scope: AmplitudeExperimentScope,
        transport: T,
    ) -> Result<Self, AmplitudeResultError> {
        let registration = AmplitudeRegistration::bind(&scope, crate::contract_digest());
        Self::with_registration(scope, transport, registration)
    }

    pub fn with_registration(
        scope: AmplitudeExperimentScope,
        transport: T,
        registration: AmplitudeRegistration,
    ) -> Result<Self, AmplitudeResultError> {
        registration.validate(&scope)?;
        Ok(Self {
            scope,
            transport,
            registration,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &AmplitudeExperimentScope {
        &self.scope
    }

    #[must_use]
    pub fn registration(&self) -> &AmplitudeRegistration {
        &self.registration
    }

    #[must_use]
    pub fn transport_provenance(&self) -> TransportProvenance {
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

    pub fn read_result_page(
        &mut self,
        operation: &AmplitudeExperimentResultRead,
    ) -> Result<AmplitudeProviderRead, AmplitudeResultError> {
        self.registration.validate(&self.scope)?;
        let request = self.build_request(operation)?;
        let provenance = self.transport.provenance();
        let response = self
            .transport
            .execute(&request)
            .map_err(AmplitudeResultError::Transport)?;
        let response_bytes = response.body.len();
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(AmplitudeResultError::BoundExceeded {
                label: "response bytes",
                maximum: MAX_RESPONSE_BYTES,
            });
        }
        Self::validate_status(response.status)?;
        let page: AmplitudeResultPage = serde_json::from_slice(&response.body)
            .map_err(|_| AmplitudeResultError::MalformedResponse)?;
        page.validate_bounds()?;
        self.validate_page(operation, &page)?;
        Ok(AmplitudeProviderRead {
            page,
            request,
            response_digest: sha256_digest(&response.body),
            response_bytes,
            provider_request_id: sanitize_request_id(response.provider_request_id),
            cost_units: response.cost_units.max(1),
            observed_at: response.observed_at,
            provenance,
        })
    }

    pub fn revoke(
        &mut self,
        reason: impl Into<String>,
    ) -> Result<crate::RegistrationRevocationReceipt, AmplitudeResultError> {
        self.registration.revoke(reason)
    }

    pub fn restore(&mut self) -> Result<(), AmplitudeResultError> {
        self.registration.restore()
    }

    fn build_request(
        &self,
        operation: &AmplitudeExperimentResultRead,
    ) -> Result<AmplitudeHttpRequest, AmplitudeResultError> {
        let path = format!("/api/3/chart/{}/csv", operation.chart_id());
        Ok(AmplitudeHttpRequest {
            method: AmplitudeHttpMethod::Get,
            host: self.scope.api().host().to_owned(),
            path,
            chart_id: operation.chart_id().to_owned(),
            page: operation.page(),
            page_size: operation.page_size(),
            project_id: self.scope.project().id().to_owned(),
            experiment_id: self.scope.experiment().id().to_owned(),
            segment_id: self.scope.segment().id().to_owned(),
            scope_digest: self.scope.digest(),
            secret_reference_digest: self.scope.secret_reference().digest(),
        })
    }

    fn validate_page(
        &self,
        operation: &AmplitudeExperimentResultRead,
        page: &AmplitudeResultPage,
    ) -> Result<(), AmplitudeResultError> {
        if page.page != operation.page()
            || page.page_size != operation.page_size()
            || page.project_id != self.scope.project().id()
            || page.experiment_id != self.scope.experiment().id()
            || page.segment_id != self.scope.segment().id()
            || page.segment_revision != self.scope.segment().revision()
            || page.exposure_window_start != self.scope.exposure_window().start()
            || page.exposure_window_end != self.scope.exposure_window().end()
        {
            return Err(AmplitudeResultError::InvalidProviderResponse(
                "scope or pagination fence",
            ));
        }
        for variant in &page.variants {
            if !self
                .scope
                .contains_variant(&variant.variant_id, variant.variant_revision)
            {
                return Err(AmplitudeResultError::InvalidProviderResponse(
                    "variant revision fence",
                ));
            }
            if variant.metrics.len() != 1 {
                return Err(AmplitudeResultError::InvalidProviderResponse(
                    "metric allowlist",
                ));
            }
            let metric = &variant.metrics[0];
            if metric.metric_id != self.scope.metric().id()
                || metric.metric_revision != self.scope.metric().revision()
            {
                return Err(AmplitudeResultError::InvalidProviderResponse(
                    "metric revision fence",
                ));
            }
        }
        Ok(())
    }

    fn validate_status(status: u16) -> Result<(), AmplitudeResultError> {
        match status {
            200..=299 => Ok(()),
            401 | 403 => Err(AmplitudeResultError::Transport(
                AmplitudeTransportError::AccessDenied { status },
            )),
            404 => Err(AmplitudeResultError::Transport(
                AmplitudeTransportError::NotFound,
            )),
            408 | 504 => Err(AmplitudeResultError::Transport(
                AmplitudeTransportError::Timeout,
            )),
            429 => Err(AmplitudeResultError::Transport(
                AmplitudeTransportError::RateLimited,
            )),
            _ => Err(AmplitudeResultError::Transport(
                AmplitudeTransportError::ProviderError { status },
            )),
        }
    }
}

fn sanitize_request_id(value: Option<String>) -> Option<String> {
    value.filter(|value| {
        !value.is_empty()
            && value.len() <= 128
            && value.trim() == value
            && !value.chars().any(char::is_control)
    })
}

#[allow(dead_code)]
fn _status_for_error(error: &AmplitudeTransportError) -> TransportStatus {
    match error {
        AmplitudeTransportError::BlockedEnv => TransportStatus::BlockedEnv,
        AmplitudeTransportError::AccessDenied { .. } => TransportStatus::AccessDenied,
        AmplitudeTransportError::NotFound => TransportStatus::NotFound,
        AmplitudeTransportError::RateLimited => TransportStatus::RateLimited,
        AmplitudeTransportError::ProviderError { .. } => TransportStatus::ProviderError,
        AmplitudeTransportError::Timeout => TransportStatus::Timeout,
        AmplitudeTransportError::InvalidDiagnostic => TransportStatus::ProviderError,
    }
}
