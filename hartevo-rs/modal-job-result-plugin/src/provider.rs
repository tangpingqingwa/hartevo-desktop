//! Modal provider seam backed only by bounded recording/fake/loopback
//! transports. There is intentionally no HTTP client or Modal SDK here.

use std::collections::VecDeque;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    AppIdentity, Digest, EnvironmentIdentity, FailureCode, FunctionCallIdentity,
    FunctionCallProjection, FunctionIdentity, HostIdentity, InputIdentity, JobStatus, ModalScope,
    RetryPolicy, TransportProvenance, UsageEvidence, WorkspaceIdentity,
};
use crate::service::ModalRegistration;
use crate::{MAX_RESPONSE_BYTES, ModalJobResultError, RESULT_EXPIRY_SECONDS, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModalHttpStatus(u16);

impl ModalHttpStatus {
    pub fn new(status: u16) -> Result<Self> {
        if (100..=599).contains(&status) {
            Ok(Self(status))
        } else {
            Err(ModalJobResultError::InvalidText {
                field: "httpStatus",
            })
        }
    }

    pub const fn code(self) -> u16 {
        self.0
    }
}

impl fmt::Display for ModalHttpStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Transport failures contain status classification only, never response
/// text or a credential.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModalTransportError {
    #[error("HTTP status {0}")]
    Http(ModalHttpStatus),
    #[error("provider timeout")]
    Timeout,
    #[error("provider access was lost")]
    AccessLost,
    #[error("response exceeded bound")]
    ResponseTooLarge,
    #[error("serialization exceeded bound")]
    SerializationLimit,
    #[error("provider response was tampered")]
    Tampered,
    #[error("no bounded fixture response was configured")]
    MissingFixture,
    #[error("live Modal invocation is forbidden in Layer 1")]
    LiveInvocationForbidden,
    #[error("environment is blocked for native Modal access")]
    BlockedEnv,
}

/// Provider classifications required by the contract.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModalProviderError {
    #[error("Modal unauthorized (401)")]
    Unauthorized,
    #[error("Modal forbidden (403)")]
    Forbidden,
    #[error("Modal object not found (404)")]
    NotFound,
    #[error("Modal conflict (409)")]
    Conflict,
    #[error("Modal rate limited (429)")]
    RateLimited,
    #[error("Modal server error ({status})")]
    ServerError { status: u16 },
    #[error("Modal request timed out")]
    Timeout,
    #[error("Modal provider access was lost")]
    AccessLost,
    #[error("ephemeral App lookup refused")]
    EphemeralAppLookup,
    #[error("App deployment is unavailable")]
    AppNotDeployed,
    #[error("duplicate FunctionCall spawn refused")]
    DuplicateSpawn,
    #[error("provider response was tampered")]
    Tampered,
    #[error("provider response exceeded bound")]
    ResponseTooLarge,
    #[error("provider serialization exceeded bound")]
    SerializationLimit,
    #[error("native Modal transport is blocked in Layer 1")]
    BlockedEnv,
    #[error("transport fixture is incomplete")]
    MissingFixture,
}

impl ModalProviderError {
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Conflict
                | Self::RateLimited
                | Self::ServerError { .. }
                | Self::Timeout
                | Self::MissingFixture
        )
    }

    pub const fn failure_code(&self) -> FailureCode {
        match self {
            Self::Unauthorized => FailureCode::Unauthorized,
            Self::Forbidden => FailureCode::Forbidden,
            Self::NotFound | Self::AppNotDeployed => FailureCode::NotFound,
            Self::Conflict | Self::DuplicateSpawn => FailureCode::Conflict,
            Self::RateLimited => FailureCode::RateLimited,
            Self::ServerError { .. } => FailureCode::ServerError,
            Self::Timeout => FailureCode::Timeout,
            Self::AccessLost | Self::BlockedEnv => FailureCode::AccessLoss,
            Self::EphemeralAppLookup => FailureCode::EphemeralApp,
            Self::Tampered | Self::MissingFixture => FailureCode::ProviderUnknown,
            Self::ResponseTooLarge | Self::SerializationLimit => FailureCode::ResultTooLarge,
        }
    }
}

impl From<ModalTransportError> for ModalProviderError {
    fn from(error: ModalTransportError) -> Self {
        match error {
            ModalTransportError::Http(status) => match status.code() {
                401 => Self::Unauthorized,
                403 => Self::Forbidden,
                404 => Self::NotFound,
                409 => Self::Conflict,
                429 => Self::RateLimited,
                500..=599 => Self::ServerError {
                    status: status.code(),
                },
                _ => Self::MissingFixture,
            },
            ModalTransportError::Timeout => Self::Timeout,
            ModalTransportError::AccessLost => Self::AccessLost,
            ModalTransportError::ResponseTooLarge => Self::ResponseTooLarge,
            ModalTransportError::SerializationLimit => Self::SerializationLimit,
            ModalTransportError::Tampered => Self::Tampered,
            ModalTransportError::MissingFixture => Self::MissingFixture,
            ModalTransportError::LiveInvocationForbidden | ModalTransportError::BlockedEnv => {
                Self::BlockedEnv
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FunctionLookupRequest {
    pub host: HostIdentity,
    pub workspace: WorkspaceIdentity,
    pub app: AppIdentity,
    pub function: FunctionIdentity,
    pub environment: EnvironmentIdentity,
    pub scope_digest: Digest,
}

impl FunctionLookupRequest {
    pub fn for_scope(scope: &ModalScope) -> Self {
        Self {
            host: scope.host.clone(),
            workspace: scope.workspace.clone(),
            app: scope.app.clone(),
            function: scope.function.clone(),
            environment: scope.environment.clone(),
            scope_digest: scope.digest(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.host.validate()?;
        self.workspace.validate()?;
        self.app.validate()?;
        self.function.validate()?;
        self.environment.validate()?;
        self.scope_digest.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FunctionLookupResponse {
    pub host: HostIdentity,
    pub workspace: WorkspaceIdentity,
    pub app: AppIdentity,
    pub function: FunctionIdentity,
    pub environment: EnvironmentIdentity,
    pub provider_request_id_digest: Option<Digest>,
    pub response_bytes: usize,
    pub response_digest: Digest,
}

impl FunctionLookupResponse {
    pub fn for_scope(scope: &ModalScope) -> Self {
        let mut response = Self {
            host: scope.host.clone(),
            workspace: scope.workspace.clone(),
            app: scope.app.clone(),
            function: scope.function.clone(),
            environment: scope.environment.clone(),
            provider_request_id_digest: Some(Digest::from_text("modal-fixture-lookup")),
            response_bytes: 512,
            response_digest: Digest::from_text("unsealed-modal-lookup"),
        };
        response.response_digest = response.calculate_digest();
        response
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.host.validate()?;
        self.workspace.validate()?;
        self.app.validate()?;
        self.function.validate()?;
        self.environment.validate()?;
        if self.response_bytes > MAX_RESPONSE_BYTES
            || self.response_digest != self.calculate_digest()
        {
            return Err(ModalJobResultError::TamperedEvidence);
        }
        if let Some(digest) = &self.provider_request_id_digest {
            digest.validate()?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.host,
            &self.workspace,
            &self.app,
            &self.function,
            &self.environment,
            &self.provider_request_id_digest,
            self.response_bytes,
        ))
    }
}

/// A version-pinned, exact lookup result. Holding it does not grant native
/// invocation authority; it is only a typed recording handle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FunctionHandle {
    pub host: HostIdentity,
    pub workspace: WorkspaceIdentity,
    pub app: AppIdentity,
    pub function: FunctionIdentity,
    pub environment: EnvironmentIdentity,
    pub lookup_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl FunctionHandle {
    fn from_response(response: &FunctionLookupResponse, provenance: TransportProvenance) -> Self {
        Self {
            host: response.host.clone(),
            workspace: response.workspace.clone(),
            app: response.app.clone(),
            function: response.function.clone(),
            environment: response.environment.clone(),
            lookup_digest: response.response_digest.clone(),
            provenance,
            connected: false,
            native: false,
            first_party: false,
        }
    }

    pub fn validate_against(&self, scope: &ModalScope) -> Result<()> {
        if self.host != scope.host {
            return Err(ModalJobResultError::HostDrift);
        }
        if self.workspace != scope.workspace {
            return Err(ModalJobResultError::WorkspaceDrift);
        }
        if self.app != scope.app {
            return Err(ModalJobResultError::AppDrift);
        }
        if self.function != scope.function {
            return Err(ModalJobResultError::FunctionDrift);
        }
        if self.environment != scope.environment {
            return Err(ModalJobResultError::EnvironmentDrift);
        }
        self.lookup_digest.validate()?;
        if self.connected || self.native || self.first_party {
            return Err(ModalJobResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpawnRequest {
    pub scope_digest: Digest,
    pub handle: FunctionHandle,
    pub call: FunctionCallIdentity,
    pub input: InputIdentity,
    pub retry: RetryPolicy,
}

impl SpawnRequest {
    pub fn for_scope(scope: &ModalScope, handle: FunctionHandle) -> Self {
        Self {
            scope_digest: scope.digest(),
            handle,
            call: scope.call.clone(),
            input: scope.input.clone(),
            retry: scope.retry.clone(),
        }
    }

    pub fn validate(&self, scope: &ModalScope) -> Result<()> {
        self.handle.validate_against(scope)?;
        if self.scope_digest != scope.digest() {
            return Err(ModalJobResultError::ScopeMismatch);
        }
        if self.call != scope.call {
            return Err(ModalJobResultError::CallDrift);
        }
        if self.input != scope.input {
            return Err(ModalJobResultError::InputDrift);
        }
        if self.retry != scope.retry {
            return Err(ModalJobResultError::RetryDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PollRequest {
    pub scope_digest: Digest,
    pub handle: FunctionHandle,
    pub call: FunctionCallIdentity,
    pub input: InputIdentity,
    pub retry: RetryPolicy,
    pub poll_index: u8,
    pub timeout_millis: u64,
    pub expected_backoff_millis: u64,
}

impl PollRequest {
    pub fn validate(&self, scope: &ModalScope, current: &FunctionCallProjection) -> Result<()> {
        self.handle.validate_against(scope)?;
        if !current.matches_scope(scope) {
            return Err(ModalJobResultError::ScopeMismatch);
        }
        if self.scope_digest != scope.digest() {
            return Err(ModalJobResultError::ScopeMismatch);
        }
        if self.call != scope.call {
            return Err(ModalJobResultError::CallDrift);
        }
        if self.input != scope.input {
            return Err(ModalJobResultError::InputDrift);
        }
        if self.retry != scope.retry {
            return Err(ModalJobResultError::RetryDrift);
        }
        if self.poll_index == 0 || self.poll_index > scope.retry.max_polls {
            return Err(ModalJobResultError::PollLimitExceeded);
        }
        if self.timeout_millis != scope.retry.timeout_millis {
            return Err(ModalJobResultError::RetryDrift);
        }
        if self.expected_backoff_millis != scope.retry.poll_delay_millis(self.poll_index - 1)
            || self.expected_backoff_millis > crate::MAX_BACKOFF_MILLIS
        {
            return Err(ModalJobResultError::PollBackoffExceeded);
        }
        Ok(())
    }
}

/// Safe provider response for a single FunctionCall observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderCallResponse {
    pub host: HostIdentity,
    pub workspace: WorkspaceIdentity,
    pub app: AppIdentity,
    pub function: FunctionIdentity,
    pub environment: EnvironmentIdentity,
    pub call: FunctionCallIdentity,
    pub input: InputIdentity,
    pub retry: RetryPolicy,
    pub status: JobStatus,
    pub attempt_number: u8,
    pub poll_count: u8,
    pub result: Option<crate::model::ResultEvidence>,
    pub response_truncated: bool,
    pub observed_at_epoch_seconds: u64,
    pub provider_request_id_digest: Option<Digest>,
    pub response_bytes: usize,
    pub response_digest: Digest,
}

impl ProviderCallResponse {
    pub fn for_scope(
        scope: &ModalScope,
        status: JobStatus,
        observed_at_epoch_seconds: u64,
        poll_count: u8,
        usage: UsageEvidence,
    ) -> Result<Self> {
        let result = if status == JobStatus::Succeeded {
            let bytes = 32;
            let result_usage = UsageEvidence::new(
                usage.input_bytes,
                bytes,
                usage.runtime_millis,
                usage.provider_retry_count,
                usage.poll_count,
            )?;
            Some(crate::model::ResultEvidence::metadata(
                Some(Digest::from_text("modal-fixture-result")),
                bytes,
                Some(bytes),
                true,
                Some(Digest::from_text("modal-fixture-result")),
                Some(bytes),
                None,
                None,
                Some(observed_at_epoch_seconds.saturating_add(RESULT_EXPIRY_SECONDS)),
                false,
                false,
                result_usage,
            )?)
        } else {
            None
        };
        let mut response = Self {
            host: scope.host.clone(),
            workspace: scope.workspace.clone(),
            app: scope.app.clone(),
            function: scope.function.clone(),
            environment: scope.environment.clone(),
            call: scope.call.clone(),
            input: scope.input.clone(),
            retry: scope.retry.clone(),
            status,
            attempt_number: 1,
            poll_count,
            result,
            response_truncated: false,
            observed_at_epoch_seconds,
            provider_request_id_digest: Some(Digest::from_text("modal-fixture-call")),
            response_bytes: 768,
            response_digest: Digest::from_text("unsealed-modal-call"),
        };
        response.response_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_result(mut self, result: crate::model::ResultEvidence) -> Self {
        self.result = Some(result);
        self.response_digest = self.calculate_digest();
        self
    }

    #[must_use]
    pub fn with_failure_code(mut self, code: FailureCode) -> Self {
        self.result = Some(
            crate::model::ResultEvidence::failure(
                code,
                None,
                self.result.as_ref().map_or_else(
                    || UsageEvidence {
                        input_bytes: self.input.serialized_bytes,
                        output_bytes: 0,
                        runtime_millis: None,
                        provider_retry_count: 0,
                        poll_count: self.poll_count,
                    },
                    |result| result.usage,
                ),
            )
            .expect("bounded failure evidence"),
        );
        self.response_digest = self.calculate_digest();
        self
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.host.validate()?;
        self.workspace.validate()?;
        self.app.validate()?;
        self.function.validate()?;
        self.environment.validate()?;
        self.call.validate()?;
        self.input.validate()?;
        self.retry.validate()?;
        if self.attempt_number == 0
            || self.poll_count > self.retry.max_polls
            || self.observed_at_epoch_seconds == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.response_digest != self.calculate_digest()
        {
            return Err(ModalJobResultError::TamperedEvidence);
        }
        if let Some(result) = &self.result {
            result.validate_integrity()?;
        }
        if let Some(digest) = &self.provider_request_id_digest {
            digest.validate()?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "modal-provider-call-response/v1",
            &[
                ("host", serde_json::to_string(&self.host).expect("identity")),
                (
                    "workspace",
                    serde_json::to_string(&self.workspace).expect("identity"),
                ),
                ("app", serde_json::to_string(&self.app).expect("identity")),
                (
                    "function",
                    serde_json::to_string(&self.function).expect("identity"),
                ),
                (
                    "environment",
                    serde_json::to_string(&self.environment).expect("identity"),
                ),
                ("call", serde_json::to_string(&self.call).expect("identity")),
                (
                    "input",
                    serde_json::to_string(&self.input).expect("identity"),
                ),
                ("retry", serde_json::to_string(&self.retry).expect("policy")),
                ("status", self.status.as_str().to_owned()),
                ("attempt", self.attempt_number.to_string()),
                ("poll", self.poll_count.to_string()),
                (
                    "result",
                    serde_json::to_string(&self.result).expect("result metadata"),
                ),
                ("truncated", self.response_truncated.to_string()),
                ("observed_at", self.observed_at_epoch_seconds.to_string()),
                (
                    "provider_request",
                    self.provider_request_id_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("response_bytes", self.response_bytes.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordedRequestKind {
    Lookup,
    Spawn,
    Poll { poll_index: u8, backoff_millis: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedRequest {
    pub kind: RecordedRequestKind,
    pub scope_digest: Digest,
    pub call_digest: Digest,
    pub input_digest: Digest,
}

pub trait ModalTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn lookup_function(
        &mut self,
        request: &FunctionLookupRequest,
    ) -> std::result::Result<FunctionLookupResponse, ModalTransportError>;

    fn spawn_function_call(
        &mut self,
        request: &SpawnRequest,
    ) -> std::result::Result<ProviderCallResponse, ModalTransportError>;

    fn poll_function_call(
        &mut self,
        request: &PollRequest,
    ) -> std::result::Result<ProviderCallResponse, ModalTransportError>;
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    lookup_response: Option<std::result::Result<FunctionLookupResponse, ModalTransportError>>,
    spawn_response: Option<std::result::Result<ProviderCallResponse, ModalTransportError>>,
    poll_responses: VecDeque<std::result::Result<ProviderCallResponse, ModalTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            lookup_response: None,
            spawn_response: None,
            poll_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn for_scope(scope: &ModalScope, provenance: TransportProvenance) -> Result<Self> {
        let usage = UsageEvidence::for_input(&scope.input, 0)?;
        let mut transport = Self::new(provenance);
        transport.lookup_response = Some(Ok(FunctionLookupResponse::for_scope(scope)));
        transport.spawn_response = Some(Ok(ProviderCallResponse::for_scope(
            scope,
            JobStatus::Queued,
            1,
            0,
            usage,
        )?));
        Ok(transport)
    }

    #[must_use]
    pub fn with_lookup_response(
        mut self,
        response: std::result::Result<FunctionLookupResponse, ModalTransportError>,
    ) -> Self {
        self.lookup_response = Some(response);
        self
    }

    #[must_use]
    pub fn with_spawn_response(
        mut self,
        response: std::result::Result<ProviderCallResponse, ModalTransportError>,
    ) -> Self {
        self.spawn_response = Some(response);
        self
    }

    pub fn push_poll_response(
        &mut self,
        response: std::result::Result<ProviderCallResponse, ModalTransportError>,
    ) {
        self.poll_responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.provenance
    }
}

impl ModalTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn lookup_function(
        &mut self,
        request: &FunctionLookupRequest,
    ) -> std::result::Result<FunctionLookupResponse, ModalTransportError> {
        self.requests.push(RecordedRequest {
            kind: RecordedRequestKind::Lookup,
            scope_digest: request.scope_digest.clone(),
            call_digest: Digest::from_text("lookup-no-call"),
            input_digest: Digest::from_text("lookup-no-input"),
        });
        self.lookup_response
            .clone()
            .unwrap_or(Err(ModalTransportError::MissingFixture))
    }

    fn spawn_function_call(
        &mut self,
        request: &SpawnRequest,
    ) -> std::result::Result<ProviderCallResponse, ModalTransportError> {
        self.requests.push(RecordedRequest {
            kind: RecordedRequestKind::Spawn,
            scope_digest: request.scope_digest.clone(),
            call_digest: request.call.digest(),
            input_digest: request.input.serialized_digest.clone(),
        });
        self.spawn_response
            .clone()
            .unwrap_or(Err(ModalTransportError::MissingFixture))
    }

    fn poll_function_call(
        &mut self,
        request: &PollRequest,
    ) -> std::result::Result<ProviderCallResponse, ModalTransportError> {
        self.requests.push(RecordedRequest {
            kind: RecordedRequestKind::Poll {
                poll_index: request.poll_index,
                backoff_millis: request.expected_backoff_millis,
            },
            scope_digest: request.scope_digest.clone(),
            call_digest: request.call.digest(),
            input_digest: request.input.serialized_digest.clone(),
        });
        self.poll_responses
            .pop_front()
            .unwrap_or(Err(ModalTransportError::MissingFixture))
    }
}

#[derive(Clone, Debug)]
pub struct FakeTransport {
    inner: RecordingTransport,
}

impl FakeTransport {
    pub fn for_scope(scope: &ModalScope) -> Result<Self> {
        Ok(Self {
            inner: RecordingTransport::for_scope(scope, TransportProvenance::Fake)?,
        })
    }

    pub fn new() -> Self {
        Self {
            inner: RecordingTransport::new(TransportProvenance::Fake),
        }
    }

    pub fn inner_mut(&mut self) -> &mut RecordingTransport {
        &mut self.inner
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        self.inner.requests()
    }
}

impl Default for FakeTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl ModalTransport for FakeTransport {
    fn provenance(&self) -> TransportProvenance {
        self.inner.provenance()
    }

    fn lookup_function(
        &mut self,
        request: &FunctionLookupRequest,
    ) -> std::result::Result<FunctionLookupResponse, ModalTransportError> {
        self.inner.lookup_function(request)
    }

    fn spawn_function_call(
        &mut self,
        request: &SpawnRequest,
    ) -> std::result::Result<ProviderCallResponse, ModalTransportError> {
        self.inner.spawn_function_call(request)
    }

    fn poll_function_call(
        &mut self,
        request: &PollRequest,
    ) -> std::result::Result<ProviderCallResponse, ModalTransportError> {
        self.inner.poll_function_call(request)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: RecordingTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &ModalScope) -> Result<Self> {
        Ok(Self {
            inner: RecordingTransport::for_scope(scope, TransportProvenance::Loopback)?,
        })
    }

    pub fn new() -> Self {
        Self {
            inner: RecordingTransport::new(TransportProvenance::Loopback),
        }
    }

    pub fn inner_mut(&mut self) -> &mut RecordingTransport {
        &mut self.inner
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        self.inner.requests()
    }
}

impl Default for LoopbackTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl ModalTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        self.inner.provenance()
    }

    fn lookup_function(
        &mut self,
        request: &FunctionLookupRequest,
    ) -> std::result::Result<FunctionLookupResponse, ModalTransportError> {
        self.inner.lookup_function(request)
    }

    fn spawn_function_call(
        &mut self,
        request: &SpawnRequest,
    ) -> std::result::Result<ProviderCallResponse, ModalTransportError> {
        self.inner.spawn_function_call(request)
    }

    fn poll_function_call(
        &mut self,
        request: &PollRequest,
    ) -> std::result::Result<ProviderCallResponse, ModalTransportError> {
        self.inner.poll_function_call(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl ModalTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn lookup_function(
        &mut self,
        _request: &FunctionLookupRequest,
    ) -> std::result::Result<FunctionLookupResponse, ModalTransportError> {
        Err(ModalTransportError::BlockedEnv)
    }

    fn spawn_function_call(
        &mut self,
        _request: &SpawnRequest,
    ) -> std::result::Result<ProviderCallResponse, ModalTransportError> {
        Err(ModalTransportError::BlockedEnv)
    }

    fn poll_function_call(
        &mut self,
        _request: &PollRequest,
    ) -> std::result::Result<ProviderCallResponse, ModalTransportError> {
        Err(ModalTransportError::BlockedEnv)
    }
}

/// Typed Modal provider. The generic transport is expected to be a recording,
/// fake, loopback, or blocked-environment implementation in Layer 1.
#[derive(Clone, Debug)]
pub struct ModalProvider<T> {
    registration: ModalRegistration,
    transport: T,
    spawned: bool,
}

impl<T: ModalTransport> ModalProvider<T> {
    pub fn new(registration: ModalRegistration, transport: T) -> Result<Self> {
        registration.validate()?;
        Ok(Self {
            registration,
            transport,
            spawned: false,
        })
    }

    pub fn registration(&self) -> &ModalRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut ModalRegistration {
        &mut self.registration
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn first_party(&self) -> bool {
        false
    }

    pub fn scope(&self) -> &ModalScope {
        self.registration.scope()
    }

    pub(crate) fn ensure_ready(&self) -> Result<()> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return match self.registration.status() {
                crate::RegistrationStatus::Revoked => Err(ModalJobResultError::RegistrationRevoked),
                crate::RegistrationStatus::Reversed => {
                    Err(ModalJobResultError::RegistrationReversed)
                }
                crate::RegistrationStatus::Active => Ok(()),
            };
        }
        if self.registration.secret_reference().is_revoked() {
            return Err(ModalJobResultError::SecretRevoked);
        }
        Ok(())
    }

    pub fn describe_workspace_app_function(&mut self) -> Result<FunctionLookupResponse> {
        self.ensure_ready()?;
        if !self.scope().app.is_deployed() {
            return Err(ModalProviderError::EphemeralAppLookup.into());
        }
        let request = FunctionLookupRequest::for_scope(self.scope());
        request.validate()?;
        let response = self
            .transport
            .lookup_function(&request)
            .map_err(ModalProviderError::from)
            .map_err(ModalJobResultError::Provider)?;
        response.validate_integrity()?;
        if response.host != self.scope().host {
            return Err(ModalJobResultError::HostDrift);
        }
        if response.workspace != self.scope().workspace {
            return Err(ModalJobResultError::WorkspaceDrift);
        }
        if response.app != self.scope().app {
            return Err(ModalJobResultError::AppDrift);
        }
        if response.function != self.scope().function {
            return Err(ModalJobResultError::FunctionDrift);
        }
        if response.environment != self.scope().environment {
            return Err(ModalJobResultError::EnvironmentDrift);
        }
        if !response.app.is_deployed() {
            return Err(ModalProviderError::AppNotDeployed.into());
        }
        Ok(response)
    }

    pub fn lookup_function(&mut self) -> Result<FunctionHandle> {
        let response = self.describe_workspace_app_function()?;
        Ok(FunctionHandle::from_response(&response, self.provenance()))
    }

    pub fn spawn(&mut self, handle: &FunctionHandle) -> Result<FunctionCallProjection> {
        self.spawn_function_call(handle)
    }

    pub fn function_call_from_id(
        &self,
        call: &FunctionCallIdentity,
    ) -> Result<FunctionCallIdentity> {
        self.ensure_ready()?;
        if call != &self.scope().call {
            return Err(ModalJobResultError::CallDrift);
        }
        Ok(call.clone())
    }

    pub fn spawn_function_call(
        &mut self,
        handle: &FunctionHandle,
    ) -> Result<FunctionCallProjection> {
        self.ensure_ready()?;
        if self.spawned {
            return Err(ModalProviderError::DuplicateSpawn.into());
        }
        handle.validate_against(self.scope())?;
        let request = SpawnRequest::for_scope(self.scope(), handle.clone());
        request.validate(self.scope())?;
        let response = self
            .transport
            .spawn_function_call(&request)
            .map_err(ModalProviderError::from)
            .map_err(ModalJobResultError::Provider)?;
        response.validate_integrity()?;
        let delay = if response.status.is_terminal() {
            0
        } else {
            self.scope().retry.poll_delay_millis(response.poll_count)
        };
        let projection = FunctionCallProjection::from_response(
            self.scope(),
            &response,
            self.provenance(),
            delay,
        )?;
        self.spawned = true;
        Ok(projection)
    }

    pub fn poll_function_call(
        &mut self,
        handle: &FunctionHandle,
        current: &FunctionCallProjection,
    ) -> Result<FunctionCallProjection> {
        self.ensure_ready()?;
        handle.validate_against(self.scope())?;
        current.validate_integrity()?;
        if !current.matches_scope(self.scope()) {
            return Err(ModalJobResultError::ScopeMismatch);
        }
        if current.status.is_terminal() {
            return Err(ModalJobResultError::CallAlreadyTerminal);
        }
        let poll_index = current
            .poll_count
            .checked_add(1)
            .ok_or(ModalJobResultError::PollLimitExceeded)?;
        if poll_index > self.scope().retry.max_polls {
            return Err(ModalJobResultError::PollLimitExceeded);
        }
        let request = PollRequest {
            scope_digest: self.scope().digest(),
            handle: handle.clone(),
            call: self.scope().call.clone(),
            input: self.scope().input.clone(),
            retry: self.scope().retry.clone(),
            poll_index,
            timeout_millis: self.scope().retry.timeout_millis,
            expected_backoff_millis: self.scope().retry.poll_delay_millis(current.poll_count),
        };
        request.validate(self.scope(), current)?;
        let response = self
            .transport
            .poll_function_call(&request)
            .map_err(ModalProviderError::from)
            .map_err(ModalJobResultError::Provider)?;
        response.validate_integrity()?;
        let delay = if response.status.is_terminal() {
            0
        } else {
            self.scope().retry.poll_delay_millis(response.poll_count)
        };
        FunctionCallProjection::from_response(self.scope(), &response, self.provenance(), delay)
    }

    pub fn poll_result(
        &mut self,
        handle: &FunctionHandle,
        current: &FunctionCallProjection,
    ) -> Result<FunctionCallProjection> {
        self.poll_function_call(handle, current)
    }

    /// Perform at most the registered poll bound. Retryable transport failure,
    /// access loss, or a bound exhaustion becomes a provider-unknown
    /// projection; no sleep and no unbounded retry is performed.
    pub fn observe_bounded(&mut self) -> Result<FunctionCallProjection> {
        let handle = self.lookup_function()?;
        let mut projection = self.spawn_function_call(&handle)?;
        while !projection.status.is_terminal() {
            if projection.poll_count >= self.scope().retry.max_polls {
                return FunctionCallProjection::provider_unknown(
                    self.scope(),
                    projection.poll_count,
                    projection.observed_at_epoch_seconds,
                    FailureCode::ProviderUnknown,
                    self.provenance(),
                );
            }
            match self.poll_function_call(&handle, &projection) {
                Ok(next) => projection = next,
                Err(ModalJobResultError::Provider(error)) => {
                    return FunctionCallProjection::provider_unknown(
                        self.scope(),
                        projection.poll_count,
                        projection.observed_at_epoch_seconds,
                        error.failure_code(),
                        self.provenance(),
                    );
                }
                Err(error) => return Err(error),
            }
        }
        Ok(projection)
    }
}
