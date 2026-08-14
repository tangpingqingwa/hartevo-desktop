//! Fixture-only provider and transport seams for Lambda metadata/result
//! projections. There is deliberately no AWS SDK, SigV4 signer, or HTTP
//! client in this Layer-1 crate.

use std::collections::VecDeque;
use std::fmt;

use serde::Serialize;

use crate::error::{AwsLambdaProviderError, AwsLambdaTransportError, Result};
use crate::model::{
    AwsLambdaScope, Digest, FailureCode, FunctionTarget, InvocationProposal,
    InvocationResultProjection, InvocationStatus, InvocationType, TransportProvenance,
    UsageEvidence,
};
use crate::service::AwsLambdaRegistration;
use crate::{AwsLambdaInvocationResultError, MAX_RESPONSE_BYTES};

pub use crate::model::AwsLambdaHttpStatus;

/// The only provider seam available in Layer 1. Implementations are
/// recording/fake/loopback/BLOCKED_ENV fixtures; a live implementation is a
/// Layer-2 concern and cannot be supplied by this crate.
pub trait AwsLambdaTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn get_function(
        &mut self,
        request: &FunctionLookupRequest,
    ) -> std::result::Result<FunctionLookupResponse, AwsLambdaTransportError>;

    fn invoke(
        &mut self,
        request: &InvocationRequest,
    ) -> std::result::Result<ProviderInvocationResponse, AwsLambdaTransportError>;
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordedRequestKind {
    GetFunction,
    Invoke,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub kind: RecordedRequestKind,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub input_digest: Digest,
    pub invocation_type: Option<InvocationType>,
    pub attempt_number: Option<u8>,
}

/// Exact metadata-only GetFunction request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionLookupRequest {
    pub scope_digest: Digest,
    pub account: String,
    pub region: String,
    pub function_arn: String,
    pub version: String,
    pub alias: Option<String>,
}

impl FunctionLookupRequest {
    pub fn for_scope(scope: &AwsLambdaScope) -> Self {
        Self {
            scope_digest: scope.digest(),
            account: scope.account.as_str().to_owned(),
            region: scope.region.as_str().to_owned(),
            function_arn: scope.function.function_arn.as_str().to_owned(),
            version: scope.function.version.as_str().to_owned(),
            alias: scope
                .function
                .alias
                .as_ref()
                .map(|alias| alias.as_str().to_owned()),
        }
    }
}

/// Bounded GetFunction metadata. Code package URLs, environment values,
/// roles, tags, and response bodies are intentionally absent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionLookupResponse {
    pub function: FunctionTarget,
    pub config_digest: Digest,
    pub config_revision: u64,
    pub response_bytes: u64,
    pub metadata_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl FunctionLookupResponse {
    pub fn new(
        function: FunctionTarget,
        config_digest: Digest,
        config_revision: u64,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        function.validate()?;
        config_digest.validate()?;
        if config_revision == 0 || response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsLambdaInvocationResultError::InvalidScope);
        }
        let mut response = Self {
            function,
            config_digest,
            config_revision,
            response_bytes,
            metadata_digest: Digest::from_text("unsealed-aws-lambda-function-metadata"),
            provenance,
            connected: false,
            native: false,
            first_party: false,
        };
        response.metadata_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn for_scope(scope: &AwsLambdaScope, provenance: TransportProvenance) -> Result<Self> {
        Self::new(
            scope.function.clone(),
            scope.config.digest(),
            scope.config.revision,
            512,
            provenance,
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.function.validate()?;
        self.config_digest.validate()?;
        if self.config_revision == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.connected
            || self.native
            || self.first_party
            || self.metadata_digest != self.calculate_digest()
        {
            return Err(AwsLambdaInvocationResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-lambda-function-metadata/v1",
            &[
                ("function", self.function.digest().as_str().to_owned()),
                ("config", self.config_digest.as_str().to_owned()),
                ("config_revision", self.config_revision.to_string()),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

/// Invocation request contains all exact fences but never the serialized
/// request payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvocationRequest {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub function: FunctionTarget,
    pub invocation_type: InvocationType,
    pub input_digest: Digest,
    pub input_revision: u64,
    pub input_bytes: u64,
    pub config_digest: Digest,
    pub config_revision: u64,
    pub retry_digest: Digest,
    pub retry_revision: u64,
    pub timeout_millis: u64,
    pub attempt_number: u8,
}

impl InvocationRequest {
    pub fn from_proposal(proposal: &InvocationProposal) -> Self {
        Self {
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            request_digest: proposal.request_digest.clone(),
            function: proposal.function.clone(),
            invocation_type: proposal.invocation_type,
            input_digest: proposal.input.input_digest.clone(),
            input_revision: proposal.input.revision,
            input_bytes: proposal.input.serialized_bytes,
            config_digest: proposal.config.digest(),
            config_revision: proposal.config.revision,
            retry_digest: proposal.retry.digest(),
            retry_revision: proposal.retry.revision,
            timeout_millis: proposal.retry.timeout_millis,
            attempt_number: 1,
        }
    }

    pub fn validate(&self, proposal: &InvocationProposal) -> Result<()> {
        proposal.validate_integrity()?;
        let expected = Self::from_proposal(proposal);
        if self != &expected {
            return Err(AwsLambdaInvocationResultError::RequestDigestMismatch);
        }
        Ok(())
    }
}

/// Metadata-only Lambda Invoke response. `output_digest` and `error_digest`
/// are supplied by a fixture/recording seam; no body is retained.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderInvocationResponse {
    pub request_digest: Digest,
    pub function: FunctionTarget,
    pub config_digest: Digest,
    pub config_revision: u64,
    pub status: InvocationStatus,
    pub failure_code: Option<FailureCode>,
    pub http_status: Option<AwsLambdaHttpStatus>,
    pub function_error: bool,
    pub output_digest: Option<Digest>,
    pub error_digest: Option<Digest>,
    pub usage: UsageEvidence,
    pub response_bytes: u64,
    pub response_truncated: bool,
    pub attempt_number: u8,
    pub observed_at_epoch_seconds: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl ProviderInvocationResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_digest: Digest,
        function: FunctionTarget,
        config_digest: Digest,
        config_revision: u64,
        status: InvocationStatus,
        failure_code: Option<FailureCode>,
        http_status: Option<AwsLambdaHttpStatus>,
        function_error: bool,
        output_digest: Option<Digest>,
        error_digest: Option<Digest>,
        usage: UsageEvidence,
        response_bytes: u64,
        response_truncated: bool,
        attempt_number: u8,
        observed_at_epoch_seconds: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        request_digest.validate()?;
        function.validate()?;
        config_digest.validate()?;
        output_digest.as_ref().map(Digest::validate).transpose()?;
        error_digest.as_ref().map(Digest::validate).transpose()?;
        if config_revision == 0
            || response_bytes > MAX_RESPONSE_BYTES
            || attempt_number == 0
            || observed_at_epoch_seconds == 0
            || usage.attempt_number != attempt_number
            || (matches!(status, InvocationStatus::FunctionError) != function_error)
            || (matches!(status, InvocationStatus::FunctionError) && error_digest.is_none())
        {
            return Err(AwsLambdaInvocationResultError::InvalidScope);
        }
        let mut response = Self {
            request_digest,
            function,
            config_digest,
            config_revision,
            status,
            failure_code,
            http_status,
            function_error,
            output_digest,
            error_digest,
            usage,
            response_bytes,
            response_truncated,
            attempt_number,
            observed_at_epoch_seconds,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-lambda-provider-response"),
            connected: false,
            native: false,
            first_party: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn for_proposal(
        proposal: &InvocationProposal,
        status: InvocationStatus,
        failure_code: Option<FailureCode>,
        http_status: Option<AwsLambdaHttpStatus>,
        function_error: bool,
        output_digest: Option<Digest>,
        error_digest: Option<Digest>,
        usage: UsageEvidence,
        response_bytes: u64,
        response_truncated: bool,
        observed_at_epoch_seconds: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let attempt_number = usage.attempt_number;
        Self::new(
            proposal.request_digest.clone(),
            proposal.function.clone(),
            proposal.config.digest(),
            proposal.config.revision,
            status,
            failure_code,
            http_status,
            function_error,
            output_digest,
            error_digest,
            usage,
            response_bytes,
            response_truncated,
            attempt_number,
            observed_at_epoch_seconds,
            provenance,
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.request_digest.validate()?;
        self.function.validate()?;
        self.config_digest.validate()?;
        self.output_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.error_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        if self.config_revision == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.attempt_number == 0
            || self.observed_at_epoch_seconds == 0
            || self.connected
            || self.native
            || self.first_party
            || self.usage.attempt_number != self.attempt_number
            || (matches!(self.status, InvocationStatus::FunctionError) != self.function_error)
            || (matches!(self.status, InvocationStatus::FunctionError)
                && self.error_digest.is_none())
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsLambdaInvocationResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn validate_against(&self, proposal: &InvocationProposal) -> Result<()> {
        self.validate_integrity()?;
        if self.request_digest != proposal.request_digest {
            return Err(AwsLambdaInvocationResultError::RequestDigestMismatch);
        }
        if self.function.function_arn != proposal.function.function_arn {
            return Err(AwsLambdaInvocationResultError::FunctionArnDrift);
        }
        if self.function.version != proposal.function.version {
            return Err(AwsLambdaInvocationResultError::FunctionVersionDrift);
        }
        if self.function.alias != proposal.function.alias {
            return Err(AwsLambdaInvocationResultError::FunctionAliasDrift);
        }
        if self.function.code_sha256 != proposal.function.code_sha256 {
            return Err(AwsLambdaInvocationResultError::FunctionCodeShaDrift);
        }
        if self.function.revision != proposal.function.revision {
            return Err(AwsLambdaInvocationResultError::FunctionRevisionDrift);
        }
        if self.config_digest != proposal.config.digest()
            || self.config_revision != proposal.config.revision
        {
            return Err(AwsLambdaInvocationResultError::ConfigDrift);
        }
        self.usage.validate_against(&AwsLambdaScope::new(
            proposal.function.function_arn.account.clone(),
            proposal.function.function_arn.region.clone(),
            proposal.function.clone(),
            proposal.invocation_type,
            proposal.input.clone(),
            proposal.config.clone(),
            proposal.retry.clone(),
            proposal.mission.clone(),
            proposal.project.clone(),
            proposal.work_product.clone(),
        )?)?;
        if self.attempt_number > proposal.retry.max_attempts {
            return Err(AwsLambdaInvocationResultError::RetryLimitExceeded);
        }
        validate_http_semantics(
            proposal.invocation_type,
            self.status,
            self.http_status,
            self.function_error,
            self.output_digest.is_some(),
            self.error_digest.is_some(),
        )
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-lambda-provider-response/v1",
            &[
                ("request", self.request_digest.as_str().to_owned()),
                ("function", self.function.digest().as_str().to_owned()),
                ("config", self.config_digest.as_str().to_owned()),
                ("config_revision", self.config_revision.to_string()),
                ("status", self.status.as_str().to_owned()),
                ("failure", format!("{:?}", self.failure_code)),
                (
                    "http_status",
                    self.http_status
                        .map_or_else(String::new, |status| status.as_u16().to_string()),
                ),
                ("function_error", self.function_error.to_string()),
                (
                    "output",
                    self.output_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "error",
                    self.error_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("usage", self.usage.digest().as_str().to_owned()),
                ("response_bytes", self.response_bytes.to_string()),
                ("truncated", self.response_truncated.to_string()),
                ("attempt", self.attempt_number.to_string()),
                ("observed_at", self.observed_at_epoch_seconds.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

fn validate_http_semantics(
    invocation_type: InvocationType,
    status: InvocationStatus,
    http_status: Option<AwsLambdaHttpStatus>,
    function_error: bool,
    has_output_digest: bool,
    has_error_digest: bool,
) -> Result<()> {
    let Some(http_status) = http_status else {
        if matches!(
            status,
            InvocationStatus::ProviderUnknown | InvocationStatus::Partial
        ) {
            return Ok(());
        }
        return Err(AwsLambdaInvocationResultError::InvalidInvocationConfiguration);
    };
    match http_status.as_u16() {
        200 => {
            if !matches!(invocation_type, InvocationType::RequestResponse) {
                return Err(AwsLambdaInvocationResultError::InvalidInvocationConfiguration);
            }
            if matches!(status, InvocationStatus::FunctionError) != function_error {
                return Err(AwsLambdaInvocationResultError::InvalidInvocationConfiguration);
            }
            if function_error {
                if !matches!(status, InvocationStatus::FunctionError) || !has_error_digest {
                    return Err(AwsLambdaInvocationResultError::MissingFunctionErrorDigest);
                }
            } else if matches!(status, InvocationStatus::Succeeded) && !has_output_digest {
                return Err(AwsLambdaInvocationResultError::MissingOutputDigest);
            }
        }
        202 => {
            if !matches!(invocation_type, InvocationType::Event)
                || function_error
                || !matches!(
                    status,
                    InvocationStatus::Accepted
                        | InvocationStatus::Queued
                        | InvocationStatus::Running
                )
                || has_output_digest
                || has_error_digest
            {
                return Err(AwsLambdaInvocationResultError::InvalidInvocationConfiguration);
            }
        }
        400 | 401 | 403 | 404 | 408 | 409 | 413 | 415 | 429 | 500..=599 => {
            if function_error || has_output_digest {
                return Err(AwsLambdaInvocationResultError::InvalidInvocationConfiguration);
            }
        }
        _ => return Err(AwsLambdaInvocationResultError::InvalidInvocationConfiguration),
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    lookup_response: Option<std::result::Result<FunctionLookupResponse, AwsLambdaTransportError>>,
    invoke_response:
        Option<std::result::Result<ProviderInvocationResponse, AwsLambdaTransportError>>,
    invoke_responses:
        VecDeque<std::result::Result<ProviderInvocationResponse, AwsLambdaTransportError>>,
    requests: Vec<RecordedRequest>,
    rebind_default_request: bool,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            lookup_response: None,
            invoke_response: None,
            invoke_responses: VecDeque::new(),
            requests: Vec::new(),
            rebind_default_request: false,
        }
    }

    pub fn for_scope(scope: &AwsLambdaScope, provenance: TransportProvenance) -> Result<Self> {
        let usage = UsageEvidence::for_input(&scope.input)?;
        let registration_id = crate::model::RegistrationId::new("fixture-registration", 1)?;
        let registration_digest = Digest::from_text("fixture-registration-binding");
        let proposal =
            InvocationProposal::new(registration_id, registration_digest, scope, provenance)?;
        let output = if matches!(scope.invocation_type, InvocationType::RequestResponse) {
            Some(Digest::from_text("fixture-lambda-output"))
        } else {
            None
        };
        let status = if matches!(scope.invocation_type, InvocationType::RequestResponse) {
            InvocationStatus::Succeeded
        } else {
            InvocationStatus::Accepted
        };
        let http_status = if matches!(scope.invocation_type, InvocationType::RequestResponse) {
            Some(AwsLambdaHttpStatus::new(200)?)
        } else {
            Some(AwsLambdaHttpStatus::new(202)?)
        };
        let response = ProviderInvocationResponse::for_proposal(
            &proposal,
            status,
            None,
            http_status,
            false,
            output,
            None,
            usage,
            512,
            false,
            1,
            provenance,
        )?;
        let mut transport = Self::new(provenance);
        transport.lookup_response = Some(Ok(FunctionLookupResponse::for_scope(scope, provenance)?));
        transport.invoke_response = Some(Ok(response));
        transport.rebind_default_request = true;
        Ok(transport)
    }

    #[must_use]
    pub fn with_lookup_response(
        mut self,
        response: std::result::Result<FunctionLookupResponse, AwsLambdaTransportError>,
    ) -> Self {
        self.lookup_response = Some(response);
        self
    }

    #[must_use]
    pub fn with_invoke_response(
        mut self,
        response: std::result::Result<ProviderInvocationResponse, AwsLambdaTransportError>,
    ) -> Self {
        self.invoke_response = Some(response);
        self.rebind_default_request = false;
        self
    }

    #[must_use]
    pub fn with_invocation_response(
        self,
        response: std::result::Result<ProviderInvocationResponse, AwsLambdaTransportError>,
    ) -> Self {
        self.with_invoke_response(response)
    }

    pub fn push_invoke_response(
        &mut self,
        response: std::result::Result<ProviderInvocationResponse, AwsLambdaTransportError>,
    ) {
        self.invoke_responses.push_back(response);
        self.rebind_default_request = false;
    }

    pub fn push_invocation_response(
        &mut self,
        response: std::result::Result<ProviderInvocationResponse, AwsLambdaTransportError>,
    ) {
        self.push_invoke_response(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    pub const fn provenance(&self) -> TransportProvenance {
        self.provenance
    }
}

impl AwsLambdaTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn get_function(
        &mut self,
        request: &FunctionLookupRequest,
    ) -> std::result::Result<FunctionLookupResponse, AwsLambdaTransportError> {
        self.requests.push(RecordedRequest {
            kind: RecordedRequestKind::GetFunction,
            scope_digest: request.scope_digest.clone(),
            request_digest: Digest::from_text("get-function-request"),
            input_digest: Digest::from_text("no-input"),
            invocation_type: None,
            attempt_number: None,
        });
        self.lookup_response
            .clone()
            .unwrap_or(Err(AwsLambdaTransportError::MissingFixture))
    }

    fn invoke(
        &mut self,
        request: &InvocationRequest,
    ) -> std::result::Result<ProviderInvocationResponse, AwsLambdaTransportError> {
        self.requests.push(RecordedRequest {
            kind: RecordedRequestKind::Invoke,
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest.clone(),
            input_digest: request.input_digest.clone(),
            invocation_type: Some(request.invocation_type),
            attempt_number: Some(request.attempt_number),
        });
        let response = self
            .invoke_responses
            .pop_front()
            .or_else(|| self.invoke_response.clone())
            .unwrap_or(Err(AwsLambdaTransportError::MissingFixture))?;
        if self.rebind_default_request {
            rebind_response_request(response, request)
                .map_err(|_| AwsLambdaTransportError::MalformedResponse)
        } else {
            Ok(response)
        }
    }
}

#[derive(Clone, Debug)]
pub struct FakeTransport {
    inner: RecordingTransport,
}

impl FakeTransport {
    pub fn new() -> Self {
        Self {
            inner: RecordingTransport::new(TransportProvenance::Fake),
        }
    }

    pub fn for_scope(scope: &AwsLambdaScope) -> Result<Self> {
        Ok(Self {
            inner: RecordingTransport::for_scope(scope, TransportProvenance::Fake)?,
        })
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

impl AwsLambdaTransport for FakeTransport {
    fn provenance(&self) -> TransportProvenance {
        self.inner.provenance()
    }

    fn get_function(
        &mut self,
        request: &FunctionLookupRequest,
    ) -> std::result::Result<FunctionLookupResponse, AwsLambdaTransportError> {
        self.inner.get_function(request)
    }

    fn invoke(
        &mut self,
        request: &InvocationRequest,
    ) -> std::result::Result<ProviderInvocationResponse, AwsLambdaTransportError> {
        self.inner.invoke(request)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: RecordingTransport,
}

impl LoopbackTransport {
    pub fn new() -> Self {
        Self {
            inner: RecordingTransport::new(TransportProvenance::Loopback),
        }
    }

    pub fn for_scope(scope: &AwsLambdaScope) -> Result<Self> {
        Ok(Self {
            inner: RecordingTransport::for_scope(scope, TransportProvenance::Loopback)?,
        })
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

impl AwsLambdaTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        self.inner.provenance()
    }

    fn get_function(
        &mut self,
        request: &FunctionLookupRequest,
    ) -> std::result::Result<FunctionLookupResponse, AwsLambdaTransportError> {
        self.inner.get_function(request)
    }

    fn invoke(
        &mut self,
        request: &InvocationRequest,
    ) -> std::result::Result<ProviderInvocationResponse, AwsLambdaTransportError> {
        self.inner.invoke(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsLambdaTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn get_function(
        &mut self,
        _request: &FunctionLookupRequest,
    ) -> std::result::Result<FunctionLookupResponse, AwsLambdaTransportError> {
        Err(AwsLambdaTransportError::BlockedEnv)
    }

    fn invoke(
        &mut self,
        _request: &InvocationRequest,
    ) -> std::result::Result<ProviderInvocationResponse, AwsLambdaTransportError> {
        Err(AwsLambdaTransportError::BlockedEnv)
    }
}

/// Typed Lambda provider. Its public transport can only be the bounded seam
/// above; the provider never resolves credentials or performs live HTTPS.
#[derive(Debug)]
pub struct AwsLambdaProvider<T> {
    registration: AwsLambdaRegistration,
    transport: T,
    invocation_started: bool,
}

impl<T: AwsLambdaTransport> AwsLambdaProvider<T> {
    pub fn new(registration: AwsLambdaRegistration, transport: T) -> Result<Self> {
        registration.validate()?;
        Ok(Self {
            registration,
            transport,
            invocation_started: false,
        })
    }

    pub fn registration(&self) -> &AwsLambdaRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsLambdaRegistration {
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

    pub fn scope(&self) -> &AwsLambdaScope {
        self.registration.scope()
    }

    pub(crate) fn ensure_ready(&self) -> Result<()> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return match self.registration.status() {
                crate::model::RegistrationStatus::Revoked => {
                    Err(AwsLambdaInvocationResultError::RegistrationRevoked)
                }
                crate::model::RegistrationStatus::Reversed => {
                    Err(AwsLambdaInvocationResultError::RegistrationReversed)
                }
                crate::model::RegistrationStatus::Active => Ok(()),
            };
        }
        if self.registration.secret_reference().is_revoked() {
            return Err(AwsLambdaInvocationResultError::SecretRevoked);
        }
        Ok(())
    }

    pub fn read_function_metadata(&mut self) -> Result<FunctionLookupResponse> {
        self.ensure_ready()?;
        let request = FunctionLookupRequest::for_scope(self.scope());
        let response = self
            .transport
            .get_function(&request)
            .map_err(|error| map_transport_error(&error))?;
        response.validate_integrity()?;
        if response.provenance != self.provenance() {
            return Err(AwsLambdaInvocationResultError::TamperedEvidence);
        }
        self.scope().matches_provider_identities(
            &response.function,
            &self.scope().input,
            &self.scope().config,
            &self.scope().retry,
        )?;
        if response.config_digest != self.scope().config.digest()
            || response.config_revision != self.scope().config.revision
        {
            return Err(AwsLambdaInvocationResultError::ConfigDrift);
        }
        Ok(response)
    }

    pub fn project_invocation_result(
        &mut self,
        proposal: &InvocationProposal,
    ) -> Result<InvocationResultProjection> {
        self.ensure_ready()?;
        proposal.validate_integrity()?;
        if proposal.registration_id != *self.registration.id()
            || proposal.registration_digest != *self.registration.binding_digest()
            || proposal.scope_digest != *self.registration.scope_digest()
        {
            return Err(AwsLambdaInvocationResultError::RegistrationDrift);
        }
        let expected_scope = self.scope();
        if proposal.scope_digest != expected_scope.digest()
            || proposal.function != expected_scope.function
            || proposal.invocation_type != expected_scope.invocation_type
            || proposal.input != expected_scope.input
            || proposal.config != expected_scope.config
            || proposal.retry != expected_scope.retry
            || proposal.mission != expected_scope.mission
            || proposal.project != expected_scope.project
            || proposal.work_product != expected_scope.work_product
        {
            return Err(AwsLambdaInvocationResultError::ScopeMismatch);
        }
        if self.invocation_started {
            return Err(AwsLambdaInvocationResultError::Provider(
                AwsLambdaProviderError::DuplicateInvocation,
            ));
        }
        self.invocation_started = true;
        let request = InvocationRequest::from_proposal(proposal);
        request.validate(proposal)?;
        let response = self
            .transport
            .invoke(&request)
            .map_err(|error| map_transport_error(&error))?;
        response.validate_against(proposal)?;
        if response.provenance != self.provenance() {
            return Err(AwsLambdaInvocationResultError::TamperedEvidence);
        }
        InvocationResultProjection::new(
            proposal,
            response.status,
            response.failure_code,
            response.http_status,
            response.function_error,
            response.output_digest,
            response.error_digest,
            response.usage,
            response.response_bytes,
            response.response_truncated,
            response.attempt_number,
            response.observed_at_epoch_seconds,
            response.provenance,
        )
    }

    pub fn invoke(&mut self, proposal: &InvocationProposal) -> Result<InvocationResultProjection> {
        self.project_invocation_result(proposal)
    }

    /// Project a bounded provider failure into typed status evidence. A
    /// `BLOCKED_ENV` transport remains an explicit Layer-2 error rather than
    /// being misrepresented as provider success or Connected evidence.
    pub fn observe_bounded(
        &mut self,
        proposal: &InvocationProposal,
    ) -> Result<InvocationResultProjection> {
        match self.project_invocation_result(proposal) {
            Ok(projection) => Ok(projection),
            Err(
                AwsLambdaInvocationResultError::Transport(AwsLambdaTransportError::BlockedEnv)
                | AwsLambdaInvocationResultError::Provider(
                    AwsLambdaProviderError::LiveTransportRejected,
                ),
            ) => Err(AwsLambdaInvocationResultError::Transport(
                AwsLambdaTransportError::BlockedEnv,
            )),
            Err(AwsLambdaInvocationResultError::Provider(error)) => {
                self.failure_projection(proposal, error)
            }
            Err(error) => Err(error),
        }
    }

    fn failure_projection(
        &self,
        proposal: &InvocationProposal,
        error: AwsLambdaProviderError,
    ) -> Result<InvocationResultProjection> {
        let (status, failure_code, http_status, truncated) = match error {
            AwsLambdaProviderError::RateLimited { .. } => (
                InvocationStatus::Throttled,
                Some(FailureCode::RateLimited),
                Some(AwsLambdaHttpStatus::new(429)?),
                false,
            ),
            AwsLambdaProviderError::Timeout => (
                InvocationStatus::Timeout,
                Some(FailureCode::Timeout),
                Some(AwsLambdaHttpStatus::new(408)?),
                false,
            ),
            AwsLambdaProviderError::MalformedResponse => (
                InvocationStatus::Partial,
                Some(FailureCode::MalformedResponse),
                None,
                true,
            ),
            AwsLambdaProviderError::ResponseTooLarge => (
                InvocationStatus::Partial,
                Some(FailureCode::ResponseTooLarge),
                None,
                true,
            ),
            AwsLambdaProviderError::BadRequest => (
                InvocationStatus::ProviderUnknown,
                Some(FailureCode::BadRequest),
                Some(AwsLambdaHttpStatus::new(400)?),
                false,
            ),
            AwsLambdaProviderError::Unauthorized => (
                InvocationStatus::ProviderUnknown,
                Some(FailureCode::Unauthorized),
                Some(AwsLambdaHttpStatus::new(401)?),
                false,
            ),
            AwsLambdaProviderError::Forbidden => (
                InvocationStatus::ProviderUnknown,
                Some(FailureCode::Forbidden),
                Some(AwsLambdaHttpStatus::new(403)?),
                false,
            ),
            AwsLambdaProviderError::NotFound => (
                InvocationStatus::ProviderUnknown,
                Some(FailureCode::NotFound),
                Some(AwsLambdaHttpStatus::new(404)?),
                false,
            ),
            AwsLambdaProviderError::Conflict => (
                InvocationStatus::ProviderUnknown,
                Some(FailureCode::Conflict),
                Some(AwsLambdaHttpStatus::new(409)?),
                false,
            ),
            AwsLambdaProviderError::ServerError { status } => (
                InvocationStatus::ProviderUnknown,
                Some(FailureCode::ServerError),
                Some(AwsLambdaHttpStatus::new(status)?),
                false,
            ),
            AwsLambdaProviderError::AccessLost => (
                InvocationStatus::ProviderUnknown,
                Some(FailureCode::AccessLost),
                None,
                false,
            ),
            AwsLambdaProviderError::UnsupportedStatus(_) => (
                InvocationStatus::ProviderUnknown,
                Some(FailureCode::ProviderUnknown),
                None,
                false,
            ),
            AwsLambdaProviderError::DuplicateInvocation
            | AwsLambdaProviderError::MissingFixture
            | AwsLambdaProviderError::LiveTransportRejected => {
                return Err(AwsLambdaInvocationResultError::Provider(error));
            }
        };
        InvocationResultProjection::new(
            proposal,
            status,
            failure_code,
            http_status,
            false,
            None,
            None,
            UsageEvidence::for_input(&proposal.input)?,
            0,
            truncated,
            1,
            1,
            self.provenance(),
        )
    }
}

fn map_transport_error(error: &AwsLambdaTransportError) -> AwsLambdaInvocationResultError {
    match error {
        AwsLambdaTransportError::BlockedEnv => {
            AwsLambdaInvocationResultError::Transport(AwsLambdaTransportError::BlockedEnv)
        }
        AwsLambdaTransportError::LiveTransportRejected => {
            AwsLambdaInvocationResultError::Provider(AwsLambdaProviderError::LiveTransportRejected)
        }
        AwsLambdaTransportError::Http(status) => {
            AwsLambdaInvocationResultError::Provider((*status).into())
        }
        AwsLambdaTransportError::Timeout => {
            AwsLambdaInvocationResultError::Provider(AwsLambdaProviderError::Timeout)
        }
        AwsLambdaTransportError::AccessLost => {
            AwsLambdaInvocationResultError::Provider(AwsLambdaProviderError::AccessLost)
        }
        AwsLambdaTransportError::MalformedResponse => {
            AwsLambdaInvocationResultError::Provider(AwsLambdaProviderError::MalformedResponse)
        }
        AwsLambdaTransportError::ResponseTooLarge => {
            AwsLambdaInvocationResultError::Provider(AwsLambdaProviderError::ResponseTooLarge)
        }
        AwsLambdaTransportError::MissingFixture => {
            AwsLambdaInvocationResultError::Provider(AwsLambdaProviderError::MissingFixture)
        }
    }
}

fn rebind_response_request(
    response: ProviderInvocationResponse,
    request: &InvocationRequest,
) -> Result<ProviderInvocationResponse> {
    ProviderInvocationResponse::new(
        request.request_digest.clone(),
        response.function,
        response.config_digest,
        response.config_revision,
        response.status,
        response.failure_code,
        response.http_status,
        response.function_error,
        response.output_digest,
        response.error_digest,
        response.usage,
        response.response_bytes,
        response.response_truncated,
        request.attempt_number,
        response.observed_at_epoch_seconds,
        response.provenance,
    )
}
