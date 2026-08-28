//! Bounded semantic errors for the Lambda result boundary.

use thiserror::Error;

use crate::model::AwsLambdaHttpStatus;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsLambdaProviderError {
    #[error("provider rejected the typed request with HTTP 400")]
    BadRequest,
    #[error("provider rejected authentication with HTTP 401")]
    Unauthorized,
    #[error("provider denied access with HTTP 403")]
    Forbidden,
    #[error("Lambda function was not found with HTTP 404")]
    NotFound,
    #[error("provider reported a conflicting Lambda state with HTTP 409")]
    Conflict,
    #[error("Lambda provider rate limited the request")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Lambda provider returned server error HTTP {status}")]
    ServerError { status: u16 },
    #[error("Lambda provider request timed out")]
    Timeout,
    #[error("Lambda provider access was lost")]
    AccessLost,
    #[error("Lambda provider response was malformed")]
    MalformedResponse,
    #[error("Lambda provider response exceeded the bounded response size")]
    ResponseTooLarge,
    #[error("Layer 1 transport cannot perform live AWS Lambda HTTPS work")]
    LiveTransportRejected,
    #[error("the same invocation proposal was replayed")]
    DuplicateInvocation,
    #[error("recording fixture is missing")]
    MissingFixture,
    #[error("provider returned an unsupported HTTP status {0}")]
    UnsupportedStatus(AwsLambdaHttpStatus),
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsLambdaTransportError {
    #[error("HTTP status {0}")]
    Http(AwsLambdaHttpStatus),
    #[error("provider request timed out")]
    Timeout,
    #[error("provider access was lost")]
    AccessLost,
    #[error("provider response was malformed")]
    MalformedResponse,
    #[error("provider response exceeded the bounded response size")]
    ResponseTooLarge,
    #[error("fixture is missing")]
    MissingFixture,
    #[error("BLOCKED_ENV: live AWS Lambda transport is unavailable in Layer 1")]
    BlockedEnv,
    #[error("live AWS Lambda transport is forbidden in Layer 1")]
    LiveTransportRejected,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsLambdaInvocationResultError {
    #[error("invalid text in {field}")]
    InvalidText { field: &'static str },
    #[error("invalid identifier in {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("invalid AWS account, region, function ARN, version, or alias")]
    InvalidAwsIdentity,
    #[error("invalid exact AWS Lambda/Mission scope")]
    InvalidScope,
    #[error("invalid invocation type or invocation configuration")]
    InvalidInvocationConfiguration,
    #[error("input exceeds the bound for the selected invocation type")]
    InputTooLarge,
    #[error("provider response exceeds the bounded response size")]
    ResponseTooLarge,
    #[error("invalid or forbidden read-only permission snapshot")]
    InvalidPermissionSnapshot,
    #[error("invalid opaque SigV4 SecretReference")]
    InvalidSecretReference,
    #[error("registration binding is invalid")]
    InvalidRegistration,
    #[error("registration already exists")]
    RegistrationAlreadyExists,
    #[error("registration is unknown")]
    RegistrationUnknown,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("registration/provider/permission/scope binding drifted")]
    RegistrationDrift,
    #[error("exact AWS Lambda/Mission scope does not match")]
    ScopeMismatch,
    #[error("function ARN drifted")]
    FunctionArnDrift,
    #[error("published function version drifted")]
    FunctionVersionDrift,
    #[error("function alias drifted")]
    FunctionAliasDrift,
    #[error("function code SHA-256 drifted")]
    FunctionCodeShaDrift,
    #[error("function metadata revision drifted")]
    FunctionRevisionDrift,
    #[error("input identity or revision drifted")]
    InputDrift,
    #[error("invocation configuration or revision drifted")]
    ConfigDrift,
    #[error("retry policy or revision drifted")]
    RetryDrift,
    #[error("Mission identity or revision drifted")]
    MissionDrift,
    #[error("Project identity or revision drifted")]
    ProjectDrift,
    #[error("Work Product identity or revision drifted")]
    WorkProductDrift,
    #[error("Mission revision is stale")]
    StaleMissionRevision,
    #[error("invocation proposal is invalid")]
    InvalidProposal,
    #[error("provider evidence was tampered")]
    TamperedEvidence,
    #[error("request digest mismatch")]
    RequestDigestMismatch,
    #[error("output digest mismatch")]
    OutputDigestMismatch,
    #[error("error digest mismatch")]
    ErrorDigestMismatch,
    #[error("usage digest mismatch")]
    UsageDigestMismatch,
    #[error("registration digest mismatch")]
    RegistrationDigestMismatch,
    #[error("provider evidence is partial or truncated")]
    PartialEvidence,
    #[error("provider state is unknown")]
    ProviderUnknown,
    #[error("an equivalent recording key was replayed with different evidence")]
    ReplayConflict,
    #[error("secret reference was revoked")]
    SecretRevoked,
    #[error("function error is missing its bounded error digest")]
    MissingFunctionErrorDigest,
    #[error("synchronous successful result is missing its bounded output digest")]
    MissingOutputDigest,
    #[error("retry attempt exceeds the registered bound")]
    RetryLimitExceeded,
    #[error("provider error: {0}")]
    Provider(#[from] AwsLambdaProviderError),
    #[error("transport error: {0}")]
    Transport(#[from] AwsLambdaTransportError),
}

pub type Result<T> = std::result::Result<T, AwsLambdaInvocationResultError>;

impl From<AwsLambdaHttpStatus> for AwsLambdaProviderError {
    fn from(status: AwsLambdaHttpStatus) -> Self {
        match status.as_u16() {
            400 | 413 | 415 => Self::BadRequest,
            401 => Self::Unauthorized,
            403 => Self::Forbidden,
            404 => Self::NotFound,
            409 => Self::Conflict,
            408 => Self::Timeout,
            429 => Self::RateLimited {
                retry_after_seconds: None,
            },
            500..=599 => Self::ServerError {
                status: status.as_u16(),
            },
            _ => Self::UnsupportedStatus(status),
        }
    }
}

impl From<AwsLambdaTransportError> for AwsLambdaProviderError {
    fn from(error: AwsLambdaTransportError) -> Self {
        match error {
            AwsLambdaTransportError::Http(status) => status.into(),
            AwsLambdaTransportError::Timeout => Self::Timeout,
            AwsLambdaTransportError::AccessLost => Self::AccessLost,
            AwsLambdaTransportError::MalformedResponse => Self::MalformedResponse,
            AwsLambdaTransportError::ResponseTooLarge => Self::ResponseTooLarge,
            AwsLambdaTransportError::MissingFixture => Self::MissingFixture,
            AwsLambdaTransportError::BlockedEnv
            | AwsLambdaTransportError::LiveTransportRejected => Self::LiveTransportRejected,
        }
    }
}
