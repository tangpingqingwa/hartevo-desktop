use thiserror::Error;

/// Errors are intentionally categorical. Provider messages and raw response
/// bodies never cross the Layer-1 error boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AwsAppFlowResultError {
    #[error("contract document is invalid")]
    ContractInvalid,
    #[error("contract digest is invalid")]
    InvalidDigest,
    #[error("identifier is invalid")]
    InvalidIdentifier,
    #[error("secret reference is invalid")]
    InvalidSecretReference,
    #[error("scope is invalid")]
    InvalidScope,
    #[error("scope does not match the request or evidence")]
    ScopeMismatch,
    #[error("permission snapshot is invalid or drifted")]
    PermissionDrift,
    #[error("revision fence does not match")]
    RevisionMismatch,
    #[error("pagination is outside the bounded Layer-1 limit")]
    PaginationLimit,
    #[error("opaque cursor does not match its operation, scope, or revision fence")]
    CursorMismatch,
    #[error("response exceeds the bounded Layer-1 response limit")]
    ResponseTooLarge,
    #[error("response integrity digest does not match")]
    ResponseTampered,
    #[error("proposal integrity digest does not match")]
    ProposalTampered,
    #[error("evidence is outside the exact registered scope")]
    EvidenceOutOfScope,
    #[error("evidence replay does not match the recorded proposal")]
    ReplayMismatch,
    #[error("recording has no response for the requested operation")]
    RecordingExhausted,
    #[error("registration is not active")]
    RegistrationInactive,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("registration transition is invalid")]
    InvalidRegistrationTransition,
    #[error("secret reference is revoked")]
    SecretRevoked,
    #[error("provider returned an access-loss projection")]
    AccessLoss,
    #[error("provider returned an unknown projection")]
    ProviderUnknown,
    #[error("provider response is malformed")]
    MalformedResponse,
    #[error("provider response is not found")]
    NotFound,
    #[error("provider response is throttled")]
    Throttled,
    #[error("invalid evidence state transition")]
    InvalidStateTransition,
    #[error("invalid timing projection")]
    InvalidTiming,
    #[error("invalid bounded counter")]
    InvalidCounter,
    #[error("blocked environment has no native transport")]
    BlockedEnv,
}

pub type Result<T> = std::result::Result<T, AwsAppFlowResultError>;

/// Transport failures are classified before a service creates a proposal.
/// This enum deliberately carries no raw provider text or response body.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AwsAppFlowTransportError {
    #[error("validation failure")]
    BadRequest,
    #[error("unauthenticated")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("flow not found")]
    NotFound,
    #[error("provider conflict")]
    Conflict,
    #[error("provider rate limit")]
    RateLimited { retry_after_seconds: Option<u32> },
    #[error("provider server failure")]
    ServerError { status: u16 },
    #[error("provider timeout")]
    Timeout,
    #[error("provider response malformed")]
    MalformedResponse,
    #[error("provider access lost")]
    AccessLost,
    #[error("provider is blocked in this environment")]
    BlockedEnv,
    #[error("recorded response replay mismatch")]
    ReplayMismatch,
    #[error("recording has no queued response")]
    RecordingExhausted,
}

impl AwsAppFlowTransportError {
    pub const fn status_code(self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::ServerError { status } => Some(status),
            Self::Timeout
            | Self::MalformedResponse
            | Self::AccessLost
            | Self::BlockedEnv
            | Self::ReplayMismatch
            | Self::RecordingExhausted => None,
        }
    }
}
