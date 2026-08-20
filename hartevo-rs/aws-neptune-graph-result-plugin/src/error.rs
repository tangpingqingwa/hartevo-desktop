use thiserror::Error;

/// Crate result type.
pub type Result<T> = std::result::Result<T, AwsNeptuneGraphResultError>;

/// Redacted transport failures that can be mapped to bounded evidence states.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsNeptuneTransportError {
    #[error("Neptune rejected the bounded read request")]
    BadRequest,
    #[error("Neptune authentication was not available")]
    Unauthorized,
    #[error("Neptune denied the bounded read request")]
    Forbidden,
    #[error("the scoped Neptune graph was not found")]
    NotFound,
    #[error("the scoped Neptune graph request conflicted with provider state")]
    Conflict,
    #[error("Neptune rate limited the bounded read request")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Neptune returned a server failure")]
    Server { status_code: u16 },
    #[error("the Neptune read request timed out")]
    Timeout,
    #[error("the environment is blocked from native Neptune access")]
    BlockedEnvironment,
    #[error("the Neptune provider returned an unknown failure")]
    Unknown,
}

impl AwsNeptuneTransportError {
    /// Return the HTTP-like status when the transport supplied one.
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::Server { status_code } => Some(*status_code),
            Self::Timeout | Self::BlockedEnvironment | Self::Unknown => None,
        }
    }

    /// Return a stable category for evidence without retaining provider text.
    pub const fn category(&self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::RateLimited { .. } => "throttled",
            Self::Server { .. } => "server_error",
            Self::Timeout => "timeout",
            Self::BlockedEnvironment => "blocked_env",
            Self::Unknown => "provider_unknown",
        }
    }

    /// Return a deterministic retry hint without exposing error payloads.
    pub const fn retry_after_seconds(&self) -> Option<u64> {
        match self {
            Self::RateLimited {
                retry_after_seconds,
            } => *retry_after_seconds,
            _ => None,
        }
    }

    /// Whether the failure represents lost access to a previously scoped read.
    pub const fn is_access_loss(&self) -> bool {
        matches!(self, Self::Unauthorized | Self::Forbidden | Self::NotFound)
    }
}

/// Fail-closed errors for model, query, provider, registration, and evidence seams.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsNeptuneGraphResultError {
    #[error("identifier for {field} is empty, malformed, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("text for {field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("the Neptune scope is invalid")]
    InvalidScope,
    #[error("the read bounds are empty or exceed the Layer-1 safety ceiling")]
    InvalidBounds,
    #[error("the parameter binding is invalid")]
    InvalidParameter,
    #[error("the graph projection is invalid")]
    InvalidProjection,
    #[error("the query compiler rejected the openCypher text")]
    QueryRejected,
    #[error("the versioned contract metadata drifted")]
    ContractDrift,
    #[error("the registration is inactive")]
    RegistrationInactive,
    #[error("the registration is revoked")]
    RegistrationRevoked,
    #[error("the registration is reversed")]
    RegistrationReversed,
    #[error("the registration digest or binding is invalid")]
    InvalidRegistration,
    #[error("the SecretReference does not match the exact scope")]
    SecretScopeMismatch,
    #[error("the proposal or request does not match the exact scope")]
    ScopeMismatch,
    #[error("the permission snapshot does not match the exact registration")]
    PermissionMismatch,
    #[error("the provider definition is invalid")]
    InvalidProvider,
    #[error("the provider response does not match the request fence")]
    ResponseFenceMismatch,
    #[error("the provider response digest does not match its redacted rows")]
    ResultDigestMismatch,
    #[error("the query digest does not match the compiled query")]
    QueryDigestMismatch,
    #[error("the parameter digest does not match the compiled bindings")]
    ParameterDigestMismatch,
    #[error("the evidence or recording was tampered with")]
    TamperedEvidence,
    #[error("the idempotency key was replayed with a different proposal")]
    ReplayConflict,
    #[error("the provider returned a repeated pagination cursor")]
    PaginationLoop,
    #[error("the response exceeded the bounded row or byte limit")]
    ResponseLimitExceeded,
    #[error("the provider elapsed time exceeded the bounded time limit")]
    TimeLimitExceeded,
    #[error("the request is invalid")]
    InvalidRequest,
    #[error("the transport returned a bounded failure")]
    Transport(#[from] AwsNeptuneTransportError),
}
