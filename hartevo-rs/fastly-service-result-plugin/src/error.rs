use thiserror::Error;

pub type Result<T> = std::result::Result<T, FastlyServiceResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FastlyServiceResultError {
    #[error("invalid {field}: {reason}")]
    InvalidIdentifier {
        field: &'static str,
        reason: &'static str,
    },
    #[error("invalid digest")]
    InvalidDigest,
    #[error("invalid {field} revision")]
    InvalidRevision { field: &'static str },
    #[error("revision overflow")]
    RevisionOverflow,
    #[error("secret reference is invalid")]
    InvalidSecretReference,
    #[error("secret reference is revoked")]
    SecretReferenceRevoked,
    #[error("provider registration is inactive")]
    RegistrationInactive,
    #[error("provider registration is revoked")]
    RegistrationRevoked,
    #[error("provider registration is reversed")]
    RegistrationReversed,
    #[error("provider registration is already active")]
    RegistrationAlreadyActive,
    #[error("provider registration is not reversible")]
    RegistrationNotReversible,
    #[error("permission snapshot does not match the Layer-1 read allowlist")]
    PermissionMismatch,
    #[error("consent scope does not match the Layer-1 registration")]
    ConsentMismatch,
    #[error("scope mismatch")]
    ScopeMismatch,
    #[error("stale Mission or registration revision")]
    StaleRevision,
    #[error("stale evidence")]
    StaleEvidence,
    #[error("tampered provider response or evidence")]
    Tampered,
    #[error("replayed idempotency key with a different evidence digest")]
    Replay,
    #[error("duplicate observation")]
    DuplicateObservation,
    #[error("page limit must be between one and the Layer-1 maximum")]
    PageLimitExceeded,
    #[error("response body exceeded the Layer-1 bound")]
    ResponseTooLarge,
    #[error("unexpected provider response")]
    UnexpectedResponse,
    #[error("provider transport is unknown in this environment")]
    ProviderUnknown,
    #[error("provider access was lost")]
    AccessLoss,
    #[error("provider request timed out")]
    Timeout,
    #[error("provider returned a server error")]
    ServerError,
    #[error("provider rate limit retry budget was exhausted")]
    RateLimitExhausted,
    #[error("provider operation is forbidden in Layer 1: {operation}")]
    MutationForbidden { operation: String },
    #[error("contract error: {0}")]
    Contract(String),
    #[error("provider error: {0}")]
    Provider(String),
}

pub type FastlyError = FastlyServiceResultError;
