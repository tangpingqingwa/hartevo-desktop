use thiserror::Error;

/// Non-sensitive reasons used by typed input failures. They intentionally do
/// not carry SQL, parameters, raw rows, credentials, or provider error text.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum InputViolation {
    #[error("value is empty")]
    Empty,
    #[error("value exceeds its byte bound")]
    TooLong,
    #[error("value contains unsupported characters")]
    InvalidCharacters,
    #[error("value is outside its allowed range")]
    OutOfRange,
    #[error("value is not a valid digest")]
    InvalidDigest,
    #[error("value is not a valid identifier")]
    InvalidIdentifier,
    #[error("value is not a valid branch point")]
    InvalidBranchPoint,
    #[error("query is not an allowlisted read shape")]
    QueryNotAllowlisted,
    #[error("query must use positional parameters")]
    QueryNotParameterized,
    #[error("query contains more than one statement")]
    MultiStatement,
    #[error("query contains a comment")]
    CommentNotAllowed,
    #[error("query contains a forbidden operation")]
    ForbiddenOperation,
    #[error("query result is unbounded")]
    UnboundedResult,
    #[error("query parameter binding is invalid")]
    InvalidParameterBinding,
    #[error("query result is truncated")]
    TruncatedResult,
    #[error("query result schema is invalid")]
    InvalidSchema,
    #[error("query result rows are invalid")]
    InvalidRows,
    #[error("operation is not available in Layer 1")]
    LayerTwoOnly,
}

/// Errors shared by the model, service, consumer, and provider boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NeonBranchResultError {
    #[error("invalid {field}: {reason}")]
    InvalidInput {
        field: &'static str,
        reason: InputViolation,
    },
    #[error("invalid digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("digest mismatch in {field}")]
    DigestMismatch { field: &'static str },
    #[error("provider manifest mismatch in {field}")]
    ProviderManifestMismatch { field: &'static str },
    #[error("scope mismatch in {field}")]
    ScopeMismatch { field: &'static str },
    #[error("provider returned a response without an exact independent receipt")]
    MissingIndependentReceipt,
    #[error("receipt mismatch in {field}")]
    ReceiptMismatch { field: &'static str },
    #[error("receipt was tampered or is not the provider's recorded receipt")]
    TamperedReceipt,
    #[error("provider registration is required")]
    RegistrationRequired,
    #[error("provider registration is revoked")]
    RegistrationRevoked,
    #[error("provider registration does not match the requested scope or version")]
    RegistrationMismatch,
    #[error("provider registration already exists")]
    RegistrationAlreadyExists,
    #[error("provider registration is unknown")]
    RegistrationUnknown,
    #[error("provider registration revision is stale")]
    RegistrationStale,
    #[error("native Connected/effect authority is not available in Layer 1")]
    NativeAuthority,
    #[error("provider error: {0}")]
    Provider(#[from] NeonProviderError),
}

/// Typed, non-sensitive failures at one of the two provider transport seams.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NeonProviderError {
    #[error("provider manifest is invalid or drifted")]
    ManifestMismatch,
    #[error("provider scope does not match the request")]
    ScopeMismatch,
    #[error("recording has no fixture for this query")]
    NoRecordedQuery,
    #[error("recording has no fixture for this capability probe")]
    NoRecordedProbe,
    #[error("provider response is invalid in {field}")]
    InvalidResponse { field: &'static str },
    #[error("provider returned a permission-lost state")]
    PermissionLost,
    #[error("provider returned a throttled state; retry after the bounded delay")]
    RateLimited { retry_after_ms: u64 },
    #[error("provider operation timed out")]
    TimedOut,
    #[error("provider operation is pending eventual consistency")]
    EventualConsistencyPending,
    #[error("provider transport is blocked by the Layer 1 environment")]
    BlockedEnv,
    #[error("provider receipt does not match the independent recording")]
    ReceiptMismatch,
    #[error("provider fingerprint already has a different recorded receipt")]
    DuplicateFingerprint,
    #[error("provider operation is unavailable in Layer 1")]
    LayerTwoOnly,
}
