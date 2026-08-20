use thiserror::Error;

/// Non-sensitive input failure categories. These errors never carry API
/// bodies, SQL, schema text, credentials, or provider diagnostics.
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
    #[error("value is not a valid cursor")]
    InvalidCursor,
    #[error("value is not a valid idempotency key")]
    InvalidIdempotencyKey,
    #[error("value is not a valid revision fence")]
    InvalidRevisionFence,
    #[error("operation is not available in Layer 1")]
    LayerTwoOnly,
}

/// Errors shared by the typed model, service, provider, and Mission consumer.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PlanetScaleBranchResultError {
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
    #[error("consent mismatch in {field}")]
    ConsentMismatch { field: &'static str },
    #[error("revision fence mismatch in {field}")]
    RevisionMismatch { field: &'static str },
    #[error("proposal and evidence receipt mismatch in {field}")]
    ReceiptMismatch { field: &'static str },
    #[error("recorded receipt is tampered or is not the provider's receipt")]
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
    #[error("proposal idempotency key already has a different digest")]
    IdempotencyConflict,
    #[error("native Connected/effect authority is not available in Layer 1")]
    NativeAuthority,
    #[error("provider error: {0}")]
    Provider(#[from] PlanetScaleProviderError),
}

/// Typed, non-sensitive failures at the bounded provider seam.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PlanetScaleProviderError {
    #[error("provider manifest is invalid or drifted")]
    ManifestMismatch,
    #[error("provider scope does not match the request")]
    ScopeMismatch,
    #[error("provider consent does not match the request")]
    ConsentMismatch,
    #[error("provider request is invalid")]
    InvalidRequest,
    #[error("provider response is invalid in {field}")]
    InvalidResponse { field: &'static str },
    #[error("provider permission was denied")]
    PermissionDenied,
    #[error("provider resource was not found")]
    NotFound,
    #[error("provider reported a conflicting or stale revision")]
    Conflict,
    #[error("provider returned a bounded rate-limit response")]
    RateLimited { retry_after_ms: u64 },
    #[error("provider operation timed out")]
    TimedOut,
    #[error("provider returned an unknown failure")]
    ProviderUnknown,
    #[error("provider transport is blocked by the Layer 1 environment")]
    BlockedEnv,
    #[error("provider registration is revoked")]
    RegistrationRevoked,
    #[error("provider response exceeds the Layer 1 response bound")]
    ResponseTooLarge,
    #[error("provider fingerprint already has a different recorded receipt")]
    DuplicateIdempotency,
    #[error("operation is unavailable in Layer 1")]
    LayerTwoOnly,
}
