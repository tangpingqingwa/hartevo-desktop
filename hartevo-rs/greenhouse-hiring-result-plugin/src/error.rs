use thiserror::Error;

/// Errors exposed by the standalone Layer-1 Greenhouse contract.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GreenhouseError {
    #[error("invalid text in {field}")]
    InvalidText { field: &'static str },
    #[error("invalid identifier in {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid SHA-256 digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("invalid revision in {field}")]
    InvalidRevision { field: &'static str },
    #[error("invalid Greenhouse hiring scope")]
    InvalidScope,
    #[error("invalid Layer-1 capability set")]
    InvalidCapabilitySet,
    #[error("invalid consent scope or receipt")]
    InvalidConsent,
    #[error("consent is expired, withdrawn, or outside the requested scope")]
    ConsentUnavailable,
    #[error("opaque SecretReference is invalid")]
    InvalidSecretReference,
    #[error("opaque SecretReference is revoked")]
    SecretRevoked,
    #[error("registration binding is invalid")]
    InvalidRegistration,
    #[error("registration is already active")]
    RegistrationAlreadyActive,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration transition is not allowed")]
    RegistrationTransitionNotAllowed,
    #[error("registration, scope, provider, capability, or credential digest drifted")]
    RegistrationDrift,
    #[error("requested scope does not match the registration")]
    ScopeMismatch,
    #[error("provider revision mismatch: expected {expected}, actual {actual}")]
    RevisionMismatch { expected: u64, actual: u64 },
    #[error("evidence digest mismatch")]
    DigestMismatch,
    #[error("stale or mismatched hiring snapshot")]
    StaleSnapshot,
    #[error("evidence integrity check failed")]
    TamperedEvidence,
    #[error("raw candidate or restricted hiring data crossed the Layer-1 boundary")]
    RestrictedData,
    #[error("Harvest endpoint is not allowlisted for the registered scope: {path}")]
    EndpointNotAllowed { path: String },
    #[error("Harvest pagination link repeated")]
    PaginationLoop,
    #[error("Harvest pagination exceeded the Layer-1 bound")]
    PaginationLimit,
    #[error("Harvest response exceeded the Layer-1 byte bound")]
    ResponseTooLarge,
    #[error("Harvest response was malformed at {endpoint}: {message}")]
    InvalidResponse { endpoint: String, message: String },
    #[error("Harvest access was lost at {endpoint}")]
    AccessLost { endpoint: String },
    #[error("Harvest provider could not classify the response at {endpoint}")]
    ProviderUnknown { endpoint: String },
    #[error("Harvest request conflicted at {endpoint}")]
    ProviderConflict { endpoint: String },
    #[error("Harvest request was rate limited after the retry bound")]
    RateLimitExhausted,
    #[error("Harvest server error persisted after the retry bound")]
    ServerErrorExhausted,
    #[error("BLOCKED_ENV: native Greenhouse credentials or HTTPS transport are unavailable")]
    BlockedEnv,
    #[error("Harvest transport failed: {message}")]
    Transport { message: String },
    #[error("Layer 1 is read/proposal/recording only; {operation} is reserved for Layer 2")]
    MutationNotAvailable { operation: &'static str },
    #[error("receipt read-back did not match the requested registration or evidence")]
    ReceiptMismatch,
    #[error("recording replay used a different evidence or proposal digest")]
    ReplayConflict,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("BLOCKED_ENV")]
    BlockedEnv,
    #[error("transport is unavailable: {0}")]
    Unavailable(String),
}
