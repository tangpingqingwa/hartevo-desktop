use thiserror::Error;

/// Errors emitted by the bounded transport seam. No provider body, header
/// dump, URL token, or credential material is carried by an error.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum DovetailTransportError {
    #[error("Dovetail transport is blocked by the environment")]
    BlockedEnv,
    #[error("Dovetail transport timed out")]
    Timeout,
    #[error("Dovetail transport rejected a non-GET request")]
    MethodNotAllowed,
    #[error("Dovetail transport rejected an unallowlisted path")]
    PathNotAllowed,
    #[error("Dovetail transport response exceeded the requested byte bound")]
    ResponseTooLarge,
    #[error("Dovetail transport failed before a response")]
    Unavailable,
}

/// Typed provider failures. The variants intentionally contain only bounded
/// status and digest facts, never raw Dovetail response text.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum DovetailProviderError {
    #[error("Dovetail transport error: {0}")]
    Transport(#[from] DovetailTransportError),
    #[error("Dovetail response was malformed or omitted metadata")]
    MalformedResponse,
    #[error("Dovetail response exceeded the configured byte bound")]
    ResponseTooLarge,
    #[error("Dovetail pagination cursor repeated")]
    PaginationLoop,
    #[error("Dovetail pagination exceeded the configured page bound")]
    PaginationLimit,
    #[error("Dovetail response item was outside the registered scope")]
    OutOfScope,
    #[error("Dovetail provider revision drifted")]
    ProviderRevisionDrift,
    #[error("Dovetail access was lost or rejected")]
    AccessLost,
    #[error("Dovetail retention gap was reported")]
    RetentionGap,
    #[error("Dovetail provider returned an unknown status")]
    ProviderUnknown,
    #[error("Dovetail rate limit or transient retry budget was exhausted")]
    RetryExhausted,
}

/// All public Layer-1 failure paths are bounded, typed, and safe to log.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum DovetailResearchResultError {
    #[error("invalid {field}: {reason}")]
    InvalidInput {
        field: &'static str,
        reason: &'static str,
    },
    #[error("invalid {field} digest")]
    InvalidDigest { field: &'static str },
    #[error("invalid opaque SecretReference")]
    InvalidSecretReference,
    #[error("invalid Layer-1 contract")]
    InvalidContract,
    #[error("registration already exists")]
    RegistrationAlreadyExists,
    #[error("registration is unknown")]
    RegistrationUnknown,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("registration integrity or revision drifted")]
    RegistrationDrift,
    #[error("scope digest does not match the registered scope")]
    ScopeMismatch,
    #[error("provider digest does not match the registered provider")]
    ProviderMismatch,
    #[error("permission digest does not match the registered permissions")]
    PermissionMismatch,
    #[error("Mission revision or digest drifted")]
    MissionDrift,
    #[error("Work Product revision or digest drifted")]
    WorkProductDrift,
    #[error("Consent scope or digest drifted")]
    ConsentDrift,
    #[error("provider result was tampered or failed its digest fence")]
    TamperedResult,
    #[error("proposal is review-only and cannot be adopted")]
    AdoptionNotPermitted,
    #[error("recording idempotency key was replayed with different evidence")]
    ReplayConflict,
    #[error("provider error: {0}")]
    Provider(#[from] DovetailProviderError),
    #[error("transport error: {0}")]
    Transport(#[from] DovetailTransportError),
}

pub type Result<T> = std::result::Result<T, DovetailResearchResultError>;
