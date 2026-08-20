use thiserror::Error;

/// Typed provider failures. These variants intentionally carry no provider
/// body, URL, SQL, credential, or connection-string material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CockroachCloudTransportError {
    #[error("BLOCKED_ENV: native CockroachDB Cloud transport is unavailable in Layer 1")]
    BlockedEnv,
    #[error("recording has no bounded CockroachDB Cloud page")]
    NoRecordedPage,
    #[error("provider response is malformed or exceeds the bounded response limit")]
    InvalidResponse,
    #[error("provider reports the exact scoped resource is absent")]
    Absent,
    #[error("provider denied the scoped read")]
    Denied,
    #[error("provider returned partial posture evidence")]
    Partial,
    #[error("provider access was lost while reading the scoped resource")]
    AccessLoss,
    #[error("provider rate limit exhausted the bounded retry seam")]
    RateLimited { retry_after_seconds: u32 },
    #[error("provider did not identify the requested posture")]
    ProviderUnknown,
    #[error("provider read timed out")]
    TimedOut,
}

/// Fail-closed errors at the service, registration, proposal, and Mission
/// boundaries. Sensitive values are represented only by their field names.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CockroachCloudResultError {
    #[error("invalid {0}")]
    InvalidInput(&'static str),
    #[error("invalid digest in {0}")]
    InvalidDigest(&'static str),
    #[error("scope mismatch")]
    ScopeMismatch,
    #[error("exact scope revision fence drifted")]
    RevisionDrift,
    #[error("permission snapshot drifted or is not least privilege")]
    PermissionMismatch,
    #[error("opaque secret reference is not bound to the exact scope")]
    SecretScopeMismatch,
    #[error("provider definition drifted")]
    ProviderDrift,
    #[error("contract or plugin version drifted")]
    ContractDrift,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("registration is stale or tampered")]
    RegistrationTampered,
    #[error("registration transition is invalid")]
    InvalidRegistrationTransition,
    #[error("proposal is stale or tampered")]
    ProposalTampered,
    #[error("evidence is stale or tampered")]
    EvidenceTampered,
    #[error("redacted receipt is stale or tampered")]
    ReceiptTampered,
    #[error("opaque cursor is not bound to the exact scope, query, page, or expiry")]
    CursorMismatch,
    #[error("opaque cursor has expired")]
    CursorExpired,
    #[error("pagination is outside the Layer-1 bound")]
    PaginationLimit,
    #[error("pagination cursor repeated")]
    RepeatedCursor,
    #[error("request or evidence has expired")]
    Expired,
    #[error("recording idempotency key conflicts with a different proposal")]
    RecordingConflict,
    #[error("native or external authority is unavailable in Layer 1")]
    NativeAuthority,
    #[error("forbidden SQL, DDL, DML, cluster, branch, or settings operation")]
    ForbiddenOperation,
    #[error("provider error: {0}")]
    Provider(#[from] CockroachCloudTransportError),
}
