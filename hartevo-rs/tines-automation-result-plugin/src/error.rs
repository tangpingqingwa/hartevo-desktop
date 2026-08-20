use thiserror::Error;

pub type Result<T> = std::result::Result<T, TinesAutomationResultError>;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TinesAutomationResultError {
    #[error("{label} is empty, malformed, or too long")]
    InvalidIdentifier { label: &'static str },
    #[error("{label} is invalid")]
    InvalidValue { label: &'static str },
    #[error("time window is invalid or exceeds the Layer-1 bound")]
    InvalidTimeWindow,
    #[error("opaque SecretReference is invalid")]
    InvalidSecretReference,
    #[error("provider permission set is incomplete or not read-only")]
    InvalidPermissionSet,
    #[error(
        "scope does not match the registered tenant, story, action, run, event, case, or Mission"
    )]
    ScopeMismatch,
    #[error("consent does not match the registered scope")]
    ConsentMismatch,
    #[error("provider digest does not match the registration")]
    ProviderDigestMismatch,
    #[error("contract digest does not match the registration")]
    ContractDigestMismatch,
    #[error("registration is inactive or has been revoked")]
    RegistrationInactive,
    #[error("registration or evidence digest is tampered")]
    TamperedEvidence,
    #[error("evidence is stale for the current Mission, entity, consent, or provider revision")]
    StaleEvidence,
    #[error("evidence digest does not match its normalized content")]
    EvidenceDigestMismatch,
    #[error("proposal digest does not match its normalized content")]
    ProposalDigestMismatch,
    #[error("duplicate evidence was presented with a different digest")]
    DuplicateEvidence,
    #[error("recording idempotency key conflicts with a different proposal")]
    RecordingConflict,
    #[error("provider response is larger than the Layer-1 bound")]
    ResponseTooLarge,
    #[error("provider pagination exceeds the Layer-1 bound")]
    PaginationExceeded,
    #[error("provider request is not an allowlisted read-only GET")]
    RequestNotAllowlisted,
    #[error("provider response is malformed or cannot be normalized")]
    MalformedResponse,
    #[error("evidence is outside the registered time window")]
    OutOfScopeTime,
    #[error("transport is blocked by BLOCKED_ENV")]
    BlockedEnv,
    #[error("transport timed out")]
    Timeout,
    #[error("provider returned an unknown transport failure")]
    ProviderUnknown,
    #[error("provider access was lost")]
    AccessLost,
    #[error("provider rate limit requires retry after {retry_after_seconds} seconds")]
    RateLimited { retry_after_seconds: u32 },
    #[error("partial provider evidence is not complete")]
    PartialEvidence,
}

pub type TinesAutomationResultErrorKind = TinesAutomationResultError;
