use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{label} is empty, malformed, or too long")]
    InvalidIdentifier { label: &'static str },
    #[error("{label} revision must be non-zero")]
    InvalidRevision { label: &'static str },
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("consent scope is invalid")]
    InvalidConsent,
    #[error("scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("event is invalid or outside the Layer-1 bound")]
    InvalidEvent,
    #[error("retry metadata is outside the Layer-1 bound")]
    InvalidRetry,
    #[error("suppression metadata is invalid")]
    InvalidSuppression,
    #[error("rate-limit metadata is outside the Layer-1 bound")]
    InvalidRateLimit,
    #[error("cursor is invalid")]
    InvalidCursor,
    #[error("idempotency key is invalid")]
    InvalidIdempotencyKey,
    #[error("webhook envelope is invalid")]
    InvalidWebhook,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is not revoked")]
    NotRevoked,
    #[error("registration revision overflowed")]
    RevisionOverflow,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MailgunTransportError {
    #[error("native Mailgun transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Mailgun transport timed out")]
    Timeout,
    #[error("Mailgun provider rate limit reached")]
    RateLimited {
        retry_after_seconds: Option<u32>,
        attempt: u16,
    },
    #[error("Mailgun provider denied the bounded read")]
    Denied,
    #[error("Mailgun provider resource was not found")]
    NotFound,
    #[error("Mailgun provider returned an unknown failure")]
    ProviderUnknown,
    #[error("Mailgun provider response was malformed")]
    MalformedResponse,
    #[error("Mailgun provider response exceeded the bounded byte limit")]
    ResponseTooLarge,
    #[error("Mailgun webhook signature or event envelope was tampered")]
    Tampered,
    #[error("Mailgun webhook event replay was rejected")]
    Replay,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MailgunProviderError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error("Mailgun SecretReference is revoked")]
    SecretRevoked,
    #[error("Mailgun provider registration is revoked")]
    RegistrationRevoked,
    #[error("Mailgun request scope does not match the provider scope")]
    ScopeMismatch,
    #[error("Mailgun request consent does not match the provider consent")]
    ConsentMismatch,
    #[error("Mailgun request revision fence is stale")]
    RevisionMismatch,
    #[error("Mailgun request cursor is not bound to the current fence")]
    CursorMismatch,
    #[error("Mailgun request page is outside the bounded pagination window")]
    PaginationBound,
    #[error("Mailgun webhook is tampered")]
    WebhookTampered,
    #[error("Mailgun webhook is a replay")]
    WebhookReplay,
    #[error(transparent)]
    Transport(#[from] MailgunTransportError),
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MailgunDeliveryResultServiceError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Provider(#[from] MailgunProviderError),
    #[error("Mailgun registration is revoked")]
    RegistrationRevoked,
    #[error("Mailgun consent is expired")]
    ConsentExpired,
    #[error("Mailgun consent digest does not match the registered scope")]
    ConsentMismatch,
    #[error("Mailgun scope revision is stale")]
    RevisionMismatch,
    #[error("Mailgun proposal does not match the active registration")]
    RegistrationMismatch,
    #[error("Mailgun proposal failed its integrity fence")]
    EvidenceMismatch,
    #[error("Mailgun idempotency key was reused for a different proposal")]
    IdempotencyConflict,
    #[error("Mailgun record idempotency key is invalid")]
    InvalidIdempotencyKey,
    #[error("Mailgun proposal replay was rejected")]
    ReplayDetected,
    #[error("Mailgun webhook event replay was rejected")]
    WebhookReplay,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionMailgunDeliveryConsumerError {
    #[error("Mission Mailgun delivery consumer is revoked")]
    Revoked,
    #[error("Mission Mailgun registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission revision is stale")]
    StaleMission,
    #[error("Work Product revision is stale")]
    StaleWorkProduct,
    #[error("Mission Mailgun proposal replay was rejected")]
    ReplayDetected,
    #[error("Mission Mailgun proposal is invalid")]
    InvalidProposal,
    #[error(transparent)]
    Service(#[from] MailgunDeliveryResultServiceError),
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ContractError {
    #[error("Mailgun delivery-result contract JSON is malformed")]
    Malformed,
    #[error("Mailgun delivery-result contract drifted from the typed surface")]
    Drift,
}

pub type ModelResult<T> = std::result::Result<T, ModelError>;
pub type ProviderResult<T> = std::result::Result<T, MailgunProviderError>;
pub type ServiceResult<T> = std::result::Result<T, MailgunDeliveryResultServiceError>;
