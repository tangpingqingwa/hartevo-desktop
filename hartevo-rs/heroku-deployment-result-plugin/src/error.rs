use thiserror::Error;

/// Failures from the deterministic transport seam. Response bodies and
/// credentials are deliberately absent from every variant.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HerokuTransportError {
    #[error("Heroku native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Heroku returned HTTP 401 or 403: access denied")]
    AccessDenied,
    #[error("Heroku returned HTTP 404")]
    NotFound,
    #[error("Heroku returned HTTP 409")]
    Conflict,
    #[error("Heroku returned HTTP 429")]
    RateLimited { retry_after_seconds: Option<u32> },
    #[error("Heroku transport timed out")]
    Timeout,
    #[error("Heroku transport returned partial metadata")]
    Partial,
    #[error("Heroku provider returned an unknown failure")]
    ProviderUnknown,
}

impl HerokuTransportError {
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::AccessDenied => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::BlockedEnv | Self::Timeout | Self::Partial | Self::ProviderUnknown => None,
        }
    }

    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::BlockedEnv => "blocked_env",
            Self::AccessDenied => "denied",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::RateLimited { .. } => "rate_limited",
            Self::Timeout => "timeout",
            Self::Partial => "partial",
            Self::ProviderUnknown => "provider_unknown",
        }
    }
}

/// Validation and authority failures for the Heroku Layer-1 boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HerokuDeploymentError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} revision must be non-zero")]
    InvalidRevision { field: &'static str },
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("Heroku deployment scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("opaque SecretReference is invalid")]
    InvalidSecretReference,
    #[error("permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("consent scope is invalid, stale, or expired")]
    InvalidConsent,
    #[error("registration is invalid or has drifted")]
    InvalidRegistration,
    #[error("registration is inactive")]
    RegistrationInactive,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is already reversed")]
    AlreadyReversed,
    #[error("registration cannot be restored after reversal")]
    RegistrationReversed,
    #[error("SecretReference is revoked")]
    SecretRevoked,
    #[error("registration revision overflowed")]
    RevisionOverflow,
    #[error("Heroku request is invalid or outside the bounded GET allowlist")]
    InvalidRequest,
    #[error("Heroku response is malformed, oversized, or outside metadata bounds")]
    InvalidResponse,
    #[error("Heroku evidence or proposal digest fence failed")]
    TamperedEvidence,
    #[error("Heroku resource is outside the exact registration scope")]
    ScopeMismatch,
    #[error("Heroku or Mission revision is stale")]
    StaleRevision,
    #[error("Heroku pagination cursor loop was detected")]
    PaginationLoop,
    #[error("Heroku pagination bound was exceeded")]
    PaginationBound,
    #[error("Heroku observation is expired")]
    Expired,
    #[error("Heroku consent is denied, revoked, or stale")]
    ConsentMismatch,
    #[error("Heroku proposal replay was rejected")]
    ReplayDetected,
    #[error("recording idempotency key conflicts with an existing proposal")]
    RecordingConflict,
    #[error("proposal is not valid for Mission consumption")]
    InvalidProposal,
    #[error("Heroku write or mutation is forbidden in Layer 1: {operation}")]
    MutationForbidden { operation: &'static str },
    #[error("Heroku provider returned malformed or tampered evidence")]
    ProviderTamper,
    #[error("transport: {0}")]
    Transport(#[from] HerokuTransportError),
}

pub type Result<T> = std::result::Result<T, HerokuDeploymentError>;
