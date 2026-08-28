use thiserror::Error;

/// Failures from the deterministic transport seam. No variant carries a
/// response body, credential material, environment variable, or raw log.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RenderTransportError {
    #[error("Render native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Render returned HTTP 401 or 403: access loss")]
    AccessLost,
    #[error("Render returned HTTP 404")]
    NotFound,
    #[error("Render returned HTTP 409")]
    Conflict,
    #[error("Render returned HTTP 429")]
    RateLimited { retry_after_seconds: Option<u32> },
    #[error("Render transport timed out")]
    Timeout,
    #[error("Render transport returned a partial response")]
    Partial,
    #[error("Render provider returned an unknown failure")]
    ProviderUnknown,
}

impl RenderTransportError {
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::AccessLost => Some(403),
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
            Self::AccessLost => "access_loss",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::RateLimited { .. } => "rate_limited",
            Self::Timeout => "timeout",
            Self::Partial => "partial",
            Self::ProviderUnknown => "provider_unknown",
        }
    }
}

/// Validation, authority, and bounded projection failures for the plugin.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RenderDeploymentError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} revision must be non-zero")]
    InvalidRevision { field: &'static str },
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("Render deployment scope is invalid: {0}")]
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
    #[error("Render request is invalid or outside the bounded GET allowlist")]
    InvalidRequest,
    #[error("Render response is malformed, oversized, or outside metadata bounds")]
    InvalidResponse,
    #[error("Render evidence or proposal digest fence failed")]
    TamperedEvidence,
    #[error("Render service or deployment is outside the exact registration scope")]
    ScopeMismatch,
    #[error("Render commit or revision is stale relative to the Mission scope")]
    StaleRevision,
    #[error("Render pagination cursor loop was detected")]
    PaginationLoop,
    #[error("Render pagination bound was exceeded")]
    PaginationBound,
    #[error("Render observation is expired")]
    Expired,
    #[error("Render consent is denied, revoked, or stale")]
    ConsentMismatch,
    #[error("Render proposal replay was rejected")]
    ReplayDetected,
    #[error("recording idempotency key conflicts with an existing proposal")]
    RecordingConflict,
    #[error("proposal is not valid for Mission consumption")]
    InvalidProposal,
    #[error("Render write or mutation is forbidden in Layer 1: {operation}")]
    MutationForbidden { operation: &'static str },
    #[error("Render provider returned malformed or tampered evidence")]
    ProviderTamper,
    #[error("transport: {0}")]
    Transport(#[from] RenderTransportError),
}

pub type Result<T> = std::result::Result<T, RenderDeploymentError>;
