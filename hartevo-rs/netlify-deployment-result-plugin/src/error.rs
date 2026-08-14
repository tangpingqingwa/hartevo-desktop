use thiserror::Error;

/// Errors produced by the deterministic transport seam. No variant contains
/// a response body, bearer token, environment variable, or provider log.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NetlifyTransportError {
    #[error("Netlify native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Netlify returned HTTP 401")]
    Unauthorized,
    #[error("Netlify returned HTTP 403")]
    Forbidden,
    #[error("Netlify returned HTTP 404")]
    NotFound,
    #[error("Netlify returned HTTP 409")]
    Conflict,
    #[error("Netlify returned HTTP 429")]
    RateLimited { retry_after_seconds: Option<u32> },
    #[error("Netlify returned HTTP {0}")]
    ServerError(u16),
    #[error("Netlify transport timed out")]
    Timeout,
    #[error("Netlify transport lost access")]
    AccessLost,
    #[error("Netlify transport returned a partial response")]
    Partial,
    #[error("Netlify transport failed without a native response")]
    ProviderUnknown,
}

impl NetlifyTransportError {
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::ServerError(status) => Some(*status),
            Self::BlockedEnv
            | Self::Timeout
            | Self::AccessLost
            | Self::Partial
            | Self::ProviderUnknown => None,
        }
    }

    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::BlockedEnv => "blocked_env",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::RateLimited { .. } => "throttled",
            Self::ServerError(_) => "server_error",
            Self::Timeout => "timeout",
            Self::AccessLost => "access_loss",
            Self::Partial => "partial",
            Self::ProviderUnknown => "provider_unknown",
        }
    }
}

/// The single error surface for model, registration, provider, service, and
/// Mission-consumer validation. Provider failures are normally projected into
/// bounded evidence rather than returned from a read.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NetlifyDeploymentError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} revision must be non-zero")]
    InvalidRevision { field: &'static str },
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("Netlify deployment scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("opaque SecretReference is invalid")]
    InvalidSecretReference,
    #[error("permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("consent scope is invalid or expired")]
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
    #[error("Netlify request is invalid or outside the bounded allowlist")]
    InvalidRequest,
    #[error("Netlify response is malformed, oversized, or outside the metadata bounds")]
    InvalidResponse,
    #[error("Netlify response or evidence digest fence failed")]
    TamperedEvidence,
    #[error("Netlify site or deploy is outside the exact registration scope")]
    ScopeMismatch,
    #[error("Netlify commit is stale relative to the Mission scope")]
    StaleCommit,
    #[error("Netlify pagination cursor loop or bound was detected")]
    PaginationLoop,
    #[error("Netlify observation expired before it could be proposed")]
    Expired,
    #[error("Netlify consent is denied, revoked, or stale")]
    ConsentMismatch,
    #[error("Netlify proposal replay was rejected")]
    ReplayDetected,
    #[error("recording idempotency key conflicts with an existing proposal")]
    RecordingConflict,
    #[error("proposal is not valid for Mission consumption")]
    InvalidProposal,
    #[error("Netlify verification found no ready preview evidence")]
    NotReady,
    #[error("transport: {0}")]
    Transport(#[from] NetlifyTransportError),
}

pub type Result<T> = std::result::Result<T, NetlifyDeploymentError>;
