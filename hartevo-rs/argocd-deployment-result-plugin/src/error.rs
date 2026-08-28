use thiserror::Error;

/// Errors emitted by the deterministic Argo CD transport seam. No variant
/// carries response bodies, bearer tokens, manifests, secrets, or logs.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ArgoCdTransportError {
    #[error("Argo CD native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Argo CD returned HTTP 401 or 403: access loss")]
    AccessLost,
    #[error("Argo CD returned HTTP 404")]
    NotFound,
    #[error("Argo CD returned HTTP 409")]
    Conflict,
    #[error("Argo CD returned HTTP 429: rate limited")]
    RateLimited { retry_after_seconds: Option<u32> },
    #[error("Argo CD transport timed out")]
    Timeout,
    #[error("Argo CD provider returned an unknown failure")]
    ProviderUnknown,
}

impl ArgoCdTransportError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::BlockedEnv => "blocked_env",
            Self::AccessLost => "access_loss",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::RateLimited { .. } => "rate_limited",
            Self::Timeout => "timeout",
            Self::ProviderUnknown => "provider_unknown",
        }
    }

    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::AccessLost => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::BlockedEnv | Self::Timeout | Self::ProviderUnknown => None,
        }
    }
}

/// Errors from the Argo CD Layer-1 boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ArgoCdDeploymentError {
    #[error("invalid digest")]
    InvalidDigest,
    #[error("invalid {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid revision for {field}")]
    InvalidRevision { field: &'static str },
    #[error("revision overflow")]
    RevisionOverflow,
    #[error("invalid scope: {0}")]
    InvalidScope(&'static str),
    #[error("invalid secret reference")]
    InvalidSecretReference,
    #[error("secret reference is revoked")]
    SecretRevoked,
    #[error("invalid consent")]
    InvalidConsent,
    #[error("consent is not active")]
    ConsentMismatch,
    #[error("invalid permission snapshot")]
    InvalidPermissions,
    #[error("invalid request")]
    InvalidRequest,
    #[error("invalid response")]
    InvalidResponse,
    #[error("response exceeds the Layer-1 bound")]
    ResponseTooLarge,
    #[error("response digest or declared evidence was tampered")]
    TamperedEvidence,
    #[error("provider response does not match the registered scope")]
    ScopeMismatch,
    #[error("provider response is from a stale target revision")]
    StaleRevision,
    #[error("resource-tree bound reached")]
    ResourceBound,
    #[error("partial provider evidence")]
    PartialEvidence,
    #[error("registration is inactive")]
    RegistrationInactive,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is already reversed")]
    AlreadyReversed,
    #[error("registration cannot be changed after reversal")]
    RegistrationReversed,
    #[error("invalid registration")]
    InvalidRegistration,
    #[error("invalid proposal")]
    InvalidProposal,
    #[error("recording conflict for an idempotency key")]
    RecordingConflict,
    #[error("mutation is forbidden in Layer 1: {operation}")]
    MutationForbidden { operation: &'static str },
    #[error("contract drift")]
    ContractDrift,
    #[error("transport error: {0}")]
    Transport(ArgoCdTransportError),
}

impl From<ArgoCdTransportError> for ArgoCdDeploymentError {
    fn from(value: ArgoCdTransportError) -> Self {
        Self::Transport(value)
    }
}

pub type ArgoCdError = ArgoCdDeploymentError;
pub type Result<T> = std::result::Result<T, ArgoCdDeploymentError>;
