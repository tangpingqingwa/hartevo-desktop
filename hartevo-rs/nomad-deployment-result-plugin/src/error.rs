use thiserror::Error;

/// Failures from the deterministic transport boundary. No response body,
/// address, ACL token, Vault token, or other secret material is retained.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NomadTransportError {
    #[error("Nomad native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Nomad returned an unauthorized response")]
    Unauthorized,
    #[error("Nomad returned a forbidden response")]
    Forbidden,
    #[error("Nomad resource was absent")]
    NotFound,
    #[error("Nomad provider reported a conflict")]
    Conflict,
    #[error("Nomad provider rate limited the read")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Nomad transport timed out")]
    Timeout,
    #[error("Nomad returned partial metadata")]
    Partial,
    #[error("Nomad access was lost while reading metadata")]
    AccessLost,
    #[error("Nomad provider returned an unknown failure")]
    ProviderUnknown,
    #[error("Nomad response was malformed or oversized")]
    InvalidResponse,
    #[error("Nomad response integrity verification failed")]
    Tampered,
}

impl NomadTransportError {
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::Partial => Some(206),
            Self::BlockedEnv
            | Self::Timeout
            | Self::AccessLost
            | Self::ProviderUnknown
            | Self::InvalidResponse
            | Self::Tampered => None,
        }
    }

    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::BlockedEnv => "blocked_env",
            Self::Unauthorized | Self::Forbidden => "access_loss",
            Self::NotFound => "absent",
            Self::Conflict => "conflict",
            Self::RateLimited { .. } => "rate_limited",
            Self::Timeout => "timeout",
            Self::Partial => "partial",
            Self::AccessLost => "access_loss",
            Self::ProviderUnknown => "provider_unknown",
            Self::InvalidResponse => "invalid_response",
            Self::Tampered => "tampered",
        }
    }

    #[must_use]
    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::AccessLost
        )
    }
}

/// Validation, digest-fence, registration, and authority failures at the
/// Nomad Layer-1 boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NomadDeploymentResultError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} revision must be non-zero")]
    InvalidRevision { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("Nomad deployment scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("opaque SecretReference is invalid")]
    InvalidSecretReference,
    #[error("Nomad permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("Nomad consent scope is invalid, stale, or expired")]
    InvalidConsent,
    #[error("Nomad registration is invalid or has drifted")]
    InvalidRegistration,
    #[error("Nomad registration is inactive")]
    RegistrationInactive,
    #[error("Nomad registration is already revoked")]
    AlreadyRevoked,
    #[error("Nomad registration is already reversed")]
    AlreadyReversed,
    #[error("Nomad registration cannot be restored after reversal")]
    RegistrationReversed,
    #[error("Nomad registration revision overflowed")]
    RevisionOverflow,
    #[error("Nomad SecretReference is revoked")]
    SecretRevoked,
    #[error("Nomad request is invalid or outside the bounded GET allowlist")]
    InvalidRequest,
    #[error("Nomad response is malformed, oversized, or outside metadata bounds")]
    InvalidResponse,
    #[error("Nomad scope or digest fence failed")]
    ScopeMismatch,
    #[error("Nomad provider or contract definition drifted")]
    ProviderDrift,
    #[error("Nomad consent is denied, revoked, or stale")]
    ConsentMismatch,
    #[error("Nomad evidence or proposal digest fence failed")]
    TamperedEvidence,
    #[error("Nomad evidence is partial and cannot be adopted")]
    PartialEvidence,
    #[error("Nomad proposal replay was rejected")]
    ReplayDetected,
    #[error("Nomad recording idempotency key conflicts with an existing proposal")]
    RecordingConflict,
    #[error("Nomad proposal is not valid for Mission consumption")]
    InvalidProposal,
    #[error("Nomad revision is stale")]
    StaleRevision,
    #[error("Nomad mutation is forbidden in Layer 1: {operation}")]
    MutationForbidden { operation: &'static str },
    #[error("Nomad transport failed: {0}")]
    Transport(#[from] NomadTransportError),
}

pub type Result<T> = std::result::Result<T, NomadDeploymentResultError>;
