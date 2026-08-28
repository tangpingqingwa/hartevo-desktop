use thiserror::Error;

pub type Result<T> = std::result::Result<T, SodaQualityResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SodaTransportError {
    #[error("BLOCKED_ENV: Soda native transport is disabled")]
    BlockedEnv,
    #[error("Soda provider denied the requested read")]
    Denied,
    #[error("Soda provider rate limited the requested read")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Soda provider state is unknown")]
    ProviderUnknown,
    #[error("Soda access was lost while reading evidence")]
    AccessLost,
    #[error("Soda provider returned a partial response")]
    Partial,
    #[error("Soda provider response was tampered with")]
    Tampered,
    #[error("Soda provider request timed out")]
    TimedOut,
    #[error("Soda provider returned an invalid response")]
    InvalidResponse,
}

impl SodaTransportError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Denied => Some(403),
            Self::RateLimited { .. } => Some(429),
            Self::BlockedEnv
            | Self::ProviderUnknown
            | Self::AccessLost
            | Self::Partial
            | Self::Tampered
            | Self::TimedOut
            | Self::InvalidResponse => None,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SodaQualityResultError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} revision must be non-zero")]
    InvalidRevision { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("Soda quality scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("opaque Soda API-token SecretReference is invalid")]
    InvalidSecretReference,
    #[error("Soda quality request is invalid")]
    InvalidRequest,
    #[error("Soda provider response is invalid")]
    InvalidResponse,
    #[error("Soda response exceeded the Layer-1 byte bound")]
    ResponseTooLarge,
    #[error("Soda provider definition drifted")]
    ProviderDrift,
    #[error("Soda contract definition drifted")]
    ContractDrift,
    #[error("Soda registration is invalid or its digest drifted")]
    InvalidRegistration,
    #[error("Soda registration is inactive")]
    RegistrationInactive,
    #[error("Soda registration is revoked")]
    RegistrationRevoked,
    #[error("Soda registration is reversed")]
    RegistrationReversed,
    #[error("Soda SecretReference is revoked")]
    SecretRevoked,
    #[error("Soda scope does not match the request, provider, or response")]
    ScopeMismatch,
    #[error("Soda evidence revision is stale")]
    StaleRevision,
    #[error("Soda evidence was tampered with")]
    TamperedEvidence,
    #[error("Soda evidence is partial or truncated")]
    PartialEvidence,
    #[error("Soda provider state is unknown")]
    ProviderUnknown,
    #[error("Soda idempotency key was replayed with a different proposal")]
    ReplayConflict,
    #[error("Soda recording key conflicts with an existing proposal")]
    RecordingConflict,
    #[error("Soda transport failed: {0}")]
    Transport(#[from] SodaTransportError),
}
