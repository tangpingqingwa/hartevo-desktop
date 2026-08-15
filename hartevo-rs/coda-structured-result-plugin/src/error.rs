use thiserror::Error;

use crate::model::CodaResourceKind;

/// Failures produced by a non-native transport seam. Response bodies and
/// credential material are intentionally absent from every variant.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CodaTransportError {
    #[error("Coda native access is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Coda API authentication was rejected")]
    Unauthorized,
    #[error("Coda API access was denied")]
    Forbidden,
    #[error("Coda resource was not found")]
    NotFound,
    #[error("Coda API is rate limited")]
    RateLimited { retry_after_seconds: Option<u32> },
    #[error("Coda response was partial")]
    Partial,
    #[error("Coda provider is unknown or unavailable")]
    ProviderUnknown,
    #[error("Coda transport timed out")]
    Timeout,
    #[error("Coda page token was rejected")]
    InvalidPageToken,
    #[error("Coda response was tampered")]
    Tampered,
}

impl CodaTransportError {
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::RateLimited { .. } => Some(429),
            Self::BlockedEnv
            | Self::Partial
            | Self::ProviderUnknown
            | Self::Timeout
            | Self::InvalidPageToken
            | Self::Tampered => None,
        }
    }
}

/// Typed provider failures. These remain below the host integration and
/// kernel authority boundaries.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CodaProviderError {
    #[error("Coda registration is revoked")]
    RegistrationRevoked,
    #[error("Coda registration digest drifted")]
    RegistrationDrift,
    #[error("Coda provider manifest drifted")]
    ProviderDrift,
    #[error("Coda scope does not match the registered scope")]
    ScopeMismatch,
    #[error("Coda {resource:?} revision drifted")]
    RevisionDrift { resource: CodaResourceKind },
    #[error("Coda page token does not match operation, scope, or page")]
    PageTokenMismatch,
    #[error("Coda page token repeated")]
    PageTokenLoop,
    #[error("Coda response exceeded a Layer-1 bound")]
    ResponseTooLarge,
    #[error("Coda response contained an item outside the registered allowlist")]
    ItemOutsideScope,
    #[error("Coda response could not be decoded into bounded metadata")]
    InvalidResponse,
    #[error("Coda response digest did not match the reported digest")]
    Tampered,
    #[error("Coda response was partial")]
    Partial,
    #[error("Coda access was denied")]
    Denied,
    #[error("Coda API is rate limited; retry after {retry_after_seconds:?} seconds")]
    RateLimited { retry_after_seconds: Option<u32> },
    #[error("Coda provider is unknown or unavailable")]
    ProviderUnknown,
    #[error("Coda native access is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("Coda secret reference is revoked")]
    SecretRevoked,
    #[error("Coda proposal replay was rejected")]
    ReplayDetected,
    #[error("Coda idempotency key conflicted with a different proposal")]
    IdempotencyConflict,
}

impl CodaProviderError {
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Denied => Some(403),
            Self::RateLimited { .. } => Some(429),
            Self::RegistrationRevoked
            | Self::RegistrationDrift
            | Self::ProviderDrift
            | Self::ScopeMismatch
            | Self::RevisionDrift { .. }
            | Self::PageTokenMismatch
            | Self::PageTokenLoop
            | Self::ResponseTooLarge
            | Self::ItemOutsideScope
            | Self::InvalidResponse
            | Self::Tampered
            | Self::Partial
            | Self::ProviderUnknown
            | Self::BlockedEnv
            | Self::SecretRevoked
            | Self::ReplayDetected
            | Self::IdempotencyConflict => None,
        }
    }
}

impl From<CodaTransportError> for CodaProviderError {
    fn from(error: CodaTransportError) -> Self {
        match error {
            CodaTransportError::BlockedEnv => Self::BlockedEnv,
            CodaTransportError::Unauthorized
            | CodaTransportError::Forbidden
            | CodaTransportError::NotFound => Self::Denied,
            CodaTransportError::RateLimited {
                retry_after_seconds,
            } => Self::RateLimited {
                retry_after_seconds,
            },
            CodaTransportError::Partial => Self::Partial,
            CodaTransportError::ProviderUnknown | CodaTransportError::Timeout => {
                Self::ProviderUnknown
            }
            CodaTransportError::InvalidPageToken => Self::PageTokenMismatch,
            CodaTransportError::Tampered => Self::Tampered,
        }
    }
}

/// Service, proposal, and Mission-consumer errors. No variant carries raw
/// Coda payloads, page tokens, API tokens, or person-identifying values.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CodaStructuredResultError {
    #[error("invalid Coda Layer-1 input: {0}")]
    Model(#[from] crate::model::CodaModelError),
    #[error("Coda contract is invalid: {0}")]
    Contract(String),
    #[error("Coda scope mismatch")]
    ScopeMismatch,
    #[error("Coda registration is revoked")]
    RegistrationRevoked,
    #[error("Coda registration or provider binding drifted")]
    RegistrationDrift,
    #[error("Coda provider error: {0}")]
    Provider(#[from] CodaProviderError),
    #[error("Coda transport error: {0}")]
    Transport(#[from] CodaTransportError),
    #[error("Coda proposal is stale or tampered")]
    Tampered,
    #[error("Coda proposal replay was rejected")]
    ReplayDetected,
    #[error("Coda idempotency key conflicted with a different proposal")]
    IdempotencyConflict,
    #[error("Coda proposal is not bound to the Mission/Project/Work Product scope")]
    WorkProductMismatch,
    #[error("Coda proposal state is not adoptable")]
    NonAdoptable,
}

pub type CodaResult<T> = Result<T, CodaStructuredResultError>;
