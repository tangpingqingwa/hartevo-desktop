use thiserror::Error;

pub type Result<T> = std::result::Result<T, BigCommerceOrderResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BigCommerceTransportError {
    #[error("BLOCKED_ENV: BigCommerce native transport is disabled")]
    BlockedEnv,
    #[error("BigCommerce request was invalid")]
    BadRequest,
    #[error("BigCommerce credentials were not authorized")]
    Unauthorized,
    #[error("BigCommerce access was forbidden")]
    Forbidden,
    #[error("BigCommerce order or store was not found")]
    NotFound,
    #[error("BigCommerce request conflicted with provider state")]
    Conflict,
    #[error("BigCommerce request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("BigCommerce provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("BigCommerce transport timed out")]
    Timeout,
    #[error("BigCommerce access was lost while reading evidence")]
    AccessLost,
    #[error("BigCommerce returned a partial transport response")]
    Partial,
    #[error("BigCommerce response was invalid")]
    InvalidResponse,
}

impl BigCommerceTransportError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::ServerError { status } => Some(*status),
            Self::BlockedEnv
            | Self::Timeout
            | Self::AccessLost
            | Self::Partial
            | Self::InvalidResponse => None,
        }
    }

    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::AccessLost
        )
    }

    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::ServerError { .. } | Self::Timeout
        )
    }

    pub const fn is_blocked_env(&self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BigCommerceOrderResultError {
    #[error("BigCommerce identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("BigCommerce digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("BigCommerce revision must be non-zero")]
    InvalidRevision,
    #[error("BigCommerce scope is invalid")]
    InvalidScope,
    #[error("BigCommerce amount or currency is invalid")]
    InvalidAmount,
    #[error("BigCommerce transaction or fulfillment evidence is invalid")]
    InvalidEvidence,
    #[error("BigCommerce response exceeds a Layer-1 bound")]
    ResponseBoundExceeded,
    #[error("BigCommerce response digest or immutable evidence does not match")]
    DigestMismatch,
    #[error("BigCommerce response fence does not match the request")]
    FenceViolation,
    #[error("BigCommerce response contains an order outside the exact scope")]
    ScopeMismatch,
    #[error("BigCommerce response contains duplicate order evidence")]
    DuplicateOrder,
    #[error("BigCommerce response contains duplicate transaction or fulfillment evidence")]
    DuplicateEvidence,
    #[error("BigCommerce order revision changed between list and get")]
    OrderRevisionDrift,
    #[error("BigCommerce provider definition is invalid")]
    InvalidProvider,
    #[error("BigCommerce registration is invalid")]
    InvalidRegistration,
    #[error("BigCommerce registration is not active")]
    RegistrationInactive,
    #[error("BigCommerce registration is revoked")]
    RegistrationRevoked,
    #[error("BigCommerce registration is reversed")]
    RegistrationReversed,
    #[error("BigCommerce SecretReference is invalid")]
    InvalidSecretReference,
    #[error("BigCommerce SecretReference is revoked")]
    SecretRevoked,
    #[error("BigCommerce page cursor repeated")]
    PageLoop,
    #[error("BigCommerce proposal is stale or tampered")]
    InvalidProposal,
    #[error("BigCommerce recording key is invalid")]
    InvalidRecordingKey,
    #[error("BigCommerce recording key conflicts with an existing proposal")]
    RecordingConflict,
    #[error("BigCommerce recording was not found")]
    RecordingNotFound,
    #[error("BigCommerce recorded evidence is stale or tampered")]
    InvalidReadBack,
    #[error("BigCommerce provider transport failed: {0}")]
    Transport(#[from] BigCommerceTransportError),
    #[error("BigCommerce contract document drifted")]
    ContractDrift,
}
