use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsPersonalizeRecommendationError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsPersonalizeTransportError {
    #[error("BLOCKED_ENV: AWS Personalize native transport is disabled")]
    BlockedEnv,
    #[error("AWS Personalize request was invalid")]
    BadRequest,
    #[error("AWS Personalize credentials were not authorized")]
    Unauthorized,
    #[error("AWS Personalize access was forbidden")]
    Forbidden,
    #[error("AWS Personalize campaign, recommender, or result was not found")]
    NotFound,
    #[error("AWS Personalize request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS Personalize provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS Personalize transport timed out")]
    Timeout,
    #[error("AWS Personalize access was lost while reading evidence")]
    AccessLost,
    #[error("AWS Personalize returned a partial transport response")]
    Partial,
    #[error("AWS Personalize response was invalid")]
    InvalidResponse,
}

impl AwsPersonalizeTransportError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
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
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsPersonalizeRecommendationError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid Amazon Personalize identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("AWS Personalize recommendation scope is invalid")]
    InvalidScope,
    #[error("AWS Personalize permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("AWS Personalize consent scope is invalid")]
    InvalidConsent,
    #[error("opaque SigV4 SecretReference is invalid")]
    InvalidSecretReference,
    #[error("AWS Personalize registration is invalid")]
    InvalidRegistration,
    #[error("AWS Personalize request is invalid")]
    InvalidRequest,
    #[error("AWS Personalize request does not match its exact scope")]
    ScopeMismatch,
    #[error("AWS Personalize filter does not match the exact scope")]
    FilterMismatch,
    #[error("AWS Personalize provider definition drifted")]
    ProviderDrift,
    #[error("AWS Personalize contract definition drifted")]
    ContractDrift,
    #[error("AWS Personalize registration is revoked")]
    RegistrationRevoked,
    #[error("AWS Personalize registration is reversed")]
    RegistrationReversed,
    #[error("AWS Personalize registration is not active")]
    RegistrationInactive,
    #[error("AWS Personalize consent is expired")]
    ConsentExpired,
    #[error("AWS Personalize consent is revoked")]
    ConsentRevoked,
    #[error("AWS Personalize evidence was tampered with")]
    TamperedEvidence,
    #[error("AWS Personalize evidence is partial or truncated")]
    PartialEvidence,
    #[error("AWS Personalize recommendation ranking is not contiguous")]
    NonContiguousRanking,
    #[error("AWS Personalize recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("AWS Personalize operation is not supported for the exact scope")]
    UnsupportedOperation,
    #[error("AWS Personalize transport failed: {0}")]
    Transport(#[from] AwsPersonalizeTransportError),
}
