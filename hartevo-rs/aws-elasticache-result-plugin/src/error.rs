use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsElastiCacheError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsElastiCacheTransportError {
    #[error("BLOCKED_ENV: AWS ElastiCache native transport is disabled")]
    BlockedEnv,
    #[error("AWS ElastiCache request was invalid")]
    BadRequest,
    #[error("AWS ElastiCache credentials were not authorized")]
    Unauthorized,
    #[error("AWS ElastiCache access was forbidden")]
    Forbidden,
    #[error("AWS ElastiCache resource was not found")]
    NotFound,
    #[error("AWS ElastiCache request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS ElastiCache provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS ElastiCache transport timed out")]
    Timeout,
    #[error("AWS ElastiCache access was lost while reading evidence")]
    AccessLost,
    #[error("AWS ElastiCache provider returned partial evidence")]
    Partial,
    #[error("AWS ElastiCache provider returned an expired marker")]
    ExpiredMarker,
    #[error("AWS ElastiCache pagination marker loop detected")]
    MarkerLoop,
    #[error("AWS ElastiCache provider state is stale")]
    StaleEvidence,
    #[error("AWS ElastiCache response was invalid")]
    InvalidResponse,
    #[error("AWS ElastiCache provider state is unknown")]
    Unknown,
}

impl AwsElastiCacheTransportError {
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
            | Self::ExpiredMarker
            | Self::MarkerLoop
            | Self::StaleEvidence
            | Self::InvalidResponse
            | Self::Unknown => None,
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
pub enum AwsElastiCacheError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid AWS ElastiCache identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("AWS ElastiCache scope is invalid")]
    InvalidScope,
    #[error("AWS ElastiCache permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("AWS ElastiCache consent scope is invalid")]
    InvalidConsent,
    #[error("opaque SigV4 secret reference is invalid")]
    InvalidSecretReference,
    #[error("AWS ElastiCache registration is invalid")]
    InvalidRegistration,
    #[error("AWS ElastiCache request is invalid")]
    InvalidRequest,
    #[error("AWS ElastiCache request does not match its scope")]
    ScopeMismatch,
    #[error("AWS ElastiCache resource or revision does not match the bound scope")]
    RevisionMismatch,
    #[error("AWS ElastiCache marker does not match its bound request")]
    MarkerMismatch,
    #[error("AWS ElastiCache marker has expired")]
    MarkerExpired,
    #[error("AWS ElastiCache provider definition drifted")]
    ProviderDrift,
    #[error("AWS ElastiCache contract definition drifted")]
    ContractDrift,
    #[error("AWS ElastiCache registration is revoked")]
    RegistrationRevoked,
    #[error("AWS ElastiCache registration is reversed")]
    RegistrationReversed,
    #[error("AWS ElastiCache registration is not active")]
    RegistrationInactive,
    #[error("AWS ElastiCache consent is expired")]
    ConsentExpired,
    #[error("AWS ElastiCache consent is revoked")]
    ConsentRevoked,
    #[error("AWS ElastiCache evidence was tampered with")]
    TamperedEvidence,
    #[error("AWS ElastiCache evidence is partial or truncated")]
    PartialEvidence,
    #[error("AWS ElastiCache provider state is stale")]
    StaleEvidence,
    #[error("AWS ElastiCache evidence is unknown")]
    UnknownEvidence,
    #[error("AWS ElastiCache recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("AWS ElastiCache transport failed: {0}")]
    Transport(#[from] AwsElastiCacheTransportError),
}
