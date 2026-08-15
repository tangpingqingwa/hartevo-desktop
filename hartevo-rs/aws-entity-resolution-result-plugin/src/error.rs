use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsEntityResolutionError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsEntityResolutionTransportError {
    #[error("BLOCKED_ENV: AWS Entity Resolution native transport is disabled")]
    BlockedEnv,
    #[error("AWS Entity Resolution request was invalid")]
    BadRequest,
    #[error("AWS Entity Resolution credentials were not authorized")]
    Unauthorized,
    #[error("AWS Entity Resolution access was forbidden")]
    Forbidden,
    #[error("AWS Entity Resolution resource was not found")]
    NotFound,
    #[error("AWS Entity Resolution request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS Entity Resolution returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS Entity Resolution transport timed out")]
    Timeout,
    #[error("AWS Entity Resolution access was lost while reading evidence")]
    AccessLost,
    #[error("AWS Entity Resolution returned a partial response")]
    Partial,
    #[error("AWS Entity Resolution response was invalid")]
    InvalidResponse,
}

impl AwsEntityResolutionTransportError {
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

    pub const fn category(&self) -> &'static str {
        match self {
            Self::BlockedEnv => "blocked_env",
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::RateLimited { .. } => "throttled",
            Self::ServerError { .. } => "server_error",
            Self::Timeout => "timeout",
            Self::AccessLost => "access_loss",
            Self::Partial => "partial",
            Self::InvalidResponse => "invalid_response",
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsEntityResolutionError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid AWS Entity Resolution identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("Entity Resolution scope is invalid")]
    InvalidScope,
    #[error("Entity Resolution permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("Entity Resolution metadata is invalid or unbounded")]
    InvalidMetadata,
    #[error("source record is invalid, empty, or exceeds the bound")]
    InvalidRecord,
    #[error("Entity Resolution provider response is invalid")]
    InvalidResponse,
    #[error("opaque SigV4 SecretReference is invalid")]
    InvalidSecretReference,
    #[error("Entity Resolution registration is invalid")]
    InvalidRegistration,
    #[error("Entity Resolution request is invalid")]
    InvalidRequest,
    #[error("Entity Resolution request does not match its scope")]
    ScopeMismatch,
    #[error("Entity Resolution provider definition drifted")]
    ProviderDrift,
    #[error("Entity Resolution contract definition drifted")]
    ContractDrift,
    #[error("Entity Resolution permission fence drifted")]
    PermissionDrift,
    #[error("Entity Resolution evidence digest drifted")]
    EvidenceDrift,
    #[error("Entity Resolution registration is revoked")]
    RegistrationRevoked,
    #[error("Entity Resolution registration is reversed")]
    RegistrationReversed,
    #[error("Entity Resolution registration is not active")]
    RegistrationInactive,
    #[error("Entity Resolution evidence was tampered with")]
    TamperedEvidence,
    #[error("Entity Resolution evidence is partial or truncated")]
    PartialEvidence,
    #[error("Entity Resolution recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("Entity Resolution transport failed: {0}")]
    Transport(#[from] AwsEntityResolutionTransportError),
}
