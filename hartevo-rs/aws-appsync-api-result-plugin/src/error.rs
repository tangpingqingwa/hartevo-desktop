use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsAppSyncApiResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsAppSyncTransportError {
    #[error("BLOCKED_ENV: AWS AppSync native transport is disabled")]
    BlockedEnv,
    #[error("AWS AppSync request was invalid")]
    BadRequest,
    #[error("AWS AppSync credentials were not authorized")]
    Unauthorized,
    #[error("AWS AppSync access was forbidden")]
    Forbidden,
    #[error("AWS AppSync API was not found")]
    NotFound,
    #[error("AWS AppSync provider state conflicted with the request")]
    Conflict,
    #[error("AWS AppSync request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS AppSync provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS AppSync transport timed out")]
    Timeout,
    #[error("AWS AppSync access was lost while reading evidence")]
    AccessLost,
    #[error("AWS AppSync evidence was partial or truncated")]
    Partial,
    #[error("AWS AppSync provider returned an unknown state")]
    Unknown,
    #[error("AWS AppSync response was invalid")]
    InvalidResponse,
    #[error("AWS AppSync evidence was tampered with")]
    Tampered,
    #[error("AWS AppSync schema, deployment, or association revision drifted")]
    ConfigDrift,
    #[error("AWS AppSync opaque pagination loop detected")]
    PaginationLoop,
}

impl AwsAppSyncTransportError {
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
            | Self::Unknown
            | Self::InvalidResponse
            | Self::Tampered
            | Self::ConfigDrift
            | Self::PaginationLoop => None,
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
pub enum AwsAppSyncApiResultError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid AWS AppSync identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("AWS AppSync scope is invalid")]
    InvalidScope,
    #[error("AWS AppSync API type is invalid for this scope")]
    InvalidApiType,
    #[error("AWS AppSync permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("AWS AppSync consent scope is invalid")]
    InvalidConsent,
    #[error("opaque AWS AppSync SecretReference is invalid")]
    InvalidSecretReference,
    #[error("AWS AppSync registration is invalid")]
    InvalidRegistration,
    #[error("AWS AppSync request is invalid")]
    InvalidRequest,
    #[error("AWS AppSync provider response is invalid")]
    InvalidResponse,
    #[error("AWS AppSync scope does not match the request or response")]
    ScopeMismatch,
    #[error("AWS AppSync API identity or type drifted")]
    ApiDrift,
    #[error("AWS AppSync schema, deployment, or association revision drifted")]
    RevisionDrift,
    #[error("AWS AppSync opaque cursor does not match its bound request")]
    CursorMismatch,
    #[error("AWS AppSync opaque pagination loop detected")]
    PaginationLoop,
    #[error("AWS AppSync provider definition drifted")]
    ProviderDrift,
    #[error("AWS AppSync contract definition drifted")]
    ContractDrift,
    #[error("AWS AppSync registration is revoked")]
    RegistrationRevoked,
    #[error("AWS AppSync registration is reversed")]
    RegistrationReversed,
    #[error("AWS AppSync registration is not active")]
    RegistrationInactive,
    #[error("AWS AppSync consent is expired")]
    ConsentExpired,
    #[error("AWS AppSync consent is revoked")]
    ConsentRevoked,
    #[error("AWS AppSync SecretReference is revoked")]
    SecretRevoked,
    #[error("AWS AppSync evidence was tampered with")]
    TamperedEvidence,
    #[error("AWS AppSync evidence is partial or truncated")]
    PartialEvidence,
    #[error("AWS AppSync provider state is unknown")]
    ProviderUnknown,
    #[error("AWS AppSync evidence was replayed with a different proposal")]
    ReplayConflict,
    #[error("AWS AppSync recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("AWS AppSync transport failed: {0}")]
    Transport(#[from] AwsAppSyncTransportError),
}
