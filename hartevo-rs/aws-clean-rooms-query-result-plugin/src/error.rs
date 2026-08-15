use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsCleanRoomsQueryResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsCleanRoomsTransportError {
    #[error("BLOCKED_ENV: AWS Clean Rooms native transport is disabled")]
    BlockedEnv,
    #[error("AWS Clean Rooms request was invalid")]
    BadRequest,
    #[error("AWS Clean Rooms credentials were not authorized")]
    Unauthorized,
    #[error("AWS Clean Rooms access was forbidden")]
    Forbidden,
    #[error("AWS Clean Rooms protected query was not found")]
    NotFound,
    #[error("AWS Clean Rooms request conflicted with provider state")]
    Conflict,
    #[error("AWS Clean Rooms request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS Clean Rooms provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS Clean Rooms transport timed out")]
    Timeout,
    #[error("AWS Clean Rooms access was lost while reading evidence")]
    AccessLost,
    #[error("AWS Clean Rooms returned a partial transport response")]
    Partial,
    #[error("AWS Clean Rooms response was invalid")]
    InvalidResponse,
}

impl AwsCleanRoomsTransportError {
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
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsCleanRoomsQueryResultError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid AWS Clean Rooms identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("AWS Clean Rooms query-result scope is invalid")]
    InvalidScope,
    #[error("AWS Clean Rooms permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("AWS Clean Rooms consent scope is invalid")]
    InvalidConsent,
    #[error("opaque SigV4 secret reference is invalid")]
    InvalidSecretReference,
    #[error("AWS Clean Rooms registration is invalid")]
    InvalidRegistration,
    #[error("AWS Clean Rooms request is invalid")]
    InvalidRequest,
    #[error("AWS Clean Rooms request does not match its scope")]
    ScopeMismatch,
    #[error("AWS Clean Rooms filter does not match its bound scope")]
    FilterMismatch,
    #[error("AWS Clean Rooms cursor does not match its bound filter")]
    CursorMismatch,
    #[error("AWS Clean Rooms provider definition drifted")]
    ProviderDrift,
    #[error("AWS Clean Rooms contract definition drifted")]
    ContractDrift,
    #[error("AWS Clean Rooms registration is revoked")]
    RegistrationRevoked,
    #[error("AWS Clean Rooms registration is reversed")]
    RegistrationReversed,
    #[error("AWS Clean Rooms registration is not active")]
    RegistrationInactive,
    #[error("AWS Clean Rooms consent is expired")]
    ConsentExpired,
    #[error("AWS Clean Rooms consent is revoked")]
    ConsentRevoked,
    #[error("AWS Clean Rooms metadata is invalid")]
    InvalidMetadata,
    #[error("AWS Clean Rooms evidence was tampered with")]
    TamperedEvidence,
    #[error("AWS Clean Rooms evidence is partial or truncated")]
    PartialEvidence,
    #[error("AWS Clean Rooms protected query metadata changed between list and get")]
    ProtectedQueryReplaced,
    #[error("AWS Clean Rooms recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("AWS Clean Rooms transport failed: {0}")]
    Transport(#[from] AwsCleanRoomsTransportError),
}
