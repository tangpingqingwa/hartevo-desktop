use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsConnectContactResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsConnectTransportError {
    #[error("BLOCKED_ENV: Amazon Connect native transport is disabled")]
    BlockedEnv,
    #[error("Amazon Connect request was invalid")]
    BadRequest,
    #[error("Amazon Connect credentials were not authorized")]
    Unauthorized,
    #[error("Amazon Connect access was forbidden")]
    Forbidden,
    #[error("Amazon Connect contact or retention record was not found")]
    NotFound,
    #[error("Amazon Connect request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Amazon Connect provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("Amazon Connect transport timed out")]
    Timeout,
    #[error("Amazon Connect access was lost while reading evidence")]
    AccessLost,
    #[error("Amazon Connect returned a partial response")]
    Partial,
    #[error("Amazon Connect response was invalid")]
    InvalidResponse,
}

impl AwsConnectTransportError {
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
pub enum AwsConnectContactResultError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid Amazon Connect identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("Amazon Connect contact-result scope is invalid")]
    InvalidScope,
    #[error("Amazon Connect permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("Amazon Connect consent scope is invalid")]
    InvalidConsent,
    #[error("opaque SigV4 SecretReference is invalid")]
    InvalidSecretReference,
    #[error("Amazon Connect registration is invalid")]
    InvalidRegistration,
    #[error("Amazon Connect request is invalid")]
    InvalidRequest,
    #[error("Amazon Connect request does not match its exact scope")]
    ScopeMismatch,
    #[error("Amazon Connect filter does not match the exact scope")]
    FilterMismatch,
    #[error("Amazon Connect sort field is not allowlisted")]
    SortNotAllowlisted,
    #[error("Amazon Connect attribute key is not allowlisted")]
    AttributeNotAllowlisted,
    #[error("Amazon Connect cursor does not match the bound query")]
    CursorMismatch,
    #[error("Amazon Connect cursor loop detected")]
    CursorLoop,
    #[error("Amazon Connect cursor or response was tampered with")]
    TamperedEvidence,
    #[error("Amazon Connect cursor was replayed against a different request")]
    CursorReplay,
    #[error("Amazon Connect provider definition drifted")]
    ProviderDrift,
    #[error("Amazon Connect contract definition drifted")]
    ContractDrift,
    #[error("Amazon Connect registration is revoked")]
    RegistrationRevoked,
    #[error("Amazon Connect registration is reversed")]
    RegistrationReversed,
    #[error("Amazon Connect registration is not active")]
    RegistrationInactive,
    #[error("Amazon Connect consent is expired")]
    ConsentExpired,
    #[error("Amazon Connect consent is revoked")]
    ConsentRevoked,
    #[error("Amazon Connect evidence is partial or truncated")]
    PartialEvidence,
    #[error("Amazon Connect Mission revision is stale")]
    StaleMission,
    #[error("Amazon Connect idempotency replay conflicts with an existing proposal")]
    RecordingConflict,
    #[error("Amazon Connect response contact was replaced")]
    ContactReplaced,
    #[error("Amazon Connect transport failed: {0}")]
    Transport(#[from] AwsConnectTransportError),
}
