use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsAppConfigDeploymentError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsAppConfigTransportError {
    #[error("BLOCKED_ENV: AWS AppConfig native transport is disabled")]
    BlockedEnv,
    #[error("AWS AppConfig request was invalid")]
    BadRequest,
    #[error("AWS AppConfig credentials were not authorized")]
    Unauthorized,
    #[error("AWS AppConfig access was forbidden")]
    Forbidden,
    #[error("AWS AppConfig deployment was not found")]
    NotFound,
    #[error("AWS AppConfig request conflicted with provider state")]
    Conflict,
    #[error("AWS AppConfig request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS AppConfig provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS AppConfig transport timed out")]
    Timeout,
    #[error("AWS AppConfig access was lost while reading deployment evidence")]
    AccessLost,
    #[error("AWS AppConfig returned a partial transport response")]
    Partial,
    #[error("AWS AppConfig response was invalid")]
    InvalidResponse,
}

impl AwsAppConfigTransportError {
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
pub enum AwsAppConfigDeploymentError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid AWS AppConfig identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("AWS AppConfig deployment scope is invalid")]
    InvalidScope,
    #[error("AWS AppConfig permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("AWS AppConfig consent scope is invalid")]
    InvalidConsent,
    #[error("opaque SigV4 secret reference is invalid")]
    InvalidSecretReference,
    #[error("AWS AppConfig registration is invalid")]
    InvalidRegistration,
    #[error("AWS AppConfig request is invalid")]
    InvalidRequest,
    #[error("AWS AppConfig request does not match its scope")]
    ScopeMismatch,
    #[error("AWS AppConfig deployment filter does not match the bound scope")]
    FilterMismatch,
    #[error("AWS AppConfig pagination cursor does not match the bound filter")]
    CursorMismatch,
    #[error("AWS AppConfig provider definition drifted")]
    ProviderDrift,
    #[error("AWS AppConfig contract definition drifted")]
    ContractDrift,
    #[error("AWS AppConfig registration is revoked")]
    RegistrationRevoked,
    #[error("AWS AppConfig registration is reversed")]
    RegistrationReversed,
    #[error("AWS AppConfig registration is not active")]
    RegistrationInactive,
    #[error("AWS AppConfig consent is expired")]
    ConsentExpired,
    #[error("AWS AppConfig consent is revoked")]
    ConsentRevoked,
    #[error("AWS AppConfig evidence was tampered with")]
    TamperedEvidence,
    #[error("AWS AppConfig evidence is partial or truncated")]
    PartialEvidence,
    #[error("AWS AppConfig deployment identity was replaced")]
    DeploymentReplaced,
    #[error("AWS AppConfig list/get state or progress drifted")]
    StateProgressDrift,
    #[error("AWS AppConfig recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("AWS AppConfig transport failed: {0}")]
    Transport(#[from] AwsAppConfigTransportError),
}
