use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsBackupRecoveryError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsBackupTransportError {
    #[error("BLOCKED_ENV: AWS Backup native transport is disabled")]
    BlockedEnv,
    #[error("AWS Backup request was invalid")]
    BadRequest,
    #[error("AWS Backup credentials were not authorized")]
    Unauthorized,
    #[error("AWS Backup access was forbidden")]
    Forbidden,
    #[error("AWS Backup recovery point or vault was not found")]
    NotFound,
    #[error("AWS Backup request conflicted with provider state")]
    Conflict,
    #[error("AWS Backup request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS Backup provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS Backup transport timed out")]
    Timeout,
    #[error("AWS Backup access was lost while reading evidence")]
    AccessLost,
    #[error("AWS Backup returned a partial transport response")]
    Partial,
    #[error("AWS Backup response was invalid")]
    InvalidResponse,
}

impl AwsBackupTransportError {
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
pub enum AwsBackupRecoveryError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid AWS Backup identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("AWS Backup scope is invalid")]
    InvalidScope,
    #[error("AWS Backup permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("AWS Backup consent scope is invalid")]
    InvalidConsent,
    #[error("opaque SigV4 secret reference is invalid")]
    InvalidSecretReference,
    #[error("AWS Backup registration is invalid")]
    InvalidRegistration,
    #[error("AWS Backup request is invalid")]
    InvalidRequest,
    #[error("AWS Backup request does not match its scope")]
    ScopeMismatch,
    #[error("AWS Backup filter does not match the bound scope")]
    FilterMismatch,
    #[error("AWS Backup cursor does not match the bound filter")]
    CursorMismatch,
    #[error("AWS Backup provider definition drifted")]
    ProviderDrift,
    #[error("AWS Backup contract definition drifted")]
    ContractDrift,
    #[error("AWS Backup registration is revoked")]
    RegistrationRevoked,
    #[error("AWS Backup registration is reversed")]
    RegistrationReversed,
    #[error("AWS Backup registration is not active")]
    RegistrationInactive,
    #[error("AWS Backup consent is expired")]
    ConsentExpired,
    #[error("AWS Backup consent is revoked")]
    ConsentRevoked,
    #[error("AWS Backup evidence was tampered with")]
    TamperedEvidence,
    #[error("AWS Backup evidence is partial or truncated")]
    PartialEvidence,
    #[error("AWS Backup recovery point was replaced")]
    RecoveryPointReplaced,
    #[error("AWS Backup recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("AWS Backup transport failed: {0}")]
    Transport(#[from] AwsBackupTransportError),
}
