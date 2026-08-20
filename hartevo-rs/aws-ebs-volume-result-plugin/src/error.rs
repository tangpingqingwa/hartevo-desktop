use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsEbsVolumeError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsEbsTransportError {
    #[error("BLOCKED_ENV: AWS EBS native transport is disabled")]
    BlockedEnv,
    #[error("AWS EBS request was invalid")]
    BadRequest,
    #[error("AWS EBS credentials were not authorized")]
    Unauthorized,
    #[error("AWS EBS access was forbidden")]
    Forbidden,
    #[error("AWS EBS resource was not found")]
    NotFound,
    #[error("AWS EBS request conflicted with provider state")]
    Conflict,
    #[error("AWS EBS request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS EBS provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS EBS transport timed out")]
    Timeout,
    #[error("AWS EBS access was lost while reading evidence")]
    AccessLoss,
    #[error("AWS EBS returned a partial transport response")]
    Partial,
    #[error("AWS EBS response was invalid")]
    InvalidResponse,
}

impl AwsEbsTransportError {
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
            | Self::AccessLoss
            | Self::Partial
            | Self::InvalidResponse => None,
        }
    }

    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::AccessLoss
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsEbsVolumeError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid AWS EBS identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("AWS EBS scope is invalid")]
    InvalidScope,
    #[error("AWS EBS permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("AWS EBS consent scope is invalid")]
    InvalidConsent,
    #[error("opaque SigV4 secret reference is invalid")]
    InvalidSecretReference,
    #[error("AWS EBS registration is invalid")]
    InvalidRegistration,
    #[error("AWS EBS request is invalid")]
    InvalidRequest,
    #[error("AWS EBS request does not match its scope")]
    ScopeMismatch,
    #[error("AWS EBS volume allowlist does not match")]
    VolumeAllowlistMismatch,
    #[error("AWS EBS snapshot allowlist does not match")]
    SnapshotAllowlistMismatch,
    #[error("AWS EBS cursor does not match its request fence")]
    CursorMismatch,
    #[error("AWS EBS provider definition drifted")]
    ProviderDrift,
    #[error("AWS EBS contract definition drifted")]
    ContractDrift,
    #[error("AWS EBS registration is revoked")]
    RegistrationRevoked,
    #[error("AWS EBS registration is reversed")]
    RegistrationReversed,
    #[error("AWS EBS registration is not active")]
    RegistrationInactive,
    #[error("AWS EBS consent is expired")]
    ConsentExpired,
    #[error("AWS EBS consent is revoked")]
    ConsentRevoked,
    #[error("AWS EBS evidence was tampered with")]
    TamperedEvidence,
    #[error("AWS EBS evidence is partial or truncated")]
    PartialEvidence,
    #[error("AWS EBS status evidence is stale")]
    StaleStatus,
    #[error("AWS EBS resource was replaced during the read")]
    ResourceReplaced,
    #[error("AWS EBS pagination loop detected")]
    PaginationLoop,
    #[error("AWS EBS recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("AWS EBS transport failed: {0}")]
    Transport(#[from] AwsEbsTransportError),
}
