use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsCloudFormationDriftError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsCloudFormationTransportError {
    #[error("BLOCKED_ENV: AWS CloudFormation native transport is disabled")]
    BlockedEnv,
    #[error("AWS CloudFormation request was invalid")]
    BadRequest,
    #[error("AWS CloudFormation credentials were not authorized")]
    Unauthorized,
    #[error("AWS CloudFormation access was forbidden")]
    Forbidden,
    #[error("AWS CloudFormation stack or drift result was not found")]
    NotFound,
    #[error("AWS CloudFormation request conflicted with provider state")]
    Conflict,
    #[error("AWS CloudFormation request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS CloudFormation provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS CloudFormation transport timed out")]
    Timeout,
    #[error("AWS CloudFormation access was lost while reading evidence")]
    AccessLost,
    #[error("AWS CloudFormation returned a partial transport response")]
    Partial,
    #[error("AWS CloudFormation response was invalid")]
    InvalidResponse,
}

impl AwsCloudFormationTransportError {
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
            Self::RateLimited { .. } | Self::ServerError { .. } | Self::Timeout | Self::Partial
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsCloudFormationDriftError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid AWS CloudFormation identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("AWS CloudFormation drift scope is invalid")]
    InvalidScope,
    #[error("AWS CloudFormation permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("AWS CloudFormation consent scope is invalid")]
    InvalidConsent,
    #[error("opaque SigV4 secret reference is invalid")]
    InvalidSecretReference,
    #[error("AWS CloudFormation registration is invalid")]
    InvalidRegistration,
    #[error("AWS CloudFormation request is invalid")]
    InvalidRequest,
    #[error("AWS CloudFormation request does not match its scope")]
    ScopeMismatch,
    #[error("AWS CloudFormation cursor does not match its bound request")]
    CursorMismatch,
    #[error("AWS CloudFormation stack revision drifted")]
    StackRevisionDrift,
    #[error("AWS CloudFormation drift detection identity was replayed")]
    DetectionReplay,
    #[error("AWS CloudFormation provider definition drifted")]
    ProviderDrift,
    #[error("AWS CloudFormation contract definition drifted")]
    ContractDrift,
    #[error("AWS CloudFormation registration is revoked")]
    RegistrationRevoked,
    #[error("AWS CloudFormation registration is reversed")]
    RegistrationReversed,
    #[error("AWS CloudFormation registration is not active")]
    RegistrationInactive,
    #[error("AWS CloudFormation consent is expired")]
    ConsentExpired,
    #[error("AWS CloudFormation consent is revoked")]
    ConsentRevoked,
    #[error("AWS CloudFormation evidence was tampered with")]
    TamperedEvidence,
    #[error("AWS CloudFormation evidence is partial or truncated")]
    PartialEvidence,
    #[error("AWS CloudFormation recording key conflicts with an existing proposal")]
    RecordingConflict,
    #[error("AWS CloudFormation transport failed: {0}")]
    Transport(#[from] AwsCloudFormationTransportError),
}

pub type AwsCloudFormationError = AwsCloudFormationDriftError;
pub type AwsCloudFormationTransportErrorAlias = AwsCloudFormationTransportError;
