use thiserror::Error;

use crate::model::ProviderErrorKind;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsIamProviderError {
    #[error("Access Analyzer rejected the request as malformed")]
    BadRequest,
    #[error("AWS credentials were not authorized")]
    Unauthorized,
    #[error("Access Analyzer access was denied")]
    Forbidden,
    #[error("the analyzer or requested provider resource was not found")]
    NotFound,
    #[error("the provider reported a conflicting request")]
    Conflict,
    #[error("Access Analyzer throttled the request")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Access Analyzer returned a server error")]
    ServerError { status: u16 },
    #[error("the provider request timed out")]
    Timeout,
    #[error("the provider response was malformed")]
    MalformedResponse,
    #[error("the recording fixture is missing")]
    MissingFixture,
    #[error("native AWS transport is blocked in Layer 1")]
    BlockedEnv,
    #[error("the provider result is unknown")]
    ProviderUnknown,
}

impl AwsIamProviderError {
    pub const fn kind(&self) -> ProviderErrorKind {
        match self {
            Self::BadRequest => ProviderErrorKind::BadRequest,
            Self::Unauthorized => ProviderErrorKind::Unauthorized,
            Self::Forbidden => ProviderErrorKind::Forbidden,
            Self::NotFound => ProviderErrorKind::NotFound,
            Self::Conflict => ProviderErrorKind::Conflict,
            Self::RateLimited { .. } => ProviderErrorKind::RateLimited,
            Self::ServerError { .. } => ProviderErrorKind::ServerError,
            Self::Timeout => ProviderErrorKind::Timeout,
            Self::MalformedResponse => ProviderErrorKind::MalformedResponse,
            Self::MissingFixture => ProviderErrorKind::MissingFixture,
            Self::BlockedEnv => ProviderErrorKind::BlockedEnv,
            Self::ProviderUnknown => ProviderErrorKind::ProviderUnknown,
        }
    }

    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::ServerError { .. } | Self::Timeout
        )
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::ServerError { status } => Some(*status),
            Self::Timeout
            | Self::MalformedResponse
            | Self::MissingFixture
            | Self::BlockedEnv
            | Self::ProviderUnknown => None,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsIamTransportError {
    #[error("HTTP status {0}")]
    Http(u16),
    #[error("transport timeout")]
    Timeout,
    #[error("malformed provider response")]
    MalformedResponse,
    #[error("fixture missing")]
    MissingFixture,
    #[error("BLOCKED_ENV: live AWS transport is disabled")]
    BlockedEnv,
}

impl From<AwsIamTransportError> for AwsIamProviderError {
    fn from(error: AwsIamTransportError) -> Self {
        match error {
            AwsIamTransportError::Http(status) => match status {
                400 => Self::BadRequest,
                401 => Self::Unauthorized,
                403 => Self::Forbidden,
                404 => Self::NotFound,
                409 => Self::Conflict,
                429 => Self::RateLimited {
                    retry_after_seconds: None,
                },
                500..=599 => Self::ServerError { status },
                _ => Self::ProviderUnknown,
            },
            AwsIamTransportError::Timeout => Self::Timeout,
            AwsIamTransportError::MalformedResponse => Self::MalformedResponse,
            AwsIamTransportError::MissingFixture => Self::MissingFixture,
            AwsIamTransportError::BlockedEnv => Self::BlockedEnv,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsIamAccessAnalyzerError {
    #[error("invalid AWS IAM Access Analyzer input: {0}")]
    InvalidInput(&'static str),
    #[error("invalid JSON policy document")]
    InvalidPolicyDocument,
    #[error("registration is invalid or tampered")]
    InvalidRegistration,
    #[error("registration is already revoked")]
    RegistrationRevoked,
    #[error("registration has been reversed")]
    RegistrationReversed,
    #[error("registration is unknown")]
    RegistrationUnknown,
    #[error("registration already exists")]
    RegistrationAlreadyExists,
    #[error("registration or secret scope does not match")]
    ScopeMismatch,
    #[error("registration binding does not match")]
    RegistrationMismatch,
    #[error("provider capability revision does not match the registration")]
    ProviderRevisionMismatch,
    #[error("permission snapshot changed")]
    PermissionFenceViolation,
    #[error("policy revision or Mission revision is stale")]
    StaleRevision,
    #[error("filter, sort, cursor, or policy binding does not match")]
    CursorBindingMismatch,
    #[error("provider response was tampered with or stale")]
    TamperedEvidence,
    #[error("provider returned an invalid finding")]
    InvalidFinding,
    #[error("provider returned an invalid policy validation finding")]
    InvalidPolicyFinding,
    #[error("provider failure: {0}")]
    Provider(#[from] AwsIamProviderError),
    #[error("consumer is revoked")]
    ConsumerRevoked,
    #[error("Mission revision is stale")]
    StaleMissionRevision,
    #[error("recording key was already used for a different evidence digest")]
    RecordingConflict,
}

pub type Result<T> = std::result::Result<T, AwsIamAccessAnalyzerError>;
