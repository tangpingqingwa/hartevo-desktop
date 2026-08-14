use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsFirehoseError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsFirehoseTransportError {
    #[error("BLOCKED_ENV: AWS Firehose native transport is disabled")]
    BlockedEnv,
    #[error("AWS Firehose request was invalid")]
    BadRequest,
    #[error("AWS Firehose credentials were not authorized")]
    Unauthorized,
    #[error("AWS Firehose access was forbidden")]
    Forbidden,
    #[error("AWS Firehose delivery stream was not found")]
    NotFound,
    #[error("AWS Firehose request was throttled")]
    Throttled { retry_after_seconds: Option<u64> },
    #[error("AWS Firehose transport timed out")]
    Timeout,
    #[error("AWS Firehose access was lost while reading evidence")]
    AccessLost,
    #[error("AWS Firehose returned a partial response")]
    Partial,
    #[error("AWS Firehose provider returned an unknown failure")]
    Unknown,
    #[error("AWS Firehose provider response was invalid or tampered")]
    InvalidResponse,
}

impl AwsFirehoseTransportError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Throttled { .. } => Some(429),
            Self::BlockedEnv
            | Self::Timeout
            | Self::AccessLost
            | Self::Partial
            | Self::Unknown
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
            Self::Throttled { .. } => "throttled",
            Self::Timeout => "timeout",
            Self::AccessLost => "access_loss",
            Self::Partial => "partial",
            Self::Unknown => "provider_unknown",
            Self::InvalidResponse => "tampered",
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsFirehoseError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid AWS Firehose identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("AWS Firehose provider scope is invalid")]
    InvalidProviderScope,
    #[error("AWS Firehose delivery scope is invalid")]
    InvalidScope,
    #[error("AWS Firehose permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("AWS Firehose consent is invalid")]
    InvalidConsent,
    #[error("opaque SigV4 SecretReference is invalid")]
    InvalidSecretReference,
    #[error("AWS Firehose registration is invalid")]
    InvalidRegistration,
    #[error("AWS Firehose request is invalid")]
    InvalidRequest,
    #[error("AWS Firehose request or response scope does not match")]
    ScopeMismatch,
    #[error("AWS Firehose pagination cursor does not match its request")]
    CursorMismatch,
    #[error("AWS Firehose provider definition drifted")]
    ProviderDrift,
    #[error("AWS Firehose contract definition drifted")]
    ContractDrift,
    #[error("AWS Firehose stream version drifted")]
    StreamVersionDrift,
    #[error("AWS Firehose source revision drifted")]
    SourceRevisionDrift,
    #[error("AWS Firehose response contained ambiguous destinations")]
    DestinationAmbiguous,
    #[error("AWS Firehose destination health was unknown")]
    DestinationUnknown,
    #[error("AWS Firehose evidence is partial or truncated")]
    PartialEvidence,
    #[error("AWS Firehose evidence was tampered with")]
    TamperedEvidence,
    #[error("AWS Firehose pagination or recording replay was detected")]
    ReplayDetected,
    #[error("AWS Firehose recording key conflicts with an existing proposal digest")]
    RecordingConflict,
    #[error("AWS Firehose registration is revoked")]
    RegistrationRevoked,
    #[error("AWS Firehose registration is reversed")]
    RegistrationReversed,
    #[error("AWS Firehose registration is not active")]
    RegistrationInactive,
    #[error("AWS Firehose consent is revoked")]
    ConsentRevoked,
    #[error("AWS Firehose consent is expired")]
    ConsentExpired,
    #[error("AWS Firehose transport failed: {0}")]
    Transport(#[from] AwsFirehoseTransportError),
}
