//! Errors for the bounded AWS S3 bucket Layer-1 boundary.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsS3BucketError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsS3TransportError {
    #[error("AWS S3 provider rejected the bounded request with HTTP 400")]
    BadRequest,
    #[error("AWS S3 provider rejected the credentials with HTTP 401")]
    Unauthorized,
    #[error("AWS S3 provider denied the bounded read with HTTP 403")]
    Forbidden,
    #[error("AWS S3 bucket or configuration was not found with HTTP 404")]
    NotFound,
    #[error("AWS S3 provider rate limited the bounded read")]
    Throttled { retry_after_seconds: Option<u64> },
    #[error("AWS S3 provider returned a server failure")]
    ServerFailure { status_code: Option<u16> },
    #[error("AWS S3 provider timed out")]
    Timeout,
    #[error("AWS S3 bounded read expired before completion")]
    Expired,
    #[error("AWS S3 marker was replayed or bound to a different request")]
    MarkerReplay,
    #[error("AWS S3 provider returned a partial response")]
    Partial,
    #[error("AWS S3 provider is unavailable in BLOCKED_ENV")]
    BlockedEnv,
    #[error("AWS S3 provider response was malformed")]
    MalformedResponse,
    #[error("AWS S3 provider response or scope drifted")]
    ScopeDrift,
    #[error("AWS S3 provider returned an unknown error")]
    Unknown,
}

impl AwsS3TransportError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Throttled { .. } => Some(429),
            Self::ServerFailure { status_code } => *status_code,
            Self::Timeout
            | Self::Expired
            | Self::MarkerReplay
            | Self::Partial
            | Self::BlockedEnv
            | Self::MalformedResponse
            | Self::ScopeDrift
            | Self::Unknown => None,
        }
    }

    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::Throttled { .. } | Self::ServerFailure { .. } | Self::Timeout
        )
    }

    pub const fn is_access_loss(&self) -> bool {
        matches!(self, Self::Unauthorized | Self::Forbidden | Self::NotFound)
    }

    pub const fn kind(&self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Throttled { .. } => "throttled",
            Self::ServerFailure { .. } => "server_failure",
            Self::Timeout => "timeout",
            Self::Expired => "expired",
            Self::MarkerReplay => "marker_replay",
            Self::Partial => "partial",
            Self::BlockedEnv => "blocked_env",
            Self::MalformedResponse => "malformed_response",
            Self::ScopeDrift => "scope_drift",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsS3BucketError {
    #[error("invalid AWS S3 bucket model: {0}")]
    InvalidModel(String),
    #[error("invalid AWS S3 request: {0}")]
    InvalidRequest(String),
    #[error("AWS S3 scope mismatch: {0}")]
    ScopeMismatch(String),
    #[error("AWS S3 provider drift")]
    ProviderDrift,
    #[error("AWS S3 API drift")]
    ApiDrift,
    #[error("AWS S3 registration is invalid or tampered")]
    InvalidRegistration,
    #[error("AWS S3 registration is revoked")]
    RegistrationRevoked,
    #[error("AWS S3 registration is reversed")]
    RegistrationReversed,
    #[error("AWS S3 registration is already in the requested state")]
    RegistrationInactive,
    #[error("AWS S3 secret reference is invalid or revoked")]
    InvalidSecretReference,
    #[error("AWS S3 proposal is tampered or bound to another registration")]
    TamperedEvidence,
    #[error("AWS S3 recording key conflicts with an existing proposal")]
    RecordingConflict,
    #[error("AWS S3 evidence is partial or otherwise not review-complete")]
    PartialEvidence,
    #[error("AWS S3 posture is unknown or missing required configuration")]
    UnknownPosture,
    #[error("AWS S3 bucket region drifted from the exact scope")]
    RegionDrift,
    #[error("AWS S3 read expired")]
    Expired,
    #[error("AWS S3 transport error: {0}")]
    Transport(#[from] AwsS3TransportError),
}
