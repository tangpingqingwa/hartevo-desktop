use thiserror::Error;

pub type Result<T> = std::result::Result<T, DockerHubImageResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DockerHubTransportError {
    #[error("BLOCKED_ENV: Docker Hub native transport is disabled")]
    BlockedEnv,
    #[error("Docker Hub request was invalid")]
    BadRequest,
    #[error("Docker Hub credentials were not authorized")]
    Unauthorized,
    #[error("Docker Hub access was forbidden")]
    Forbidden,
    #[error("Docker Hub tag was not found")]
    NotFound,
    #[error("Docker Hub request was rate limited")]
    RateLimited,
    #[error("Docker Hub provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("Docker Hub transport timed out")]
    Timeout,
    #[error("Docker Hub access was lost while reading evidence")]
    AccessLost,
    #[error("Docker Hub returned a partial response")]
    Partial,
    #[error("Docker Hub provider returned unknown state")]
    Unknown,
    #[error("Docker Hub response was invalid")]
    InvalidResponse,
    #[error("Docker Hub evidence was tampered with")]
    Tampered,
    #[error("Docker Hub namespace, repository, tag, or digest scope drifted")]
    ScopeDrift,
}

impl DockerHubTransportError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::RateLimited => Some(429),
            Self::ServerError { status } => Some(*status),
            Self::BlockedEnv
            | Self::Timeout
            | Self::AccessLost
            | Self::Partial
            | Self::Unknown
            | Self::InvalidResponse
            | Self::Tampered
            | Self::ScopeDrift => None,
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
pub enum DockerHubImageResultError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid Docker Hub identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("value is not a valid immutable OCI digest")]
    InvalidImmutableDigest,
    #[error("Docker Hub image-result scope is invalid")]
    InvalidScope,
    #[error("Docker Hub platform scope is invalid")]
    InvalidPlatformScope,
    #[error("Docker Hub permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("opaque Docker Hub SecretReference is invalid")]
    InvalidSecretReference,
    #[error("Docker Hub registration is invalid")]
    InvalidRegistration,
    #[error("Docker Hub request is invalid")]
    InvalidRequest,
    #[error("Docker Hub provider response is invalid")]
    InvalidResponse,
    #[error("Docker Hub scope does not match the request or response")]
    ScopeMismatch,
    #[error("Docker Hub manifest or image digest drifted from the scope")]
    ManifestDrift,
    #[error("Docker Hub platform tuple is outside the scope")]
    PlatformDrift,
    #[error("Docker Hub provider definition drifted")]
    ProviderDrift,
    #[error("Docker Hub contract definition drifted")]
    ContractDrift,
    #[error("Docker Hub registration is revoked")]
    RegistrationRevoked,
    #[error("Docker Hub registration is reversed")]
    RegistrationReversed,
    #[error("Docker Hub registration is not active")]
    RegistrationInactive,
    #[error("Docker Hub SecretReference is revoked")]
    SecretRevoked,
    #[error("Docker Hub evidence was tampered with")]
    TamperedEvidence,
    #[error("Docker Hub evidence is partial or truncated")]
    PartialEvidence,
    #[error("Docker Hub provider state is unknown")]
    ProviderUnknown,
    #[error("Docker Hub evidence was replayed with a different proposal")]
    ReplayConflict,
    #[error("Docker Hub recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("Docker Hub transport failed: {0}")]
    Transport(#[from] DockerHubTransportError),
}
