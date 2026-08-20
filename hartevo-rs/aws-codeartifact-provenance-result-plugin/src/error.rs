use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsCodeArtifactProvenanceError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsCodeArtifactTransportError {
    #[error("BLOCKED_ENV: AWS CodeArtifact native transport is disabled")]
    BlockedEnv,
    #[error("AWS CodeArtifact request was invalid")]
    BadRequest,
    #[error("AWS CodeArtifact credentials were not authorized")]
    Unauthorized,
    #[error("AWS CodeArtifact access was forbidden")]
    Forbidden,
    #[error("AWS CodeArtifact package version was not found")]
    NotFound,
    #[error("AWS CodeArtifact request conflicted with provider state")]
    Conflict,
    #[error("AWS CodeArtifact request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS CodeArtifact provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS CodeArtifact transport timed out")]
    Timeout,
    #[error("AWS CodeArtifact access was lost while reading evidence")]
    AccessLost,
    #[error("AWS CodeArtifact returned a partial response")]
    Partial,
    #[error("AWS CodeArtifact response was invalid")]
    InvalidResponse,
}

impl AwsCodeArtifactTransportError {
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

    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::ServerError { .. } | Self::Timeout | Self::Partial
        )
    }

    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::AccessLost
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsCodeArtifactProvenanceError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid AWS CodeArtifact identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("AWS CodeArtifact provenance scope is invalid")]
    InvalidScope,
    #[error("AWS CodeArtifact permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("AWS CodeArtifact consent scope is invalid")]
    InvalidConsent,
    #[error("opaque SigV4 secret reference is invalid")]
    InvalidSecretReference,
    #[error("AWS CodeArtifact registration is invalid")]
    InvalidRegistration,
    #[error("AWS CodeArtifact request is invalid")]
    InvalidRequest,
    #[error("AWS CodeArtifact request does not match its scope")]
    ScopeMismatch,
    #[error("AWS CodeArtifact request revision does not match its scope")]
    RevisionMismatch,
    #[error("AWS CodeArtifact cursor does not match its bound request")]
    CursorMismatch,
    #[error("AWS CodeArtifact provider definition drifted")]
    ProviderDrift,
    #[error("AWS CodeArtifact contract definition drifted")]
    ContractDrift,
    #[error("AWS CodeArtifact registration is revoked")]
    RegistrationRevoked,
    #[error("AWS CodeArtifact registration is reversed")]
    RegistrationReversed,
    #[error("AWS CodeArtifact registration is not active")]
    RegistrationInactive,
    #[error("AWS CodeArtifact consent is expired")]
    ConsentExpired,
    #[error("AWS CodeArtifact consent is revoked")]
    ConsentRevoked,
    #[error("AWS CodeArtifact evidence was tampered with")]
    TamperedEvidence,
    #[error("AWS CodeArtifact evidence is partial or truncated")]
    PartialEvidence,
    #[error("AWS CodeArtifact package version revision, status, or origin drifted")]
    PackageRevisionReplaced,
    #[error("AWS CodeArtifact dependency metadata was truncated")]
    DependencyTruncated,
    #[error("AWS CodeArtifact recording key conflicts with an existing digest")]
    RecordingConflict,
    #[error("AWS CodeArtifact transport failed: {0}")]
    Transport(#[from] AwsCodeArtifactTransportError),
}
