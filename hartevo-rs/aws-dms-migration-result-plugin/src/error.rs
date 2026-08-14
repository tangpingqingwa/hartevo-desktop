use thiserror::Error;

pub type Result<T> = std::result::Result<T, AwsDmsMigrationError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsDmsTransportError {
    #[error("BLOCKED_ENV: AWS DMS native transport is disabled")]
    BlockedEnv,
    #[error("AWS DMS request was invalid")]
    BadRequest,
    #[error("AWS DMS credentials were not authorized")]
    Unauthorized,
    #[error("AWS DMS access was forbidden")]
    Forbidden,
    #[error("AWS DMS replication object was not found")]
    NotFound,
    #[error("AWS DMS request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS DMS provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS DMS transport timed out")]
    Timeout,
    #[error("AWS DMS access was lost while reading evidence")]
    AccessLost,
    #[error("AWS DMS returned a partial transport response")]
    Partial,
    #[error("AWS DMS response was invalid")]
    InvalidResponse,
}

impl AwsDmsTransportError {
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
pub enum AwsDmsMigrationError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid AWS DMS identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} is not a valid lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("AWS DMS scope is invalid")]
    InvalidScope,
    #[error("AWS DMS migration window is invalid")]
    InvalidWindow,
    #[error("AWS DMS permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("AWS DMS consent scope is invalid")]
    InvalidConsent,
    #[error("opaque SigV4 secret reference is invalid or revoked")]
    InvalidSecretReference,
    #[error("AWS DMS registration is invalid")]
    InvalidRegistration,
    #[error("AWS DMS request is invalid")]
    InvalidRequest,
    #[error("AWS DMS request does not match its scope")]
    ScopeMismatch,
    #[error("AWS DMS task or endpoint identity drifted")]
    IdentityDrift,
    #[error("AWS DMS revision drifted")]
    RevisionDrift,
    #[error("AWS DMS provider or API definition drifted")]
    ProviderDrift,
    #[error("AWS DMS contract definition drifted")]
    ContractDrift,
    #[error("AWS DMS marker does not match its bound request")]
    MarkerMismatch,
    #[error("AWS DMS pagination loop or replay was detected")]
    PaginationReplay,
    #[error("AWS DMS evidence is partial or truncated")]
    PartialEvidence,
    #[error("AWS DMS evidence was tampered with")]
    TamperedEvidence,
    #[error("AWS DMS registration is revoked")]
    RegistrationRevoked,
    #[error("AWS DMS registration is reversed")]
    RegistrationReversed,
    #[error("AWS DMS registration is not active")]
    RegistrationInactive,
    #[error("AWS DMS consent is expired")]
    ConsentExpired,
    #[error("AWS DMS consent is revoked")]
    ConsentRevoked,
    #[error("AWS DMS recording key conflicts with an existing proposal")]
    RecordingConflict,
    #[error("AWS DMS verification failed")]
    VerificationFailed,
    #[error("AWS DMS transport failed: {0}")]
    Transport(#[from] AwsDmsTransportError),
}
