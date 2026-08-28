use thiserror::Error;

pub type Result<T> = std::result::Result<T, CloudinaryAssetResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CloudinaryTransportError {
    #[error("BLOCKED_ENV: Cloudinary native transport is disabled")]
    BlockedEnv,
    #[error("Cloudinary request was invalid")]
    BadRequest,
    #[error("Cloudinary credentials were not authorized")]
    Unauthorized,
    #[error("Cloudinary access was forbidden")]
    Forbidden,
    #[error("Cloudinary asset was not found")]
    NotFound,
    #[error("Cloudinary asset was deleted")]
    Deleted,
    #[error("Cloudinary request conflicted with provider state")]
    Conflict,
    #[error("Cloudinary request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Cloudinary provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("Cloudinary transport timed out")]
    Timeout,
    #[error("Cloudinary access was lost while reading evidence")]
    AccessLost,
    #[error("Cloudinary provider returned a partial response")]
    Partial,
    #[error("Cloudinary provider returned an invalid response")]
    InvalidResponse,
    #[error("Cloudinary evidence was tampered with")]
    Tampered,
    #[error("Cloudinary provider returned unknown state")]
    ProviderUnknown,
    #[error("Cloudinary retry/backoff bound was exhausted")]
    BackoffExhausted,
}

impl CloudinaryTransportError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::ServerError { status } => Some(*status),
            Self::Deleted
            | Self::BlockedEnv
            | Self::Timeout
            | Self::AccessLost
            | Self::Partial
            | Self::InvalidResponse
            | Self::Tampered
            | Self::ProviderUnknown
            | Self::BackoffExhausted => None,
        }
    }

    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::NotFound | Self::AccessLost
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CloudinaryAssetResultError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid Cloudinary identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("value is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("Cloudinary scope is invalid")]
    InvalidScope,
    #[error("Cloudinary permission snapshot is invalid")]
    InvalidPermissionSnapshot,
    #[error("Cloudinary registration is invalid")]
    InvalidRegistration,
    #[error("Cloudinary request is invalid")]
    InvalidRequest,
    #[error("Cloudinary provider definition drifted")]
    ProviderDrift,
    #[error("Cloudinary contract definition drifted")]
    ContractDrift,
    #[error("opaque API-key/signature SecretReference is invalid")]
    InvalidSecretReference,
    #[error("Cloudinary registration is revoked")]
    RegistrationRevoked,
    #[error("Cloudinary registration is reversed")]
    RegistrationReversed,
    #[error("Cloudinary registration is not active")]
    RegistrationInactive,
    #[error("Cloudinary scope does not match the request or response")]
    ScopeMismatch,
    #[error("Cloudinary scope revision drifted")]
    RevisionDrift,
    #[error("Cloudinary asset was deleted")]
    AssetDeleted,
    #[error("Cloudinary evidence was invalid")]
    InvalidEvidence,
    #[error("Cloudinary evidence was tampered with")]
    TamperedEvidence,
    #[error("Cloudinary evidence was partial or truncated")]
    PartialEvidence,
    #[error("Cloudinary provider state is unknown")]
    ProviderUnknown,
    #[error("Cloudinary access was lost while reading evidence")]
    AccessLoss,
    #[error("Cloudinary evidence was replayed with a different proposal")]
    ReplayConflict,
    #[error("Cloudinary evidence was already recorded")]
    DuplicateEvidence,
    #[error("Cloudinary evidence was rate limited")]
    RateLimited,
    #[error("Cloudinary request or response was denied")]
    Denied,
    #[error("Cloudinary transport failed: {0}")]
    Transport(#[from] CloudinaryTransportError),
}
