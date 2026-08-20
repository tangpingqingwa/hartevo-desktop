use thiserror::Error;

use crate::model::{ConfluenceCapability, KnowledgeReadbackField};

/// Failures produced by a transport seam. Response bodies are deliberately
/// not retained so HTTP diagnostics cannot become a data exfiltration path.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConfluenceTransportError {
    #[error("Confluence transport authentication was rejected")]
    Unauthorized,
    #[error("Confluence transport access was denied")]
    Forbidden,
    #[error("Confluence content was not found")]
    NotFound,
    #[error("Confluence request conflicted with the current resource")]
    Conflict,
    #[error("Confluence transport was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Confluence transport timed out")]
    Timeout,
    #[error("Confluence transport returned an upstream failure")]
    ServerFailure { status: u16 },
    #[error("Confluence transport failed")]
    Network,
    #[error("Confluence CQL was rejected")]
    CqlRejected,
    #[error("Confluence cursor was rejected")]
    InvalidCursor,
    #[error("Confluence transport returned a partial response")]
    PartialResponse,
    #[error("Confluence transport response was truncated")]
    Truncated,
    #[error("Confluence transport response could not be decoded")]
    Decode,
    #[error("Confluence transport configuration is invalid")]
    InvalidConfiguration,
}

impl ConfluenceTransportError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::ServerFailure { status } => Some(*status),
            Self::Timeout
            | Self::Network
            | Self::CqlRejected
            | Self::InvalidCursor
            | Self::PartialResponse
            | Self::Truncated
            | Self::Decode
            | Self::InvalidConfiguration => None,
        }
    }
}

/// Provider credential failures. The only successful value is opaque
/// host-owned secret material at the transport boundary.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConfluenceCredentialError {
    #[error("BLOCKED_ENV: Confluence credentials are unavailable")]
    BlockedEnv,
    #[error("Confluence credential reference was revoked")]
    Revoked,
    #[error("Confluence credential reference was not found")]
    NotFound,
    #[error("Confluence credential reference was rejected")]
    Unauthorized,
}

/// Provider-level failures retain typed status classes and fence failures,
/// but never retain response bodies, tokens, or customer text.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConfluenceProviderError {
    #[error("BLOCKED_ENV: Confluence native access is unavailable")]
    BlockedEnv,
    #[error("Confluence credential was revoked")]
    Revoked,
    #[error("Confluence API returned 401 Unauthorized")]
    Unauthorized,
    #[error("Confluence API returned 403 Forbidden")]
    Forbidden,
    #[error("Confluence API returned 404 Not Found")]
    NotFound,
    #[error("Confluence page is archived")]
    Archived,
    #[error("Confluence page is deleted")]
    Deleted,
    #[error("Confluence page access was lost")]
    AccessLost,
    #[error("Confluence API returned 409 Conflict")]
    Conflict,
    #[error("Confluence API returned 429 Rate Limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Confluence API returned upstream HTTP {status}")]
    ServerFailure { status: u16 },
    #[error("Confluence provider transport failed")]
    Transport,
    #[error("Confluence provider response could not be decoded")]
    Decode,
    #[error("Confluence CQL template was rejected")]
    CqlRejected,
    #[error("Confluence pagination cursor is invalid")]
    InvalidCursor,
    #[error("Confluence pagination cursor repeated")]
    CursorLoop,
    #[error("Confluence response was partial")]
    PartialResponse,
    #[error("Confluence response was truncated")]
    Truncated,
    #[error("Confluence scope does not match the registered scope")]
    ScopeMismatch,
    #[error("Confluence provider manifest drifted")]
    ProviderManifestDrift,
    #[error("Confluence registration digest does not match")]
    RegistrationDigestMismatch,
    #[error("Confluence registration is revoked")]
    RegistrationRevoked,
    #[error("Confluence site or cloud ID drifted")]
    SiteDrift,
    #[error("Confluence account drifted")]
    AccountDrift,
    #[error("Confluence space drifted")]
    SpaceDrift,
    #[error("Confluence page or content ID drifted")]
    PageDrift,
    #[error("Confluence page version drifted")]
    VersionDrift,
    #[error("Confluence permission snapshot drifted")]
    PermissionDrift,
    #[error("Confluence body digest did not match the bounded response")]
    BodyMismatch,
    #[error("Confluence metadata digest did not match the bounded response")]
    MetadataMismatch,
    #[error("Confluence response was empty")]
    EmptyResponse,
    #[error("Confluence provider configuration is invalid")]
    InvalidConfiguration,
    #[error("Confluence credential resolution failed")]
    Credential,
    #[error("Confluence provider returned an invalid response")]
    InvalidResponse,
}

impl ConfluenceProviderError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::ServerFailure { status } => Some(*status),
            Self::BlockedEnv
            | Self::Revoked
            | Self::RegistrationRevoked
            | Self::Transport
            | Self::Decode
            | Self::CqlRejected
            | Self::InvalidCursor
            | Self::CursorLoop
            | Self::PartialResponse
            | Self::Truncated
            | Self::ScopeMismatch
            | Self::ProviderManifestDrift
            | Self::RegistrationDigestMismatch
            | Self::SiteDrift
            | Self::AccountDrift
            | Self::SpaceDrift
            | Self::PageDrift
            | Self::VersionDrift
            | Self::PermissionDrift
            | Self::BodyMismatch
            | Self::MetadataMismatch
            | Self::EmptyResponse
            | Self::Archived
            | Self::Deleted
            | Self::AccessLost
            | Self::InvalidConfiguration
            | Self::Credential
            | Self::InvalidResponse => None,
        }
    }
}

impl From<ConfluenceCredentialError> for ConfluenceProviderError {
    fn from(error: ConfluenceCredentialError) -> Self {
        match error {
            ConfluenceCredentialError::BlockedEnv => Self::BlockedEnv,
            ConfluenceCredentialError::Revoked => Self::Revoked,
            ConfluenceCredentialError::NotFound | ConfluenceCredentialError::Unauthorized => {
                Self::Credential
            }
        }
    }
}

impl From<ConfluenceTransportError> for ConfluenceProviderError {
    fn from(error: ConfluenceTransportError) -> Self {
        match error {
            ConfluenceTransportError::Unauthorized => Self::Unauthorized,
            ConfluenceTransportError::Forbidden => Self::Forbidden,
            ConfluenceTransportError::NotFound => Self::NotFound,
            ConfluenceTransportError::Conflict => Self::Conflict,
            ConfluenceTransportError::RateLimited {
                retry_after_seconds,
            } => Self::RateLimited {
                retry_after_seconds,
            },
            ConfluenceTransportError::Timeout | ConfluenceTransportError::Network => {
                Self::Transport
            }
            ConfluenceTransportError::ServerFailure { status } => Self::ServerFailure { status },
            ConfluenceTransportError::CqlRejected => Self::CqlRejected,
            ConfluenceTransportError::InvalidCursor => Self::InvalidCursor,
            ConfluenceTransportError::PartialResponse => Self::PartialResponse,
            ConfluenceTransportError::Truncated => Self::Truncated,
            ConfluenceTransportError::Decode => Self::Decode,
            ConfluenceTransportError::InvalidConfiguration => Self::InvalidConfiguration,
        }
    }
}

/// Service and Mission-consumer failures. They remain outside the kernel
/// Outcome/Consent/Effect/Receipt authority boundary.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConfluenceKnowledgeResultError {
    #[error("invalid {field}: {reason}")]
    InvalidInput { field: &'static str, reason: String },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("invalid Confluence scope")]
    InvalidScope,
    #[error("consent does not grant capability {capability:?}")]
    ConsentRequired { capability: ConfluenceCapability },
    #[error("provider manifest is invalid")]
    InvalidProviderManifest,
    #[error("provider manifest drifted")]
    ProviderManifestDrift,
    #[error("Layer 1 provider exposes external-write or privileged authority")]
    ExternalWriteAuthority,
    #[error("request scope does not match the registration")]
    ScopeMismatch,
    #[error("proposal is invalid")]
    InvalidProposal,
    #[error("proposal is bound to a different registration")]
    ProposalRegistrationMismatch,
    #[error("knowledge evidence is empty and cannot produce a proposal")]
    EmptyEvidence,
    #[error("knowledge evidence is partial, truncated, or ambiguous")]
    AmbiguousEvidence,
    #[error("knowledge result read-back mismatch for {field:?}")]
    ReadbackMismatch {
        field: KnowledgeReadbackField,
        expected: String,
        actual: String,
    },
    #[error("knowledge result read-back is invalid")]
    InvalidReadback,
    #[error("provider error: {0}")]
    Provider(#[from] ConfluenceProviderError),
}
