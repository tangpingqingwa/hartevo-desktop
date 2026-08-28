use thiserror::Error;

use crate::model::SharePointCapability;

/// Transport failures are intentionally typed and body-free. A Graph
/// response body never crosses this error boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SharePointTransportError {
    #[error("Microsoft Graph returned 401 Unauthorized")]
    Unauthorized,
    #[error("Microsoft Graph returned 403 Forbidden")]
    Forbidden,
    #[error("Microsoft Graph returned 404 Not Found")]
    NotFound,
    #[error("Microsoft Graph returned 409 Conflict")]
    Conflict,
    #[error("Microsoft Graph returned 429 Rate Limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Microsoft Graph returned upstream HTTP {status}")]
    ServerFailure { status: u16 },
    #[error("Microsoft Graph transport timed out")]
    Timeout,
    #[error("Microsoft Graph transport failed")]
    Network,
    #[error("Microsoft Graph response could not be decoded")]
    Decode,
    #[error("Microsoft Graph response was partial")]
    PartialResponse,
    #[error("Microsoft Graph response was truncated")]
    Truncated,
    #[error("Microsoft Graph transport is BLOCKED_ENV")]
    BlockedEnv,
    #[error("Microsoft Graph transport configuration is invalid")]
    InvalidConfiguration,
}

impl SharePointTransportError {
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
            | Self::Decode
            | Self::PartialResponse
            | Self::Truncated
            | Self::BlockedEnv
            | Self::InvalidConfiguration => None,
        }
    }
}

/// Credential resolution reports only an availability class. Raw Entra
/// tokens are never represented by this Layer 1 API.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EntraCredentialError {
    #[error("BLOCKED_ENV: Microsoft Entra credentials are unavailable")]
    BlockedEnv,
    #[error("Microsoft Entra secret reference was revoked")]
    Revoked,
    #[error("Microsoft Entra secret reference was not found")]
    NotFound,
    #[error("Microsoft Entra credential reference was rejected")]
    Unauthorized,
}

/// Provider failures preserve status and scope-fence classes without
/// retaining content, tokens, URL query values, or response bodies.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MicrosoftGraphSharePointProviderError {
    #[error("BLOCKED_ENV: native Microsoft Graph access is unavailable")]
    BlockedEnv,
    #[error("Microsoft Entra credential was revoked")]
    Revoked,
    #[error("Microsoft Graph returned 401 Unauthorized")]
    Unauthorized,
    #[error("Microsoft Graph returned 403 Forbidden")]
    Forbidden,
    #[error("Microsoft Graph returned 404 Not Found")]
    NotFound,
    #[error("Microsoft Graph returned 409 Conflict")]
    Conflict,
    #[error("Microsoft Graph returned 429 Rate Limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Microsoft Graph returned upstream HTTP {status}")]
    ServerFailure { status: u16 },
    #[error("Microsoft Graph provider transport failed")]
    Transport,
    #[error("Microsoft Graph response could not be decoded")]
    Decode,
    #[error("Microsoft Graph response was partial")]
    PartialResponse,
    #[error("Microsoft Graph response was truncated")]
    Truncated,
    #[error("Microsoft Graph pagination cursor repeated")]
    PaginationLoop,
    #[error("Microsoft Graph API version drifted")]
    ApiVersionDrift,
    #[error("Microsoft Graph provider revision drifted")]
    ProviderRevisionDrift,
    #[error("Microsoft Graph tenant drifted")]
    TenantDrift,
    #[error("Microsoft Graph national cloud drifted")]
    NationalCloudDrift,
    #[error("SharePoint site drifted")]
    SiteDrift,
    #[error("SharePoint drive drifted")]
    DriveDrift,
    #[error("SharePoint list drifted")]
    ListDrift,
    #[error("SharePoint item drifted")]
    ItemDrift,
    #[error("SharePoint item version drifted")]
    VersionDrift,
    #[error("SharePoint search scope drifted")]
    SearchDrift,
    #[error("SharePoint permission snapshot drifted")]
    PermissionDrift,
    #[error("SharePoint provider manifest drifted")]
    ProviderManifestDrift,
    #[error("SharePoint registration digest does not match")]
    RegistrationDigestMismatch,
    #[error("SharePoint registration is revoked")]
    RegistrationRevoked,
    #[error("SharePoint response identity is invalid")]
    InvalidResponse,
    #[error("SharePoint response was empty")]
    EmptyResponse,
    #[error("SharePoint credential resolution failed")]
    Credential,
}

impl MicrosoftGraphSharePointProviderError {
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
            | Self::Transport
            | Self::Decode
            | Self::PartialResponse
            | Self::Truncated
            | Self::PaginationLoop
            | Self::ApiVersionDrift
            | Self::ProviderRevisionDrift
            | Self::TenantDrift
            | Self::NationalCloudDrift
            | Self::SiteDrift
            | Self::DriveDrift
            | Self::ListDrift
            | Self::ItemDrift
            | Self::VersionDrift
            | Self::SearchDrift
            | Self::PermissionDrift
            | Self::ProviderManifestDrift
            | Self::RegistrationDigestMismatch
            | Self::RegistrationRevoked
            | Self::InvalidResponse
            | Self::EmptyResponse
            | Self::Credential => None,
        }
    }
}

impl From<EntraCredentialError> for MicrosoftGraphSharePointProviderError {
    fn from(error: EntraCredentialError) -> Self {
        match error {
            EntraCredentialError::BlockedEnv => Self::BlockedEnv,
            EntraCredentialError::Revoked => Self::Revoked,
            EntraCredentialError::NotFound | EntraCredentialError::Unauthorized => Self::Credential,
        }
    }
}

impl From<SharePointTransportError> for MicrosoftGraphSharePointProviderError {
    fn from(error: SharePointTransportError) -> Self {
        match error {
            SharePointTransportError::Unauthorized => Self::Unauthorized,
            SharePointTransportError::Forbidden => Self::Forbidden,
            SharePointTransportError::NotFound => Self::NotFound,
            SharePointTransportError::Conflict => Self::Conflict,
            SharePointTransportError::RateLimited {
                retry_after_seconds,
            } => Self::RateLimited {
                retry_after_seconds,
            },
            SharePointTransportError::ServerFailure { status } => Self::ServerFailure { status },
            SharePointTransportError::Timeout
            | SharePointTransportError::Network
            | SharePointTransportError::InvalidConfiguration => Self::Transport,
            SharePointTransportError::Decode => Self::Decode,
            SharePointTransportError::PartialResponse => Self::PartialResponse,
            SharePointTransportError::Truncated => Self::Truncated,
            SharePointTransportError::BlockedEnv => Self::BlockedEnv,
        }
    }
}

/// Service and Mission-consumer failures remain outside kernel Outcome,
/// Effect, durable Receipt, and Work Product adoption authority.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SharePointKnowledgeResultError {
    #[error("invalid {field}: {reason}")]
    InvalidInput { field: &'static str, reason: String },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("invalid SharePoint knowledge scope")]
    InvalidScope,
    #[error("consent scope does not grant capability {capability:?}")]
    ConsentRequired { capability: SharePointCapability },
    #[error("invalid provider manifest")]
    InvalidProviderManifest,
    #[error("provider manifest drifted")]
    ProviderManifestDrift,
    #[error("Layer 1 exposes forbidden external-write or privileged authority")]
    ExternalWriteAuthority,
    #[error("request scope does not match the registration")]
    ScopeMismatch,
    #[error("registration digest does not match the provider")]
    RegistrationDigestMismatch,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("knowledge evidence is invalid")]
    InvalidEvidence,
    #[error("knowledge evidence digest does not match its fields")]
    EvidenceDigestMismatch,
    #[error("knowledge evidence is empty and cannot produce a result")]
    EmptyEvidence,
    #[error("knowledge result proposal is invalid")]
    InvalidProposal,
    #[error("knowledge result proposal is bound to a different registration")]
    ProposalRegistrationMismatch,
    #[error("knowledge result proposal is bound to a different scope")]
    ProposalScopeMismatch,
    #[error("provider error: {0}")]
    Provider(#[from] MicrosoftGraphSharePointProviderError),
}
