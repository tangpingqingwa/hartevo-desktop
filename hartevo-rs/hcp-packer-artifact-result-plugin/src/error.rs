use thiserror::Error;

pub type Result<T> = std::result::Result<T, HcpPackerArtifactResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HcpPackerArtifactResultError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    InvalidText { field: &'static str },
    #[error("{field} contains unsupported characters")]
    InvalidCharacters { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("the HCP Packer scope is invalid")]
    InvalidScope,
    #[error("the permission fence is invalid")]
    InvalidPermissionFence,
    #[error("the registration is invalid or tampered")]
    InvalidRegistration,
    #[error("the registration is inactive")]
    RegistrationInactive,
    #[error("the registration has been reversed")]
    RegistrationReversed,
    #[error("the registration is already in the requested state")]
    RegistrationStateConflict,
    #[error("the HCP Packer scope does not match")]
    ScopeMismatch,
    #[error("the permission fence does not match")]
    PermissionMismatch,
    #[error("the opaque SecretReference is revoked or mismatched")]
    SecretRevoked,
    #[error("the provider identity or revision drifted")]
    ProviderDrift,
    #[error("the API revision drifted")]
    ApiDrift,
    #[error("the contract identity or digest drifted")]
    ContractDrift,
    #[error("the evidence digest fence drifted")]
    EvidenceDrift,
    #[error("the channel or version metadata is stale")]
    StaleState,
    #[error("the provider response was tampered")]
    TamperedEvidence,
    #[error("the request or response was replayed")]
    ReplayConflict,
    #[error("the pagination cursor was replayed")]
    PaginationReplay,
    #[error("the pagination limit was exhausted")]
    PaginationExceeded,
    #[error("the provider response was truncated")]
    Truncated,
    #[error("provider access was lost")]
    AccessLoss,
    #[error("the provider is unknown or unavailable")]
    ProviderUnknown,
    #[error("the provider response exceeded the byte bound")]
    ResponseTooLarge,
    #[error("the provider request is invalid")]
    InvalidRequest,
    #[error("the operation is not allowlisted")]
    ForbiddenOperation,
    #[error("the operation is read-only and cannot mutate HCP Packer")]
    ExternalWriteForbidden,
    #[error("the local recording key conflicts with another proposal")]
    RecordingConflict,
    #[error("the requested mission revision is stale")]
    StaleMissionRevision,
    #[error("the JSON contract is invalid")]
    ContractShape,
    #[error("transport error: {0}")]
    Transport(#[from] HcpPackerTransportError),
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HcpPackerTransportError {
    #[error("the environment is blocked")]
    BlockedEnvironment,
    #[error("the provider returned an unauthorized response")]
    Unauthorized,
    #[error("the provider returned a forbidden response")]
    Forbidden,
    #[error("the provider resource was not found")]
    NotFound,
    #[error("the provider rate limited the request")]
    RateLimited,
    #[error("the provider returned a server failure")]
    ServerFailure,
    #[error("the provider response was malformed")]
    MalformedResponse,
    #[error("the provider response was explicitly truncated")]
    ResponseTruncated,
    #[error("the provider reported access loss")]
    AccessLoss,
    #[error("the provider identity is unknown")]
    ProviderUnknown,
    #[error("the provider transport replayed a response")]
    Replay,
}

impl HcpPackerArtifactResultError {
    pub const fn is_fail_closed(&self) -> bool {
        matches!(
            self,
            Self::InvalidRegistration
                | Self::RegistrationInactive
                | Self::RegistrationReversed
                | Self::ScopeMismatch
                | Self::PermissionMismatch
                | Self::SecretRevoked
                | Self::ProviderDrift
                | Self::ApiDrift
                | Self::ContractDrift
                | Self::EvidenceDrift
                | Self::StaleState
                | Self::TamperedEvidence
                | Self::ReplayConflict
                | Self::PaginationReplay
                | Self::PaginationExceeded
                | Self::Truncated
                | Self::AccessLoss
                | Self::ProviderUnknown
                | Self::ResponseTooLarge
                | Self::StaleMissionRevision
                | Self::Transport(_)
        )
    }
}
