//! Errors for the bounded AWS Service Catalog Layer-1 boundary.

use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsServiceCatalogTransportError {
    #[error("native transport is blocked by Layer 1")]
    BlockedEnv,
    #[error("provider rejected the bounded request")]
    BadRequest,
    #[error("provider credentials were not authorized")]
    Unauthorized,
    #[error("provider access was forbidden")]
    Forbidden,
    #[error("provider object was not found")]
    NotFound,
    #[error("provider rate limited the bounded read")]
    RateLimited,
    #[error("provider returned a server error")]
    ServerError,
    #[error("provider read timed out")]
    Timeout,
    #[error("provider access was lost during the read")]
    AccessLost,
    #[error("provider returned only a partial page")]
    Partial,
    #[error("provider response was malformed")]
    InvalidResponse,
}

impl AwsServiceCatalogTransportError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::RateLimited => Some(429),
            Self::ServerError => Some(500),
            Self::BlockedEnv
            | Self::Timeout
            | Self::AccessLost
            | Self::Partial
            | Self::InvalidResponse => None,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsServiceCatalogError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} is too long")]
    TooLong { field: &'static str },
    #[error("{field} contains invalid whitespace or a control character")]
    InvalidText { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} exceeds its bound")]
    BoundExceeded { field: &'static str },
    #[error("SearchProvisionedProducts page size must be between one and one hundred")]
    InvalidSearchPageSize,
    #[error("ListRecordHistory page size must be between one and twenty")]
    InvalidHistoryPageSize,
    #[error("page count must be positive and bounded")]
    InvalidPageCount,
    #[error("opaque page token is invalid")]
    InvalidPageToken,
    #[error("opaque cursor repeated a prior page")]
    CursorLoop,
    #[error("opaque cursor does not match its request binding")]
    CursorTampered,
    #[error("a response was replayed or duplicated")]
    ReplayRejected,
    #[error("idempotency key was reused with a different request")]
    IdempotencyConflict,
    #[error("Mission revision is stale")]
    StaleMission,
    #[error("provider/product/artifact/provisioned-product/record revision fence failed")]
    RevisionMismatch,
    #[error("request scope does not match the active registration")]
    ScopeMismatch,
    #[error("provider returned an object outside the exact registered scope")]
    ScopeViolation,
    #[error("registration is inactive")]
    RegistrationInactive,
    #[error("registration has already been reversed")]
    RegistrationReversed,
    #[error("registration binding is invalid")]
    InvalidRegistration,
    #[error("registration contract drifted")]
    ContractDrift,
    #[error("provider definition is not the Layer-1 definition")]
    ProviderDefinitionMismatch,
    #[error("provider response integrity digest is invalid")]
    ResponseIntegrity,
    #[error("proposal or evidence integrity digest is invalid")]
    TamperedEvidence,
    #[error("provider response ordering is not deterministic")]
    NonDeterministicOrder,
    #[error("provider returned an unsupported SearchQuery")]
    UnsupportedSearchQuery,
    #[error("provider access was lost")]
    AccessLost,
    #[error("provider state is unknown")]
    ProviderUnknown,
    #[error("provider transport failed: {0}")]
    Transport(#[from] AwsServiceCatalogTransportError),
}

pub type Result<T> = std::result::Result<T, AwsServiceCatalogError>;
