//! Errors shared by the bounded AWS Firewall Manager Layer-1 seams.

use thiserror::Error;

use crate::model::Digest;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    ControlCharacter { field: &'static str },
    #[error("{field} contains unsupported characters")]
    InvalidCharacters { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a bounded opaque cursor")]
    InvalidCursor { field: &'static str },
    #[error("{field} contains too many entries")]
    TooMany { field: &'static str },
    #[error("{field} is not allowed for this operation")]
    Unsupported { field: &'static str },
    #[error("{field} has a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("registration is already revoked or reversed")]
    RegistrationInactive,
    #[error("{field} is expired")]
    Expired { field: &'static str },
}

#[derive(Clone, Copy, Debug, Eq, Error, Hash, PartialEq)]
pub enum TransportFailure {
    #[error("400 bad request")]
    BadRequest,
    #[error("401 unauthorized")]
    Unauthorized,
    #[error("403 access denied")]
    AccessDenied,
    #[error("403 forbidden")]
    Forbidden,
    #[error("404 not found")]
    NotFound,
    #[error("429 throttled")]
    Throttled,
    #[error("429 rate limited")]
    RateLimited,
    #[error("500 server error")]
    Server,
    #[error("500 server error")]
    ServerError,
    #[error("request timed out")]
    Timeout,
    #[error("provider access was lost")]
    AccessLoss,
    #[error("provider returned partial evidence")]
    Partial,
    #[error("provider response is unknown or malformed")]
    Unknown,
    #[error("the environment is BLOCKED_ENV")]
    BlockedEnv,
    #[error("provider pagination loop detected")]
    PaginationLoop,
    #[error("provider evidence is stale")]
    Stale,
}

impl TransportFailure {
    pub const fn status_code(self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::AccessDenied | Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Throttled | Self::RateLimited => Some(429),
            Self::Server | Self::ServerError => Some(500),
            Self::Timeout
            | Self::AccessLoss
            | Self::Partial
            | Self::Unknown
            | Self::BlockedEnv
            | Self::PaginationLoop
            | Self::Stale => None,
        }
    }

    pub const fn from_status(status: u16) -> Self {
        match status {
            400 => Self::BadRequest,
            401 => Self::Unauthorized,
            403 => Self::AccessDenied,
            404 => Self::NotFound,
            429 => Self::Throttled,
            500..=599 => Self::Server,
            _ => Self::Unknown,
        }
    }

    pub const fn is_access_loss(self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::AccessDenied | Self::Forbidden | Self::AccessLoss
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("AWS Firewall Manager transport failure: {failure}")]
pub struct TransportError {
    pub failure: TransportFailure,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

impl TransportError {
    pub fn new(failure: TransportFailure) -> Self {
        let label = match failure {
            TransportFailure::BadRequest => "400",
            TransportFailure::Unauthorized => "401",
            TransportFailure::AccessDenied | TransportFailure::Forbidden => "403",
            TransportFailure::NotFound => "404",
            TransportFailure::Throttled | TransportFailure::RateLimited => "429",
            TransportFailure::Server | TransportFailure::ServerError => "500",
            TransportFailure::Timeout => "timeout",
            TransportFailure::AccessLoss => "access_loss",
            TransportFailure::Partial => "partial",
            TransportFailure::Unknown => "unknown",
            TransportFailure::BlockedEnv => "BLOCKED_ENV",
            TransportFailure::PaginationLoop => "pagination_loop",
            TransportFailure::Stale => "stale",
        };
        Self {
            failure,
            status_code: failure.status_code(),
            error_digest: Digest::from_text(format!("aws-fms-transport/{label}/v1")),
        }
    }

    pub fn from_status(status: u16) -> Self {
        Self::new(TransportFailure::from_status(status))
    }

    pub fn blocked_env() -> Self {
        Self::new(TransportFailure::BlockedEnv)
    }

    pub fn timeout() -> Self {
        Self::new(TransportFailure::Timeout)
    }

    pub fn access_loss() -> Self {
        Self::new(TransportFailure::AccessLoss)
    }

    pub fn partial() -> Self {
        Self::new(TransportFailure::Partial)
    }

    pub fn unknown() -> Self {
        Self::new(TransportFailure::Unknown)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsFirewallManagerError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("provider definition is invalid")]
    InvalidProvider,
    #[error("provider operation is not allowlisted")]
    OperationNotAllowed,
    #[error("provider response is malformed or exceeds a Layer-1 bound")]
    InvalidResponse,
    #[error("provider response contains a duplicate item")]
    DuplicateItem,
    #[error("provider pagination cursor is invalid or repeated")]
    CursorMismatch,
    #[error("provider pagination is incomplete within the Layer-1 bound")]
    IncompletePagination,
    #[error("provider response scope or permission fence drifted")]
    ProviderDrift,
    #[error("policy is outside the explicit policy allowlist")]
    PolicyNotAllowed,
    #[error("member account is outside the explicit account allowlist")]
    AccountNotAllowed,
    #[error("resource type is outside the explicit resource-type allowlist")]
    ResourceTypeNotAllowed,
    #[error("opaque SigV4 secret reference is invalid, revoked, or out of scope")]
    InvalidSecretReference,
    #[error("permission snapshot is invalid or no longer matches the registration")]
    PermissionDrift,
    #[error("Mission, Project, or Work Product scope is stale")]
    StaleMission,
    #[error("consent or evidence has expired")]
    ExpiredEvidence,
    #[error("registration is inactive")]
    RegistrationInactive,
    #[error("registration digest or revision does not match")]
    RegistrationMismatch,
    #[error("registration transition is invalid")]
    InvalidRegistrationTransition,
    #[error("evidence is partial, unknown, stale, or access-loss and cannot be accepted")]
    NonAdoptableEvidence,
    #[error("evidence or proposal digest verification failed")]
    TamperedEvidence,
    #[error("recording key already contains a different evidence digest")]
    RecordingConflict,
    #[error("recording replay does not match the original proposal")]
    ReplayMismatch,
    #[error("Layer-1 never grants external effect or effective authorization")]
    AuthorityViolation,
}

pub type Result<T> = std::result::Result<T, AwsFirewallManagerError>;
pub type ProviderError = AwsFirewallManagerError;
pub type ServiceError = AwsFirewallManagerError;
pub type ConsumerError = AwsFirewallManagerError;
