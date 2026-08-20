use thiserror::Error;

/// Errors returned by the typed Box Layer 1 boundary.  Error messages are
/// deliberately identifier- and payload-free so a failed provider call cannot
/// turn customer content, tokens, or collaborator data into log material.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum BoxArtifactError {
    #[error("invalid {field}: {reason}")]
    InvalidInput {
        field: &'static str,
        reason: &'static str,
    },
    #[error("invalid {kind} identifier")]
    InvalidIdentifier { kind: &'static str },
    #[error("BLOCKED_ENV: Box credentials are unavailable")]
    BlockedEnv,
    #[error("Box artifact plugin registration is revoked")]
    Revoked,
    #[error("Box artifact request is outside the registered scope")]
    ScopeMismatch,
    #[error("Box artifact registration digest does not match")]
    RegistrationDigestMismatch,
    #[error("Box artifact provider version does not match the registration")]
    ProviderVersionMismatch,
    #[error("Box artifact provider response has an invalid digest")]
    InvalidDigest,
    #[error("Box SHA-1 digest did not match the bounded content")]
    Sha1Mismatch,
    #[error("Box content digest did not match the bounded content")]
    ContentDigestMismatch,
    #[error("Box content range did not match the requested bounded range")]
    RangeMismatch,
    #[error("Box content read was partial and cannot be adopted")]
    PartialContent,
    #[error("Box file revision is stale")]
    StaleRevision,
    #[error("Box file revision is ambiguous")]
    AmbiguousRevision,
    #[error("Box file access was lost")]
    AccessLost,
    #[error("Box file was deleted or not found")]
    Deleted,
    #[error("Box file is trashed")]
    Trashed,
    #[error("Box provider returned an unknown state")]
    ProviderUnknown,
    #[error("Box pagination cursor is invalid")]
    InvalidCursor,
    #[error("Box pagination cursor does not match the registered scope")]
    CursorScopeMismatch,
    #[error("Box provider is rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Box provider request timed out")]
    Timeout,
    #[error("Box provider transport failed")]
    Transport,
    #[error("Box provider response could not be decoded")]
    Decode,
    #[error("Box provider response exceeded the bounded response size")]
    ResponseTooLarge,
    #[error("Box provider returned an unexpected HTTP status")]
    UnexpectedStatus { status: u16 },
    #[error("Box native transport configuration is invalid")]
    InvalidConfiguration,
    #[error("Layer 1 is read-only; {operation} is reserved for Layer 2")]
    WriteNotAvailable { operation: &'static str },
    #[error("Box artifact result is not adoptable: {reason}")]
    NotAdoptable { reason: &'static str },
    #[error("Box artifact registration revision overflowed")]
    RegistrationRevisionOverflow,
    #[error("Box provider revision overflowed")]
    ProviderRevisionOverflow,
}

/// Transport failures are kept separate from provider semantics so fixtures,
/// loopback servers, and native HTTPS can share the same typed seam.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum BoxTransportError {
    #[error("Box transport authentication was rejected")]
    Unauthorized,
    #[error("Box transport access was denied")]
    Forbidden,
    #[error("Box transport resource was not found")]
    NotFound,
    #[error("Box transport resource was gone")]
    Gone,
    #[error("Box transport was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Box transport timed out")]
    Timeout,
    #[error("Box transport failed")]
    Network,
    #[error("Box transport response could not be decoded")]
    Decode,
    #[error("Box transport response exceeded its byte bound")]
    ResponseTooLarge,
    #[error("Box transport returned an invalid content range")]
    RangeMismatch,
    #[error("Box transport returned an unexpected HTTP status")]
    UnexpectedStatus { status: u16 },
    #[error("Box transport configuration is invalid")]
    InvalidConfiguration,
}

impl From<BoxTransportError> for BoxArtifactError {
    fn from(error: BoxTransportError) -> Self {
        match error {
            BoxTransportError::Unauthorized | BoxTransportError::Forbidden => Self::AccessLost,
            BoxTransportError::NotFound | BoxTransportError::Gone => Self::Deleted,
            BoxTransportError::RateLimited {
                retry_after_seconds,
            } => Self::RateLimited {
                retry_after_seconds,
            },
            BoxTransportError::Timeout => Self::Timeout,
            BoxTransportError::Network => Self::Transport,
            BoxTransportError::Decode => Self::Decode,
            BoxTransportError::ResponseTooLarge => Self::ResponseTooLarge,
            BoxTransportError::RangeMismatch => Self::RangeMismatch,
            BoxTransportError::UnexpectedStatus { status } => Self::UnexpectedStatus { status },
            BoxTransportError::InvalidConfiguration => Self::InvalidConfiguration,
        }
    }
}
