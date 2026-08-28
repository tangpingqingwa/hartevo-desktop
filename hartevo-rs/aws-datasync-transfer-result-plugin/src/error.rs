use thiserror::Error;

use crate::model::Digest;

pub type Result<T> = std::result::Result<T, AwsDataSyncTransferError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsDataSyncTransferError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} is too long")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character")]
    ControlCharacter { field: &'static str },
    #[error("{field} is not a valid bounded identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("invalid SHA-256 digest")]
    InvalidDigest,
    #[error("invalid account or region scope")]
    InvalidScope,
    #[error("scope fence does not match")]
    ScopeMismatch,
    #[error("task fence does not match")]
    TaskMismatch,
    #[error("execution fence does not match")]
    ExecutionMismatch,
    #[error("cursor is not bound to this scope and request")]
    CursorMismatch,
    #[error("response is larger than the Layer-1 response bound")]
    ResponseTooLarge,
    #[error("response contains more items than the request bound")]
    ResponseItemBoundExceeded,
    #[error("invalid provider response")]
    InvalidResponse,
    #[error("provider identity or API revision drifted")]
    ProviderDrift,
    #[error("invalid permission snapshot")]
    InvalidPermissionSnapshot,
    #[error("invalid consent scope")]
    InvalidConsent,
    #[error("invalid opaque SigV4 secret reference")]
    InvalidSecretReference,
    #[error("secret reference has been revoked")]
    SecretRevoked,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("evidence was tampered with")]
    TamperedEvidence,
    #[error("provider state transition is invalid")]
    InvalidStateTransition,
    #[error("request is invalid")]
    InvalidRequest,
    #[error("provider transport is blocked by the environment")]
    BlockedEnv,
    #[error("provider transport returned an invalid result")]
    TransportInvalid,
    #[error("provider transport failure ({kind})")]
    Transport { kind: &'static str, digest: Digest },
    #[error("contract validation failed: {0}")]
    Contract(String),
    #[error("plugin runtime definition failed: {0}")]
    Plugin(#[from] hartevo_plugin_runtime::PluginError),
}
