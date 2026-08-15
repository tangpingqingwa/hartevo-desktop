use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("invalid {field} identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid digest")]
    InvalidDigest,
    #[error("invalid time window")]
    InvalidTimeWindow,
    #[error("invalid bound for {field}")]
    InvalidBound { field: &'static str },
    #[error("invalid scope or digest fence")]
    InvalidScope,
    #[error("invalid opaque secret reference")]
    InvalidSecretReference,
    #[error("invalid opaque cursor")]
    InvalidCursor,
    #[error("serialization failed")]
    Serialization,
}
