use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("invalid {field} identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid digest")]
    InvalidDigest,
    #[error("invalid bounded value: {field}")]
    InvalidBound { field: &'static str },
    #[error("invalid time window")]
    InvalidTimeWindow,
    #[error("invalid scope binding")]
    InvalidScope,
    #[error("invalid opaque secret reference")]
    InvalidSecretReference,
    #[error("invalid opaque cursor")]
    InvalidCursor,
    #[error("serialization failed while computing a digest")]
    Serialization,
}
