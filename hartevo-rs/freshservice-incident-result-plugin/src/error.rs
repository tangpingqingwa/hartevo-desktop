//! Typed errors for the bounded Freshservice result boundary.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, FreshserviceIncidentResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FreshserviceIncidentResultError {
    #[error("invalid {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} revision must be non-zero")]
    InvalidRevision { field: &'static str },
    #[error("invalid digest")]
    InvalidDigest,
    #[error("invalid Freshservice scope: {0}")]
    InvalidScope(&'static str),
    #[error("invalid consent scope")]
    InvalidConsent,
    #[error("invalid permission snapshot")]
    InvalidPermissionSnapshot,
    #[error("invalid opaque secret reference")]
    InvalidSecretReference,
    #[error("invalid request")]
    InvalidRequest,
    #[error("registration is inactive")]
    RegistrationInactive,
    #[error("registration is already revoked")]
    RegistrationAlreadyRevoked,
    #[error("registration is not revoked")]
    RegistrationNotRevoked,
    #[error("registration revision overflowed")]
    RegistrationRevisionOverflow,
    #[error("scope mismatch")]
    ScopeMismatch,
    #[error("revision mismatch")]
    RevisionMismatch,
    #[error("consent mismatch")]
    ConsentMismatch,
    #[error("provider definition drift")]
    ProviderDefinitionDrift,
    #[error("pagination cursor drift")]
    PaginationDrift,
    #[error("pagination page bound exceeded")]
    PaginationBoundExceeded,
    #[error("response is too large")]
    ResponseTooLarge,
    #[error("malformed provider response")]
    MalformedResponse,
    #[error("provider transport failed: {0}")]
    Provider(#[from] crate::provider::FreshserviceTransportError),
    #[error("evidence is tampered")]
    TamperedEvidence,
    #[error("proposal is tampered")]
    TamperedProposal,
    #[error("proposal has already been consumed")]
    ReplayDetected,
    #[error("recording idempotency key conflicts with another proposal")]
    RecordingConflict,
    #[error("contract identity mismatch")]
    ContractMismatch,
    #[error("unsupported external mutation")]
    UnsupportedMutation,
}
