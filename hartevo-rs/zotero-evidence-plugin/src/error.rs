use thiserror::Error;

use crate::model::{
    Digest, ZoteroAccessLoss, ZoteroConflictReason, ZoteroObjectIdentity,
    ZoteroPreconditionFailure, ZoteroPreconditionKind, ZoteroProvenance, ZoteroVersion,
};

/// Provider-bound failures retain the provider's status class but never retain
/// a response body, URL query, token, private note, or attachment content.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ZoteroProviderError {
    #[error("Zotero native or external access is blocked in Layer 1")]
    BlockedEnv,
    #[error("a SecretReference is required for this private library read")]
    SecretReferenceRequired,
    #[error("provider manifest is invalid or has drifted")]
    ManifestMismatch,
    #[error("provider request scope does not match the registered scope")]
    ScopeMismatch,
    #[error("no deterministic recording exists for operation {operation:?}")]
    NoRecordedResponse { operation: ZoteroOperationKind },
    #[error("provider reached an unknown state during operation {operation:?}")]
    ProviderUnknown { operation: ZoteroOperationKind },
    #[error("recorded provider response is invalid for {field}")]
    InvalidResponse { field: &'static str },
    #[error("Zotero returned 403 Forbidden: {access:?}")]
    Forbidden403 { access: ZoteroAccessLoss },
    #[error("Zotero returned 404 Not Found for {object:?}")]
    NotFound404 {
        object: ZoteroObjectIdentity,
        deleted: bool,
    },
    #[error("Zotero returned 409 Conflict: {reason:?}")]
    Conflict409 { reason: ZoteroConflictReason },
    #[error(
        "Zotero returned 412 Precondition Failed: expected {expected:?}, actual {actual:?}, reason {reason:?}"
    )]
    PreconditionFailed412 {
        expected: Option<ZoteroVersion>,
        actual: Option<ZoteroVersion>,
        reason: ZoteroPreconditionFailure,
    },
    #[error("Zotero returned 428 Precondition Required: {required:?}")]
    PreconditionRequired428 { required: ZoteroPreconditionKind },
    #[error(
        "Zotero returned 429 Too Many Requests (retry after {retry_after_seconds:?}, backoff {backoff_seconds:?})"
    )]
    RateLimited429 {
        retry_after_seconds: Option<u64>,
        backoff_seconds: Option<u64>,
    },
    #[error("Zotero requested a backoff of {seconds} seconds")]
    Backoff { seconds: u64 },
    #[error("Zotero returned unsupported HTTP status {status}")]
    Http { status: u16 },
    #[error("provider response failed closed because its cursor regressed")]
    CursorRegressed,
    #[error("provider response is partial or ambiguous")]
    PartialOrAmbiguous,
    #[error("provider response was tampered with")]
    TamperedResponse,
    #[error(
        "provider response used an unexpected provenance: expected {expected:?}, actual {actual:?}"
    )]
    ProvenanceMismatch {
        expected: ZoteroProvenance,
        actual: ZoteroProvenance,
    },
}

impl ZoteroProviderError {
    /// Convert an HTTP status to the typed Layer 1 status class.
    pub const fn from_status(status: u16) -> Self {
        match status {
            403 => Self::Forbidden403 {
                access: ZoteroAccessLoss::Unknown,
            },
            404 => Self::NotFound404 {
                object: ZoteroObjectIdentity::Unknown,
                deleted: false,
            },
            409 => Self::Conflict409 {
                reason: ZoteroConflictReason::LibraryLocked,
            },
            412 => Self::PreconditionFailed412 {
                expected: None,
                actual: None,
                reason: ZoteroPreconditionFailure::VersionDrift,
            },
            428 => Self::PreconditionRequired428 {
                required: ZoteroPreconditionKind::IfUnmodifiedSinceVersion,
            },
            429 => Self::RateLimited429 {
                retry_after_seconds: None,
                backoff_seconds: None,
            },
            status => Self::Http { status },
        }
    }

    /// Return the HTTP status represented by this provider failure, if any.
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Forbidden403 { .. } => Some(403),
            Self::NotFound404 { .. } => Some(404),
            Self::Conflict409 { .. } => Some(409),
            Self::PreconditionFailed412 { .. } => Some(412),
            Self::PreconditionRequired428 { .. } => Some(428),
            Self::RateLimited429 { .. } => Some(429),
            Self::Http { status } => Some(*status),
            Self::BlockedEnv
            | Self::SecretReferenceRequired
            | Self::ManifestMismatch
            | Self::ScopeMismatch
            | Self::NoRecordedResponse { .. }
            | Self::ProviderUnknown { .. }
            | Self::InvalidResponse { .. }
            | Self::Backoff { .. }
            | Self::CursorRegressed
            | Self::PartialOrAmbiguous
            | Self::TamperedResponse
            | Self::ProvenanceMismatch { .. } => None,
        }
    }
}

/// Service and Mission-consumer failures are fail-closed and content-free.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ZoteroEvidenceError {
    #[error("invalid {field}: {reason}")]
    InvalidInput { field: &'static str, reason: String },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("Zotero scope is invalid")]
    InvalidScope,
    #[error("Zotero provider manifest is invalid")]
    InvalidProviderManifest,
    #[error("Zotero provider manifest drifted: expected {expected}, actual {actual}")]
    ProviderManifestDrift { expected: Digest, actual: Digest },
    #[error("Zotero registration is revoked or not reversible")]
    RegistrationRevoked,
    #[error("Layer 1 provider exposes external write or native authority")]
    ExternalWriteAuthority,
    #[error("request scope does not match the registered provider scope")]
    ScopeMismatch,
    #[error("cursor identity does not match the exact library, scope, or provenance")]
    CursorIdentityMismatch,
    #[error("since cursor regressed from {requested} to {returned}")]
    CursorRegressed {
        requested: ZoteroVersion,
        returned: ZoteroVersion,
    },
    #[error("conditional request is not bound to the exact scope")]
    ConditionalScopeMismatch,
    #[error("provider provenance does not match the registered transport")]
    ProvenanceMismatch,
    #[error("provider response is not a valid Layer 1 response")]
    InvalidProviderResponse,
    #[error("provider response is tampered with")]
    TamperedResponse,
    #[error("source evidence cannot be adopted from a 304 Not Modified response")]
    NotModifiedIsNotEvidence,
    #[error("citation is formatted-only and is not source evidence")]
    CitationOnlyNotEvidence,
    #[error("citation and item metadata are not bound to the same exact version")]
    CitationVersionMismatch,
    #[error("citation style or locale drifted between request and result")]
    CitationPresentationMismatch,
    #[error("item is deleted or access was lost")]
    DeletedOrAccessLost,
    #[error("read result is partial or ambiguous")]
    PartialOrAmbiguous,
    #[error("evidence proposal binding is invalid")]
    InvalidEvidenceBinding,
    #[error("evidence proposal digest does not match its fields")]
    EvidenceDigestMismatch,
    #[error("provider error: {0}")]
    Provider(#[from] ZoteroProviderError),
}

/// Operation names are used in content-free recording calls and diagnostics.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ZoteroOperationKind {
    Probe,
    Read,
    Citation,
}
