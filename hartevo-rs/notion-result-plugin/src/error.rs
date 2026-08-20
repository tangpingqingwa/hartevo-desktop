use thiserror::Error;

use crate::model::{NotionCapability, NotionReadbackField};

/// Provider-bound failures.  The variants deliberately retain status classes
/// without retaining response bodies, which keeps diagnostics content-free.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum NotionProviderError {
    #[error("Notion native access is blocked by the environment")]
    BlockedEnv,
    #[error("Notion API returned 403 Forbidden")]
    Forbidden,
    #[error("Notion API returned 404 Not Found")]
    NotFound,
    #[error("Notion API returned 409 Conflict")]
    Conflict,
    #[error("Notion API returned 429 Rate Limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Notion API returned HTTP {status}")]
    Http { status: u16 },
    #[error("provider manifest does not match the request")]
    ManifestMismatch,
    #[error("recording provider has no matching page")]
    NoRecordedPage,
    #[error("provider response is invalid for {field}")]
    InvalidResponse { field: &'static str },
}

impl NotionProviderError {
    /// Classify the status codes that are part of the Layer 1 contract.
    pub const fn from_status(status: u16) -> Self {
        match status {
            403 => Self::Forbidden,
            404 => Self::NotFound,
            409 => Self::Conflict,
            429 => Self::RateLimited {
                retry_after_seconds: None,
            },
            status => Self::Http { status },
        }
    }

    /// Return the HTTP status when the failure represents one.
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::Http { status } => Some(*status),
            Self::BlockedEnv
            | Self::ManifestMismatch
            | Self::NoRecordedPage
            | Self::InvalidResponse { .. } => None,
        }
    }
}

/// Fail-closed service, scope, proposal, and read-back failures.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum NotionResultError {
    #[error("invalid {field}: {reason}")]
    InvalidInput { field: &'static str, reason: String },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("invalid Notion scope or consent")]
    InvalidScope,
    #[error("invalid Notion provider manifest")]
    InvalidProviderManifest,
    #[error("provider manifest drifted: expected {expected}, actual {actual}")]
    ProviderManifestDrift { expected: String, actual: String },
    #[error("Layer 1 provider has external-write or privileged authority")]
    ExternalWriteAuthority,
    #[error("request scope does not match the provider scope")]
    ScopeMismatch,
    #[error("consent does not grant capability {capability:?}")]
    ConsentRequired { capability: NotionCapability },
    #[error("proposal is invalid")]
    InvalidProposal,
    #[error("proposal is bound to a different provider manifest")]
    ProposalManifestMismatch,
    #[error("read-back mismatch for {field:?}: expected {expected}, actual {actual}")]
    ReadbackMismatch {
        field: NotionReadbackField,
        expected: String,
        actual: String,
    },
    #[error("read-back is invalid for {field}")]
    InvalidReadback { field: &'static str },
    #[error("provider error: {0}")]
    Provider(#[from] NotionProviderError),
}
