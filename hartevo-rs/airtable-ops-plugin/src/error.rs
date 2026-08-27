use thiserror::Error;

use crate::model::{AirtableProviderProvenance, AirtableScope};

/// Errors returned by the Layer 1 Airtable operations service.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum AirtableError {
    #[error("invalid {field}: {reason}")]
    InvalidInput { field: String, reason: String },
    #[error("Airtable contract drift: expected {expected}, observed {observed}")]
    ContractDrift { expected: String, observed: String },
    #[error("Airtable provider scope mismatch: expected {expected:?}, observed {observed:?}")]
    ScopeMismatch {
        expected: Box<AirtableScope>,
        observed: Box<AirtableScope>,
    },
    #[error("Airtable schema drift: expected {expected}, observed {observed}")]
    SchemaDrift { expected: String, observed: String },
    #[error("Airtable field allowlist rejected {field}: {reason}")]
    FieldAllowlist { field: String, reason: String },
    #[error("Airtable pagination failed: {reason}")]
    Pagination { reason: String },
    #[error("Airtable batch has {count} records; maximum is {maximum}")]
    BatchBoundary { count: usize, maximum: usize },
    #[error("Airtable read-back mismatch: {0}")]
    ReadbackMismatch(#[from] ReadbackMismatch),
    #[error("Airtable receipt mismatch: {reason}")]
    ReceiptMismatch { reason: String },
    #[error("Airtable native environment is blocked: missing {variable}")]
    BlockedEnv { variable: String },
    #[error("Airtable serialization failed: {0}")]
    Serialization(String),
    #[error("Airtable provider error: {0}")]
    Provider(#[from] AirtableProviderError),
}

impl AirtableError {
    pub(crate) fn invalid(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidInput {
            field: field.into(),
            reason: reason.into(),
        }
    }

    /// Returns the retry classification when the error came from a provider.
    pub const fn retry_classification(&self) -> RetryClassification {
        match self {
            Self::Provider(error) => error.retry_classification(),
            _ => RetryClassification::DoNotRetry,
        }
    }

    pub fn is_blocked_env(&self) -> bool {
        matches!(
            self,
            Self::BlockedEnv { .. } | Self::Provider(AirtableProviderError::BlockedEnv { .. })
        )
    }
}

/// Provider failures are deliberately classified without retaining a PAT or
/// response body.  A caller can use the classification to schedule a later
/// retry, but Layer 1 never performs the retry or external write.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum AirtableProviderError {
    #[error("blocked environment: {variable}")]
    BlockedEnv { variable: String },
    #[error("Airtable HTTP {status}: {message}")]
    Http {
        status: u16,
        message: String,
        retry_after_seconds: Option<u64>,
    },
    #[error("Airtable authentication rejected with HTTP {status}")]
    Authentication { status: u16 },
    #[error("Airtable permission rejected with HTTP {status}")]
    PermissionDenied { status: u16 },
    #[error("Airtable resource not found with HTTP {status}")]
    NotFound { status: u16 },
    #[error("Airtable request is invalid: {message}")]
    InvalidRequest { message: String },
    #[error("Airtable transport failed: {message}")]
    Transport { message: String },
    #[error("Airtable schema drift: {message}")]
    SchemaDrift { message: String },
    #[error("Airtable provider scope mismatch")]
    ScopeMismatch,
}

impl AirtableProviderError {
    pub const DEFAULT_RATE_LIMIT_RETRY_AFTER_SECONDS: u64 = 30;

    pub fn from_http(
        status: u16,
        message: impl Into<String>,
        retry_after_seconds: Option<u64>,
    ) -> Self {
        let message = message.into();
        match status {
            401 => Self::Authentication { status },
            403 => Self::PermissionDenied { status },
            404 => Self::NotFound { status },
            429 => Self::Http {
                status,
                message,
                retry_after_seconds: Some(
                    retry_after_seconds.unwrap_or(Self::DEFAULT_RATE_LIMIT_RETRY_AFTER_SECONDS),
                ),
            },
            _ => Self::Http {
                status,
                message,
                retry_after_seconds,
            },
        }
    }

    pub const fn retry_classification(&self) -> RetryClassification {
        match self {
            Self::Http { status: 429, .. } => RetryClassification::RetryAfter,
            Self::Http { status, .. } if *status >= 500 => RetryClassification::RetryWithBackoff,
            Self::Transport { .. } => RetryClassification::RetryWithBackoff,
            _ => RetryClassification::DoNotRetry,
        }
    }

    pub const fn http_status(&self) -> Option<u16> {
        match self {
            Self::Http { status, .. }
            | Self::Authentication { status }
            | Self::PermissionDenied { status }
            | Self::NotFound { status } => Some(*status),
            _ => None,
        }
    }

    pub const fn retry_after_seconds(&self) -> Option<u64> {
        match self {
            Self::Http {
                retry_after_seconds,
                ..
            } => *retry_after_seconds,
            _ => None,
        }
    }
}

/// The action a future integration may take after a provider failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryClassification {
    RetryAfter,
    RetryWithBackoff,
    DoNotRetry,
}

/// A mismatch category that is safe to expose in a receipt or log.  It never
/// carries raw Airtable field values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadbackMismatchField {
    RecordId,
    Scope,
    FieldFingerprint,
    Revision,
    ContentDigest,
    ManifestDigest,
    IdempotencyKey,
    ProviderProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
#[error("{field:?}: expected {expected}, observed {observed}")]
pub struct ReadbackMismatch {
    pub field: ReadbackMismatchField,
    pub expected: String,
    pub observed: String,
}

impl ReadbackMismatch {
    pub(crate) fn new(
        field: ReadbackMismatchField,
        expected: impl Into<String>,
        observed: impl Into<String>,
    ) -> Self {
        Self {
            field,
            expected: expected.into(),
            observed: observed.into(),
        }
    }
}

/// The only provider provenance values that Layer 1 can truthfully emit.
/// `NativeHttps` remains a reserved value for a later layer and has no live
/// implementation in this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderTrust {
    pub provenance: AirtableProviderProvenance,
    pub connected: bool,
}

impl ProviderTrust {
    pub const fn for_provenance(provenance: AirtableProviderProvenance) -> Self {
        Self {
            provenance,
            connected: provenance.is_connected(),
        }
    }
}
