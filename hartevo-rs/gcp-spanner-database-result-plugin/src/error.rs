use thiserror::Error;

use crate::model::{Digest, ModelError};

pub type Result<T> = std::result::Result<T, GcpSpannerError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GcpSpannerTransportError {
    #[error("Spanner management request returned HTTP {status_code} for {operation}")]
    HttpStatus {
        operation: String,
        status_code: u16,
        response_digest: Digest,
        response_bytes: u64,
    },
    #[error("Spanner management request timed out for {operation}")]
    Timeout {
        operation: String,
        request_digest: Digest,
    },
    #[error("Spanner management response was malformed for {operation}")]
    MalformedResponse {
        operation: String,
        response_digest: Digest,
        response_bytes: u64,
    },
    #[error("Spanner provider is unknown for {operation}")]
    ProviderUnknown {
        operation: String,
        response_digest: Digest,
    },
    #[error("Spanner transport failed for {operation}")]
    Transport {
        operation: String,
        error_digest: Digest,
    },
    #[error("Spanner operation is not available in this Layer-1 transport: {operation}")]
    Unsupported { operation: String },
}

impl GcpSpannerTransportError {
    #[must_use]
    pub fn http_status(
        operation: impl Into<String>,
        status_code: u16,
        response_body: impl AsRef<[u8]>,
    ) -> Self {
        Self::HttpStatus {
            operation: operation.into(),
            status_code,
            response_digest: Digest::from_bytes(response_body.as_ref()),
            response_bytes: response_body.as_ref().len() as u64,
        }
    }

    #[must_use]
    pub fn unauthorized(operation: impl Into<String>) -> Self {
        Self::http_status(operation, 401, b"unauthorized")
    }

    #[must_use]
    pub fn forbidden(operation: impl Into<String>) -> Self {
        Self::http_status(operation, 403, b"forbidden")
    }

    #[must_use]
    pub fn not_found(operation: impl Into<String>) -> Self {
        Self::http_status(operation, 404, b"not-found")
    }

    #[must_use]
    pub fn conflict(operation: impl Into<String>) -> Self {
        Self::http_status(operation, 409, b"conflict")
    }

    #[must_use]
    pub fn rate_limited(operation: impl Into<String>) -> Self {
        Self::http_status(operation, 429, b"rate-limited")
    }

    #[must_use]
    pub fn server_error(operation: impl Into<String>, status_code: u16) -> Self {
        Self::http_status(operation, status_code, b"server-error")
    }

    #[must_use]
    pub fn timeout(operation: impl Into<String>, request_digest: Digest) -> Self {
        Self::Timeout {
            operation: operation.into(),
            request_digest,
        }
    }

    #[must_use]
    pub fn malformed(operation: impl Into<String>, response_body: impl AsRef<[u8]>) -> Self {
        Self::MalformedResponse {
            operation: operation.into(),
            response_digest: Digest::from_bytes(response_body.as_ref()),
            response_bytes: response_body.as_ref().len() as u64,
        }
    }

    #[must_use]
    pub fn provider_unknown(operation: impl Into<String>, response_body: impl AsRef<[u8]>) -> Self {
        Self::ProviderUnknown {
            operation: operation.into(),
            response_digest: Digest::from_bytes(response_body.as_ref()),
        }
    }

    #[must_use]
    pub fn transport(operation: impl Into<String>, error: impl AsRef<[u8]>) -> Self {
        Self::Transport {
            operation: operation.into(),
            error_digest: Digest::from_bytes(error.as_ref()),
        }
    }

    #[must_use]
    pub fn operation(&self) -> &str {
        match self {
            Self::HttpStatus { operation, .. }
            | Self::Timeout { operation, .. }
            | Self::MalformedResponse { operation, .. }
            | Self::ProviderUnknown { operation, .. }
            | Self::Transport { operation, .. }
            | Self::Unsupported { operation } => operation,
        }
    }

    #[must_use]
    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::HttpStatus { status_code, .. } => Some(*status_code),
            Self::Timeout { .. }
            | Self::MalformedResponse { .. }
            | Self::ProviderUnknown { .. }
            | Self::Transport { .. }
            | Self::Unsupported { .. } => None,
        }
    }

    #[must_use]
    pub fn response_digest(&self) -> Option<&Digest> {
        match self {
            Self::HttpStatus {
                response_digest, ..
            }
            | Self::MalformedResponse {
                response_digest, ..
            }
            | Self::ProviderUnknown {
                response_digest, ..
            } => Some(response_digest),
            Self::Timeout { .. } | Self::Transport { .. } | Self::Unsupported { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum GcpSpannerError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Transport(#[from] GcpSpannerTransportError),
    #[error("Spanner contract drifted or failed validation")]
    ContractDrift,
    #[error("Spanner provider definition drifted")]
    ProviderDrift,
    #[error("Spanner permission snapshot drifted")]
    PermissionDrift,
    #[error("Spanner scope drifted")]
    ScopeDrift,
    #[error("Spanner registration is invalid")]
    InvalidRegistration,
    #[error("Spanner registration is inactive")]
    RegistrationInactive,
    #[error("Spanner registration is revoked or reversed")]
    RegistrationRevoked,
    #[error("Spanner evidence is tampered or internally inconsistent")]
    EvidenceTampered,
    #[error("Spanner proposal is invalid")]
    InvalidProposal,
    #[error("Spanner proposal replay was rejected")]
    ReplayDetected,
    #[error("Spanner recording idempotency conflict")]
    ReplayConflict,
    #[error("Mission binding is stale")]
    StaleMission,
    #[error("Spanner pagination exceeded its Layer-1 bound")]
    PaginationExceeded,
    #[error("Spanner pagination cursor drifted or looped")]
    CursorMismatch,
    #[error("Spanner operation is not allowed by the Layer-1 contract")]
    ForbiddenOperation,
}
