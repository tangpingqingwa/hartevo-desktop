use thiserror::Error;

use crate::model::{Digest, ModelError};

pub type Result<T> = std::result::Result<T, RedisCloudDatabaseResultError>;

/// Transport failures contain only operation names and digests, never provider bodies.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RedisCloudTransportError {
    #[error("BLOCKED_ENV: Redis Cloud native transport is disabled")]
    BlockedEnv,
    #[error("Redis Cloud request was invalid for {operation}")]
    BadRequest {
        operation: String,
        response_digest: Digest,
    },
    #[error("Redis Cloud credentials were not authorized for {operation}")]
    Unauthorized {
        operation: String,
        response_digest: Digest,
    },
    #[error("Redis Cloud access was forbidden for {operation}")]
    Forbidden {
        operation: String,
        response_digest: Digest,
    },
    #[error("Redis Cloud resource was not found for {operation}")]
    NotFound {
        operation: String,
        response_digest: Digest,
    },
    #[error("Redis Cloud request was rate limited for {operation}")]
    RateLimited {
        operation: String,
        response_digest: Digest,
    },
    #[error("Redis Cloud provider returned server status {status} for {operation}")]
    ServerError {
        operation: String,
        status: u16,
        response_digest: Digest,
    },
    #[error("Redis Cloud request timed out for {operation}")]
    Timeout {
        operation: String,
        request_digest: Digest,
    },
    #[error("Redis Cloud access was lost while reading {operation}")]
    AccessLost { operation: String },
    #[error("Redis Cloud returned partial posture evidence for {operation}")]
    Partial {
        operation: String,
        response_digest: Digest,
    },
    #[error("Redis Cloud response was truncated for {operation}")]
    Truncated {
        operation: String,
        response_digest: Digest,
    },
    #[error("Redis Cloud response contained unexpected pagination for {operation}")]
    Pagination {
        operation: String,
        response_digest: Digest,
    },
    #[error("Redis Cloud pagination cursor looped for {operation}")]
    PaginationLoop {
        operation: String,
        cursor_digest: Digest,
    },
    #[error("Redis Cloud provider state is unknown for {operation}")]
    ProviderUnknown {
        operation: String,
        response_digest: Digest,
    },
    #[error("Redis Cloud provider response was malformed for {operation}")]
    InvalidResponse {
        operation: String,
        response_digest: Digest,
    },
    #[error("Redis Cloud evidence was tampered with for {operation}")]
    Tampered {
        operation: String,
        response_digest: Digest,
    },
    #[error("Redis Cloud scope drifted for {operation}")]
    ScopeDrift { operation: String },
    #[error("Redis Cloud operation is not allowed by the Layer-1 contract: {operation}")]
    Unsupported { operation: String },
}

impl RedisCloudTransportError {
    #[must_use]
    pub fn http_status(&self) -> Option<u16> {
        match self {
            Self::BadRequest { .. } => Some(400),
            Self::Unauthorized { .. } => Some(401),
            Self::Forbidden { .. } => Some(403),
            Self::NotFound { .. } => Some(404),
            Self::RateLimited { .. } => Some(429),
            Self::ServerError { status, .. } => Some(*status),
            _ => None,
        }
    }

    #[must_use]
    pub fn operation(&self) -> Option<&str> {
        match self {
            Self::BlockedEnv => None,
            Self::BadRequest { operation, .. }
            | Self::Unauthorized { operation, .. }
            | Self::Forbidden { operation, .. }
            | Self::NotFound { operation, .. }
            | Self::RateLimited { operation, .. }
            | Self::ServerError { operation, .. }
            | Self::Timeout { operation, .. }
            | Self::AccessLost { operation }
            | Self::Partial { operation, .. }
            | Self::Truncated { operation, .. }
            | Self::Pagination { operation, .. }
            | Self::PaginationLoop { operation, .. }
            | Self::ProviderUnknown { operation, .. }
            | Self::InvalidResponse { operation, .. }
            | Self::Tampered { operation, .. }
            | Self::ScopeDrift { operation }
            | Self::Unsupported { operation } => Some(operation),
        }
    }

    #[must_use]
    pub fn response_digest(&self) -> Option<&Digest> {
        match self {
            Self::BadRequest {
                response_digest, ..
            }
            | Self::Unauthorized {
                response_digest, ..
            }
            | Self::Forbidden {
                response_digest, ..
            }
            | Self::NotFound {
                response_digest, ..
            }
            | Self::RateLimited {
                response_digest, ..
            }
            | Self::ServerError {
                response_digest, ..
            }
            | Self::Partial {
                response_digest, ..
            }
            | Self::Truncated {
                response_digest, ..
            }
            | Self::Pagination {
                response_digest, ..
            }
            | Self::ProviderUnknown {
                response_digest, ..
            }
            | Self::InvalidResponse {
                response_digest, ..
            }
            | Self::Tampered {
                response_digest, ..
            } => Some(response_digest),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized { .. } | Self::Forbidden { .. } | Self::AccessLost { .. }
        )
    }

    #[must_use]
    pub fn from_status(
        operation: impl Into<String>,
        status: u16,
        response: impl AsRef<[u8]>,
    ) -> Self {
        let operation = operation.into();
        let response_digest = Digest::from_bytes(response.as_ref());
        match status {
            400 => Self::BadRequest {
                operation,
                response_digest,
            },
            401 => Self::Unauthorized {
                operation,
                response_digest,
            },
            403 => Self::Forbidden {
                operation,
                response_digest,
            },
            404 => Self::NotFound {
                operation,
                response_digest,
            },
            429 => Self::RateLimited {
                operation,
                response_digest,
            },
            status if status >= 500 => Self::ServerError {
                operation,
                status,
                response_digest,
            },
            _ => Self::InvalidResponse {
                operation,
                response_digest,
            },
        }
    }

    #[must_use]
    pub const fn blocked() -> Self {
        Self::BlockedEnv
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RedisCloudDatabaseResultError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Transport(#[from] RedisCloudTransportError),
    #[error("Redis Cloud contract drifted or failed validation")]
    ContractDrift,
    #[error("Redis Cloud provider definition drifted")]
    ProviderDrift,
    #[error("Redis Cloud API revision drifted")]
    ApiDrift,
    #[error("Redis Cloud permission snapshot drifted")]
    PermissionDrift,
    #[error("Redis Cloud scope drifted")]
    ScopeDrift,
    #[error("Redis Cloud evidence binding drifted")]
    EvidenceDrift,
    #[error("Redis Cloud registration is invalid or tampered")]
    InvalidRegistration,
    #[error("Redis Cloud registration is not active")]
    RegistrationInactive,
    #[error("Redis Cloud registration is revoked")]
    RegistrationRevoked,
    #[error("Redis Cloud registration is reversed")]
    RegistrationReversed,
    #[error("Redis Cloud SecretReference is revoked")]
    SecretRevoked,
    #[error("Redis Cloud evidence is tampered or internally inconsistent")]
    TamperedEvidence,
    #[error("Redis Cloud evidence is partial")]
    PartialEvidence,
    #[error("Redis Cloud evidence is truncated")]
    TruncatedEvidence,
    #[error("Redis Cloud provider state is unknown")]
    ProviderUnknown,
    #[error("Redis Cloud evidence is stale")]
    StaleState,
    #[error("Redis Cloud pagination was rejected")]
    PaginationRejected,
    #[error("Redis Cloud pagination cursor drifted or looped")]
    CursorMismatch,
    #[error("Redis Cloud proposal replay conflicted with an existing recording")]
    ReplayConflict,
    #[error("Redis Cloud recording idempotency key is invalid")]
    InvalidIdempotencyKey,
    #[error("Redis Cloud proposal is invalid")]
    InvalidProposal,
    #[error("Redis Cloud operation is forbidden by the Layer-1 contract")]
    ForbiddenOperation,
}
