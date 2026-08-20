use thiserror::Error;

use crate::model::{ModelError, PermissionAction};

pub type Result<T> = std::result::Result<T, AwsIotDeviceDefenderError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsIotDeviceDefenderTransportError {
    #[error("BLOCKED_ENV")]
    BlockedEnv,
    #[error("bad request")]
    BadRequest,
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("server failure")]
    ServerFailure { status_code: Option<u16> },
    #[error("timeout")]
    Timeout,
    #[error("access was lost")]
    AccessLost,
    #[error("partial provider response")]
    Partial,
    #[error("malformed provider response")]
    MalformedResponse,
}

impl AwsIotDeviceDefenderTransportError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::RateLimited { .. } => Some(429),
            Self::ServerFailure { status_code } => *status_code,
            Self::BlockedEnv
            | Self::Timeout
            | Self::AccessLost
            | Self::Partial
            | Self::MalformedResponse => None,
        }
    }

    pub const fn category(&self) -> &'static str {
        match self {
            Self::BlockedEnv => "blocked_env",
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::RateLimited { .. } => "throttled",
            Self::ServerFailure { .. } => "server_failure",
            Self::Timeout => "timeout",
            Self::AccessLost => "access_loss",
            Self::Partial => "partial",
            Self::MalformedResponse => "malformed_response",
        }
    }

    pub fn operation_permission(operation: &str) -> Option<PermissionAction> {
        match operation {
            "ListAuditTasks" => Some(PermissionAction::ListAuditTasks),
            "DescribeAuditTask" => Some(PermissionAction::DescribeAuditTask),
            "ListAuditFindings" => Some(PermissionAction::ListAuditFindings),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsIotDeviceDefenderError {
    #[error("model error: {0}")]
    Model(#[from] ModelError),
    #[error("provider definition error: {0}")]
    ProviderDefinition(String),
    #[error("provider transport error: {0}")]
    Transport(#[from] AwsIotDeviceDefenderTransportError),
    #[error("provider page binding or digest is invalid")]
    PageBinding,
    #[error("provider API revision is incompatible")]
    ProviderRevision,
    #[error("required permission is missing: {0:?}")]
    PermissionMissing(PermissionAction),
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("opaque SecretReference is revoked")]
    SecretReferenceRevoked,
    #[error("registration, scope, provider, permission, or contract digest does not match")]
    RegistrationMismatch,
    #[error("consent is invalid or expired")]
    ConsentInvalid,
    #[error("proposal is tampered or stale")]
    ProposalTampered,
    #[error("evidence is tampered or stale")]
    EvidenceTampered,
    #[error("recording key is empty or replay conflicts with an existing record")]
    ReplayConflict,
}
