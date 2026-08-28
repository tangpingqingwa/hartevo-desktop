use thiserror::Error;

/// Errors crossing the provider seam.  Bodies, tokens, keys, SQL, and PII
/// are intentionally absent from this type.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SupabaseProviderError {
    #[error("HTTP unauthorized (401)")]
    Unauthorized,
    #[error("HTTP forbidden (403)")]
    Forbidden,
    #[error("HTTP not found (404)")]
    NotFound,
    #[error("HTTP conflict (409)")]
    Conflict,
    #[error("HTTP rate limited (429)")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("HTTP server failure ({status})")]
    ServerFailure { status: u16 },
    #[error("provider request timed out")]
    Timeout,
    #[error("provider environment is blocked")]
    BlockedEnv,
    #[error("provider returned an unknown failure: {code}")]
    ProviderUnknown { code: String },
    #[error("provider response was invalid: {field}")]
    InvalidResponse { field: String },
    #[error("provider response failed integrity validation")]
    TamperedResponse,
    #[error("provider response crossed the requested scope")]
    ScopeMismatch,
    #[error("service-role authority is not accepted by this Layer-1 boundary")]
    ServiceRoleRejected,
}

impl SupabaseProviderError {
    pub fn from_http_status(status: u16) -> Self {
        match status {
            401 => Self::Unauthorized,
            403 => Self::Forbidden,
            404 => Self::NotFound,
            409 => Self::Conflict,
            429 => Self::RateLimited {
                retry_after_seconds: None,
            },
            500..=599 => Self::ServerFailure { status },
            other => Self::ProviderUnknown {
                code: format!("http-{other}"),
            },
        }
    }

    pub const fn http_status(&self) -> Option<u16> {
        match self {
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::ServerFailure { status } => Some(*status),
            Self::Timeout
            | Self::BlockedEnv
            | Self::ProviderUnknown { .. }
            | Self::InvalidResponse { .. }
            | Self::TamperedResponse
            | Self::ScopeMismatch
            | Self::ServiceRoleRejected => None,
        }
    }
}

/// Errors in the typed Layer-1 service boundary.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SupabaseIdentityError {
    #[error("invalid model: {0}")]
    InvalidModel(String),
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
    #[error("contract or provider registration drifted")]
    ContractDrift,
    #[error("permission digest drifted")]
    PermissionDrift,
    #[error("registration is not active")]
    RegistrationInactive,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration scope or digest fence failed")]
    RegistrationDrift,
    #[error("mission scope does not match the registered Supabase scope")]
    MissionScopeMismatch,
    #[error("service-role authority is rejected at the Mission boundary")]
    ServiceRoleAuthorityRejected,
    #[error("provider error: {0}")]
    Provider(#[from] SupabaseProviderError),
    #[error("provider response exceeded the configured Layer-1 bound")]
    BoundsExceeded,
    #[error("provider response was tampered")]
    TamperedEvidence,
    #[error("JWT audience does not match the exact Mission scope")]
    JwtAudienceMismatch,
    #[error("JWT issuer does not match the exact Supabase project")]
    JwtIssuerMismatch,
    #[error("JWT is expired or not yet valid")]
    JwtExpired,
    #[error("JWT signature evidence is not verified")]
    JwtNotVerified,
    #[error("identity role is outside the allowed role fence")]
    RoleMismatch,
    #[error("identity tenant is outside the allowed tenant fence")]
    TenantMismatch,
    #[error("identity project or region is outside the registered fence")]
    ProjectMismatch,
    #[error("grant and RLS policy evidence is inconsistent")]
    GrantPolicyMismatch,
    #[error("requested evidence is not present")]
    EvidenceNotPresent,
    #[error("policy proposal is not bound to the supplied evidence")]
    ProposalEvidenceMismatch,
}
