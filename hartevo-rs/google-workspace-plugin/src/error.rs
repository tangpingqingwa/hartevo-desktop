use thiserror::Error;

/// Errors emitted by the typed Layer 1 service and its provider.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum GoogleWorkspaceError {
    #[error("invalid {field}: {reason}")]
    InvalidInput { field: &'static str, reason: String },
    #[error("BLOCKED_ENV: missing {variable}")]
    BlockedEnv { variable: &'static str },
    #[error("OAuth probe rejected by Google: HTTP {status} ({reason})")]
    OAuthRejected { status: u16, reason: String },
    #[error("OAuth token is expired")]
    OAuthTokenExpired,
    #[error("OAuth scope is missing: {scope}")]
    MissingOAuthScope { scope: String },
    #[error("Google Workspace authentication was rejected at {endpoint} (HTTP {status})")]
    AuthenticationRejected { endpoint: String, status: u16 },
    #[error("Google Workspace access was denied for {resource}")]
    AccessDenied { resource: String },
    #[error("Google Workspace resource was not found: {resource}")]
    NotFound { resource: String },
    #[error("Google Workspace corpus move detected for {resource}")]
    CorpusMoved { resource: String },
    #[error("Google Workspace change cursor expired for {corpus}")]
    ChangeCursorExpired { corpus: String },
    #[error("Google Workspace HTTP {status} from {endpoint}: {body}")]
    Http {
        endpoint: String,
        status: u16,
        body: String,
    },
    #[error("Google Workspace transport failed at {endpoint}: {message}")]
    Transport { endpoint: String, message: String },
    #[error("invalid Google Workspace response from {endpoint}: {message}")]
    InvalidResponse { endpoint: String, message: String },
    #[error("Google Workspace response from {endpoint} exceeded {limit} bytes")]
    ResponseTooLarge { endpoint: String, limit: usize },
    #[error("revision conflict: expected provider revision {expected}, actual {actual}")]
    RevisionConflict { expected: String, actual: String },
    #[error("Layer 1 is read-only; {operation} is reserved for Layer 2")]
    WriteNotAvailable { operation: &'static str },
    #[error("Google Workspace plugin registration is revoked")]
    PluginRevoked,
    #[error("Google Workspace plugin scope does not match the requested Mission scope")]
    ScopeMismatch,
    #[error("Google Workspace plugin registration revision overflowed")]
    RegistrationRevisionOverflow,
}
