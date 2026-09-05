//! Error types for the bounded AWS IoT SiteWise Layer-1 boundary.

use crate::provider::AwsIoTSiteWiseOperation;

pub type Result<T> = std::result::Result<T, AwsIoTSiteWiseMeasurementError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsIoTSiteWiseTransportError {
    AccessDenied(AwsIoTSiteWiseOperation),
    BlockedEnv(AwsIoTSiteWiseOperation),
    Malformed(AwsIoTSiteWiseOperation),
    MissingRecording(AwsIoTSiteWiseOperation),
    NotFound(AwsIoTSiteWiseOperation),
    ProviderUnknown(AwsIoTSiteWiseOperation),
    Throttled(AwsIoTSiteWiseOperation),
}

impl AwsIoTSiteWiseTransportError {
    pub const fn operation(&self) -> AwsIoTSiteWiseOperation {
        match self {
            Self::AccessDenied(operation)
            | Self::BlockedEnv(operation)
            | Self::Malformed(operation)
            | Self::MissingRecording(operation)
            | Self::NotFound(operation)
            | Self::ProviderUnknown(operation)
            | Self::Throttled(operation) => *operation,
        }
    }

    pub const fn category(&self) -> &'static str {
        match self {
            Self::AccessDenied(_) => "access_denied",
            Self::BlockedEnv(_) => "blocked_env",
            Self::Malformed(_) => "malformed",
            Self::MissingRecording(_) => "missing_recording",
            Self::NotFound(_) => "not_found",
            Self::ProviderUnknown(_) => "provider_unknown",
            Self::Throttled(_) => "throttled",
        }
    }

    pub const fn is_access_loss(&self) -> bool {
        matches!(self, Self::AccessDenied(_) | Self::NotFound(_))
    }
}

impl std::fmt::Display for AwsIoTSiteWiseTransportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}:{}",
            self.category(),
            self.operation().as_str()
        )
    }
}

impl std::error::Error for AwsIoTSiteWiseTransportError {}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AwsIoTSiteWiseMeasurementError {
    #[error("invalid identifier: {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid digest")]
    InvalidDigest,
    #[error("invalid measurement scope")]
    InvalidScope,
    #[error("invalid measurement bounds")]
    InvalidBounds,
    #[error("invalid request")]
    InvalidRequest,
    #[error("cursor does not match its request fence")]
    CursorMismatch,
    #[error("request filter does not match its scope fence")]
    FilterMismatch,
    #[error("provider response does not match the exact scope")]
    ScopeMismatch,
    #[error("provider response exceeded the bounded response size")]
    ResponseTooLarge,
    #[error("provider response exceeded the bounded point count")]
    PointLimitExceeded,
    #[error("provider history ordering violated the ascending fence")]
    OrderingViolation,
    #[error("provider response violated the time-window or quality fence")]
    MeasurementFenceViolation,
    #[error("provider evidence digest or provenance was tampered")]
    TamperedEvidence,
    #[error("registration is inactive")]
    RegistrationInactive,
    #[error("registration is permanently reversed")]
    RegistrationReversed,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("consent does not cover the permission snapshot")]
    InvalidConsent,
    #[error("provider identity drifted")]
    ProviderDrift,
    #[error("provider recording key conflicted with an existing proposal")]
    RecordingConflict,
    #[error("required provider evidence is missing")]
    MissingEvidence,
    #[error("transport error: {0}")]
    Transport(#[source] AwsIoTSiteWiseTransportError),
}

impl From<AwsIoTSiteWiseTransportError> for AwsIoTSiteWiseMeasurementError {
    fn from(error: AwsIoTSiteWiseTransportError) -> Self {
        Self::Transport(error)
    }
}
