use thiserror::Error;

use crate::model::ModelError;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwsDynamoDbTransportError {
    #[error("DynamoDB provider rejected a bad request")]
    BadRequest,
    #[error("DynamoDB provider authentication failed")]
    Unauthorized,
    #[error("DynamoDB provider denied access")]
    Forbidden,
    #[error("DynamoDB table was not found")]
    NotFound,
    #[error("DynamoDB provider throttled the request")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("DynamoDB provider returned a server error")]
    ServerError { status_code: u16 },
    #[error("DynamoDB provider request timed out")]
    Timeout,
    #[error("DynamoDB provider returned partial evidence")]
    Partial,
    #[error("DynamoDB provider access was lost")]
    AccessLost,
    #[error("DynamoDB provider is blocked by the environment")]
    BlockedEnv,
    #[error("DynamoDB provider returned a conflicting revision")]
    Conflict,
    #[error("DynamoDB provider response was malformed or tampered")]
    InvalidResponse,
}

impl AwsDynamoDbTransportError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::RateLimited { .. } => Some(429),
            Self::ServerError { status_code } => Some(*status_code),
            Self::Timeout
            | Self::Partial
            | Self::AccessLost
            | Self::BlockedEnv
            | Self::Conflict
            | Self::InvalidResponse => None,
        }
    }

    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::AccessLost
        )
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwsDynamoDbTableError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Transport(#[from] AwsDynamoDbTransportError),
    #[error("AWS DynamoDB contract is invalid: {0}")]
    Contract(&'static str),
    #[error("AWS DynamoDB provider definition drifted")]
    ProviderDrift,
    #[error("AWS DynamoDB registration is invalid")]
    InvalidRegistration,
    #[error("AWS DynamoDB registration is inactive")]
    RegistrationInactive,
    #[error("AWS DynamoDB registration is revoked")]
    RegistrationRevoked,
    #[error("AWS DynamoDB registration is reversed")]
    RegistrationReversed,
    #[error("AWS DynamoDB registration transition is invalid")]
    InvalidRegistrationTransition,
    #[error("AWS DynamoDB registration or evidence scope does not match")]
    ScopeMismatch,
    #[error("AWS DynamoDB permission fence does not match")]
    PermissionMismatch,
    #[error("AWS DynamoDB consent fence does not match")]
    ConsentMismatch,
    #[error("AWS DynamoDB opaque SigV4 SecretReference is invalid or revoked")]
    InvalidSecretReference,
    #[error("AWS DynamoDB evidence is tampered")]
    TamperedEvidence,
    #[error("AWS DynamoDB proposal is tampered or stale")]
    TamperedProposal,
    #[error("AWS DynamoDB record is tampered or stale")]
    TamperedRecord,
    #[error("AWS DynamoDB recording key conflicts with an existing record")]
    RecordingConflict,
    #[error("AWS DynamoDB replay is invalid")]
    ReplayConflict,
    #[error("AWS DynamoDB pagination cursor loop detected")]
    PaginationLoop,
    #[error("AWS DynamoDB pagination is incomplete")]
    PartialEvidence,
    #[error("AWS DynamoDB table was replaced during the read")]
    TableReplaced,
    #[error("AWS DynamoDB table schema drifted during the read")]
    SchemaDrift,
    #[error("AWS DynamoDB table index drifted during the read")]
    IndexDrift,
    #[error("AWS DynamoDB table metadata is stale or crosses an eventual-consistency fence")]
    StaleMetadata,
    #[error("AWS DynamoDB table is not in the explicit allowlist")]
    TableNotAllowlisted,
    #[error("AWS DynamoDB response exceeds the bounded response budget")]
    ResponseTooLarge,
    #[error("AWS DynamoDB response page binding is invalid")]
    PageBinding,
}

pub type Result<T> = std::result::Result<T, AwsDynamoDbTableError>;
