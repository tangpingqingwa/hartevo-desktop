use std::fmt::{Display, Formatter, Result as FmtResult};

use crate::model::InferenceField;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BedrockError {
    InvalidIdentifier {
        field: &'static str,
        reason: &'static str,
    },
    InvalidAccountId,
    InvalidRegion,
    InvalidModelTarget,
    InvalidRoutingPolicy,
    InvalidGuardrail,
    InvalidBudgetPolicy,
    InvalidInferenceConfig {
        field: InferenceField,
    },
    InvalidContentDigest,
    InvalidToolSchema,
    InvalidMissionRevision,
    InvalidCapabilitySnapshot,
    MaxTokensRequired,
    MaxTokensExceedsPolicy {
        requested: u32,
        maximum: u32,
    },
    MaxTokensExceedsCapability {
        requested: u32,
        maximum: u32,
    },
    UnsupportedFields(Vec<String>),
    LongLivedCredentialsRejected,
    SecretReferenceRejected,
    ContractVersionMismatch,
    ContractDigestMismatch,
    AdapterRevisionMismatch,
    CapabilityScopeMismatch,
    RegistrationAlreadyExists,
    RegistrationNotFound,
    RegistrationRevoked,
    RegistrationInactive,
    RegistrationStale,
    CannotRestoreRegistration,
    MissionScopeMismatch,
    ProviderModelMismatch,
    ProviderRoutingMismatch,
    ProviderGuardrailMismatch,
    InvalidProviderResponse,
    UsageMismatch,
    RequestDigestMismatch,
    ResultDigestMismatch,
    BlockedEnv,
    LiveTransportRejected,
    Transport {
        class: &'static str,
    },
}

impl Display for BedrockError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::InvalidIdentifier { field, reason } => {
                write!(formatter, "invalid {field}: {reason}")
            }
            Self::InvalidAccountId => {
                formatter.write_str("AWS account id must be exactly 12 digits")
            }
            Self::InvalidRegion => formatter.write_str("invalid AWS region"),
            Self::InvalidModelTarget => {
                formatter.write_str("invalid Bedrock model or inference-profile target")
            }
            Self::InvalidRoutingPolicy => formatter.write_str("invalid routing geography policy"),
            Self::InvalidGuardrail => formatter.write_str("invalid guardrail binding"),
            Self::InvalidBudgetPolicy => formatter.write_str("invalid budget policy"),
            Self::InvalidInferenceConfig { field } => {
                write!(formatter, "invalid inference field {}", field.as_str())
            }
            Self::InvalidContentDigest => formatter.write_str("invalid content digest set"),
            Self::InvalidToolSchema => formatter.write_str("invalid tool-schema digest"),
            Self::InvalidMissionRevision => {
                formatter.write_str("mission revision must be positive")
            }
            Self::InvalidCapabilitySnapshot => {
                formatter.write_str("invalid model capability snapshot")
            }
            Self::MaxTokensRequired => formatter.write_str("maxTokens must be explicit"),
            Self::MaxTokensExceedsPolicy { requested, maximum } => {
                write!(
                    formatter,
                    "maxTokens {requested} exceeds policy maximum {maximum}"
                )
            }
            Self::MaxTokensExceedsCapability { requested, maximum } => {
                write!(
                    formatter,
                    "maxTokens {requested} exceeds capability maximum {maximum}"
                )
            }
            Self::UnsupportedFields(fields) => {
                write!(
                    formatter,
                    "unsupported inference fields: {}",
                    fields.join(",")
                )
            }
            Self::LongLivedCredentialsRejected => {
                formatter.write_str("long-lived IAM-user credentials are rejected")
            }
            Self::SecretReferenceRejected => {
                formatter.write_str("secret reference must name a temporary role session")
            }
            Self::ContractVersionMismatch => formatter.write_str("contract version mismatch"),
            Self::ContractDigestMismatch => formatter.write_str("contract digest mismatch"),
            Self::AdapterRevisionMismatch => formatter.write_str("adapter revision mismatch"),
            Self::CapabilityScopeMismatch => {
                formatter.write_str("capability snapshot is not bound to scope")
            }
            Self::RegistrationAlreadyExists => formatter.write_str("registration already exists"),
            Self::RegistrationNotFound => formatter.write_str("registration not found"),
            Self::RegistrationRevoked => formatter.write_str("registration is revoked"),
            Self::RegistrationInactive => formatter.write_str("registration is inactive"),
            Self::RegistrationStale => {
                formatter.write_str("registration or mission scope is stale")
            }
            Self::CannotRestoreRegistration => {
                formatter.write_str("registration cannot be restored")
            }
            Self::MissionScopeMismatch => formatter.write_str("Mission/Project scope mismatch"),
            Self::ProviderModelMismatch => formatter.write_str("provider model identity mismatch"),
            Self::ProviderRoutingMismatch => {
                formatter.write_str("provider routing geography mismatch")
            }
            Self::ProviderGuardrailMismatch => {
                formatter.write_str("provider guardrail projection mismatch")
            }
            Self::InvalidProviderResponse => formatter.write_str("invalid provider response"),
            Self::UsageMismatch => {
                formatter.write_str("provider usage total does not equal input plus output")
            }
            Self::RequestDigestMismatch => formatter.write_str("request digest mismatch"),
            Self::ResultDigestMismatch => formatter.write_str("result digest mismatch"),
            Self::BlockedEnv => {
                formatter.write_str("BLOCKED_ENV: live Bedrock is unavailable in Layer 1")
            }
            Self::LiveTransportRejected => {
                formatter.write_str("live transport is forbidden in Layer 1")
            }
            Self::Transport { class } => write!(formatter, "provider transport error: {class}"),
        }
    }
}

impl std::error::Error for BedrockError {}

pub type Result<T> = std::result::Result<T, BedrockError>;
