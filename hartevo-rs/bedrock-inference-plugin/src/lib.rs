//! Layer-1 Amazon Bedrock Runtime `Converse` capability seam.
//!
//! This crate is intentionally standalone and dependency-free. It compiles a
//! scoped, non-streaming Converse proposal from digests, accepts only
//! recording/fake/loopback/BLOCKED_ENV transports, and projects provider output
//! into untrusted Mission evidence. It never invokes Bedrock, executes tools,
//! retains raw content or credentials, or adopts an Outcome.

mod consumer;
mod digest;
mod error;
mod model;
mod provider;
mod registration;
mod service;

pub use consumer::MissionBedrockInferenceConsumer;
pub use digest::Digest;
pub use error::{BedrockError, Result};
pub use model::{
    AwsAccountId, AwsPartition, AwsRegion, BedrockScope, BudgetPolicy, ContentBlockKind,
    ContentDigests, ContentMessageDigest, ContentRole, DestinationEvidence, GuardrailBinding,
    GuardrailProjection, InferenceConfig, InferenceContentBlock, InferenceField, InferenceRequest,
    InferenceResultProposal, InvocationProposal, InvocationReceipt, Layer1Provenance,
    MissionContext, MissionId, ModelCapabilitySnapshot, ModelTarget, ModelTargetKind, ProjectId,
    RegistrationId, ResultDisposition, RoutingGeography, RoutingPolicy, SecretReference,
    ServiceTier, StopReason, TokenUsage, ToolSchemaDigest, UntrustedToolUseProposal, UsageReceipt,
    VerificationFailure, VerificationReport,
};
pub use provider::{
    BedrockConverseProvider, BlockedEnvTransport, ConverseTransport, FakeTransport,
    LoopbackTransport, ProviderContentBlock, ProviderResponse, RecordingTransport,
    SigV4ConverseTransport, TransportErrorClass,
};
pub use registration::{
    RegistrationRecord, RegistrationRegistry, RegistrationSpec, RegistrationState,
    RegistrationStatus, RevocationReason,
};
pub use service::BedrockInferenceService;

pub const BEDROCK_INFERENCE_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/bedrock-inference/contract.v1.json");
pub const BEDROCK_INFERENCE_CONTRACT_VERSION: &str = "bedrock-inference/v1";
pub const BEDROCK_INFERENCE_PLUGIN_VERSION: &str = "bedrock-inference-plugin/v1";
pub const BEDROCK_RUNTIME_SERVICE: &str = "bedrock-runtime";
pub const BEDROCK_CONVERSE_OPERATION: &str = "Converse";
pub const BEDROCK_INFERENCE_LAYER: u8 = 1;

/// The checked-in contract is hashed at the registration boundary. The raw
/// document is a public contract, not an invocation payload or receipt field.
pub fn bedrock_inference_contract_digest() -> Digest {
    Digest::of_str(BEDROCK_INFERENCE_CONTRACT_JSON)
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_is_layer_one_converse_only() {
        assert_eq!(BEDROCK_INFERENCE_LAYER, 1);
        assert_eq!(BEDROCK_RUNTIME_SERVICE, "bedrock-runtime");
        assert_eq!(BEDROCK_CONVERSE_OPERATION, "Converse");
        assert!(BEDROCK_INFERENCE_CONTRACT_JSON.contains("proposal_recording_only"));
        assert!(bedrock_inference_contract_digest().as_hex().len() == 64);
    }
}
