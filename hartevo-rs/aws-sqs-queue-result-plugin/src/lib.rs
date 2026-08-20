//! Standalone Layer-1 AWS SQS queue-health result boundary.
//!
//! This crate models only bounded queue/DLQ posture reads, digest fences,
//! reversible registration, and Mission-scoped review/recording. Recording,
//! fixture, loopback, and `BLOCKED_ENV` transports are always non-connected,
//! non-native, and non-first-party.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

use serde_json::Value;

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{MissionAwsSqsConsumer, MissionAwsSqsResult};
pub use error::{AwsSqsQueueError, AwsSqsQueueTransportError, Result};
pub use model::*;
pub use provider::{
    AwsSqsOperation, AwsSqsProvider, AwsSqsProviderDefinition, AwsSqsProviderError,
    AwsSqsTransport, BlockedEnvTransport, FixtureAwsSqsTransport, FixtureTransport,
    GetQueueAttributesRequest, GetQueueAttributesResponse, GetQueueUrlRequest, GetQueueUrlResponse,
    ListDeadLetterSourceQueuesRequest, ListDeadLetterSourceQueuesResponse, ListQueuesRequest,
    ListQueuesResponse, LoopbackAwsSqsTransport, LoopbackTransport, RecordedRequest,
    RecordingTransport,
};
pub use service::{
    AwsSqsQueueCapabilities, AwsSqsQueueEvidence, AwsSqsQueueProposal, AwsSqsQueueReadRequest,
    AwsSqsQueueRecord, AwsSqsQueueRegistration, AwsSqsQueueService, EvidenceDigests,
    FailureEvidence, QueueEvidenceState, QueueFailureClass, QueueHealthState, RegistrationStatus,
    RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-sqs-queue-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-SQS-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-sqs-queue-result/v1|layer=1|service=aws.sqs.queue-result.read|provider=aws.sqs.queue-result.recording|consumer=mission.aws-sqs-queue.consumer";
pub const CONTRACT_DIGEST: &str =
    "b2171ee7733d6b8b712d55c05c9654069cda6c5e68cc24ff90c3419de5f840a4";
pub const PLUGIN_ID: &str = "aws.sqs.queue-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.sqs.queue-result.read";
pub const PROVIDER_ID: &str = "aws.sqs.queue-result.recording";
pub const PROVIDER_API_REVISION: &str =
    "sqs-list-queues-get-queue-url-get-queue-attributes-list-dead-letter-source-queues-1";
pub const CONSUMER_ID: &str = "mission.aws-sqs-queue.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-sqs-queue-result/contract.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
pub const MAX_APPROXIMATE_COUNT: u64 = 1_000_000_000_000;
pub const MAX_COUNT_AGE_SECONDS: u64 = 300;
pub const LAYER1_PERMISSIONS: [&str; 5] = [
    "sqs:ListQueues",
    "sqs:GetQueueUrl",
    "sqs:GetQueueAttributes",
    "sqs:ListDeadLetterSourceQueues",
    "mission.scope",
];

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractError {
    InvalidJson(String),
    Shape(&'static str),
    Identity(&'static str),
}

/// Checked in-contract representation used by the standalone validation gate.
/// It is not an authority object and cannot enable additional provider calls.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsSqsQueueContract {
    value: Value,
}

impl AwsSqsQueueContract {
    pub fn baseline() -> std::result::Result<Self, ContractError> {
        let value = serde_json::from_str::<Value>(CONTRACT_JSON)
            .map_err(|error| ContractError::InvalidJson(error.to_string()))?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> std::result::Result<(), ContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(ContractError::Shape("contract is not an object"))?;
        for key in [
            "$schema",
            "$id",
            "title",
            "description",
            "schemaVersion",
            "contractVersion",
            "pluginId",
            "pluginVersion",
            "layer",
            "evidenceLevel",
            "digestInput",
            "contractDigest",
            "service",
            "provider",
            "consumer",
            "credentials",
            "scope",
            "registration",
            "pagination",
            "metadata",
            "evidence",
            "provenance",
            "authorityBoundary",
            "layer2Gaps",
            "honesty",
            "forbidden",
        ] {
            if !object.contains_key(key) {
                return Err(ContractError::Shape("required contract key missing"));
            }
        }
        if object.get("schemaVersion").and_then(Value::as_str) != Some(CONTRACT_SCHEMA)
            || object.get("contractVersion").and_then(Value::as_str) != Some(CONTRACT_VERSION)
            || object.get("pluginId").and_then(Value::as_str) != Some(PLUGIN_ID)
            || object.get("pluginVersion").and_then(Value::as_str) != Some(PLUGIN_VERSION)
            || object.get("layer") != Some(&Value::from(1))
            || object.get("evidenceLevel").and_then(Value::as_str) != Some(EVIDENCE_LEVEL)
            || object.get("digestInput").and_then(Value::as_str) != Some(CONTRACT_DIGEST_INPUT)
            || object.get("contractDigest").and_then(Value::as_str) != Some(CONTRACT_DIGEST)
            || contract_digest().as_str() != CONTRACT_DIGEST
        {
            return Err(ContractError::Identity("contract identity drifted"));
        }

        let service = object
            .get("service")
            .and_then(Value::as_object)
            .ok_or(ContractError::Shape("service is not an object"))?;
        if service.get("id").and_then(Value::as_str) != Some(SERVICE_ID)
            || service.get("type").and_then(Value::as_str) != Some("AwsSqsQueueService")
            || service.get("readOnly") != Some(&Value::Bool(true))
            || service.get("proposalOnly") != Some(&Value::Bool(true))
            || service.get("recordingOnly") != Some(&Value::Bool(true))
            || service.get("liveExecution") != Some(&Value::Bool(false))
            || service.get("externalWrites") != Some(&Value::Bool(false))
            || service.get("kernelAuthority") != Some(&Value::Bool(false))
        {
            return Err(ContractError::Identity("service identity drifted"));
        }
        let operations = service
            .get("operations")
            .and_then(Value::as_array)
            .ok_or(ContractError::Shape("service operations missing"))?;
        let expected_operations = [
            "describe_capabilities",
            "describe_scope",
            "register",
            "read_list_queues",
            "read_get_queue_url",
            "read_get_queue_attributes",
            "read_list_dead_letter_source_queues",
            "propose",
            "record",
            "verify",
            "revoke_registration",
            "reverse_registration",
            "restore_registration",
        ];
        if operations.len() != expected_operations.len()
            || operations
                .iter()
                .zip(expected_operations)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err(ContractError::Identity(
                "service operation allowlist drifted",
            ));
        }

        let provider = object
            .get("provider")
            .and_then(Value::as_object)
            .ok_or(ContractError::Shape("provider is not an object"))?;
        let provider_operations = provider
            .get("operations")
            .and_then(Value::as_array)
            .ok_or(ContractError::Shape("provider operations missing"))?;
        let expected_provider_operations = [
            "ListQueues",
            "GetQueueUrl",
            "GetQueueAttributes",
            "ListDeadLetterSourceQueues",
        ];
        if provider.get("id").and_then(Value::as_str) != Some(PROVIDER_ID)
            || provider.get("type").and_then(Value::as_str) != Some("AwsSqsProvider")
            || provider.get("apiRevision").and_then(Value::as_str) != Some(PROVIDER_API_REVISION)
            || provider_operations
                .iter()
                .zip(expected_provider_operations)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
            || provider_operations.len() != expected_provider_operations.len()
            || provider.get("connectedEvidence") != Some(&Value::Bool(false))
            || provider.get("nativeEvidence") != Some(&Value::Bool(false))
            || provider.get("providerReceipt") != Some(&Value::Bool(false))
        {
            return Err(ContractError::Identity("provider identity drifted"));
        }

        let consumer = object
            .get("consumer")
            .and_then(Value::as_object)
            .ok_or(ContractError::Shape("consumer is not an object"))?;
        if consumer.get("id").and_then(Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("type").and_then(Value::as_str) != Some("MissionAwsSqsConsumer")
            || consumer.get("adoptsOutcome") != Some(&Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&Value::Bool(false))
            || consumer.get("deliveryAuthority") != Some(&Value::Bool(false))
        {
            return Err(ContractError::Identity("consumer identity drifted"));
        }

        let scope = object
            .get("scope")
            .and_then(Value::as_object)
            .ok_or(ContractError::Shape("scope is not an object"))?;
        if scope.get("messageBodies") != Some(&Value::Bool(false))
            || scope.get("messageAttributes") != Some(&Value::Bool(false))
            || scope.get("rawQueueAttributes") != Some(&Value::Bool(false))
            || scope.get("rawRedrivePolicy") != Some(&Value::Bool(false))
        {
            return Err(ContractError::Identity("scope data boundary drifted"));
        }

        let honesty = object
            .get("honesty")
            .and_then(Value::as_object)
            .ok_or(ContractError::Shape("honesty is not an object"))?;
        for key in [
            "blockedEnvironmentIsNative",
            "fixtureIsNative",
            "recordingIsNative",
            "loopbackIsNative",
            "approximateCountsAreDeliveryProof",
            "queuePostureIsDeliveryProof",
            "queuePostureIsCertification",
        ] {
            if honesty.get(key) != Some(&Value::Bool(false)) {
                return Err(ContractError::Identity("honesty flag drifted"));
            }
        }

        let forbidden = object
            .get("forbidden")
            .and_then(Value::as_array)
            .ok_or(ContractError::Shape("forbidden operations missing"))?;
        for operation in [
            "SendMessage",
            "ReceiveMessage",
            "DeleteMessage",
            "PurgeQueue",
            "CreateQueue",
            "SetQueueAttributes",
            "read_message_body",
            "read_message_attributes",
            "claim_connected",
            "claim_native",
            "claim_delivery_proof",
            "adopt_kernel_outcome",
        ] {
            if !forbidden
                .iter()
                .any(|value| value.as_str() == Some(operation))
            {
                return Err(ContractError::Identity("forbidden operation missing"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod contract_tests {
    use super::{AwsSqsQueueContract, CONTRACT_DIGEST, CONTRACT_JSON, contract_digest};

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        AwsSqsQueueContract::baseline().expect("checked AWS SQS contract");
        let json: serde_json::Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(json["contractDigest"], CONTRACT_DIGEST);
        assert_eq!(contract_digest().as_str(), CONTRACT_DIGEST);
    }
}
