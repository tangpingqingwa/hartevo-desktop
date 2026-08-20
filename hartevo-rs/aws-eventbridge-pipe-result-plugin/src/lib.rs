//! Standalone Layer-1 AWS EventBridge Pipes state-result boundary.
//!
//! The crate models only bounded `ListPipes`/`DescribePipe` metadata, digest
//! fences, reversible registration, and Mission-scoped review/recording. It
//! deliberately has no signer, credential resolver, HTTP client, event
//! payload type, lifecycle effect, durable provider receipt, or kernel
//! Outcome/Work Product authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::fn_params_excessive_bools,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::missing_fields_in_debug,
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

use thiserror::Error;

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionAwsEventBridgePipeConsumer, MissionAwsEventBridgePipeResult, ProposalDisposition,
    RecordedAwsEventBridgePipeResult,
};
pub use error::{
    AwsEventBridgePipeError, AwsEventBridgePipeTransportError, ErrorClassification, Result,
};
pub use model::*;
pub use provider::{
    AwsEventBridgePipeProvider, AwsEventBridgePipeProviderDefinition,
    AwsEventBridgePipeProviderError, AwsEventBridgePipeTransport, BlockedEnvTransport,
    DescribePipeRequest, DescribePipeResponse, FixtureTransport, ListPipesRequest,
    ListPipesResponse, LoopbackTransport, PipeOperation, RecordedRequest, RecordingTransport,
};
pub use service::{
    AwsEventBridgePipeCapabilities, AwsEventBridgePipeEvidence, AwsEventBridgePipeProposal,
    AwsEventBridgePipeReadRequest, AwsEventBridgePipeRecord, AwsEventBridgePipeRegistration,
    AwsEventBridgePipeService, FailureEvidence, RegistrationStatus, RegistrationTransitionEvidence,
    VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-eventbridge-pipe-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-EVENTBRIDGE-PIPES-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-eventbridge-pipe-result/v1|layer=1|service=aws.eventbridge.pipe-result.read|provider=aws.eventbridge.pipe-result.recording|consumer=mission.aws-eventbridge-pipe.consumer";
pub const CONTRACT_DIGEST: &str =
    "75b91d2fd591bb88b3814dfec42b9badba5890af7970ad5793ed122464c9e008";
pub const PLUGIN_ID: &str = "aws.eventbridge.pipe-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.eventbridge.pipe-result.read";
pub const PROVIDER_ID: &str = "aws.eventbridge.pipe-result.recording";
pub const PROVIDER_API_REVISION: &str = "eventbridge-pipes-list-describe-1";
pub const CONSUMER_ID: &str = "mission.aws-eventbridge-pipe.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-eventbridge-pipe-result/contract.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_ARN_BYTES: usize = 2_048;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_REQUESTS_PER_READ: u16 = MAX_PAGES + 1;

pub const LAYER1_PERMISSIONS: [&str; 3] =
    ["pipes:ListPipes", "pipes:DescribePipe", "mission.scope"];

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContractError {
    #[error("contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("contract identity is invalid: {0}")]
    Identity(&'static str),
}

/// Checked in-contract representation used by the standalone validation
/// gate. The public value is retained as JSON only; it is not an authority
/// object and does not enable additional provider operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsEventBridgePipeContract {
    value: serde_json::Value,
}

impl AwsEventBridgePipeContract {
    pub fn baseline() -> std::result::Result<Self, ContractError> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|error| ContractError::InvalidJson(error.to_string()))?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    pub fn value(&self) -> &serde_json::Value {
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
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(CONTRACT_SCHEMA)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_VERSION)
            || object.get("pluginId").and_then(serde_json::Value::as_str) != Some(PLUGIN_ID)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(PLUGIN_VERSION)
            || object.get("layer") != Some(&serde_json::Value::from(1))
            || object
                .get("evidenceLevel")
                .and_then(serde_json::Value::as_str)
                != Some(EVIDENCE_LEVEL)
            || object
                .get("digestInput")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST_INPUT)
            || object
                .get("contractDigest")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST)
            || contract_digest().as_str() != CONTRACT_DIGEST
        {
            return Err(ContractError::Identity("contract identity drifted"));
        }

        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("service is not an object"))?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("type").and_then(serde_json::Value::as_str)
                != Some("AwsEventBridgePipeService")
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("recordingOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractError::Identity("service identity drifted"));
        }
        let operations = service
            .get("operations")
            .and_then(serde_json::Value::as_array)
            .ok_or(ContractError::Shape("service operations missing"))?;
        if operations.len() != 11
            || operations[3].as_str() != Some("read_list_pipes")
            || operations[4].as_str() != Some("read_describe_pipe")
            || operations[5].as_str() != Some("propose")
            || operations[6].as_str() != Some("record")
        {
            return Err(ContractError::Identity(
                "service operation allowlist drifted",
            ));
        }

        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("provider is not an object"))?;
        let provider_operations = provider
            .get("operations")
            .and_then(serde_json::Value::as_array)
            .ok_or(ContractError::Shape("provider operations missing"))?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider.get("type").and_then(serde_json::Value::as_str)
                != Some("AwsEventBridgePipeProvider")
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(PROVIDER_API_REVISION)
            || provider_operations
                != &[
                    serde_json::Value::String("ListPipes".to_owned()),
                    serde_json::Value::String("DescribePipe".to_owned()),
                ]
            || provider.get("connectedEvidence") != Some(&serde_json::Value::Bool(false))
            || provider.get("nativeEvidence") != Some(&serde_json::Value::Bool(false))
            || provider.get("providerReceipt") != Some(&serde_json::Value::Bool(false))
            || provider.get("eventPayloads") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractError::Identity("provider identity drifted"));
        }

        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("consumer is not an object"))?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("type").and_then(serde_json::Value::as_str)
                != Some("MissionAwsEventBridgePipeConsumer")
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractError::Identity("consumer identity drifted"));
        }

        let forbidden = object
            .get("forbidden")
            .and_then(serde_json::Value::as_array)
            .ok_or(ContractError::Shape("forbidden operations missing"))?;
        for operation in [
            "CreatePipe",
            "UpdatePipe",
            "DeletePipe",
            "StartPipe",
            "StopPipe",
            "read_event_payload",
            "claim_connected",
            "claim_native",
            "adopt_kernel_outcome",
        ] {
            if !forbidden
                .iter()
                .any(|value| value.as_str() == Some(operation))
            {
                return Err(ContractError::Identity("forbidden operation missing"));
            }
        }

        let honesty = object
            .get("honesty")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("honesty is not an object"))?;
        for key in [
            "blockedEnvironmentIsNative",
            "fixtureIsNative",
            "recordingIsNative",
            "loopbackIsNative",
            "stateObservationIsDeliveryProof",
            "stateObservationIsCertification",
        ] {
            if honesty.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(ContractError::Identity("honesty flag drifted"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod contract_tests {
    use super::{AwsEventBridgePipeContract, CONTRACT_DIGEST, CONTRACT_JSON, contract_digest};

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        AwsEventBridgePipeContract::baseline().expect("checked EventBridge Pipes contract");
        let json: serde_json::Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(json["contractDigest"], CONTRACT_DIGEST);
        assert_eq!(contract_digest().as_str(), CONTRACT_DIGEST);
    }
}
