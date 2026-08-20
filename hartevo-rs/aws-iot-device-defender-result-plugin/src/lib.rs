//! Standalone Layer-1 AWS IoT Device Defender audit-result boundary.
//!
//! This crate models only bounded read proposals, redacted evidence,
//! recording, verification, and reversible registration. Fixture, recording,
//! loopback, and `BLOCKED_ENV` transports can never claim native, connected,
//! or first-party evidence.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::result_large_err,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::type_complexity,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConsumerError, MissionAwsIotDeviceDefenderConsumer, MissionAwsIotDeviceDefenderDecisionState,
    MissionAwsIotDeviceDefenderResult, RecordedAwsIotDeviceDefenderResult,
};
pub use error::{AwsIotDeviceDefenderError, AwsIotDeviceDefenderTransportError, Result};
pub use model::*;
pub use provider::{
    AwsIotDeviceDefenderProvider, AwsIotDeviceDefenderProviderDefinition,
    AwsIotDeviceDefenderProviderError, AwsIotDeviceDefenderProviderIdentity,
    AwsIotDeviceDefenderTransport, BlockedEnvAwsIotDeviceDefenderTransport, BlockedEnvTransport,
    DescribeAuditTaskResponse, FakeAwsIotDeviceDefenderTransport,
    FixtureAwsIotDeviceDefenderTransport, FixtureTransport, ListAuditFindingsResponse,
    ListAuditTasksResponse, LoopbackAwsIotDeviceDefenderTransport, LoopbackTransport,
    ProviderProvenance, RecordedRequest, RecordingAwsIotDeviceDefenderTransport,
    RecordingTransport, TransportError,
};
pub use service::{
    AwsIotDeviceDefenderProposal, AwsIotDeviceDefenderReadRequest,
    AwsIotDeviceDefenderRecordReceipt, AwsIotDeviceDefenderRegistration,
    AwsIotDeviceDefenderService, RegistrationStatus, RegistrationTransitionEvidence,
    VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-iot-device-defender-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-IOT-DEFENDER-01-L1/v1";
pub const PLUGIN_ID: &str = "aws.iot.device-defender-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.iot.device-defender-result.read";
pub const PROVIDER_ID: &str = "aws.iot.device-defender-result.recording";
pub const PROVIDER_VERSION: &str = "1.0.0";
pub const API_REVISION: &str =
    "iot-device-defender-list-audit-tasks-describe-audit-task-list-audit-findings-1";
pub const CONSUMER_ID: &str = "mission.aws-iot-device-defender.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-iot-device-defender-result/v1|layer=1|service=aws.iot.device-defender-result.read|provider=aws.iot.device-defender-result.recording|consumer=mission.aws-iot-device-defender.consumer";
pub const CONTRACT_DIGEST: &str =
    "ac0e260cde1170423b05f5251b971764e3bdf154b9f6ac281ab4b31c3b9c552f";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-iot-device-defender-result/contract.v1.json");

pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_CHECKS: usize = 64;
pub const MAX_RESOURCES: usize = 128;
pub const MAX_FINDINGS: usize = 512;
pub const MAX_FINDINGS_PER_PAGE: usize = 128;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;

pub type AwsIotDeviceDefenderReadResult = AwsIotDeviceDefenderEvidence;

pub const LAYER1_PERMISSIONS: [&str; 4] = [
    "iot:ListAuditTasks",
    "iot:DescribeAuditTask",
    "iot:ListAuditFindings",
    "mission.scope",
];

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsIotDeviceDefenderContract {
    value: serde_json::Value,
}

impl AwsIotDeviceDefenderContract {
    pub fn baseline() -> std::result::Result<Self, ContractValidationError> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|error| ContractValidationError::InvalidJson(error.to_string()))?;
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

    pub fn validate(&self) -> std::result::Result<(), ContractValidationError> {
        let object = self
            .value
            .as_object()
            .ok_or(ContractValidationError::Shape("contract is not an object"))?;
        for key in [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "pluginId",
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
            "boundedReads",
            "evidence",
            "honesty",
            "forbidden",
            "layer2Gaps",
        ] {
            if !object.contains_key(key) {
                return Err(ContractValidationError::Shape(
                    "required contract key missing",
                ));
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
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(PLUGIN_VERSION)
            || object.get("pluginId").and_then(serde_json::Value::as_str) != Some(PLUGIN_ID)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
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
                != Some(contract_digest().as_str())
        {
            return Err(ContractValidationError::Identity(
                "contract identity drifted",
            ));
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractValidationError::Shape("service is not an object"))?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("type").and_then(serde_json::Value::as_str)
                != Some("AwsIotDeviceDefenderService")
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || service.get("kernelAuthority") != Some(&serde_json::Value::Bool(false))
            || service.get("outcomeAdoption") != Some(&serde_json::Value::Bool(false))
            || service.get("workProductAdoption") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractValidationError::Boundary(
                "service authority widened",
            ));
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractValidationError::Shape("provider is not an object"))?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider.get("type").and_then(serde_json::Value::as_str)
                != Some("AwsIotDeviceDefenderProvider")
            || provider.get("connectedEvidence") != Some(&serde_json::Value::Bool(false))
            || provider.get("nativeEvidence") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstPartyEvidence") != Some(&serde_json::Value::Bool(false))
            || provider.get("providerReceipt") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractValidationError::Boundary(
                "provider authority widened",
            ));
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractValidationError::Shape("consumer is not an object"))?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("type").and_then(serde_json::Value::as_str)
                != Some("MissionAwsIotDeviceDefenderConsumer")
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractValidationError::Boundary(
                "consumer authority widened",
            ));
        }
        let honesty = object
            .get("honesty")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractValidationError::Shape("honesty is not an object"))?;
        if honesty
            .values()
            .any(|value| value != &serde_json::Value::Bool(false))
        {
            return Err(ContractValidationError::Boundary("honesty flags widened"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum ContractValidationError {
    #[error("contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("contract identity is invalid: {0}")]
    Identity(&'static str),
    #[error("contract authority boundary is invalid: {0}")]
    Boundary(&'static str),
}

#[cfg(test)]
mod contract_tests {
    use super::{
        AwsIotDeviceDefenderContract, CONTRACT_DIGEST, CONTRACT_JSON, CONTRACT_SCHEMA,
        CONTRACT_VERSION, EVIDENCE_LEVEL, PLUGIN_ID, contract_digest,
    };

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract = AwsIotDeviceDefenderContract::baseline().expect("valid contract");
        let object = contract.value().as_object().expect("contract object");
        assert_eq!(object["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(object["contractVersion"], CONTRACT_VERSION);
        assert_eq!(object["pluginId"], PLUGIN_ID);
        assert_eq!(object["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(object["contractDigest"], contract_digest().as_str());
        assert_eq!(CONTRACT_DIGEST, contract_digest().as_str());
        assert!(!CONTRACT_JSON.is_empty());
    }
}
