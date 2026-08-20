//! Standalone Layer-1 AWS SSM Automation result boundary.
//!
//! This crate is intentionally below Hartevo Truth, Effect, Receipt,
//! Verification, Outcome, and durable Work Product authority. It models only
//! bounded Automation metadata reads, opaque filter/cursor binding, redacted
//! output/error digests, reversible registration, and a Mission-scoped
//! proposal/record seam. Fixture, recording, loopback, and `BLOCKED_ENV`
//! transports are always non-connected, non-native, and non-first-party.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_excessive_bools,
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
    MissionAwsSsmAutomationConsumer, MissionAwsSsmAutomationResult, ProposalDisposition,
    RecordedAwsSsmAutomationResult,
};
pub use error::{AwsSsmAutomationError, AwsSsmAutomationTransportError, ModelResult, Result};
pub use model::*;
pub use provider::{
    AwsSsmAutomationProvider, AwsSsmAutomationProviderDefinition, AwsSsmAutomationProviderError,
    AwsSsmAutomationTransport, BlockedEnvAwsSsmAutomationTransport, BlockedEnvTransport,
    FixtureAwsSsmAutomationTransport, FixtureTransport, LoopbackAwsSsmAutomationTransport,
    LoopbackTransport, ProviderResult, RecordingAwsSsmAutomationTransport, RecordingTransport,
};
pub use service::{
    AwsSsmAutomationCapabilities, AwsSsmAutomationEvidence, AwsSsmAutomationProposal,
    AwsSsmAutomationReadResult, AwsSsmAutomationRecord, AwsSsmAutomationRegistration,
    AwsSsmAutomationService, AwsSsmAutomationServiceError, RegistrationStatus,
    RegistrationTransition, VerificationReport,
};

pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo.aws-ssm-automation-result.contract/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-SSM-AUTOMATION-01-L1/v1";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.ssm.automation-result.read";
pub const PROVIDER_ID: &str = "aws.ssm.automation-result.recording";
pub const PROVIDER_API_REVISION: &str =
    "ssm-describe-automation-executions-get-automation-execution-describe-step-executions-1";
pub const CONSUMER_ID: &str = "mission.aws-ssm-automation.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-ssm-automation-result.contract/v1|layer=1|service=aws.ssm.automation-result.read|provider=aws.ssm.automation-result.recording|consumer=mission.aws-ssm-automation.consumer";
pub const CONTRACT_DIGEST: &str =
    "c8d16f142ef9acd8be16d59cdcc0aa15e521877fc63baafdcbc6fea5dd008f31";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-ssm-automation-result/contract.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 50;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

pub fn contract_digest() -> Digest {
    Digest::parse(CONTRACT_DIGEST.to_owned()).expect("checked contract digest")
}

pub fn plugin_version() -> (u16, u16, u16) {
    (1, 0, 0)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsSsmAutomationContract {
    value: serde_json::Value,
}

impl AwsSsmAutomationContract {
    pub fn baseline() -> Result<Self> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|_| AwsSsmAutomationError::InvalidScope)?;
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

    pub fn validate(&self) -> Result<()> {
        let object = self
            .value
            .as_object()
            .ok_or(AwsSsmAutomationError::InvalidScope)?;
        let required = [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "layer",
            "evidenceLevel",
            "digestInput",
            "contractDigest",
            "service",
            "provider",
            "consumer",
            "scope",
            "registration",
            "pagination",
            "evidence",
            "redaction",
            "provenance",
            "authorityBoundary",
            "forbidden",
            "layer2Gaps",
            "honestNativeGap",
        ];
        if required.iter().any(|key| !object.contains_key(*key))
            || object
                .get("schemaVersion")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_SCHEMA_VERSION)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(PLUGIN_VERSION)
            || object.get("layer").and_then(serde_json::Value::as_u64) != Some(1)
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
            return Err(AwsSsmAutomationError::InvalidScope);
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsSsmAutomationError::InvalidScope)?;
        if service.get("type").and_then(serde_json::Value::as_str)
            != Some("AwsSsmAutomationService")
            || service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || service.get("outcomeAdoption") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsSsmAutomationError::InvalidScope);
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsSsmAutomationError::InvalidScope)?;
        if provider.get("type").and_then(serde_json::Value::as_str)
            != Some("AwsSsmAutomationProvider")
            || provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsSsmAutomationError::InvalidScope);
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsSsmAutomationError::InvalidScope)?;
        if consumer.get("type").and_then(serde_json::Value::as_str)
            != Some("MissionAwsSsmAutomationConsumer")
            || consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsSsmAutomationError::InvalidScope);
        }
        let forbidden = object
            .get("forbidden")
            .and_then(serde_json::Value::as_array)
            .ok_or(AwsSsmAutomationError::InvalidScope)?;
        for operation in [
            "StartAutomationExecution",
            "StopAutomationExecution",
            "SendCommand",
            "automation_parameter_mutation",
            "automation_target_mutation",
            "raw_output_retention",
            "raw_log_retention",
            "secret_material_retention",
            "adopt_kernel_outcome",
        ] {
            if !forbidden
                .iter()
                .any(|value| value.as_str() == Some(operation))
            {
                return Err(AwsSsmAutomationError::InvalidScope);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }

    pub const fn durable_provider_receipt() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_in_contract_matches_typed_boundary() {
        let contract = AwsSsmAutomationContract::baseline().expect("contract");
        assert_eq!(contract.digest(), contract_digest());
        assert_eq!(plugin_version(), (1, 0, 0));
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::adopted_outcome());
    }
}
