//! Standalone Layer-1 governed AWS Config resource-compliance result slice.
//!
//! The crate provides typed scope, registration, bounded read, proposal,
//! recording, verification, and Mission-consumption seams. It deliberately
//! does not resolve credentials, sign native SigV4 requests, mutate AWS
//! Config or resources, retain raw configuration items, claim certification,
//! or adopt Hartevo kernel Outcome authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

use thiserror::Error;

pub use consumer::{
    ConsumerError, MissionAwsConfigComplianceConsumer, MissionAwsConfigComplianceResult,
    MissionAwsConfigConsumer, MissionAwsConfigDecisionState, MissionAwsConfigResult,
};
pub use model::*;
pub use provider::{
    AwsConfigProvider, AwsConfigProviderError, AwsConfigProviderIdentity, AwsConfigTransport,
    BlockedEnvAwsConfigTransport, BlockedEnvTransport, FakeAwsConfigTransport,
    FixtureAwsConfigTransport, LoopbackAwsConfigTransport, ProviderDefinitionError,
    ProviderProvenance, RecordingAwsConfigTransport, is_access_loss,
};
pub use service::{
    AwsConfigCapabilities, AwsConfigComplianceProposal, AwsConfigComplianceService,
    AwsConfigComplianceServiceError, AwsConfigReadResult, AwsConfigRecordReceipt,
    AwsConfigRegistration, AwsConfigRegistrationReceipt, AwsConfigService, AwsConfigServiceError,
    AwsConfigVerifiedRecord, RegistrationError, RegistrationState,
};

pub const AWS_CONFIG_SCHEMA_VERSION: &str = "hartevo.aws-config-compliance-result.contract/v1";
pub const AWS_CONFIG_CONTRACT_VERSION: &str = "aws-config-compliance-result/v1";
pub const AWS_CONFIG_PLUGIN_VERSION: &str = "1.0.0";
pub const AWS_CONFIG_SERVICE_ID: &str = "hartevo.aws.config.compliance-result";
pub const AWS_CONFIG_PROVIDER_ID: &str = "aws.config";
pub const AWS_CONFIG_PROVIDER_VERSION: &str = "1.0.0";
pub const AWS_CONFIG_API_REVISION: &str = "aws-config-read-r1";
pub const AWS_CONFIG_CONSUMER_ID: &str = "mission.aws.config.compliance-result";
pub const AWS_CONFIG_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AWS_CONFIG_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-config-compliance-result/aws-config-compliance-result.v1.json"
);

pub fn contract_digest() -> Digest {
    model::sha256_digest(AWS_CONFIG_CONTRACT_JSON.as_bytes())
}

pub const fn plugin_version() -> (u16, u16, u16) {
    (1, 0, 0)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsConfigComplianceContract {
    value: serde_json::Value,
}

impl AwsConfigComplianceContract {
    pub fn baseline() -> Result<Self, AwsConfigContractError> {
        let value = serde_json::from_str::<serde_json::Value>(AWS_CONFIG_CONTRACT_JSON)
            .map_err(|error| AwsConfigContractError::InvalidJson(error.to_string()))?;
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

    pub fn validate(&self) -> Result<(), AwsConfigContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(AwsConfigContractError::Shape("contract is not an object"))?;
        for key in [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "layer",
            "service",
            "provider",
            "consumer",
            "scope",
            "registration",
            "bounds",
            "evidence",
            "redaction",
            "authority",
            "honesty",
            "layer2Gaps",
            "forbidden",
        ] {
            if !object.contains_key(key) {
                return Err(AwsConfigContractError::Shape(
                    "required contract key missing",
                ));
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(AWS_CONFIG_SCHEMA_VERSION)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_CONFIG_CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_CONFIG_PLUGIN_VERSION)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
        {
            return Err(AwsConfigContractError::Identity(
                "contract identity drifted",
            ));
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsConfigContractError::Shape("service is not an object"))?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(AWS_CONFIG_SERVICE_ID)
            || service
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AwsConfigComplianceService")
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsConfigContractError::Identity("service identity drifted"));
        }
        let expected_operations = [
            "describe_capabilities",
            "register",
            "revoke_registration",
            "read_bounded",
            "propose",
            "record",
            "verify",
        ];
        let operations = service
            .get("operations")
            .and_then(serde_json::Value::as_array)
            .ok_or(AwsConfigContractError::Shape("service operations missing"))?;
        if operations.len() != expected_operations.len()
            || operations
                .iter()
                .zip(expected_operations)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err(AwsConfigContractError::Identity(
                "service operations drifted",
            ));
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsConfigContractError::Shape("provider is not an object"))?;
        let operations = provider
            .get("allowlistedOperations")
            .and_then(serde_json::Value::as_array)
            .ok_or(AwsConfigContractError::Shape(
                "provider operation allowlist missing",
            ))?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(AWS_CONFIG_PROVIDER_ID)
            || provider
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AwsConfigProvider")
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || operations
                != &[
                    serde_json::Value::String("GetComplianceDetailsByConfigRule".to_owned()),
                    serde_json::Value::String("DescribeComplianceByResource".to_owned()),
                ]
        {
            return Err(AwsConfigContractError::Identity(
                "provider allowlist drifted",
            ));
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsConfigContractError::Shape("consumer is not an object"))?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(AWS_CONFIG_CONSUMER_ID)
            || consumer
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("MissionAwsConfigConsumer")
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsConfigContractError::Identity(
                "consumer identity drifted",
            ));
        }
        let authority = object
            .get("authority")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsConfigContractError::Shape("authority is not an object"))?;
        for key in [
            "externalWrites",
            "configRuleMutation",
            "evaluationStart",
            "remediation",
            "resourceMutation",
            "rawConfigurationRead",
            "credentialResolution",
            "certification",
            "connected",
            "native",
            "kernelOutcomeAdoption",
        ] {
            if authority.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(AwsConfigContractError::Boundary(
                    "Layer-1 authority widened",
                ));
            }
        }
        let forbidden = object
            .get("forbidden")
            .and_then(serde_json::Value::as_array)
            .ok_or(AwsConfigContractError::Shape("forbidden list missing"))?;
        for required in [
            "create_config_rule",
            "update_config_rule",
            "delete_config_rule",
            "start_config_rule_evaluation",
            "invoke_remediation",
            "mutate_aws_resource",
            "read_raw_configuration_item",
            "resolve_live_credentials",
            "claim_compliance_certification",
            "adopt_kernel_outcome",
        ] {
            if !forbidden
                .iter()
                .any(|entry| entry.as_str() == Some(required))
            {
                return Err(AwsConfigContractError::Boundary(
                    "forbidden operation missing",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsConfigContractError {
    #[error("AWS Config contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("AWS Config contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("AWS Config contract identity is invalid: {0}")]
    Identity(&'static str),
    #[error("AWS Config contract authority boundary is invalid: {0}")]
    Boundary(&'static str),
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

    pub const fn durable_receipt() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }

    pub const fn certification_authority() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_in_contract_matches_typed_boundary() {
        let contract = AwsConfigComplianceContract::baseline().expect("contract");
        assert_eq!(contract.digest(), contract_digest());
        assert_eq!(plugin_version(), (1, 0, 0));
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::certification_authority());
    }
}
