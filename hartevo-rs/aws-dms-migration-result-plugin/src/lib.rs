//! Standalone Layer-1 governed AWS DMS migration-result boundary.
//!
//! The crate models bounded metadata reads, digest fences, reversible
//! registration, idempotent recording, and Mission-scoped review proposals.
//! It deliberately does not resolve credentials, sign native SigV4 requests,
//! perform live HTTPS, mutate DMS, execute assessments, claim migration
//! safety, or adopt Hartevo kernel Outcome/Work Product authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::bool_to_int_with_if,
    clippy::cast_possible_truncation,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::single_match_else,
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

pub use consumer::{MissionAwsDmsConsumer, MissionAwsDmsResult};
pub use error::{AwsDmsMigrationError, AwsDmsTransportError, Result};
pub use model::*;
pub use provider::{
    AwsDmsProvider, AwsDmsProviderDefinition, AwsDmsTransport, BlockedEnvDmsTransport,
    BlockedEnvTransport, DescribeReplicationTaskAssessmentResults, FixtureDmsTransport,
    FixtureTransport, LoopbackDmsTransport, LoopbackTransport, ProviderProvenance, RecordedRequest,
    RecordingDmsTransport, RecordingTransport, is_access_loss,
};
pub use service::{
    AwsDmsCapabilities, AwsDmsMigrationProposal, AwsDmsMigrationService, AwsDmsRecordReceipt,
    AwsDmsRegistration, ProposalDisposition, RegistrationStatus, RegistrationTransitionEvidence,
    VerificationFailure, VerificationReport,
};

pub const AWS_DMS_SCHEMA_VERSION: &str = "hartevo.aws-dms-migration-result.contract/v1";
pub const AWS_DMS_CONTRACT_VERSION: &str = "aws-dms-migration-result/v1";
pub const AWS_DMS_PLUGIN_VERSION: &str = "1.0.0";
pub const AWS_DMS_SERVICE_ID: &str = "hartevo.aws.dms.migration-result";
pub const AWS_DMS_PROVIDER_ID: &str = "aws.dms";
pub const AWS_DMS_PROVIDER_VERSION: &str = "1.0.0";
pub const AWS_DMS_API_REVISION: &str = "aws-dms-read-r1";
pub const AWS_DMS_CONSUMER_ID: &str = "mission.aws.dms.migration-result";
pub const AWS_DMS_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AWS_DMS_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-dms-migration-result/contract.v1.json");

pub fn contract_digest() -> Digest {
    Digest::from_bytes(AWS_DMS_CONTRACT_JSON.as_bytes())
}

pub fn validate_contract() -> std::result::Result<(), AwsDmsContractError> {
    AwsDmsMigrationContract::baseline().map(|_| ())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsDmsMigrationContract {
    value: serde_json::Value,
}

impl AwsDmsMigrationContract {
    pub fn baseline() -> std::result::Result<Self, AwsDmsContractError> {
        let value = serde_json::from_str::<serde_json::Value>(AWS_DMS_CONTRACT_JSON)
            .map_err(|error| AwsDmsContractError::InvalidJson(error.to_string()))?;
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

    pub fn validate(&self) -> std::result::Result<(), AwsDmsContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(AwsDmsContractError::Shape("contract is not an object"))?;
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
            "permissions",
            "honesty",
            "layer2Gaps",
            "forbidden",
        ] {
            if !object.contains_key(key) {
                return Err(AwsDmsContractError::Shape("required contract key missing"));
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(AWS_DMS_SCHEMA_VERSION)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_DMS_CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_DMS_PLUGIN_VERSION)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
        {
            return Err(AwsDmsContractError::Identity("contract identity drifted"));
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsDmsContractError::Shape("service is not an object"))?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(AWS_DMS_SERVICE_ID)
            || service
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AwsDmsMigrationService")
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsDmsContractError::Identity("service identity drifted"));
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsDmsContractError::Shape("provider is not an object"))?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(AWS_DMS_PROVIDER_ID)
            || provider
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AwsDmsProvider")
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsDmsContractError::Boundary("provider authority widened"));
        }
        let operations = provider
            .get("allowlistedOperations")
            .and_then(serde_json::Value::as_array)
            .ok_or(AwsDmsContractError::Shape("provider operations missing"))?;
        let expected_operations = [
            "DescribeReplicationTasks",
            "DescribeReplications",
            "DescribeReplicationTaskAssessmentResults",
        ];
        if operations.len() != expected_operations.len()
            || operations
                .iter()
                .zip(expected_operations)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err(AwsDmsContractError::Identity("provider operations drifted"));
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsDmsContractError::Shape("consumer is not an object"))?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(AWS_DMS_CONSUMER_ID)
            || consumer
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("MissionAwsDmsConsumer")
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsDmsContractError::Boundary("consumer authority widened"));
        }
        let accepted_transports = provider
            .get("acceptedTransports")
            .and_then(serde_json::Value::as_array)
            .ok_or(AwsDmsContractError::Shape("provider transports missing"))?;
        if accepted_transports.len() != 4
            || accepted_transports
                .iter()
                .any(|transport| transport.as_str() == Some("native"))
        {
            return Err(AwsDmsContractError::Boundary(
                "native transport was admitted",
            ));
        }
        let permissions = object
            .get("permissions")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsDmsContractError::Shape("permission boundary missing"))?;
        let allow = permissions
            .get("allow")
            .and_then(serde_json::Value::as_array)
            .ok_or(AwsDmsContractError::Shape("permission allowlist missing"))?;
        if allow.len() != LAYER1_PERMISSIONS.len()
            || LAYER1_PERMISSIONS.iter().any(|permission| {
                !allow
                    .iter()
                    .any(|value| value.as_str() == Some(*permission))
            })
        {
            return Err(AwsDmsContractError::Boundary(
                "permission allowlist drifted",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AwsDmsContractError {
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
    use super::*;

    #[test]
    fn contract_is_versioned_and_non_native() {
        let contract = AwsDmsMigrationContract::baseline().expect("checked DMS contract");
        assert_eq!(contract.digest(), contract_digest());
        assert_eq!(contract.value()["layer"], "Layer-1");
        assert_eq!(contract.value()["provider"]["native"], false);
        assert_eq!(contract.value()["provider"]["connected"], false);
        assert_eq!(contract.value()["provider"]["firstParty"], false);
        assert_eq!(contract.value()["consumer"]["adoptsOutcome"], false);
    }
}
