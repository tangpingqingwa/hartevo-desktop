//! Standalone Layer-1 governed AWS ECS deployment result slice.
//!
//! The crate exposes only typed bounded DescribeServices, DescribeTasks,
//! DescribeTaskDefinition and ListTasks read seams plus proposal, recording,
//! verification and Mission consumption. It deliberately does not resolve
//! credentials, sign native SigV4 requests, perform live HTTP, mutate ECS,
//! read logs or environment/secrets, execute commands, download image content,
//! claim connection/native authority, or adopt kernel Outcome authority.

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

pub use consumer::{
    ConsumerError, MissionEcsDeploymentConsumer, MissionEcsDeploymentResult,
    RecordedEcsDeploymentResult,
};
pub use model::*;
pub use provider::{
    BlockedEnvTransport, EcsProvider, EcsProviderError, EcsProviderIdentity, EcsProviderTransport,
    EcsTransport, FixtureEcsTransport, LoopbackEcsTransport, ProviderProvenance,
    RecordingEcsTransport, TransportCall, TransportError, TransportFailure,
};
pub use service::{
    EcsCapabilities, EcsDeploymentProposal, EcsDeploymentReadResult, EcsDeploymentRecord,
    EcsDeploymentRegistration, EcsDeploymentResultService, EcsDeploymentServiceError,
    EcsDeploymentVerifiedRecord, RegistrationError, RegistrationState,
};

pub const AWS_ECS_SCHEMA_VERSION: &str = "hartevo.aws-ecs-deployment-result.contract/v1";
pub const AWS_ECS_CONTRACT_VERSION: &str = "aws-ecs-deployment-result/v1";
pub const AWS_ECS_PLUGIN_VERSION: &str = "1.0.0";
pub const AWS_ECS_SERVICE_ID: &str = "aws.ecs.deployment.result";
pub const AWS_ECS_PROVIDER_ID: &str = "aws.ecs.deployment.read";
pub const AWS_ECS_PROVIDER_VERSION: &str = "aws-ecs-provider/v1";
pub const AWS_ECS_API_VERSION: &str = "2014-11-13";
pub const AWS_ECS_API_REVISION: &str =
    "ecs-describe-services-describe-tasks-describe-task-definition-list-tasks-r1";
pub const AWS_ECS_CONSUMER_ID: &str = "mission.aws.ecs.deployment";
pub const AWS_ECS_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AWS_ECS_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-ecs-deployment-result/aws-ecs-deployment-result.v1.json"
);

pub fn contract_digest() -> Digest {
    Digest::from_bytes(AWS_ECS_CONTRACT_JSON.as_bytes())
}

pub const fn plugin_version() -> (u16, u16, u16) {
    (1, 0, 0)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcsDeploymentContract {
    value: serde_json::Value,
}

impl EcsDeploymentContract {
    pub fn baseline() -> Result<Self, ContractError> {
        let value = serde_json::from_str::<serde_json::Value>(AWS_ECS_CONTRACT_JSON)
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

    pub fn validate(&self) -> Result<(), ContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(ContractError::Shape("contract is not an object"))?;
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
            "normalization",
            "evidence",
            "redaction",
            "authority",
            "honesty",
            "layer2Gaps",
            "forbidden",
        ] {
            if !object.contains_key(key) {
                return Err(ContractError::Shape("required contract key missing"));
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(AWS_ECS_SCHEMA_VERSION)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_ECS_CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_ECS_PLUGIN_VERSION)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
        {
            return Err(ContractError::Identity("contract identity drifted"));
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("service is not an object"))?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(AWS_ECS_SERVICE_ID)
            || service
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("EcsDeploymentResultService")
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
            || service.get("outcomeAdoption") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractError::Identity("service identity drifted"));
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("provider is not an object"))?;
        let operations = provider
            .get("allowlistedOperations")
            .and_then(serde_json::Value::as_array)
            .ok_or(ContractError::Shape("provider operation allowlist missing"))?;
        let expected_operations = [
            "DescribeServices",
            "DescribeTasks",
            "DescribeTaskDefinition",
            "ListTasks",
        ];
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(AWS_ECS_PROVIDER_ID)
            || provider
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("EcsProvider")
            || provider
                .get("apiVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_ECS_API_VERSION)
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || operations.len() != expected_operations.len()
            || operations
                .iter()
                .zip(expected_operations)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err(ContractError::Identity("provider identity drifted"));
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("consumer is not an object"))?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(AWS_ECS_CONSUMER_ID)
            || consumer
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("MissionEcsDeploymentConsumer")
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractError::Identity("consumer identity drifted"));
        }
        let authority = object
            .get("authority")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("authority is not an object"))?;
        for key in [
            "externalWrites",
            "runTask",
            "updateService",
            "stopTask",
            "createService",
            "deploy",
            "rollback",
            "exec",
            "logs",
            "environmentExport",
            "secretExport",
            "imageContentDownload",
            "kernelAuthority",
            "outcomeAdoption",
            "connected",
            "native",
            "durableReceipt",
        ] {
            if authority.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(ContractError::Boundary("Layer-1 authority widened"));
            }
        }
        let forbidden = object
            .get("forbidden")
            .and_then(serde_json::Value::as_array)
            .ok_or(ContractError::Shape("forbidden list missing"))?;
        for required in [
            "RunTask",
            "UpdateService",
            "StopTask",
            "CreateService",
            "deploy",
            "rollback",
            "execute_command",
            "read_logs",
            "export_environment",
            "export_secrets",
            "download_image_content",
            "resolve_live_credentials",
            "claim_connected",
            "claim_native",
            "adopt_kernel_outcome",
        ] {
            if !forbidden
                .iter()
                .any(|entry| entry.as_str() == Some(required))
            {
                return Err(ContractError::Boundary("forbidden operation missing"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum ContractError {
    #[error("AWS ECS contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("AWS ECS contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("AWS ECS contract identity is invalid: {0}")]
    Identity(&'static str),
    #[error("AWS ECS contract authority boundary is invalid: {0}")]
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

    pub const fn kernel_authority() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_in_contract_matches_typed_boundary() {
        let contract = EcsDeploymentContract::baseline().expect("contract");
        assert_eq!(contract.digest(), contract_digest());
        assert_eq!(plugin_version(), (1, 0, 0));
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::adopted_outcome());
    }
}

#[cfg(test)]
mod adversarial_tests;
