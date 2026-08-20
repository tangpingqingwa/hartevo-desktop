//! Standalone Layer-1 governed AWS Elastic Beanstalk deployment result slice.
//!
//! This crate provides typed scope, version, provider, permission, evidence,
//! reversible-registration, bounded-read, proposal, recording, and Mission
//! consumption seams. It intentionally has no native SigV4 resolution, no
//! Connected claim, no write operation, no upload, and no raw source/log/
//! environment/secret representation.

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

use serde_json::Value;
use thiserror::Error;

pub use consumer::{
    ConsumerError, MissionAwsElasticBeanstalkConsumer, MissionAwsElasticBeanstalkDecisionState,
    MissionAwsElasticBeanstalkDeploymentConsumer, MissionAwsElasticBeanstalkDeploymentResult,
    MissionAwsElasticBeanstalkResult,
};
pub use model::*;
pub use provider::{
    AwsElasticBeanstalkProvider, AwsElasticBeanstalkProviderDefinition,
    AwsElasticBeanstalkTransport, BlockedEnvAwsElasticBeanstalkTransport, BlockedEnvTransport,
    DescribeEnvironmentResourcesPage, DescribeEnvironmentResourcesRequest,
    DescribeEnvironmentsPage, DescribeEnvironmentsRequest, DescribeEventsPage,
    DescribeEventsRequest, FakeAwsElasticBeanstalkTransport, FixtureAwsElasticBeanstalkTransport,
    LoopbackAwsElasticBeanstalkTransport, ProviderDefinitionError, ProviderError,
    ProviderProvenance, RecordedRequest, RecordingAwsElasticBeanstalkTransport, TransportError,
    TransportFailure, TransportProvenance,
};
pub use service::{
    AwsElasticBeanstalkDeploymentCapabilities, AwsElasticBeanstalkDeploymentEvidence,
    AwsElasticBeanstalkDeploymentProposal, AwsElasticBeanstalkDeploymentReadResult,
    AwsElasticBeanstalkDeploymentRegistration, AwsElasticBeanstalkDeploymentService,
    AwsElasticBeanstalkDeploymentServiceError, AwsElasticBeanstalkProposal,
    AwsElasticBeanstalkReadResult, AwsElasticBeanstalkRecordReceipt,
    AwsElasticBeanstalkRegistrationReceipt, AwsElasticBeanstalkRegistrationState,
    AwsElasticBeanstalkService, AwsElasticBeanstalkServiceError, EvidenceAuthority,
    EvidencePageCounts, EvidenceStatus, RegistrationError,
};

pub const AWS_ELASTIC_BEANSTALK_SCHEMA_VERSION: &str =
    "hartevo.aws-elastic-beanstalk-deployment-result.contract/v1";
pub const AWS_ELASTIC_BEANSTALK_CONTRACT_VERSION: &str =
    "aws-elastic-beanstalk-deployment-result/v1";
pub const AWS_ELASTIC_BEANSTALK_PLUGIN_VERSION: &str = "1.0.0";
pub const AWS_ELASTIC_BEANSTALK_SERVICE_ID: &str =
    "hartevo.aws.elastic-beanstalk.deployment-result";
pub const AWS_ELASTIC_BEANSTALK_PROVIDER_ID: &str = "aws.elastic-beanstalk";
pub const AWS_ELASTIC_BEANSTALK_PROVIDER_VERSION: &str = "1.0.0";
pub const AWS_ELASTIC_BEANSTALK_API_REVISION: &str = "aws-elastic-beanstalk-read-r1";
pub const AWS_ELASTIC_BEANSTALK_CONSUMER_ID: &str =
    "mission.aws.elastic-beanstalk.deployment-result";
pub const AWS_ELASTIC_BEANSTALK_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AWS_ELASTIC_BEANSTALK_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-elastic-beanstalk-deployment-result/contract.v1.json"
);

pub fn contract_digest() -> Digest {
    model::sha256_digest(AWS_ELASTIC_BEANSTALK_CONTRACT_JSON.as_bytes())
}

pub const fn plugin_version() -> (u16, u16, u16) {
    (1, 0, 0)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsElasticBeanstalkDeploymentContract {
    value: Value,
}

impl AwsElasticBeanstalkDeploymentContract {
    pub fn baseline() -> Result<Self, AwsElasticBeanstalkContractError> {
        let value = serde_json::from_str::<Value>(AWS_ELASTIC_BEANSTALK_CONTRACT_JSON)
            .map_err(|error| AwsElasticBeanstalkContractError::InvalidJson(error.to_string()))?;
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

    pub fn validate(&self) -> Result<(), AwsElasticBeanstalkContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(AwsElasticBeanstalkContractError::Shape(
                "contract is not an object",
            ))?;
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
                return Err(AwsElasticBeanstalkContractError::Shape(
                    "required contract key missing",
                ));
            }
        }
        if object.get("schemaVersion").and_then(Value::as_str)
            != Some(AWS_ELASTIC_BEANSTALK_SCHEMA_VERSION)
            || object.get("contractVersion").and_then(Value::as_str)
                != Some(AWS_ELASTIC_BEANSTALK_CONTRACT_VERSION)
            || object.get("pluginVersion").and_then(Value::as_str)
                != Some(AWS_ELASTIC_BEANSTALK_PLUGIN_VERSION)
            || object.get("layer").and_then(Value::as_str) != Some("Layer-1")
        {
            return Err(AwsElasticBeanstalkContractError::Identity(
                "contract identity drifted",
            ));
        }
        let service = object.get("service").and_then(Value::as_object).ok_or(
            AwsElasticBeanstalkContractError::Shape("service is not an object"),
        )?;
        if service.get("id").and_then(Value::as_str) != Some(AWS_ELASTIC_BEANSTALK_SERVICE_ID)
            || service.get("implementation").and_then(Value::as_str)
                != Some("AwsElasticBeanstalkDeploymentService")
            || service.get("readOnly") != Some(&Value::Bool(true))
            || service.get("proposalOnly") != Some(&Value::Bool(true))
            || service.get("liveExecution") != Some(&Value::Bool(false))
        {
            return Err(AwsElasticBeanstalkContractError::Identity(
                "service identity drifted",
            ));
        }
        let expected_service_operations = [
            "describe_capabilities",
            "register",
            "revoke_registration",
            "read_bounded",
            "propose",
            "record",
            "verify",
        ];
        let service_operations = service.get("operations").and_then(Value::as_array).ok_or(
            AwsElasticBeanstalkContractError::Shape("service operations missing"),
        )?;
        if service_operations.len() != expected_service_operations.len()
            || service_operations
                .iter()
                .zip(expected_service_operations)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err(AwsElasticBeanstalkContractError::Identity(
                "service operations drifted",
            ));
        }
        let provider = object.get("provider").and_then(Value::as_object).ok_or(
            AwsElasticBeanstalkContractError::Shape("provider is not an object"),
        )?;
        let provider_operations = provider
            .get("allowlistedOperations")
            .and_then(Value::as_array)
            .ok_or(AwsElasticBeanstalkContractError::Shape(
                "provider operation allowlist missing",
            ))?;
        let expected_provider_operations = [
            Value::String("DescribeEnvironments".to_owned()),
            Value::String("DescribeEnvironmentResources".to_owned()),
            Value::String("DescribeEvents".to_owned()),
        ];
        if provider.get("id").and_then(Value::as_str) != Some(AWS_ELASTIC_BEANSTALK_PROVIDER_ID)
            || provider.get("implementation").and_then(Value::as_str)
                != Some("AwsElasticBeanstalkProvider")
            || provider.get("version").and_then(Value::as_str)
                != Some(AWS_ELASTIC_BEANSTALK_PROVIDER_VERSION)
            || provider.get("apiRevision").and_then(Value::as_str)
                != Some(AWS_ELASTIC_BEANSTALK_API_REVISION)
            || provider.get("native") != Some(&Value::Bool(false))
            || provider.get("connected") != Some(&Value::Bool(false))
            || provider.get("externalWrites") != Some(&Value::Bool(false))
            || provider_operations != &expected_provider_operations
        {
            return Err(AwsElasticBeanstalkContractError::Identity(
                "provider identity or allowlist drifted",
            ));
        }
        let accepted_transports = provider
            .get("acceptedTransports")
            .and_then(Value::as_array)
            .ok_or(AwsElasticBeanstalkContractError::Shape(
                "provider transports missing",
            ))?;
        for expected in ["fixture", "recording", "loopback", "BLOCKED_ENV"] {
            if !accepted_transports
                .iter()
                .any(|entry| entry.as_str() == Some(expected))
            {
                return Err(AwsElasticBeanstalkContractError::Boundary(
                    "accepted transport missing",
                ));
            }
        }
        let consumer = object.get("consumer").and_then(Value::as_object).ok_or(
            AwsElasticBeanstalkContractError::Shape("consumer is not an object"),
        )?;
        if consumer.get("id").and_then(Value::as_str) != Some(AWS_ELASTIC_BEANSTALK_CONSUMER_ID)
            || consumer.get("implementation").and_then(Value::as_str)
                != Some("MissionAwsElasticBeanstalkConsumer")
            || consumer.get("adoptsOutcome") != Some(&Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&Value::Bool(false))
            || consumer.get("connected") != Some(&Value::Bool(false))
            || consumer.get("native") != Some(&Value::Bool(false))
        {
            return Err(AwsElasticBeanstalkContractError::Identity(
                "consumer identity drifted",
            ));
        }
        let authority = object.get("authority").and_then(Value::as_object).ok_or(
            AwsElasticBeanstalkContractError::Shape("authority is not an object"),
        )?;
        for key in [
            "externalWrites",
            "createEnvironment",
            "updateEnvironment",
            "terminateEnvironment",
            "cnameMutation",
            "upload",
            "rawLogs",
            "rawSource",
            "rawEnvironment",
            "credentialResolution",
            "connected",
            "native",
            "kernelOutcomeAdoption",
        ] {
            if authority.get(key) != Some(&Value::Bool(false)) {
                return Err(AwsElasticBeanstalkContractError::Boundary(
                    "Layer-1 authority widened",
                ));
            }
        }
        let forbidden = object.get("forbidden").and_then(Value::as_array).ok_or(
            AwsElasticBeanstalkContractError::Shape("forbidden list missing"),
        )?;
        for expected in [
            "create_environment",
            "update_environment",
            "terminate_environment",
            "mutate_cname",
            "upload_source_bundle",
            "read_raw_logs",
            "read_source_bundle",
            "read_environment_variables",
            "resolve_live_credentials",
            "claim_connected",
            "claim_deployment_success",
            "adopt_kernel_outcome",
        ] {
            if !forbidden
                .iter()
                .any(|entry| entry.as_str() == Some(expected))
            {
                return Err(AwsElasticBeanstalkContractError::Boundary(
                    "forbidden operation missing",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsElasticBeanstalkContractError {
    #[error("AWS Elastic Beanstalk contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("AWS Elastic Beanstalk contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("AWS Elastic Beanstalk contract identity is invalid: {0}")]
    Identity(&'static str),
    #[error("AWS Elastic Beanstalk contract authority boundary is invalid: {0}")]
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
    fn checked_in_contract_matches_typed_layer_one_boundary() {
        let contract = AwsElasticBeanstalkDeploymentContract::baseline().expect("contract");
        assert_eq!(contract.digest(), contract_digest());
        assert_eq!(plugin_version(), (1, 0, 0));
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::certification_authority());
    }
}
