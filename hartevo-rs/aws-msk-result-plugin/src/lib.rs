//! Standalone Layer-1 governed Amazon MSK cluster and streaming-health result slice.
//!
//! The crate provides typed account/region/cluster/configuration/operation
//! scope, opaque SigV4 references, bounded read pages, redacted readiness
//! evidence, reversible registration, proposals, integrity receipts, and a
//! Mission consumer. It deliberately does not resolve credentials, sign native
//! SigV4 requests, mutate MSK, expose broker endpoints, read Kafka records, or
//! adopt Hartevo kernel Outcome or verified Work Product authority.

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
    ConsumerError, MissionAwsMskConsumer, MissionAwsMskDecision, MissionAwsMskDecisionState,
    MissionAwsMskResult, MissionAwsMskResultConsumer,
};
pub use model::*;
pub use provider::{
    AwsMskProvider, AwsMskProviderError, AwsMskProviderIdentity, AwsMskTransport,
    BlockedEnvAwsMskTransport, BlockedEnvTransport, FakeAwsMskTransport, FixtureAwsMskTransport,
    LoopbackAwsMskTransport, ProviderDefinitionError, ProviderProvenance, RecordingAwsMskTransport,
    is_access_loss,
};
pub use service::{
    AwsMskCapabilities, AwsMskProposal, AwsMskReadResult, AwsMskRecordReceipt, AwsMskRegistration,
    AwsMskRegistrationReceipt, AwsMskResultService, AwsMskService, AwsMskServiceError,
    AwsMskServiceResult, AwsMskTransportProvenance, AwsMskVerifiedRecord, RegistrationError,
    RegistrationState,
};

pub const AWS_MSK_SCHEMA_VERSION: &str = "hartevo.aws-msk-result.contract/v1";
pub const AWS_MSK_CONTRACT_VERSION: &str = "aws-msk-result/v1";
pub const AWS_MSK_PLUGIN_VERSION: &str = "1.0.0";
pub const AWS_MSK_SERVICE_ID: &str = "hartevo.aws.msk.result";
pub const AWS_MSK_PROVIDER_ID: &str = "aws.msk";
pub const AWS_MSK_PROVIDER_VERSION: &str = "1.0.0";
pub const AWS_MSK_API_REVISION: &str = "aws-msk-read-r1";
pub const AWS_MSK_CONSUMER_ID: &str = "mission.aws.msk.result";
pub const AWS_MSK_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AWS_MSK_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-msk-result/aws-msk-result.v1.json");

pub fn contract_digest() -> Digest {
    model::sha256_digest(AWS_MSK_CONTRACT_JSON.as_bytes())
}

pub const fn plugin_version() -> (u16, u16, u16) {
    (1, 0, 0)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsMskContract {
    value: serde_json::Value,
}

impl AwsMskContract {
    pub fn baseline() -> Result<Self, AwsMskContractError> {
        let value = serde_json::from_str::<serde_json::Value>(AWS_MSK_CONTRACT_JSON)
            .map_err(|error| AwsMskContractError::InvalidJson(error.to_string()))?;
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

    pub fn validate(&self) -> Result<(), AwsMskContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(AwsMskContractError::Shape("contract is not an object"))?;
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
                return Err(AwsMskContractError::Shape("required contract key missing"));
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(AWS_MSK_SCHEMA_VERSION)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_MSK_CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_MSK_PLUGIN_VERSION)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
        {
            return Err(AwsMskContractError::Identity("contract identity drifted"));
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsMskContractError::Shape("service is not an object"))?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(AWS_MSK_SERVICE_ID)
            || service
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AwsMskService")
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsMskContractError::Identity("service identity drifted"));
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
            .ok_or(AwsMskContractError::Shape("service operations missing"))?;
        if operations.len() != expected_operations.len()
            || operations
                .iter()
                .zip(expected_operations)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err(AwsMskContractError::Identity("service operations drifted"));
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsMskContractError::Shape("provider is not an object"))?;
        let expected_provider_operations = vec![
            serde_json::Value::String("ListClustersV2".to_owned()),
            serde_json::Value::String("DescribeClusterV2".to_owned()),
            serde_json::Value::String("DescribeConfigurationRevision".to_owned()),
            serde_json::Value::String("ListClusterOperationsV2".to_owned()),
        ];
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(AWS_MSK_PROVIDER_ID)
            || provider
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AwsMskProvider")
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || provider
                .get("allowlistedOperations")
                .and_then(serde_json::Value::as_array)
                != Some(&expected_provider_operations)
        {
            return Err(AwsMskContractError::Identity(
                "provider identity or allowlist drifted",
            ));
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsMskContractError::Shape("consumer is not an object"))?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(AWS_MSK_CONSUMER_ID)
            || consumer
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("MissionAwsMskConsumer")
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsMskContractError::Identity("consumer identity drifted"));
        }
        let authority = object
            .get("authority")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsMskContractError::Shape("authority is not an object"))?;
        for key in [
            "externalWrites",
            "clusterMutation",
            "configurationMutation",
            "operationMutation",
            "topicMutation",
            "recordRead",
            "credentialResolution",
            "nativeTransport",
            "connected",
            "native",
            "firstParty",
            "durableReceipt",
            "independentNativeReread",
            "kernelOutcomeAdoption",
            "workProductAdoption",
            "certification",
        ] {
            if authority.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(AwsMskContractError::Boundary("Layer-1 authority widened"));
            }
        }
        let forbidden = object
            .get("forbidden")
            .and_then(serde_json::Value::as_array)
            .ok_or(AwsMskContractError::Shape("forbidden list missing"))?;
        for required in [
            "create_cluster",
            "update_cluster_configuration",
            "cancel_operation",
            "create_topic",
            "read_kafka_records",
            "read_bootstrap_endpoints",
            "retain_raw_configuration_properties",
            "retain_raw_operation_messages",
            "resolve_live_credentials",
            "claim_connected",
            "claim_native",
            "claim_first_party",
            "adopt_kernel_outcome",
            "adopt_verified_work_product",
        ] {
            if !forbidden
                .iter()
                .any(|entry| entry.as_str() == Some(required))
            {
                return Err(AwsMskContractError::Boundary("forbidden operation missing"));
            }
        }
        let honesty = object
            .get("honesty")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsMskContractError::Shape("honesty is not an object"))?;
        for key in [
            "blockedEnvironmentIsNative",
            "fixtureIsNative",
            "fakeIsNative",
            "recordingIsNative",
            "loopbackIsNative",
            "readyIsCertification",
        ] {
            if honesty.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(AwsMskContractError::Boundary("honesty declaration drifted"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsMskContractError {
    #[error("AWS MSK contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("AWS MSK contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("AWS MSK contract identity is invalid: {0}")]
    Identity(&'static str),
    #[error("AWS MSK contract authority boundary is invalid: {0}")]
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

    pub const fn first_party() -> bool {
        false
    }

    pub const fn durable_receipt() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }

    pub const fn work_product_adoption() -> bool {
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
        let contract = AwsMskContract::baseline().expect("contract");
        assert_eq!(contract.digest(), contract_digest());
        assert_eq!(plugin_version(), (1, 0, 0));
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::work_product_adoption());
        assert!(!Layer1Authority::certification_authority());
    }
}
