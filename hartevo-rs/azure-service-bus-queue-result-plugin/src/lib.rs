//! Standalone Layer-1 Azure Service Bus queue posture result boundary.
//!
//! The crate exposes only bounded, read-only queue and dead-letter posture
//! evidence. It has no Azure SDK, Entra credential resolver, native HTTP
//! transport, Service Bus data-plane operation, message-body type, or kernel
//! authority. Fixture, recording, loopback, and `BLOCKED_ENV` transports are
//! always non-connected, non-native, and non-first-party.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConsumerError, MissionAzureServiceBusConsumer, MissionAzureServiceBusDecisionState,
    MissionAzureServiceBusResult,
};
pub use model::*;
pub use provider::{
    ARM_QUEUE_GET_PATH_TEMPLATE, ARM_QUEUE_LIST_PATH_TEMPLATE, AzureServiceBusHttpResponse,
    AzureServiceBusProvider, AzureServiceBusProviderError, AzureServiceBusProviderIdentity,
    AzureServiceBusTransport, BlockedEnvAzureServiceBusTransport, BlockedEnvTransport,
    FakeAzureServiceBusTransport, FixtureAzureServiceBusTransport,
    LoopbackAzureServiceBusTransport, ProviderDefinitionError, ProviderProvenance, RecordedRequest,
    RecordingAzureServiceBusTransport, is_access_loss,
};
pub use service::{
    AzureServiceBusCapabilities, AzureServiceBusQueueResultProposal,
    AzureServiceBusQueueResultService, AzureServiceBusQueueResultServiceError,
    AzureServiceBusReadResult, AzureServiceBusRecordReceipt, AzureServiceBusRegistration,
    AzureServiceBusRegistrationError, AzureServiceBusRegistrationState,
    AzureServiceBusVerifiedRecord,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.azure-service-bus-queue-result.contract/v1";
pub const CONTRACT_VERSION: &str = "EXT-AZURE-SERVICE-BUS-01-L1/v1";
pub const PLUGIN_ID: &str = "azure-service-bus-queue-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "azure.service-bus.queue-result.read";
pub const PROVIDER_ID: &str = "azure.service-bus.control-plane.recording";
pub const PROVIDER_API_REVISION: &str = "servicebus-queues-get-list-2026-01-01-r1";
pub const CONSUMER_ID: &str = "mission.azure-service-bus.queue-result";
pub const AZURE_SERVICE_BUS_API_VERSION: &str = "2026-01-01";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/azure-service-bus-queue-result/azure-service-bus-queue-result.v1.json"
);

pub const AZURE_SERVICE_BUS_QUEUE_RESULT_SCHEMA_VERSION: &str = CONTRACT_SCHEMA;
pub const AZURE_SERVICE_BUS_QUEUE_RESULT_CONTRACT_VERSION: &str = CONTRACT_VERSION;
pub const AZURE_SERVICE_BUS_QUEUE_RESULT_PLUGIN_VERSION: &str = PLUGIN_VERSION;
pub const AZURE_SERVICE_BUS_QUEUE_RESULT_SERVICE_ID: &str = SERVICE_ID;
pub const AZURE_SERVICE_BUS_QUEUE_RESULT_PROVIDER_ID: &str = PROVIDER_ID;
pub const AZURE_SERVICE_BUS_QUEUE_RESULT_CONSUMER_ID: &str = CONSUMER_ID;
pub const AZURE_SERVICE_BUS_QUEUE_RESULT_BLOCKED_ENV: &str = "BLOCKED_ENV";

/// SHA-256 digest of the checked-in versioned contract bytes.
pub fn contract_digest() -> Digest {
    model::sha256_digest(CONTRACT_JSON.as_bytes())
}

pub const fn plugin_version() -> (u16, u16, u16) {
    (1, 0, 0)
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContractError {
    #[error("Azure Service Bus contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("Azure Service Bus contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("Azure Service Bus contract identity is invalid: {0}")]
    Identity(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureServiceBusQueueResultContract {
    value: serde_json::Value,
}

impl AzureServiceBusQueueResultContract {
    pub fn baseline() -> Result<Self, ContractError> {
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
            "officialReferences",
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
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(PLUGIN_VERSION)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
        {
            return Err(ContractError::Identity("contract identity drifted"));
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("service is not an object"))?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AzureServiceBusQueueResultService")
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractError::Identity("service identity drifted"));
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("provider is not an object"))?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AzureServiceBusProvider")
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractError::Identity("provider identity drifted"));
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("consumer is not an object"))?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("MissionAzureServiceBusConsumer")
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
            || consumer.get("consentAuthority") != Some(&serde_json::Value::Bool(false))
            || consumer.get("effectAuthority") != Some(&serde_json::Value::Bool(false))
            || consumer.get("receiptAuthority") != Some(&serde_json::Value::Bool(false))
            || consumer.get("verificationAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractError::Identity("consumer identity drifted"));
        }
        let authority = object
            .get("authority")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("authority is not an object"))?;
        for key in [
            "truth",
            "consent",
            "effect",
            "receipt",
            "verification",
            "outcome",
            "connected",
            "native",
            "firstParty",
            "externalWrites",
            "messageDataPlane",
        ] {
            if authority.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(ContractError::Identity("authority boundary drifted"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod contract_tests {
    use super::{
        AzureServiceBusQueueResultContract, CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION,
    };

    #[test]
    fn checked_contract_is_layer_one_and_validates() {
        let contract = AzureServiceBusQueueResultContract::baseline().expect("contract");
        assert_eq!(contract.digest().as_str().len(), 64);
        let value = contract.value();
        assert_eq!(value["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(value["contractVersion"], CONTRACT_VERSION);
        assert_eq!(value["pluginVersion"], "1.0.0");
        assert!(CONTRACT_JSON.contains("2026-01-01"));
    }
}
