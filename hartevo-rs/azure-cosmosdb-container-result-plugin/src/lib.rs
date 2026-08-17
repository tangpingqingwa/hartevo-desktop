//! Standalone Layer-1 governed Azure Cosmos DB container-posture result slice.
//!
//! This crate emits bounded, redacted management-plane evidence and a Mission
//! review proposal.  It does not resolve Entra credentials, perform live ARM
//! HTTPS, read the Cosmos data plane, retain provider payloads, mutate a
//! resource, or exercise Hartevo Truth, Consent, Effect, Receipt,
//! Verification, or Outcome authority.

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
    ConsumerError, MissionAzureCosmosContainerConsumer, MissionAzureCosmosContainerObservation,
    MissionAzureCosmosContainerResult, MissionDecisionState,
};
pub use model::*;
pub use provider::{
    AccountResourceProjection, AzureCosmosGetRequest, AzureCosmosOperation,
    AzureCosmosProviderDefinition, AzureCosmosProviderDefinition as ProviderDefinition,
    AzureCosmosProviderError, AzureCosmosProviderErrorCode, AzureCosmosResourceProjection,
    AzureCosmosResourceProvider, AzureCosmosResourceProviderDefinition,
    AzureCosmosResourceResponse, AzureCosmosTransport, BlockedEnvAzureCosmosTransport,
    BlockedEnvTransport, EntraSecretReference, FakeAzureCosmosTransport, FakeTransport,
    FixtureAzureCosmosTransport, FixtureTransport, LoopbackAzureCosmosTransport, LoopbackTransport,
    ProviderProvenance, RecordedRequest, RecordingAzureCosmosTransport, RecordingTransport,
    SqlContainerResourceProjection, SqlDatabaseResourceProjection, ThroughputResourceProjection,
    is_access_loss,
};
pub use service::{
    AzureCosmosCapabilities, AzureCosmosContainerProposal, AzureCosmosContainerResultService,
    AzureCosmosReadRequest, AzureCosmosRecordReceipt, AzureCosmosRegistration,
    AzureCosmosRegistrationRequest, AzureCosmosService, AzureCosmosServiceError,
    AzureCosmosServiceVerificationReport, AzureCosmosTransportFailure, ProposalVerification,
    RegistrationState, RegistrationTransitionEvidence, ServiceVerificationStatus,
};

pub const AZURE_COSMOS_SCHEMA_VERSION: &str = "hartevo.azure-cosmosdb-container-result.contract/v1";
pub const AZURE_COSMOS_CONTRACT_VERSION: &str = "azure-cosmosdb-container-result/v1";
pub const AZURE_COSMOS_PLUGIN_VERSION: &str = "1.0.0";
pub const AZURE_COSMOS_SERVICE_ID: &str = "hartevo.azure.cosmosdb.container-result";
pub const AZURE_COSMOS_PROVIDER_ID: &str = "azure.cosmosdb.resource";
pub const AZURE_COSMOS_PROVIDER_VERSION: &str = "1.0.0";
pub const AZURE_COSMOS_PROVIDER_REVISION: &str = "azure-cosmosdb-arm-read-r1";
pub const AZURE_COSMOS_API_VERSION: &str = "2024-11-01";
pub const AZURE_COSMOS_API_REVISION: &str = "azure-cosmosdb-arm-read-r1";
pub const AZURE_COSMOS_CONSUMER_ID: &str = "mission.azure.cosmosdb.container-result";
pub const AZURE_COSMOS_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AZURE_COSMOS_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/azure-cosmosdb-container-result/azure-cosmosdb-container-result.v1.json"
);

pub fn contract_digest() -> Digest {
    model::sha256_digest(AZURE_COSMOS_CONTRACT_JSON.as_bytes())
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AzureCosmosContractError {
    #[error("Azure Cosmos contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("Azure Cosmos contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("Azure Cosmos contract identity is invalid: {0}")]
    Identity(&'static str),
    #[error("Azure Cosmos contract authority boundary is invalid: {0}")]
    Authority(&'static str),
    #[error("Azure Cosmos provider boundary is invalid: {0}")]
    ProviderBoundary(&'static str),
    #[error("Azure Cosmos contract model is invalid: {0}")]
    Model(ModelError),
}

impl From<ModelError> for AzureCosmosContractError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureCosmosContainerResultContract {
    value: Value,
}

impl AzureCosmosContainerResultContract {
    pub fn baseline() -> Result<Self, AzureCosmosContractError> {
        let value = serde_json::from_str::<Value>(AZURE_COSMOS_CONTRACT_JSON)
            .map_err(|error| AzureCosmosContractError::InvalidJson(error.to_string()))?;
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

    pub fn validate(&self) -> Result<(), AzureCosmosContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(AzureCosmosContractError::Shape("contract is not an object"))?;
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
                return Err(AzureCosmosContractError::Shape(
                    "required contract key missing",
                ));
            }
        }
        if object.get("schemaVersion").and_then(Value::as_str) != Some(AZURE_COSMOS_SCHEMA_VERSION)
            || object.get("contractVersion").and_then(Value::as_str)
                != Some(AZURE_COSMOS_CONTRACT_VERSION)
            || object.get("pluginVersion").and_then(Value::as_str)
                != Some(AZURE_COSMOS_PLUGIN_VERSION)
            || object.get("layer").and_then(Value::as_str) != Some("Layer-1")
        {
            return Err(AzureCosmosContractError::Identity(
                "contract identity drifted",
            ));
        }
        let service = object
            .get("service")
            .and_then(Value::as_object)
            .ok_or(AzureCosmosContractError::Shape("service is not an object"))?;
        if service.get("id").and_then(Value::as_str) != Some(AZURE_COSMOS_SERVICE_ID)
            || service.get("implementation").and_then(Value::as_str)
                != Some("AzureCosmosContainerResultService")
            || service.get("readOnly") != Some(&Value::Bool(true))
            || service.get("proposalOnly") != Some(&Value::Bool(true))
            || service.get("liveExecution") != Some(&Value::Bool(false))
            || service.get("externalWrites") != Some(&Value::Bool(false))
        {
            return Err(AzureCosmosContractError::Identity(
                "service identity drifted",
            ));
        }
        let provider = object
            .get("provider")
            .and_then(Value::as_object)
            .ok_or(AzureCosmosContractError::Shape("provider is not an object"))?;
        if provider.get("id").and_then(Value::as_str) != Some(AZURE_COSMOS_PROVIDER_ID)
            || provider.get("implementation").and_then(Value::as_str)
                != Some("AzureCosmosResourceProvider")
            || provider.get("apiVersion").and_then(Value::as_str) != Some(AZURE_COSMOS_API_VERSION)
            || provider.get("native") != Some(&Value::Bool(false))
            || provider.get("connected") != Some(&Value::Bool(false))
            || provider.get("first_party") != Some(&Value::Bool(false))
            || provider.get("externalWrites") != Some(&Value::Bool(false))
            || provider.get("dataPlane") != Some(&Value::Bool(false))
            || provider.get("allowlistedMethods")
                != Some(&Value::Array(vec![Value::String("GET".to_owned())]))
        {
            return Err(AzureCosmosContractError::Authority(
                "provider boundary drifted",
            ));
        }
        let consumer = object
            .get("consumer")
            .and_then(Value::as_object)
            .ok_or(AzureCosmosContractError::Shape("consumer is not an object"))?;
        if consumer.get("id").and_then(Value::as_str) != Some(AZURE_COSMOS_CONSUMER_ID)
            || consumer.get("implementation").and_then(Value::as_str)
                != Some("MissionAzureCosmosContainerConsumer")
            || consumer.get("adoptsOutcome") != Some(&Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&Value::Bool(false))
        {
            return Err(AzureCosmosContractError::Authority(
                "consumer boundary drifted",
            ));
        }
        let authority = object.get("authority").and_then(Value::as_object).ok_or(
            AzureCosmosContractError::Shape("authority is not an object"),
        )?;
        for key in [
            "externalWrites",
            "dataPlaneRead",
            "keyRetrieval",
            "connectionStringRetrieval",
            "resourceMutation",
            "throughputMutation",
            "indexingMutation",
            "partitionMutation",
            "networkMutation",
            "native",
            "connected",
            "firstParty",
            "truthAuthority",
            "consentAuthority",
            "effectAuthority",
            "receiptAuthority",
            "verificationAuthority",
            "outcomeAuthority",
            "workProductAdoption",
        ] {
            if authority.get(key) != Some(&Value::Bool(false)) {
                return Err(AzureCosmosContractError::Authority(
                    "Layer-1 authority widened",
                ));
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

    pub const fn durable_receipt() -> bool {
        false
    }

    pub const fn truth_authority() -> bool {
        false
    }

    pub const fn consent_authority() -> bool {
        false
    }

    pub const fn effect_authority() -> bool {
        false
    }

    pub const fn outcome_authority() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_in_contract_matches_typed_boundary() {
        let contract = AzureCosmosContainerResultContract::baseline().expect("contract");
        assert_eq!(contract.digest(), contract_digest());
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::truth_authority());
        assert!(!Layer1Authority::outcome_authority());
    }
}
