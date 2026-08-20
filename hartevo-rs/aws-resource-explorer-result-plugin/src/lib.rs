//! Standalone Layer-1 governed AWS Resource Explorer inventory result plugin.
//!
//! The crate exposes typed `AwsResourceExplorerService`,
//! `AwsResourceExplorerProvider`, and `MissionAwsResourceExplorerConsumer`
//! seams for bounded `Search`/`ListIndexes` evidence. It never resolves
//! credentials, signs native SigV4 requests, mutates an index/view/resource,
//! retains raw properties/tags/PII, claims Connected/native authority, claims
//! deployment or compliance authority, or adopts a kernel Outcome.

#![forbid(unsafe_code)]
#![allow(
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::type_complexity
)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionAwsResourceExplorerConsumer, MissionAwsResourceExplorerConsumerError,
    MissionAwsResourceExplorerObservation, MissionAwsResourceExplorerResult,
    MissionAwsResourceExplorerResultConsumer, MissionAwsResourceExplorerState,
};
pub use model::*;
pub use provider::{
    AWS_RESOURCE_EXPLORER_API_REVISION, AWS_RESOURCE_EXPLORER_PROVIDER_ID,
    AWS_RESOURCE_EXPLORER_PROVIDER_SCHEMA, AWS_RESOURCE_EXPLORER_PROVIDER_VERSION,
    AwsResourceExplorerListIndexesRequest, AwsResourceExplorerOpaqueCursor,
    AwsResourceExplorerProvider, AwsResourceExplorerProviderDefinition,
    AwsResourceExplorerProviderError, AwsResourceExplorerProviderErrorKind,
    AwsResourceExplorerProviderIdentity, AwsResourceExplorerSearchRequest,
    AwsResourceExplorerTransport, BlockedEnvAwsResourceExplorerTransport,
    FakeAwsResourceExplorerTransport, FixtureAwsResourceExplorerTransport, ListIndexesPage,
    ListIndexesRequest, LoopbackAwsResourceExplorerTransport, OpaqueCursor, OpaquePageToken,
    OpaquePageTokenPlaceholder, ProviderDefinitionError, RecordingAwsResourceExplorerTransport,
    SearchPage, SearchRequest, TransportError, required_permission,
};
pub use service::{
    AWS_RESOURCE_EXPLORER_SERVICE_ID, AWS_RESOURCE_EXPLORER_SERVICE_NAME,
    AWS_RESOURCE_EXPLORER_SERVICE_SCHEMA, AwsResourceExplorerCapability,
    AwsResourceExplorerProposal, AwsResourceExplorerProposalEnvelope, AwsResourceExplorerRecord,
    AwsResourceExplorerRecordReceipt, AwsResourceExplorerRegistration, AwsResourceExplorerService,
    AwsResourceExplorerServiceDefinition, AwsResourceExplorerServiceError,
    AwsResourceExplorerVerification, AwsResourceExplorerVerificationReport,
    MISSION_AWS_RESOURCE_EXPLORER_CONSUMER_ID, MISSION_AWS_RESOURCE_EXPLORER_CONSUMER_SCHEMA,
    RegistrationError, RegistrationState,
};

pub const AWS_RESOURCE_EXPLORER_SCHEMA_VERSION: &str =
    "hartevo.aws-resource-explorer-result-contract/v1";
pub const AWS_RESOURCE_EXPLORER_CONTRACT_VERSION: &str = "aws-resource-explorer-result/v1";
pub const AWS_RESOURCE_EXPLORER_PLUGIN_VERSION: &str = "1.0.0";
pub const AWS_RESOURCE_EXPLORER_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AWS_RESOURCE_EXPLORER_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-resource-explorer-result/aws-resource-explorer-result.v1.json"
);

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_bytes(AWS_RESOURCE_EXPLORER_CONTRACT_JSON.as_bytes())
}

#[must_use]
pub fn version_digest() -> Digest {
    Digest::from_text(AWS_RESOURCE_EXPLORER_PLUGIN_VERSION)
}

#[must_use]
pub fn provider_schema_digest() -> Digest {
    Digest::from_text(AWS_RESOURCE_EXPLORER_PROVIDER_SCHEMA)
}

#[must_use]
pub fn permission_digest() -> Digest {
    PermissionFence::for_layer_one(1)
        .expect("Layer-1 permission fence is valid")
        .digest()
}

#[must_use]
pub const fn contract_json_is_embedded() -> bool {
    !AWS_RESOURCE_EXPLORER_CONTRACT_JSON.is_empty()
}

#[must_use]
pub const fn consumer_id() -> &'static str {
    MISSION_AWS_RESOURCE_EXPLORER_CONSUMER_ID
}

#[must_use]
pub const fn provider_revision() -> &'static str {
    AWS_RESOURCE_EXPLORER_API_REVISION
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsResourceExplorerContract {
    value: serde_json::Value,
}

impl AwsResourceExplorerContract {
    pub fn baseline() -> Result<Self, AwsResourceExplorerContractError> {
        let value = serde_json::from_str::<serde_json::Value>(AWS_RESOURCE_EXPLORER_CONTRACT_JSON)
            .map_err(|error| AwsResourceExplorerContractError::InvalidJson(error.to_string()))?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    #[must_use]
    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<(), AwsResourceExplorerContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(AwsResourceExplorerContractError::Shape(
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
            "allowlist",
            "registration",
            "bounds",
            "evidence",
            "redaction",
            "authority",
            "honesty",
            "layer2Gaps",
        ] {
            if !object.contains_key(key) {
                return Err(AwsResourceExplorerContractError::Shape(
                    "required contract key missing",
                ));
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(AWS_RESOURCE_EXPLORER_SCHEMA_VERSION)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_RESOURCE_EXPLORER_CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_RESOURCE_EXPLORER_PLUGIN_VERSION)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
        {
            return Err(AwsResourceExplorerContractError::Identity(
                "contract identity drifted",
            ));
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsResourceExplorerContractError::Shape(
                "service is not an object",
            ))?;
        if service.get("id").and_then(serde_json::Value::as_str)
            != Some(AWS_RESOURCE_EXPLORER_SERVICE_ID)
            || service
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_RESOURCE_EXPLORER_SERVICE_NAME)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsResourceExplorerContractError::Identity(
                "service identity drifted",
            ));
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsResourceExplorerContractError::Shape(
                "provider is not an object",
            ))?;
        if provider.get("id").and_then(serde_json::Value::as_str)
            != Some(AWS_RESOURCE_EXPLORER_PROVIDER_ID)
            || provider
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AwsResourceExplorerProvider")
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsResourceExplorerContractError::Identity(
                "provider identity drifted",
            ));
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsResourceExplorerContractError::Shape(
                "consumer is not an object",
            ))?;
        if consumer.get("id").and_then(serde_json::Value::as_str)
            != Some(MISSION_AWS_RESOURCE_EXPLORER_CONSUMER_ID)
            || consumer
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("MissionAwsResourceExplorerConsumer")
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
            || consumer.get("deployabilityAuthority") != Some(&serde_json::Value::Bool(false))
            || consumer.get("complianceAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsResourceExplorerContractError::Identity(
                "consumer identity drifted",
            ));
        }
        let authority = object
            .get("authority")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsResourceExplorerContractError::Shape(
                "authority is not an object",
            ))?;
        for key in [
            "externalWrites",
            "indexMutation",
            "viewMutation",
            "resourceMutation",
            "tagMutation",
            "rawPropertyBag",
            "credentialResolution",
            "connected",
            "native",
            "durableReceipt",
            "deployability",
            "compliance",
            "kernelOutcomeAdoption",
        ] {
            if authority.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(AwsResourceExplorerContractError::Boundary(
                    "Layer-1 authority widened",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum AwsResourceExplorerContractError {
    #[error("AWS Resource Explorer contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("AWS Resource Explorer contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("AWS Resource Explorer contract identity is invalid: {0}")]
    Identity(&'static str),
    #[error("AWS Resource Explorer contract authority boundary is invalid: {0}")]
    Boundary(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    #[must_use]
    pub const fn connected() -> bool {
        false
    }

    #[must_use]
    pub const fn native() -> bool {
        false
    }

    #[must_use]
    pub const fn external_writes() -> bool {
        false
    }

    #[must_use]
    pub const fn raw_properties() -> bool {
        false
    }

    #[must_use]
    pub const fn raw_tags() -> bool {
        false
    }

    #[must_use]
    pub const fn raw_pii() -> bool {
        false
    }

    #[must_use]
    pub const fn deployment_or_compliance_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn adopted_outcome() -> bool {
        false
    }
}
