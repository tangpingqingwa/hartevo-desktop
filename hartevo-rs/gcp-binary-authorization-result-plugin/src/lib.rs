//! Standalone Layer-1 GCP Binary Authorization evidence plugin.
//!
//! The slice is deliberately bounded to policy/attestor GET metadata and a
//! digest-only `validateAttestationOccurrence` proposal/record/verify seam.
//! Fixture, recording, loopback, and `BLOCKED_ENV` transports are evidence
//! sources only. This crate never resolves credentials, performs a live GCP
//! request, mutates policy or attestors, signs, deploys, retains raw keys or
//! attestation payloads, creates a durable receipt, or adopts a Work Product.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

use hartevo_plugin_runtime::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId as RuntimeConsumerId,
    Digest as RuntimeDigest, PluginContributions, PluginDefinition, PluginError,
    PluginId as RuntimePluginId, PluginScope, PluginVersion, ProviderCardinality,
    ProviderDefinition, ProviderId as RuntimeProviderId, ServiceDefinition,
    ServiceId as RuntimeServiceId,
};
use serde_json::Value;
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConsumerError, MissionGcpBinaryAuthorizationConsumer, MissionGcpBinaryAuthorizationResult,
    MissionGcpBinaryAuthorizationState,
};
pub use model::*;
pub use provider::BinaryAuthorizationTransport as GcpBinaryAuthorizationTransport;
pub use provider::{
    AttestorGetRequest, AttestorGetResponse, BinaryAuthorizationTransport,
    BlockedEnvGcpBinaryAuthorizationTransport, BlockedEnvTransport,
    FakeGcpBinaryAuthorizationTransport, FakeTransport, FixtureGcpBinaryAuthorizationTransport,
    FixtureTransport, GcpBinaryAuthorizationProvider, GcpBinaryAuthorizationProviderApi,
    GcpBinaryAuthorizationProviderDefinition, GetPolicyRequest, LoopbackTransport,
    PolicyGetRequest, PolicyGetResponse, ProviderDefinitionError, ProviderError,
    ProviderProvenance, RecordingGcpBinaryAuthorizationTransport, TransportError,
    ValidateAttestationOccurrenceRequest, ValidationResponse, ValidationTransportResponse,
};
pub use provider::{
    AttestorGetRequest as GetAttestorRequest, AttestorGetResponse as GetAttestorResponse,
    RecordingGcpBinaryAuthorizationTransport as RecordingTransport,
};
pub use provider::{
    PolicyGetResponse as GetPolicyResponse, TransportError as GcpBinaryAuthorizationTransportError,
};
pub use service::{
    GcpBinaryAuthorizationCapability, GcpBinaryAuthorizationOperation,
    GcpBinaryAuthorizationProposal, GcpBinaryAuthorizationRecord, GcpBinaryAuthorizationService,
    GcpBinaryAuthorizationServiceDefinition, GcpBinaryAuthorizationServiceError,
    GcpBinaryAuthorizationVerification, PolicyReadEvidence, ValidateAttestationOccurrenceProposal,
    ValidateAttestationOccurrenceRecord, ValidateAttestationOccurrenceVerification,
    ValidationEvidence,
};

pub const GCP_BINARY_AUTHORIZATION_RESULT_SCHEMA_VERSION: &str =
    "hartevo.gcp-binary-authorization-result-contract/v1";
pub const GCP_BINARY_AUTHORIZATION_RESULT_CONTRACT_VERSION: &str =
    "gcp-binary-authorization-result-e1/v1";
pub const GCP_BINARY_AUTHORIZATION_RESULT_EVIDENCE_LEVEL: &str = "E1";
pub const GCP_BINARY_AUTHORIZATION_RESULT_PLUGIN_ID: &str = "gcp-binary-authorization-result";
pub const GCP_BINARY_AUTHORIZATION_RESULT_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const GCP_BINARY_AUTHORIZATION_RESULT_SERVICE_ID: &str = "gcp.binary-authorization.result";
pub const GCP_BINARY_AUTHORIZATION_RESULT_SERVICE_NAME: &str = "GcpBinaryAuthorizationService";
pub const GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_ID: &str = "gcp.binary-authorization";
pub const GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_NAME: &str = "GcpBinaryAuthorizationProvider";
pub const GCP_BINARY_AUTHORIZATION_RESULT_CONSUMER_ID: &str =
    "mission.gcp-binary-authorization.result";
pub const GCP_BINARY_AUTHORIZATION_RESULT_CONSUMER_NAME: &str =
    "MissionGcpBinaryAuthorizationConsumer";
pub const GCP_BINARY_AUTHORIZATION_RESULT_SERVICE_SCHEMA: &str =
    "hartevo.gcp-binary-authorization-result-service/v1";
pub const GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_SCHEMA: &str =
    "hartevo.gcp-binary-authorization-result-provider/v1";
pub const GCP_BINARY_AUTHORIZATION_RESULT_CONSUMER_SCHEMA: &str =
    "hartevo.mission-gcp-binary-authorization-result-consumer/v1";
pub const GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_REVISION: &str =
    "gcp-binary-authorization-rest-r1";
pub const GCP_BINARY_AUTHORIZATION_RESULT_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const GCP_BINARY_AUTHORIZATION_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/gcp-binary-authorization-result/gcp-binary-authorization-result.v1.json"
);

/// Short aliases retained for callers that use the provider product name.
pub const GCP_BINARY_AUTHORIZATION_SCHEMA_VERSION: &str =
    GCP_BINARY_AUTHORIZATION_RESULT_SCHEMA_VERSION;
pub const GCP_BINARY_AUTHORIZATION_CONTRACT_VERSION: &str =
    GCP_BINARY_AUTHORIZATION_RESULT_CONTRACT_VERSION;
pub const GCP_BINARY_AUTHORIZATION_SERVICE_ID: &str = GCP_BINARY_AUTHORIZATION_RESULT_SERVICE_ID;
pub const GCP_BINARY_AUTHORIZATION_PROVIDER_ID: &str = GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_ID;
pub const MISSION_GCP_BINARY_AUTHORIZATION_CONSUMER_ID: &str =
    GCP_BINARY_AUTHORIZATION_RESULT_CONSUMER_ID;

pub fn contract_digest() -> Digest {
    Digest::from_text(GCP_BINARY_AUTHORIZATION_RESULT_CONTRACT_JSON)
}

pub fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Parsed checked-in contract document. Validation is intentionally explicit
/// so a contract edit cannot silently grant native or kernel authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpBinaryAuthorizationContract {
    document: Value,
}

impl GcpBinaryAuthorizationContract {
    pub fn baseline() -> Result<Self, GcpBinaryAuthorizationContractError> {
        let document = serde_json::from_str::<Value>(GCP_BINARY_AUTHORIZATION_RESULT_CONTRACT_JSON)
            .map_err(|error| GcpBinaryAuthorizationContractError::Parse(error.to_string()))?;
        let contract = Self { document };
        contract.validate()?;
        Ok(contract)
    }

    pub fn document(&self) -> &Value {
        &self.document
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<(), GcpBinaryAuthorizationContractError> {
        let service_operations = [
            "describe_capabilities",
            "register",
            "revoke_registration",
            "get_policy",
            "get_attestor",
            "propose_validate_attestation_occurrence",
            "record_validate_attestation_occurrence",
            "verify_validate_attestation_occurrence",
            "consume_observation",
        ];
        let provider_operations = [
            "get_policy",
            "get_attestor",
            "validateAttestationOccurrence",
        ];
        let decisions = ["allow", "deny", "error", "unknown"];
        let provenance = ["fixture", "recording", "loopback", "blocked_env"];
        let required_scope = [
            "projectId",
            "policyId",
            "attestorIds",
            "imageDigest",
            "platform",
            "projectIdAndRevision",
            "missionIdAndRevision",
            "workProductIdAndRevision",
            "permissionDigest",
            "consentDigest",
            "secretReferenceDigest",
            "credentialRevision",
        ];
        let valid = self.document["schemaVersion"]
            == GCP_BINARY_AUTHORIZATION_RESULT_SCHEMA_VERSION
            && self.document["contractVersion"] == GCP_BINARY_AUTHORIZATION_RESULT_CONTRACT_VERSION
            && self.document["evidenceLevel"] == GCP_BINARY_AUTHORIZATION_RESULT_EVIDENCE_LEVEL
            && self.document["layer"] == 1
            && self.document["service"]["id"] == GCP_BINARY_AUTHORIZATION_RESULT_SERVICE_ID
            && self.document["service"]["name"] == GCP_BINARY_AUTHORIZATION_RESULT_SERVICE_NAME
            && self.document["service"]["version"]
                == GCP_BINARY_AUTHORIZATION_RESULT_PLUGIN_VERSION_TEXT
            && self.document["service"]["readOnly"] == Value::Bool(true)
            && self.document["service"]["native"] == Value::Bool(false)
            && string_array(&self.document["service"]["operations"]) == service_operations
            && self.document["provider"]["id"] == GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_ID
            && self.document["provider"]["name"] == GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_NAME
            && self.document["provider"]["providerRevision"]
                == GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_REVISION
            && string_array(&self.document["provider"]["operations"]) == provider_operations
            && provenance.iter().all(|value| {
                self.document["provider"]["acceptedProvenance"]
                    .as_array()
                    .is_some_and(|values| values.iter().any(|item| item == value))
            })
            && self.document["provider"]["native"] == Value::Bool(false)
            && self.document["provider"]["liveExecution"] == Value::Bool(false)
            && self.document["provider"]["credentialResolution"] == Value::Bool(false)
            && self.document["provider"]["rawKeys"] == Value::Bool(false)
            && self.document["provider"]["rawAttestationPayload"] == Value::Bool(false)
            && self.document["provider"]["containerBytes"] == Value::Bool(false)
            && self.document["provider"]["policyMutation"] == Value::Bool(false)
            && self.document["provider"]["attestorMutation"] == Value::Bool(false)
            && self.document["provider"]["signing"] == Value::Bool(false)
            && self.document["provider"]["deployment"] == Value::Bool(false)
            && self.document["provider"]["consentEffectBypass"] == Value::Bool(false)
            && self.document["consumer"]["id"] == GCP_BINARY_AUTHORIZATION_RESULT_CONSUMER_ID
            && self.document["consumer"]["name"] == GCP_BINARY_AUTHORIZATION_RESULT_CONSUMER_NAME
            && self.document["consumer"]["missionBound"] == Value::Bool(true)
            && self.document["consumer"]["projectBound"] == Value::Bool(true)
            && self.document["consumer"]["workProductBound"] == Value::Bool(true)
            && self.document["consumer"]["adoptsOutcome"] == Value::Bool(false)
            && self.document["consumer"]["truthAuthority"] == Value::Bool(false)
            && self.document["consumer"]["nativeConnected"] == Value::Bool(false)
            && required_scope.iter().all(|value| {
                self.document["scope"]["required"]
                    .as_array()
                    .is_some_and(|values| values.iter().any(|item| item == value))
            })
            && self.document["validation"]["operation"] == "validateAttestationOccurrence"
            && self.document["validation"]["proposalRecordVerify"] == Value::Bool(true)
            && string_array(&self.document["validation"]["decisions"]) == decisions
            && self.document["validation"]["imageDigestBound"] == Value::Bool(true)
            && self.document["validation"]["requiresConsentEffectFence"] == Value::Bool(true)
            && self.document["validation"]["bypassesKernelConsentEffect"] == Value::Bool(false)
            && self.document["registration"]["reversible"] == Value::Bool(true)
            && self.document["registration"]["revocable"] == Value::Bool(true)
            && self.document["registration"]["failClosedOnDrift"] == Value::Bool(true)
            && self.document["authority"]["connected"] == Value::Bool(false)
            && self.document["authority"]["nativeProvider"] == Value::Bool(false)
            && self.document["authority"]["consent"] == Value::Bool(false)
            && self.document["authority"]["effect"] == Value::Bool(false)
            && self.document["authority"]["receipt"] == Value::Bool(false)
            && self.document["authority"]["verification"] == Value::Bool(false)
            && self.document["authority"]["outcome"] == Value::Bool(false)
            && self.document["authority"]["workProductAdoption"] == Value::Bool(false)
            && self.document["nativeGap"]["status"] == GCP_BINARY_AUTHORIZATION_RESULT_BLOCKED_ENV
            && self.document["honestNativeGap"]
                .as_str()
                .is_some_and(|value| value.contains(GCP_BINARY_AUTHORIZATION_RESULT_BLOCKED_ENV))
            && self.document["honestNativeGap"]
                .as_str()
                .is_some_and(|value| value.contains("never bypasses kernel Consent/Effect"));
        if valid {
            Ok(())
        } else {
            Err(GcpBinaryAuthorizationContractError::Mismatch)
        }
    }
}

fn string_array(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GcpBinaryAuthorizationContractError {
    #[error("contract JSON could not be parsed: {0}")]
    Parse(String),
    #[error("checked-in GCP Binary Authorization contract does not match the Layer-1 baseline")]
    Mismatch,
}

/// Builds a runtime contribution set for one exact Project/Mission scope.
/// Mounting and revocation remain host-owned and reversible.
pub fn plugin_definition(scope: PluginScope) -> Result<PluginDefinition, PluginError> {
    let plugin_id = RuntimePluginId::new(GCP_BINARY_AUTHORIZATION_RESULT_PLUGIN_ID)?;
    let service_id = RuntimeServiceId::new(GCP_BINARY_AUTHORIZATION_RESULT_SERVICE_ID)?;
    let provider_id = RuntimeProviderId::new(GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_ID)?;
    let consumer_id = RuntimeConsumerId::new(GCP_BINARY_AUTHORIZATION_RESULT_CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(GCP_BINARY_AUTHORIZATION_RESULT_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(GCP_BINARY_AUTHORIZATION_RESULT_CONSUMER_SCHEMA),
        )?],
        events: Vec::new(),
        ui_surfaces: Vec::new(),
    };
    PluginDefinition::new(plugin_id, version, scope, contributions)
}

/// Layer-1 authority facts are all negative. The provider can produce a
/// typed proposal or recording but cannot become Connected, native, Consent,
/// Effect, Receipt, Verification, Outcome, or Work Product authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn consent() -> bool {
        false
    }

    pub const fn effect() -> bool {
        false
    }

    pub const fn durable_receipt() -> bool {
        false
    }

    pub const fn verification() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }

    pub const fn work_product_adoption() -> bool {
        false
    }

    pub const fn raw_keys() -> bool {
        false
    }

    pub const fn raw_attestation_payload() -> bool {
        false
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("GCP Binary Authorization Layer-1 error: {message}")]
pub struct GcpBinaryAuthorizationError {
    pub message: String,
}

#[cfg(test)]
mod contract_document_tests {
    use super::*;

    #[test]
    fn checked_in_contract_is_layer_one_and_honest() {
        let contract = GcpBinaryAuthorizationContract::baseline().expect("contract");
        assert_eq!(contract.digest(), contract_digest());
        assert_eq!(GCP_BINARY_AUTHORIZATION_RESULT_BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::consent());
        assert!(!Layer1Authority::effect());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::verification());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::work_product_adoption());
        assert!(!Layer1Authority::raw_keys());
        assert!(!Layer1Authority::raw_attestation_payload());
    }

    #[test]
    fn plugin_definition_is_scoped_and_read_only() {
        let scope = PluginScope::new(
            hartevo_plugin_runtime::ProjectId::new("project-1").expect("project"),
            hartevo_plugin_runtime::MissionId::new("mission-1").expect("mission"),
            3,
        )
        .expect("scope");
        let definition = plugin_definition(scope).expect("definition");
        assert_eq!(definition.scope().generation(), 3);
        assert_eq!(definition.contributions().services.len(), 1);
        assert_eq!(definition.contributions().providers.len(), 1);
        assert_eq!(definition.contributions().consumers.len(), 1);
    }
}
