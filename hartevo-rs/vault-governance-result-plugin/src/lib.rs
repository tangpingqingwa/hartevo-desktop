//! Layer-1 Vault governance-result plugin.
//!
//! This crate exposes bounded health, token-self, capability-self, and lease
//! metadata evidence for a Mission.  It is intentionally not a secret store,
//! auth client, effect authority, receipt authority, or native Connected
//! provider.  Native authentication/HTTPS remains an explicit Layer-2 gap.

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
    clippy::too_many_lines
)]

use hartevo_plugin_runtime::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId, Digest as RuntimeDigest,
    PluginContributions, PluginDefinition, PluginError, PluginId, PluginScope, PluginVersion,
    ProviderCardinality, ProviderDefinition, ProviderId, ServiceDefinition, ServiceId,
};
use serde_json::Value;
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{
    MissionVaultGovernanceConsumer, MissionVaultGovernanceObservation,
    MissionVaultGovernanceResult, MissionVaultGovernanceState,
};
pub use model::*;
pub use provider::{
    ProviderDefinitionError, RegistrationState, VaultProvider, VaultProviderDefinition,
    VaultProviderError, VaultRegistration, VaultStatusClass, classify_status,
};
pub use service::{
    VaultGovernanceCapability, VaultGovernanceOperation, VaultGovernanceProposal,
    VaultGovernanceRecord, VaultGovernanceResultService, VaultVerification,
};
pub use transport::{
    BlockedEnvTransport, BlockedEnvVaultTransport, FakeVaultTransport, FixtureVaultTransport,
    LoopbackVaultTransport, RecordingVaultTransport, VaultEndpoint, VaultHttpResponse,
    VaultRequest, VaultTransport, VaultTransportError,
};

pub const VAULT_GOVERNANCE_RESULT_SCHEMA_VERSION: &str =
    "hartevo.vault-governance-result-contract/v1";
pub const VAULT_GOVERNANCE_RESULT_CONTRACT_VERSION: &str = "vault-governance-result-e1/v1";
pub const VAULT_GOVERNANCE_RESULT_EVIDENCE_LEVEL: &str = "E1";
pub const VAULT_GOVERNANCE_RESULT_PLUGIN_ID: &str = "vault-governance-result";
pub const VAULT_GOVERNANCE_RESULT_SERVICE_ID: &str = "vault.governance.result";
pub const VAULT_GOVERNANCE_RESULT_PROVIDER_ID: &str = "vault.governance";
pub const MISSION_VAULT_GOVERNANCE_CONSUMER_ID: &str = "mission.vault-governance-result";
pub const VAULT_GOVERNANCE_RESULT_SERVICE_VERSION: &str = "1.0.0";
pub const VAULT_GOVERNANCE_RESULT_SERVICE_NAME: &str = "VaultGovernanceResultService";
pub const VAULT_GOVERNANCE_RESULT_PROVIDER_NAME: &str = "VaultProvider";
pub const MISSION_VAULT_GOVERNANCE_CONSUMER_NAME: &str = "MissionVaultGovernanceConsumer";
pub const VAULT_GOVERNANCE_RESULT_SERVICE_SCHEMA: &str =
    "hartevo.vault-governance-result-service/v1";
pub const VAULT_GOVERNANCE_RESULT_PROVIDER_SCHEMA: &str =
    "hartevo.vault-governance-result-provider/v1";
pub const VAULT_GOVERNANCE_RESULT_CONSUMER_SCHEMA: &str =
    "hartevo.mission-vault-governance-result-consumer/v1";
pub const VAULT_GOVERNANCE_RESULT_PROVIDER_REVISION: &str = "vault-http-governance-r1";
pub const VAULT_GOVERNANCE_RESULT_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const VAULT_GOVERNANCE_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/vault-governance-result/vault-governance-result.v1.json"
);

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum VaultGovernanceError {
    #[error("Vault governance contract is invalid: {0}")]
    Contract(String),
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Provider(#[from] VaultProviderError),
    #[error("Vault governance proposal or record digest does not match")]
    EvidenceDigestMismatch,
    #[error("Vault governance evidence is stale for the Mission scope")]
    StaleEvidence,
    #[error("Vault governance evidence scope does not match the Mission scope")]
    ScopeMismatch,
    #[error("plugin runtime rejected the Vault governance contribution: {0}")]
    Plugin(#[from] PluginError),
}

pub fn contract_digest() -> Digest {
    Digest::from_bytes(VAULT_GOVERNANCE_RESULT_CONTRACT_JSON.as_bytes())
}

pub fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Parses and validates the checked-in versioned contract, including its
/// Layer-1 honesty and native-gap claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultGovernanceResultContract {
    document: Value,
}

impl VaultGovernanceResultContract {
    pub fn baseline() -> Result<Self, VaultGovernanceError> {
        let document = serde_json::from_str::<Value>(VAULT_GOVERNANCE_RESULT_CONTRACT_JSON)
            .map_err(|error| VaultGovernanceError::Contract(error.to_string()))?;
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

    pub fn validate(&self) -> Result<(), VaultGovernanceError> {
        let operations = [
            "describe_capabilities",
            "register",
            "revoke_registration",
            "propose_governance_read",
            "record_evidence",
            "verify_evidence",
            "consume_observation",
        ];
        let provider_operations = [
            "sys_health",
            "auth_token_lookup_self",
            "sys_capabilities_self_allowlisted",
            "sys_leases_lookup_metadata",
        ];
        let provenance = ["fixture", "recording", "loopback", "blocked_env"];
        let required_scope = [
            "namespace",
            "mount",
            "allowlistedPaths",
            "policyDigest",
            "leaseScopeDigest",
            "missionIdAndRevision",
            "projectIdAndRevision",
            "secretReferenceDigest",
            "credentialRevision",
        ];
        let layer2_gaps = self
            .document
            .get("layer2Gaps")
            .and_then(Value::as_array)
            .is_some_and(|values| !values.is_empty());
        let authority_is_false = [
            "connected",
            "nativeProvider",
            "effect",
            "receipt",
            "verification",
            "outcome",
            "workProductAdoption",
        ]
        .iter()
        .all(|field| self.document["authority"][*field] == Value::Bool(false));
        let honest_gap = self
            .document
            .get("honestNativeGap")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let valid = self.document["schemaVersion"] == VAULT_GOVERNANCE_RESULT_SCHEMA_VERSION
            && self.document["contractVersion"] == VAULT_GOVERNANCE_RESULT_CONTRACT_VERSION
            && self.document["evidenceLevel"] == VAULT_GOVERNANCE_RESULT_EVIDENCE_LEVEL
            && self.document["layer"] == 1
            && self.document["service"]["id"] == VAULT_GOVERNANCE_RESULT_SERVICE_ID
            && self.document["service"]["name"] == VAULT_GOVERNANCE_RESULT_SERVICE_NAME
            && self.document["service"]["version"] == VAULT_GOVERNANCE_RESULT_SERVICE_VERSION
            && self.document["service"]["readOnly"] == Value::Bool(true)
            && self.document["service"]["native"] == Value::Bool(false)
            && string_array(&self.document["service"]["operations"]) == operations
            && self.document["provider"]["id"] == VAULT_GOVERNANCE_RESULT_PROVIDER_ID
            && self.document["provider"]["name"] == VAULT_GOVERNANCE_RESULT_PROVIDER_NAME
            && self.document["provider"]["version"] == VAULT_GOVERNANCE_RESULT_SERVICE_VERSION
            && self.document["provider"]["providerRevision"]
                == VAULT_GOVERNANCE_RESULT_PROVIDER_REVISION
            && string_array(&self.document["provider"]["operations"]) == provider_operations
            && provenance.iter().all(|value| {
                self.document["provider"]["acceptedProvenance"]
                    .as_array()
                    .is_some_and(|values| values.iter().any(|item| item == value))
            })
            && self.document["provider"]["native"] == Value::Bool(false)
            && self.document["provider"]["secretValuesRead"] == Value::Bool(false)
            && self.document["provider"]["tokenMaterialRetained"] == Value::Bool(false)
            && self.document["provider"]["login"] == Value::Bool(false)
            && self.document["provider"]["policyMutation"] == Value::Bool(false)
            && self.document["provider"]["leaseRenew"] == Value::Bool(false)
            && self.document["provider"]["leaseRevoke"] == Value::Bool(false)
            && self.document["provider"]["rootTokenPaths"] == Value::Bool(false)
            && self.document["consumer"]["id"] == MISSION_VAULT_GOVERNANCE_CONSUMER_ID
            && self.document["consumer"]["name"] == MISSION_VAULT_GOVERNANCE_CONSUMER_NAME
            && self.document["consumer"]["missionBound"] == Value::Bool(true)
            && self.document["consumer"]["projectBound"] == Value::Bool(true)
            && self.document["consumer"]["adoptsOutcome"] == Value::Bool(false)
            && self.document["consumer"]["truthAuthority"] == Value::Bool(false)
            && self.document["consumer"]["nativeConnected"] == Value::Bool(false)
            && required_scope.iter().all(|field| {
                self.document["scope"]["required"]
                    .as_array()
                    .is_some_and(|values| values.iter().any(|item| item == field))
            })
            && self.document["scope"]["rootNamespace"] == Value::Bool(false)
            && self.document["scope"]["rootTokenPaths"] == Value::Bool(false)
            && self.document["scope"]["pathTraversal"] == Value::Bool(false)
            && self.document["evidence"]["secretValues"] == Value::Bool(false)
            && self.document["evidence"]["rawProviderPayload"] == Value::Bool(false)
            && self.document["evidence"]["tokenMaterial"] == Value::Bool(false)
            && self.document["evidence"]["rawLeaseIdentifiers"] == Value::Bool(false)
            && self.document["evidence"]["rawPolicyNames"] == Value::Bool(false)
            && self.document["registration"]["reversible"] == Value::Bool(true)
            && self.document["registration"]["revocable"] == Value::Bool(true)
            && self.document["registration"]["failClosedOnDrift"] == Value::Bool(true)
            && authority_is_false
            && self.document["nativeGap"]["status"] == VAULT_GOVERNANCE_RESULT_BLOCKED_ENV
            && layer2_gaps
            && honest_gap.contains("BLOCKED_ENV")
            && honest_gap.contains("secret values")
            && honest_gap.contains("logs in")
            && honest_gap.contains("policy")
            && honest_gap.contains("renew")
            && honest_gap.contains("revoke");
        if valid {
            Ok(())
        } else {
            Err(VaultGovernanceError::Contract(
                "checked-in Vault governance contract does not match the Layer-1 baseline"
                    .to_owned(),
            ))
        }
    }
}

fn string_array(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// Builds the plugin-runtime contribution set for one exact Project/Mission
/// generation. Mounting and revocation remain host-owned and reversible.
pub fn plugin_definition(scope: PluginScope) -> Result<PluginDefinition, VaultGovernanceError> {
    let plugin_id = PluginId::new(VAULT_GOVERNANCE_RESULT_PLUGIN_ID)?;
    let service_id = ServiceId::new(VAULT_GOVERNANCE_RESULT_SERVICE_ID)?;
    let provider_id = ProviderId::new(VAULT_GOVERNANCE_RESULT_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(MISSION_VAULT_GOVERNANCE_CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(VAULT_GOVERNANCE_RESULT_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(VAULT_GOVERNANCE_RESULT_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(VAULT_GOVERNANCE_RESULT_CONSUMER_SCHEMA),
        )?],
        events: Vec::new(),
        ui_surfaces: Vec::new(),
    };
    Ok(PluginDefinition::new(
        plugin_id,
        version,
        scope,
        contributions,
    )?)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
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

    pub const fn truth_authority() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use super::*;

    #[test]
    fn checked_in_contract_validates() {
        let contract = VaultGovernanceResultContract::baseline().expect("contract");
        assert_eq!(contract.digest(), contract_digest());
        assert_eq!(VAULT_GOVERNANCE_RESULT_BLOCKED_ENV, "BLOCKED_ENV");
    }

    #[test]
    fn layer_one_authority_is_false() {
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::effect());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::verification());
        assert!(!Layer1Authority::truth_authority());
        assert!(!Layer1Authority::adopted_outcome());
    }
}
