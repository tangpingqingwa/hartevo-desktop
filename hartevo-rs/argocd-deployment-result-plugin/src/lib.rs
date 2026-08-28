//! Standalone Layer-1 Argo CD deployment-result capability.
//!
//! This crate owns bounded, read-only Application/resource-tree/sync-status/
//! operation metadata, typed proposal and recording seams, and exact Mission
//! scope fences. It imports no Hartevo application, desktop, domain, storage,
//! catalog, keyring, browser, kernel, Kubernetes, or provider authority and
//! contains no native HTTP client.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::result_large_err,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{
    MissionArgoCdDeploymentConsumer, MissionArgoCdDeploymentResult, ProposalDisposition,
    RecordedArgoCdDeploymentResult,
};
pub use error::{ArgoCdDeploymentError, ArgoCdError, ArgoCdTransportError, Result};
pub use model::*;
pub use provider::{ArgoCdProvider, ArgoCdProviderDefinition};
pub use service::{
    ArgoCdCapabilityDescription, ArgoCdDeploymentEvidence, ArgoCdDeploymentProposal,
    ArgoCdDeploymentReceipt, ArgoCdDeploymentRegistration, ArgoCdDeploymentResultService,
    ArgoCdDeploymentServiceDefinition, ArgoCdReadRequest, CapabilityDescription, EvidenceDigests,
    FailureEvidence, RegistrationStatus, RegistrationTransitionEvidence, VerificationFailure,
    VerificationReport,
};
pub use transport::{
    ArgoCdOperation, ArgoCdRequest, ArgoCdResponse, ArgoCdTransport, BlockedEnvTransport,
    FakeTransport, FixtureTransport, LoopbackTransport, RecordingTransport, RetryPolicy,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.argocd-deployment-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-ARGOCD-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.argocd-deployment-result/v1|layer=1|service=argocd.deployment-result.read|provider=argocd.deployment-result.recording|consumer=mission.argocd-deployment.consumer|api=argo-cd-applications-resource-tree-sync-status-operation-v1";
pub const CONTRACT_DIGEST: &str =
    "4a907108976c499ac4319a1eea0809730092207455b25b3868d37308e1430504";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/argocd-deployment-result/contract.v1.json");
pub const PLUGIN_ID: &str = "argocd.deployment-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "argocd.deployment-result.read";
pub const PROVIDER_ID: &str = "argocd.deployment-result.recording";
pub const PROVIDER_VERSION: &str = "1.0.0";
pub const ARGOCD_API_REVISION: &str = "argo-cd-applications-resource-tree-sync-status-operation-v1";
pub const MISSION_CONSUMER_ID: &str = "mission.argocd-deployment.consumer";
pub const CONSUMER_ID: &str = MISSION_CONSUMER_ID;
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const ARGOCD_API_DOCS: &str =
    "https://argo-cd.readthedocs.io/en/stable/developer-guide/api-docs/";
pub const NATIVE_GAP: &str = "BLOCKED_ENV: native bearer-token resolution, live Argo CD HTTPS reads, durable provider receipts, independent Kubernetes readback, sync/rollback/terminate effects, raw manifest/secret/log access, Hartevo authority, generic deployment registry, and verified Work Product adoption remain Layer 2 gaps";

#[must_use]
pub fn contract_digest() -> String {
    model::sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArgoCdDeploymentContract {
    value: serde_json::Value,
}

impl ArgoCdDeploymentContract {
    pub fn baseline() -> Result<Self> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|_| ArgoCdDeploymentError::ContractDrift)?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    #[must_use]
    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    pub fn validate(&self) -> Result<()> {
        let object = self
            .value
            .as_object()
            .ok_or(ArgoCdDeploymentError::ContractDrift)?;
        for key in [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginId",
            "pluginVersion",
            "layer",
            "evidenceLevel",
            "digestInput",
            "contractDigest",
            "typedSurface",
            "authority",
            "service",
            "provider",
            "consumer",
            "exactScope",
            "allowlist",
            "authentication",
            "bounds",
            "states",
            "projection",
            "registration",
            "evidence",
            "provenance",
            "authorityBoundary",
            "errorHandling",
            "layer2Gaps",
        ] {
            if !object.contains_key(key) {
                return Err(ArgoCdDeploymentError::ContractDrift);
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
            || object.get("pluginId").and_then(serde_json::Value::as_str) != Some(PLUGIN_ID)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(PLUGIN_VERSION)
            || object.get("layer").and_then(serde_json::Value::as_u64) != Some(1)
            || object
                .get("evidenceLevel")
                .and_then(serde_json::Value::as_str)
                != Some(EVIDENCE_LEVEL)
            || object
                .get("digestInput")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST_INPUT)
            || object
                .get("contractDigest")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST)
            || contract_digest() != CONTRACT_DIGEST
        {
            return Err(ArgoCdDeploymentError::ContractDrift);
        }
        let authority = object
            .get("authority")
            .and_then(serde_json::Value::as_object)
            .ok_or(ArgoCdDeploymentError::ContractDrift)?;
        for key in [
            "readOnly",
            "proposalOnly",
            "recordingOnly",
            "externalWrites",
            "connected",
            "nativeProvider",
            "firstPartyProvider",
            "kernelAuthority",
            "outcomeAuthority",
            "workProductAdoption",
        ] {
            if authority.get(key)
                != Some(&serde_json::Value::Bool(matches!(
                    key,
                    "readOnly" | "proposalOnly" | "recordingOnly"
                )))
            {
                return Err(ArgoCdDeploymentError::ContractDrift);
            }
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(ArgoCdDeploymentError::ContractDrift)?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ArgoCdDeploymentError::ContractDrift);
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(ArgoCdDeploymentError::ContractDrift)?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(ARGOCD_API_REVISION)
            || provider.get("connectedEvidence") != Some(&serde_json::Value::Bool(false))
            || provider.get("nativeEvidence") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstPartyEvidence") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ArgoCdDeploymentError::ContractDrift);
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(ArgoCdDeploymentError::ContractDrift)?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ArgoCdDeploymentError::ContractDrift);
        }
        let writes = object
            .get("allowlist")
            .and_then(serde_json::Value::as_object)
            .and_then(|allowlist| allowlist.get("writes"))
            .and_then(serde_json::Value::as_array)
            .ok_or(ArgoCdDeploymentError::ContractDrift)?;
        if !writes.is_empty() {
            return Err(ArgoCdDeploymentError::ContractDrift);
        }
        for forbidden in [
            "application_sync",
            "application_rollback",
            "application_terminate",
            "kubernetes_apply",
            "kubernetes_patch",
            "kubernetes_delete",
            "raw_manifest_read",
            "raw_secret_read",
            "raw_log_read",
            "generic_deployment_registry",
        ] {
            if !object
                .get("allowlist")
                .and_then(serde_json::Value::as_object)
                .and_then(|allowlist| allowlist.get("forbidden"))
                .and_then(serde_json::Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(forbidden)))
            {
                return Err(ArgoCdDeploymentError::ContractDrift);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    #[must_use]
    pub const fn connected() -> bool {
        false
    }

    #[must_use]
    pub const fn native_provider() -> bool {
        false
    }

    #[must_use]
    pub const fn first_party_provider() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_provider_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn kernel_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn outcome_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn work_product_adoption() -> bool {
        false
    }

    #[must_use]
    pub const fn external_writes() -> bool {
        false
    }
}

pub type ArgoCdDeploymentService<T> = ArgoCdDeploymentResultService<T>;

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_contract_is_versioned_bounded_and_layer_one_honest() {
        let contract = ArgoCdDeploymentContract::baseline().expect("Argo CD contract");
        assert_eq!(contract.value()["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(contract.value()["contractVersion"], CONTRACT_VERSION);
        assert_eq!(contract.value()["pluginId"], PLUGIN_ID);
        assert_eq!(contract.value()["contractDigest"], CONTRACT_DIGEST);
        assert_eq!(contract.value()["provider"]["id"], PROVIDER_ID);
        assert_eq!(contract.value()["consumer"]["id"], CONSUMER_ID);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party_provider());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::work_product_adoption());
        assert!(!Layer1Authority::external_writes());
    }
}
