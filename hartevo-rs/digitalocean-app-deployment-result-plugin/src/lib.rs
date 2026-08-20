//! Standalone Layer-1 governed DigitalOcean App Platform deployment-result
//! boundary.
//!
//! This crate models only bounded, read-only app/deployment/event/health
//! evidence, digest fences, reversible registration, redacted receipts, and
//! a Mission-scoped review projection. It never resolves credentials, opens
//! native HTTPS, performs an external effect, emits a durable provider
//! receipt, or adopts a Work Product. Fixture, recording, loopback, and
//! `BLOCKED_ENV` transports are always non-connected, non-native, and
//! non-first-party.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps,
    clippy::struct_excessive_bools,
    clippy::similar_names,
    clippy::return_self_not_must_use,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::missing_panics_doc
)]

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

use sha2::Digest as ShaDigest;

pub use consumer::{
    MissionDigitalOceanAppDeploymentConsumer, MissionDigitalOceanAppDeploymentResult,
    MissionDigitalOceanAppDeploymentResultProjection, ProposalDisposition,
    RecordedDigitalOceanAppDeploymentResult,
};
pub use error::{DigitalOceanAppDeploymentResultError, DigitalOceanTransportError, Result};
pub use model::*;
pub use provider::{
    AppRead, BlockedEnvTransport, DeploymentPageRead, DeploymentRead, DigitalOceanAppsOperation,
    DigitalOceanAppsProvider, DigitalOceanAppsProviderDefinition, DigitalOceanAppsResponse,
    DigitalOceanAppsTransport, EventsRead, FixtureTransport, GetAppHealthRequest, GetAppRequest,
    GetDeploymentRequest, HealthRead, ListDeploymentsRequest, ListEventsRequest, LoopbackTransport,
    PageCursor, RecordedRequest, RecordingTransport,
};
pub use service::{
    CapabilityDescription, DigitalOceanAppDeploymentEvidenceRequest,
    DigitalOceanAppDeploymentProposal, DigitalOceanAppDeploymentRegistration,
    DigitalOceanAppDeploymentResult, DigitalOceanAppDeploymentResultService,
    DigitalOceanAppDeploymentService, DigitalOceanAppDeploymentServiceError, FailureEvidence,
    RegistrationStatus, RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.digitalocean-app-deployment-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-DIGITALOCEAN-APPS-01-L1/v1";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const PLUGIN_ID: &str = "digitalocean.apps.app-deployment.result";
pub const SERVICE_ID: &str = "digitalocean.apps.app-deployment.result.read";
pub const PROVIDER_ID: &str = "digitalocean.apps.provider.recording";
pub const PROVIDER_VERSION: &str = "1.0.0";
pub const API_REVISION: &str =
    "digitalocean-apps-get-app-list-deployments-get-deployment-list-events-get-app-health-v2-r1";
pub const CONSUMER_ID: &str = "mission.digitalocean.app-deployment.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.digitalocean-app-deployment-result/v1|layer=1|service=digitalocean.apps.app-deployment.result.read|provider=digitalocean.apps.provider.recording|consumer=mission.digitalocean.app-deployment.consumer|api=digitalocean-apps-get-app-list-deployments-get-deployment-list-events-get-app-health-v2-r1";
pub const CONTRACT_DIGEST: &str =
    "0a67bc52c58f1927bf0e159efe194000dae2bd31da4c8d54a395bda1547bb6a3";
pub const BASE_URL: &str = "https://api.digitalocean.com";
pub const LAYER1_PERMISSIONS: [&str; 2] = ["app:read", "mission.scope"];
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 200;
pub const MAX_PAGES: u16 = 8;
pub const MAX_COMPONENTS: usize = 64;
pub const MAX_EVENTS: usize = 64;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/digitalocean-app-deployment-result/digitalocean-app-deployment-result.v1.json"
);

#[must_use]
pub fn contract_digest() -> String {
    hex::encode(sha2::Sha256::digest(CONTRACT_DIGEST_INPUT.as_bytes()))
}

#[must_use]
pub fn contract_digest_value() -> Digest {
    Digest::parse(CONTRACT_DIGEST.to_owned()).expect("contract digest constant is valid")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigitalOceanAppDeploymentResultContract {
    value: serde_json::Value,
}

impl DigitalOceanAppDeploymentResultContract {
    pub fn baseline() -> Result<Self> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|_| DigitalOceanAppDeploymentResultError::ContractDrift)?;
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
        contract_digest_value()
    }

    pub fn validate(&self) -> Result<()> {
        let object = self
            .value
            .as_object()
            .ok_or(DigitalOceanAppDeploymentResultError::ContractDrift)?;
        for key in [
            "$schema",
            "$id",
            "title",
            "description",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "pluginId",
            "layer",
            "evidenceLevel",
            "status",
            "digestInput",
            "contractDigest",
            "authority",
            "typedSurface",
            "service",
            "provider",
            "consumer",
            "exactScope",
            "authentication",
            "registration",
            "pagination",
            "projection",
            "evidenceStates",
            "redaction",
            "provenance",
            "authorityBoundary",
            "forbiddenEffects",
            "layer2Gaps",
            "honestNativeGap",
        ] {
            if !object.contains_key(key) {
                return Err(DigitalOceanAppDeploymentResultError::ContractDrift);
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
            || object.get("pluginId").and_then(serde_json::Value::as_str) != Some(PLUGIN_ID)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
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
            return Err(DigitalOceanAppDeploymentResultError::ContractDrift);
        }
        let authority = object
            .get("authority")
            .and_then(serde_json::Value::as_object)
            .ok_or(DigitalOceanAppDeploymentResultError::ContractDrift)?;
        for key in [
            "connected",
            "nativeProvider",
            "firstParty",
            "durableProviderReceipt",
            "kernelTruthAuthority",
            "kernelConsentAuthority",
            "kernelEffectAuthority",
            "kernelReceiptAuthority",
            "kernelVerificationAuthority",
            "outcomeAuthority",
            "workProductAdoption",
            "externalWrites",
        ] {
            if authority.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(DigitalOceanAppDeploymentResultError::ContractDrift);
            }
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(DigitalOceanAppDeploymentResultError::ContractDrift)?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(API_REVISION)
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || provider
                .get("allowlistedWrites")
                .and_then(serde_json::Value::as_array)
                .is_none_or(|writes| !writes.is_empty())
        {
            return Err(DigitalOceanAppDeploymentResultError::ContractDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    pub const fn first_party() -> bool {
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

#[cfg(test)]
mod contract_tests {
    use super::{
        CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION,
        DigitalOceanAppDeploymentResultContract, EVIDENCE_LEVEL, Layer1Authority, PLUGIN_ID,
        PROVIDER_ID, SERVICE_ID, contract_digest,
    };

    #[test]
    fn contract_is_machine_readable_and_layer_one_honest() {
        let document: serde_json::Value =
            serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(document["contractVersion"], CONTRACT_VERSION);
        assert_eq!(document["pluginId"], PLUGIN_ID);
        assert_eq!(document["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(document["service"]["id"], SERVICE_ID);
        assert_eq!(document["provider"]["id"], PROVIDER_ID);
        assert_eq!(document["consumer"]["id"], CONSUMER_ID);
        assert_eq!(document["contractDigest"], CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert!(DigitalOceanAppDeploymentResultContract::baseline().is_ok());
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::work_product_adoption());
        assert!(!Layer1Authority::external_writes());
    }
}
