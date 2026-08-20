//! Standalone Layer-1 governed Docker Hub image-result boundary.
//!
//! This crate is intentionally below Hartevo Truth, Consent, Effect, Receipt,
//! Verification, Outcome, and durable Work Product authority. It models only
//! one bounded exact-tag Docker Hub metadata read, digest fences, reversible
//! registration, redacted receipts, and a Mission-scoped proposal seam.
//! Recording, fixture, fake, loopback, and BLOCKED_ENV transports are always
//! non-connected, non-native, and non-first-party.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::fn_params_excessive_bools,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

use sha2::{Digest as ShaDigest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionDockerHubImageConsumer, MissionDockerHubImageConsumerError, MissionDockerHubImageResult,
    MissionDockerHubImageResultState,
};
pub use error::{DockerHubImageResultError, DockerHubTransportError, Result};
pub use model::*;
pub use provider::{
    BlockedEnvDockerHubTransport, DockerHubOperation, DockerHubProvider,
    DockerHubProviderDefinition, DockerHubTagRequest, DockerHubTagResponse, DockerHubTransport,
    FakeDockerHubTransport, FixtureDockerHubTransport, LoopbackDockerHubTransport,
    RecordedDockerHubRequest, RecordingDockerHubTransport,
};
pub use service::{
    CapabilityDescription, DockerHubFailureEvidence, DockerHubImageResultEvidence,
    DockerHubImageResultProposal, DockerHubImageResultRegistration, DockerHubImageResultService,
    DockerHubRegistration, DockerHubRegistrationStatus, DockerHubRegistrationTransition,
    DockerHubVerificationFailure, DockerHubVerificationReport,
};

pub type DockerHubImageScope = DockerHubImageResultScope;
pub type DockerHubResultService<T> = DockerHubImageResultService<T>;
pub type DockerHubImageResult = DockerHubImageResultProposal;
pub type DockerHubImageResultServiceError = DockerHubImageResultError;
pub type DockerHubProviderError = DockerHubTransportError;

pub const CONTRACT_SCHEMA: &str = "hartevo.dockerhub-image-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-DOCKERHUB-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.dockerhub-image-result/v1|layer=1|service=dockerhub.image.result.read|provider=dockerhub.image.result.recording|consumer=mission.dockerhub-image.consumer|api=dockerhub-hub-v2-read-repository-tag-r1";
pub const CONTRACT_DIGEST: &str =
    "5737a484d4b360966c042366ba3a529436b93a4bb2fbd8b499120e0965d5c532";
pub const PLUGIN_ID: &str = "dockerhub.image.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "dockerhub.image.result.read";
pub const PROVIDER_ID: &str = "dockerhub.image.result.recording";
pub const API_REVISION: &str = "dockerhub-hub-v2-read-repository-tag-r1";
pub const CONSUMER_ID: &str = "mission.dockerhub-image.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const LAYER1_PERMISSIONS: [&str; 2] = ["dockerhub:ReadRepositoryTag", "mission.scope"];
pub const MAX_IDENTIFIER_BYTES: usize = 255;
pub const MAX_PLATFORM_TUPLES: usize = 32;
pub const MAX_IMAGES: usize = 32;
pub const MAX_LAYERS_PER_IMAGE: usize = 256;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/dockerhub-image-result/dockerhub-image-result.v1.json"
);

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerHubImageResultContract {
    value: serde_json::Value,
}

impl DockerHubImageResultContract {
    pub fn baseline() -> Result<Self> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|_| DockerHubImageResultError::ContractDrift)?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(CONTRACT_DIGEST_INPUT)
    }

    pub fn validate(&self) -> Result<()> {
        let object = self
            .value
            .as_object()
            .ok_or(DockerHubImageResultError::ContractDrift)?;
        for key in [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "pluginId",
            "layer",
            "evidenceLevel",
            "digestInput",
            "contractDigest",
            "service",
            "provider",
            "consumer",
            "credentials",
            "scope",
            "registration",
            "pagination",
            "projection",
            "receipts",
            "evidence",
            "provenance",
            "authorityBoundary",
            "forbiddenEffects",
            "layer2Gaps",
            "honestNativeGap",
        ] {
            if !object.contains_key(key) {
                return Err(DockerHubImageResultError::ContractDrift);
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
            return Err(DockerHubImageResultError::ContractDrift);
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(DockerHubImageResultError::ContractDrift)?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || service.get("kernelAuthority") != Some(&serde_json::Value::Bool(false))
            || service.get("outcomeAdoption") != Some(&serde_json::Value::Bool(false))
        {
            return Err(DockerHubImageResultError::ContractDrift);
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(DockerHubImageResultError::ContractDrift)?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(API_REVISION)
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("providerReceipt") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(DockerHubImageResultError::ContractDrift);
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(DockerHubImageResultError::ContractDrift)?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(DockerHubImageResultError::ContractDrift);
        }
        let provenance = object
            .get("provenance")
            .and_then(serde_json::Value::as_object)
            .ok_or(DockerHubImageResultError::ContractDrift)?;
        for key in ["connected", "native", "firstParty", "providerReceipt"] {
            if provenance.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(DockerHubImageResultError::ContractDrift);
            }
        }
        for forbidden in [
            "Login",
            "Pull",
            "Push",
            "Delete",
            "Tag",
            "Build",
            "Scan",
            "WebhookMutation",
            "DownloadLayer",
            "ExecuteImage",
            "VerifyContentIntegrity",
            "VerifySignature",
            "VerifyAttestation",
            "ProduceSbom",
            "ProduceVulnerabilityResult",
            "adopt_verified_work_product",
        ] {
            if !object
                .get("forbiddenEffects")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(forbidden)))
            {
                return Err(DockerHubImageResultError::ContractDrift);
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

    pub const fn durable_provider_receipt() -> bool {
        false
    }

    pub const fn adopts_outcome() -> bool {
        false
    }

    pub const fn adopts_work_product() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_is_pinned_to_layer_one_and_honest_provenance() {
        let contract = DockerHubImageResultContract::baseline().expect("contract");
        assert_eq!(contract.digest().as_str(), CONTRACT_DIGEST);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::adopts_outcome());
        assert!(!Layer1Authority::adopts_work_product());
    }
}
