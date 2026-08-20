//! Standalone Layer-1 governed Google Cloud Memorystore for Redis instance
//! result boundary.
//!
//! Only bounded, redacted `v1` management-plane evidence for one exact
//! project/location/instance is modeled here. Native credential resolution,
//! live HTTPS, Redis data-plane access, instance mutation, kernel authority,
//! availability guarantees, and outcome adoption remain outside Layer 1.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
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

use sha2::{Digest as ShaDigest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionGcpMemorystoreInstanceConsumer, MissionGcpMemorystoreInstanceResult,
    RecordedGcpMemorystoreInstanceResult,
};
pub use error::{GcpMemorystoreError, GcpMemorystoreTransportError, Result};
pub use model::*;
pub use provider::{
    BlockedEnvTransport, FakeGcpMemorystoreTransport, FixtureTransport,
    GcpMemorystoreAdminProvider, GcpMemorystoreOperation, GcpMemorystoreProvider,
    GcpMemorystoreProviderDefinition, GcpMemorystoreTransport, GetInstanceRequest,
    GetInstanceResponse, ListInstancesRequest, ListInstancesResponse, LoopbackTransport,
    RecordedRequest, RecordingTransport,
};
pub use service::{
    GcpMemorystoreEvidenceRequest, GcpMemorystoreInstanceProposal,
    GcpMemorystoreInstanceRegistration, GcpMemorystoreInstanceResultService,
    GcpMemorystoreRegistration, GcpMemorystoreServiceDefinition, RegistrationStatus,
    RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.gcp-memorystore-redis-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-GCP-MEMORYSTORE-01-L1/v1";
pub const PLUGIN_ID: &str = "gcp.memorystore.redis.instance.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "gcp.memorystore.redis.instance.result.read";
pub const PROVIDER_ID: &str = "gcp.memorystore.admin";
pub const API_REVISION: &str = "memorystore-redis-v1-instances-get-list-r1";
pub const CONSUMER_ID: &str = "mission.gcp-memorystore-instance.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const GCP_MEMORYSTORE_OAUTH_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
pub const LAYER1_PERMISSIONS: [&str; 3] = [
    "redis.instances.get",
    "redis.instances.list",
    "mission.scope",
];
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_LABELS: usize = 16;
pub const MAX_PAGE_SIZE: u32 = 100;
pub const MAX_PAGES: u16 = 8;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_LIST_ITEMS: usize = 256;
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.gcp-memorystore-redis-result/v1|layer=1|service=gcp.memorystore.redis.instance.result.read|provider=gcp.memorystore.admin|consumer=mission.gcp-memorystore-instance.consumer|api=memorystore-redis-v1-instances-get-list-r1";
pub const CONTRACT_DIGEST: &str =
    "5a459e7a77100fe8608b82d82cf5f888e51a178245251cd9969da73400ed30ad";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/gcp-memorystore-redis-result/gcp-memorystore-redis-result.v1.json"
);

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpMemorystoreContract {
    value: serde_json::Value,
}
impl GcpMemorystoreContract {
    pub fn baseline() -> Result<Self> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|_| GcpMemorystoreError::ContractDrift)?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }
    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }
    pub fn digest(&self) -> model::Digest {
        model::Digest::from_text(CONTRACT_DIGEST_INPUT)
    }
    pub fn validate(&self) -> Result<()> {
        let object = self
            .value
            .as_object()
            .ok_or(GcpMemorystoreError::ContractDrift)?;
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
            "permissions",
            "registration",
            "pagination",
            "projection",
            "receipts",
            "evidence",
            "provenance",
            "authorityBoundary",
            "forbiddenEffects",
            "layer2Gaps",
            "nativeClaims",
        ] {
            if !object.contains_key(key) {
                return Err(GcpMemorystoreError::ContractDrift);
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
            return Err(GcpMemorystoreError::ContractDrift);
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(GcpMemorystoreError::ContractDrift)?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || service.get("liveExternalIo") != Some(&serde_json::Value::Bool(false))
            || service.get("kernelAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(GcpMemorystoreError::ContractDrift);
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(GcpMemorystoreError::ContractDrift)?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(API_REVISION)
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(GcpMemorystoreError::ContractDrift);
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(GcpMemorystoreError::ContractDrift)?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
            || consumer.get("kernelAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(GcpMemorystoreError::ContractDrift);
        }
        let claims = object
            .get("nativeClaims")
            .and_then(serde_json::Value::as_object)
            .ok_or(GcpMemorystoreError::ContractDrift)?;
        for key in [
            "connected",
            "nativeProvider",
            "firstParty",
            "durableProviderReceipt",
            "adoptedOutcome",
            "adoptedWorkProduct",
            "blockedEnvironmentIsNative",
        ] {
            if claims.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(GcpMemorystoreError::ContractDrift);
            }
        }
        for forbidden in [
            "instances.create",
            "instances.patch",
            "instances.update",
            "instances.delete",
            "instances.failover",
            "instances.import",
            "instances.export",
            "instances.upgrade",
            "instances.rescheduleMaintenance",
            "instances.getAuthString",
            "redis_data_plane_read",
            "redis_data_plane_write",
            "read_keys_or_values",
            "capture_command_output",
            "adopt_verified_work_product",
        ] {
            if !object
                .get("forbiddenEffects")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(forbidden)))
            {
                return Err(GcpMemorystoreError::ContractDrift);
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
    pub const fn truth_authority() -> bool {
        false
    }
    pub const fn consent_authority() -> bool {
        false
    }
    pub const fn effect_authority() -> bool {
        false
    }
    pub const fn verification_authority() -> bool {
        false
    }
    pub const fn adopts_outcome() -> bool {
        false
    }
    pub const fn adopts_work_product() -> bool {
        false
    }
    pub const fn availability_guarantee() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    #[test]
    fn contract_is_layer_one_and_honest() {
        let contract = GcpMemorystoreContract::baseline().expect("contract");
        assert_eq!(contract.digest().as_str(), CONTRACT_DIGEST);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::truth_authority());
        assert!(!Layer1Authority::consent_authority());
        assert!(!Layer1Authority::effect_authority());
        assert!(!Layer1Authority::verification_authority());
        assert!(!Layer1Authority::adopts_outcome());
        assert!(!Layer1Authority::adopts_work_product());
        assert!(!Layer1Authority::availability_guarantee());
    }
}
