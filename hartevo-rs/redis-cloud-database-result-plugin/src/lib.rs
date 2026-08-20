//! Standalone Layer-1 governed Redis Cloud database-posture boundary.
//!
//! This root is deliberately below Hartevo Truth, Consent, Effect, Receipt,
//! Verification, Outcome, and durable Work Product authority. It accepts only
//! bounded management metadata for one exact scope. All available transports
//! are recording, fixture, fake, loopback, or BLOCKED_ENV and are permanently
//! disconnected, non-native, and non-first-party.

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

use serde_json::Value;
use sha2::{Digest as ShaDigest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionRedisCloudDatabaseConsumer, MissionRedisCloudDatabaseResult,
    RecordedRedisCloudDatabaseResult,
};
pub use error::{RedisCloudDatabaseResultError, RedisCloudTransportError, Result};
pub use model::*;
pub use provider::{
    BlockedEnvRedisCloudTransport, BlockedEnvTransport, FakeRedisCloudTransport, FakeTransport,
    FixtureRedisCloudTransport, FixtureTransport, LoopbackRedisCloudTransport, LoopbackTransport,
    RecordingRedisCloudTransport, RecordingTransport, RedisCloudOperation, RedisCloudProvider,
    RedisCloudProviderDefinition, RedisCloudReadRequest, RedisCloudResponse, RedisCloudTransport,
};
pub use service::{
    CapabilityDescription, RedisCloudDatabaseResultEvidence, RedisCloudDatabaseResultProposal,
    RedisCloudDatabaseResultRegistration, RedisCloudDatabaseResultService,
    RedisCloudFailureEvidence, RedisCloudRegistration, RedisCloudRegistrationStatus,
    RedisCloudRegistrationTransition, RedisCloudVerificationFailure, RedisCloudVerificationReport,
};

pub type RedisCloudScope = RedisCloudDatabaseScope;
pub type RedisCloudResultService<T> = RedisCloudDatabaseResultService<T>;
pub type RedisCloudDatabaseResult = RedisCloudDatabaseResultProposal;

pub const CONTRACT_SCHEMA: &str = "hartevo.redis-cloud-database-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-REDIS-CLOUD-01-L1/v1";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const PLUGIN_ID: &str = "redis.cloud.database.result";
pub const SERVICE_ID: &str = "redis.cloud.database.result.read";
pub const PROVIDER_ID: &str = "redis.cloud.database.result.recording";
pub const API_REVISION: &str = "redis-cloud-rest-v1-read-account-subscription-database-posture-r1";
pub const CONSUMER_ID: &str = "mission.redis-cloud-database.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.redis-cloud-database-result/v1|layer=1|service=redis.cloud.database.result.read|provider=redis.cloud.database.result.recording|consumer=mission.redis-cloud-database.consumer|api=redis-cloud-rest-v1-read-account-subscription-database-posture-r1";
pub const CONTRACT_DIGEST: &str =
    "e1f53b0506084eba89b4948a6f0b5bdae3f7957c7c0cb97d04e2310ed13e2691";
pub const EVIDENCE_DIGEST_INPUT: &str = "redis-cloud-database-evidence/v1|account|subscription|database|status|region|plan|sharding|replication|endpoint-posture|redacted=endpoints,credentials,data,keys,values,raw-responses|pagination=reject|provenance=non-native";
pub const EVIDENCE_DIGEST: &str =
    "a445d2e330e4c200b2e4ec348081e31778e2f8519db97954668e8c10e19a3171";
pub const LAYER1_PERMISSIONS: [&str; 4] = [
    "redis-cloud:ReadAccount",
    "redis-cloud:ReadSubscription",
    "redis-cloud:ReadDatabase",
    "mission.scope",
];
pub const MAX_IDENTIFIER_BYTES: usize = 255;
pub const MAX_REGIONS: usize = 32;
pub const MAX_PAGE_SIZE: u16 = 1;
pub const MAX_PAGES: u16 = 1;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/redis-cloud-database-result/redis-cloud-database-result.v1.json"
);

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedisCloudDatabaseResultContract {
    value: Value,
}

impl RedisCloudDatabaseResultContract {
    pub fn baseline() -> Result<Self> {
        let value = serde_json::from_str::<Value>(CONTRACT_JSON)
            .map_err(|_| RedisCloudDatabaseResultError::ContractDrift)?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    #[must_use]
    pub fn value(&self) -> &Value {
        &self.value
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(CONTRACT_DIGEST_INPUT)
    }

    pub fn validate(&self) -> Result<()> {
        let object = self
            .value
            .as_object()
            .ok_or(RedisCloudDatabaseResultError::ContractDrift)?;
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
            "redaction",
            "receipts",
            "evidence",
            "provenance",
            "authorityBoundary",
            "forbiddenEffects",
            "layer2Gaps",
            "honestNativeGap",
        ] {
            if !object.contains_key(key) {
                return Err(RedisCloudDatabaseResultError::ContractDrift);
            }
        }
        if object.get("schemaVersion").and_then(Value::as_str) != Some(CONTRACT_SCHEMA)
            || object.get("contractVersion").and_then(Value::as_str) != Some(CONTRACT_VERSION)
            || object.get("pluginVersion").and_then(Value::as_str) != Some(PLUGIN_VERSION)
            || object.get("pluginId").and_then(Value::as_str) != Some(PLUGIN_ID)
            || object.get("layer").and_then(Value::as_str) != Some("Layer-1")
            || object.get("evidenceLevel").and_then(Value::as_str) != Some(EVIDENCE_LEVEL)
            || object.get("digestInput").and_then(Value::as_str) != Some(CONTRACT_DIGEST_INPUT)
            || object.get("contractDigest").and_then(Value::as_str) != Some(CONTRACT_DIGEST)
            || contract_digest() != CONTRACT_DIGEST
        {
            return Err(RedisCloudDatabaseResultError::ContractDrift);
        }
        let service = object
            .get("service")
            .and_then(Value::as_object)
            .ok_or(RedisCloudDatabaseResultError::ContractDrift)?;
        if service.get("id").and_then(Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&Value::Bool(true))
            || service.get("proposalOnly") != Some(&Value::Bool(true))
            || service.get("recordingOnly") != Some(&Value::Bool(true))
            || service.get("externalWrites") != Some(&Value::Bool(false))
            || service.get("kernelAuthority") != Some(&Value::Bool(false))
            || service.get("outcomeAdoption") != Some(&Value::Bool(false))
        {
            return Err(RedisCloudDatabaseResultError::ContractDrift);
        }
        let provider = object
            .get("provider")
            .and_then(Value::as_object)
            .ok_or(RedisCloudDatabaseResultError::ContractDrift)?;
        if provider.get("id").and_then(Value::as_str) != Some(PROVIDER_ID)
            || provider.get("apiRevision").and_then(Value::as_str) != Some(API_REVISION)
            || provider.get("connected") != Some(&Value::Bool(false))
            || provider.get("native") != Some(&Value::Bool(false))
            || provider.get("firstParty") != Some(&Value::Bool(false))
            || provider.get("providerReceipt") != Some(&Value::Bool(false))
            || provider.get("externalWrites") != Some(&Value::Bool(false))
        {
            return Err(RedisCloudDatabaseResultError::ContractDrift);
        }
        let consumer = object
            .get("consumer")
            .and_then(Value::as_object)
            .ok_or(RedisCloudDatabaseResultError::ContractDrift)?;
        if consumer.get("id").and_then(Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&Value::Bool(false))
            || consumer.get("consentAuthority") != Some(&Value::Bool(false))
            || consumer.get("effectAuthority") != Some(&Value::Bool(false))
            || consumer.get("receiptAuthority") != Some(&Value::Bool(false))
            || consumer.get("verificationAuthority") != Some(&Value::Bool(false))
        {
            return Err(RedisCloudDatabaseResultError::ContractDrift);
        }
        let provenance = object
            .get("provenance")
            .and_then(Value::as_object)
            .ok_or(RedisCloudDatabaseResultError::ContractDrift)?;
        for key in ["connected", "native", "firstParty", "providerReceipt"] {
            if provenance.get(key) != Some(&Value::Bool(false)) {
                return Err(RedisCloudDatabaseResultError::ContractDrift);
            }
        }
        for forbidden in [
            "create_database",
            "update_database",
            "delete_database",
            "import_database",
            "export_database",
            "backup_database",
            "restore_database",
            "scale_database",
            "mutate_acl",
            "read_data_plane",
            "read_keys",
            "read_values",
            "read_raw_endpoints",
            "resolve_live_credentials",
            "serialize_credentials",
            "serialize_raw_provider_response",
            "adopt_kernel_truth",
            "adopt_kernel_consent",
            "adopt_kernel_effect",
            "claim_provider_receipt",
            "adopt_kernel_verification",
            "adopt_kernel_outcome",
            "adopt_verified_work_product",
        ] {
            if !object
                .get("forbiddenEffects")
                .and_then(Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(forbidden)))
            {
                return Err(RedisCloudDatabaseResultError::ContractDrift);
            }
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
    pub const fn native() -> bool {
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
    pub const fn truth_authority() -> bool {
        false
    }
    #[must_use]
    pub const fn consent_authority() -> bool {
        false
    }
    #[must_use]
    pub const fn effect_authority() -> bool {
        false
    }
    #[must_use]
    pub const fn receipt_authority() -> bool {
        false
    }
    #[must_use]
    pub const fn verification_authority() -> bool {
        false
    }
    #[must_use]
    pub const fn outcome_authority() -> bool {
        false
    }
    #[must_use]
    pub const fn adopts_outcome() -> bool {
        false
    }
    #[must_use]
    pub const fn adopts_work_product() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_is_pinned_to_layer_one_and_honest_provenance() {
        let contract = RedisCloudDatabaseResultContract::baseline().expect("contract");
        assert_eq!(contract.digest().as_str(), CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::truth_authority());
        assert!(!Layer1Authority::consent_authority());
        assert!(!Layer1Authority::effect_authority());
        assert!(!Layer1Authority::receipt_authority());
        assert!(!Layer1Authority::verification_authority());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::adopts_outcome());
        assert!(!Layer1Authority::adopts_work_product());
    }
}
