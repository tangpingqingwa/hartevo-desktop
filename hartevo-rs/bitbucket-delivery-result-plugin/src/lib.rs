//! Standalone Layer-1 Bitbucket Cloud delivery-result plugin.
//!
//! This crate exposes typed, bounded repository/PR/commit-status/pipeline/
//! deployment evidence for a Mission.  It is deliberately read/proposal/
//! recording-only: no native Connected claim, repository mutation, merge,
//! approval, pipeline trigger, raw source/diff/comment/artifact retention, or
//! generic CI authority exists here.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::if_not_else)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::result_large_err)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::struct_excessive_bools)]

use hartevo_plugin_runtime::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId, Digest as RuntimeDigest,
    PluginContributions, PluginDefinition, PluginId, PluginScope, PluginVersion,
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
    BitbucketDeliveryObservation, BitbucketDeliveryResult, MissionBitbucketDeliveryConsumer,
    MissionBitbucketDeliveryReadResult, MissionBitbucketDeliveryResult,
};
pub use model::*;
pub use provider::{
    AccessToken, BitbucketCloudProvider, BitbucketCredentialResolver,
    BitbucketCredentialResolverError, BitbucketDeliveryError, BitbucketProvider,
    BitbucketRegistration, BitbucketRegistrationRequest, BlockedEnvCredentialResolver,
    CredentialError, NativeProbe, NativeProbeStatus, RegistrationState,
    native_probe_from_environment,
};
pub use service::{
    BitbucketDeliveryCapability, BitbucketDeliveryOperation, BitbucketDeliveryResultService,
    BitbucketDeliveryResultServiceDefinition, BitbucketDeliveryResultServiceError,
    BitbucketServiceDefinition,
};
pub use transport::{
    BitbucketDeliveryTransport, BitbucketEndpoint, BitbucketHttpRequest, BitbucketHttpResponse,
    BitbucketTransportError, BlockedEnvBitbucketTransport, BlockedEnvTransport,
    FakeBitbucketTransport, FixtureBitbucketTransport, LoopbackBitbucketTransport,
    RecordingBitbucketTransport, RequestBounds,
};

pub const BITBUCKET_DELIVERY_RESULT_SCHEMA_VERSION: &str =
    "hartevo.bitbucket-delivery-result-contract/v1";
pub const BITBUCKET_DELIVERY_RESULT_CONTRACT_VERSION: &str = "bitbucket-delivery-result/v1";
pub const BITBUCKET_DELIVERY_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const BITBUCKET_DELIVERY_RESULT_PLUGIN_ID: &str = "bitbucket-delivery-result";
pub const BITBUCKET_DELIVERY_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/bitbucket-delivery-result/bitbucket-delivery-result.v1.json";
pub const BITBUCKET_DELIVERY_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/bitbucket-delivery-result/bitbucket-delivery-result.v1.json"
);
pub const BITBUCKET_DELIVERY_RESULT_SERVICE_ID: &str = "bitbucket.delivery.result";
pub const BITBUCKET_DELIVERY_RESULT_SERVICE_NAME: &str = "BitbucketDeliveryResultService";
pub const BITBUCKET_DELIVERY_RESULT_PROVIDER_ID: &str = "bitbucket.cloud.delivery";
pub const BITBUCKET_DELIVERY_RESULT_PROVIDER_NAME: &str = "BitbucketProvider";
pub const BITBUCKET_DELIVERY_RESULT_CONSUMER_ID: &str = "mission.bitbucket-delivery-result";
pub const BITBUCKET_DELIVERY_RESULT_CONSUMER_NAME: &str = "MissionBitbucketDeliveryConsumer";
pub const BITBUCKET_DELIVERY_RESULT_SERVICE_SCHEMA: &str =
    "hartevo.bitbucket-delivery-result-service/v1";
pub const BITBUCKET_DELIVERY_RESULT_PROVIDER_SCHEMA: &str = "hartevo.bitbucket-provider/v1";
pub const BITBUCKET_DELIVERY_RESULT_CONSUMER_SCHEMA: &str =
    "hartevo.mission-bitbucket-delivery-consumer/v1";
pub const BITBUCKET_API_ORIGIN: &str = "https://api.bitbucket.org";
pub const BITBUCKET_OFFICIAL_API: &str = "https://developer.atlassian.com/cloud/bitbucket/rest/";
pub const BITBUCKET_API_REVISION: &str = "bitbucket-cloud-rest-2.0-r1";
pub const BITBUCKET_PROVIDER_REVISION: &str = "bitbucket-cloud-rest-2.0-r1";
pub const BITBUCKET_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_STATUS_RECORDS: usize = 128;
pub const MAX_DEPLOYMENTS: usize = 8;
pub const MAX_PAGES: u16 = 4;
pub const PAGE_SIZE: u16 = 50;
pub const MAX_REQUESTS_PER_MINUTE: usize = 30;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;

#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(BITBUCKET_DELIVERY_RESULT_CONTRACT_JSON.as_bytes())
}

#[must_use]
pub fn plugin_version() -> PluginVersion {
    PluginVersion::new(0, 1, 0)
}

/// Layer 1's negative authority declaration.
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

    pub const fn external_writes() -> bool {
        false
    }

    pub const fn generic_ci_authority() -> bool {
        false
    }

    pub const fn outcome_authority() -> bool {
        false
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ContractError {
    #[error("Bitbucket delivery contract JSON is invalid: {0}")]
    Json(String),
    #[error("Bitbucket delivery contract does not match the typed Layer-1 boundary")]
    Drift,
}

#[derive(Clone, Debug)]
pub struct BitbucketDeliveryResultContract {
    document: Value,
}

impl BitbucketDeliveryResultContract {
    pub fn baseline() -> Result<Self, ContractError> {
        let document = serde_json::from_str::<Value>(BITBUCKET_DELIVERY_RESULT_CONTRACT_JSON)
            .map_err(|error| ContractError::Json(error.to_string()))?;
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

    pub fn validate(&self) -> Result<(), ContractError> {
        let get = |path: &[&str]| -> Option<&Value> {
            path.iter()
                .try_fold(&self.document, |value, key| value.get(*key))
        };
        let states = get(&["states"]).and_then(Value::as_array);
        let transports = get(&["provider", "transportProvenance"]).and_then(Value::as_array);
        let authority = get(&["authority"]);
        let registration = get(&["registration"]);
        let valid_states = states.is_some_and(|values| {
            [
                "open",
                "merged",
                "declined",
                "failed",
                "partial",
                "denied",
                "rate_limit",
                "provider_unknown",
                "tamper",
            ]
            .iter()
            .all(|state| values.iter().any(|value| value == state))
        });
        let valid_transports = transports.is_some_and(|values| {
            ["fixture", "recording", "fake", "loopback", "BLOCKED_ENV"]
                .iter()
                .all(|transport| values.iter().any(|value| value == transport))
        });
        if get(&["schemaVersion"])
            != Some(&Value::String(
                BITBUCKET_DELIVERY_RESULT_SCHEMA_VERSION.to_owned(),
            ))
            || get(&["contractVersion"])
                != Some(&Value::String(
                    BITBUCKET_DELIVERY_RESULT_CONTRACT_VERSION.to_owned(),
                ))
            || get(&["pluginVersion"])
                != Some(&Value::String(
                    BITBUCKET_DELIVERY_RESULT_PLUGIN_VERSION.to_owned(),
                ))
            || get(&["layer"]) != Some(&Value::from(1))
            || get(&["officialApi"]) != Some(&Value::String(BITBUCKET_OFFICIAL_API.to_owned()))
            || get(&["service", "id"])
                != Some(&Value::String(
                    BITBUCKET_DELIVERY_RESULT_SERVICE_ID.to_owned(),
                ))
            || get(&["provider", "id"])
                != Some(&Value::String(
                    BITBUCKET_DELIVERY_RESULT_PROVIDER_ID.to_owned(),
                ))
            || get(&["consumer", "id"])
                != Some(&Value::String(
                    BITBUCKET_DELIVERY_RESULT_CONSUMER_ID.to_owned(),
                ))
            || get(&["provider", "apiRevision"])
                != Some(&Value::String(BITBUCKET_API_REVISION.to_owned()))
            || !valid_states
            || !valid_transports
            || authority.is_none_or(|value| {
                value.get("connected") != Some(&Value::Bool(false))
                    || value.get("native") != Some(&Value::Bool(false))
                    || value.get("firstParty") != Some(&Value::Bool(false))
                    || value.get("externalWrites") != Some(&Value::Bool(false))
                    || value.get("genericCiAuthority") != Some(&Value::Bool(false))
            })
            || registration.is_none_or(|value| {
                value.get("contractDigestBound") != Some(&Value::Bool(true))
                    || value.get("providerRevisionBound") != Some(&Value::Bool(true))
                    || value.get("secretReferenceDigestBound") != Some(&Value::Bool(true))
                    || value.get("scopeDigestBound") != Some(&Value::Bool(true))
                    || value.get("idempotencyBound") != Some(&Value::Bool(true))
                    || value.get("reversible") != Some(&Value::Bool(true))
                    || value.get("revocable") != Some(&Value::Bool(true))
            })
        {
            return Err(ContractError::Drift);
        }
        Ok(())
    }
}

pub fn validate_contract() -> Result<(), ContractError> {
    BitbucketDeliveryResultContract::baseline()?.validate()
}

/// Builds the plugin-runtime contribution set for one exact Project/Mission
/// generation. Runtime mounting remains a host decision.
pub fn plugin_definition(scope: PluginScope) -> Result<PluginDefinition, BitbucketDeliveryError> {
    let plugin_id = PluginId::new(BITBUCKET_DELIVERY_RESULT_PLUGIN_ID)?;
    let service_id = ServiceId::new(BITBUCKET_DELIVERY_RESULT_SERVICE_ID)?;
    let provider_id = ProviderId::new(BITBUCKET_DELIVERY_RESULT_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(BITBUCKET_DELIVERY_RESULT_CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(BITBUCKET_DELIVERY_RESULT_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(BITBUCKET_DELIVERY_RESULT_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(BITBUCKET_DELIVERY_RESULT_CONSUMER_SCHEMA),
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

#[cfg(test)]
mod contract_document_tests {
    use super::{
        BITBUCKET_API_REVISION, BITBUCKET_DELIVERY_RESULT_CONTRACT_VERSION,
        BITBUCKET_DELIVERY_RESULT_PROVIDER_ID, BITBUCKET_DELIVERY_RESULT_SERVICE_ID,
        BITBUCKET_OFFICIAL_API, Layer1Authority, NativeProbeStatus, native_probe_from_environment,
        validate_contract,
    };

    #[test]
    fn contract_is_machine_readable_and_native_gap_is_honest() {
        validate_contract().expect("Bitbucket contract validates");
        let contract = super::BitbucketDeliveryResultContract::baseline().expect("contract");
        let document = contract.document();
        assert_eq!(
            document["service"]["id"],
            BITBUCKET_DELIVERY_RESULT_SERVICE_ID
        );
        assert_eq!(
            document["provider"]["id"],
            BITBUCKET_DELIVERY_RESULT_PROVIDER_ID
        );
        assert_eq!(document["provider"]["apiRevision"], BITBUCKET_API_REVISION);
        assert_eq!(document["officialApi"], BITBUCKET_OFFICIAL_API);
        assert_eq!(
            document["contractVersion"],
            BITBUCKET_DELIVERY_RESULT_CONTRACT_VERSION
        );
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert_eq!(
            native_probe_from_environment().status,
            NativeProbeStatus::BlockedEnv
        );
    }
}
