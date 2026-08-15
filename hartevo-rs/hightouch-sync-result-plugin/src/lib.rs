//! Standalone Layer-1 Hightouch reverse-ETL sync-result plugin.
//!
//! The crate exposes typed, bounded metadata-only seams for
//! [`HightouchSyncResultService`], [`HightouchProvider`], and
//! [`MissionHightouchSyncConsumer`]. It never resolves a native API key,
//! opens a live Hightouch connection, triggers or cancels a sync, writes to a
//! destination, exposes source rows, creates a kernel receipt, or adopts a
//! Work Product/Outcome.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::result_large_err,
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

pub use consumer::{
    ConsumerError, HightouchMissionResult, HightouchMissionResultState, HightouchObservationResult,
    MissionHightouchSyncConsumer, MissionHightouchSyncConsumerError, MissionHightouchSyncResult,
    MissionHightouchSyncResultState, MissionResultState,
};
pub use model::*;
pub use provider::{
    BlockedEnvHightouchTransport, FakeHightouchTransport, FixtureHightouchTransport,
    HightouchProvider, HightouchProviderDefinition, HightouchProviderError, HightouchProviderRead,
    HightouchRequest, HightouchResponse, HightouchTransport, HightouchTransportError,
    LoopbackHightouchTransport, RecordingHightouchTransport,
};
pub use service::{
    HightouchSyncResultService, HightouchSyncResultServiceDefinition,
    HightouchSyncResultServiceError,
};

pub const HIGHTOUCH_SYNC_RESULT_SCHEMA_VERSION: &str = "hartevo.hightouch-sync-result/v1";
pub const HIGHTOUCH_SYNC_RESULT_CONTRACT_VERSION: &str = "EXT-HIGHTOUCH-01-L1/v1";
pub const HIGHTOUCH_SYNC_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const HIGHTOUCH_SYNC_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/hightouch-sync-result/hightouch-sync-result.v1.json";
pub const HIGHTOUCH_SYNC_RESULT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/hightouch-sync-result/hightouch-sync-result.v1.json");
pub const HIGHTOUCH_SYNC_RESULT_SERVICE_ID: &str = "hightouch.sync-result.read";
pub const HIGHTOUCH_PROVIDER_ID: &str = "hightouch.sync-result.metadata";
pub const HIGHTOUCH_PROVIDER_VERSION: &str = "1.0.0";
pub const HIGHTOUCH_PROVIDER_API_REVISION: &str = "hightouch-api-v1-metadata-read-r1";
pub const MISSION_HIGHTOUCH_SYNC_CONSUMER_ID: &str = "mission.hightouch-sync-result";
pub const HIGHTOUCH_API_BASE_URL: &str = "https://api.hightouch.com/api/v1";
pub const HIGHTOUCH_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const HIGHTOUCH_METADATA_PERMISSION: &str = "hightouch:metadata.read";

/// SHA-256 of the exact checked-in contract bytes.
#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(HIGHTOUCH_SYNC_RESULT_CONTRACT_JSON.as_bytes())
}

/// SHA-256 binding the provider identity, API revision, and GET allowlist.
#[must_use]
pub fn provider_digest() -> Digest {
    canonical_digest(&(
        HIGHTOUCH_PROVIDER_ID,
        HIGHTOUCH_PROVIDER_VERSION,
        HIGHTOUCH_PROVIDER_API_REVISION,
        HIGHTOUCH_API_BASE_URL,
        [
            "GET /workspaces/{workspaceId}",
            "GET /sources/{sourceId}",
            "GET /models/{modelId}",
            "GET /destinations/{destinationId}",
            "GET /syncs/{syncId}",
            "GET /syncs/{syncId}/runs",
        ],
    ))
}

/// Layer 1 deliberately reports no native or kernel authority.
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
    pub const fn external_writes() -> bool {
        false
    }

    #[must_use]
    pub const fn sync_effects() -> bool {
        false
    }

    #[must_use]
    pub const fn destination_writes() -> bool {
        false
    }

    #[must_use]
    pub const fn source_rows() -> bool {
        false
    }

    #[must_use]
    pub const fn raw_credentials() -> bool {
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
    pub const fn work_product_adoption() -> bool {
        false
    }

    #[must_use]
    pub const fn outcome_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn verified_readback() -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContractValidationError {
    #[error("contract JSON is invalid: {0}")]
    Json(String),
    #[error("contract field {0} is not the frozen Layer-1 value")]
    FrozenField(&'static str),
}

/// Validates the checked-in contract and its immutable Layer-1 honesty pins.
#[allow(clippy::too_many_lines)]
pub fn validate_contract() -> std::result::Result<(), ContractValidationError> {
    let contract: serde_json::Value = serde_json::from_str(HIGHTOUCH_SYNC_RESULT_CONTRACT_JSON)
        .map_err(|error| ContractValidationError::Json(error.to_string()))?;
    let is = |path: &'static str, condition: bool| {
        if condition {
            Ok(())
        } else {
            Err(ContractValidationError::FrozenField(path))
        }
    };
    is(
        "schemaVersion",
        contract["schemaVersion"] == HIGHTOUCH_SYNC_RESULT_SCHEMA_VERSION,
    )?;
    is(
        "contractVersion",
        contract["contractVersion"] == HIGHTOUCH_SYNC_RESULT_CONTRACT_VERSION,
    )?;
    is(
        "pluginVersion",
        contract["pluginVersion"] == HIGHTOUCH_SYNC_RESULT_PLUGIN_VERSION,
    )?;
    is("layer", contract["layer"] == 1)?;
    is(
        "service.id",
        contract["service"]["id"] == HIGHTOUCH_SYNC_RESULT_SERVICE_ID,
    )?;
    is(
        "provider.id",
        contract["provider"]["id"] == HIGHTOUCH_PROVIDER_ID,
    )?;
    is(
        "provider.apiRevision",
        contract["provider"]["apiRevision"] == HIGHTOUCH_PROVIDER_API_REVISION,
    )?;
    is(
        "provider.baseUrl",
        contract["provider"]["baseUrl"] == HIGHTOUCH_API_BASE_URL,
    )?;
    is(
        "consumer.id",
        contract["consumer"]["id"] == MISSION_HIGHTOUCH_SYNC_CONSUMER_ID,
    )?;
    for path in [
        "authority.connected",
        "authority.nativeProvider",
        "authority.externalWrites",
        "authority.syncEffects",
        "authority.destinationWrites",
        "authority.sourceRows",
        "authority.rawCredentials",
        "authority.durableProviderReceipt",
        "authority.kernelAuthority",
        "authority.workProductAdoption",
        "authority.outcomeAuthority",
        "authority.verifiedReadback",
        "provider.native",
        "provider.connected",
    ] {
        let value = path
            .split('.')
            .fold(&contract, |current, key| &current[key]);
        is(path, value == false)?;
    }
    is(
        "allowlist.writes",
        contract["allowlist"]["writes"]
            .as_array()
            .is_some_and(Vec::is_empty),
    )?;
    is(
        "provider.transportProvenance",
        contract["provider"]["transportProvenance"]
            == serde_json::json!(["fixture", "recording", "fake", "loopback", "BLOCKED_ENV"]),
    )?;
    is(
        "registration.reversible",
        contract["registration"]["reversible"] == true,
    )?;
    is(
        "registration.revocable",
        contract["registration"]["revocable"] == true,
    )?;
    Ok(())
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_contract_is_machine_readable_and_layer_one_honest() {
        validate_contract().expect("contract validates");
        assert!(!contract_digest().as_str().is_empty());
        assert_eq!(contract_digest().as_str().len(), 64);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::external_writes());
        assert!(!Layer1Authority::sync_effects());
        assert!(!Layer1Authority::destination_writes());
        assert!(!Layer1Authority::source_rows());
        assert!(!Layer1Authority::raw_credentials());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::work_product_adoption());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::verified_readback());
    }
}
