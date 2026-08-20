//! Standalone Layer-1 governed Google Cloud Bigtable table-posture result.
//!
//! This crate has only bounded, digest-oriented metadata seams for the
//! documented Admin API `tables.get` and `clusters.get` calls. It has no row
//! or cell type, no mutation operation, no credential resolver, and no live
//! HTTP client. Its proposals are review-only Layer-1 evidence.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
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

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::*;
pub use model::*;
pub use provider::*;
pub use service::*;

pub const GCP_BIGTABLE_TABLE_RESULT_SCHEMA_VERSION: &str =
    "hartevo-gcp-bigtable-table-result-contract/v1";
pub const GCP_BIGTABLE_TABLE_RESULT_CONTRACT_VERSION: &str = "gcp-bigtable-table-result-e1/v1";
pub const GCP_BIGTABLE_TABLE_RESULT_PLUGIN_ID: &str = "gcp-bigtable-table-result";
pub const GCP_BIGTABLE_TABLE_RESULT_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const GCP_BIGTABLE_TABLE_RESULT_SERVICE_ID: &str = "gcp.bigtable.table.result";
pub const GCP_BIGTABLE_TABLE_RESULT_SERVICE_NAME: &str = "GcpBigtableTableResultService";
pub const GCP_BIGTABLE_TABLE_RESULT_PROVIDER_ID: &str = "gcp.bigtable.admin";
pub const GCP_BIGTABLE_TABLE_RESULT_PROVIDER_VERSION_TEXT: &str = "1.0.0";
pub const GCP_BIGTABLE_TABLE_RESULT_PROVIDER_SCHEMA: &str =
    "hartevo.gcp-bigtable-table-result-provider/v1";
pub const MISSION_GCP_BIGTABLE_TABLE_CONSUMER_ID: &str =
    "mission.gcp.bigtable.table.result.consumer";
pub const MISSION_GCP_BIGTABLE_TABLE_CONSUMER_SCHEMA: &str =
    "hartevo.mission-gcp-bigtable-table-consumer/v1";
pub const GCP_BIGTABLE_TABLE_RESULT_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const GCP_BIGTABLE_TABLE_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/gcp-bigtable-table-result/gcp-bigtable-table-result.v1.json";
pub const GCP_BIGTABLE_TABLE_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/gcp-bigtable-table-result/gcp-bigtable-table-result.v1.json"
);
pub const GCP_BIGTABLE_API_REVISION: &str = "bigtable-admin-rest-v2-tables-get-clusters-get-r1";
pub const GCP_BIGTABLE_TABLE_GET_OPERATION: &str =
    "GET /v2/projects/{project}/instances/{instance}/tables/{table}?view=SCHEMA_VIEW";
pub const GCP_BIGTABLE_CLUSTER_GET_OPERATION: &str =
    "GET /v2/projects/{project}/instances/{instance}/clusters/{cluster}";
pub const GCP_BIGTABLE_TABLE_PERMISSION: &str = "bigtable.tables.get";
pub const GCP_BIGTABLE_CLUSTER_PERMISSION: &str = "bigtable.clusters.get";
pub const GCP_BIGTABLE_SCOPE_PERMISSION: &str = "mission.scope";

// Short aliases used by integration code and contract-oriented tests.
pub const GCP_BIGTABLE_TABLE_RESULT_SCHEMA: &str = GCP_BIGTABLE_TABLE_RESULT_SCHEMA_VERSION;
pub const GCP_BIGTABLE_TABLE_RESULT_CONTRACT: &str = GCP_BIGTABLE_TABLE_RESULT_CONTRACT_VERSION;
pub const GCP_BIGTABLE_TABLE_RESULT_SERVICE: &str = GCP_BIGTABLE_TABLE_RESULT_SERVICE_ID;
pub const GCP_BIGTABLE_TABLE_RESULT_PROVIDER: &str = GCP_BIGTABLE_TABLE_RESULT_PROVIDER_ID;
pub const GCP_BIGTABLE_TABLE_RESULT_CONSUMER: &str = MISSION_GCP_BIGTABLE_TABLE_CONSUMER_ID;

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_bytes(GCP_BIGTABLE_TABLE_RESULT_CONTRACT_JSON.as_bytes())
}

#[must_use]
pub fn plugin_version_digest() -> Digest {
    Digest::from_text(GCP_BIGTABLE_TABLE_RESULT_PLUGIN_VERSION_TEXT)
}

#[must_use]
pub const fn plugin_version() -> &'static str {
    GCP_BIGTABLE_TABLE_RESULT_PLUGIN_VERSION_TEXT
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractValidationError {
    InvalidJson(String),
    Invariant(&'static str),
}

impl std::fmt::Display for ContractValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJson(error) => write!(formatter, "contract JSON is invalid: {error}"),
            Self::Invariant(error) => write!(formatter, "contract invariant failed: {error}"),
        }
    }
}

impl std::error::Error for ContractValidationError {}

/// Validate the safety-critical metadata that is compiled into this root.
pub fn validate_contract() -> Result<(), ContractValidationError> {
    let document: serde_json::Value = serde_json::from_str(GCP_BIGTABLE_TABLE_RESULT_CONTRACT_JSON)
        .map_err(|error| ContractValidationError::InvalidJson(error.to_string()))?;
    let invariant = |condition: bool, name| {
        condition
            .then_some(())
            .ok_or(ContractValidationError::Invariant(name))
    };
    invariant(
        document["schemaVersion"] == GCP_BIGTABLE_TABLE_RESULT_SCHEMA_VERSION,
        "schema version",
    )?;
    invariant(
        document["contractVersion"] == GCP_BIGTABLE_TABLE_RESULT_CONTRACT_VERSION,
        "contract version",
    )?;
    invariant(
        document["pluginId"] == GCP_BIGTABLE_TABLE_RESULT_PLUGIN_ID,
        "plugin id",
    )?;
    invariant(document["layer"] == 1, "layer one")?;
    invariant(
        document["service"]["id"] == GCP_BIGTABLE_TABLE_RESULT_SERVICE_ID
            && document["service"]["typed"] == GCP_BIGTABLE_TABLE_RESULT_SERVICE_NAME
            && document["service"]["readOnly"] == true
            && document["service"]["liveExecution"] == false
            && document["service"]["proposalOnly"] == true,
        "service boundary",
    )?;
    invariant(
        document["provider"]["id"] == GCP_BIGTABLE_TABLE_RESULT_PROVIDER_ID
            && document["provider"]["typed"] == "GcpBigtableAdminProvider"
            && document["provider"]["native"] == false
            && document["provider"]["connected"] == false
            && document["provider"]["firstParty"] == false
            && document["provider"]["rowReads"] == false
            && document["provider"]["externalWrites"] == false,
        "provider boundary",
    )?;
    invariant(
        document["consumer"]["id"] == MISSION_GCP_BIGTABLE_TABLE_CONSUMER_ID
            && document["consumer"]["typed"] == "MissionGcpBigtableTableConsumer",
        "consumer identity",
    )?;
    for field in [
        "adoptsOutcome",
        "truthAuthority",
        "consentAuthority",
        "effectAuthority",
        "receiptAuthority",
        "verificationAuthority",
        "outcomeAuthority",
    ] {
        invariant(
            !document["consumer"][field].as_bool().unwrap_or(true),
            field,
        )?;
    }
    for provenance in ["fixture", "recording", "fake", "loopback", "blocked_env"] {
        invariant(
            document["provider"]["acceptedProvenance"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| value == provenance)),
            "offline provenance",
        )?;
    }
    let allow = document["readPolicy"]["allow"]
        .as_array()
        .ok_or(ContractValidationError::Invariant("read allow-list"))?;
    invariant(
        allow.iter().any(|value| value == "get_table_schema")
            && allow.iter().any(|value| value == "get_cluster_posture"),
        "two bounded reads",
    )?;
    let deny = document["readPolicy"]["deny"]
        .as_array()
        .ok_or(ContractValidationError::Invariant("read deny-list"))?;
    for forbidden in [
        "read_rows",
        "read_cells",
        "read_values",
        "mutate_schema",
        "backup",
        "restore",
        "set_iam_policy",
        "credential_material",
        "pii",
    ] {
        invariant(
            deny.iter().any(|value| value == forbidden),
            "forbidden operation",
        )?;
    }
    for field in [
        "connected",
        "nativeProvider",
        "firstParty",
        "durableReceipt",
        "truthAuthority",
        "consentAuthority",
        "effectAuthority",
        "verificationAuthority",
        "outcomeAuthority",
        "blockedEnvironmentIsNative",
    ] {
        invariant(
            !document["nativeClaims"][field].as_bool().unwrap_or(true),
            field,
        )?;
    }
    Ok(())
}

/// Layer 1 intentionally reports no external or kernel authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Layer1Authority {
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
}

impl Layer1Authority {
    #[must_use]
    pub const fn offline() -> Self {
        Self {
            connected: false,
            native_provider: false,
            first_party: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
        }
    }

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
    pub const fn truth() -> bool {
        false
    }
    #[must_use]
    pub const fn consent() -> bool {
        false
    }
    #[must_use]
    pub const fn effect() -> bool {
        false
    }
    #[must_use]
    pub const fn receipt() -> bool {
        false
    }
    #[must_use]
    pub const fn verification() -> bool {
        false
    }
    #[must_use]
    pub const fn outcome() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_is_layer_one_and_authority_free() {
        validate_contract().expect("contract invariants");
        assert_eq!(Layer1Authority::offline(), Layer1Authority::offline());
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::truth());
    }
}

#[cfg(test)]
mod adversarial_tests;
