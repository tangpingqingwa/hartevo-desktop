//! Standalone Layer-1 governed Google Cloud Build result plugin.
//!
//! The crate exposes typed bounded list/get, proposal, recording, verification,
//! and Mission projection seams. It never resolves native credentials, sends
//! HTTPS, creates/cancels/retries builds, mutates triggers, reads raw logs,
//! claims build correctness, or adopts kernel Truth, Outcome, or Work Product
//! authority.

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
    clippy::type_complexity,
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

pub const GCP_CLOUD_BUILD_SCHEMA_VERSION: &str = "hartevo.gcp-cloud-build-result/v1";
pub const GCP_CLOUD_BUILD_CONTRACT_VERSION: &str = "gcp-cloud-build-result/v1";
pub const GCP_CLOUD_BUILD_PLUGIN_ID: &str = "gcp-cloud-build-result";
pub const GCP_CLOUD_BUILD_PLUGIN_VERSION_TEXT: &str = "0.1.0";
pub const GCP_CLOUD_BUILD_SERVICE_ID: &str = "gcp.cloud-build.result";
pub const GCP_CLOUD_BUILD_SERVICE_NAME: &str = "GcpCloudBuildResultService";
pub const GCP_CLOUD_BUILD_PROVIDER_ID: &str = "gcp.cloud-build";
pub const GCP_CLOUD_BUILD_PROVIDER_VERSION_TEXT: &str = "1.0.0";
pub const GCP_CLOUD_BUILD_PROVIDER_SCHEMA: &str = "hartevo.gcp-cloud-build-provider/v1";
pub const MISSION_GCP_BUILD_CONSUMER_ID: &str = "mission.gcp.cloud-build.result";
pub const MISSION_GCP_BUILD_CONSUMER_SCHEMA: &str = "hartevo.mission-gcp-build-consumer/v1";
pub const GCP_CLOUD_BUILD_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const GCP_CLOUD_BUILD_CONTRACT_PATH: &str =
    "contracts/plugins/gcp-cloud-build-result/gcp-cloud-build-result.v1.json";
pub const GCP_CLOUD_BUILD_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/gcp-cloud-build-result/gcp-cloud-build-result.v1.json"
);

pub const GCP_CLOUD_BUILD_RESULT_SCHEMA_VERSION: &str = GCP_CLOUD_BUILD_SCHEMA_VERSION;
pub const GCP_CLOUD_BUILD_RESULT_CONTRACT_VERSION: &str = GCP_CLOUD_BUILD_CONTRACT_VERSION;
pub const GCP_CLOUD_BUILD_RESULT_CONTRACT_JSON: &str = GCP_CLOUD_BUILD_CONTRACT_JSON;

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_bytes(GCP_CLOUD_BUILD_CONTRACT_JSON.as_bytes())
}

#[must_use]
pub fn plugin_version() -> &'static str {
    GCP_CLOUD_BUILD_PLUGIN_VERSION_TEXT
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

pub fn validate_contract() -> Result<(), ContractValidationError> {
    let document: serde_json::Value = serde_json::from_str(GCP_CLOUD_BUILD_CONTRACT_JSON)
        .map_err(|error| ContractValidationError::InvalidJson(error.to_string()))?;
    let invariant = |condition: bool, name| {
        condition
            .then_some(())
            .ok_or(ContractValidationError::Invariant(name))
    };
    invariant(
        document["schemaVersion"] == GCP_CLOUD_BUILD_SCHEMA_VERSION,
        "schema version",
    )?;
    invariant(
        document["contractVersion"] == GCP_CLOUD_BUILD_CONTRACT_VERSION,
        "contract version",
    )?;
    invariant(document["layer"] == 1, "layer one")?;
    invariant(
        document["service"]["id"] == GCP_CLOUD_BUILD_SERVICE_ID,
        "service id",
    )?;
    invariant(
        document["provider"]["id"] == GCP_CLOUD_BUILD_PROVIDER_ID,
        "provider id",
    )?;
    invariant(
        document["consumer"]["id"] == MISSION_GCP_BUILD_CONSUMER_ID,
        "consumer id",
    )?;
    for field in [
        "connected",
        "nativeProvider",
        "firstParty",
        "credentialResolution",
        "durableProviderReceipt",
        "independentReadback",
        "kernelTruthAuthority",
        "outcomeAuthority",
        "workProductAdoption",
        "externalWrites",
    ] {
        invariant(
            !document["authority"][field].as_bool().unwrap_or(true),
            field,
        )?;
    }
    invariant(
        document["provider"]["allowlistedMethods"]
            .as_array()
            .is_some_and(|methods| methods.len() == 2),
        "two read methods",
    )?;
    invariant(
        document["allowlist"]["writes"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "no writes",
    )?;
    Ok(())
}

/// Layer 1 intentionally reports no external or kernel authority.
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
    pub const fn credential_resolution() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_provider_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn independent_readback() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_native_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn independent_native_readback() -> bool {
        false
    }

    #[must_use]
    pub const fn external_writes() -> bool {
        false
    }

    #[must_use]
    pub const fn creates_builds() -> bool {
        false
    }

    #[must_use]
    pub const fn cancels_builds() -> bool {
        false
    }

    #[must_use]
    pub const fn retries_builds() -> bool {
        false
    }

    #[must_use]
    pub const fn trigger_mutation() -> bool {
        false
    }

    #[must_use]
    pub const fn raw_logs() -> bool {
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
    pub const fn adopted_outcome() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use super::{
        ContractValidationError, GCP_CLOUD_BUILD_BLOCKED_ENV, GCP_CLOUD_BUILD_CONTRACT_JSON,
        GCP_CLOUD_BUILD_CONTRACT_VERSION, GCP_CLOUD_BUILD_PROVIDER_ID,
        GCP_CLOUD_BUILD_SCHEMA_VERSION, GCP_CLOUD_BUILD_SERVICE_ID, Layer1Authority,
        MISSION_GCP_BUILD_CONSUMER_ID, contract_digest, validate_contract,
    };

    #[test]
    fn contract_is_machine_readable_and_honest() {
        validate_contract().expect("Cloud Build contract invariants");
        let document: serde_json::Value =
            serde_json::from_str(GCP_CLOUD_BUILD_CONTRACT_JSON).expect("contract JSON");
        assert_eq!(document["schemaVersion"], GCP_CLOUD_BUILD_SCHEMA_VERSION);
        assert_eq!(
            document["contractVersion"],
            GCP_CLOUD_BUILD_CONTRACT_VERSION
        );
        assert_eq!(document["service"]["id"], GCP_CLOUD_BUILD_SERVICE_ID);
        assert_eq!(document["provider"]["id"], GCP_CLOUD_BUILD_PROVIDER_ID);
        assert_eq!(document["consumer"]["id"], MISSION_GCP_BUILD_CONSUMER_ID);
        assert_eq!(document["authority"]["connected"], false);
        assert_eq!(document["authority"]["nativeProvider"], false);
        assert_eq!(document["authority"]["outcomeAuthority"], false);
        assert_eq!(document["provider"]["native"], false);
        assert_eq!(document["provider"]["connected"], false);
        assert_eq!(GCP_CLOUD_BUILD_BLOCKED_ENV, "BLOCKED_ENV");
        assert_eq!(contract_digest().len(), 64);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::credential_resolution());
        assert!(!Layer1Authority::external_writes());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::work_product_adoption());
    }

    #[test]
    fn contract_validation_has_a_typed_error_surface() {
        let _ = ContractValidationError::Invariant("test");
    }
}
