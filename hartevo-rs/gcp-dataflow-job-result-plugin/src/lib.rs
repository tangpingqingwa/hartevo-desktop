//! Standalone Layer-1 governed Google Cloud Dataflow job-result plugin.
//!
//! This crate exposes typed bounded list/get/getMetrics, proposal, recording,
//! verification, and Mission projection seams. It never resolves native
//! OAuth/service-account credentials, sends live HTTPS, creates/updates/cancels
//! or drains jobs, reads raw pipeline options/logs/worker IPs/secrets, or
//! adopts kernel Truth, Outcome, or Work Product authority.

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

pub const GCP_DATAFLOW_JOB_RESULT_SCHEMA_VERSION: &str = "hartevo.gcp-dataflow-job-result/v1";
pub const GCP_DATAFLOW_JOB_RESULT_CONTRACT_VERSION: &str = "gcp-dataflow-job-result/v1";
pub const GCP_DATAFLOW_JOB_RESULT_PLUGIN_ID: &str = "gcp-dataflow-job-result";
pub const GCP_DATAFLOW_JOB_RESULT_PLUGIN_VERSION_TEXT: &str = "0.1.0";
pub const GCP_DATAFLOW_JOB_RESULT_SERVICE_ID: &str = "gcp.dataflow.job-result";
pub const GCP_DATAFLOW_JOB_RESULT_SERVICE_NAME: &str = "GcpDataflowJobResultService";
pub const GCP_DATAFLOW_JOB_RESULT_PROVIDER_ID: &str = "gcp.dataflow.jobs";
pub const GCP_DATAFLOW_JOB_RESULT_PROVIDER_VERSION_TEXT: &str = "1.0.0";
pub const GCP_DATAFLOW_JOB_RESULT_PROVIDER_SCHEMA: &str =
    "hartevo.gcp-dataflow-job-result-provider/v1";
pub const MISSION_GCP_DATAFLOW_CONSUMER_ID: &str = "mission.gcp.dataflow.job-result";
pub const MISSION_GCP_DATAFLOW_CONSUMER_SCHEMA: &str = "hartevo.mission-gcp-dataflow-consumer/v1";
pub const GCP_DATAFLOW_JOB_RESULT_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const GCP_DATAFLOW_JOB_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/gcp-dataflow-job-result/gcp-dataflow-job-result.v1.json";
pub const GCP_DATAFLOW_JOB_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/gcp-dataflow-job-result/gcp-dataflow-job-result.v1.json"
);

pub const GCP_DATAFLOW_SCHEMA_VERSION: &str = GCP_DATAFLOW_JOB_RESULT_SCHEMA_VERSION;
pub const GCP_DATAFLOW_CONTRACT_VERSION: &str = GCP_DATAFLOW_JOB_RESULT_CONTRACT_VERSION;
pub const GCP_DATAFLOW_PLUGIN_ID: &str = GCP_DATAFLOW_JOB_RESULT_PLUGIN_ID;
pub const GCP_DATAFLOW_PLUGIN_VERSION_TEXT: &str = GCP_DATAFLOW_JOB_RESULT_PLUGIN_VERSION_TEXT;
pub const GCP_DATAFLOW_SERVICE_ID: &str = GCP_DATAFLOW_JOB_RESULT_SERVICE_ID;
pub const GCP_DATAFLOW_PROVIDER_ID: &str = GCP_DATAFLOW_JOB_RESULT_PROVIDER_ID;
pub const GCP_DATAFLOW_CONTRACT_JSON: &str = GCP_DATAFLOW_JOB_RESULT_CONTRACT_JSON;

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_bytes(GCP_DATAFLOW_JOB_RESULT_CONTRACT_JSON.as_bytes())
}

#[must_use]
pub fn plugin_version_digest() -> Digest {
    Digest::from_text(GCP_DATAFLOW_JOB_RESULT_PLUGIN_VERSION_TEXT)
}

#[must_use]
pub fn plugin_version() -> &'static str {
    GCP_DATAFLOW_JOB_RESULT_PLUGIN_VERSION_TEXT
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
    let document: serde_json::Value =
        serde_json::from_str(GCP_DATAFLOW_JOB_RESULT_CONTRACT_JSON)
            .map_err(|error| ContractValidationError::InvalidJson(error.to_string()))?;
    let invariant = |condition: bool, name| {
        condition
            .then_some(())
            .ok_or(ContractValidationError::Invariant(name))
    };
    invariant(
        document["schemaVersion"] == GCP_DATAFLOW_JOB_RESULT_SCHEMA_VERSION,
        "schema version",
    )?;
    invariant(
        document["contractVersion"] == GCP_DATAFLOW_JOB_RESULT_CONTRACT_VERSION,
        "contract version",
    )?;
    invariant(
        document["pluginId"] == GCP_DATAFLOW_JOB_RESULT_PLUGIN_ID,
        "plugin id",
    )?;
    invariant(document["layer"] == 1, "layer one")?;
    invariant(
        document["service"]["id"] == GCP_DATAFLOW_JOB_RESULT_SERVICE_ID,
        "service id",
    )?;
    invariant(
        document["provider"]["id"] == GCP_DATAFLOW_JOB_RESULT_PROVIDER_ID,
        "provider id",
    )?;
    invariant(
        document["consumer"]["id"] == MISSION_GCP_DATAFLOW_CONSUMER_ID,
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
        "kernelConsentAuthority",
        "kernelEffectAuthority",
        "kernelReceiptAuthority",
        "kernelVerificationAuthority",
        "outcomeAuthority",
        "workProductAdoption",
        "externalWrites",
        "parallelRegistry",
    ] {
        invariant(
            !document["authority"][field].as_bool().unwrap_or(true),
            field,
        )?;
    }
    invariant(
        document["provider"]["allowlistedMethods"]
            .as_array()
            .is_some_and(|methods| methods.len() == 3),
        "three read methods",
    )?;
    invariant(
        document["allowlist"]["writes"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "no writes",
    )?;
    for provenance in ["fixture", "recording", "loopback", "blockedEnv"] {
        invariant(
            document["provenance"][provenance] == "non_native_non_connected_non_first_party",
            "provenance",
        )?;
    }
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
    pub const fn external_writes() -> bool {
        false
    }

    #[must_use]
    pub const fn creates_jobs() -> bool {
        false
    }

    #[must_use]
    pub const fn updates_jobs() -> bool {
        false
    }

    #[must_use]
    pub const fn cancels_jobs() -> bool {
        false
    }

    #[must_use]
    pub const fn drains_jobs() -> bool {
        false
    }

    #[must_use]
    pub const fn raw_pipeline_options() -> bool {
        false
    }

    #[must_use]
    pub const fn raw_logs() -> bool {
        false
    }

    #[must_use]
    pub const fn worker_ips() -> bool {
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
}

#[cfg(test)]
mod contract_document_tests {
    use super::*;

    #[test]
    fn contract_is_machine_readable_and_honest() {
        validate_contract().expect("Dataflow contract invariants");
        let document: serde_json::Value =
            serde_json::from_str(GCP_DATAFLOW_JOB_RESULT_CONTRACT_JSON).expect("contract JSON");
        assert_eq!(
            document["schemaVersion"],
            GCP_DATAFLOW_JOB_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            GCP_DATAFLOW_JOB_RESULT_CONTRACT_VERSION
        );
        assert_eq!(
            document["provider"]["id"],
            GCP_DATAFLOW_JOB_RESULT_PROVIDER_ID
        );
        assert_eq!(document["authority"]["connected"], false);
        assert_eq!(contract_digest().len(), 64);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::credential_resolution());
        assert!(!Layer1Authority::creates_jobs());
        assert!(!Layer1Authority::updates_jobs());
        assert!(!Layer1Authority::cancels_jobs());
        assert!(!Layer1Authority::drains_jobs());
        assert!(!Layer1Authority::raw_pipeline_options());
        assert!(!Layer1Authority::raw_logs());
        assert!(!Layer1Authority::worker_ips());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::work_product_adoption());
    }
}
