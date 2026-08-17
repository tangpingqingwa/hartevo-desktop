//! Standalone Layer-1 governed Google Cloud Scheduler result plugin.
//!
//! This crate owns only typed, bounded, redacted `jobs.list`/`jobs.get`
//! proposal and evidence seams. It never resolves credentials, performs live
//! HTTPS, writes Scheduler state, invokes a target, or adopts kernel authority.

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

pub const GCP_CLOUD_SCHEDULER_SCHEMA_VERSION: &str = "hartevo.gcp-cloud-scheduler-result/v1";
pub const GCP_CLOUD_SCHEDULER_CONTRACT_VERSION: &str = "gcp-cloud-scheduler-result/v1";
pub const GCP_CLOUD_SCHEDULER_PLUGIN_ID: &str = "gcp-cloud-scheduler-result";
pub const GCP_CLOUD_SCHEDULER_PLUGIN_VERSION_TEXT: &str = "0.1.0";
pub const GCP_CLOUD_SCHEDULER_SERVICE_ID: &str = "gcp.cloud-scheduler.result";
pub const GCP_CLOUD_SCHEDULER_SERVICE_NAME: &str = "GcpCloudSchedulerResultService";
pub const GCP_CLOUD_SCHEDULER_PROVIDER_ID: &str = "gcp.cloud-scheduler";
pub const GCP_CLOUD_SCHEDULER_PROVIDER_VERSION_TEXT: &str = "1.0.0";
pub const GCP_CLOUD_SCHEDULER_PROVIDER_SCHEMA: &str = "hartevo.gcp-cloud-scheduler-provider/v1";
pub const MISSION_GCP_CLOUD_SCHEDULER_CONSUMER_ID: &str = "mission.gcp.cloud-scheduler.result";
pub const MISSION_GCP_CLOUD_SCHEDULER_CONSUMER_SCHEMA: &str =
    "hartevo.mission-gcp-cloud-scheduler-consumer/v1";
pub const GCP_CLOUD_SCHEDULER_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const GCP_CLOUD_SCHEDULER_CONTRACT_PATH: &str =
    "contracts/plugins/gcp-cloud-scheduler-result/gcp-cloud-scheduler-result.v1.json";
pub const GCP_CLOUD_SCHEDULER_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/gcp-cloud-scheduler-result/gcp-cloud-scheduler-result.v1.json"
);

pub const GCP_CLOUD_SCHEDULER_RESULT_SCHEMA_VERSION: &str = GCP_CLOUD_SCHEDULER_SCHEMA_VERSION;
pub const GCP_CLOUD_SCHEDULER_RESULT_CONTRACT_VERSION: &str = GCP_CLOUD_SCHEDULER_CONTRACT_VERSION;
pub const GCP_CLOUD_SCHEDULER_RESULT_CONTRACT_JSON: &str = GCP_CLOUD_SCHEDULER_CONTRACT_JSON;

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_bytes(GCP_CLOUD_SCHEDULER_CONTRACT_JSON.as_bytes())
}

#[must_use]
pub fn plugin_version() -> &'static str {
    GCP_CLOUD_SCHEDULER_PLUGIN_VERSION_TEXT
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

/// Validates the invariants that make the embedded document a Layer-1 root.
pub fn validate_contract() -> Result<(), ContractValidationError> {
    let document: serde_json::Value = serde_json::from_str(GCP_CLOUD_SCHEDULER_CONTRACT_JSON)
        .map_err(|error| ContractValidationError::InvalidJson(error.to_string()))?;
    let invariant = |condition: bool, name| {
        condition
            .then_some(())
            .ok_or(ContractValidationError::Invariant(name))
    };
    invariant(
        document["schemaVersion"] == GCP_CLOUD_SCHEDULER_SCHEMA_VERSION,
        "schema version",
    )?;
    invariant(
        document["contractVersion"] == GCP_CLOUD_SCHEDULER_CONTRACT_VERSION,
        "contract version",
    )?;
    invariant(document["layer"] == 1, "layer one")?;
    invariant(
        document["service"]["id"] == GCP_CLOUD_SCHEDULER_SERVICE_ID,
        "service id",
    )?;
    invariant(
        document["service"]["name"] == GCP_CLOUD_SCHEDULER_SERVICE_NAME,
        "service name",
    )?;
    invariant(
        document["provider"]["id"] == GCP_CLOUD_SCHEDULER_PROVIDER_ID,
        "provider id",
    )?;
    invariant(
        document["provider"]["implementation"] == "GcpCloudSchedulerProvider",
        "provider implementation",
    )?;
    invariant(
        document["consumer"]["id"] == MISSION_GCP_CLOUD_SCHEDULER_CONSUMER_ID,
        "consumer id",
    )?;
    invariant(
        document["consumer"]["implementation"] == "MissionGcpCloudSchedulerConsumer",
        "consumer implementation",
    )?;
    for field in [
        "connected",
        "nativeProvider",
        "credentialResolution",
        "durableNativeReceipt",
        "independentNativeReadback",
        "kernelOutcomeAdoption",
        "workProductAdoption",
        "externalWrites",
        "jobCreation",
        "jobDeletion",
        "jobPatching",
        "jobPausing",
        "jobResuming",
        "jobRunning",
        "targetInvocation",
    ] {
        invariant(
            !document["authority"][field].as_bool().unwrap_or(true),
            field,
        )?;
    }
    invariant(
        document["provider"]["operations"]
            .as_array()
            .is_some_and(|operations| operations == &["jobs.list", "jobs.get"]),
        "list/get operations",
    )?;
    invariant(
        document["permissions"]["allow"]
            .as_array()
            .is_some_and(|actions| {
                actions == &["cloudscheduler.jobs.list", "cloudscheduler.jobs.get"]
            }),
        "read permissions",
    )?;
    invariant(
        document["permissions"]["externalWrites"] == false,
        "no external writes",
    )?;
    invariant(
        document["transport"]["connected"] == false && document["transport"]["native"] == false,
        "non-native transports",
    )?;
    invariant(
        document["scope"]["secret"] == "opaque_non_serializing_oauth_or_service_account_reference",
        "opaque secret reference",
    )?;
    invariant(
        document["authority"]["rawTarget"] == false
            && document["authority"]["rawHeaders"] == false
            && document["authority"]["rawBodies"] == false,
        "target redaction",
    )?;
    Ok(())
}

/// Layer 1 intentionally reports no external, native, or kernel authority.
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
    pub const fn creates_jobs() -> bool {
        false
    }

    #[must_use]
    pub const fn deletes_jobs() -> bool {
        false
    }

    #[must_use]
    pub const fn patches_jobs() -> bool {
        false
    }

    #[must_use]
    pub const fn pauses_jobs() -> bool {
        false
    }

    #[must_use]
    pub const fn resumes_jobs() -> bool {
        false
    }

    #[must_use]
    pub const fn runs_jobs() -> bool {
        false
    }

    #[must_use]
    pub const fn invokes_targets() -> bool {
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

    #[must_use]
    pub const fn kernel_authority() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use super::{
        ContractValidationError, GCP_CLOUD_SCHEDULER_BLOCKED_ENV,
        GCP_CLOUD_SCHEDULER_CONTRACT_JSON, GCP_CLOUD_SCHEDULER_CONTRACT_VERSION,
        GCP_CLOUD_SCHEDULER_PROVIDER_ID, GCP_CLOUD_SCHEDULER_SCHEMA_VERSION,
        GCP_CLOUD_SCHEDULER_SERVICE_ID, Layer1Authority, MISSION_GCP_CLOUD_SCHEDULER_CONSUMER_ID,
        contract_digest, validate_contract,
    };

    #[test]
    fn contract_is_machine_readable_and_honest() {
        validate_contract().expect("Cloud Scheduler contract invariants");
        let document: serde_json::Value =
            serde_json::from_str(GCP_CLOUD_SCHEDULER_CONTRACT_JSON).expect("contract JSON");
        assert_eq!(
            document["schemaVersion"],
            GCP_CLOUD_SCHEDULER_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            GCP_CLOUD_SCHEDULER_CONTRACT_VERSION
        );
        assert_eq!(document["service"]["id"], GCP_CLOUD_SCHEDULER_SERVICE_ID);
        assert_eq!(document["provider"]["id"], GCP_CLOUD_SCHEDULER_PROVIDER_ID);
        assert_eq!(
            document["consumer"]["id"],
            MISSION_GCP_CLOUD_SCHEDULER_CONSUMER_ID
        );
        assert_eq!(document["authority"]["connected"], false);
        assert_eq!(document["authority"]["nativeProvider"], false);
        assert_eq!(document["authority"]["targetInvocation"], false);
        assert_eq!(GCP_CLOUD_SCHEDULER_BLOCKED_ENV, "BLOCKED_ENV");
        assert_eq!(contract_digest().as_str().len(), 64);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::external_writes());
        assert!(!Layer1Authority::invokes_targets());
        assert!(!Layer1Authority::kernel_authority());
    }

    #[test]
    fn contract_validator_reports_invalid_json() {
        let error = serde_json::from_str::<serde_json::Value>("not-json").expect_err("invalid");
        let error = ContractValidationError::InvalidJson(error.to_string());
        assert!(error.to_string().contains("contract JSON is invalid"));
    }
}
