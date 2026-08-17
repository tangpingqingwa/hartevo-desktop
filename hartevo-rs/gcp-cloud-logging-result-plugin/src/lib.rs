//! Standalone Layer-1 governed Google Cloud Logging evidence-result plugin.
//!
//! The crate owns a versioned contract, an exact provider-resource and
//! Project/Mission/Work Product scope, a predeclared bounded `entries.list`
//! filter AST, redacted aggregate evidence, and a Mission consumer. It never
//! resolves native credentials, calls Google Cloud, retains raw log payloads,
//! mutates provider resources, or claims kernel Truth/Consent/Effect/Receipt/
//! Verification/Outcome authority.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    AdoptionAvailability, ConsumerError, ConsumerRegistration, MissionGcpCloudLoggingConsumer,
    MissionGcpCloudLoggingResult, MissionResultState,
};
pub use model::*;
pub use provider::{
    BlockedEnvGcpCloudLoggingTransport, BlockedEnvTransport, EntriesListRequest,
    FakeGcpCloudLoggingTransport, FixtureGcpCloudLoggingTransport, GcpCloudLoggingApiVersion,
    GcpCloudLoggingProvider, GcpCloudLoggingProviderDefinition, GcpCloudLoggingTransport,
    LogEntriesPage, LoopbackGcpCloudLoggingTransport, ProviderDefinitionError, ProviderProvenance,
    RecordingGcpCloudLoggingTransport, TransportCall, TransportError,
};
pub use service::{
    GcpCloudLoggingProjection, GcpCloudLoggingRegistration, GcpCloudLoggingResultEvidence,
    GcpCloudLoggingResultProposal, GcpCloudLoggingResultService, GcpCloudLoggingResultServiceError,
    PartialReason, RegistrationTransition, ResultEvidence, ResultProjection, RetryPolicy,
};

pub const GCP_CLOUD_LOGGING_RESULT_SCHEMA_VERSION: &str =
    "hartevo.gcp-cloud-logging-result.contract/v1";
pub const GCP_CLOUD_LOGGING_RESULT_CONTRACT_VERSION: &str = "gcp-cloud-logging-result-e1/v1";
pub const GCP_CLOUD_LOGGING_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const GCP_CLOUD_LOGGING_RESULT_SERVICE_ID: &str = "gcp.cloud.logging.result";
pub const GCP_CLOUD_LOGGING_RESULT_PROVIDER_ID: &str = "gcp.cloud.logging.entries-list";
pub const GCP_CLOUD_LOGGING_RESULT_CONSUMER_ID: &str = "mission.gcp.cloud.logging.result";
pub const GCP_CLOUD_LOGGING_RESULT_PROVIDER_VERSION: &str = "gcp-cloud-logging-api-v2-r1";
pub const GCP_CLOUD_LOGGING_RESULT_API_VERSION: &str = "v2";
pub const GCP_CLOUD_LOGGING_RESULT_API_OPERATION: &str = "entries.list";
pub const GCP_CLOUD_LOGGING_RESULT_EVIDENCE_LEVEL: &str = "E1";
pub const GCP_CLOUD_LOGGING_RESULT_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const GCP_CLOUD_LOGGING_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/gcp-cloud-logging-result/gcp-cloud-logging-result.v1.json"
);

pub type Layer1Authority = EvidenceAuthority;

pub fn plugin_version() -> &'static str {
    GCP_CLOUD_LOGGING_RESULT_PLUGIN_VERSION
}

pub fn contract_digest() -> Digest {
    Digest::from_bytes(GCP_CLOUD_LOGGING_RESULT_CONTRACT_JSON.as_bytes())
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContractValidationError {
    #[error("contract JSON is invalid: {0}")]
    Json(String),
    #[error("contract field {0} is not the frozen Layer-1 value")]
    FrozenField(&'static str),
}

/// Validates the checked-in contract and its non-authoritative Layer-1 pins.
#[allow(clippy::too_many_lines)]
pub fn validate_contract() -> Result<(), ContractValidationError> {
    let contract: serde_json::Value = serde_json::from_str(GCP_CLOUD_LOGGING_RESULT_CONTRACT_JSON)
        .map_err(|error| ContractValidationError::Json(error.to_string()))?;
    let check = |path: &'static str, condition: bool| {
        if condition {
            Ok(())
        } else {
            Err(ContractValidationError::FrozenField(path))
        }
    };
    check(
        "schemaVersion",
        contract["schemaVersion"] == GCP_CLOUD_LOGGING_RESULT_SCHEMA_VERSION,
    )?;
    check(
        "contractVersion",
        contract["contractVersion"] == GCP_CLOUD_LOGGING_RESULT_CONTRACT_VERSION,
    )?;
    check(
        "pluginVersion",
        contract["pluginVersion"] == GCP_CLOUD_LOGGING_RESULT_PLUGIN_VERSION,
    )?;
    check(
        "evidenceLevel",
        contract["evidenceLevel"] == GCP_CLOUD_LOGGING_RESULT_EVIDENCE_LEVEL,
    )?;
    check("layer", contract["layer"] == "Layer-1")?;
    check(
        "service.id",
        contract["service"]["id"] == GCP_CLOUD_LOGGING_RESULT_SERVICE_ID,
    )?;
    check("service.readOnly", contract["service"]["readOnly"] == true)?;
    check(
        "service.liveExecution",
        contract["service"]["liveExecution"] == false,
    )?;
    check(
        "provider.id",
        contract["provider"]["id"] == GCP_CLOUD_LOGGING_RESULT_PROVIDER_ID,
    )?;
    check(
        "provider.apiVersion",
        contract["provider"]["apiVersion"] == "v2",
    )?;
    check(
        "provider.officialApi",
        contract["provider"]["officialApi"] == "entries.list",
    )?;
    check("provider.native", contract["provider"]["native"] == false)?;
    check(
        "provider.connected",
        contract["provider"]["connected"] == false,
    )?;
    check(
        "provider.firstParty",
        contract["provider"]["firstParty"] == false,
    )?;
    check(
        "provider.allowedOperations",
        contract["provider"]["allowedOperations"] == serde_json::json!(["entries.list"]),
    )?;
    check(
        "consumer.id",
        contract["consumer"]["id"] == GCP_CLOUD_LOGGING_RESULT_CONSUMER_ID,
    )?;
    check(
        "consumer.missionBound",
        contract["consumer"]["missionBound"] == true,
    )?;
    check(
        "consumer.projectBound",
        contract["consumer"]["projectBound"] == true,
    )?;
    check(
        "consumer.workProductBound",
        contract["consumer"]["workProductBound"] == true,
    )?;
    check(
        "consumer.adoptsOutcome",
        contract["consumer"]["adoptsOutcome"] == false,
    )?;
    check(
        "consumer.truthAuthority",
        contract["consumer"]["truthAuthority"] == false,
    )?;
    check(
        "filterPolicy.arbitraryFilterText",
        contract["filterPolicy"]["arbitraryFilterText"] == false,
    )?;
    check(
        "filterPolicy.mandatoryTimeBound",
        contract["filterPolicy"]["mandatoryTimeBound"] == true,
    )?;
    check("evidence.rawText", contract["evidence"]["rawText"] == false)?;
    check("evidence.rawJson", contract["evidence"]["rawJson"] == false)?;
    check(
        "evidence.rawProto",
        contract["evidence"]["rawProto"] == false,
    )?;
    check("evidence.pii", contract["evidence"]["pii"] == false)?;
    check(
        "registration.reversible",
        contract["registration"]["reversible"] == true,
    )?;
    check(
        "registration.revocable",
        contract["registration"]["revocable"] == true,
    )?;
    check(
        "registration.failClosedOnDrift",
        contract["registration"]["failClosedOnDrift"] == true,
    )?;
    for transport in ["fixture", "recording", "loopback", "BLOCKED_ENV"] {
        check(
            "transportClaims.connected",
            contract["transportClaims"][transport]["connected"] == false,
        )?;
        check(
            "transportClaims.native",
            contract["transportClaims"][transport]["native"] == false,
        )?;
        check(
            "transportClaims.firstParty",
            contract["transportClaims"][transport]["firstParty"] == false,
        )?;
    }
    for authority in [
        "truth",
        "consent",
        "effect",
        "receipt",
        "verification",
        "outcome",
        "connected",
        "nativeEvidence",
        "firstParty",
        "externalWrites",
    ] {
        check("authority", contract["authority"][authority] == false)?;
    }
    Ok(())
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_contract_is_valid_and_digest_is_stable() {
        validate_contract().expect("contract validates");
        assert_eq!(contract_digest(), contract_digest());
        assert_eq!(plugin_version(), "0.1.0");
        assert_eq!(GCP_CLOUD_LOGGING_RESULT_BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!GCP_CLOUD_LOGGING_RESULT_CONTRACT_JSON.is_empty());
        let authority = EvidenceAuthority;
        assert!(!authority.connected());
        assert!(!authority.native());
        assert!(!authority.first_party());
        assert!(!authority.truth());
        assert!(!authority.consent());
        assert!(!authority.effect());
        assert!(!authority.receipt());
        assert!(!authority.verification());
        assert!(!authority.outcome());
    }
}

#[cfg(test)]
mod adversarial_tests;
