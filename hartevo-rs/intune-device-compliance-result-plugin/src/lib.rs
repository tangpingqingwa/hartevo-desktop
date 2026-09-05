//! Standalone Layer-1 governed Microsoft Intune device-compliance result plugin.
//!
//! The crate exposes typed, bounded read/proposal/record/verify projections for
//! Microsoft Graph v1.0-shaped compliance-policy metadata, managed-device
//! compliance state, and policy-state summaries. It never resolves Entra
//! credentials, sends native HTTPS, retains raw device/user identifiers,
//! mutates device or policy state, creates a durable provider receipt, adopts an
//! Outcome, or claims compliance certification.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::result_large_err,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    MissionIntuneComplianceConsumer, MissionIntuneComplianceConsumerError,
    MissionIntuneComplianceResult, MissionIntuneComplianceResultState, MissionResultState,
};
pub use model::{
    ComplianceRecord, ComplianceState, ComplianceSummary, ComplianceWindow, DeviceSelector, Digest,
    EvidenceStatus, IntuneEvidence, IntuneReadRequest, IntuneRegistration, IntuneScope,
    Layer1Authority, MAX_NEXT_LINK_BYTES, MAX_PAGES, MAX_RECORDS, MAX_RECORDS_PER_PAGE,
    MAX_RESPONSE_BYTES, MissionBinding, ModelError, NationalCloud, OpaqueNextLink, Platform,
    PolicyFingerprints, PolicyMetadataProjection, PolicyStateSummary, ProjectBinding,
    ProviderErrorEvidence, ProviderErrorKind, ProviderProvenance, QueryBounds, ReadSurface,
    RegistrationBinding, RegistrationRevocation, RegistrationState, Revision, SecretReference,
    Timestamp, WorkProductBinding,
};
pub use provider::{
    BlockedEnvIntuneGraphTransport, FixtureIntuneGraphTransport, INTUNE_BLOCKED_ENV,
    INTUNE_GRAPH_API_VERSION, INTUNE_GRAPH_PROVIDER_ID, INTUNE_GRAPH_PROVIDER_VERSION,
    IntuneGraphRequest, IntuneGraphResponse, IntuneGraphTransport, IntuneProvider,
    IntuneProviderDefinition, IntuneProviderDefinitionError, IntuneTransportError,
    LoopbackIntuneGraphTransport, RecordingIntuneGraphTransport,
};
pub use service::{
    IntuneComplianceProposal, IntuneDeviceComplianceResultService, IntuneDeviceComplianceService,
    IntuneDeviceComplianceServiceDefinition, IntuneDeviceComplianceServiceError,
    IntuneObservationReceipt, IntuneVerification,
};

pub const INTUNE_DEVICE_COMPLIANCE_RESULT_SCHEMA_VERSION: &str =
    "hartevo.intune-device-compliance-result-contract/v1";
pub const INTUNE_DEVICE_COMPLIANCE_RESULT_CONTRACT_VERSION: &str =
    "intune-device-compliance-result-e1/v1";
pub const INTUNE_DEVICE_COMPLIANCE_RESULT_PLUGIN_VERSION: &str = "1.0.0";
pub const INTUNE_DEVICE_COMPLIANCE_RESULT_SERVICE_ID: &str = "intune.device.compliance.result";
pub const MISSION_INTUNE_COMPLIANCE_CONSUMER_ID: &str = "mission.intune.device.compliance.result";
pub const INTUNE_DEVICE_COMPLIANCE_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/intune-device-compliance-result/intune-device-compliance-result.v1.json";
pub const INTUNE_DEVICE_COMPLIANCE_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/intune-device-compliance-result/intune-device-compliance-result.v1.json"
);

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_bytes(INTUNE_DEVICE_COMPLIANCE_RESULT_CONTRACT_JSON.as_bytes())
}

pub fn validate_contract() -> Result<(), String> {
    let document: serde_json::Value =
        serde_json::from_str(INTUNE_DEVICE_COMPLIANCE_RESULT_CONTRACT_JSON)
            .map_err(|error| error.to_string())?;
    let writes_are_empty = document["queryPolicy"]["writes"]
        .as_array()
        .is_some_and(Vec::is_empty);
    let accepted_provenance = document["provider"]["acceptedProvenance"]
        .as_array()
        .is_some_and(|values| {
            ["fixture", "recording", "loopback", "blocked_env"]
                .iter()
                .all(|expected| values.iter().any(|value| value == expected))
        });
    let matches = document["schemaVersion"] == INTUNE_DEVICE_COMPLIANCE_RESULT_SCHEMA_VERSION
        && document["contractVersion"] == INTUNE_DEVICE_COMPLIANCE_RESULT_CONTRACT_VERSION
        && document["layer"] == 1
        && document["service"]["id"] == INTUNE_DEVICE_COMPLIANCE_RESULT_SERVICE_ID
        && document["provider"]["id"] == INTUNE_GRAPH_PROVIDER_ID
        && document["provider"]["apiVersion"] == INTUNE_GRAPH_API_VERSION
        && document["consumer"]["id"] == MISSION_INTUNE_COMPLIANCE_CONSUMER_ID
        && document["provider"]["connected"] == false
        && document["provider"]["native"] == false
        && document["provider"]["firstParty"] == false
        && document["authority"]["connected"] == false
        && document["authority"]["nativeProvider"] == false
        && document["authority"]["firstParty"] == false
        && document["authority"]["externalWrites"] == false
        && document["authority"]["certification"] == false
        && document["authority"]["outcomeAuthority"] == false
        && writes_are_empty
        && accepted_provenance;
    if matches {
        Ok(())
    } else {
        Err("Intune Layer-1 contract does not match its typed boundary".to_owned())
    }
}

#[cfg(test)]
mod contract_document_tests {
    use super::*;

    #[test]
    fn contract_is_machine_readable_and_layer_one_honest() {
        validate_contract().expect("contract");
        let document: serde_json::Value =
            serde_json::from_str(INTUNE_DEVICE_COMPLIANCE_RESULT_CONTRACT_JSON)
                .expect("contract JSON");
        assert_eq!(document["layer"], 1);
        assert_eq!(
            document["service"]["id"],
            INTUNE_DEVICE_COMPLIANCE_RESULT_SERVICE_ID
        );
        assert_eq!(document["provider"]["id"], INTUNE_GRAPH_PROVIDER_ID);
        assert_eq!(document["provider"]["apiVersion"], INTUNE_GRAPH_API_VERSION);
        assert_eq!(
            document["consumer"]["id"],
            MISSION_INTUNE_COMPLIANCE_CONSUMER_ID
        );
        assert!(!contract_digest().as_str().is_empty());
        assert_eq!(INTUNE_BLOCKED_ENV, "BLOCKED_ENV");
        let provider = IntuneProviderDefinition::new(
            INTUNE_GRAPH_PROVIDER_VERSION,
            ProviderProvenance::Recording,
        )
        .expect("provider");
        assert!(!provider.connected);
        assert!(!provider.native);
        assert!(!provider.first_party);
        let service = IntuneDeviceComplianceService::<RecordingIntuneGraphTransport>::definition();
        assert!(service.read_only);
        assert!(!service.live_execution);
        assert!(!service.external_writes);
        assert!(!service.certification);
        assert!(!service.outcome_authority);
    }
}
