//! Standalone Layer-1 governed Opsgenie incident-result boundary.
//!
//! This crate owns typed account/region/team/service/alert/alias/incident/
//! schedule/escalation/timeline scope, bounded redacted reads, reversible
//! registration, proposal/recording seams, and deterministic fixture,
//! recording, loopback, and `BLOCKED_ENV` transports. It intentionally does
//! not resolve credentials, open native HTTPS, mutate Opsgenie, create a
//! durable provider receipt, or become Hartevo Truth/Effect/Receipt/
//! Verification/Outcome authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::collapsible_if,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::large_enum_variant,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::ignored_unit_patterns,
    clippy::redundant_closure,
    clippy::return_self_not_must_use,
    clippy::type_complexity,
    clippy::result_large_err,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::bool_assert_comparison
)]
#![allow(dead_code)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    MissionOpsgenieIncidentConsumer, MissionOpsgenieIncidentConsumerError,
    MissionOpsgenieIncidentResult, MissionOpsgenieIncidentResultState,
    MissionOpsgenieIncidentState,
};
pub use model::*;
pub use provider::{
    BlockedEnvOpsgenieTransport, BlockedEnvTransport, FixtureOpsgenieTransport, FixtureTransport,
    GET_ALERT_PATH, GET_ALERT_TIMELINE_PATH, GET_ESCALATION_PATH, GET_INCIDENT_PATH,
    GET_SCHEDULE_PATH, LoopbackOpsgenieTransport, LoopbackTransport, OPSGENIE_API_REVISION,
    OpsgenieAlertPayload, OpsgenieEscalationPayload, OpsgenieIncidentPayload, OpsgenieProvider,
    OpsgenieProviderDefinition, OpsgenieProviderError, OpsgenieProviderRead, OpsgenieRequest,
    OpsgenieResponse, OpsgenieSchedulePayload, OpsgenieTimelineEntryPayload,
    OpsgenieTimelinePayload, OpsgenieTransport, OpsgenieTransportError, RecordingOpsgenieTransport,
    RecordingTransport,
};
pub type OpsgenieIncidentResultProvider<T> = OpsgenieProvider<T>;
pub type OpsgenieProviderTransport = dyn OpsgenieTransport;
pub type OpsgenieProviderFailure = OpsgenieProviderError;
pub use service::{
    OpsgenieIncidentResultEvidenceModel, OpsgenieIncidentResultProposalModel,
    OpsgenieIncidentResultRegistrationModel, OpsgenieIncidentResultService,
    OpsgenieIncidentResultServiceDefinition, OpsgenieIncidentResultServiceError,
    OpsgenieIncidentResultServiceResult, OpsgenieService, OpsgenieServiceError,
};

pub const OPSGENIE_INCIDENT_RESULT_SCHEMA_VERSION: &str = "hartevo.opsgenie-incident-result/v1";
pub const OPSGENIE_INCIDENT_RESULT_CONTRACT_VERSION: &str = "EXT-OPSGENIE-01-L1/v1";
pub const OPSGENIE_INCIDENT_RESULT_PLUGIN_VERSION: &str = "1.0.0";
pub const OPSGENIE_INCIDENT_RESULT_CONTRACT_DIGEST_INPUT: &str = "hartevo.opsgenie-incident-result/v1|layer=1|service=opsgenie.incident-result.read|provider=opsgenie.incident-result.recording|consumer=mission.opsgenie-incident-result.consumer";
pub const OPSGENIE_INCIDENT_RESULT_CONTRACT_DIGEST: &str =
    "2835403e7aef15d50fbdacefddcb1452853f05b0996687f578ea2ab0dfd43d6c";
pub const OPSGENIE_INCIDENT_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/opsgenie-incident-result/opsgenie-incident-result.v1.json";
pub const OPSGENIE_INCIDENT_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/opsgenie-incident-result/opsgenie-incident-result.v1.json"
);
pub const OPSGENIE_INCIDENT_RESULT_SERVICE_ID: &str = "opsgenie.incident-result.read";
pub const OPSGENIE_PROVIDER_ID: &str = "opsgenie.incident-result.recording";
pub const OPSGENIE_PROVIDER_VERSION: &str = "1.0.0";
pub const MISSION_OPSGENIE_INCIDENT_CONSUMER_ID: &str = "mission.opsgenie-incident-result.consumer";
pub const OPSGENIE_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const BLOCKED_ENV: &str = OPSGENIE_BLOCKED_ENV;

pub const CONTRACT_SCHEMA: &str = OPSGENIE_INCIDENT_RESULT_SCHEMA_VERSION;
pub const CONTRACT_VERSION: &str = OPSGENIE_INCIDENT_RESULT_CONTRACT_VERSION;
pub const CONTRACT_DIGEST_INPUT: &str = OPSGENIE_INCIDENT_RESULT_CONTRACT_DIGEST_INPUT;
pub const CONTRACT_DIGEST: &str = OPSGENIE_INCIDENT_RESULT_CONTRACT_DIGEST;
pub const PLUGIN_ID: &str = "opsgenie.incident-result";
pub const PLUGIN_VERSION: &str = OPSGENIE_INCIDENT_RESULT_PLUGIN_VERSION;
pub const SERVICE_ID: &str = OPSGENIE_INCIDENT_RESULT_SERVICE_ID;
pub const PROVIDER_ID: &str = OPSGENIE_PROVIDER_ID;
pub const PROVIDER_API_REVISION: &str = OPSGENIE_API_REVISION;
pub const CONSUMER_ID: &str = MISSION_OPSGENIE_INCIDENT_CONSUMER_ID;
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str = OPSGENIE_INCIDENT_RESULT_CONTRACT_JSON;

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::parse(CONTRACT_DIGEST.to_owned()).expect("checked Opsgenie contract digest")
}

/// Layer 1 deliberately reports no native, Connected, first-party, or
/// kernel authority.
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
    pub const fn durable_provider_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn kernel_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn outcome_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn external_writes() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use serde_json::Value;

    use super::{
        BLOCKED_ENV, Layer1Authority, MISSION_OPSGENIE_INCIDENT_CONSUMER_ID, OPSGENIE_API_REVISION,
        OPSGENIE_INCIDENT_RESULT_CONTRACT_JSON, OPSGENIE_INCIDENT_RESULT_CONTRACT_VERSION,
        OPSGENIE_INCIDENT_RESULT_SCHEMA_VERSION, OPSGENIE_PROVIDER_ID, contract_digest,
    };

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let document: Value = serde_json::from_str(OPSGENIE_INCIDENT_RESULT_CONTRACT_JSON)
            .expect("Opsgenie contract JSON");
        assert_eq!(
            document["schemaVersion"],
            OPSGENIE_INCIDENT_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            OPSGENIE_INCIDENT_RESULT_CONTRACT_VERSION
        );
        assert_eq!(document["layer"], 1);
        assert_eq!(document["service"]["id"], "opsgenie.incident-result.read");
        assert_eq!(document["provider"]["id"], OPSGENIE_PROVIDER_ID);
        assert_eq!(document["provider"]["apiRevision"], OPSGENIE_API_REVISION);
        assert_eq!(
            document["consumer"]["id"],
            MISSION_OPSGENIE_INCIDENT_CONSUMER_ID
        );
        assert_eq!(document["contractDigest"], contract_digest().as_str());
        assert_eq!(document["authority"]["connected"], false);
        assert_eq!(document["authority"]["nativeProvider"], false);
        assert_eq!(document["authority"]["externalWrites"], false);
        assert_eq!(
            document["provider"]["transportProvenance"]
                .as_array()
                .map(Vec::len),
            Some(4)
        );
        assert_eq!(BLOCKED_ENV, "BLOCKED_ENV");
        assert_eq!(document["allowlist"]["methods"][0], "GET");
        assert_eq!(
            document["allowlist"]["writes"].as_array().map(Vec::len),
            Some(0)
        );
        assert_eq!(contract_digest().as_str().len(), 64);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::external_writes());
    }
}
