//! Standalone Layer-1 Grafana alert-result observation plugin.
//!
//! The crate exposes three typed seams: [`GrafanaAlertResultService`],
//! [`GrafanaProvider`], and [`MissionGrafanaAlertConsumer`].  It is a bounded
//! read/proposal/recording seam for Grafana alerting metadata and alert
//! instances.  It never mutates Grafana, sends notifications, queries an
//! arbitrary data source, retains raw logs or provider payloads in evidence,
//! creates a kernel receipt, or adopts a Mission Outcome.

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::struct_excessive_bools)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    MissionAlertProjection, MissionGrafanaAlertConsumer, MissionGrafanaAlertConsumerError,
};
pub use model::{
    AlertInstanceObservation, AlertResultError, AlertResultEvidence, AlertResultProjection,
    AlertResultProposal, AlertResultReadOperation, AlertRuleMetadata, AlertState, AllowlistedLabel,
    CloudStack, Digest, EvidenceClassification, GrafanaAlertResultError, GrafanaAlertScope,
    GrafanaAlertScopeSpec, GrafanaApiDefinition, GrafanaErrorProjection, GrafanaPermission,
    GrafanaPermissionSnapshot, GrafanaRegistration, GrafanaRegistrationState,
    GrafanaRevocationReceipt, GrafanaTransportError, IdentityBinding, IncidentState,
    IncidentStateTransition, MAX_ALERT_INSTANCES, MAX_IDENTIFIER_BYTES, MAX_INCIDENT_TRANSITIONS,
    MAX_LABEL_BYTES, MAX_LABELS, MAX_NUMERIC_EVIDENCE, MAX_PAGE_SIZE, MAX_PAGES,
    MAX_RESPONSE_BYTES, MAX_RULE_GROUPS, MAX_RULES, MissionBinding, NumericEvidenceDigest,
    PluginVersion, ProjectBinding, RuleGroupMetadata, SecretKind, SecretReference,
    TransportProvenance, canonical_digest, sha256_digest,
};
pub use provider::{
    BlockedEnvGrafanaTransport, FakeGrafanaTransport, FixtureGrafanaTransport, GrafanaHttpMethod,
    GrafanaHttpRequest, GrafanaHttpResponse, GrafanaPage, GrafanaProvider, GrafanaTransport,
    LoopbackGrafanaTransport, RecordedFault, RecordingGrafanaTransport,
};
pub use service::GrafanaAlertResultService;

pub const GRAFANA_ALERT_RESULT_SCHEMA_VERSION: &str = "hartevo.grafana-alert-result/v1";
pub const GRAFANA_ALERT_RESULT_CONTRACT_VERSION: &str = "grafana-alert-result-e1/v1";
pub const GRAFANA_ALERT_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/grafana-alert-result/grafana-alert-result.v1.json";
pub const GRAFANA_ALERT_RESULT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/grafana-alert-result/grafana-alert-result.v1.json");
pub const GRAFANA_ALERT_RESULT_PLUGIN_ID: &str = "grafana-alert-result";
pub const GRAFANA_ALERT_RESULT_SERVICE_ID: &str = "grafana.alert-result";
pub const GRAFANA_ALERT_RESULT_SERVICE_NAME: &str = "GrafanaAlertResultService";
pub const GRAFANA_PROVIDER_ID: &str = "grafana.alert-result";
pub const GRAFANA_PROVIDER_NAME: &str = "GrafanaProvider";
pub const MISSION_GRAFANA_ALERT_CONSUMER_ID: &str = "mission.grafana-alert-result";
pub const MISSION_GRAFANA_ALERT_CONSUMER_NAME: &str = "MissionGrafanaAlertConsumer";
pub const GRAFANA_HTTP_API_REVISION: &str = "grafana-http-api-v1";
pub const GRAFANA_ALERTING_API_REVISION: &str = "grafana-alerting-api-v1";
pub const GRAFANA_PROVIDER_REVISION: &str = "grafana-alert-result-provider-v1";

/// Returns the lowercase SHA-256 digest of the checked-in contract.
#[must_use]
pub fn contract_digest() -> Digest {
    model::sha256_digest(GRAFANA_ALERT_RESULT_CONTRACT_JSON.as_bytes())
}

/// Returns the plugin version bound into registrations.
#[must_use]
pub const fn plugin_version() -> PluginVersion {
    PluginVersion::V1
}

/// Layer-1 authority is intentionally false for every native or kernel claim.
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
    pub const fn durable_native_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn kernel_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn outcome_adoption() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use serde_json::Value;

    use super::{
        GRAFANA_ALERT_RESULT_CONTRACT_JSON, GRAFANA_ALERT_RESULT_CONTRACT_VERSION,
        GRAFANA_ALERT_RESULT_SCHEMA_VERSION, GRAFANA_ALERT_RESULT_SERVICE_ID,
        GRAFANA_ALERT_RESULT_SERVICE_NAME, GRAFANA_PROVIDER_ID, GRAFANA_PROVIDER_NAME,
        Layer1Authority, MISSION_GRAFANA_ALERT_CONSUMER_ID, MISSION_GRAFANA_ALERT_CONSUMER_NAME,
    };

    #[test]
    fn contract_is_machine_readable_and_layer_one_honest() {
        let document: Value = serde_json::from_str(GRAFANA_ALERT_RESULT_CONTRACT_JSON)
            .expect("Grafana alert-result contract JSON");
        assert_eq!(
            document["schemaVersion"],
            GRAFANA_ALERT_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            GRAFANA_ALERT_RESULT_CONTRACT_VERSION
        );
        assert_eq!(document["layer"], 1);
        assert_eq!(document["service"]["id"], GRAFANA_ALERT_RESULT_SERVICE_ID);
        assert_eq!(
            document["service"]["name"],
            GRAFANA_ALERT_RESULT_SERVICE_NAME
        );
        assert_eq!(document["provider"]["id"], GRAFANA_PROVIDER_ID);
        assert_eq!(document["provider"]["name"], GRAFANA_PROVIDER_NAME);
        assert_eq!(
            document["consumer"]["id"],
            MISSION_GRAFANA_ALERT_CONSUMER_ID
        );
        assert_eq!(
            document["consumer"]["name"],
            MISSION_GRAFANA_ALERT_CONSUMER_NAME
        );
        assert_eq!(document["authority"]["connected"], false);
        assert_eq!(document["authority"]["nativeProvider"], false);
        assert_eq!(document["authority"]["kernelAuthority"], false);
        assert_eq!(document["authority"]["outcomeAdoption"], false);
        assert_eq!(document["authentication"]["rawTokenSerialized"], false);
        assert_eq!(
            document["allowlist"]["writes"].as_array().map(Vec::len),
            Some(0)
        );
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::durable_native_receipt());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::outcome_adoption());
    }

    #[test]
    fn contract_distinguishes_neighboring_provider_domains() {
        let document: Value = serde_json::from_str(GRAFANA_ALERT_RESULT_CONTRACT_JSON)
            .expect("Grafana alert-result contract JSON");
        assert_eq!(document["distinction"]["notDatadogSloOutcome"], true);
        assert_eq!(document["distinction"]["notSentryIssueEvent"], true);
        assert_eq!(document["distinction"]["notPagerDutyIncident"], true);
    }
}
