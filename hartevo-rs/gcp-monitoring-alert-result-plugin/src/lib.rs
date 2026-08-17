//! Standalone Layer-1 Google Cloud Monitoring alert-result boundary.
//!
//! This crate models bounded, read-only alert-policy and alert evidence for a
//! Mission decision. It deliberately stops below Hartevo Truth, Outcome,
//! Effect, Receipt, Verification, dashboard, and incident-causality
//! authority. Recording, fixture, loopback, and `BLOCKED_ENV` transports are
//! always non-connected and non-native.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::cast_possible_truncation,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionGcpMonitoringAlertConsumer, MissionGcpMonitoringAlertResult, ProposalDisposition,
    ReadBackReceipt, RecordedGcpMonitoringAlertResult,
};
pub use error::{GcpMonitoringAlertError, GcpMonitoringTransportError, Result, TransportErrorKind};
pub use model::*;
pub use provider::{
    AlertOperation, BlockedEnvTransport, FixtureTransport, GcpMonitoringProvider,
    GcpMonitoringProviderDefinition, GcpMonitoringTransport, GetAlertPolicyRequest,
    GetAlertPolicyResponse, GetAlertRequest, GetAlertResponse, ListAlertPoliciesRequest,
    ListAlertPoliciesResponse, ListAlertsRequest, ListAlertsResponse, LoopbackTransport,
    MonitoringProvider, ProviderDefinitionError, ProviderProvenance, RecordedRequest,
    RecordingTransport, TransportError,
};
pub use service::{
    AlertEvidenceProjection, GcpMonitoringAlertEvidence, GcpMonitoringAlertProposal,
    GcpMonitoringAlertRegistration, GcpMonitoringAlertService, GcpMonitoringAlertServiceDefinition,
    GcpMonitoringAlertServiceError, ProposalRequest, RegistrationStatus,
    RegistrationTransitionEvidence, ResultProjection, RetryEvidence,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.gcp-monitoring-alert-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-GCP-MONITORING-ALERT-01-L1/v1";
pub const PLUGIN_ID: &str = "gcp.monitoring.alert.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "gcp.monitoring.alert.result.read";
pub const PROVIDER_ID: &str = "gcp.monitoring.alert.result.recording";
pub const PROVIDER_API_REVISION: &str = "monitoring-v3-alertPolicies-list-get-alerts-list-get-r1";
pub const CONSUMER_ID: &str = "mission.gcp-monitoring-alert.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_DIGEST_INPUT: &str = concat!(
    "hartevo.gcp-monitoring-alert-result/v1|layer=1|service=",
    "gcp.monitoring.alert.result.read|provider=",
    "gcp.monitoring.alert.result.recording|consumer=",
    "mission.gcp-monitoring-alert.consumer|api=",
    "monitoring-v3-alertPolicies-list-get-alerts-list-get-r1"
);
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/gcp-monitoring-alert-result/gcp-monitoring-alert-result.v1.json"
);

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_TOKEN_BYTES: usize = 4 * 1024;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 8;
pub const MAX_POLICY_COUNT: usize = 100;
pub const MAX_ALERT_COUNT: usize = 100;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_LABEL_COUNT: usize = 128;

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as ShaDigest, Sha256};

    hex::encode(Sha256::digest(bytes))
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

/// The capabilities that Layer 1 is allowed to expose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn durable_provider_receipt() -> bool {
        false
    }

    pub const fn causal_incident_claim() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }

    pub const fn truth_authority() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use serde::Deserialize;

    use super::{
        BLOCKED_ENV, CONSUMER_ID, CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA,
        CONTRACT_VERSION, EVIDENCE_LEVEL, Layer1Authority, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID,
        SERVICE_ID, contract_digest,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        plugin_version: String,
        plugin_id: String,
        layer: String,
        evidence_level: String,
        digest_input: String,
        contract_digest: String,
        service: ServiceDocument,
        provider: ProviderDocument,
        consumer: ConsumerDocument,
        native_claims: NativeClaims,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ServiceDocument {
        id: String,
        read_only: bool,
        proposal_only: bool,
        external_writes: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderDocument {
        id: String,
        connected: bool,
        native: bool,
        external_writes: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConsumerDocument {
        id: String,
        adopts_outcome: bool,
        truth_authority: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NativeClaims {
        connected: bool,
        native_provider: bool,
        durable_provider_receipt: bool,
        causal_incident_claim: bool,
        adopted_outcome: bool,
        blocked_environment_is_native: bool,
    }

    #[test]
    fn contract_is_exactly_layer_one_and_non_native() {
        let contract = serde_json::from_str::<ContractDocument>(CONTRACT_JSON)
            .expect("GCP Monitoring alert contract");
        assert_eq!(contract.schema_version, CONTRACT_SCHEMA);
        assert_eq!(contract.contract_version, CONTRACT_VERSION);
        assert_eq!(contract.plugin_version, PLUGIN_VERSION);
        assert_eq!(contract.plugin_id, PLUGIN_ID);
        assert_eq!(contract.layer, "Layer-1");
        assert_eq!(contract.evidence_level, EVIDENCE_LEVEL);
        assert_eq!(contract.digest_input, CONTRACT_DIGEST_INPUT);
        assert_eq!(contract.contract_digest, contract_digest());
        assert_eq!(contract.service.id, SERVICE_ID);
        assert!(contract.service.read_only);
        assert!(contract.service.proposal_only);
        assert!(!contract.service.external_writes);
        assert_eq!(contract.provider.id, PROVIDER_ID);
        assert!(!contract.provider.connected);
        assert!(!contract.provider.native);
        assert!(!contract.provider.external_writes);
        assert_eq!(contract.consumer.id, CONSUMER_ID);
        assert!(!contract.consumer.adopts_outcome);
        assert!(!contract.consumer.truth_authority);
        assert!(!contract.native_claims.connected);
        assert!(!contract.native_claims.native_provider);
        assert!(!contract.native_claims.durable_provider_receipt);
        assert!(!contract.native_claims.causal_incident_claim);
        assert!(!contract.native_claims.adopted_outcome);
        assert!(!contract.native_claims.blocked_environment_is_native);
        assert_eq!(BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::causal_incident_claim());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::truth_authority());
    }
}
