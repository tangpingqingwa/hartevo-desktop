//! Standalone Layer-1 CockroachDB Cloud posture result boundary.
//!
//! This crate is deliberately below Hartevo Truth, Effect, Receipt,
//! Verification, Outcome, Work Product, and kernel authority. It exposes
//! bounded typed provider seams and Mission review projections only. It does
//! not resolve credentials, contact CockroachDB Cloud, execute SQL, retain
//! raw SQL/results, or mutate a cluster, branch, or setting.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

mod consumer;
mod error;
mod model;
mod provider;
mod service;

pub use consumer::{
    ConsumerError, MissionCockroachCloudConsumer, MissionCockroachCloudDecisionState,
    MissionCockroachCloudResult,
};
pub use error::{CockroachCloudResultError, CockroachCloudTransportError};
pub use model::*;
pub use provider::{
    BlockedEnvCockroachCloudTransport, BlockedEnvTransport, CockroachCloudCall,
    CockroachCloudProvider, CockroachCloudProviderDefinition, CockroachCloudTransport,
    FakeCockroachCloudTransport, FakeTransport, FixtureCockroachCloudTransport, FixtureTransport,
    LoopbackCockroachCloudTransport, LoopbackTransport, RecordingCockroachCloudTransport,
    RecordingTransport,
};
pub use service::{
    CockroachCloudCapabilities, CockroachCloudEvidence, CockroachCloudEvidenceDigests,
    CockroachCloudProposal, CockroachCloudReadResult, CockroachCloudRecord,
    CockroachCloudRegistration, CockroachCloudResultService, EvidenceVerification, FailureEvidence,
    FailureKind, PaginationEvidence, ReadReceipt, RecordDisposition, RegistrationTransition,
    VerificationFailure,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.cockroach-cloud-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-COCKROACH-01-L1/v1";
pub const PLUGIN_ID: &str = "cockroach.cloud.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "cockroach.cloud.result.read";
pub const PROVIDER_ID: &str = "cockroach.cloud.result.recording";
pub const CONSUMER_ID: &str = "mission.cockroach-cloud.consumer";
pub const API_REVISION: &str = "cockroach-cloud-api-v1-read-r1";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/cockroach-cloud-result/cockroach-cloud-result.v1.json"
);

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_CURSOR_BYTES: usize = 256;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_SETTINGS_ENTRIES: usize = 64;
pub const MAX_SQL_ACTIVITY_ENTRIES: usize = 128;
pub const MAX_ACTIVITY_WINDOW_SECONDS: u64 = 24 * 60 * 60;
pub const MAX_REQUEST_AGE_SECONDS: u64 = 15 * 60;

pub const LAYER1_PERMISSIONS: [&str; 10] = [
    "organization:read",
    "project:read",
    "cluster:read",
    "cluster_health:read",
    "cluster_settings:read",
    "database:read",
    "branch:read",
    "sql_activity:read",
    "mission.scope",
    "work_product.proposal",
];

/// Layer 1 never carries native or external authority claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }

    pub const fn sql_execution() -> bool {
        false
    }

    pub const fn external_writes() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }

    pub const fn adopted_work_product() -> bool {
        false
    }
}

/// SHA-256 digest of the exact checked-in contract bytes.
pub fn contract_digest() -> Digest {
    Digest::from_bytes(CONTRACT_JSON.as_bytes())
}

/// SHA-256 digest of the exact plugin version text.
pub fn plugin_version_digest() -> Digest {
    Digest::from_text(PLUGIN_VERSION)
}

/// SHA-256 binding the provider identity, revision, read allowlist, and
/// Layer-1 non-native status.
pub fn provider_digest() -> Digest {
    Digest::from_serializable(&(
        PROVIDER_ID,
        API_REVISION,
        LAYER1_PERMISSIONS,
        [
            "GET organization",
            "GET cloud project",
            "GET cluster",
            "GET cluster health",
            "GET settings metadata",
            "GET SQL activity posture",
        ],
        false,
        false,
        false,
    ))
}

#[cfg(test)]
mod contract_tests {
    use serde::Deserialize;

    use super::{
        API_REVISION, BLOCKED_ENV, CONSUMER_ID, CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION,
        EVIDENCE_LEVEL, Layer1Authority, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
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
        service: ServiceDocument,
        provider: ProviderDocument,
        consumer: ConsumerDocument,
        native_gap: NativeGap,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ServiceDocument {
        id: String,
        read_only: bool,
        external_writes: bool,
        sql_execution: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderDocument {
        id: String,
        api_revision: String,
        connected_evidence: bool,
        native_evidence: bool,
        first_party_evidence: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConsumerDocument {
        id: String,
        adopts_outcome: bool,
        adopts_work_product: bool,
        truth_authority: bool,
    }

    #[derive(Debug, Deserialize)]
    struct NativeGap {
        status: String,
        connected: bool,
    }

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract = serde_json::from_str::<ContractDocument>(CONTRACT_JSON)
            .expect("checked CockroachDB Cloud contract");
        assert_eq!(contract.schema_version, CONTRACT_SCHEMA);
        assert_eq!(contract.contract_version, CONTRACT_VERSION);
        assert_eq!(contract.plugin_version, PLUGIN_VERSION);
        assert_eq!(contract.plugin_id, PLUGIN_ID);
        assert_eq!(contract.layer, "Layer-1");
        assert_eq!(contract.evidence_level, EVIDENCE_LEVEL);
        assert_eq!(contract.service.id, SERVICE_ID);
        assert!(contract.service.read_only);
        assert!(!contract.service.external_writes);
        assert!(!contract.service.sql_execution);
        assert_eq!(contract.provider.id, PROVIDER_ID);
        assert_eq!(contract.provider.api_revision, API_REVISION);
        assert!(!contract.provider.connected_evidence);
        assert!(!contract.provider.native_evidence);
        assert!(!contract.provider.first_party_evidence);
        assert_eq!(contract.consumer.id, CONSUMER_ID);
        assert!(!contract.consumer.adopts_outcome);
        assert!(!contract.consumer.adopts_work_product);
        assert!(!contract.consumer.truth_authority);
        assert_eq!(contract.native_gap.status, BLOCKED_ENV);
        assert!(!contract.native_gap.connected);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::sql_execution());
        assert!(!Layer1Authority::external_writes());
    }
}
