//! Standalone Layer-1 governed RudderStack event-quality evidence plugin.
//!
//! The crate exposes typed, scope-bound, read-only evidence and proposal
//! seams for source metadata, tracking-plan versions, schema violations,
//! delivery health, and aggregate governance metrics. It never resolves an
//! API token, sends or transforms events, mutates a destination or tracking
//! plan, retains raw event data, adopts a Work Product, or claims native
//! Truth/Outcome authority.

#![forbid(unsafe_code)]
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

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    ConsumerError, MissionEventQualityConsumer, MissionRudderStackEventConsumer,
    MissionRudderStackEventConsumerError, MissionRudderStackEventQualityConsumer,
    MissionRudderStackResult,
};
pub use model::*;
pub use provider::{
    BlockedEnvRudderStackTransport, BlockedEnvTransport, FakeRudderStackTransport,
    FixtureRudderStackTransport, FixtureTransport, LoopbackRudderStackTransport, LoopbackTransport,
    RecordingRudderStackTransport, RecordingTransport, RudderStackBatchRead, RudderStackHttpMethod,
    RudderStackOperation, RudderStackOperationFailure, RudderStackProvider,
    RudderStackProviderDefinition, RudderStackProviderError, RudderStackProviderRead,
    RudderStackRequest, RudderStackResponse, RudderStackResponseBuilder,
    RudderStackResponseValidation, RudderStackTransport, RudderStackTransportError,
};
pub use service::{
    RudderStackEventQualityService, RudderStackEventQualityServiceDefinition,
    RudderStackEventQualityServiceError, RudderStackReadConsent, RudderStackServiceDefinition,
    RudderStackServiceError,
};

pub const RUDDERSTACK_EVENT_QUALITY_SCHEMA_VERSION: &str =
    "hartevo-rudderstack-event-quality-contract/v1";
pub const RUDDERSTACK_EVENT_QUALITY_CONTRACT_VERSION: &str = "rudderstack-event-quality-e1/v1";
pub const RUDDERSTACK_EVENT_QUALITY_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const RUDDERSTACK_EVENT_QUALITY_SERVICE_ID: &str = "rudderstack.event-quality.result";
pub const RUDDERSTACK_EVENT_QUALITY_SERVICE_VERSION_TEXT: &str = "1.0.0";
pub const RUDDERSTACK_EVENT_QUALITY_PROVIDER_ID: &str = "rudderstack.event-quality.read";
pub const RUDDERSTACK_EVENT_QUALITY_PROVIDER_VERSION_TEXT: &str = "1.0.0";
pub const RUDDERSTACK_EVENT_QUALITY_CONSUMER_ID: &str =
    "mission.rudderstack.event-quality.consumer";
pub const RUDDERSTACK_EVENT_QUALITY_EVIDENCE_LEVEL: &str = "E1";
pub const RUDDERSTACK_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const RUDDERSTACK_API_ORIGIN: &str = "https://api.rudderstack.com";
pub const RUDDERSTACK_API_METHOD: &str = "GET";
pub const RUDDERSTACK_API_REVISION: &str = "rudderstack-event-quality-api-v1";
pub const RUDDERSTACK_PRIVACY_POLICY_VERSION: &str = "rudderstack-event-quality-privacy/v1";
pub const RUDDERSTACK_MAX_IDENTIFIER_BYTES: usize = 128;
pub const RUDDERSTACK_MAX_WINDOW_DAYS: i64 = 31;
pub const RUDDERSTACK_MAX_PAGE_SIZE: usize = 100;
pub const RUDDERSTACK_MAX_CURSOR_BYTES: usize = 256;
pub const RUDDERSTACK_MAX_RESPONSE_BYTES: usize = 256 * 1024;
pub const RUDDERSTACK_MAX_DIAGNOSTIC_BYTES: usize = 512;
pub const RUDDERSTACK_MAX_REQUESTS_PER_MINUTE: u16 = 60;
pub const RUDDERSTACK_MAX_EVENT_NAMES: usize = 128;
pub const RUDDERSTACK_MAX_PROPERTIES: usize = 256;
pub const RUDDERSTACK_MAX_VIOLATIONS: usize = 256;
pub const RUDDERSTACK_MAX_AGGREGATE_COUNT: u64 = 1_000_000_000;

pub const RUDDERSTACK_EVENT_QUALITY_CONTRACT_PATH: &str =
    "contracts/plugins/rudderstack-event-quality/contract.v1.json";
pub const RUDDERSTACK_EVENT_QUALITY_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/rudderstack-event-quality/contract.v1.json");

pub fn contract_digest() -> Digest {
    Digest::from_text(RUDDERSTACK_EVENT_QUALITY_CONTRACT_JSON)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }

    pub const fn https_transport() -> bool {
        false
    }

    pub const fn durable_receipt() -> bool {
        false
    }

    pub const fn readback() -> bool {
        false
    }

    pub const fn external_writes() -> bool {
        false
    }

    pub const fn adopts_work_product() -> bool {
        false
    }

    pub const fn adopts_outcome() -> bool {
        false
    }

    pub const fn truth_authority() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use serde::Deserialize;

    use super::{
        Layer1Authority, RUDDERSTACK_API_METHOD, RUDDERSTACK_API_ORIGIN,
        RUDDERSTACK_EVENT_QUALITY_CONSUMER_ID, RUDDERSTACK_EVENT_QUALITY_CONTRACT_JSON,
        RUDDERSTACK_EVENT_QUALITY_CONTRACT_VERSION, RUDDERSTACK_EVENT_QUALITY_EVIDENCE_LEVEL,
        RUDDERSTACK_EVENT_QUALITY_PLUGIN_VERSION_TEXT, RUDDERSTACK_EVENT_QUALITY_PROVIDER_ID,
        RUDDERSTACK_EVENT_QUALITY_SCHEMA_VERSION, RUDDERSTACK_EVENT_QUALITY_SERVICE_ID,
        RUDDERSTACK_MAX_CURSOR_BYTES, RUDDERSTACK_MAX_DIAGNOSTIC_BYTES,
        RUDDERSTACK_MAX_EVENT_NAMES, RUDDERSTACK_MAX_PAGE_SIZE, RUDDERSTACK_MAX_PROPERTIES,
        RUDDERSTACK_MAX_RESPONSE_BYTES, RUDDERSTACK_MAX_VIOLATIONS,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        plugin_version: String,
        evidence_level: String,
        layer: u8,
        service: ServiceDocument,
        provider: ProviderDocument,
        consumer: ConsumerDocument,
        bounds: LimitDocument,
        native_claims: NativeClaims,
        states: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ServiceDocument {
        id: String,
        version: String,
        read_only: bool,
        proposal_only: bool,
        live_execution: bool,
        external_writes: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderDocument {
        id: String,
        version: String,
        origin: String,
        method: String,
        native: bool,
        connected: bool,
        first_party: bool,
        writes: bool,
        operations: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConsumerDocument {
        id: String,
        adopts_work_product: bool,
        adopts_outcome: bool,
        truth_authority: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    #[allow(clippy::struct_field_names)]
    struct LimitDocument {
        max_page_size: usize,
        max_cursor_bytes: usize,
        max_response_bytes: usize,
        max_diagnostic_bytes: usize,
        max_event_names: usize,
        max_properties: usize,
        max_violations: usize,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NativeClaims {
        connected: bool,
        native_provider: bool,
        first_party: bool,
        https_transport: bool,
        durable_receipt: bool,
        readback: bool,
        adopted_work_product: bool,
        adopted_outcome: bool,
        blocked_environment_is_native: bool,
    }

    #[test]
    fn contract_document_matches_the_typed_negative_boundary() {
        let document =
            serde_json::from_str::<ContractDocument>(RUDDERSTACK_EVENT_QUALITY_CONTRACT_JSON)
                .expect("RudderStack contract JSON");
        assert_eq!(
            document.schema_version,
            RUDDERSTACK_EVENT_QUALITY_SCHEMA_VERSION
        );
        assert_eq!(
            document.contract_version,
            RUDDERSTACK_EVENT_QUALITY_CONTRACT_VERSION
        );
        assert_eq!(
            document.plugin_version,
            RUDDERSTACK_EVENT_QUALITY_PLUGIN_VERSION_TEXT
        );
        assert_eq!(
            document.evidence_level,
            RUDDERSTACK_EVENT_QUALITY_EVIDENCE_LEVEL
        );
        assert_eq!(document.layer, 1);
        assert_eq!(document.service.id, RUDDERSTACK_EVENT_QUALITY_SERVICE_ID);
        assert_eq!(document.service.version, "1.0.0");
        assert!(document.service.read_only);
        assert!(document.service.proposal_only);
        assert!(!document.service.live_execution);
        assert!(!document.service.external_writes);
        assert_eq!(document.provider.id, RUDDERSTACK_EVENT_QUALITY_PROVIDER_ID);
        assert_eq!(document.provider.version, "1.0.0");
        assert_eq!(document.provider.origin, RUDDERSTACK_API_ORIGIN);
        assert_eq!(document.provider.method, RUDDERSTACK_API_METHOD);
        assert!(!document.provider.native);
        assert!(!document.provider.connected);
        assert!(!document.provider.first_party);
        assert!(!document.provider.writes);
        assert_eq!(document.provider.operations.len(), 5);
        assert_eq!(document.consumer.id, RUDDERSTACK_EVENT_QUALITY_CONSUMER_ID);
        assert!(!document.consumer.adopts_work_product);
        assert!(!document.consumer.adopts_outcome);
        assert!(!document.consumer.truth_authority);
        assert_eq!(document.bounds.max_page_size, RUDDERSTACK_MAX_PAGE_SIZE);
        assert_eq!(
            document.bounds.max_cursor_bytes,
            RUDDERSTACK_MAX_CURSOR_BYTES
        );
        assert_eq!(
            document.bounds.max_response_bytes,
            RUDDERSTACK_MAX_RESPONSE_BYTES
        );
        assert_eq!(
            document.bounds.max_diagnostic_bytes,
            RUDDERSTACK_MAX_DIAGNOSTIC_BYTES
        );
        assert_eq!(document.bounds.max_event_names, RUDDERSTACK_MAX_EVENT_NAMES);
        assert_eq!(document.bounds.max_properties, RUDDERSTACK_MAX_PROPERTIES);
        assert_eq!(document.bounds.max_violations, RUDDERSTACK_MAX_VIOLATIONS);
        for claim in [
            document.native_claims.connected,
            document.native_claims.native_provider,
            document.native_claims.first_party,
            document.native_claims.https_transport,
            document.native_claims.durable_receipt,
            document.native_claims.readback,
            document.native_claims.adopted_work_product,
            document.native_claims.adopted_outcome,
            document.native_claims.blocked_environment_is_native,
        ] {
            assert!(!claim);
        }
        assert!(document.states.iter().any(|state| state == "tamper"));
        assert!(document.states.iter().any(|state| state == "stale"));
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::external_writes());
    }
}
