//! Layer-1 governed Mixpanel aggregate analytics result plugin.
//!
//! The crate models the official Mixpanel Insights saved-report request shape
//! while deliberately stopping before native credential resolution or HTTPS.
//! It retains only bounded aggregate counts and safe event labels. Raw API
//! bodies, raw events, event properties, user identifiers, ingestion, replay,
//! causal claims, and Outcome authority are outside this boundary.

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
mod query;
mod service;

#[cfg(test)]
mod adversarial_tests;

pub use consumer::{
    ConsumerError, MissionMixpanelAnalyticsConsumer, MissionMixpanelAnalyticsResult,
    MissionResultState,
};
pub use model::{
    AggregateBucket, AggregateSeries, DateWindow, Digest, EventName, EventSelector, MissionId,
    MissionScope, MixpanelAnalyticsScope, MixpanelRegistration, ModelError, PrivacyPolicy,
    ProjectId, ProjectScope, ProviderErrorKind, ProviderProvenance, RedactionSummary,
    RegistrationRevocation, RegistrationState, ReportId, ResultStatus, Revision, SecretReference,
    Timestamp, UtcDate, WorkProductId, WorkProductScope, WorkspaceId,
};
pub use provider::{
    BlockedEnvMixpanelTransport, FakeMixpanelTransport, FixtureMixpanelTransport,
    LoopbackMixpanelTransport, MixpanelHttpResponse, MixpanelProvider, MixpanelProviderDefinition,
    MixpanelProviderError, MixpanelProviderEvidence, MixpanelTransport, MixpanelTransportError,
    RecordingMixpanelTransport,
};
pub use query::{IdempotencyKey, MixpanelAnalyticsResultRequest, QueryError};
pub use service::{
    MixpanelAnalyticsResultProposal, MixpanelAnalyticsResultReceipt,
    MixpanelAnalyticsResultService, MixpanelAnalyticsResultServiceError, MixpanelServiceDefinition,
};

pub const MIXPANEL_ANALYTICS_RESULT_SCHEMA_VERSION: &str =
    "hartevo-mixpanel-analytics-result-contract/v1";
pub const MIXPANEL_ANALYTICS_RESULT_CONTRACT_VERSION: &str = "mixpanel-analytics-result-e1/v1";
pub const MIXPANEL_ANALYTICS_RESULT_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const MIXPANEL_ANALYTICS_RESULT_SERVICE_ID: &str = "mixpanel.analytics.result";
pub const MIXPANEL_ANALYTICS_RESULT_PROVIDER_ID: &str = "mixpanel.query.insights";
pub const MIXPANEL_ANALYTICS_RESULT_CONSUMER_ID: &str =
    "mission.mixpanel.analytics.result.consumer";
pub const MIXPANEL_ANALYTICS_RESULT_EVIDENCE_LEVEL: &str = "E1";
pub const MIXPANEL_ANALYTICS_RESULT_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const MIXPANEL_INSIGHTS_ORIGIN: &str = "https://mixpanel.com";
pub const MIXPANEL_INSIGHTS_PATH: &str = "/api/query/insights";
pub const MIXPANEL_INSIGHTS_METHOD: &str = "GET";
pub const MIXPANEL_PRIVACY_POLICY_VERSION: &str = "mixpanel-analytics-privacy/v1";
pub const MIXPANEL_MAX_EVENT_SELECTORS: usize = 8;
pub const MIXPANEL_MAX_SERIES: usize = 8;
pub const MIXPANEL_MAX_BUCKETS_PER_SERIES: usize = 31;
pub const MIXPANEL_MAX_RESPONSE_BYTES: usize = 256 * 1024;
pub const MIXPANEL_MAX_REQUESTS_PER_PROJECT_PER_UTC_HOUR: u8 = 60;
pub const MIXPANEL_MAX_CONCURRENT_QUERIES: u8 = 5;
pub const MIXPANEL_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/mixpanel-analytics-result/mixpanel-analytics-result.v1.json"
);

pub(crate) fn contract_digest() -> Digest {
    Digest::from_text(MIXPANEL_CONTRACT_JSON)
}

pub(crate) fn service_version_digest() -> Digest {
    Digest::from_text(MIXPANEL_ANALYTICS_RESULT_PLUGIN_VERSION_TEXT)
}

/// Layer 1 exposes evidence only. None of these flags imply a connected
/// account, native provider, first-party transport, or Truth authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1ResultAuthority;

impl Layer1ResultAuthority {
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

    pub const fn readback() -> bool {
        false
    }

    pub const fn durable_receipt() -> bool {
        false
    }

    pub const fn adopted_work_product() -> bool {
        false
    }

    pub const fn outcome_authority() -> bool {
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
        Layer1ResultAuthority, MIXPANEL_ANALYTICS_RESULT_CONSUMER_ID,
        MIXPANEL_ANALYTICS_RESULT_CONTRACT_VERSION, MIXPANEL_ANALYTICS_RESULT_EVIDENCE_LEVEL,
        MIXPANEL_ANALYTICS_RESULT_PROVIDER_ID, MIXPANEL_ANALYTICS_RESULT_SCHEMA_VERSION,
        MIXPANEL_ANALYTICS_RESULT_SERVICE_ID, MIXPANEL_CONTRACT_JSON, MIXPANEL_INSIGHTS_METHOD,
        MIXPANEL_INSIGHTS_PATH, MIXPANEL_MAX_BUCKETS_PER_SERIES, MIXPANEL_MAX_EVENT_SELECTORS,
        MIXPANEL_MAX_REQUESTS_PER_PROJECT_PER_UTC_HOUR, MIXPANEL_MAX_RESPONSE_BYTES,
        MIXPANEL_MAX_SERIES,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        evidence_level: String,
        layer: u8,
        service: ServiceDocument,
        provider: ProviderDocument,
        consumer: ConsumerDocument,
        limits: LimitDocument,
        native_claims: NativeClaims,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ServiceDocument {
        id: String,
        version: String,
        read_only: bool,
        live_execution: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderDocument {
        id: String,
        method: String,
        path: String,
        native: bool,
        https_transport: bool,
        first_party: bool,
        readback: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConsumerDocument {
        id: String,
        adopts_work_product: bool,
        truth_authority: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    #[allow(clippy::struct_field_names)]
    struct LimitDocument {
        max_event_selectors: usize,
        max_series: usize,
        max_buckets_per_series: usize,
        max_response_bytes: usize,
        max_requests_per_project_per_utc_hour: u8,
        max_concurrent_queries: u8,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NativeClaims {
        connected: bool,
        native_provider: bool,
        first_party: bool,
        https_transport: bool,
        durable_receipt: bool,
        adopted_work_product: bool,
        adopted_outcome: bool,
        blocked_environment_is_native: bool,
    }

    #[test]
    fn contract_document_matches_the_typed_boundary() {
        let document = serde_json::from_str::<ContractDocument>(MIXPANEL_CONTRACT_JSON)
            .expect("Mixpanel contract JSON");
        assert_eq!(
            document.schema_version,
            MIXPANEL_ANALYTICS_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document.contract_version,
            MIXPANEL_ANALYTICS_RESULT_CONTRACT_VERSION
        );
        assert_eq!(
            document.evidence_level,
            MIXPANEL_ANALYTICS_RESULT_EVIDENCE_LEVEL
        );
        assert_eq!(document.layer, 1);
        assert_eq!(document.service.id, MIXPANEL_ANALYTICS_RESULT_SERVICE_ID);
        assert_eq!(document.service.version, "1.0.0");
        assert!(document.service.read_only);
        assert!(!document.service.live_execution);
        assert_eq!(document.provider.id, MIXPANEL_ANALYTICS_RESULT_PROVIDER_ID);
        assert_eq!(document.provider.method, MIXPANEL_INSIGHTS_METHOD);
        assert_eq!(document.provider.path, MIXPANEL_INSIGHTS_PATH);
        assert!(!document.provider.native);
        assert!(!document.provider.https_transport);
        assert!(!document.provider.first_party);
        assert!(!document.provider.readback);
        assert_eq!(document.consumer.id, MIXPANEL_ANALYTICS_RESULT_CONSUMER_ID);
        assert!(!document.consumer.adopts_work_product);
        assert!(!document.consumer.truth_authority);
        assert_eq!(
            document.limits.max_event_selectors,
            MIXPANEL_MAX_EVENT_SELECTORS
        );
        assert_eq!(document.limits.max_series, MIXPANEL_MAX_SERIES);
        assert_eq!(
            document.limits.max_buckets_per_series,
            MIXPANEL_MAX_BUCKETS_PER_SERIES
        );
        assert_eq!(
            document.limits.max_response_bytes,
            MIXPANEL_MAX_RESPONSE_BYTES
        );
        assert_eq!(
            document.limits.max_requests_per_project_per_utc_hour,
            MIXPANEL_MAX_REQUESTS_PER_PROJECT_PER_UTC_HOUR
        );
        assert_eq!(document.limits.max_concurrent_queries, 5);
        assert!(!document.native_claims.connected);
        assert!(!document.native_claims.native_provider);
        assert!(!document.native_claims.first_party);
        assert!(!document.native_claims.https_transport);
        assert!(!document.native_claims.durable_receipt);
        assert!(!document.native_claims.adopted_work_product);
        assert!(!document.native_claims.adopted_outcome);
        assert!(!document.native_claims.blocked_environment_is_native);
        assert!(!Layer1ResultAuthority::connected());
        assert!(!Layer1ResultAuthority::native_provider());
        assert!(!Layer1ResultAuthority::first_party());
        assert!(!Layer1ResultAuthority::truth_authority());
    }
}
