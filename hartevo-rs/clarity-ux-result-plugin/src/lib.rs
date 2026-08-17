//! Layer-1 governed Microsoft Clarity aggregate UX-behavior result plugin.
//!
//! This crate exposes a typed, read-only proposal boundary for a bounded
//! Clarity Data Export API GET. It has no native token resolver, HTTPS client,
//! session or heatmap access, visitor identity path, mutation API, dashboard,
//! causal inference, Work Product adoption, or kernel Outcome authority.

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
    ConsumerError, MissionClarityUxConsumer, MissionClarityUxResult, MissionResultState,
};
pub use model::{
    AggregateMeasure, AggregateRow, AggregateValue, AppId, ApplicationId, ClarityAppId,
    ClarityDeploymentId, ClarityProjectId, ClarityRegistration, ClaritySiteId, ClarityUxScope,
    ConsentPurpose, ConsentScope, DeploymentId, Digest, Dimension, DimensionSet, DimensionValue,
    Metric, MetricEvidence, MetricSet, MissionId, MissionScope, ModelError, PrivacyPolicy,
    ProjectId, ProjectScope, ProviderErrorKind, ProviderProvenance, RedactionSummary,
    RegistrationRevocation, RegistrationState, ResultStatus, Revision, SecretReference, SiteId,
    TimeWindow, Timestamp, WebsiteUrl, WorkProductId, WorkProductScope,
};
pub use provider::{
    BlockedEnvTransport, ClarityDataExportProvider, ClarityDataExportTransport,
    ClarityHttpResponse, ClarityProvider, ClarityProviderDefinition, ClarityProviderError,
    ClarityProviderEvidence, ClarityTransportError, FakeClarityTransport, FixtureClarityTransport,
    LoopbackClarityTransport, ProviderDefinitionError, RecordingClarityTransport,
};
pub use query::{ClarityDataExportGetRequest, ClarityUxResultRequest, QueryError};
pub use service::{
    ClarityServiceDefinition, ClarityUxResultProposal, ClarityUxResultReceipt,
    ClarityUxResultService, ClarityUxResultServiceError,
};

pub const CLARITY_UX_RESULT_SCHEMA_VERSION: &str = "hartevo-clarity-ux-result-contract/v1";
pub const CLARITY_UX_RESULT_CONTRACT_VERSION: &str = "clarity-ux-result-e1/v1";
pub const CLARITY_UX_RESULT_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const CLARITY_UX_RESULT_SERVICE_ID: &str = "clarity.ux.result";
pub const CLARITY_UX_RESULT_PROVIDER_ID: &str = "clarity.data-export.project-live-insights";
pub const CLARITY_UX_RESULT_CONSUMER_ID: &str = "mission.clarity.ux.result.consumer";
pub const CLARITY_UX_RESULT_EVIDENCE_LEVEL: &str = "E1";
pub const CLARITY_UX_RESULT_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CLARITY_DATA_EXPORT_ORIGIN: &str = "https://www.clarity.ms";
pub const CLARITY_DATA_EXPORT_PATH: &str = "/export-data/api/v1/project-live-insights";
pub const CLARITY_DATA_EXPORT_METHOD: &str = "GET";
pub const CLARITY_PRIVACY_POLICY_VERSION: &str = "clarity-ux-privacy/v1";
pub const CLARITY_MAX_DAYS: u8 = 3;
pub const CLARITY_MAX_DIMENSIONS: usize = 3;
pub const CLARITY_MAX_RESPONSE_ROWS: u16 = 1_000;
pub const CLARITY_MAX_RESPONSE_BYTES: usize = 256 * 1024;
pub const CLARITY_MAX_REQUESTS_PER_PROJECT_PER_DAY: u8 = 10;
pub const CLARITY_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/clarity-ux-result/clarity-ux-result.v1.json");

pub(crate) fn contract_digest() -> Digest {
    Digest::from_text(CLARITY_CONTRACT_JSON)
}

/// Layer 1 authority is deliberately negative: the proposal is evidence for
/// a decision and never a connected provider, durable native receipt, or Truth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1ResultAuthority;

impl Layer1ResultAuthority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
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

    pub const fn adopted_outcome() -> bool {
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
        CLARITY_CONTRACT_JSON, CLARITY_DATA_EXPORT_PATH, CLARITY_MAX_DIMENSIONS,
        CLARITY_MAX_REQUESTS_PER_PROJECT_PER_DAY, CLARITY_MAX_RESPONSE_BYTES,
        CLARITY_MAX_RESPONSE_ROWS, CLARITY_UX_RESULT_CONSUMER_ID,
        CLARITY_UX_RESULT_CONTRACT_VERSION, CLARITY_UX_RESULT_EVIDENCE_LEVEL,
        CLARITY_UX_RESULT_PROVIDER_ID, CLARITY_UX_RESULT_SCHEMA_VERSION,
        CLARITY_UX_RESULT_SERVICE_ID, ClarityProviderDefinition, Layer1ResultAuthority,
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
        limits: LimitDocument,
        native_claims: NativeClaims,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ServiceDocument {
        id: String,
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
        readback: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct LimitDocument {
        max_dimensions: usize,
        max_rows: u16,
        max_response_bytes: usize,
        max_requests_per_project_per_utc_day: u8,
        paginated: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NativeClaims {
        connected: bool,
        native_provider: bool,
        https_transport: bool,
        durable_receipt: bool,
        readback: bool,
        adopted_work_product: bool,
        adopted_outcome: bool,
        blocked_environment_is_native: bool,
    }

    #[test]
    fn contract_document_matches_the_typed_boundary() {
        let document = serde_json::from_str::<ContractDocument>(CLARITY_CONTRACT_JSON)
            .expect("Clarity contract JSON");
        assert_eq!(document.schema_version, CLARITY_UX_RESULT_SCHEMA_VERSION);
        assert_eq!(
            document.contract_version,
            CLARITY_UX_RESULT_CONTRACT_VERSION
        );
        assert_eq!(document.evidence_level, CLARITY_UX_RESULT_EVIDENCE_LEVEL);
        assert_eq!(document.layer, 1);
        assert_eq!(document.service.id, CLARITY_UX_RESULT_SERVICE_ID);
        assert!(document.service.read_only);
        assert!(!document.service.live_execution);
        assert_eq!(document.provider.id, CLARITY_UX_RESULT_PROVIDER_ID);
        assert_eq!(document.provider.method, "GET");
        assert_eq!(document.provider.path, CLARITY_DATA_EXPORT_PATH);
        assert!(!document.provider.native);
        assert!(!document.provider.https_transport);
        assert!(!document.provider.readback);
        assert_eq!(document.limits.max_dimensions, CLARITY_MAX_DIMENSIONS);
        assert_eq!(document.limits.max_rows, CLARITY_MAX_RESPONSE_ROWS);
        assert_eq!(
            document.limits.max_response_bytes,
            CLARITY_MAX_RESPONSE_BYTES
        );
        assert_eq!(
            document.limits.max_requests_per_project_per_utc_day,
            CLARITY_MAX_REQUESTS_PER_PROJECT_PER_DAY
        );
        assert!(!document.limits.paginated);
        assert_eq!(
            CLARITY_UX_RESULT_CONSUMER_ID,
            "mission.clarity.ux.result.consumer"
        );
        assert!(!document.native_claims.connected);
        assert!(!document.native_claims.native_provider);
        assert!(!document.native_claims.https_transport);
        assert!(!document.native_claims.durable_receipt);
        assert!(!document.native_claims.readback);
        assert!(!document.native_claims.adopted_work_product);
        assert!(!document.native_claims.adopted_outcome);
        assert!(!document.native_claims.blocked_environment_is_native);
        assert!(!Layer1ResultAuthority::connected());
        assert!(!Layer1ResultAuthority::native_provider());
        assert!(!Layer1ResultAuthority::https_transport());
        assert!(!Layer1ResultAuthority::readback());
        assert!(!Layer1ResultAuthority::durable_receipt());
        assert!(!Layer1ResultAuthority::adopted_work_product());
        assert!(!Layer1ResultAuthority::adopted_outcome());
        assert!(!Layer1ResultAuthority::truth_authority());
        ClarityProviderDefinition::new()
            .validate()
            .expect("typed definition matches the contract");
    }
}
