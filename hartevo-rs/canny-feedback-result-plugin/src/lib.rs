//! Standalone Layer-1 governed Canny feedback evidence result plugin.
//!
//! This crate exposes typed, scope-bound, read-only evidence and proposal
//! seams for bounded Canny board/post/comment/status/category/roadmap reads
//! and aggregate vote counts. It deliberately has no native API-key resolver,
//! HTTPS client, feedback mutation, voter or author identity path, Jira or
//! project mutation, causal-demand authority, Work Product adoption, or
//! kernel Outcome/Truth authority.

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
mod query;
mod service;

#[cfg(test)]
mod adversarial_tests;

pub use consumer::{
    ConsumerError, MissionCannyFeedbackConsumer, MissionCannyFeedbackResult,
    MissionFeedbackConsumer, MissionFeedbackResult, MissionResultState,
};
pub use model::*;
pub use provider::{
    BlockedEnvCannyTransport, BlockedEnvTransport, CannyFeedbackProvider,
    CannyFeedbackProviderError, CannyFeedbackTransport, CannyHttpResponse, CannyProvider,
    CannyProviderDefinition, CannyProviderError, CannyTransport, CannyTransportError,
    FakeCannyTransport, FixtureCannyTransport, LoopbackCannyTransport, ProviderDefinitionError,
    RecordingCannyTransport,
};
pub use query::{
    CannyFeedbackReadOperations, CannyFeedbackRequest, CannyFeedbackResultRequest, IdempotencyKey,
    QueryError,
};
pub use service::{
    CannyFeedbackRecordReceipt, CannyFeedbackResultProposal, CannyFeedbackResultReceipt,
    CannyFeedbackResultService, CannyFeedbackResultServiceError, CannyFeedbackService,
    CannyFeedbackServiceDefinition, CannyFeedbackServiceError, ServiceDefinitionError,
};

pub const CANNY_FEEDBACK_RESULT_SCHEMA_VERSION: &str = "hartevo-canny-feedback-result-contract/v1";
pub const CANNY_FEEDBACK_RESULT_CONTRACT_VERSION: &str = "canny-feedback-result-e1/v1";
pub const CANNY_FEEDBACK_RESULT_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const CANNY_FEEDBACK_RESULT_SERVICE_ID: &str = "canny.feedback.result";
pub const CANNY_FEEDBACK_RESULT_PROVIDER_ID: &str = "canny.feedback.read";
pub const CANNY_FEEDBACK_RESULT_CONSUMER_ID: &str = "mission.canny.feedback.result.consumer";
pub const CANNY_FEEDBACK_RESULT_EVIDENCE_LEVEL: &str = "E1";
pub const CANNY_FEEDBACK_RESULT_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CANNY_API_ORIGIN: &str = "https://canny.io";
pub const CANNY_API_METHOD: &str = "POST";
pub const CANNY_API_PATH_PREFIX: &str = "/api";
pub const CANNY_PRIVACY_POLICY_VERSION: &str = "canny-feedback-privacy/v1";
pub const CANNY_MAX_WINDOW_DAYS: i64 = 31;
pub const CANNY_MAX_BOARDS: usize = 1;
pub const CANNY_MAX_POSTS: usize = 128;
pub const CANNY_MAX_COMMENTS: usize = 256;
pub const CANNY_MAX_VOTE_AGGREGATES: usize = 128;
pub const CANNY_MAX_STATUSES: usize = 64;
pub const CANNY_MAX_CATEGORIES: usize = 64;
pub const CANNY_MAX_ROADMAPS: usize = 32;
pub const CANNY_MAX_RESPONSE_BYTES: usize = 256 * 1024;
pub const CANNY_MAX_REQUESTS_PER_SCOPE_PER_UTC_HOUR: u8 = 60;
pub const CANNY_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/canny-feedback-result/canny-feedback-result.v1.json");

pub(crate) fn contract_digest() -> Digest {
    Digest::from_text(CANNY_CONTRACT_JSON)
}

pub(crate) fn service_version_digest() -> Digest {
    Digest::from_text(CANNY_FEEDBACK_RESULT_PLUGIN_VERSION_TEXT)
}

/// Layer 1 authority is deliberately negative: this slice is evidence and a
/// proposal, never a connected provider, native credential, or Truth claim.
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

    pub const fn feedback_mutation() -> bool {
        false
    }

    pub const fn voter_pii() -> bool {
        false
    }

    pub const fn causal_demand() -> bool {
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
        CANNY_API_METHOD, CANNY_CONTRACT_JSON, CANNY_FEEDBACK_RESULT_CONSUMER_ID,
        CANNY_FEEDBACK_RESULT_CONTRACT_VERSION, CANNY_FEEDBACK_RESULT_EVIDENCE_LEVEL,
        CANNY_FEEDBACK_RESULT_PROVIDER_ID, CANNY_FEEDBACK_RESULT_SCHEMA_VERSION,
        CANNY_FEEDBACK_RESULT_SERVICE_ID, CANNY_MAX_CATEGORIES, CANNY_MAX_COMMENTS,
        CANNY_MAX_POSTS, CANNY_MAX_RESPONSE_BYTES, CANNY_MAX_ROADMAPS, CANNY_MAX_STATUSES,
        CANNY_MAX_VOTE_AGGREGATES, CANNY_MAX_WINDOW_DAYS, CannyProviderDefinition,
        Layer1ResultAuthority,
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
        proposal_only: bool,
        live_execution: bool,
        external_writes: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderDocument {
        id: String,
        method: String,
        native: bool,
        connected: bool,
        https_transport: bool,
        readback: bool,
        writes: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConsumerDocument {
        id: String,
        adopts_work_product: bool,
        truth_authority: bool,
        connected: bool,
        native_provider: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    #[allow(clippy::struct_field_names)]
    struct LimitDocument {
        max_window_days: i64,
        max_posts: usize,
        max_comments: usize,
        max_vote_aggregates: usize,
        max_statuses: usize,
        max_categories: usize,
        max_roadmaps: usize,
        max_response_bytes: usize,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NativeClaims {
        connected: bool,
        native_provider: bool,
        https_transport: bool,
        first_party: bool,
        durable_receipt: bool,
        readback: bool,
        adopted_work_product: bool,
        adopted_outcome: bool,
        blocked_environment_is_native: bool,
    }

    #[test]
    fn contract_document_matches_the_typed_boundary() {
        let document = serde_json::from_str::<ContractDocument>(CANNY_CONTRACT_JSON)
            .expect("Canny contract JSON");
        assert_eq!(
            document.schema_version,
            CANNY_FEEDBACK_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document.contract_version,
            CANNY_FEEDBACK_RESULT_CONTRACT_VERSION
        );
        assert_eq!(
            document.evidence_level,
            CANNY_FEEDBACK_RESULT_EVIDENCE_LEVEL
        );
        assert_eq!(document.layer, 1);
        assert_eq!(document.service.id, CANNY_FEEDBACK_RESULT_SERVICE_ID);
        assert_eq!(document.service.version, "1.0.0");
        assert!(document.service.read_only);
        assert!(document.service.proposal_only);
        assert!(!document.service.live_execution);
        assert!(!document.service.external_writes);
        assert_eq!(document.provider.id, CANNY_FEEDBACK_RESULT_PROVIDER_ID);
        assert_eq!(document.provider.method, CANNY_API_METHOD);
        assert!(!document.provider.native);
        assert!(!document.provider.connected);
        assert!(!document.provider.https_transport);
        assert!(!document.provider.readback);
        assert!(!document.provider.writes);
        assert_eq!(document.consumer.id, CANNY_FEEDBACK_RESULT_CONSUMER_ID);
        assert!(!document.consumer.adopts_work_product);
        assert!(!document.consumer.truth_authority);
        assert!(!document.consumer.connected);
        assert!(!document.consumer.native_provider);
        assert_eq!(document.limits.max_window_days, CANNY_MAX_WINDOW_DAYS);
        assert_eq!(document.limits.max_posts, CANNY_MAX_POSTS);
        assert_eq!(document.limits.max_comments, CANNY_MAX_COMMENTS);
        assert_eq!(
            document.limits.max_vote_aggregates,
            CANNY_MAX_VOTE_AGGREGATES
        );
        assert_eq!(document.limits.max_statuses, CANNY_MAX_STATUSES);
        assert_eq!(document.limits.max_categories, CANNY_MAX_CATEGORIES);
        assert_eq!(document.limits.max_roadmaps, CANNY_MAX_ROADMAPS);
        assert_eq!(document.limits.max_response_bytes, CANNY_MAX_RESPONSE_BYTES);
        assert!(!document.native_claims.connected);
        assert!(!document.native_claims.native_provider);
        assert!(!document.native_claims.https_transport);
        assert!(!document.native_claims.first_party);
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
        assert!(!Layer1ResultAuthority::feedback_mutation());
        assert!(!Layer1ResultAuthority::voter_pii());
        assert!(!Layer1ResultAuthority::causal_demand());
        assert!(!Layer1ResultAuthority::adopted_work_product());
        assert!(!Layer1ResultAuthority::adopted_outcome());
        assert!(!Layer1ResultAuthority::truth_authority());
        CannyProviderDefinition::new()
            .validate()
            .expect("typed provider definition matches the contract");
    }
}
