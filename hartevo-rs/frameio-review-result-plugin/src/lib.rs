//! Layer-1 governed Frame.io creative-review evidence.
//!
//! This standalone root exposes typed `FrameIoReviewResultService`,
//! `FrameIoProvider`, and `MissionFrameIoReviewConsumer` seams.  It accepts
//! only bounded, redacted GET-shaped evidence from fixture, recording,
//! loopback, or blocked-environment transports.  It never stores media,
//! signed URLs, raw comments, reviewer identity, drawings, binaries, or
//! provider credentials, and it never claims Connected/native authority.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{
    ConsumerError, MissionFrameIoReviewConsumer, MissionFrameIoReviewResult,
    MissionFrameIoReviewState,
};
pub use model::*;
pub use provider::{
    FrameIoProvider, FrameIoProviderDefinition, FrameIoProviderError, FrameIoProviderRead,
    FrameIoProviderRevision, FrameIoReadFailure, FrameIoReadReceipt, FrameIoRetryEvidence,
    FrameIoTransportProvenance, ProviderDefinitionError,
};
pub use service::{
    FrameIoAuthority, FrameIoRegistration, FrameIoReviewEvidence, FrameIoReviewProposal,
    FrameIoReviewProposalRequest, FrameIoReviewResultService, FrameIoServiceDefinition,
    FrameIoServiceError,
};
pub use transport::{
    BlockedEnvFrameIoTransport, FixtureFrameIoTransport, FrameIoFixtureTransport,
    FrameIoGetRequest, FrameIoGetResponse, FrameIoLoopbackTransport, FrameIoSnapshot,
    FrameIoTransport, FrameIoTransportError, FrameIoTransportErrorKind, LoopbackFrameIoTransport,
    OpaqueCursor, RecordingFrameIoTransport,
};

pub const FRAME_IO_REVIEW_RESULT_SCHEMA_VERSION: &str = "hartevo.frameio-review-result-contract/v1";
pub const FRAME_IO_REVIEW_RESULT_CONTRACT_VERSION: &str = "frameio-review-result/v1";
pub const FRAME_IO_REVIEW_RESULT_PLUGIN_ID: &str = "frameio-review-result";
pub const FRAME_IO_REVIEW_RESULT_PLUGIN_VERSION: &str = "1.0.0";
pub const FRAME_IO_REVIEW_RESULT_SERVICE_ID: &str = "frameio.review-result";
pub const FRAME_IO_REVIEW_RESULT_SERVICE_NAME: &str = "FrameIoReviewResultService";
pub const FRAME_IO_PROVIDER_ID: &str = "frameio.api";
pub const FRAME_IO_PROVIDER_NAME: &str = "FrameIoProvider";
pub const MISSION_FRAME_IO_REVIEW_CONSUMER_ID: &str = "mission.frameio-review-result";
pub const MISSION_FRAME_IO_REVIEW_CONSUMER_NAME: &str = "MissionFrameIoReviewConsumer";
pub const FRAME_IO_REVIEW_RESULT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/frameio-review-result/frameio-review-result.v1.json");
pub const FRAME_IO_MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const FRAME_IO_MAX_PAGES: u16 = 4;
pub const FRAME_IO_PAGE_SIZE: u16 = 50;
pub const FRAME_IO_MAX_COMMENT_SUMMARIES: u32 = 128;
pub const FRAME_IO_MAX_WINDOW_SECONDS: i64 = 31 * 24 * 60 * 60;
pub const FRAME_IO_MAX_RETRY_ATTEMPTS: u8 = 4;
pub const FRAME_IO_BLOCKED_ENV: &str = "BLOCKED_ENV";

/// SHA-256 of the exact checked-in contract bytes.
pub fn contract_digest() -> Digest {
    Digest::from_text(FRAME_IO_REVIEW_RESULT_CONTRACT_JSON)
}

pub fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PluginVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

impl PluginVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub const fn major(self) -> u16 {
        self.major
    }

    pub const fn minor(self) -> u16 {
        self.minor
    }

    pub const fn patch(self) -> u16 {
        self.patch
    }
}

impl std::fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrameIoContract {
    #[serde(rename = "$schema")]
    pub schema_uri: String,
    #[serde(rename = "$id")]
    pub id: String,
    pub title: String,
    pub schema_version: String,
    pub contract_version: String,
    pub layer: u8,
    pub service: ContractService,
    pub provider: ContractProvider,
    pub consumer: ContractConsumer,
    pub scope: ContractScope,
    pub reads: ContractReads,
    pub evidence: ContractEvidence,
    pub states: Vec<String>,
    pub registration: ContractRegistration,
    pub authority: ContractAuthority,
    pub honesty: ContractHonesty,
    pub layer2_gaps: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractService {
    pub id: String,
    pub version: String,
    pub implementation: String,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub live_execution: bool,
    pub writes: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractProvider {
    pub id: String,
    pub version: String,
    pub implementation: String,
    pub transport: Vec<String>,
    pub operations: Vec<String>,
    pub native: bool,
    pub connected: bool,
    pub live_https: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractConsumer {
    pub id: String,
    pub version: String,
    pub implementation: String,
    pub mission_bound: bool,
    pub project_bound: bool,
    pub work_product_bound: bool,
    pub adopts_work_product: bool,
    pub outcome_authority: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractScope {
    pub required: Vec<String>,
    pub secret_reference: String,
    pub digest: String,
    pub registration: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractReads {
    pub allow: Vec<String>,
    pub method: String,
    pub arbitrary_path: bool,
    pub arbitrary_query: bool,
    pub cursor: String,
    pub time_window: String,
    pub max_pages: u16,
    pub page_size: u16,
    pub max_response_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractEvidence {
    pub retain: Vec<String>,
    pub redact: Vec<String>,
    pub raw_provider_payload: bool,
    pub raw_comments: bool,
    pub reviewer_pii: bool,
    pub media_download: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractRegistration {
    pub version_bound: bool,
    pub provider_bound: bool,
    pub contract_digest_bound: bool,
    pub scope_digest_bound: bool,
    pub secret_reference_bound: bool,
    pub credential_revision_bound: bool,
    pub reversible: bool,
    pub revocable: bool,
    pub fail_closed_on_drift: bool,
    pub duplicate_proposal_rejected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractAuthority {
    pub read_only: bool,
    pub external_writes: bool,
    pub asset_upload: bool,
    pub asset_replacement: bool,
    pub comment_mutation: bool,
    pub approval_mutation: bool,
    pub review_link_creation: bool,
    pub media_download: bool,
    pub signed_url_exposure: bool,
    pub webhook_registration: bool,
    pub publication: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub receipt: bool,
    pub verification: bool,
    pub outcome: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractHonesty {
    pub fixture_native: bool,
    pub recording_native: bool,
    pub loopback_native: bool,
    pub blocked_env_native: bool,
    pub fixture_connected: bool,
    pub recording_connected: bool,
    pub loopback_connected: bool,
    pub blocked_env_connected: bool,
    pub absence_of_comments_is_approval: bool,
    pub absence_of_approval_is_quality: bool,
    pub blocked_environment_status: String,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum FrameIoContractError {
    #[error("Frame.io contract could not be decoded: {0}")]
    Decode(String),
    #[error("Frame.io contract does not match the checked-in Layer-1 baseline: {0}")]
    Invalid(String),
}

impl FrameIoContract {
    pub fn baseline() -> Result<Self, FrameIoContractError> {
        let contract = serde_json::from_str::<Self>(FRAME_IO_REVIEW_RESULT_CONTRACT_JSON)
            .map_err(|error| FrameIoContractError::Decode(error.to_string()))?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn validate(&self) -> Result<(), FrameIoContractError> {
        let expected_operations = vec![
            "describe_capabilities",
            "register",
            "revoke_registration",
            "read_asset_metadata",
            "read_asset_version",
            "read_review_link",
            "read_approval_status",
            "read_comment_summary",
            "compile_review_proposal",
            "record_review_proposal",
            "consume_review_proposal",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_states = [
            "uploaded",
            "processing",
            "ready",
            "in_review",
            "approved",
            "changes_requested",
            "rejected",
            "partial",
            "retention_gap",
            "access_lost",
            "provider_unknown",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let valid = self.schema_uri == "https://json-schema.org/draft/2020-12/schema"
            && self.id
                == "https://hartevo.local/contracts/plugins/frameio-review-result/frameio-review-result.v1.json"
            && self.title == "Hartevo Frame.io governed creative-review result contract"
            && self.schema_version == FRAME_IO_REVIEW_RESULT_SCHEMA_VERSION
            && self.contract_version == FRAME_IO_REVIEW_RESULT_CONTRACT_VERSION
            && self.layer == 1
            && self.service.id == FRAME_IO_REVIEW_RESULT_SERVICE_ID
            && self.service.version == FRAME_IO_REVIEW_RESULT_PLUGIN_VERSION
            && self.service.implementation == FRAME_IO_REVIEW_RESULT_SERVICE_NAME
            && self.service.operations == expected_operations
            && self.service.read_only
            && !self.service.live_execution
            && !self.service.writes
            && self.provider.id == FRAME_IO_PROVIDER_ID
            && self.provider.version == FRAME_IO_REVIEW_RESULT_PLUGIN_VERSION
            && self.provider.implementation == FRAME_IO_PROVIDER_NAME
            && self.provider.transport == vec!["fixture", "recording", "loopback", "blocked_env"]
            && self.provider.operations.len() == 5
            && self
                .provider
                .operations
                .iter()
                .all(|operation| operation.starts_with("GET ") && !operation.starts_with("POST "))
            && !self.provider.native
            && !self.provider.connected
            && !self.provider.live_https
            && self.consumer.id == MISSION_FRAME_IO_REVIEW_CONSUMER_ID
            && self.consumer.version == FRAME_IO_REVIEW_RESULT_PLUGIN_VERSION
            && self.consumer.implementation == MISSION_FRAME_IO_REVIEW_CONSUMER_NAME
            && self.consumer.mission_bound
            && self.consumer.project_bound
            && self.consumer.work_product_bound
            && !self.consumer.adopts_work_product
            && !self.consumer.outcome_authority
            && self.scope.secret_reference == "opaque_secret_reference_only"
            && self.scope.digest == "sha256_lower_hex"
            && self.scope.registration == "version_provider_scope_secret_revision_bound"
            && self.reads.method == "GET"
            && !self.reads.arbitrary_path
            && !self.reads.arbitrary_query
            && self.reads.cursor == "opaque_digest_only"
            && self.reads.time_window == "bounded"
            && self.reads.max_pages == FRAME_IO_MAX_PAGES
            && self.reads.page_size == FRAME_IO_PAGE_SIZE
            && self.reads.max_response_bytes == FRAME_IO_MAX_RESPONSE_BYTES
            && !self.evidence.raw_provider_payload
            && !self.evidence.raw_comments
            && !self.evidence.reviewer_pii
            && !self.evidence.media_download
            && self.states == expected_states
            && self.registration.version_bound
            && self.registration.provider_bound
            && self.registration.contract_digest_bound
            && self.registration.scope_digest_bound
            && self.registration.secret_reference_bound
            && self.registration.credential_revision_bound
            && self.registration.reversible
            && self.registration.revocable
            && self.registration.fail_closed_on_drift
            && self.registration.duplicate_proposal_rejected
            && self.authority.read_only
            && !self.authority.external_writes
            && !self.authority.asset_upload
            && !self.authority.asset_replacement
            && !self.authority.comment_mutation
            && !self.authority.approval_mutation
            && !self.authority.review_link_creation
            && !self.authority.media_download
            && !self.authority.signed_url_exposure
            && !self.authority.webhook_registration
            && !self.authority.publication
            && !self.authority.connected
            && !self.authority.native_provider
            && !self.authority.receipt
            && !self.authority.verification
            && !self.authority.outcome
            && !self.authority.work_product_adoption
            && !self.honesty.fixture_native
            && !self.honesty.recording_native
            && !self.honesty.loopback_native
            && !self.honesty.blocked_env_native
            && !self.honesty.fixture_connected
            && !self.honesty.recording_connected
            && !self.honesty.loopback_connected
            && !self.honesty.blocked_env_connected
            && !self.honesty.absence_of_comments_is_approval
            && !self.honesty.absence_of_approval_is_quality
            && self.honesty.blocked_environment_status == FRAME_IO_BLOCKED_ENV;
        if valid {
            Ok(())
        } else {
            Err(FrameIoContractError::Invalid(
                "checked-in values do not match the Layer-1 implementation boundary".to_owned(),
            ))
        }
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_in_contract_is_valid_and_non_native() {
        let contract = FrameIoContract::baseline().expect("contract baseline");
        assert_eq!(contract.digest(), contract_digest());
        assert!(!contract.provider.native);
        assert!(!contract.provider.connected);
        assert!(!contract.service.writes);
        assert_eq!(FRAME_IO_BLOCKED_ENV, "BLOCKED_ENV");
    }
}
