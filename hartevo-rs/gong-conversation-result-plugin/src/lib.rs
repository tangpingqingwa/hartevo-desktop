//! Layer-1 governed Gong conversation-intelligence result plugin.
//!
//! This standalone crate exposes a typed, read-only evidence seam for a
//! consented Mission. It retains only normalized interaction signals and
//! redacted receipts. It never captures, uploads, downloads, mutates, or
//! exposes Gong recordings, transcripts, media, participant PII, CRM objects,
//! scorecards, comments, or messages; it also never claims Connected/native,
//! Effect, Receipt, Verification, Outcome, or kernel authority.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(clippy::module_name_repetitions)]

use serde::{Deserialize, Serialize};

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    ConsumerError, MissionConversationState, MissionGongConversationConsumer,
    MissionGongConversationResult,
};
pub use model::*;
pub use provider::{
    BlockedEnvTransport, FakeGongTransport, GongProvider, GongProviderDefinition,
    GongProviderError, GongTransport, GongTransportError, LoopbackGongTransport,
    RecordingGongTransport, TransportProvenance,
};
pub use service::{
    GongConversationResultProjection, GongConversationResultProposal,
    GongConversationResultService, GongIssueCode, GongProviderIssue, GongRegistration,
    GongResultEvidence, GongResultProjection, GongServiceError, PartialReason, RegistrationReceipt,
    RegistrationRevocation, RegistrationStatus,
};

pub const GONG_CONVERSATION_RESULT_SCHEMA_VERSION: &str =
    "hartevo.gong-conversation-result-contract/v1";
pub const GONG_CONVERSATION_RESULT_CONTRACT_VERSION: &str = "gong-conversation-result/v1";
pub const GONG_CONVERSATION_RESULT_PLUGIN_ID: &str = "gong-conversation-result";
pub const GONG_CONVERSATION_RESULT_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const GONG_CONVERSATION_RESULT_SERVICE_ID: &str = "gong.conversation.result";
pub const GONG_CONVERSATION_RESULT_PROVIDER_ID: &str = "gong.public-api.read";
pub const MISSION_GONG_CONVERSATION_RESULT_CONSUMER_ID: &str = "mission.gong-conversation-result";
pub const GONG_API_VERSION: &str = "v2";
pub const GONG_PROVIDER_REVISION: &str = "gong-api-v2-r1";
pub const GONG_MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const GONG_MAX_PAGES: u8 = 4;
pub const GONG_PAGE_SIZE: u16 = 50;
pub const GONG_MAX_DATE_WINDOW_DAYS: i64 = 31;
pub const GONG_REQUESTS_PER_SECOND: u8 = 3;
pub const GONG_DAILY_REQUEST_LIMIT: u32 = 10_000;
pub const GONG_MAX_REQUESTS_PER_SECOND: u8 = GONG_REQUESTS_PER_SECOND;
pub const GONG_MAX_DAILY_REQUESTS: u32 = GONG_DAILY_REQUEST_LIMIT;
pub const GONG_MAX_USERS: usize = 128;
pub const GONG_MAX_CONTEXTS: usize = 64;
pub const GONG_MAX_SCORECARDS: usize = 64;
pub const GONG_MAX_TRACKERS: usize = 128;
pub const GONG_MAX_TOPICS: usize = 128;
pub const GONG_MAX_ACTION_ITEMS: usize = 128;

pub const GONG_CONVERSATION_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/gong-conversation-result/gong-conversation-result.v1.json"
);

/// SHA-256 of the checked-in JSON contract. The digest is used by every
/// registration and proposal fence; it is not a host receipt authority.
#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(GONG_CONVERSATION_RESULT_CONTRACT_JSON.as_bytes())
}

#[must_use]
pub const fn plugin_version() -> PluginVersion {
    PluginVersion::V1
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GongConversationResultContract {
    pub schema_version: String,
    pub contract_version: String,
    pub layer: u8,
    pub plugin_id: String,
    pub version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub api_version: String,
    pub api_origin: String,
    pub allowlisted_reads: Vec<String>,
    pub scope_fence: Vec<String>,
    pub transport_provenance: Vec<String>,
    pub projection_states: Vec<String>,
    pub bounds: GongBoundsContract,
    pub receipts: GongReceiptsContract,
    pub authority: GongAuthorityContract,
    pub registration: GongRegistrationContract,
    pub negative_capabilities: Vec<String>,
    pub native_gap: GongNativeGapContract,
    pub honest_native_gap: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GongBoundsContract {
    pub max_response_bytes: usize,
    pub max_pages: u8,
    pub page_size: u16,
    pub max_date_window_days: i64,
    pub requests_per_second: u8,
    pub daily_request_limit: u32,
    pub max_users: usize,
    pub max_contexts: usize,
    pub max_scorecards: usize,
    pub max_trackers: usize,
    pub max_topics: usize,
    pub max_action_items: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GongReceiptsContract {
    pub request_digest: bool,
    pub allowlisted_path: bool,
    pub response_status: bool,
    pub response_size: bool,
    pub response_digest: bool,
    pub provider_revision: bool,
    pub raw_provider_payload: bool,
    pub transcript: bool,
    pub audio: bool,
    pub media_urls: bool,
    pub participant_pii: bool,
    pub phone_numbers: bool,
    pub comments: bool,
    pub raw_crm_objects: bool,
    pub credential_material: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GongAuthorityContract {
    pub read_only: bool,
    pub external_writes: bool,
    pub call_upload: bool,
    pub call_update: bool,
    pub call_delete: bool,
    pub recording_download: bool,
    pub raw_transcript: bool,
    pub raw_audio: bool,
    pub raw_media: bool,
    pub crm_write: bool,
    pub scorecard_mutation: bool,
    pub comment_mutation: bool,
    pub messaging: bool,
    pub generic_crm_registry: bool,
    pub connected: bool,
    pub native: bool,
    pub effect: bool,
    pub receipt_authority: bool,
    pub verification: bool,
    pub outcome: bool,
    pub kernel_authority: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GongRegistrationContract {
    pub bound_fields: Vec<String>,
    pub reversible: bool,
    pub revocable: bool,
    pub fail_closed_on_drift: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GongNativeGapContract {
    pub status: String,
    pub deferred_to: String,
    pub fail_closed_cases: Vec<String>,
}

impl GongConversationResultContract {
    pub fn baseline() -> Result<Self, GongServiceError> {
        let contract = serde_json::from_str::<Self>(GONG_CONVERSATION_RESULT_CONTRACT_JSON)
            .map_err(|error| GongServiceError::Contract(error.to_string()))?;
        contract.validate()?;
        Ok(contract)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<(), GongServiceError> {
        let expected_reads = vec![
            "call_metadata",
            "interaction_metrics",
            "topics_trackers",
            "action_item_counts",
            "scorecard_status",
            "external_crm_context_identifiers",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_projections = vec![
            "analyzed",
            "processing",
            "partial",
            "consent_blocked",
            "retention_gap",
            "access_lost",
            "provider_unknown",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_transports = vec!["recording", "fixture", "loopback", "BLOCKED_ENV"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if self.schema_version != GONG_CONVERSATION_RESULT_SCHEMA_VERSION
            || self.contract_version != GONG_CONVERSATION_RESULT_CONTRACT_VERSION
            || self.layer != 1
            || self.plugin_id != GONG_CONVERSATION_RESULT_PLUGIN_ID
            || self.version != GONG_CONVERSATION_RESULT_PLUGIN_VERSION_TEXT
            || self.service_id != GONG_CONVERSATION_RESULT_SERVICE_ID
            || self.provider_id != GONG_CONVERSATION_RESULT_PROVIDER_ID
            || self.consumer_id != MISSION_GONG_CONVERSATION_RESULT_CONSUMER_ID
            || self.api_version != GONG_API_VERSION
            || self.api_origin != "provider-bound"
            || self.allowlisted_reads != expected_reads
            || self.transport_provenance != expected_transports
            || self.projection_states != expected_projections
            || self.bounds.max_response_bytes != GONG_MAX_RESPONSE_BYTES
            || self.bounds.max_pages != GONG_MAX_PAGES
            || self.bounds.page_size != GONG_PAGE_SIZE
            || self.bounds.max_date_window_days != GONG_MAX_DATE_WINDOW_DAYS
            || self.bounds.requests_per_second != GONG_REQUESTS_PER_SECOND
            || self.bounds.daily_request_limit != GONG_DAILY_REQUEST_LIMIT
            || self.bounds.max_users != GONG_MAX_USERS
            || self.bounds.max_contexts != GONG_MAX_CONTEXTS
            || self.bounds.max_scorecards != GONG_MAX_SCORECARDS
            || self.bounds.max_trackers != GONG_MAX_TRACKERS
            || self.bounds.max_topics != GONG_MAX_TOPICS
            || self.bounds.max_action_items != GONG_MAX_ACTION_ITEMS
            || !self.receipts.request_digest
            || !self.receipts.allowlisted_path
            || !self.receipts.response_status
            || !self.receipts.response_size
            || !self.receipts.response_digest
            || !self.receipts.provider_revision
            || self.receipts.raw_provider_payload
            || self.receipts.transcript
            || self.receipts.audio
            || self.receipts.media_urls
            || self.receipts.participant_pii
            || self.receipts.phone_numbers
            || self.receipts.comments
            || self.receipts.raw_crm_objects
            || self.receipts.credential_material
            || !self.authority.read_only
            || self.authority.external_writes
            || self.authority.call_upload
            || self.authority.call_update
            || self.authority.call_delete
            || self.authority.recording_download
            || self.authority.raw_transcript
            || self.authority.raw_audio
            || self.authority.raw_media
            || self.authority.crm_write
            || self.authority.scorecard_mutation
            || self.authority.comment_mutation
            || self.authority.messaging
            || self.authority.generic_crm_registry
            || self.authority.connected
            || self.authority.native
            || self.authority.effect
            || self.authority.receipt_authority
            || self.authority.verification
            || self.authority.outcome
            || self.authority.kernel_authority
            || !self.registration.reversible
            || !self.registration.revocable
            || !self.registration.fail_closed_on_drift
            || self.native_gap.status != "BLOCKED_ENV"
            || !self
                .honest_native_gap
                .contains("Native Gong credential resolution")
            || !self.negative_capabilities.iter().any(|value| {
                value == "absence_of_action_items_or_trackers_is_not_deal_health_or_customer_intent"
            })
        {
            return Err(GongServiceError::Contract(
                "Gong conversation-result contract does not match the Layer-1 baseline".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PluginVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl PluginVersion {
    pub const V1: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GongServiceDefinition {
    pub id: String,
    pub version: PluginVersion,
    pub read_only: bool,
    pub contract_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub authority: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionGongConversationConsumerDefinition {
    pub id: String,
    pub service_id: String,
    pub version: PluginVersion,
    pub kind: String,
    pub binding: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GongConversationResultPluginDefinition {
    pub schema_version: String,
    pub plugin_id: String,
    pub version: PluginVersion,
    pub contract_digest: Digest,
    pub service: GongServiceDefinition,
    pub provider: GongProviderDefinition,
    pub consumer: MissionGongConversationConsumerDefinition,
    pub reversible: bool,
    pub writes: bool,
    pub native: bool,
    pub connected: bool,
    pub generic_crm_registry: bool,
    pub kernel_authority: bool,
}

impl GongConversationResultPluginDefinition {
    pub fn layer1() -> Result<Self, GongServiceError> {
        let digest = contract_digest();
        let provider = GongProviderDefinition::layer1(TransportProvenance::BlockedEnv)?;
        let definition = Self {
            schema_version: GONG_CONVERSATION_RESULT_SCHEMA_VERSION.to_owned(),
            plugin_id: GONG_CONVERSATION_RESULT_PLUGIN_ID.to_owned(),
            version: plugin_version(),
            contract_digest: digest.clone(),
            service: GongServiceDefinition {
                id: GONG_CONVERSATION_RESULT_SERVICE_ID.to_owned(),
                version: plugin_version(),
                read_only: true,
                contract_digest: digest,
                connected: false,
                native: false,
                authority: "bounded_observational_conversation_evidence".to_owned(),
            },
            provider,
            consumer: MissionGongConversationConsumerDefinition {
                id: MISSION_GONG_CONVERSATION_RESULT_CONSUMER_ID.to_owned(),
                service_id: GONG_CONVERSATION_RESULT_SERVICE_ID.to_owned(),
                version: plugin_version(),
                kind: "mission_conversation_result_proposal".to_owned(),
                binding: vec![
                    "account_id".to_owned(),
                    "team_id".to_owned(),
                    "user_ids".to_owned(),
                    "call_id_and_revision".to_owned(),
                    "meeting_id".to_owned(),
                    "deal_id".to_owned(),
                    "context_ids".to_owned(),
                    "context_revision".to_owned(),
                    "scorecard_ids".to_owned(),
                    "scorecard_revision".to_owned(),
                    "tracker_ids".to_owned(),
                    "mission_id_and_revision".to_owned(),
                    "project_id_and_revision".to_owned(),
                    "consent_id_and_revision".to_owned(),
                    "registration_digest".to_owned(),
                    "source_result_digest".to_owned(),
                ],
            },
            reversible: true,
            writes: false,
            native: false,
            connected: false,
            generic_crm_registry: false,
            kernel_authority: false,
        };
        definition.validate()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<(), GongServiceError> {
        GongConversationResultContract::baseline()?;
        if self.schema_version != GONG_CONVERSATION_RESULT_SCHEMA_VERSION
            || self.plugin_id != GONG_CONVERSATION_RESULT_PLUGIN_ID
            || self.version != plugin_version()
            || self.contract_digest != contract_digest()
            || self.service.id != GONG_CONVERSATION_RESULT_SERVICE_ID
            || self.service.version != plugin_version()
            || !self.service.read_only
            || self.service.contract_digest != self.contract_digest
            || self.service.connected
            || self.service.native
            || self.provider.provider_id != GONG_CONVERSATION_RESULT_PROVIDER_ID
            || self.provider.service_id != self.service.id
            || self.provider.version != plugin_version()
            || self.provider.native
            || self.provider.connected
            || !self.provider.read_only
            || !self.provider.reversible
            || !self.provider.revocable
            || self.consumer.id != MISSION_GONG_CONVERSATION_RESULT_CONSUMER_ID
            || self.consumer.service_id != self.service.id
            || self.consumer.version != plugin_version()
            || !self.reversible
            || self.writes
            || self.native
            || self.connected
            || self.generic_crm_registry
            || self.kernel_authority
        {
            return Err(GongServiceError::InvalidDefinition);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn bind(
        &self,
        scope: GongConversationScope,
        provider: &GongProviderDefinition,
        secret: &SecretReference,
        registration_revision: u64,
    ) -> Result<RegistrationReceipt, GongServiceError> {
        self.validate()?;
        scope.validate()?;
        provider.validate()?;
        if registration_revision == 0 {
            return Err(GongServiceError::RegistrationMismatch);
        }
        RegistrationReceipt::new(self, &scope, provider, secret, registration_revision)
    }
}

pub fn plugin_definition() -> Result<GongConversationResultPluginDefinition, GongServiceError> {
    GongConversationResultPluginDefinition::layer1()
}
