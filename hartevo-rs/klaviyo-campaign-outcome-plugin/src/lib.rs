//! Layer-1 governed Klaviyo campaign and flow outcome evidence.
//!
//! This crate is intentionally a standalone nested workspace.  It exposes a
//! typed service/provider/consumer seam for bounded recorded evidence only.
//! It does not resolve credentials, call Klaviyo, send or edit campaigns,
//! ingest profiles or events, issue a native receipt, or adopt a Hartevo
//! Outcome.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::items_after_statements,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::return_self_not_must_use,
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

#[cfg(test)]
mod adversarial_tests;

pub use consumer::{
    ConsumerError, ConsumerRegistration, MissionKlaviyoCampaignConsumer,
    MissionKlaviyoCampaignOutcome, MissionOutcomeState,
};
pub use model::{
    AccountId, AdoptionAvailability, AggregateValue, CampaignFlowMetadata, CampaignId,
    CampaignStatus, ConsumerId, CostEvidence, CurrencyCode, DeliveryState, Digest, ErrorSeverity,
    EvidenceDigests, FlowId, KlaviyoPermission, KlaviyoRegistration, KlaviyoScope, MessageChannel,
    MetricId, MetricSelection, MissionId, ModelError, OpaquePageCursor, PermissionFence,
    PermissionSnapshot, ProjectId, ProviderErrorEvidence, ProviderErrorKind, RedactionEvidence,
    RegistrationRevocation, ReportKind, ReportPage, ReportRow, ReportWindow, ResourceId,
    ResourceKind, Revision, ScopeRevisions, SecretKind, SecretReference, SeriesInterval, ServiceId,
    Statistic, Timeframe, VariationSelector, WorkProductId,
};
pub use provider::{
    BlockedEnvTransport, CampaignMetadataRequest, CampaignMetadataResponse, FakeKlaviyoTransport,
    KlaviyoProvider, KlaviyoProviderDefinition, KlaviyoProviderPort, KlaviyoTransport,
    LoopbackKlaviyoTransport, LoopbackTransport, ProviderDefinitionError, ProviderProvenance,
    RecordingKlaviyoTransport, ReportRequest, TransportError,
};
pub use service::{
    AuthorityClassification, KlaviyoCampaignOutcomeEvidence, KlaviyoCampaignOutcomeProposal,
    KlaviyoCampaignOutcomeService, KlaviyoOutcomeRequest, KlaviyoServiceDefinition,
    KlaviyoServiceError, OutcomeProjection, ReportWindowReceipt, RetryEvidence, RetryPolicy,
    RetryPolicyError,
};

pub const KLAVIYO_CAMPAIGN_OUTCOME_SCHEMA_VERSION: &str = "hartevo.klaviyo-campaign-outcome/v1";
pub const KLAVIYO_CAMPAIGN_OUTCOME_CONTRACT_VERSION: &str = "klaviyo-campaign-outcome-e1/v1";
pub const KLAVIYO_CAMPAIGN_OUTCOME_CONTRACT_PATH: &str =
    "contracts/plugins/klaviyo-campaign-outcome/klaviyo-campaign-outcome.v1.json";
pub const KLAVIYO_CAMPAIGN_OUTCOME_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/klaviyo-campaign-outcome/klaviyo-campaign-outcome.v1.json"
);
pub const KLAVIYO_CAMPAIGN_OUTCOME_SERVICE_ID: &str = "klaviyo.campaign-outcome.read";
pub const KLAVIYO_CAMPAIGN_OUTCOME_PROVIDER_ID: &str = "klaviyo.campaign-outcome";
pub const KLAVIYO_CAMPAIGN_OUTCOME_CONSUMER_ID: &str = "mission.klaviyo-campaign.consumer";
pub const KLAVIYO_CAMPAIGN_OUTCOME_PROVIDER_IMPLEMENTATION: &str = "KlaviyoProvider";
pub const KLAVIYO_CAMPAIGN_OUTCOME_API_REVISION: &str = "2024-10-15";
pub const KLAVIYO_CAMPAIGN_OUTCOME_EVIDENCE_LEVEL: &str = "E1";
pub const KLAVIYO_CAMPAIGN_OUTCOME_BLOCKED_ENV: &str = "BLOCKED_ENV";

/// Layer-1 authority is intentionally all false: this crate produces a
/// proposal and evidence for a later decision, never external authority.
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

    pub const fn durable_native_receipt() -> bool {
        false
    }

    pub const fn independent_write_readback() -> bool {
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
    use serde_json::Value;

    use super::{
        KLAVIYO_CAMPAIGN_OUTCOME_API_REVISION, KLAVIYO_CAMPAIGN_OUTCOME_BLOCKED_ENV,
        KLAVIYO_CAMPAIGN_OUTCOME_CONSUMER_ID, KLAVIYO_CAMPAIGN_OUTCOME_CONTRACT_JSON,
        KLAVIYO_CAMPAIGN_OUTCOME_CONTRACT_VERSION, KLAVIYO_CAMPAIGN_OUTCOME_PROVIDER_ID,
        KLAVIYO_CAMPAIGN_OUTCOME_SCHEMA_VERSION, KLAVIYO_CAMPAIGN_OUTCOME_SERVICE_ID,
        Layer1Authority,
    };

    #[test]
    fn contract_document_is_versioned_and_layer_one_honest() {
        let document = serde_json::from_str::<Value>(KLAVIYO_CAMPAIGN_OUTCOME_CONTRACT_JSON)
            .expect("Klaviyo contract JSON");
        assert_eq!(
            document["schemaVersion"],
            KLAVIYO_CAMPAIGN_OUTCOME_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            KLAVIYO_CAMPAIGN_OUTCOME_CONTRACT_VERSION
        );
        assert_eq!(document["layer"], 1);
        assert_eq!(document["authority"], "read_only_observational_evidence");
        let service = &document["service"];
        assert_eq!(service["id"], KLAVIYO_CAMPAIGN_OUTCOME_SERVICE_ID);
        assert_eq!(service["version"], "1.0.0");
        assert_eq!(service["access"], "read_only");
        assert_eq!(
            service["contractDigest"],
            "sha256_of_this_contract_at_runtime"
        );
        assert_eq!(service["liveExecution"], false);
        assert_eq!(service["emitsOutcome"], false);
        let provider = &document["provider"];
        assert_eq!(provider["id"], KLAVIYO_CAMPAIGN_OUTCOME_PROVIDER_ID);
        assert_eq!(provider["serviceId"], KLAVIYO_CAMPAIGN_OUTCOME_SERVICE_ID);
        assert_eq!(provider["version"], "1.0.0");
        assert_eq!(provider["implementation"], "KlaviyoProvider");
        assert_eq!(
            provider["apiRevision"],
            KLAVIYO_CAMPAIGN_OUTCOME_API_REVISION
        );
        assert_eq!(provider["native"], false);
        assert_eq!(provider["firstParty"], false);
        let consumer = &document["consumer"];
        assert_eq!(consumer["id"], KLAVIYO_CAMPAIGN_OUTCOME_CONSUMER_ID);
        assert_eq!(consumer["serviceId"], KLAVIYO_CAMPAIGN_OUTCOME_SERVICE_ID);
        assert_eq!(consumer["adoptsOutcome"], false);
        assert_eq!(consumer["truthAuthority"], false);
        let honesty = &document["honesty"];
        assert_eq!(honesty["readOnly"], true);
        assert_eq!(honesty["proposalOnly"], true);
        for field in [
            "fixtureNative",
            "recordingNative",
            "fakeNative",
            "loopbackNative",
            "blockedEnvNative",
            "fixtureConnected",
            "recordingConnected",
            "fakeConnected",
            "loopbackConnected",
            "blockedEnvConnected",
            "fixtureFirstParty",
            "recordingFirstParty",
            "fakeFirstParty",
            "loopbackFirstParty",
            "blockedEnvFirstParty",
            "durableNativeReceipt",
            "independentWriteReadback",
            "adoptsOutcome",
            "truthAuthority",
        ] {
            assert_eq!(honesty[field], false, "{field}");
        }
        assert_eq!(honesty["nativeHttpsLayer"], "layer_2_gap");
        assert_eq!(KLAVIYO_CAMPAIGN_OUTCOME_API_REVISION, "2024-10-15");
        assert_eq!(KLAVIYO_CAMPAIGN_OUTCOME_BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_native_receipt());
        assert!(!Layer1Authority::independent_write_readback());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::truth_authority());
    }
}
