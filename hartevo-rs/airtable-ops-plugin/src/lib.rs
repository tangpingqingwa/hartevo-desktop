//! Layer 1 Airtable structured-record operations capability.
//!
//! The crate is intentionally standalone and is not a member of Hartevo's
//! root workspace.  It owns the contract, typed base/table scope, schema
//! description, Mission consumer, proposal compiler, recording/fake provider,
//! and read-back verification.  It has no live create/update/webhook
//! transport, credential store, or native Connected state.

#![forbid(unsafe_code)]

mod consumer;
mod error;
mod model;
mod provider;
mod service;

pub use consumer::{AirtableMissionConsumer, MissionRecordConsumer};
pub use error::{
    AirtableError, AirtableProviderError, ProviderTrust, ReadbackMismatch, ReadbackMismatchField,
    RetryClassification,
};
pub use model::{
    AirtableBaseId, AirtableCapability, AirtableChangeSignal, AirtableFieldAllowlist,
    AirtableFieldBinding, AirtableFieldDefinition, AirtableFieldId, AirtableFieldType,
    AirtableOffset, AirtableProviderManifest, AirtableProviderProvenance,
    AirtableReadRecordsResult, AirtableReadRecordsResult as ReadRecordsResult, AirtableRecordBatch,
    AirtableRecordId, AirtableRecordPage, AirtableRecordPage as RecordPage, AirtableRecordSnapshot,
    AirtableRecordSnapshot as RecordSnapshot, AirtableSchemaDescription, AirtableScope,
    AirtableTableId, AirtableTableSchema, AirtableViewId, ListRecordsRequest, MissionId,
    MissionOutput, MissionOutputKind, MissionRecordProposalRequest, OutcomeCandidate,
    OutcomeCandidateId, ProjectId, ProposedField, ReadbackReceipt, ReceiptKind, RecordProposal,
    RecordReadback, RecordReceipt, RecordValue, SecretReference, StableRecordField, WorkProduct,
    WorkProductId,
};
pub use provider::{
    AIRTABLE_PAT_ENV, AirtableOpsProvider, AirtableProvider, AirtableProviderOperation,
    BlockedEnvAirtableProvider, FakeAirtableProvider, RecordedProviderRequest,
    RecordingAirtableProvider, native_provider_from_environment,
};
pub use service::AirtableOpsService;

pub const AIRTABLE_SCHEMA_VERSION: &str = "hartevo-airtable-ops-plugin-contract/v1";
pub const AIRTABLE_CONTRACT_VERSION: &str = "EXT-AIRTABLE-01-L1/v1";
pub const AIRTABLE_PLUGIN_ID: &str = "airtable-ops.structured-record";
pub const AIRTABLE_SERVICE_ID: &str = "external.record.operations";
pub const AIRTABLE_MISSION_CONSUMER_ID: &str = "mission.external.record.airtable";
pub const AIRTABLE_PROVIDER_ID: &str = "airtable.web-api.ops";
pub const AIRTABLE_PROVIDER_VERSION: u64 = 1;
pub const AIRTABLE_MAX_PAGE_SIZE: usize = 100;
pub const AIRTABLE_MAX_BATCH_SIZE: usize = 10;
pub const AIRTABLE_API_BASE_URL: &str = "https://api.airtable.com/v0";
pub const AIRTABLE_NATIVE_STATUS: &str = "BLOCKED_ENV";
pub const AIRTABLE_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/airtable-ops/manifest.v1.json");

/// Layer 1 authority is intentionally all false.  Keeping this typed makes it
/// hard for a caller to accidentally equate a fixture with a native provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn external_write() -> bool {
        false
    }

    pub const fn webhook_truth() -> bool {
        false
    }

    pub const fn store() -> bool {
        false
    }

    pub const fn keyring() -> bool {
        false
    }

    pub const fn browser_profile() -> bool {
        false
    }

    pub const fn effect_broker() -> bool {
        false
    }
}

pub fn contract_digest() -> String {
    model::digest_bytes(AIRTABLE_CONTRACT_JSON.as_bytes())
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        AIRTABLE_CONTRACT_JSON, AIRTABLE_CONTRACT_VERSION, AIRTABLE_MISSION_CONSUMER_ID,
        AIRTABLE_PLUGIN_ID, AIRTABLE_PROVIDER_ID, AIRTABLE_PROVIDER_VERSION,
        AIRTABLE_SCHEMA_VERSION, AIRTABLE_SERVICE_ID, Layer1Authority, contract_digest,
    };

    #[test]
    fn embedded_contract_is_the_layer_one_write_fence() {
        let document: Value =
            serde_json::from_str(AIRTABLE_CONTRACT_JSON).expect("valid Airtable contract");
        assert_eq!(
            document["properties"]["schemaVersion"]["const"],
            AIRTABLE_SCHEMA_VERSION
        );
        assert_eq!(
            document["properties"]["contractVersion"]["const"],
            AIRTABLE_CONTRACT_VERSION
        );
        assert_eq!(document["properties"]["layer"]["const"], 1);
        assert_eq!(
            document["properties"]["pluginId"]["const"],
            AIRTABLE_PLUGIN_ID
        );
        assert_eq!(
            document["properties"]["provider"]["properties"]["id"]["const"],
            AIRTABLE_PROVIDER_ID
        );
        assert_eq!(
            document["properties"]["provider"]["properties"]["version"]["const"],
            AIRTABLE_PROVIDER_VERSION
        );
        assert_eq!(
            document["properties"]["service"]["properties"]["id"]["const"],
            AIRTABLE_SERVICE_ID
        );
        assert_eq!(
            document["properties"]["missionConsumer"]["properties"]["id"]["const"],
            AIRTABLE_MISSION_CONSUMER_ID
        );
        assert_eq!(
            document["properties"]["authority"]["properties"]["externalWrite"]["const"],
            false
        );
        assert_eq!(
            document["properties"]["authority"]["properties"]["webhookTruth"]["const"],
            false
        );
        assert_eq!(
            document["properties"]["provider"]["properties"]["batching"]["properties"]["maxRecordsPerRequest"]
                ["const"],
            10
        );
        assert_eq!(
            document["properties"]["provider"]["properties"]["pagination"]["properties"]["maxPageSize"]
                ["const"],
            100
        );
        assert!(!contract_digest().is_empty());
        assert!(!Layer1Authority::external_write());
        assert!(!Layer1Authority::webhook_truth());
        assert!(!Layer1Authority::store());
        assert!(!Layer1Authority::keyring());
        assert!(!Layer1Authority::browser_profile());
        assert!(!Layer1Authority::effect_broker());
    }
}
