//! Standalone Layer-1 Segment event-quality and delivery-evidence plugin.
//!
//! This crate is intentionally outside the root Cargo workspace. It exposes
//! only bounded, read-only Protocols/tracking-plan/schema/violation/delivery
//! evidence. It does not send or replay events, mutate a tracking plan or
//! destination, retain raw payloads or PII, resolve native credentials, mint a
//! kernel receipt, or adopt a Work Product/Outcome.

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
    clippy::struct_field_names,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    AdoptionAction, CanonicalAdoptionProposal, ConsumerError, MissionConsumerRegistration,
    MissionSegmentOutcome, MissionSegmentOutcomeConsumer,
};
pub use model::{
    ConnectionStatus, ConsumerId, DeliveryEvidence, DeliveryHealth, DestinationEvidence,
    DestinationId, Digest, EventSchemaEvidence, EventSpecId, EvidenceBounds, EvidenceStatus,
    EvidenceWindow, FreshnessState, MissionId, ModelError, OpaqueCursor, Permission,
    PermissionSnapshot, PluginVersion, ProjectId, ProviderId, RegistrationState, RetentionState,
    Revision, SecretKind, SecretReference, SegmentRegistration, SegmentScope, ServiceId,
    SourceEvidence, SourceId, TrackingPlanEvidence, TrackingPlanId, ViolationCategory,
    ViolationEvidence, WorkProductId, WorkspaceId,
};
pub use provider::{
    BlockedEnvSegmentTransport, FixtureSegmentTransport, LoopbackSegmentTransport,
    OfficialSegmentApiTransport, PageStatus, ProviderDefinitionError, ProviderProvenance,
    RecordingSegmentTransport, SegmentPageStatus, SegmentProvider, SegmentProviderDefinition,
    SegmentReadOperation, SegmentReadPage, SegmentReadRequest, SegmentReadTransport, SegmentRecord,
    TransportError,
};
pub use service::{
    SegmentEventEvidence, SegmentEventEvidenceProposal, SegmentEventEvidenceService,
    SegmentEventEvidenceServiceDefinition, SegmentEvidenceDigests, SegmentEvidenceReceipt,
    SegmentProviderAccess, SegmentReadEvidence, ServiceError, VerifiedSegmentEvidence,
};

pub const SEGMENT_EVENT_EVIDENCE_SCHEMA_VERSION: &str =
    "hartevo.segment-event-evidence-contract/v1";
pub const SEGMENT_EVENT_EVIDENCE_CONTRACT_VERSION: &str = "segment-event-evidence-e1/v1";
pub const SEGMENT_EVENT_EVIDENCE_SERVICE_ID: &str = "segment.event-evidence.read";
pub const SEGMENT_EVENT_EVIDENCE_PROVIDER_ID: &str = "segment.protocols.read";
pub const SEGMENT_EVENT_EVIDENCE_CONSUMER_ID: &str = "mission.segment-event-evidence.consumer";
pub const SEGMENT_EVENT_EVIDENCE_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const SEGMENT_EVENT_EVIDENCE_EVIDENCE_LEVEL: &str = "E1";

pub const SEGMENT_EVENT_EVIDENCE_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/segment-event-evidence/segment-event-evidence.v1.json"
);

#[must_use]
pub fn segment_event_evidence_contract_digest() -> Digest {
    Digest::from_text(SEGMENT_EVENT_EVIDENCE_CONTRACT_JSON)
}

/// Layer 1's authority is observational only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    #[must_use]
    pub const fn connected() -> bool {
        false
    }

    #[must_use]
    pub const fn native_provider() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn adopted_outcome() -> bool {
        false
    }

    #[must_use]
    pub const fn truth_authority() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use serde::Deserialize;

    use super::{
        Layer1Authority, SEGMENT_EVENT_EVIDENCE_BLOCKED_ENV, SEGMENT_EVENT_EVIDENCE_CONSUMER_ID,
        SEGMENT_EVENT_EVIDENCE_CONTRACT_JSON, SEGMENT_EVENT_EVIDENCE_CONTRACT_VERSION,
        SEGMENT_EVENT_EVIDENCE_EVIDENCE_LEVEL, SEGMENT_EVENT_EVIDENCE_PROVIDER_ID,
        SEGMENT_EVENT_EVIDENCE_SCHEMA_VERSION, SEGMENT_EVENT_EVIDENCE_SERVICE_ID,
        segment_event_evidence_contract_digest,
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
        native_claims: NativeClaims,
        non_goals: Vec<String>,
        layer2_gaps: Vec<String>,
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
        native: bool,
        writes: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConsumerDocument {
        id: String,
        mutates_external_state: bool,
        adopts_outcome: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NativeClaims {
        connected: bool,
        native_provider: bool,
        durable_receipt: bool,
        adopted_outcome: bool,
        blocked_environment_is_native: bool,
    }

    #[test]
    fn contract_document_is_versioned_bounded_and_honest() {
        let document =
            serde_json::from_str::<ContractDocument>(SEGMENT_EVENT_EVIDENCE_CONTRACT_JSON)
                .expect("Segment contract JSON");
        assert_eq!(
            document.schema_version,
            SEGMENT_EVENT_EVIDENCE_SCHEMA_VERSION
        );
        assert_eq!(
            document.contract_version,
            SEGMENT_EVENT_EVIDENCE_CONTRACT_VERSION
        );
        assert_eq!(
            document.evidence_level,
            SEGMENT_EVENT_EVIDENCE_EVIDENCE_LEVEL
        );
        assert_eq!(document.layer, 1);
        assert_eq!(document.service.id, SEGMENT_EVENT_EVIDENCE_SERVICE_ID);
        assert!(document.service.read_only);
        assert!(!document.service.live_execution);
        assert_eq!(document.provider.id, SEGMENT_EVENT_EVIDENCE_PROVIDER_ID);
        assert!(!document.provider.native);
        assert!(!document.provider.writes);
        assert_eq!(document.consumer.id, SEGMENT_EVENT_EVIDENCE_CONSUMER_ID);
        assert!(!document.consumer.mutates_external_state);
        assert!(!document.consumer.adopts_outcome);
        assert!(!document.native_claims.connected);
        assert!(!document.native_claims.native_provider);
        assert!(!document.native_claims.durable_receipt);
        assert!(!document.native_claims.adopted_outcome);
        assert!(!document.native_claims.blocked_environment_is_native);
        assert!(!document.non_goals.is_empty());
        assert!(!document.layer2_gaps.is_empty());
        assert_eq!(SEGMENT_EVENT_EVIDENCE_BLOCKED_ENV, "BLOCKED_ENV");
        assert_eq!(segment_event_evidence_contract_digest().as_str().len(), 64);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::truth_authority());
    }
}
