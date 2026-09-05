//! Layer-1 governed Aha! Discovery study/interview evidence result plugin.
//!
//! The crate exposes bounded, redacted metadata projections and deterministic
//! Mission proposals. It deliberately has no native credential resolver,
//! HTTPS client, transcript/media store, participant identity path, mutation
//! API, durable provider receipt, independent native read-back, or adoption
//! authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

mod consumer;
mod model;
mod provider;
mod service;

#[cfg(test)]
mod adversarial_tests;

pub use consumer::{
    MissionAhaDiscoveryConsumer, MissionAhaDiscoveryResult, ProposalDisposition,
    RecordedAhaDiscoveryResult,
};
pub use model::{
    AccountId, AhaDiscoveryPage, AhaDiscoveryProjection, AhaDiscoveryRequest,
    AhaDiscoveryResultError, AhaDiscoveryScope, Digest, DiscoveryResource, EvidenceDigests,
    EvidenceFence, HighlightId, HighlightProjection, InsightState, InterviewId,
    InterviewProjection, LinkedRecordId, LinkedRecordKind, LinkedRecordProjection, MissionId,
    PageCursor, PermissionSnapshot, ProjectId, QuestionId, QuestionProjection, RedactedText,
    RedactionSummary, ResponseId, ResponseProjection, Revision, StudyId, StudyProjection,
    WorkProductId, WorkspaceId,
};
pub use provider::{
    AhaDiscoveryProvider, AhaDiscoveryProviderDefinition, AhaDiscoveryProviderError,
    AhaDiscoveryProviderResponse, AhaDiscoveryTransport, AhaDiscoveryTransportError,
    BlockedEnvTransport, FixtureAhaDiscoveryTransport, LoopbackAhaDiscoveryTransport,
    RecordingAhaDiscoveryTransport, TransportProvenance,
};
pub use service::{
    AhaDiscoveryRegistration, AhaDiscoveryRegistrationProjection, AhaDiscoveryResultProposal,
    AhaDiscoveryResultService, AhaDiscoveryResultServiceError, AhaDiscoveryServiceDefinition,
    RegistrationStatus, RegistrationTransitionEvidence, SecretReference,
};

pub const AHA_DISCOVERY_RESULT_SCHEMA_VERSION: &str = "hartevo-aha-discovery-result-contract/v1";
pub const AHA_DISCOVERY_RESULT_CONTRACT_VERSION: &str = "aha-discovery-result-e1/v1";
pub const AHA_DISCOVERY_RESULT_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const AHA_DISCOVERY_RESULT_SERVICE_ID: &str = "aha.discovery.result";
pub const AHA_DISCOVERY_RESULT_PROVIDER_ID: &str = "aha.discovery.study-interview-evidence";
pub const AHA_DISCOVERY_RESULT_CONSUMER_ID: &str = "mission.aha.discovery.result.consumer";
pub const AHA_DISCOVERY_RESULT_EVIDENCE_LEVEL: &str = "E1";
pub const AHA_DISCOVERY_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AHA_DISCOVERY_PROVIDER_REVISION: u64 = 1;
pub const AHA_DISCOVERY_PROVIDER_RELEASE: &str = "aha-discovery-layer1/v1";
pub const AHA_DISCOVERY_MAX_PAGE_SIZE: u16 = 50;
pub const AHA_DISCOVERY_MAX_CURSOR_BYTES: usize = 128;
pub const AHA_DISCOVERY_MAX_REDACTED_TEXT_BYTES: usize = 256;
pub const AHA_DISCOVERY_MAX_BOUNDED_COUNT: u16 = 50;
pub const AHA_DISCOVERY_RESULT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aha-discovery-result/aha-discovery-result.v1.json");

pub(crate) fn contract_digest() -> Digest {
    Digest::from_text(AHA_DISCOVERY_RESULT_CONTRACT_JSON)
}

/// Layer 1 exposes evidence for a decision and never a connected provider or adoption authority.
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

    pub const fn first_party() -> bool {
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
    use serde_json::Value;

    use super::{
        AHA_DISCOVERY_BLOCKED_ENV, AHA_DISCOVERY_MAX_BOUNDED_COUNT, AHA_DISCOVERY_MAX_CURSOR_BYTES,
        AHA_DISCOVERY_MAX_PAGE_SIZE, AHA_DISCOVERY_MAX_REDACTED_TEXT_BYTES,
        AHA_DISCOVERY_RESULT_CONSUMER_ID, AHA_DISCOVERY_RESULT_CONTRACT_JSON,
        AHA_DISCOVERY_RESULT_CONTRACT_VERSION, AHA_DISCOVERY_RESULT_EVIDENCE_LEVEL,
        AHA_DISCOVERY_RESULT_PROVIDER_ID, AHA_DISCOVERY_RESULT_SCHEMA_VERSION,
        AHA_DISCOVERY_RESULT_SERVICE_ID, Layer1ResultAuthority,
    };

    #[test]
    fn versioned_contract_matches_the_typed_negative_boundary() {
        let document = serde_json::from_str::<Value>(AHA_DISCOVERY_RESULT_CONTRACT_JSON)
            .expect("contract JSON");
        assert_eq!(
            document["schemaVersion"],
            AHA_DISCOVERY_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            AHA_DISCOVERY_RESULT_CONTRACT_VERSION
        );
        assert_eq!(
            document["evidenceLevel"],
            AHA_DISCOVERY_RESULT_EVIDENCE_LEVEL
        );
        assert_eq!(document["layer"], 1);
        assert_eq!(document["service"]["id"], AHA_DISCOVERY_RESULT_SERVICE_ID);
        assert!(
            document["service"]["readOnly"]
                .as_bool()
                .expect("read-only flag")
        );
        assert!(
            !document["service"]["liveExecution"]
                .as_bool()
                .expect("live execution flag")
        );
        assert!(
            !document["service"]["mutationAuthority"]
                .as_bool()
                .expect("mutation authority flag")
        );
        assert_eq!(document["provider"]["id"], AHA_DISCOVERY_RESULT_PROVIDER_ID);
        assert_eq!(document["provider"]["revision"], 1);
        assert!(
            !document["provider"]["native"]
                .as_bool()
                .expect("native flag")
        );
        assert!(
            !document["provider"]["httpsTransport"]
                .as_bool()
                .expect("HTTPS flag")
        );
        assert!(
            !document["provider"]["readback"]
                .as_bool()
                .expect("read-back flag")
        );
        assert!(
            !document["provider"]["firstParty"]
                .as_bool()
                .expect("first-party flag")
        );
        assert_eq!(
            document["limits"]["maxPageSize"],
            AHA_DISCOVERY_MAX_PAGE_SIZE
        );
        assert_eq!(
            document["limits"]["maxRedactedTextBytes"],
            AHA_DISCOVERY_MAX_REDACTED_TEXT_BYTES
        );
        assert_eq!(
            document["limits"]["maxOpaqueCursorBytes"],
            AHA_DISCOVERY_MAX_CURSOR_BYTES
        );
        assert_eq!(
            document["limits"]["maxBoundedCount"],
            AHA_DISCOVERY_MAX_BOUNDED_COUNT
        );
        assert!(
            document["provider"]["transports"]
                .as_array()
                .expect("transport list")
                .iter()
                .all(|transport| {
                    !transport["connected"].as_bool().expect("connected flag")
                        && !transport["native"].as_bool().expect("native flag")
                        && !transport["firstParty"].as_bool().expect("first-party flag")
                }),
        );
        assert_eq!(AHA_DISCOVERY_BLOCKED_ENV, "BLOCKED_ENV");
        assert!(
            !document["nativeClaims"]["blockedEnvironmentIsNative"]
                .as_bool()
                .expect("blocked environment flag")
        );
        assert_eq!(
            AHA_DISCOVERY_RESULT_CONSUMER_ID,
            "mission.aha.discovery.result.consumer"
        );
        assert!(!Layer1ResultAuthority::connected());
        assert!(!Layer1ResultAuthority::native_provider());
        assert!(!Layer1ResultAuthority::https_transport());
        assert!(!Layer1ResultAuthority::first_party());
        assert!(!Layer1ResultAuthority::readback());
        assert!(!Layer1ResultAuthority::durable_receipt());
        assert!(!Layer1ResultAuthority::adopted_work_product());
        assert!(!Layer1ResultAuthority::adopted_outcome());
        assert!(!Layer1ResultAuthority::truth_authority());
    }
}
