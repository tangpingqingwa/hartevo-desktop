//! Standalone Layer-1 Miro collaborative decision-result evidence plugin.
//!
//! The root is intentionally contract-first and recording-only.  It exposes a
//! typed provider seam for bounded board/item evidence, a service that issues
//! redacted proposals and ephemeral recordings, and a Mission consumer that
//! keeps the result below Hartevo kernel authority.  It never resolves an
//! OAuth token, reports Connected/native/first-party status, mutates Miro, or
//! adopts a Work Product.

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

#[cfg(test)]
mod adversarial_tests;

pub use consumer::{
    ConsumerError, ConsumerRegistration, MissionMiroDecision, MissionMiroDecisionConsumer,
    MissionMiroDecisionState,
};
pub use model::{
    AdoptionAvailability, BoardId, ConsumerId, DecisionBounds, DecisionResultAuthority, Digest,
    EvidenceDigests, ItemId, Label, MiroAuthKind, MiroBoardItem, MiroBoardItemKind,
    MiroBoardMetadata, MiroDecisionRegistration, MiroDecisionRegistration as Registration,
    MiroDecisionScope, MiroDecisionScopeSpec, MissionId, ModelError, OpaqueCursor, PermissionFence,
    ProjectId, ProviderErrorEvidence, ProviderErrorKind, ProviderId, RedactedExternalLink,
    RegistrationRevocation, RegistrationState, Revision, SecretReference, ServiceId, TeamId,
    UpdateTimestamp, WorkProductId,
};
pub use provider::{
    BlockedEnvMiroBoardTransport, BlockedEnvTransport, FakeMiroBoardTransport,
    LoopbackMiroBoardTransport, MiroBoardPage, MiroBoardProvider, MiroBoardProviderAdapter,
    MiroBoardProviderClient, MiroBoardProviderDefinition, MiroBoardReadRequest, MiroBoardTransport,
    ProviderDefinitionError, ProviderProvenance, RecordingMiroBoardTransport, TransportError,
};
pub use service::{
    MiroDecisionEvidence, MiroDecisionOutcomeService, MiroDecisionProjection,
    MiroDecisionProposalRequest, MiroDecisionResultProposal, MiroDecisionResultRecording,
    MiroDecisionResultService, MiroDecisionResultServiceDefinition, MiroDecisionResultServiceError,
    MiroDecisionResultStatus, PartialReason, RetryEvidence, RetryPolicy, RetryPolicyError,
};

pub const MIRO_DECISION_RESULT_SCHEMA_VERSION: &str = "hartevo-miro-decision-result-contract/v1";
pub const MIRO_DECISION_RESULT_CONTRACT_VERSION: &str = "miro-decision-result-e1/v1";
pub const MIRO_DECISION_RESULT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/miro-decision-result/miro-decision-result.v1.json");
pub const MIRO_DECISION_RESULT_SERVICE_ID: &str = "miro.decision-result";
pub const MIRO_DECISION_RESULT_PROVIDER_ID: &str = "miro.board.items";
pub const MIRO_DECISION_RESULT_CONSUMER_ID: &str = "mission.miro-decision-result";
pub const MIRO_DECISION_RESULT_EVIDENCE_LEVEL: &str = "E1";
pub const MIRO_DECISION_RESULT_API_VERSION: &str = "v2";
pub const MIRO_DECISION_RESULT_BLOCKED_ENV: &str = "BLOCKED_ENV";

/// Layer 1's authority boundary.  Every method is a constant false so a
/// fixture, recording, loopback, or blocked environment cannot be promoted
/// into native or Connected authority by accident.
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

    pub const fn durable_receipt() -> bool {
        false
    }

    pub const fn independent_read_back() -> bool {
        false
    }

    pub const fn verified_adoption() -> bool {
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
        Layer1Authority, MIRO_DECISION_RESULT_API_VERSION, MIRO_DECISION_RESULT_BLOCKED_ENV,
        MIRO_DECISION_RESULT_CONSUMER_ID, MIRO_DECISION_RESULT_CONTRACT_JSON,
        MIRO_DECISION_RESULT_CONTRACT_VERSION, MIRO_DECISION_RESULT_EVIDENCE_LEVEL,
        MIRO_DECISION_RESULT_PROVIDER_ID, MIRO_DECISION_RESULT_SCHEMA_VERSION,
        MIRO_DECISION_RESULT_SERVICE_ID,
    };

    #[test]
    fn contract_document_keeps_layer_one_honest_and_bounded() {
        let document = serde_json::from_str::<Value>(MIRO_DECISION_RESULT_CONTRACT_JSON)
            .expect("Miro decision-result contract JSON");
        assert_eq!(
            document["schemaVersion"],
            MIRO_DECISION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            MIRO_DECISION_RESULT_CONTRACT_VERSION
        );
        assert_eq!(
            document["evidenceLevel"],
            MIRO_DECISION_RESULT_EVIDENCE_LEVEL
        );
        assert_eq!(document["layer"], 1);
        assert_eq!(document["api"]["version"], MIRO_DECISION_RESULT_API_VERSION);
        assert_eq!(document["service"]["id"], MIRO_DECISION_RESULT_SERVICE_ID);
        assert_eq!(document["provider"]["id"], MIRO_DECISION_RESULT_PROVIDER_ID);
        assert_eq!(document["consumer"]["id"], MIRO_DECISION_RESULT_CONSUMER_ID);
        assert_eq!(document["service"]["readOnly"], true);
        assert_eq!(document["service"]["liveExecution"], false);
        assert_eq!(document["service"]["externalWrites"], false);
        assert_eq!(document["service"]["sharingAuthority"], false);
        assert_eq!(document["provider"]["native"], false);
        assert_eq!(document["provider"]["firstParty"], false);
        assert_eq!(document["provider"]["connected"], false);
        assert_eq!(
            document["nativeClaims"]["blockedEnvironmentIsNative"],
            false
        );
        assert_eq!(document["nativeClaims"]["fixtureIsNative"], false);
        assert_eq!(document["nativeClaims"]["recordingIsNative"], false);
        assert_eq!(document["nativeClaims"]["loopbackIsNative"], false);
        assert_eq!(MIRO_DECISION_RESULT_BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::independent_read_back());
        assert!(!Layer1Authority::verified_adoption());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::truth_authority());
    }
}
