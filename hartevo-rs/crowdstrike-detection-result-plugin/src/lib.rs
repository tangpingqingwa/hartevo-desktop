//! Standalone Layer-1 governed CrowdStrike Falcon detection-result boundary.
//!
//! This crate owns typed, bounded QueryDetects/GetDetectSummaries seams,
//! revision-fenced scope, redacted projections, reversible registration,
//! proposal/recording/verification envelopes, and deterministic harness
//! transports. It intentionally does not resolve credentials, perform native
//! HTTPS, mutate Falcon, create a durable provider receipt, or become a
//! Hartevo Truth/Consent/Effect/Receipt/Verification/Outcome authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::collapsible_if,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::result_large_err,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConsumerError, MissionCrowdStrikeDetectionConsumer, MissionCrowdStrikeDetectionConsumerError,
    MissionCrowdStrikeDetectionResult, ProposalDisposition, RecordedCrowdStrikeDetectionResult,
};
pub use model::*;
pub use provider::{
    BlockedEnvCrowdStrikeTransport, BlockedEnvTransport, CROWDSTRIKE_API_REVISION,
    CrowdStrikeDetectionRead, CrowdStrikeDetectionReadRequest, CrowdStrikeFalconProvider,
    CrowdStrikeFalconProviderDefinition, CrowdStrikeFalconTransport, CrowdStrikeProviderError,
    DetectionReadBounds, FalconReadBounds, FalconTransportError, FalconTransportFailure,
    FixtureCrowdStrikeTransport, FixtureTransport, GET_DETECT_SUMMARIES_PATH,
    GetDetectSummariesRequest, GetDetectSummariesResponse, LoopbackCrowdStrikeTransport,
    LoopbackTransport, ProviderError, QUERY_DETECTS_PATH, QueryDetectsRequest,
    QueryDetectsResponse, RecordedRequest, RecordingCrowdStrikeTransport, RecordingTransport,
};
pub use service::{
    CrowdStrikeCapabilityDescription, CrowdStrikeDetectionProposal,
    CrowdStrikeDetectionRegistration, CrowdStrikeDetectionResultService,
    CrowdStrikeDetectionVerificationReport, CrowdStrikeRegistration, CrowdStrikeServiceError,
    RegistrationStatus, RegistrationTransitionReceipt, ServiceError, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.crowdstrike-detection-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-CROWDSTRIKE-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.crowdstrike-detection-result/v1|layer=1|service=crowdstrike.detection.result.read|provider=crowdstrike.falcon.detection.result.recording|consumer=mission.crowdstrike.detection.consumer";
pub const CONTRACT_DIGEST: &str =
    "1d257ef69c20b53690ad6e5729818f38f66a29f174352a4f4b1cc58eca9e147f";
pub const PLUGIN_ID: &str = "crowdstrike.detection.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "crowdstrike.detection.result.read";
pub const PROVIDER_ID: &str = "crowdstrike.falcon.detection.result.recording";
pub const PROVIDER_API_REVISION: &str = provider::CROWDSTRIKE_API_REVISION;
pub const CONSUMER_ID: &str = "mission.crowdstrike.detection.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const FALCON_ALERTS_READ_PERMISSION: &str = "alerts.read";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/crowdstrike-detection-result/contract.v1.json");

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::parse(CONTRACT_DIGEST.to_owned()).expect("checked contract digest")
}

/// Layer 1 deliberately reports no native, connected, or kernel authority.
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
    pub const fn first_party() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_provider_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn kernel_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn outcome_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn external_writes() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use serde_json::Value;

    use super::{
        CONSUMER_ID, CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION, EVIDENCE_LEVEL,
        Layer1Authority, PLUGIN_ID, PROVIDER_ID, SERVICE_ID, contract_digest,
    };

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let document: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(document["contractVersion"], CONTRACT_VERSION);
        assert_eq!(document["pluginId"], PLUGIN_ID);
        assert_eq!(document["pluginVersion"], "1.0.0");
        assert_eq!(document["layer"], 1);
        assert_eq!(document["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(document["contractDigest"], contract_digest().as_str());
        assert_eq!(document["service"]["id"], SERVICE_ID);
        assert_eq!(document["provider"]["id"], PROVIDER_ID);
        assert_eq!(document["consumer"]["id"], CONSUMER_ID);
        assert_eq!(document["service"]["externalWrites"], false);
        assert_eq!(document["provider"]["connectedEvidence"], false);
        assert_eq!(document["provider"]["nativeEvidence"], false);
        assert_eq!(document["provider"]["firstPartyEvidence"], false);
        assert_eq!(document["authority"]["connected"], false);
        assert_eq!(document["authority"]["nativeProvider"], false);
        assert_eq!(document["authority"]["firstParty"], false);
        assert_eq!(document["authority"]["externalWrites"], false);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::external_writes());
    }
}
