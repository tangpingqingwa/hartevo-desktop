//! Standalone Layer-1 Veracode application-security evidence boundary.
//!
//! This crate exposes typed, bounded application/build/scan/finding/policy
//! reads, redacted projections, reversible registration, Mission-scoped
//! proposal/recording/verification, and deterministic harness transports. It
//! intentionally does not resolve credentials, upload code or packages,
//! launch scans, mutate findings or policies, perform native HTTPS, create a
//! durable provider receipt, certify security, or become Hartevo Truth,
//! Consent, Effect, Receipt, Verification, or Outcome authority.

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
    ConsumerError, MissionVeracodeResultConsumer, MissionVeracodeSecurityConsumer,
    RecordedVeracodeResult, VeracodeMissionResult,
};
pub use model::*;
pub use provider::{
    APPLICATIONS_PATH, BLOCKED_ENV_PROVIDER_REVISION, BlockedEnvTransport,
    BlockedEnvVeracodeTransport, FINDINGS_PATH_TEMPLATE, FixtureTransport,
    FixtureVeracodeTransport, LoopbackTransport, LoopbackVeracodeTransport, POLICIES_PATH,
    ReadBounds, RecordedRequest, RecordingTransport, RecordingVeracodeTransport, VeracodeProvider,
    VeracodeProviderDefinition, VeracodeProviderError, VeracodeReadRequest, VeracodeReadResponse,
    VeracodeTransport, VeracodeTransportError, VeracodeTransportFailure,
};
pub use service::{
    ProposalDisposition, RegistrationStatus, RegistrationTransitionReceipt, ServiceError,
    VeracodeCapabilityDescription, VeracodeEvidence, VeracodeProposal, VeracodeRegistration,
    VeracodeResultService, VeracodeSecurityResultService, VeracodeVerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.veracode-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-VERACODE-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.veracode-result/v1|layer=1|service=veracode.result.read|provider=veracode.appsec.result.recording|consumer=mission.veracode.result.consumer";
pub const CONTRACT_DIGEST: &str =
    "9e7e5b41c6ab3e52c8acd04e689d8889e776c136ba5ff4c2b83c6a5cb12d6e63";
pub const PLUGIN_ID: &str = "veracode.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "veracode.result.read";
pub const PROVIDER_ID: &str = "veracode.appsec.result.recording";
pub const PROVIDER_API_REVISION: &str = "veracode-applications-builds-scans-findings-policies-1";
pub const CONSUMER_ID: &str = "mission.veracode.result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const VERACODE_RESULTS_READ_PERMISSION: &str = "results.read";
pub const RESULTS_READ_PERMISSION: &str = VERACODE_RESULTS_READ_PERMISSION;
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/veracode-appsec-result/veracode-appsec-result.v1.json"
);

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::parse(CONTRACT_DIGEST.to_owned()).expect("checked Veracode contract digest")
}

/// Layer 1 deliberately reports no native, connected, first-party, or kernel
/// authority regardless of transport provenance.
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
        for field in [
            "connected",
            "nativeProvider",
            "firstParty",
            "durableProviderReceipt",
            "kernelAuthority",
            "outcomeAuthority",
            "externalWrites",
        ] {
            assert_eq!(document["authority"][field], false, "authority.{field}");
        }
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::external_writes());
    }
}
