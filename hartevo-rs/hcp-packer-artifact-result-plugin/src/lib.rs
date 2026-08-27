//! Standalone Layer-1 governed HCP Packer artifact-version result boundary.
//!
//! This crate models only bounded, read-only HCP Packer bucket/channel/version/
//! build/artifact metadata for one exact organization, project, bucket,
//! version, channel, cloud, and region scope. It never resolves bearer
//! credentials, performs native HTTPS calls, triggers builds, assigns or
//! revokes channels, deletes resources, mutates images, downloads artifacts,
//! retains raw artifact locations or build logs, or claims Hartevo Truth,
//! Consent, Effect, Receipt, Verification, Outcome, or Work Product authority.
//! Fixture, recording, fake, loopback, and `BLOCKED_ENV` transports are always
//! `connected=false`, `native=false`, and `first_party=false`.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::collapsible_if,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::return_self_not_must_use,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

use sha2::{Digest as ShaDigest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionHcpPackerArtifactConsumer, MissionHcpPackerArtifactResult, ProposalDisposition,
    RecordedHcpPackerArtifactResult,
};
pub use error::{HcpPackerArtifactResultError, HcpPackerTransportError, Result};
pub use model::*;
pub use provider::{
    ArtifactPageResponse, BlockedEnvTransport, BucketResponse, BuildPageResponse, ChannelResponse,
    FakeTransport, FixtureTransport, GetBucketRequest, GetChannelRequest, GetVersionRequest,
    HcpPackerOperation, HcpPackerProvider, HcpPackerProviderDefinition, HcpPackerTransport,
    ListArtifactsRequest, ListBuildsRequest, LoopbackTransport, RecordedRequest,
    RecordingTransport, VersionResponse,
};
pub use service::{
    HcpPackerArtifactRecordReceipt, HcpPackerArtifactResultProposal,
    HcpPackerArtifactResultRegistration, HcpPackerArtifactResultService, HcpPackerCapabilities,
    HcpPackerReadRequest, HcpPackerReadResult, RegistrationStatus, RegistrationTransitionEvidence,
    VerificationFailure, VerificationReport,
};

pub type HcpPackerArtifactRegistration = HcpPackerArtifactResultRegistration;
pub type HcpPackerRegistration = HcpPackerArtifactResultRegistration;
pub type HcpPackerArtifactProposal = HcpPackerArtifactResultProposal;
pub type HcpPackerResultProposal = HcpPackerArtifactResultProposal;
pub type HcpPackerArtifactService<T = BlockedEnvTransport> = HcpPackerArtifactResultService<T>;

pub const CONTRACT_SCHEMA: &str = "hartevo.hcp-packer-artifact-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-HCP-PACKER-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.hcp-packer-artifact-result/v1|layer=1|service=hcp.packer.artifact.result.read|provider=hcp.packer.artifact.result.recording|consumer=mission.hcp-packer-artifact-result.consumer|api=hcp-packer-bucket-channel-version-build-artifact-2023-01-01-r1";
pub const CONTRACT_DIGEST: &str =
    "3c3c30a96ad062e13fd4b5fbc5a679316c831827e06cddc55d3f280b48c84ba6";
pub const PLUGIN_ID: &str = "hcp.packer.artifact.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "hcp.packer.artifact.result.read";
pub const PROVIDER_ID: &str = "hcp.packer.artifact.result.recording";
pub const PROVIDER_API_REVISION: &str =
    "hcp-packer-bucket-channel-version-build-artifact-2023-01-01-r1";
pub const CONSUMER_ID: &str = "mission.hcp-packer-artifact-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_VALUE_BYTES: usize = 4_096;
pub const MAX_LABEL_BYTES: usize = 256;
pub const MAX_LABEL_KEYS: usize = 32;
pub const MAX_PAGE_SIZE: u16 = 50;
pub const MAX_PAGES: u16 = 4;
pub const MAX_BUILDS: usize = 128;
pub const MAX_ARTIFACTS: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_READ: u16 = 32;
pub const NEXT_TOKEN_TTL_SECONDS: i64 = 300;

pub const LAYER1_PERMISSIONS: [&str; 6] = [
    "packer:ReadBucket",
    "packer:ReadChannel",
    "packer:ReadVersion",
    "packer:ListBuilds",
    "packer:ListArtifacts",
    "mission.scope",
];

pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/hcp-packer-artifact-result/hcp-packer-artifact-result.v1.json"
);

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

pub fn validate_contract() -> Result<()> {
    let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
        .map_err(|_| HcpPackerArtifactResultError::ContractShape)?;
    let object = value
        .as_object()
        .ok_or(HcpPackerArtifactResultError::ContractShape)?;
    for key in [
        "schemaVersion",
        "contractVersion",
        "pluginVersion",
        "pluginId",
        "layer",
        "evidenceLevel",
        "digestInput",
        "contractDigest",
        "service",
        "provider",
        "consumer",
        "credentials",
        "scope",
        "registration",
        "projection",
        "evidence",
        "provenance",
        "authorityBoundary",
        "layer2Gaps",
        "forbidden",
        "honestNativeGap",
    ] {
        if !object.contains_key(key) {
            return Err(HcpPackerArtifactResultError::ContractShape);
        }
    }
    if object
        .get("schemaVersion")
        .and_then(serde_json::Value::as_str)
        != Some(CONTRACT_SCHEMA)
        || object
            .get("contractVersion")
            .and_then(serde_json::Value::as_str)
            != Some(CONTRACT_VERSION)
        || object
            .get("pluginVersion")
            .and_then(serde_json::Value::as_str)
            != Some(PLUGIN_VERSION)
        || object.get("pluginId").and_then(serde_json::Value::as_str) != Some(PLUGIN_ID)
        || object.get("layer").and_then(serde_json::Value::as_u64) != Some(1)
        || object
            .get("evidenceLevel")
            .and_then(serde_json::Value::as_str)
            != Some(EVIDENCE_LEVEL)
        || object
            .get("digestInput")
            .and_then(serde_json::Value::as_str)
            != Some(CONTRACT_DIGEST_INPUT)
        || object
            .get("contractDigest")
            .and_then(serde_json::Value::as_str)
            != Some(CONTRACT_DIGEST)
        || contract_digest() != CONTRACT_DIGEST
    {
        return Err(HcpPackerArtifactResultError::ContractDrift);
    }
    let service = object
        .get("service")
        .and_then(serde_json::Value::as_object)
        .ok_or(HcpPackerArtifactResultError::ContractShape)?;
    if service.get("type").and_then(serde_json::Value::as_str)
        != Some("HcpPackerArtifactResultService")
        || service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
        || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
        || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
        || service.get("recordingOnly") != Some(&serde_json::Value::Bool(true))
        || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
    {
        return Err(HcpPackerArtifactResultError::ContractDrift);
    }
    let provider = object
        .get("provider")
        .and_then(serde_json::Value::as_object)
        .ok_or(HcpPackerArtifactResultError::ContractShape)?;
    if provider.get("type").and_then(serde_json::Value::as_str) != Some("HcpPackerProvider")
        || provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
        || provider
            .get("apiRevision")
            .and_then(serde_json::Value::as_str)
            != Some(PROVIDER_API_REVISION)
        || provider.get("connected") != Some(&serde_json::Value::Bool(false))
        || provider.get("native") != Some(&serde_json::Value::Bool(false))
        || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
        || provider.get("providerReceipt") != Some(&serde_json::Value::Bool(false))
        || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
    {
        return Err(HcpPackerArtifactResultError::ContractDrift);
    }
    let consumer = object
        .get("consumer")
        .and_then(serde_json::Value::as_object)
        .ok_or(HcpPackerArtifactResultError::ContractShape)?;
    if consumer.get("type").and_then(serde_json::Value::as_str)
        != Some("MissionHcpPackerArtifactConsumer")
        || consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
        || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
        || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
        || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
        || consumer.get("verificationAuthority") != Some(&serde_json::Value::Bool(false))
    {
        return Err(HcpPackerArtifactResultError::ContractDrift);
    }
    let provenance = object
        .get("provenance")
        .and_then(serde_json::Value::as_object)
        .ok_or(HcpPackerArtifactResultError::ContractShape)?;
    for key in ["connected", "native", "firstParty", "providerReceipt"] {
        if provenance.get(key) != Some(&serde_json::Value::Bool(false)) {
            return Err(HcpPackerArtifactResultError::ContractDrift);
        }
    }
    let forbidden = object
        .get("forbidden")
        .and_then(serde_json::Value::as_array)
        .ok_or(HcpPackerArtifactResultError::ContractShape)?;
    for required in [
        "trigger_build",
        "assign_channel",
        "revoke_version",
        "delete_bucket",
        "delete_version",
        "delete_build",
        "mutate_image",
        "download_artifact",
        "read_build_logs",
        "serialize_raw_artifact_location",
        "serialize_raw_credentials",
        "serialize_non_allowlisted_labels",
        "claim_connected",
        "claim_native",
        "claim_first_party",
        "claim_kernel_truth",
        "adopt_kernel_outcome",
    ] {
        if !forbidden.iter().any(|item| item.as_str() == Some(required)) {
            return Err(HcpPackerArtifactResultError::ContractDrift);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }
    pub const fn native() -> bool {
        false
    }
    pub const fn first_party() -> bool {
        false
    }
    pub const fn truth_authority() -> bool {
        false
    }
    pub const fn consent_authority() -> bool {
        false
    }
    pub const fn effect_authority() -> bool {
        false
    }
    pub const fn receipt_authority() -> bool {
        false
    }
    pub const fn verification_authority() -> bool {
        false
    }
    pub const fn outcome_authority() -> bool {
        false
    }
    pub const fn work_product_adoption() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_is_pinned_and_honest() {
        validate_contract().expect("valid HCP Packer contract");
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::truth_authority());
        assert!(!Layer1Authority::outcome_authority());
    }
}
