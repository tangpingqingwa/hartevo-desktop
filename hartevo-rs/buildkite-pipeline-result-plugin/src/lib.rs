//! Standalone Layer-1 Buildkite pipeline-result read, proposal, and recording boundary.
//!
//! This crate owns typed Buildkite identity, bounded metadata projections,
//! tamper/redaction evidence, and a reversible registration seam.  It does
//! not resolve credentials, issue native requests, retain logs or artifact
//! bytes, mutate Buildkite, claim Connected/native status, or adopt a Mission
//! Outcome.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

use std::fmt::Write as _;

use serde::Serialize;
use sha2::{Digest as Sha2Digest, Sha256};
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    BuildkitePipelineResultProposal, BuildkitePipelineResultRecordingLog,
    MissionBuildkitePipelineConsumer, RecordedBuildkitePipelineResult, RecordedPipelineResult,
};
pub use model::*;
pub use provider::{
    AnnotationPage, ArtifactMetadataPage, BlockedEnvTransport, BuildPage, BuildkiteProvider,
    BuildkiteProviderError, BuildkiteReadRequest, BuildkiteTransport, BuildkiteTransportError,
    FakeBuildkiteTransport, FakeTransport, JobPage, LoopbackBuildkiteTransport, LoopbackTransport,
    RecordingBuildkiteTransport, RecordingTransport,
};
pub use service::{
    BuildkitePipelineResultService, BuildkiteRegistration, BuildkiteRegistrationRegistry,
    CapabilityDescription, ProviderIdentity, RegistrationReceipt, RegistrationStatus,
    RegistrationTransitionEvidence,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.buildkite-pipeline-result-contract/v1";
pub const CONTRACT_VERSION: &str = "buildkite-pipeline-result-01-layer-1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.buildkite-pipeline-result-contract/v1|layer=1|service=buildkite.pipeline-result.read|provider=buildkite.cloud.pipeline-result.recording|consumer=mission.buildkite-pipeline-result.consumer";
pub const CONTRACT_DIGEST: &str =
    "c9942af361e8c7636dff8d344ce1189f592f6276e560e42f0b7d495bb902de4f";
pub const PLUGIN_ID: &str = "buildkite.pipeline-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "buildkite.pipeline-result.read";
pub const PROVIDER_ID: &str = "buildkite.cloud.pipeline-result.recording";
pub const PROVIDER_API_REVISION: &str = "buildkite-rest-pipeline-result-read-1";
pub const CONSUMER_ID: &str = "mission.buildkite-pipeline-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/buildkite-pipeline-result/contract.v1.json");

pub const MAX_PAGE_SIZE: usize = 50;
pub const MAX_PAGES: usize = 8;
pub const MAX_BUILDS: usize = 32;
pub const MAX_JOBS: usize = 128;
pub const MAX_ATTEMPTS: usize = 128;
pub const MAX_ANNOTATIONS: usize = 128;
pub const MAX_ARTIFACTS: usize = 128;
pub const MAX_PAGE_TOKEN_BYTES: usize = 512;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_METADATA_BYTES: u64 = 64 * 1024;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_RETRY_NUMBER: u32 = 1024;

/// Errors are deliberately semantic and bounded: no provider body, token,
/// log, artifact bytes, or annotation body is stored in an error.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum BuildkitePipelineResultError {
    #[error("invalid text in {field}")]
    InvalidText { field: &'static str },
    #[error("invalid identifier in {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("invalid HTTPS Buildkite host origin")]
    InvalidHost,
    #[error("invalid opaque API-token/OIDC SecretReference")]
    InvalidSecretReference,
    #[error("invalid exact Buildkite/Mission scope")]
    InvalidScope,
    #[error("invalid read-only permission snapshot")]
    InvalidPermissionSnapshot,
    #[error("invalid registration binding")]
    InvalidRegistration,
    #[error("registration already exists")]
    RegistrationAlreadyExists,
    #[error("registration is unknown")]
    RegistrationUnknown,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("registration integrity or revision drifted")]
    RegistrationDrift,
    #[error("exact Buildkite/Mission scope does not match")]
    ScopeMismatch,
    #[error("provider evidence was tampered")]
    TamperedEvidence,
    #[error("provider evidence was truncated and is review-only")]
    TruncatedEvidence,
    #[error("provider evidence redaction boundary was violated")]
    RedactionViolation,
    #[error("provider response exceeded its byte bound")]
    ResponseTooLarge,
    #[error("provider pagination exceeded its bound")]
    PaginationLimit,
    #[error("provider page token repeated")]
    PaginationLoop,
    #[error("provider returned an out-of-scope entry")]
    OutOfScope,
    #[error("proposal is invalid")]
    InvalidProposal,
    #[error("recording idempotency key was replayed with different evidence")]
    ReplayConflict,
    #[error("provider error: {0}")]
    Provider(#[from] BuildkiteProviderError),
    #[error("transport error: {0}")]
    Transport(#[from] BuildkiteTransportError),
}

pub type Result<T> = std::result::Result<T, BuildkitePipelineResultError>;

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

pub(crate) fn digest_serialized<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("contract values must serialize");
    sha256_hex(&bytes)
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(crate) fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
    allow_internal_whitespace: bool,
) -> Result<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
        || (!allow_internal_whitespace && value.chars().any(char::is_whitespace))
    {
        Err(BuildkitePipelineResultError::InvalidText { field })
    } else {
        Ok(())
    }
}

pub(crate) fn validate_identifier(value: &str, field: &'static str) -> Result<()> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES, false)
}

pub(crate) fn validate_digest(value: &str, field: &'static str) -> Result<()> {
    if valid_digest(value) {
        Ok(())
    } else {
        Err(BuildkitePipelineResultError::InvalidDigest { field })
    }
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

#[cfg(test)]
mod contract_tests {
    use serde::Deserialize;

    use super::{
        CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION,
        EVIDENCE_LEVEL, PLUGIN_ID, contract_digest,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        plugin_id: String,
        layer: u8,
        evidence_level: String,
        contract_digest: String,
        digest_input: String,
    }

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract = serde_json::from_str::<ContractDocument>(CONTRACT_JSON)
            .expect("checked Buildkite contract");
        assert_eq!(contract.schema_version, CONTRACT_SCHEMA);
        assert_eq!(contract.contract_version, CONTRACT_VERSION);
        assert_eq!(contract.plugin_id, PLUGIN_ID);
        assert_eq!(contract.layer, 1);
        assert_eq!(contract.evidence_level, EVIDENCE_LEVEL);
        assert_eq!(contract.digest_input, CONTRACT_DIGEST_INPUT);
        assert_eq!(contract.contract_digest, CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert!(!CONTRACT_DIGEST.contains("REPLACED"));
    }
}
