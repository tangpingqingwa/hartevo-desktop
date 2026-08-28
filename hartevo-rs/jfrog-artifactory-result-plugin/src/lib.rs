//! Standalone Layer-1 JFrog Artifactory release-result boundary.
//!
//! This crate binds one exact Artifactory repository/path/build/module/artifact
//! and source revision to one Mission release objective. It only accepts
//! recording, fake, loopback, or BLOCKED_ENV transport fixtures. It never
//! resolves credentials, reads artifact bytes, mutates Artifactory, or claims
//! Connected, native, provider-receipt, or Outcome authority.

#![forbid(unsafe_code)]

use std::fmt::Write as _;

use serde::Serialize;
use sha2::{Digest as Sha2Digest, Sha256};
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    JfrogArtifactRecordingLog, JfrogArtifactReleaseProposal, MissionJfrogArtifactConsumer,
    ProposalDisposition, RecordedJfrogArtifactResult, ReleaseDecision, ReleaseDecisionProposal,
};
pub use model::{
    AqlMetadataQuery, AqlMetadataRecord, AqlRange, ArtifactChecksums, ArtifactIdentity,
    ArtifactMetadata, ArtifactName, ArtifactPath, ArtifactPathIdentity, ArtifactStatus,
    BuildIdentity, BuildInfoEvidence, BuildName, BuildNumber, Checksum, CommitIdentity, CommitSha,
    Digest, HostIdentity, JfrogArtifactoryScope, JfrogScope, MissionId, MissionIdentity,
    ModuleEvidence, ModuleIdentity, ModuleName, OrganizationId, OrganizationIdentity,
    PermissionSnapshot, PluginVersion, ProjectId, ProjectIdentity, ProjectionCompleteness,
    PromotionEvidence, PromotionState, PropertyEvidence, ProviderProvenance, RegistrationId,
    RegistrationStatus, RepositoryIdentity, RepositoryKey, SecretKind, SecretReference,
    TransportProvenance, WorkProductId, WorkProductIdentity,
};
pub use provider::{
    ArtifactMetadataReadRequest, ArtifactReadSelector, BlockedEnvTransport, FakeTransport,
    JfrogArtifactProjection, JfrogArtifactoryProvider, JfrogArtifactoryResponse,
    JfrogArtifactoryTransport, LoopbackTransport, RecordingTransport,
};
pub use service::{
    CapabilityDescription, JfrogArtifactoryRegistration, JfrogArtifactoryResultService,
    JfrogRegistration, JfrogRegistrationRegistry, ProviderIdentity, RegistrationReceipt,
};

pub type JfrogArtifactoryProviderError = JfrogProviderError;
pub type JfrogArtifactoryTransportError = JfrogTransportError;

pub const CONTRACT_SCHEMA: &str = "hartevo.jfrog-artifactory-result-contract/v1";
pub const CONTRACT_VERSION: &str = "jfrog-artifactory-result-01-layer-1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.jfrog-artifactory-result-contract/v1|layer=1|service=jfrog.artifactory-result.read|provider=jfrog.artifactory.result.recording|consumer=mission.jfrog-artifactory-result.consumer";
pub const CONTRACT_DIGEST: &str =
    "c40e23ec7ad3f4e88285a8619f35a92f77dfa9b03bdcd5dccbb7f727a4d35ae4";
pub const PLUGIN_ID: &str = "jfrog.artifactory-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "jfrog.artifactory-result.read";
pub const PROVIDER_ID: &str = "jfrog.artifactory.result.recording";
pub const PROVIDER_API_REVISION: &str = "jfrog-artifactory-result-read-1";
pub const CONSUMER_ID: &str = "mission.jfrog-artifactory-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/jfrog-artifactory-result/contract.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PATH_BYTES: usize = 2_048;
pub const MAX_TEXT_BYTES: usize = 512;
pub const MAX_PAGE_SIZE: usize = 50;
pub const MAX_PAGES: usize = 8;
pub const MAX_AQL_RESULTS: usize = 128;
pub const MAX_PROPERTIES: usize = 128;
pub const MAX_MODULES: usize = 32;
pub const MAX_ARTIFACTS: usize = 64;
pub const MAX_PAGE_TOKEN_BYTES: usize = 512;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_METADATA_BYTES: usize = 65_536;

/// Construction, scope, registration, and integrity failures for Layer 1.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum JfrogArtifactoryResultError {
    #[error("invalid text in {field}")]
    InvalidText { field: &'static str },
    #[error("invalid identifier in {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("invalid HTTPS Artifactory host")]
    InvalidHost,
    #[error("artifact path traversal or unsafe path syntax was refused")]
    PathTraversalRefused,
    #[error("invalid exact Artifactory/Mission scope")]
    InvalidScope,
    #[error("invalid opaque SecretReference")]
    InvalidSecretReference,
    #[error("invalid read-only permission snapshot")]
    InvalidPermissionSnapshot,
    #[error("invalid registration")]
    InvalidRegistration,
    #[error("registration already exists")]
    RegistrationAlreadyExists,
    #[error("registration is unknown")]
    RegistrationUnknown,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("registration binding or revision drifted")]
    RegistrationDrift,
    #[error("opaque secret reference is revoked")]
    SecretRevoked,
    #[error("scope does not match the exact registered scope")]
    ScopeMismatch,
    #[error("provider response was malformed or outside the allowlist")]
    MalformedResponse,
    #[error("provider response was partial and cannot be treated as complete")]
    PartialResponse,
    #[error("checksum evidence does not match the expected artifact")]
    ChecksumMismatch,
    #[error("artifact metadata digest does not match its fields")]
    MetadataMismatch,
    #[error("build-info revision or source revision does not match the scope")]
    BuildInfoRevisionMismatch,
    #[error("promotion metadata does not match the bound build or repository")]
    PromotionMismatch,
    #[error("provider provenance is not an allowed non-native provenance")]
    ProvenanceMismatch,
    #[error("AQL query is not the allowlisted bounded metadata query")]
    AqlNotAllowlisted,
    #[error("AQL result is outside the exact scope")]
    AqlOutOfScope,
    #[error("duplicate AQL evidence was received")]
    DuplicateEvidence,
    #[error("provider evidence exceeded its bound")]
    EvidenceLimit,
    #[error("provider response exceeded its byte bound")]
    ResponseTooLarge,
    #[error("provider page token repeated")]
    PaginationLoop,
    #[error("provider pagination exceeded its bound")]
    PaginationLimit,
    #[error("provider evidence was truncated and cannot be treated as complete")]
    TruncatedEvidence,
    #[error("provider evidence or proposal was tampered")]
    TamperedEvidence,
    #[error("invalid release decision proposal")]
    InvalidProposal,
    #[error("recording idempotency key was replayed with different evidence")]
    ReplayConflict,
}

pub type Result<T> = std::result::Result<T, JfrogArtifactoryResultError>;

/// Transport failures are finite classifications. They deliberately contain
/// no raw response text, credentials, headers, or provider logs.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum JfrogTransportError {
    #[error("environment is blocked for native JFrog access")]
    EnvironmentBlocked,
    #[error("JFrog returned HTTP 401 Unauthorized")]
    Unauthorized401,
    #[error("JFrog returned HTTP 403 Forbidden")]
    Forbidden403,
    #[error("JFrog returned HTTP 404 Not Found")]
    NotFound404,
    #[error("JFrog returned HTTP 409 Conflict")]
    Conflict409,
    #[error("JFrog returned HTTP 429 Rate Limited")]
    RateLimited429,
    #[error("JFrog request timed out")]
    Timeout,
    #[error("JFrog returned server HTTP {status}")]
    Server5xx { status: u16 },
    #[error("JFrog access was lost during the read")]
    AccessLost,
    #[error("JFrog provider identity is unknown")]
    ProviderUnknown,
    #[error("JFrog response was malformed")]
    MalformedResponse,
    #[error("JFrog response was partial")]
    PartialResponse,
}

/// Provider-bound failures keep HTTP classification separate from typed scope
/// and evidence validation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum JfrogProviderError {
    #[error("provider registration is invalid: {0}")]
    Registration(#[from] JfrogArtifactoryResultError),
    #[error("provider registration is revoked")]
    RegistrationRevoked,
    #[error("provider registration is reversed")]
    RegistrationReversed,
    #[error("provider registration drifted")]
    RegistrationDrift,
    #[error("opaque provider secret reference is revoked")]
    SecretRevoked,
    #[error("host identity drifted")]
    HostDrift,
    #[error("organization identity drifted")]
    OrganizationDrift,
    #[error("repository identity drifted")]
    RepositoryDrift,
    #[error("artifact path identity drifted")]
    ArtifactPathDrift,
    #[error("build identity or build-info revision drifted")]
    BuildDrift,
    #[error("module identity drifted")]
    ModuleDrift,
    #[error("artifact identity drifted")]
    ArtifactDrift,
    #[error("commit/source revision drifted")]
    CommitDrift,
    #[error("Mission identity or revision drifted")]
    MissionDrift,
    #[error("Project identity or revision drifted")]
    ProjectDrift,
    #[error("Work Product identity or revision drifted")]
    WorkProductDrift,
    #[error("checksum evidence did not match the requested checksum")]
    ChecksumMismatch,
    #[error("artifact metadata digest did not match its fields")]
    MetadataMismatch,
    #[error("build-info revision or source revision did not match the scope")]
    BuildInfoRevisionMismatch,
    #[error("promotion metadata did not match the bound scope")]
    PromotionMismatch,
    #[error("provider response was malformed or not safely redacted")]
    TamperedEvidence,
    #[error("provider evidence was not allowlisted")]
    EvidenceNotAllowlisted,
    #[error("provider evidence exceeded its bound")]
    EvidenceLimit,
    #[error("provider response exceeded its byte bound")]
    ResponseTooLarge,
    #[error("provider AQL query was not allowlisted")]
    AqlNotAllowlisted,
    #[error("provider AQL result was outside the exact scope")]
    AqlOutOfScope,
    #[error("duplicate provider AQL evidence was received")]
    DuplicateEvidence,
    #[error("provider page token repeated")]
    PaginationLoop,
    #[error("provider pagination exceeded its bound")]
    PaginationLimit,
    #[error("provider access was lost")]
    AccessLost,
    #[error("provider identity is unknown")]
    ProviderUnknown,
    #[error("provider transport failed: {0}")]
    Transport(#[from] JfrogTransportError),
}

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
    allow_empty: bool,
) -> Result<()> {
    if (!allow_empty && value.is_empty())
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(JfrogArtifactoryResultError::InvalidText { field })
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
        Err(JfrogArtifactoryResultError::InvalidDigest { field })
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
        digest_input: String,
        contract_digest: String,
    }

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract = serde_json::from_str::<ContractDocument>(CONTRACT_JSON)
            .expect("checked JFrog contract");
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
