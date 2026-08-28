//! Standalone Layer-1 Snyk project/snapshot security-result boundary.
//!
//! This crate deliberately stops at typed, bounded provider evidence and a
//! redacted Mission proposal/recording seam. It does not resolve credentials,
//! perform live HTTPS I/O, mutate Snyk projects or issues, retain raw source
//! or dependency-graph data, create provider receipts, or claim Connected or
//! native execution.

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
    MissionSnykSecurityConsumer, ProposalDisposition, RecordedSecurityResult,
    SecurityResultProposal, SecurityResultRecordingLog,
};
pub use model::{
    CommitId, CommitIdentity, Digest, Evidence, EvidenceKind, FindingStatus, FixAvailability,
    FixMetadata, GroupId, GroupIdentity, IaCSeverity, IacEvidence, IssueId, IssueIdentity,
    LicenseEvidence, LicenseRisk, MissionId, MissionIdentity, OrganizationId, OrganizationIdentity,
    PackageId, PackageIdentity, PathId, PathIdentity, PermissionSnapshot, PluginVersion,
    ProjectContextIdentity, ProjectId, ProjectIdentity, ProjectionCompleteness, RegionId,
    RegionIdentity, RegistrationId, RegistrationStatus, SecretKind, SecretReference, Severity,
    SnapshotId, SnapshotIdentity, SnapshotStatus, SnykProjectId, SnykScope, TargetId,
    TargetIdentity, TransportProvenance, VulnerabilityEvidence, WorkProductId, WorkProductIdentity,
};
pub use provider::{
    BlockedEnvTransport, FakeTransport, LoopbackTransport, ProjectSnapshotProjection,
    ProjectSnapshotReadRequest, ProjectSnapshotResponse, RecordingTransport, SnykProvider,
    SnykTransport,
};
pub use service::{
    CapabilityDescription, ProviderIdentity, RegistrationReceipt, SnykRegistration,
    SnykRegistrationRegistry, SnykSecurityResultService,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.snyk-security-result-contract/v1";
pub const CONTRACT_VERSION: &str = "snyk-security-result-01-layer-1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.snyk-security-result-contract/v1|layer=1|service=snyk.security-result.read|provider=snyk.security-result.recording|consumer=mission.snyk-security-result.consumer";
pub const CONTRACT_DIGEST: &str =
    "2f8d404d9f3af3449fe704c73542de43cc77cfb9472d6951f06e9390e80c389c";
pub const PLUGIN_ID: &str = "snyk.security-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "snyk.security-result.read";
pub const PROVIDER_ID: &str = "snyk.security-result.recording";
pub const PROVIDER_API_REVISION: &str = "snyk-security-result-read-1";
pub const CONSUMER_ID: &str = "mission.snyk-security-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/snyk-security-result/contract.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_TEXT_BYTES: usize = 512;
pub const MAX_PAGE_SIZE: usize = 100;
pub const MAX_PAGES: usize = 16;
pub const MAX_PAGE_TOKEN_BYTES: usize = 512;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_EVIDENCE_ITEMS: usize = 256;

/// Construction and integrity failures for the Layer-1 contract.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SnykSecurityResultError {
    #[error("invalid text in {field}")]
    InvalidText { field: &'static str },
    #[error("invalid identifier in {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("invalid HTTPS regional host")]
    InvalidRegionHost,
    #[error("invalid opaque SecretReference")]
    InvalidSecretReference,
    #[error("invalid exact Snyk/Mission scope")]
    InvalidScope,
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
    #[error("invalid security-result proposal")]
    InvalidProposal,
    #[error("recording idempotency key was replayed with different evidence")]
    ReplayConflict,
    #[error("recording is truncated and cannot be treated as complete evidence")]
    TruncatedEvidence,
    #[error("redacted evidence digest is invalid or raw material was attempted")]
    RedactedEvidence,
    #[error("provider evidence is not in the allowlist")]
    EvidenceNotAllowlisted,
    #[error("provider evidence exceeded its bound")]
    EvidenceLimit,
    #[error("provider response exceeded its byte bound")]
    ResponseTooLarge,
    #[error("provider page token repeated")]
    PaginationLoop,
    #[error("provider pagination exceeded its bound")]
    PaginationLimit,
    #[error("provider response was tampered")]
    TamperedEvidence,
}

pub type Result<T> = std::result::Result<T, SnykSecurityResultError>;

/// Transport failures are intentionally finite and do not carry unbounded
/// provider response text or credentials.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SnykTransportError {
    #[error("environment is blocked for native Snyk access")]
    EnvironmentBlocked,
    #[error("Snyk returned HTTP 401 Unauthorized")]
    Unauthorized401,
    #[error("Snyk returned HTTP 403 Forbidden")]
    Forbidden403,
    #[error("Snyk returned HTTP 404 Not Found")]
    NotFound404,
    #[error("Snyk returned HTTP 409 Conflict")]
    Conflict409,
    #[error("Snyk returned HTTP 429 Rate Limited")]
    RateLimited429,
    #[error("Snyk request timed out")]
    Timeout,
    #[error("Snyk returned server HTTP {status}")]
    Server5xx { status: u16 },
    #[error("Snyk access was lost during the read")]
    AccessLost,
}

/// Provider-bound failures keep transport classification separate from typed
/// scope and evidence validation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SnykProviderError {
    #[error("provider registration is invalid: {0}")]
    Registration(#[from] SnykSecurityResultError),
    #[error("provider registration is revoked")]
    RegistrationRevoked,
    #[error("provider registration is reversed")]
    RegistrationReversed,
    #[error("provider registration drifted")]
    RegistrationDrift,
    #[error("opaque provider secret reference is revoked")]
    SecretRevoked,
    #[error("requested scope does not match the exact provider registration")]
    ScopeMismatch,
    #[error("region identity drifted")]
    RegionDrift,
    #[error("organization identity drifted")]
    OrganizationDrift,
    #[error("group identity drifted")]
    GroupDrift,
    #[error("target identity drifted")]
    TargetDrift,
    #[error("Snyk project identity drifted")]
    ProjectDrift,
    #[error("snapshot identity drifted")]
    SnapshotDrift,
    #[error("issue identity drifted")]
    IssueDrift,
    #[error("package identity drifted")]
    PackageDrift,
    #[error("path identity drifted")]
    PathDrift,
    #[error("commit identity drifted")]
    CommitDrift,
    #[error("Mission identity or revision drifted")]
    MissionDrift,
    #[error("Hartevo Project identity or revision drifted")]
    ProjectContextDrift,
    #[error("Work Product identity or revision drifted")]
    WorkProductDrift,
    #[error("provider evidence is not allowlisted")]
    EvidenceNotAllowlisted,
    #[error("provider evidence exceeded its bound")]
    EvidenceLimit,
    #[error("provider response exceeded its byte bound")]
    ResponseTooLarge,
    #[error("provider page token repeated")]
    PaginationLoop,
    #[error("provider pagination exceeded its bound")]
    PaginationLimit,
    #[error("provider response was tampered or not safely redacted")]
    TamperedEvidence,
    #[error("provider transport failed: {0}")]
    Transport(#[from] SnykTransportError),
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

pub(crate) fn validate_text(value: &str, field: &'static str, max_bytes: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(SnykSecurityResultError::InvalidText { field })
    } else {
        Ok(())
    }
}

pub(crate) fn validate_identifier(value: &str, field: &'static str) -> Result<()> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES)
}

pub(crate) fn validate_digest(value: &str, field: &'static str) -> Result<()> {
    if valid_digest(value) {
        Ok(())
    } else {
        Err(SnykSecurityResultError::InvalidDigest { field })
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
        let contract =
            serde_json::from_str::<ContractDocument>(CONTRACT_JSON).expect("checked Snyk contract");
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
