//! Standalone Layer-1 SonarQube quality-result boundary.
//!
//! This crate is intentionally a below-kernel read/proposal/recording seam.
//! It models a small, allowlisted SonarQube Web API surface without resolving
//! bearer credentials, opening native HTTPS, executing analysis, mutating
//! quality gates or issues, exporting source, or claiming Connected/native
//! evidence.

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
    MissionConsumption, MissionConsumptionDisposition, MissionSonarQubeQualityConsumer,
    ProposalDisposition, QualityDecision, RecordedSonarQubeQualityResult, RecordingDisposition,
    SonarQubeQualityProposal, SonarQubeQualityRecordingLog,
};
pub use model::{
    AnalysisDate, AnalysisIdentity, AnalysisKey, BranchOrPullRequest, ComparisonOperator,
    ConditionStatus, Digest, HostIdentity, Measure, MeasureBasis, MeasureSelector, MeasureValue,
    MetricKey, MissionId, MissionScope, OrganizationId, Permission, PermissionSnapshot, ProjectId,
    ProjectionState, QualityGateCondition, QualityGateId, QualityGateIdentity, QualityGateName,
    QualityGateStatus, RegistrationId, RegistrationStatus, SecretKind, SecretReference,
    SonarProjectKey, SonarQubeQualityScope, SourceRevision, TransportProvenance, Version,
    WorkProductId,
};
pub use provider::{
    AnalysisPage, AnalysisSearchRequest, BlockedEnvTransport, FixtureTransport, LoopbackTransport,
    MeasuresComponentResponse, MeasuresReadRequest, QualityGateStatusRequest,
    QualityGateStatusResponse, ReadLimits, RecordingTransport, SonarQubeEndpoint,
    SonarQubeProvider, SonarQubeProviderError, SonarQubeQualityProjection, SonarQubeReadRequest,
    SonarQubeResponse, SonarQubeTransport, SonarQubeTransportError, TransportRequestRecord,
};
pub use service::{
    CapabilityDescription, ProviderIdentity, RegistrationReceipt, SonarQubeQualityRegistration,
    SonarQubeQualityResultService,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.sonarqube-quality-result/v1";
pub const CONTRACT_VERSION: &str = "sonarqube-quality-result-01-layer-1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.sonarqube-quality-result/v1|layer=1|service=quality.sonarqube.result.read|provider=sonarqube.quality-result.recording|consumer=mission.sonarqube-quality-result.consumer";
pub const CONTRACT_DIGEST: &str =
    "9a0748ccf2f19de4579641ab8f914767217605d5144c3a952d68c52f5ed70ecc";
pub const PLUGIN_ID: &str = "sonarqube.quality-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "quality.sonarqube.result.read";
pub const PROVIDER_ID: &str = "sonarqube.quality-result.recording";
pub const PROVIDER_API_REVISION: &str = "sonarqube-web-api-read-1";
pub const CONSUMER_ID: &str = "mission.sonarqube-quality-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/sonarqube-quality-result/service.v1.json");

pub const QUALITY_GATE_STATUS_PATH: &str = "/api/qualitygates/project_status";
pub const MEASURES_COMPONENT_PATH: &str = "/api/measures/component";
pub const PROJECT_ANALYSES_SEARCH_PATH: &str = "/api/project_analyses/search";

pub const MAX_HOST_BYTES: usize = 256;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_TEXT_BYTES: usize = 512;
pub const MAX_DATE_BYTES: usize = 64;
pub const MAX_METRIC_KEYS: usize = 32;
pub const MAX_CONDITIONS: usize = 128;
pub const MAX_MEASURES: usize = 64;
pub const MAX_ANALYSES: usize = 128;
pub const MAX_ANALYSIS_PAGES: usize = 8;
pub const MAX_PAGE_SIZE: usize = 50;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;

/// Construction, scope, registration, integrity, and bounded-read failures.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SonarQubeQualityResultError {
    #[error("invalid text in {field}")]
    InvalidText { field: &'static str },
    #[error("invalid identifier in {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("invalid HTTPS SonarQube host")]
    InvalidHost,
    #[error("invalid exact SonarQube/Mission scope")]
    InvalidScope,
    #[error("metric is not in the bounded allowlist")]
    MetricNotAllowlisted,
    #[error("permission snapshot is not the bounded read-only set")]
    InvalidPermissionSnapshot,
    #[error("opaque bearer SecretReference is invalid")]
    InvalidSecretReference,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is already present")]
    RegistrationAlreadyExists,
    #[error("registration is unknown")]
    RegistrationUnknown,
    #[error("registration is unmounted")]
    RegistrationUnmounted,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration binding or revision drifted")]
    RegistrationDrift,
    #[error("opaque SecretReference is revoked")]
    SecretRevoked,
    #[error("scope does not match the exact registered scope")]
    ScopeMismatch,
    #[error("endpoint is outside the SonarQube read allowlist")]
    EndpointNotAllowlisted,
    #[error("page size or page number is outside the bound")]
    InvalidPage,
    #[error("response exceeded its byte bound")]
    ResponseTooLarge,
    #[error("response was malformed or outside the typed allowlist")]
    MalformedResponse,
    #[error("response was not redacted")]
    ResponseNotRedacted,
    #[error("response or proposal digest did not verify")]
    TamperedEvidence,
    #[error("response was partial or truncated")]
    PartialResponse,
    #[error("analysis history pagination repeated or exceeded its bound")]
    PaginationLoop,
    #[error("analysis page contained duplicate evidence")]
    DuplicateAnalysis,
    #[error("analysis revision did not match the exact scope")]
    AnalysisDrift,
    #[error("quality-gate identity did not match the exact scope")]
    QualityGateDrift,
    #[error("measure evidence did not match the exact selection")]
    MeasureDrift,
    #[error("a required measure was missing")]
    MeasureMissing,
    #[error("proposal is invalid")]
    InvalidProposal,
    #[error("proposal was tampered")]
    ProposalTampered,
    #[error("recording idempotency key was replayed with different evidence")]
    ReplayConflict,
    #[error("Mission revision is stale")]
    StaleMissionRevision,
    #[error("consumer is inactive")]
    ConsumerInactive,
}

pub type Result<T> = std::result::Result<T, SonarQubeQualityResultError>;

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
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn validate_digest(value: &str, field: &'static str) -> Result<()> {
    if valid_digest(value) && value.bytes().all(|byte| !byte.is_ascii_uppercase()) {
        Ok(())
    } else {
        Err(SonarQubeQualityResultError::InvalidDigest { field })
    }
}

pub(crate) fn validate_text(
    value: &str,
    field: &'static str,
    maximum: usize,
    allow_empty: bool,
) -> Result<()> {
    if (!allow_empty && value.is_empty())
        || value.len() > maximum
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        Err(SonarQubeQualityResultError::InvalidText { field })
    } else {
        Ok(())
    }
}

pub(crate) fn validate_identifier(value: &str, field: &'static str, maximum: usize) -> Result<()> {
    validate_text(value, field, maximum, false)?;
    if value.chars().any(char::is_whitespace) {
        Err(SonarQubeQualityResultError::InvalidIdentifier { field })
    } else {
        Ok(())
    }
}

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}
