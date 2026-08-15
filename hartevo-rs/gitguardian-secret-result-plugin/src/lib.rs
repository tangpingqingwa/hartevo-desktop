//! Standalone Layer-1 GitGuardian secret incident and occurrence result seam.
//!
//! The crate provides typed incident, occurrence, detector, and status reads;
//! digest-bound registration; a below-kernel Mission proposal consumer; and
//! local fixture/recording/loopback evidence. It never resolves native
//! credentials, performs live HTTP, retains secret material or occurrence
//! content, performs incident or secret remediation, claims Connected/native
//! authority, or adopts a kernel Outcome.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::result_large_err,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConsumerError, MissionConsumerError, MissionGitGuardianSecretConsumer,
    MissionGitGuardianSecretConsumerResult, MissionGitGuardianSecretDecision,
    MissionGitGuardianSecretDecisionState, MissionGitGuardianSecretResult,
    MissionGitGuardianSecretResultConsumer, MissionGitGuardianSecretResultState,
};
pub use model::{
    CommitSha, DetectorId, DetectorKind, DetectorStatus, Digest, EvidenceStatus,
    GitGuardianAuthKind, GitGuardianDetector, GitGuardianEvidence, GitGuardianEvidenceState,
    GitGuardianIncident, GitGuardianIncidentInput, GitGuardianIncidentStatus,
    GitGuardianOccurrence, GitGuardianOccurrenceInput, GitGuardianPermission, GitGuardianQuery,
    GitGuardianResultState, GitGuardianScope, GitGuardianSecretReference,
    GitGuardianSecretResultEvidence, GitGuardianSecretResultScope, IncidentId, IncidentStatus,
    MAX_CURSOR_BYTES, MAX_DETECTORS, MAX_IDENTIFIER_BYTES, MAX_INCIDENTS, MAX_OCCURRENCES,
    MAX_PAGE_SIZE, MAX_PAGES, MAX_PROVIDER_ERRORS, MAX_REQUESTS_PER_READ, MAX_RESPONSE_BYTES,
    MAX_SECRET_REFERENCE_BYTES, MissionId, MissionScopeBinding, ModelError, OccurrenceId,
    OccurrencePresence, OpaqueCursor, PerimeterId, PermissionSnapshot, ProjectId,
    RedactedRateReceipt, RedactedRequestReceipt, RefName, RepositoryIdentity, Revision,
    SecretReference, SecretResultScope, Severity, TransportProvenance, ValidityStatus,
    WorkProductId, WorkspaceId,
};
pub use provider::{
    BlockedEnvGitGuardianTransport, BlockedEnvTransport, DetectorResponse,
    FakeGitGuardianTransport, FakeTransport, FixtureGitGuardianTransport, FixtureTransport,
    GitGuardianDetectorResponse, GitGuardianHealth, GitGuardianIncidentPage,
    GitGuardianIncidentResponse, GitGuardianOccurrencePage, GitGuardianOccurrenceResponse,
    GitGuardianOperation, GitGuardianProvider, GitGuardianProviderDefinition,
    GitGuardianProviderDefinitionAlias, GitGuardianProviderError, GitGuardianReadRequest,
    GitGuardianRequest, GitGuardianResponse, GitGuardianStatusResponse, GitGuardianTransport,
    IncidentPage, IncidentResponse, LoopbackGitGuardianTransport, LoopbackTransport,
    OccurrencePage, OccurrenceResponse, ProviderDefinition, ProviderDefinitionError, ProviderError,
    ProviderErrorKind, ProviderResponse, RecordingGitGuardianTransport, RecordingTransport,
    StatusResponse, TransportError,
};
pub use service::{
    GitGuardianCapabilityDescription, GitGuardianDecision, GitGuardianProposal, GitGuardianRecord,
    GitGuardianRecordReceipt, GitGuardianRegistration, GitGuardianRemediationDecision,
    GitGuardianResultProposal, GitGuardianSecretResultProposal,
    GitGuardianSecretResultRecordReceipt, GitGuardianSecretResultRecording,
    GitGuardianSecretResultRegistration, GitGuardianSecretResultService,
    GitGuardianSecretResultServiceDefinition, GitGuardianService, GitGuardianServiceError,
    GitGuardianVerifiedRecord, GitGuardianVerifiedRecording, ReadLimits, Registration,
    RegistrationState, RegistrationTransition, RegistrationTransitionReceipt, ServiceDefinition,
    ServiceError, VerifiedRecord, classify_provider_error,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.gitguardian-secret-result/v1";
pub const CONTRACT_VERSION: &str = "gitguardian-secret-result-01-layer-1/v1";
pub const PLUGIN_ID: &str = "gitguardian.secret-result";
pub const PLUGIN_VERSION: &str = "0.1.0";
pub const SERVICE_ID: &str = "security.gitguardian.secret.result.read";
pub const PROVIDER_ID: &str = "gitguardian.secret-result.recording";
pub const CONSUMER_ID: &str = "mission.gitguardian-secret-result.consumer";
pub const API_REVISION: &str = "gitguardian-api-read-v1";
pub const PROVIDER_API_REVISION: &str = API_REVISION;
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.gitguardian-secret-result/v1|gitguardian-secret-result-01-layer-1/v1|gitguardian.secret-result|security.gitguardian.secret.result.read|gitguardian.secret-result.recording|mission.gitguardian-secret-result.consumer";
pub const EVIDENCE_POLICY_INPUT: &str = "gitguardian-secret-result/evidence-policy/v1|incident-status|occurrence-status-presence|detector-kind-status|workspace-perimeter-incident-occurrence-detector-repository-commit-digests|redacted-request-rate-receipts|no-secret|no-token|no-occurrence-content|no-raw-provider-payload|no-compliance-certification";

pub const INCIDENTS_ENDPOINT: &str = "/v1/incidents/secrets";
pub const INCIDENT_ENDPOINT: &str = "/v1/incidents/secrets";
pub const OCCURRENCES_ENDPOINT: &str = "/v1/occurrences/secrets";
pub const OCCURRENCE_ENDPOINT: &str = "/v1/occurrences/secrets";
pub const DETECTORS_ENDPOINT: &str = "/v1/secret_detectors";
pub const DETECTOR_ENDPOINT: &str = "/v1/secret_detectors";
pub const HEALTH_ENDPOINT: &str = "/v1/health";

pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/gitguardian-secret-result/gitguardian-secret-result.v1.json"
);

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProbeStatus {
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeProbe {
    pub status: NativeProbeStatus,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

/// Layer 1 has no native credential or environment probe. This is a fixed
/// honesty result, not a claim about the host environment.
#[must_use]
pub const fn native_probe_from_environment() -> NativeProbe {
    NativeProbe {
        status: NativeProbeStatus::BlockedEnv,
        connected: false,
        native: false,
        first_party: false,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    #[must_use]
    pub const fn connected() -> bool {
        false
    }

    #[must_use]
    pub const fn native() -> bool {
        false
    }

    #[must_use]
    pub const fn first_party() -> bool {
        false
    }

    #[must_use]
    pub const fn truth() -> bool {
        false
    }

    #[must_use]
    pub const fn consent() -> bool {
        false
    }

    #[must_use]
    pub const fn effect() -> bool {
        false
    }

    #[must_use]
    pub const fn receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn verification() -> bool {
        false
    }

    #[must_use]
    pub const fn outcome() -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitGuardianSecretResultContract;

impl GitGuardianSecretResultContract {
    pub fn baseline() -> Result<Self, ContractValidationError> {
        validate_contract().map(|()| Self)
    }

    #[must_use]
    pub const fn schema_version() -> &'static str {
        CONTRACT_SCHEMA
    }

    #[must_use]
    pub const fn version() -> &'static str {
        CONTRACT_VERSION
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        contract_digest()
    }
}

pub type GitGuardianContract = GitGuardianSecretResultContract;
pub type Contract = GitGuardianSecretResultContract;

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContractValidationError {
    #[error("contract JSON is invalid: {0}")]
    Json(String),
    #[error("contract field {0} is not the frozen Layer-1 value")]
    FrozenField(&'static str),
}

pub fn validate_contract() -> Result<(), ContractValidationError> {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT_JSON)
        .map_err(|error| ContractValidationError::Json(error.to_string()))?;
    let is = |path: &'static str, condition: bool| {
        if condition {
            Ok(())
        } else {
            Err(ContractValidationError::FrozenField(path))
        }
    };
    is(
        "schemaVersion",
        contract["schemaVersion"] == CONTRACT_SCHEMA,
    )?;
    is(
        "contractVersion",
        contract["contractVersion"] == CONTRACT_VERSION,
    )?;
    is("pluginId", contract["pluginId"] == PLUGIN_ID)?;
    is("pluginVersion", contract["pluginVersion"] == PLUGIN_VERSION)?;
    is(
        "contractDigestInput",
        contract["contractDigestInput"] == CONTRACT_DIGEST_INPUT,
    )?;
    is(
        "contractDigest",
        contract["contractDigest"] == contract_digest().as_str(),
    )?;
    is("layer", contract["layer"] == 1)?;
    is("evidenceLevel", contract["evidenceLevel"] == EVIDENCE_LEVEL)?;
    is(
        "service.type",
        contract["service"]["type"] == "GitGuardianSecretResultService",
    )?;
    is("service.id", contract["service"]["id"] == SERVICE_ID)?;
    for field in ["readOnly", "proposalOnly", "proposalsBelowKernel"] {
        is("service.authority", contract["service"][field] == true)?;
    }
    is(
        "service.liveExecution",
        contract["service"]["liveExecution"] == false,
    )?;
    is(
        "provider.type",
        contract["provider"]["type"] == "GitGuardianProvider",
    )?;
    is("provider.id", contract["provider"]["id"] == PROVIDER_ID)?;
    is(
        "provider.apiRevision",
        contract["provider"]["apiRevision"] == API_REVISION,
    )?;
    for field in ["native", "connected", "firstParty", "externalWrites"] {
        is("provider.honesty", contract["provider"][field] == false)?;
    }
    is(
        "provider.requiredQuery.explicitPagination",
        contract["provider"]["requiredQuery"]["explicitPagination"] == true,
    )?;
    is(
        "consumer.type",
        contract["consumer"]["type"] == "MissionGitGuardianSecretConsumer",
    )?;
    is("consumer.id", contract["consumer"]["id"] == CONSUMER_ID)?;
    is(
        "consumer.producesDecisionProposal",
        contract["consumer"]["producesDecisionProposal"] == true,
    )?;
    for field in [
        "adoptsKernelOutcome",
        "truthAuthority",
        "certificationAuthority",
    ] {
        is("consumer.authority", contract["consumer"][field] == false)?;
    }
    for field in ["serialized", "rawMaterialAccepted"] {
        is("credentials", contract["credentials"][field] == false)?;
    }
    is(
        "permissions.writePermissions",
        contract["permissions"]["writePermissions"] == false,
    )?;
    for field in ["reversible", "revocable"] {
        is("registration", contract["registration"][field] == true)?;
    }
    for field in [
        "literalSecret",
        "apiKeyValue",
        "serviceAccountMaterial",
        "occurrenceContent",
        "rawProviderPayload",
        "rawAuthorizationHeader",
        "rawCursor",
        "complianceCertification",
    ] {
        is(
            "evidence.notRetained",
            contract["evidence"]["notRetained"]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item == field)),
        )?;
    }
    for field in [
        "connectedClaim",
        "nativeClaim",
        "firstPartyClaim",
        "durableProviderReceipt",
    ] {
        is("provenance", contract["provenance"][field] == false)?;
    }
    for field in [
        "revoke_incident",
        "resolve_incident",
        "ignore_incident",
        "rotate_secret",
        "delete_occurrence",
        "retrieve_secret",
        "export_occurrence_content",
        "claim_connected",
        "claim_native",
        "claim_first_party",
        "claim_compliance_certification",
        "adopt_kernel_outcome",
    ] {
        is(
            "forbidden",
            contract["forbidden"]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item == field)),
        )?;
    }
    Ok(())
}

#[must_use]
pub fn contract_bounds_tripwire() -> bool {
    validate_contract().is_ok()
        && !Layer1Authority::connected()
        && !Layer1Authority::native()
        && !Layer1Authority::first_party()
        && !Layer1Authority::truth()
        && !Layer1Authority::effect()
        && !Layer1Authority::outcome()
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_is_layer_one_and_honest() {
        validate_contract().expect("checked contract validates");
        assert_eq!(
            GitGuardianSecretResultContract::baseline()
                .unwrap()
                .digest(),
            contract_digest()
        );
        assert!(contract_bounds_tripwire());
        let probe = native_probe_from_environment();
        assert_eq!(probe.status, NativeProbeStatus::BlockedEnv);
        assert!(!probe.connected);
        assert!(!probe.native);
        assert!(!probe.first_party);
    }
}
