//! Standalone Layer-1 governed GitHub secret-scanning result boundary.
//!
//! This crate owns a typed, bounded repository/organization alert read seam,
//! digest-only evidence, a reversible/revocable registration, and a Mission
//! proposal consumer. It never resolves App/OAuth material, performs live
//! HTTPS, retains a secret or raw location, mutates GitHub, claims Connected/
//! native/first-party authority, or adopts a kernel Outcome.

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
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::fn_params_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConsumerError, MissionGithubSecretScanningConsumer, MissionGithubSecretScanningDecision,
    MissionGithubSecretScanningDecisionState, MissionGithubSecretScanningResult,
};
pub use model::{
    AlertNumber, AlertState, CommitSha, Digest, GithubAuthKind, GithubSecretScanningAlert,
    GithubSecretScanningEvidence, GithubSecretScanningScope, InstallationId, LocationKind,
    MAX_ALERTS, MAX_CURSOR_BYTES, MAX_LOCATIONS, MAX_PAGE_SIZE, MAX_PAGES, MAX_PROVIDER_ERRORS,
    MAX_REQUESTS_PER_READ, MAX_RESPONSE_BYTES, MissionId, MissionScopeBinding, OpaqueCursor,
    OrganizationName, Permission, PermissionSnapshot, ProjectId, PushProtectionMetadata,
    RedactedLocation, RedactedRateReceipt, RedactedRequestReceipt, RefName, RepositoryIdentity,
    Revision, SecretReference, SecretScanningAlert, SecretScanningAlertInput,
    SecretScanningOperation, SecretScanningQuery, SecretScanningScope, SecretType, SecretTypeClass,
    TransportProvenance, ValidityClass, WorkProductId,
};
pub use provider::{
    AlertPage, AlertResponse, AlertTarget, BlockedEnvGithubSecretScanningTransport,
    BlockedEnvTransport, FakeGithubSecretScanningTransport, FixtureGithubSecretScanningTransport,
    FixtureTransport, GithubProviderDefinition, GithubSecretScanningAlertResponse,
    GithubSecretScanningPage, GithubSecretScanningProvider, GithubSecretScanningProviderDefinition,
    GithubSecretScanningProviderError, GithubSecretScanningReadRequest,
    GithubSecretScanningRequest, GithubSecretScanningResponse, GithubSecretScanningTransport,
    LoopbackGithubSecretScanningTransport, LoopbackTransport, ProviderDefinitionError,
    ProviderError, ProviderErrorKind, ProviderResponse, RecordingGithubSecretScanningTransport,
    RecordingTransport, TransportError,
};
pub use service::{
    GithubSecretScanningCapabilityDescription, GithubSecretScanningProposal,
    GithubSecretScanningRecord, GithubSecretScanningRecordReceipt, GithubSecretScanningRecording,
    GithubSecretScanningRegistration, GithubSecretScanningResultProposal,
    GithubSecretScanningResultService, GithubSecretScanningService,
    GithubSecretScanningServiceDefinition, GithubSecretScanningServiceDefinitionAlias,
    GithubSecretScanningServiceDefinitionPublic, GithubSecretScanningServiceError,
    GithubSecretScanningVerifiedRecord, ProjectionState, ReadLimits, Registration,
    RegistrationState, RegistrationTransition, RegistrationTransitionReceipt, ServiceError,
};

pub type GithubSecretReference = SecretReference;
pub type GithubSecretScanningResultEvidence = GithubSecretScanningEvidence;
pub type GithubSecretScanningAlertEvidence = SecretScanningAlert;

pub const CONTRACT_SCHEMA: &str = "hartevo.github-secret-scanning-result/v1";
pub const CONTRACT_VERSION: &str = "github-secret-scanning-result-01-layer-1/v1";
pub const PLUGIN_ID: &str = "github.secret-scanning-result";
pub const PLUGIN_VERSION: &str = "0.1.0";
pub const SERVICE_ID: &str = "security.github.secret-scanning.result.read";
pub const PROVIDER_ID: &str = "github.secret-scanning.result.recording";
pub const CONSUMER_ID: &str = "mission.github-secret-scanning-result.consumer";
pub const PROVIDER_API_REVISION: &str = "github-secret-scanning-read-v1";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const PROVIDER_VERSION: &str = PLUGIN_VERSION;
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.github-secret-scanning-result/v1|github-secret-scanning-result-01-layer-1/v1|github.secret-scanning-result|security.github.secret-scanning.result.read|github.secret-scanning.result.recording|mission.github-secret-scanning-result.consumer";
pub const EVIDENCE_POLICY_INPUT: &str = "github-secret-scanning-result/evidence-policy/v1|alert-number-state-times|secret-type-digest|validity-class|installation-organization-repository-ref-commit-digests|path-region-digests|push-protection-metadata|redacted-request-rate-receipts|no-secret|no-token|no-raw-location|no-code|no-comments|no-reviewer-pii";

// Endpoint suffixes are kept separately from the owner/org path so request
// construction can bind their digests without retaining a raw receipt.
pub const ALERTS_REPOSITORY_ENDPOINT: &str = "/secret-scanning/alerts";
pub const ALERTS_ORG_ENDPOINT: &str = "/secret-scanning/alerts";
pub const ALERT_ENDPOINT: &str = "/secret-scanning/alerts";

pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/github-secret-scanning-result/github-secret-scanning-result.v1.json"
);

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

/// Layer 1 has no native credential/environment probe. This is a fixed
/// honesty result, not a claim about the host environment.
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
    pub const fn connected() -> bool {
        false
    }

    pub const fn native() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }

    pub const fn truth() -> bool {
        false
    }

    pub const fn consent() -> bool {
        false
    }

    pub const fn effect() -> bool {
        false
    }

    pub const fn receipt() -> bool {
        false
    }

    pub const fn verification() -> bool {
        false
    }

    pub const fn outcome() -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubSecretScanningContract;

impl GithubSecretScanningContract {
    pub fn baseline() -> Result<Self, serde_json::Error> {
        validate_contract()
            .map(|()| Self)
            .map_err(|error| serde_json::Error::io(std::io::Error::other(error.to_string())))
    }

    pub const fn schema_version() -> &'static str {
        CONTRACT_SCHEMA
    }

    pub const fn version() -> &'static str {
        CONTRACT_VERSION
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }
}

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
        contract["service"]["type"] == "GithubSecretScanningService",
    )?;
    is("service.id", contract["service"]["id"] == SERVICE_ID)?;
    is("service.readOnly", contract["service"]["readOnly"] == true)?;
    is(
        "service.liveExecution",
        contract["service"]["liveExecution"] == false,
    )?;
    is(
        "provider.type",
        contract["provider"]["type"] == "GithubSecretScanningProvider",
    )?;
    is(
        "provider.id",
        contract["provider"]["id"] == "github.secret-scanning.result.recording",
    )?;
    is(
        "provider.apiRevision",
        contract["provider"]["apiRevision"] == PROVIDER_API_REVISION,
    )?;
    for field in ["native", "connected", "firstParty", "externalWrites"] {
        is("provider.honesty", contract["provider"][field] == false)?;
    }
    is(
        "provider.requiredQuery.hide_secret",
        contract["provider"]["requiredQuery"]["hide_secret"] == true,
    )?;
    is(
        "provider.requiredQuery.explicitPagination",
        contract["provider"]["requiredQuery"]["explicitPagination"] == true,
    )?;
    is(
        "consumer.type",
        contract["consumer"]["type"] == "MissionGithubSecretScanningConsumer",
    )?;
    is("consumer.id", contract["consumer"]["id"] == CONSUMER_ID)?;
    for field in [
        "producesDecisionProposal",
        "adoptsKernelOutcome",
        "truthAuthority",
    ] {
        let expected = field == "producesDecisionProposal";
        is(
            "consumer.authority",
            contract["consumer"][field] == expected,
        )?;
    }
    is(
        "credentials.serialized",
        contract["credentials"]["serialized"] == false,
    )?;
    is(
        "credentials.rawMaterialAccepted",
        contract["credentials"]["rawMaterialAccepted"] == false,
    )?;
    is(
        "permissions.writePermissions",
        contract["permissions"]["writePermissions"] == false,
    )?;
    is("query.hideSecret", contract["query"]["hideSecret"] == true)?;
    is(
        "query.explicitPagination",
        contract["query"]["explicitPagination"] == true,
    )?;
    is(
        "registration.reversible",
        contract["registration"]["reversible"] == true,
    )?;
    is(
        "registration.revocable",
        contract["registration"]["revocable"] == true,
    )?;
    for field in [
        "literalSecret",
        "tokenValue",
        "rawLocationPath",
        "rawLocationContext",
        "codeLines",
        "comments",
        "reviewerPii",
    ] {
        let evidence = &contract["evidence"]["notRetained"];
        is(
            "evidence.notRetained",
            evidence
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
        "resolve_secret_scanning_alert",
        "reopen_secret_scanning_alert",
        "bypass_push_protection",
        "mutate_custom_patterns",
        "retrieve_secret",
        "export_raw_location",
        "export_raw_code",
        "webhook_authority",
        "remediation_commit",
        "claim_connected",
        "claim_native",
        "claim_first_party",
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

pub fn contract_bounds_tripwire() -> bool {
    validate_contract().is_ok()
        && !Layer1Authority::connected()
        && !Layer1Authority::native()
        && !Layer1Authority::first_party()
        && !Layer1Authority::truth()
        && !Layer1Authority::outcome()
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_is_layer_one_and_honest() {
        validate_contract().expect("checked contract validates");
        assert_eq!(
            GithubSecretScanningContract::baseline().unwrap().digest(),
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
