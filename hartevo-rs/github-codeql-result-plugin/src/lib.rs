//! Standalone Layer-1 GitHub CodeQL/code-scanning result boundary.
//!
//! The crate is a bounded read/proposal/recording seam. It never resolves an
//! App or OAuth credential, performs native HTTPS, retains source or raw SARIF,
//! mutates GitHub, claims vulnerability absence, or adopts a kernel Outcome.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::similar_names)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::if_not_else)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    AdoptionAvailability, ConsumerError, ConsumerRegistration, MissionCodeqlDecisionState,
    MissionGithubCodeqlConsumer, MissionGithubCodeqlResult,
};
pub use model::{
    AlertFingerprint, AlertNumber, AlertSeverity, AlertState, AnalysisId, AnalysisStatus,
    CodeScanningTool, CommitSha, Digest, GithubAuthKind, GithubCodeqlScope, InstallationId,
    MissionId, MissionScopeBinding, Permission, PermissionSnapshot, ProjectId, RedactedLocation,
    RefName, RegistrationId, RegistrationState, RepositoryIdentity, Revision, RuleAllowlist,
    RuleId, SecretReference, TransportProvenance, Version, WorkProductId,
};
pub use provider::{
    AlertPage, AlertRecord, AlertSummary, AnalysisPage, AnalysisRecord, AnalysisSummary,
    BlockedEnvTransport, CodeqlReadRequest, FixtureTransport, GetAlertRequest,
    GithubCodeScanningApiVersion, GithubCodeScanningProvider, GithubCodeScanningProviderDefinition,
    GithubCodeScanningTransport, GithubProviderDefinition, ListAlertsRequest, ListAnalysesRequest,
    LoopbackTransport, OpaquePageToken, ProviderDefinitionError, ProviderError, ProviderErrorKind,
    ProviderProvenance, ReadScript, RecordingTransport, TransportError, TransportRequestRecord,
};
pub use service::{
    CodeqlResultEvidence, CodeqlResultProposal, CodeqlResultRecording,
    GithubCodeqlCapabilityDescription, GithubCodeqlRegistration, GithubCodeqlResultProjection,
    GithubCodeqlResultService, GithubCodeqlResultServiceDefinition, GithubCodeqlServiceDefinition,
    ProjectionState, ProposalDisposition, ReadLimits, ServiceError,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.github-codeql-result/v1";
pub const CONTRACT_VERSION: &str = "github-codeql-result-01-layer-1/v1";
pub const PLUGIN_ID: &str = "github.codeql-result";
pub const PLUGIN_VERSION: &str = "0.1.0";
pub const SERVICE_ID: &str = "security.github.codeql.result.read";
pub const PROVIDER_ID: &str = "github.codeql.result.recording";
pub const CONSUMER_ID: &str = "mission.github-codeql-result.consumer";
pub const PROVIDER_API_REVISION: &str = "github-code-scanning-read-v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.github-codeql-result/v1|github-codeql-result-01-layer-1/v1|github.codeql-result|security.github.codeql.result.read|github.codeql.result.recording|mission.github-codeql-result.consumer";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/github-codeql-result/service.v1.json");
pub const ALERTS_ENDPOINT: &str = "/repos/{owner}/{repo}/code-scanning/alerts";
pub const ALERT_ENDPOINT: &str = "/repos/{owner}/{repo}/code-scanning/alerts/{alertNumber}";
pub const ANALYSES_ENDPOINT: &str = "/repos/{owner}/{repo}/code-scanning/analyses";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";

/// The stable digest of the contract identity input, excluding the JSON
/// document itself so the checked-in document can carry the digest.
pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContractValidationError {
    #[error("contract JSON is invalid: {0}")]
    Json(String),
    #[error("contract field {0} is not the frozen Layer-1 value")]
    FrozenField(&'static str),
}

/// Validate the checked-in contract and its authority/honesty pins.
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
    is(
        "evidenceLevel",
        contract["evidenceLevel"] == "L1_PROVIDER_CONTRACT",
    )?;
    is(
        "service.type",
        contract["service"]["type"] == "GithubCodeqlResultService",
    )?;
    is("service.id", contract["service"]["id"] == SERVICE_ID)?;
    is(
        "service.access",
        contract["service"]["access"] == "read_only",
    )?;
    is(
        "service.liveExecution",
        contract["service"]["liveExecution"] == false,
    )?;
    is(
        "service.proposalsBelowKernel",
        contract["service"]["proposalsBelowKernel"] == true,
    )?;
    is(
        "provider.type",
        contract["provider"]["type"] == "GithubCodeScanningProvider",
    )?;
    is("provider.id", contract["provider"]["id"] == PROVIDER_ID)?;
    is(
        "provider.apiRevision",
        contract["provider"]["apiRevision"] == PROVIDER_API_REVISION,
    )?;
    is("provider.native", contract["provider"]["native"] == false)?;
    is(
        "provider.allowedTransportProvenance",
        contract["provider"]["allowedTransportProvenance"]
            == serde_json::json!(["fixture", "recording", "loopback", "BLOCKED_ENV"]),
    )?;
    for field in [
        "dismissAlert",
        "fixAlert",
        "uploadSarif",
        "triggerAnalysis",
        "mutateBranch",
        "mutatePullRequest",
        "resolveSecret",
        "adoptOutcome",
    ] {
        is(
            "provider.mutations",
            contract["provider"]["mutations"][field] == false,
        )?;
    }
    is(
        "consumer.type",
        contract["consumer"]["type"] == "MissionGithubCodeqlConsumer",
    )?;
    is("consumer.id", contract["consumer"]["id"] == CONSUMER_ID)?;
    is(
        "consumer.adoptsKernelOutcome",
        contract["consumer"]["adoptsKernelOutcome"] == false,
    )?;
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
    is(
        "registration.reversible",
        contract["registration"]["reversible"] == true,
    )?;
    is(
        "registration.revocable",
        contract["registration"]["revocable"] == true,
    )?;
    is(
        "evidence.rawSource",
        contract["evidence"]["rawSource"] == false,
    )?;
    is(
        "evidence.rawSarif",
        contract["evidence"]["rawSarif"] == false,
    )?;
    is(
        "evidence.userIdentity",
        contract["evidence"]["userIdentity"] == false,
    )?;
    is(
        "evidence.secretValue",
        contract["evidence"]["secretValue"] == false,
    )?;
    is(
        "evidence.unboundedLocations",
        contract["evidence"]["unboundedLocations"] == false,
    )?;
    for field in [
        "connectedClaim",
        "nativeClaim",
        "firstPartyClaim",
        "durableProviderReceipt",
    ] {
        is("provenance", contract["provenance"][field] == false)?;
    }
    Ok(())
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_is_valid_and_layer_one_is_honest() {
        validate_contract().expect("contract validates");
        assert_eq!(contract_digest(), contract_digest());
        assert_eq!(BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!CONTRACT_JSON.is_empty());
    }
}
