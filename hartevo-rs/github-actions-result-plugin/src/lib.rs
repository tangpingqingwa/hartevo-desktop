//! Standalone Layer-1 governed GitHub Actions workflow result plugin.
//!
//! The crate exposes bounded, typed workflow-run/job/artifact metadata reads
//! and proposal-only Mission evidence. It never resolves credentials, opens a
//! native GitHub connection, downloads logs/source/ZIP bytes, performs a
//! workflow effect, claims green CI from missing jobs, or adopts a kernel
//! Outcome.

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::if_not_else)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::result_large_err)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::struct_excessive_bools)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    MissionGithubActionsConsumer, MissionGithubActionsConsumerError, MissionGithubActionsResult,
    MissionGithubActionsResultState, MissionResultState,
};
pub use model::{
    Attempt, CommitSha, Digest, GithubActionsConclusion, GithubActionsPermission,
    GithubActionsPermissions, GithubActionsRegistration, GithubActionsScope,
    GithubActionsScopeSpec, GithubAppAuthKind, GithubAppInstallationId, GithubArtifactMetadata,
    GithubAuthKind, GithubCommitSha, GithubJobId, GithubJobMetadata, GithubJobStatus,
    GithubOrganization, GithubRepository, GithubRepositoryName, GithubRunAttempt, GithubTimestamp,
    GithubWorkflowId, GithubWorkflowRunId, GithubWorkflowRunMetadata, GithubWorkflowRunStatus,
    InstallationId, JobId, Layer1Authority, MAX_ARTIFACT_NAME_BYTES, MAX_ARTIFACT_SIZE_BYTES,
    MAX_ARTIFACTS, MAX_DIAGNOSTIC_BYTES, MAX_IDENTIFIER_BYTES, MAX_JOBS, MAX_PAGES,
    MAX_RESPONSE_BYTES, MAX_TIMESTAMP_BYTES, MissionBinding, ModelError, OpaqueEtag,
    OpaquePageToken, Organization, ProjectBinding, RegistrationRevocationReceipt,
    RegistrationState, RepositoryName, Revision, SecretReference, TransportProvenance,
    WorkProductBinding, WorkflowId, WorkflowRunId, canonical_digest, sha256_digest,
};
pub use provider::{
    BlockedEnvGithubActionsTransport, FixtureGithubActionsTransport, GithubActionsApiResponse,
    GithubActionsFixture, GithubActionsHttpMethod, GithubActionsObservation,
    GithubActionsOperation, GithubActionsProvider, GithubActionsProviderDefinition,
    GithubActionsProviderDefinitionError, GithubActionsProviderError,
    GithubActionsProviderErrorKind, GithubActionsRequest, GithubActionsRequestReceipt,
    GithubActionsResponse, GithubActionsResponseReceipt, GithubActionsTransport,
    GithubActionsTransportError, LoopbackGithubActionsTransport, RecordingGithubActionsTransport,
};
pub use service::{
    GithubActionsEvidence, GithubActionsEvidenceState, GithubActionsObservationReceipt,
    GithubActionsProviderErrorEvidence, GithubActionsResultProposal, GithubActionsResultService,
    GithubActionsResultServiceDefinition, GithubActionsResultServiceError,
};

pub const GITHUB_ACTIONS_RESULT_SCHEMA_VERSION: &str = "hartevo.github-actions-result/v1";
pub const GITHUB_ACTIONS_RESULT_CONTRACT_VERSION: &str = "github-actions-result-e1/v1";
pub const GITHUB_ACTIONS_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const GITHUB_ACTIONS_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/github-actions-result/github-actions-result.v1.json";
pub const GITHUB_ACTIONS_RESULT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/github-actions-result/github-actions-result.v1.json");
pub const GITHUB_ACTIONS_RESULT_SERVICE_ID: &str = "github.actions.result";
pub const GITHUB_ACTIONS_PROVIDER_ID: &str = "github.actions.workflow-result";
pub const GITHUB_ACTIONS_PROVIDER_VERSION: &str = "1.0.0";
pub const GITHUB_ACTIONS_API_REVISION: &str = "github-actions-rest-v3";
pub const MISSION_GITHUB_ACTIONS_CONSUMER_ID: &str = "mission.github.actions.result";
pub const GITHUB_ACTIONS_BLOCKED_ENV: &str = "BLOCKED_ENV";

#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(GITHUB_ACTIONS_RESULT_CONTRACT_JSON.as_bytes())
}

#[must_use]
pub fn version_digest() -> Digest {
    canonical_digest(&(
        "github-actions-result-version/v1",
        GITHUB_ACTIONS_RESULT_PLUGIN_VERSION,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Capabilities;

impl Layer1Capabilities {
    #[must_use]
    pub const fn connected() -> bool {
        false
    }

    #[must_use]
    pub const fn native_provider() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_receipt() -> bool {
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
    pub const fn green_ci_authority() -> bool {
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
        GITHUB_ACTIONS_API_REVISION, GITHUB_ACTIONS_PROVIDER_ID,
        GITHUB_ACTIONS_RESULT_CONTRACT_JSON, GITHUB_ACTIONS_RESULT_CONTRACT_VERSION,
        GITHUB_ACTIONS_RESULT_SCHEMA_VERSION, GITHUB_ACTIONS_RESULT_SERVICE_ID, Layer1Capabilities,
        MISSION_GITHUB_ACTIONS_CONSUMER_ID, contract_digest,
    };

    #[test]
    fn contract_is_machine_readable_and_layer_one_honest() {
        let document: Value = serde_json::from_str(GITHUB_ACTIONS_RESULT_CONTRACT_JSON)
            .expect("GitHub Actions result contract JSON");
        assert_eq!(
            document["schemaVersion"],
            GITHUB_ACTIONS_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            GITHUB_ACTIONS_RESULT_CONTRACT_VERSION
        );
        assert_eq!(document["layer"], 1);
        assert_eq!(document["service"]["id"], GITHUB_ACTIONS_RESULT_SERVICE_ID);
        assert_eq!(document["provider"]["id"], GITHUB_ACTIONS_PROVIDER_ID);
        assert_eq!(
            document["provider"]["apiRevision"],
            GITHUB_ACTIONS_API_REVISION
        );
        assert_eq!(
            document["consumer"]["id"],
            MISSION_GITHUB_ACTIONS_CONSUMER_ID
        );
        assert_eq!(document["authority"]["connected"], false);
        assert_eq!(document["authority"]["nativeProvider"], false);
        assert_eq!(document["authority"]["greenCiAuthority"], false);
        assert_eq!(
            document["allowlist"]["writes"].as_array().map(Vec::len),
            Some(0)
        );
        assert_eq!(document["provider"]["writes"], false);
        assert_eq!(document["provider"]["logs"], false);
        assert_eq!(document["provider"]["artifactZipBytes"], false);
        assert!(!contract_digest().is_empty());
        assert!(!Layer1Capabilities::connected());
        assert!(!Layer1Capabilities::native_provider());
        assert!(!Layer1Capabilities::durable_receipt());
        assert!(!Layer1Capabilities::kernel_authority());
        assert!(!Layer1Capabilities::outcome_authority());
        assert!(!Layer1Capabilities::green_ci_authority());
        assert!(!Layer1Capabilities::external_writes());
    }
}
