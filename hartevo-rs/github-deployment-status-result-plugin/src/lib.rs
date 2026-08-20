//! Standalone Layer-1 governed GitHub Deployment and Deployment Status result
//! plugin.
//!
//! The crate exposes bounded, typed deployment metadata and paginated status
//! history reads, a proposal-only service, and a Mission consumer. It never
//! resolves credentials, opens native HTTPS, accepts webhooks, writes a
//! deployment/status, retains payload/log/source/artifact bytes, or adopts a
//! kernel Truth/Receipt/Outcome.

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
    MissionGithubDeploymentStatusConsumer, MissionGithubDeploymentStatusConsumerError,
    MissionGithubDeploymentStatusResult, MissionGithubDeploymentStatusResultState,
    MissionResultState,
};
pub use model::{
    Digest, GithubAppAuthKind, GithubAppInstallationId, GithubAuthKind, GithubCommitSha,
    GithubDeploymentId, GithubDeploymentMetadata, GithubDeploymentState,
    GithubDeploymentStatusMetadata, GithubDeploymentStatusPermission,
    GithubDeploymentStatusPermissions, GithubDeploymentStatusRegistration,
    GithubDeploymentStatusScope, GithubDeploymentStatusScopeSpec, GithubDeploymentStatusState,
    GithubEnvironment, GithubOrganization, GithubRef, GithubRefName, GithubRepository,
    GithubRepositoryName, GithubTimestamp, GithubUrlDigests, HISTORY_SECONDS, Layer1Authority,
    MAX_DIAGNOSTIC_BYTES, MAX_ENVIRONMENT_BYTES, MAX_HISTORY_DAYS, MAX_IDENTIFIER_BYTES,
    MAX_OPAQUE_HEADER_BYTES, MAX_PAGES, MAX_REF_BYTES, MAX_RESPONSE_BYTES, MAX_STATUSES,
    MAX_TIMESTAMP_BYTES, MAX_URL_BYTES, MissionBinding, ModelError, OpaqueEtag, OpaquePageToken,
    ProjectBinding, RegistrationRevocationReceipt, RegistrationState, Revision, SecretReference,
    TransportProvenance, WorkProductBinding, canonical_digest, sha256_digest,
};
pub use provider::{
    BlockedEnvGithubDeploymentStatusTransport, FixtureGithubDeploymentStatusTransport,
    GithubDeploymentStatusApiResponse, GithubDeploymentStatusFixture,
    GithubDeploymentStatusHttpMethod, GithubDeploymentStatusObservation,
    GithubDeploymentStatusOperation, GithubDeploymentStatusProvider,
    GithubDeploymentStatusProviderDefinition, GithubDeploymentStatusProviderDefinitionError,
    GithubDeploymentStatusProviderError, GithubDeploymentStatusProviderErrorKind,
    GithubDeploymentStatusRequest, GithubDeploymentStatusRequestReceipt,
    GithubDeploymentStatusResponse, GithubDeploymentStatusResponseReceipt,
    GithubDeploymentStatusTransport, GithubDeploymentStatusTransportError,
    LoopbackGithubDeploymentStatusTransport, RecordingGithubDeploymentStatusTransport,
};
pub use service::{
    GithubDeploymentStatusEvidence, GithubDeploymentStatusEvidenceState,
    GithubDeploymentStatusObservationReceipt, GithubDeploymentStatusProviderErrorEvidence,
    GithubDeploymentStatusResultProposal, GithubDeploymentStatusService,
    GithubDeploymentStatusServiceDefinition, GithubDeploymentStatusServiceError,
};

pub const GITHUB_DEPLOYMENT_STATUS_RESULT_SCHEMA_VERSION: &str =
    "hartevo.github-deployment-status-result/v1";
pub const GITHUB_DEPLOYMENT_STATUS_RESULT_CONTRACT_VERSION: &str =
    "github-deployment-status-result-e1/v1";
pub const GITHUB_DEPLOYMENT_STATUS_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const GITHUB_DEPLOYMENT_STATUS_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/github-deployment-status-result/github-deployment-status-result.v1.json";
pub const GITHUB_DEPLOYMENT_STATUS_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/github-deployment-status-result/github-deployment-status-result.v1.json"
);
pub const GITHUB_DEPLOYMENT_STATUS_SERVICE_ID: &str = "github.deployment-status.result";
pub const GITHUB_DEPLOYMENT_STATUS_PROVIDER_ID: &str = "github.deployments.deployment-status";
pub const GITHUB_DEPLOYMENT_STATUS_PROVIDER_VERSION: &str = "1.0.0";
pub const GITHUB_DEPLOYMENT_STATUS_API_REVISION: &str = "github-deployments-rest-v3";
pub const MISSION_GITHUB_DEPLOYMENT_STATUS_CONSUMER_ID: &str =
    "mission.github.deployment-status.result";
pub const GITHUB_DEPLOYMENT_STATUS_BLOCKED_ENV: &str = "BLOCKED_ENV";

#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(GITHUB_DEPLOYMENT_STATUS_RESULT_CONTRACT_JSON.as_bytes())
}

#[must_use]
pub fn version_digest() -> Digest {
    canonical_digest(&(
        "github-deployment-status-result-version/v1",
        GITHUB_DEPLOYMENT_STATUS_RESULT_PLUGIN_VERSION,
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
    pub const fn truth_authority() -> bool {
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
        GITHUB_DEPLOYMENT_STATUS_API_REVISION, GITHUB_DEPLOYMENT_STATUS_PROVIDER_ID,
        GITHUB_DEPLOYMENT_STATUS_RESULT_CONTRACT_JSON,
        GITHUB_DEPLOYMENT_STATUS_RESULT_CONTRACT_VERSION,
        GITHUB_DEPLOYMENT_STATUS_RESULT_SCHEMA_VERSION, GITHUB_DEPLOYMENT_STATUS_SERVICE_ID,
        Layer1Capabilities, MISSION_GITHUB_DEPLOYMENT_STATUS_CONSUMER_ID, contract_digest,
    };

    #[test]
    fn contract_is_machine_readable_and_layer_one_honest() {
        let document: Value = serde_json::from_str(GITHUB_DEPLOYMENT_STATUS_RESULT_CONTRACT_JSON)
            .expect("GitHub deployment-status result contract JSON");
        assert_eq!(
            document["schemaVersion"],
            GITHUB_DEPLOYMENT_STATUS_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            GITHUB_DEPLOYMENT_STATUS_RESULT_CONTRACT_VERSION
        );
        assert_eq!(document["layer"], 1);
        assert_eq!(
            document["service"]["id"],
            GITHUB_DEPLOYMENT_STATUS_SERVICE_ID
        );
        assert_eq!(
            document["provider"]["id"],
            GITHUB_DEPLOYMENT_STATUS_PROVIDER_ID
        );
        assert_eq!(
            document["provider"]["apiRevision"],
            GITHUB_DEPLOYMENT_STATUS_API_REVISION
        );
        assert_eq!(
            document["consumer"]["id"],
            MISSION_GITHUB_DEPLOYMENT_STATUS_CONSUMER_ID
        );
        assert_eq!(document["authority"]["connected"], false);
        assert_eq!(document["authority"]["nativeProvider"], false);
        assert_eq!(document["authority"]["outcomeAuthority"], false);
        assert_eq!(document["provider"]["writes"], false);
        assert_eq!(document["provider"]["maxHistoryDays"], 90);
        assert_eq!(
            document["allowlist"]["writes"].as_array().map(Vec::len),
            Some(0)
        );
        assert!(!contract_digest().is_empty());
        assert!(!Layer1Capabilities::connected());
        assert!(!Layer1Capabilities::native_provider());
        assert!(!Layer1Capabilities::durable_receipt());
        assert!(!Layer1Capabilities::kernel_authority());
        assert!(!Layer1Capabilities::truth_authority());
        assert!(!Layer1Capabilities::outcome_authority());
        assert!(!Layer1Capabilities::external_writes());
    }
}
