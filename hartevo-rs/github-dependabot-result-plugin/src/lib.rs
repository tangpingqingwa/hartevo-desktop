//! Layer-1 governed GitHub Dependabot security-result plugin.
//!
//! This crate is intentionally standalone. It owns a versioned contract, a
//! typed read-only provider seam, bounded evidence/proposal/record/verify
//! lifecycle, and a Mission consumer for a supply-chain decision. It does not
//! resolve App/OAuth credentials, make live HTTPS calls, mutate Dependabot
//! alerts, export a dependency graph, issue remediation instructions, mint a
//! durable native receipt, adopt an Outcome, or claim Connected/native/
//! first-party authority.

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
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

mod consumer;
mod model;
mod provider;
mod service;

#[cfg(test)]
mod adversarial_tests;

pub use consumer::{
    ConsumerError, MissionGithubDependabotConsumer, MissionGithubDependabotConsumerError,
    MissionGithubDependabotDecision, MissionGithubDependabotDecisionState,
    MissionGithubDependabotResult,
};
pub use model::{
    AdvisoryIdentifier, AlertFilter, AlertNumber, AlertRevision, AlertState, CommitSha,
    DependabotAlert, DependabotAlertBinding, DependabotEvidenceState, DeploymentBinding,
    DeploymentId, Digest, GithubAuthKind, GithubDependabotEvidence, GithubDependabotReadOperation,
    GithubDependabotReadPage, GithubDependabotReadRequest, GithubDependabotScope, GithubRepository,
    MAX_ALERTS, MAX_ALERTS_PER_PAGE, MAX_CURSOR_BYTES, MAX_IDENTIFIER_BYTES, MAX_PAGES,
    MAX_PROVIDER_ERRORS, MAX_REQUESTS_PER_READ, MAX_RESPONSE_BYTES, MAX_RETRIES, ManifestPath,
    MissionBinding, MissionId, ModelError, OpaqueCursor, PAGE_SIZE, PackageEcosystem, PackageName,
    PartialReason, PermissionAction, PermissionFence, PermissionId, ProjectBinding, ProjectId,
    ProviderErrorEvidence, ProviderErrorKind, ProviderId, ProviderRevision, RefName,
    RepositoryName, RepositoryOwner, Revision, SecretReference, Severity, TransportError,
    TransportProvenance, WorkProductBinding, WorkProductId, digest_serialized, sha256_digest,
};
pub use provider::{
    BlockedEnvGithubDependabotTransport, BlockedEnvTransport, FakeGithubDependabotTransport,
    FixtureGithubDependabotTransport, GithubDependabotProvider, GithubDependabotProviderDefinition,
    GithubDependabotProviderError, GithubDependabotProviderIdentity, GithubDependabotTransport,
    LoopbackGithubDependabotTransport, ProviderDefinitionError, ProviderProvenance,
    RecordingGithubDependabotTransport, is_access_loss,
};
pub use service::{
    GithubDependabotProposal, GithubDependabotProviderErrorEvidence, GithubDependabotReadResult,
    GithubDependabotRecordReceipt, GithubDependabotRegistration,
    GithubDependabotRegistrationReceipt, GithubDependabotResultProposal,
    GithubDependabotResultService, GithubDependabotResultServiceDefinition,
    GithubDependabotService, GithubDependabotServiceDefinition, GithubDependabotServiceError,
    GithubDependabotServiceErrorAlias, GithubDependabotTransportProvenance,
    GithubDependabotVerifiedRecord, RegistrationError, RegistrationState,
};

pub const GITHUB_DEPENDABOT_SCHEMA_VERSION: &str = "hartevo.github-dependabot-result.contract/v1";
pub const GITHUB_DEPENDABOT_CONTRACT_VERSION: &str = "github-dependabot-result/v1";
pub const GITHUB_DEPENDABOT_PLUGIN_VERSION: &str = "1.0.0";
pub const GITHUB_DEPENDABOT_API_REVISION: &str = "github-dependabot-read-r1";
pub const GITHUB_DEPENDABOT_SERVICE_ID: &str = "hartevo.github.dependabot.result";
pub const GITHUB_DEPENDABOT_PROVIDER_ID: &str = "github.dependabot";
pub const GITHUB_DEPENDABOT_CONSUMER_ID: &str = "mission.github.dependabot.result";
pub const GITHUB_DEPENDABOT_EVIDENCE_LEVEL: &str = "E1";
pub const GITHUB_DEPENDABOT_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const GITHUB_DEPENDABOT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/github-dependabot-result/github-dependabot-result.v1.json"
);

pub type GithubDependabotProviderScope = GithubDependabotScope;
pub type GithubDependabotAlertState = AlertState;
pub type GithubDependabotPackageEcosystem = PackageEcosystem;
pub type GithubDependabotSeverity = Severity;
pub type GithubDependabotAlertScope = DependabotAlertBinding;
pub type GithubDependabotAlertEvidence = DependabotAlert;
pub type GithubDependabotResultEvidence = GithubDependabotEvidence;
pub type GithubSecretReference = SecretReference;

pub fn contract_digest() -> Digest {
    Digest::from_text(GITHUB_DEPENDABOT_CONTRACT_JSON)
}

/// Authority flags exposed by Layer 1. Every flag is deliberately false.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }

    pub const fn durable_receipt() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }

    pub const fn truth_authority() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use serde::Deserialize;

    use super::{
        GITHUB_DEPENDABOT_API_REVISION, GITHUB_DEPENDABOT_BLOCKED_ENV,
        GITHUB_DEPENDABOT_CONSUMER_ID, GITHUB_DEPENDABOT_CONTRACT_JSON,
        GITHUB_DEPENDABOT_CONTRACT_VERSION, GITHUB_DEPENDABOT_EVIDENCE_LEVEL,
        GITHUB_DEPENDABOT_PLUGIN_VERSION, GITHUB_DEPENDABOT_PROVIDER_ID,
        GITHUB_DEPENDABOT_SCHEMA_VERSION, GITHUB_DEPENDABOT_SERVICE_ID, Layer1Authority,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        plugin_version: String,
        layer: String,
        evidence_level: String,
        service: ServiceDocument,
        provider: ProviderDocument,
        consumer: ConsumerDocument,
        honesty: HonestyDocument,
        authority: AuthorityDocument,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ServiceDocument {
        id: String,
        version: String,
        read_only: bool,
        live_execution: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderDocument {
        id: String,
        api_revision: String,
        native: bool,
        connected: bool,
        first_party: bool,
        external_writes: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConsumerDocument {
        id: String,
        produces_decision_proposal: bool,
        adopts_outcome: bool,
        truth_authority: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct HonestyDocument {
        native_status: String,
        blocked_environment_is_native: bool,
        fixture_is_native: bool,
        recording_is_native: bool,
        loopback_is_native: bool,
        connected_claim: bool,
        first_party_claim: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AuthorityDocument {
        connected: bool,
        native: bool,
        first_party: bool,
        durable_receipt: bool,
        kernel_outcome_adoption: bool,
    }

    #[test]
    fn contract_document_keeps_layer_one_honest() {
        let document = serde_json::from_str::<ContractDocument>(GITHUB_DEPENDABOT_CONTRACT_JSON)
            .expect("GitHub Dependabot contract JSON");
        assert_eq!(document.schema_version, GITHUB_DEPENDABOT_SCHEMA_VERSION);
        assert_eq!(
            document.contract_version,
            GITHUB_DEPENDABOT_CONTRACT_VERSION
        );
        assert_eq!(document.plugin_version, GITHUB_DEPENDABOT_PLUGIN_VERSION);
        assert_eq!(document.layer, "Layer-1");
        assert_eq!(document.evidence_level, GITHUB_DEPENDABOT_EVIDENCE_LEVEL);
        assert_eq!(document.service.id, GITHUB_DEPENDABOT_SERVICE_ID);
        assert_eq!(document.service.version, GITHUB_DEPENDABOT_PLUGIN_VERSION);
        assert!(document.service.read_only);
        assert!(!document.service.live_execution);
        assert_eq!(document.provider.id, GITHUB_DEPENDABOT_PROVIDER_ID);
        assert_eq!(
            document.provider.api_revision,
            GITHUB_DEPENDABOT_API_REVISION
        );
        assert!(!document.provider.native);
        assert!(!document.provider.connected);
        assert!(!document.provider.first_party);
        assert!(!document.provider.external_writes);
        assert_eq!(document.consumer.id, GITHUB_DEPENDABOT_CONSUMER_ID);
        assert!(document.consumer.produces_decision_proposal);
        assert!(!document.consumer.adopts_outcome);
        assert!(!document.consumer.truth_authority);
        assert_eq!(
            document.honesty.native_status,
            GITHUB_DEPENDABOT_BLOCKED_ENV
        );
        assert!(!document.honesty.blocked_environment_is_native);
        assert!(!document.honesty.fixture_is_native);
        assert!(!document.honesty.recording_is_native);
        assert!(!document.honesty.loopback_is_native);
        assert!(!document.honesty.connected_claim);
        assert!(!document.honesty.first_party_claim);
        assert!(!document.authority.connected);
        assert!(!document.authority.native);
        assert!(!document.authority.first_party);
        assert!(!document.authority.durable_receipt);
        assert!(!document.authority.kernel_outcome_adoption);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::truth_authority());
    }
}
