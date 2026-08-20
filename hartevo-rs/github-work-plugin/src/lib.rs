//! Mission-scoped GitHub App repository work read and proposal boundary.
//!
//! Layer 1 deliberately ends at an authenticated, repository-scoped read
//! projection and a canonical proposal.  The provider has no write method,
//! no Store/keyring/Browser Profile handle, and no Effect execution path.
//! Layer 2 can consume the proposal through the existing Effect Broker after
//! approval, receipt, readback, and reconciliation are designed separately.

#![deny(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use hartevo_plugin_runtime::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId, Digest, PluginContributions,
    PluginDefinition, PluginError, PluginId, PluginScope, PluginVersion, ProviderCardinality,
    ProviderDefinition, ProviderId, ServiceDefinition, ServiceId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod transport;

pub use consumer::{
    DevWorkService, GithubWorkProposalInput, GithubWorkService, MissionGithubWorkConsumer,
    MissionGithubWorkProposalResult, MissionGithubWorkReadResult,
};
pub use model::{
    GithubCheckRunProjection, GithubEndpoint, GithubHttpRequest, GithubHttpResponse,
    GithubHttpResponseBody, GithubHttpResponseReceipt, GithubIssueProjection, GithubPageReceipt,
    GithubPermissionReceipt, GithubProposalTarget, GithubPullRequestProjection,
    GithubRateLimitReceipt, GithubRepositoryProjection, GithubWorkProposal,
    GithubWorkReadProjection, GithubWorkReadRequest, GithubWorkResultMetadata,
};
pub use provider::{
    BlockedEnvCredentialResolver, EnvironmentGithubAppCredentialResolver, GITHUB_PROVIDER_ID,
    GITHUB_WORK_ADAPTER_ID, GITHUB_WORK_ADAPTER_VERSION, GITHUB_WORK_PROVIDER_REGISTRY_VERSION,
    GithubAppCredentialResolver, GithubAppProbeReceipt, GithubAppWorkConnection,
    GithubAppWorkProvider, GithubInstallationProjection, GithubWorkProviderRevision,
    github_work_provider_registry, native_probe_from_environment,
};
pub use transport::{
    GithubTransportError, GithubWorkHttpTransport, LoopbackGithubWorkTransport,
    UreqGithubAppTransport,
};

pub const GITHUB_WORK_SCHEMA_VERSION: &str = "hartevo.github-work-plugin/v1";
pub const GITHUB_WORK_CONTRACT_VERSION: &str = "github-work-e1/v1";
pub const GITHUB_WORK_PLUGIN_ID: &str = "github-work";
pub const GITHUB_WORK_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const DEV_WORK_SERVICE_ID: &str = "dev-work.service";
pub const DEV_WORK_SERVICE_NAME: &str = "DevWorkService";
pub const GITHUB_WORK_PROVIDER_ID: &str = "github-app-work";
pub const GITHUB_WORK_PROVIDER_NAME: &str = "GitHubAppWorkProvider";
pub const MISSION_GITHUB_WORK_CONSUMER_ID: &str = "mission.github-work-consumer";
pub const MISSION_GITHUB_WORK_CONSUMER_NAME: &str = "MissionGithubWorkConsumer";
pub const GITHUB_WORK_SERVICE_SCHEMA: &str = "hartevo.dev-work-service/v1";
pub const GITHUB_WORK_PROVIDER_SCHEMA: &str = "hartevo.github-app-work-provider/v1";
pub const GITHUB_WORK_CONSUMER_SCHEMA: &str = "hartevo.mission-github-work-consumer/v1";
pub const GITHUB_WORK_CAPABILITY_ID: &str = "github.work.read";
pub const GITHUB_WORK_PROPOSAL_CAPABILITY_ID: &str = "github.work.proposal";
pub const GITHUB_API_VERSION: &str = "2022-11-28";
pub const GITHUB_ACCEPT_HEADER: &str = "application/vnd.github+json";
pub const GITHUB_WORK_MAX_PAGE_SIZE: u32 = 100;
pub const GITHUB_WORK_MAX_PAGES: u32 = 100;
pub const GITHUB_WORK_NATIVE_PROBE_GATE: &str = "HARTEVO_GITHUB_APP_NATIVE_PROBE=1";
pub const GITHUB_WORK_NATIVE_PROBE_ENV: &str = "HARTEVO_GITHUB_APP_NATIVE_PROBE";
pub const GITHUB_WORK_CREDENTIAL_ENV: &str = "HARTEVO_GITHUB_APP_INSTALLATION_TOKEN";
pub const GITHUB_WORK_API_BASE_URL: &str = "https://api.github.com";

pub const GITHUB_REQUIRED_PERMISSIONS: [(&str, &str); 4] = [
    ("metadata", "read"),
    ("issues", "read"),
    ("pull_requests", "read"),
    ("checks", "read"),
];

pub const GITHUB_REQUIRED_SCOPES: [&str; 4] = [
    "metadata:read",
    "issues:read",
    "pull_requests:read",
    "checks:read",
];

pub const GITHUB_WORK_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/github-work/github-work.v1.json");

/// The checked-in contract is the immutable root of the plugin digest.
pub fn github_work_plugin_digest() -> String {
    sha256_bytes(GITHUB_WORK_CONTRACT_JSON.as_bytes())
}

pub fn github_work_plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Builds the plugin-runtime contribution set for one exact Project/Mission
/// scope.  The runtime owns registration, generation fencing, and reversible
/// unmount/revocation; this crate owns only the typed contributions.
pub fn plugin_definition(scope: PluginScope) -> Result<PluginDefinition, GithubWorkError> {
    let plugin_id = PluginId::new(GITHUB_WORK_PLUGIN_ID)?;
    let service_id = ServiceId::new(DEV_WORK_SERVICE_ID)?;
    let provider_id = ProviderId::new(GITHUB_WORK_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(MISSION_GITHUB_WORK_CONSUMER_ID)?;
    let version = github_work_plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            Digest::from_text(GITHUB_WORK_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            Digest::from_text(GITHUB_WORK_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            Digest::from_text(GITHUB_WORK_CONSUMER_SCHEMA),
        )?],
        events: Vec::new(),
        ui_surfaces: Vec::new(),
    };
    Ok(PluginDefinition::new(
        plugin_id,
        version,
        scope,
        contributions,
    )?)
}

/// The root contract is parsed in tests and by callers that need a typed
/// contract receipt without granting the document authority by itself.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubWorkContract {
    pub schema_version: String,
    pub contract_version: String,
    pub service: String,
    pub provider: String,
    pub consumer: String,
    pub authority: String,
    pub transport: String,
    pub api_version: String,
    pub operations: Vec<String>,
    pub required_permissions: BTreeMap<String, String>,
    pub read_only: bool,
    pub external_mutation: bool,
    pub proposal_only: bool,
    pub pagination: GithubWorkPaginationContract,
    pub forbidden_authorities: Vec<String>,
    pub native_probe: GithubWorkNativeProbeContract,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubWorkPaginationContract {
    pub max_page_size: u32,
    pub max_pages: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubWorkNativeProbeContract {
    pub env_gate: String,
    pub credential_env: String,
    pub status_without_gate: String,
}

impl GithubWorkContract {
    pub fn baseline() -> Result<Self, GithubWorkError> {
        let contract = serde_json::from_str::<Self>(GITHUB_WORK_CONTRACT_JSON)
            .map_err(|error| GithubWorkError::Contract(error.to_string()))?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn digest(&self) -> String {
        github_work_plugin_digest()
    }

    pub fn validate(&self) -> Result<(), GithubWorkError> {
        let expected_operations = [
            "probe_installation",
            "probe_repository",
            "read_issue",
            "read_pull_request",
            "read_check_runs",
            "propose_issue_comment",
            "propose_pull_request_comment",
            "propose_pull_request_update",
        ];
        let expected_permissions = GITHUB_REQUIRED_PERMISSIONS
            .into_iter()
            .map(|(name, level)| (name.to_owned(), level.to_owned()))
            .collect::<BTreeMap<_, _>>();
        if self.schema_version != GITHUB_WORK_SCHEMA_VERSION
            || self.contract_version != GITHUB_WORK_CONTRACT_VERSION
            || self.service != DEV_WORK_SERVICE_NAME
            || self.provider != GITHUB_WORK_PROVIDER_NAME
            || self.consumer != MISSION_GITHUB_WORK_CONSUMER_NAME
            || self.authority != "repository_scoped_read_and_proposal"
            || self.transport != "github_app_installation_access_token_over_https"
            || self.api_version != GITHUB_API_VERSION
            || self.operations != expected_operations
            || self.required_permissions != expected_permissions
            || !self.read_only
            || self.external_mutation
            || !self.proposal_only
            || self.pagination.max_page_size != GITHUB_WORK_MAX_PAGE_SIZE
            || self.pagination.max_pages != GITHUB_WORK_MAX_PAGES
            || self.forbidden_authorities
                != vec![
                    "store".to_owned(),
                    "keyring".to_owned(),
                    "browser_profile".to_owned(),
                    "effect_execution".to_owned(),
                ]
            || self.native_probe.env_gate != GITHUB_WORK_NATIVE_PROBE_GATE
            || self.native_probe.credential_env != GITHUB_WORK_CREDENTIAL_ENV
            || self.native_probe.status_without_gate != "BLOCKED_ENV"
        {
            return Err(GithubWorkError::Contract(
                "github work contract does not match the checked-in Layer 1 baseline".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GithubWorkError {
    #[error("BLOCKED_ENV: GitHub App native probe is disabled or its token is unavailable")]
    BlockedEnv,
    #[error("GitHub Work input is invalid: {0}")]
    InvalidInput(String),
    #[error("GitHub Work contract is invalid: {0}")]
    Contract(String),
    #[error("GitHub Work scope mismatch: {0}")]
    ScopeMismatch(String),
    #[error("GitHub App credential or authentication session expired")]
    AuthExpired,
    #[error("GitHub App credential or provider registration was revoked")]
    Revoked,
    #[error("GitHub App installation was revoked or no longer owns the repository")]
    InstallationRevoked,
    #[error("GitHub repository was revoked or is no longer selected by the installation")]
    RepositoryRevoked,
    #[error("GitHub App permission receipt drifted from the mounted registration")]
    PermissionDrift,
    #[error("GitHub read response was not modified and no cached projection was supplied")]
    NotModified,
    #[error("GitHub Work requested issue, pull request, or check run was not found")]
    ItemNotFound,
    #[error("GitHub Work read is fenced by a stale head SHA")]
    StaleHead,
    #[error("GitHub Work pagination is invalid: {0}")]
    Pagination(String),
    #[error("GitHub App provider rejected the request: {0}")]
    Unauthorized(String),
    #[error("GitHub App provider rate limit is exhausted until {reset_at}")]
    RateLimited { reset_at: String },
    #[error("GitHub App transport failed: {0}")]
    Transport(String),
    #[error("GitHub App response could not be decoded: {0}")]
    Decode(String),
    #[error("GitHub Work plugin runtime rejected the definition: {0}")]
    Plugin(PluginError),
}

impl From<PluginError> for GithubWorkError {
    fn from(error: PluginError) -> Self {
        Self::Plugin(error)
    }
}

impl From<hartevo_connector_sdk::ConnectorError> for GithubWorkError {
    fn from(error: hartevo_connector_sdk::ConnectorError) -> Self {
        match error {
            hartevo_connector_sdk::ConnectorError::InvalidCredentialLease
            | hartevo_connector_sdk::ConnectorError::InvalidAuthSession
            | hartevo_connector_sdk::ConnectorError::GenerationMismatch
            | hartevo_connector_sdk::ConnectorError::ProbeExpired => Self::AuthExpired,
            hartevo_connector_sdk::ConnectorError::ScopeMismatch
            | hartevo_connector_sdk::ConnectorError::ProbeScopeMismatch => {
                Self::ScopeMismatch(error.to_string())
            }
            other => Self::Transport(other.to_string()),
        }
    }
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn digest_json<T: Serialize>(value: &T) -> Result<String, GithubWorkError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| GithubWorkError::InvalidInput(error.to_string()))?;
    Ok(sha256_bytes(&bytes))
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn valid_github_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn validate_text(
    value: &str,
    field: &str,
    max_bytes: usize,
) -> Result<(), GithubWorkError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(GithubWorkError::InvalidInput(format!(
            "{field} must be non-empty, trimmed, and bounded"
        )));
    }
    Ok(())
}

pub(crate) fn validate_identifier(value: &str, field: &str) -> Result<(), GithubWorkError> {
    if value.is_empty()
        || value.len() > 128
        || value.chars().any(char::is_control)
        || value.contains('/') && field != "full_name"
    {
        return Err(GithubWorkError::InvalidInput(format!(
            "{field} is not a valid bounded identifier"
        )));
    }
    Ok(())
}

pub(crate) fn required_permissions() -> BTreeMap<String, String> {
    GITHUB_REQUIRED_PERMISSIONS
        .into_iter()
        .map(|(name, level)| (name.to_owned(), level.to_owned()))
        .collect()
}

pub(crate) fn required_scopes() -> BTreeSet<String> {
    GITHUB_REQUIRED_SCOPES
        .into_iter()
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests;
