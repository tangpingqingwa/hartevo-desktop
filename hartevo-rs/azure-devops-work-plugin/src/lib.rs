//! Azure DevOps Work Layer-1 standalone plugin.
//!
//! This root exposes a typed read-only graph from an Azure DevOps Work Item
//! revision through its Azure Repos pull request and bounded Build Timeline /
//! Artifact metadata.  It intentionally has no write method, no raw log or
//! artifact retention, no native Connected claim, and no Outcome authority.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

use std::collections::BTreeMap;

use hartevo_plugin_runtime::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId, Digest as RuntimeDigest,
    PluginContributions, PluginDefinition, PluginError, PluginId, PluginScope, PluginVersion,
    ProviderCardinality, ProviderDefinition, ProviderId, ServiceDefinition, ServiceId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{
    AzureDevOpsWorkObservation, MissionAzureDevOpsWorkConsumer, MissionAzureDevOpsWorkReadResult,
};
pub use model::*;
pub use provider::{
    AzureDevOpsRegistration, AzureDevOpsRegistrationRequest, AzureDevOpsServicesProvider,
    BlockedEnvCredentialResolver, CredentialLease, EntraAccessToken, EntraCredentialError,
    EntraCredentialResolver, EnvironmentEntraCredentialResolver, NativeProbe, NativeProbeStatus,
    RegistrationState, native_probe_from_environment,
};
pub use service::{AzureDevOpsCapability, AzureDevOpsWorkOperation, AzureDevOpsWorkService};
pub use transport::{
    AzureDevOpsEndpoint, AzureDevOpsHttpRequest, AzureDevOpsHttpResponse,
    AzureDevOpsTransportError, AzureDevOpsWorkTransport, BlockedEnvTransport,
    FakeAzureDevOpsTransport, RecordingAzureDevOpsTransport, RequestBounds,
    UreqAzureDevOpsTransport,
};

pub const AZURE_DEVOPS_WORK_SCHEMA_VERSION: &str = "hartevo.azure-devops-work-contract/v1";
pub const AZURE_DEVOPS_WORK_CONTRACT_VERSION: &str = "azure-devops-work/v1";
pub const AZURE_DEVOPS_WORK_PLUGIN_ID: &str = "azure-devops-work";
pub const AZURE_DEVOPS_WORK_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const AZURE_DEVOPS_API_VERSION: &str = "7.1";
pub const AZURE_DEVOPS_WORK_SERVICE_ID: &str = "azure-devops.work";
pub const AZURE_DEVOPS_WORK_SERVICE_NAME: &str = "AzureDevOpsWorkService";
pub const AZURE_DEVOPS_SERVICES_PROVIDER_ID: &str = "azure-devops.services";
pub const AZURE_DEVOPS_SERVICES_PROVIDER_NAME: &str = "AzureDevOpsServicesProvider";
pub const MISSION_AZURE_DEVOPS_WORK_CONSUMER_ID: &str = "mission.azure-devops-work";
pub const MISSION_AZURE_DEVOPS_WORK_CONSUMER_NAME: &str = "MissionAzureDevOpsWorkConsumer";
pub const AZURE_DEVOPS_WORK_SERVICE_SCHEMA: &str = "hartevo.azure-devops-work-service/v1";
pub const AZURE_DEVOPS_SERVICES_PROVIDER_SCHEMA: &str = "hartevo.azure-devops-services-provider/v1";
pub const MISSION_AZURE_DEVOPS_WORK_CONSUMER_SCHEMA: &str =
    "hartevo.mission-azure-devops-work-consumer/v1";
pub const AZURE_DEVOPS_WORK_PROVIDER_REVISION: &str = "azure-devops-rest-7.1-r1";
pub const AZURE_DEVOPS_NATIVE_PROBE_GATE: &str = "HARTEVO_AZURE_DEVOPS_NATIVE_PROBE=1";
pub const AZURE_DEVOPS_NATIVE_PROBE_ENV: &str = "HARTEVO_AZURE_DEVOPS_NATIVE_PROBE";
pub const AZURE_DEVOPS_ACCESS_TOKEN_ENV: &str = "HARTEVO_AZURE_DEVOPS_ACCESS_TOKEN";
pub const AZURE_DEVOPS_API_ORIGIN: &str = "https://dev.azure.com";
pub const AZURE_DEVOPS_MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const AZURE_DEVOPS_MAX_PAGES: u16 = 4;
pub const AZURE_DEVOPS_PAGE_SIZE: u16 = 50;

pub const AZURE_DEVOPS_WORK_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/azure-devops-work/azure-devops-work.v1.json");

pub fn contract_digest() -> Digest {
    model::sha256_digest(AZURE_DEVOPS_WORK_CONTRACT_JSON.as_bytes())
}

pub fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Builds the plugin-runtime contribution set for one exact Project/Mission
/// generation.  Registration is still inert until a host defines and mounts
/// this definition in its own runtime.
pub fn plugin_definition(scope: PluginScope) -> Result<PluginDefinition, AzureDevOpsWorkError> {
    let plugin_id = PluginId::new(AZURE_DEVOPS_WORK_PLUGIN_ID)?;
    let service_id = ServiceId::new(AZURE_DEVOPS_WORK_SERVICE_ID)?;
    let provider_id = ProviderId::new(AZURE_DEVOPS_SERVICES_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(MISSION_AZURE_DEVOPS_WORK_CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(AZURE_DEVOPS_WORK_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(AZURE_DEVOPS_SERVICES_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(MISSION_AZURE_DEVOPS_WORK_CONSUMER_SCHEMA),
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureDevOpsWorkContract {
    pub schema_version: String,
    pub contract_version: String,
    pub layer: u8,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub api_version: String,
    pub api_areas: BTreeMap<String, String>,
    pub transport_provenance: Vec<String>,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub mutating_provider_operations: Vec<String>,
    pub authority: AzureDevOpsAuthorityContract,
    pub registration: AzureDevOpsRegistrationContract,
    pub scope_fence: Vec<String>,
    pub bounds: AzureDevOpsBoundsContract,
    pub receipts: AzureDevOpsReceiptsContract,
    pub native_gap: AzureDevOpsNativeGapContract,
    pub honest_native_gap: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct AzureDevOpsAuthorityContract {
    pub external_writes: bool,
    pub raw_logs: bool,
    pub raw_artifacts: bool,
    pub connected: bool,
    pub effect: bool,
    pub receipt: bool,
    pub verification: bool,
    pub outcome: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureDevOpsRegistrationContract {
    pub bound_fields: Vec<String>,
    pub reversible: bool,
    pub revocable: bool,
    pub fail_closed_on_drift: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureDevOpsBoundsContract {
    pub max_response_bytes: usize,
    pub max_work_item_relations: usize,
    pub max_builds: usize,
    pub max_timeline_records: usize,
    pub max_artifacts: usize,
    pub max_pages: u16,
    pub page_size: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct AzureDevOpsReceiptsContract {
    pub request_path_and_query: bool,
    pub api_version: bool,
    pub response_status: bool,
    pub response_size: bool,
    pub response_digest: bool,
    pub provider_revision: bool,
    pub raw_provider_payload: bool,
    pub raw_logs: bool,
    pub raw_artifacts: bool,
    pub credential_material: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureDevOpsNativeGapContract {
    pub status: String,
    pub deferred_to: String,
    pub fail_closed_cases: Vec<String>,
}

impl AzureDevOpsWorkContract {
    pub fn baseline() -> Result<Self, AzureDevOpsWorkError> {
        let contract = serde_json::from_str::<Self>(AZURE_DEVOPS_WORK_CONTRACT_JSON)
            .map_err(|error| AzureDevOpsWorkError::Contract(error.to_string()))?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<(), AzureDevOpsWorkError> {
        let expected_operations = vec![
            "describe_capabilities",
            "register",
            "revoke_registration",
            "read_work_item_graph",
            "read_pull_request",
            "read_build_timeline_artifacts",
            "consume_observation",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_areas = BTreeMap::from([
            ("build".to_owned(), "build".to_owned()),
            ("repos".to_owned(), "git".to_owned()),
            ("workItems".to_owned(), "wit".to_owned()),
        ]);
        if self.schema_version != AZURE_DEVOPS_WORK_SCHEMA_VERSION
            || self.contract_version != AZURE_DEVOPS_WORK_CONTRACT_VERSION
            || self.layer != 1
            || self.service_id != AZURE_DEVOPS_WORK_SERVICE_ID
            || self.provider_id != AZURE_DEVOPS_SERVICES_PROVIDER_ID
            || self.consumer_id != MISSION_AZURE_DEVOPS_WORK_CONSUMER_ID
            || self.api_version != AZURE_DEVOPS_API_VERSION
            || self.api_areas != expected_areas
            || self.operations != expected_operations
            || !self.read_only
            || !self.mutating_provider_operations.is_empty()
            || self.authority.external_writes
            || self.authority.raw_logs
            || self.authority.raw_artifacts
            || self.authority.connected
            || self.authority.effect
            || self.authority.receipt
            || self.authority.verification
            || self.authority.outcome
            || self.authority.work_product_adoption
            || !self.registration.reversible
            || !self.registration.revocable
            || !self.registration.fail_closed_on_drift
            || self.bounds.max_response_bytes != AZURE_DEVOPS_MAX_RESPONSE_BYTES
            || self.bounds.max_work_item_relations != MAX_RELATIONS
            || self.bounds.max_builds != MAX_BUILDS
            || self.bounds.max_timeline_records != MAX_TIMELINE_RECORDS
            || self.bounds.max_artifacts != MAX_ARTIFACTS
            || self.bounds.max_pages != AZURE_DEVOPS_MAX_PAGES
            || self.bounds.page_size != AZURE_DEVOPS_PAGE_SIZE
            || self.receipts.raw_provider_payload
            || self.receipts.raw_logs
            || self.receipts.raw_artifacts
            || self.receipts.credential_material
            || self.native_gap.status != "BLOCKED_ENV"
            || !self.honest_native_gap.contains("native Connected")
            || !self
                .honest_native_gap
                .contains("raw logs/artifact downloads")
        {
            return Err(AzureDevOpsWorkError::Contract(
                "Azure DevOps Work contract does not match the checked-in Layer-1 baseline"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AzureDevOpsWorkError {
    #[error("BLOCKED_ENV: native Microsoft Entra authority is unavailable")]
    BlockedEnv,
    #[error("Azure DevOps Work input is invalid: {0}")]
    InvalidInput(String),
    #[error("Azure DevOps Work contract is invalid: {0}")]
    Contract(String),
    #[error("Azure DevOps Work scope mismatch: {0}")]
    ScopeMismatch(String),
    #[error("Azure DevOps Work plugin version mismatch")]
    VersionMismatch,
    #[error("Azure DevOps Work contract digest mismatch")]
    ContractDigestMismatch,
    #[error("Azure DevOps Work registration is revoked")]
    RegistrationRevoked,
    #[error("Azure DevOps Work registration is stale or drifted: {0}")]
    RegistrationDrift(String),
    #[error("Azure DevOps Work credential lease is invalid or expired")]
    CredentialExpired,
    #[error("Azure DevOps Work credential resolution failed: {0}")]
    Credential(String),
    #[error("Azure DevOps API version drifted from REST {expected}: {actual}")]
    ApiVersionDrift { expected: String, actual: String },
    #[error("Azure DevOps response was too large: {size} bytes")]
    ResponseTooLarge { size: usize },
    #[error("Azure DevOps returned unexpected HTTP status {status}")]
    UnexpectedStatus { status: u16 },
    #[error("Azure DevOps response could not be decoded: {0}")]
    Decode(String),
    #[error("Azure DevOps transport failed: {0}")]
    Transport(String),
    #[error("Work Item {expected} was not returned")]
    WorkItemNotFound { expected: u64 },
    #[error("Work Item revision fence mismatch: expected {expected}, observed {observed}")]
    WorkItemRevisionMismatch { expected: u64, observed: u64 },
    #[error("Work Item has no Azure Repos pull request relation for repository {repository}")]
    PullRequestRelationMissing { repository: String },
    #[error("Azure Repos pull request relation is outside the registered repository")]
    PullRequestRepositoryMismatch,
    #[error("Azure Repos pull request id fence mismatch")]
    PullRequestIdMismatch,
    #[error("Azure Repos pull request was not returned")]
    PullRequestNotFound,
    #[error("Azure Repos pull request source/target commit is invalid")]
    PullRequestCommitInvalid,
    #[error("Azure DevOps build source branch is not the registered pull request fence")]
    BuildBranchMismatch,
    #[error("Azure DevOps build source version is not bound to the pull request")]
    BuildSourceMismatch,
    #[error("Azure DevOps returned no bounded validation build for the pull request")]
    BuildNotFound,
    #[error("Azure DevOps timeline record bound exceeded")]
    TimelineBoundExceeded,
    #[error("Azure DevOps artifact bound exceeded")]
    ArtifactBoundExceeded,
    #[error("Azure DevOps pagination is invalid or exceeded its bound")]
    Pagination(String),
    #[error("Azure DevOps response receipt retained forbidden payload material")]
    ForbiddenPayloadRetention,
    #[error("Azure DevOps evidence digest mismatch")]
    EvidenceDigestMismatch,
    #[error("Azure DevOps evidence is stale for this consumer")]
    StaleEvidence,
    #[error("Azure DevOps Work plugin runtime rejected the definition: {0}")]
    Plugin(PluginError),
}

impl From<PluginError> for AzureDevOpsWorkError {
    fn from(error: PluginError) -> Self {
        Self::Plugin(error)
    }
}

impl From<model::ModelError> for AzureDevOpsWorkError {
    fn from(error: model::ModelError) -> Self {
        Self::InvalidInput(error.to_string())
    }
}
