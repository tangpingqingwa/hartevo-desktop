//! Layer-1 governed Crowdin localization-result evidence.
//!
//! This crate exposes only bounded, normalized GET evidence and a canonical
//! Mission-scoped proposal. It never stores provider bodies or localization
//! text, resolves credentials, mutates Crowdin, downloads a build, registers
//! a webhook, claims publication, or adopts a kernel Outcome.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

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

pub use consumer::{MissionCrowdinLocalizationConsumer, MissionCrowdinLocalizationResult};
pub use model::*;
pub use provider::{
    CrowdinProvider, CrowdinRegistration, CrowdinRegistrationRequest, RegistrationState,
};
pub use service::{CrowdinCapability, CrowdinLocalizationResultService};
pub use transport::{
    BlockedEnvCrowdinTransport, BlockedEnvTransport, CrowdinHttpMethod, CrowdinNormalizedResponse,
    CrowdinReadRequest, CrowdinReadResponse, CrowdinReadTransport, CrowdinTransportError,
    FakeCrowdinTransport, FixtureCrowdinTransport, LoopbackCrowdinTransport,
    RecordingCrowdinTransport,
};

pub const CROWDIN_LOCALIZATION_RESULT_SCHEMA_VERSION: &str =
    "hartevo-crowdin-localization-result-contract/v1";
pub const CROWDIN_LOCALIZATION_RESULT_CONTRACT_VERSION: &str = "crowdin-localization-result/v1";
pub const CROWDIN_LOCALIZATION_RESULT_PLUGIN_ID: &str = "crowdin-localization-result";
pub const CROWDIN_LOCALIZATION_RESULT_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const CROWDIN_API_VERSION: &str = "2.0";
pub const CROWDIN_API_ORIGIN: &str = "https://api.crowdin.com/api/v2";
pub const CROWDIN_LOCALIZATION_RESULT_SERVICE_ID: &str = "crowdin.localization-result";
pub const CROWDIN_LOCALIZATION_RESULT_SERVICE_NAME: &str = "CrowdinLocalizationResultService";
pub const CROWDIN_PROVIDER_ID: &str = "crowdin.api-v2";
pub const CROWDIN_PROVIDER_NAME: &str = "CrowdinProvider";
pub const MISSION_CROWDIN_LOCALIZATION_RESULT_CONSUMER_ID: &str =
    "mission.crowdin-localization-result";
pub const MISSION_CROWDIN_LOCALIZATION_RESULT_CONSUMER_NAME: &str =
    "MissionCrowdinLocalizationConsumer";
pub const CROWDIN_LOCALIZATION_RESULT_SERVICE_SCHEMA: &str =
    "hartevo.crowdin-localization-result-service/v1";
pub const CROWDIN_PROVIDER_SCHEMA: &str = "hartevo.crowdin-provider/v1";
pub const MISSION_CROWDIN_LOCALIZATION_RESULT_CONSUMER_SCHEMA: &str =
    "hartevo.mission-crowdin-localization-result-consumer/v1";
pub const CROWDIN_PROVIDER_REVISION: &str = "crowdin-api-v2-read-r1";
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_PAGES: u16 = 4;
pub const PAGE_SIZE: u16 = 50;
pub const MAX_RETRIES: u8 = 3;
pub const MAX_BACKOFF_MS: u64 = 8_000;
pub const MAX_WINDOW_SECONDS: u64 = 2_678_400;

pub const CROWDIN_LOCALIZATION_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/crowdin-localization-result/crowdin-localization-result.v1.json"
);

pub fn contract_digest() -> Digest {
    sha256_digest(CROWDIN_LOCALIZATION_RESULT_CONTRACT_JSON.as_bytes())
}

pub const fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Builds the inert plugin-runtime contribution descriptors for a host-owned
/// Project/Mission scope. Mounting and all external authority remain host work.
pub fn plugin_definition(scope: PluginScope) -> Result<PluginDefinition, CrowdinError> {
    let plugin_id = PluginId::new(CROWDIN_LOCALIZATION_RESULT_PLUGIN_ID)?;
    let service_id = ServiceId::new(CROWDIN_LOCALIZATION_RESULT_SERVICE_ID)?;
    let provider_id = ProviderId::new(CROWDIN_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(MISSION_CROWDIN_LOCALIZATION_RESULT_CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(CROWDIN_LOCALIZATION_RESULT_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(CROWDIN_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(MISSION_CROWDIN_LOCALIZATION_RESULT_CONSUMER_SCHEMA),
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
pub struct CrowdinLocalizationResultContract {
    #[serde(rename = "$schema")]
    pub json_schema: String,
    #[serde(rename = "$id")]
    pub contract_id: String,
    pub schema_version: String,
    pub contract_version: String,
    pub layer: u8,
    pub service: ContractService,
    pub provider: ContractProvider,
    pub consumer: ContractConsumer,
    pub scope: ContractScope,
    pub bounds: ContractBounds,
    pub redaction: ContractRedaction,
    pub authority: ContractAuthority,
    pub registration: ContractRegistration,
    pub native_claims: ContractNativeClaims,
    pub layer2_gaps: Vec<String>,
    pub official_api_references: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractService {
    pub id: String,
    pub name: String,
    pub version: String,
    pub read_only: bool,
    pub native_connected: bool,
    pub operations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractProvider {
    pub id: String,
    pub name: String,
    pub version: String,
    pub api: String,
    pub api_origin: String,
    pub allowed_get_paths: Vec<String>,
    pub accepted_provenance: Vec<String>,
    pub native: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractConsumer {
    pub id: String,
    pub name: String,
    pub mission_bound: bool,
    pub project_bound: bool,
    pub work_product_bound: bool,
    pub consent_bound: bool,
    pub adopts_outcome: bool,
    pub publication_authority: bool,
    pub truth_authority: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractScope {
    pub required: Vec<String>,
    pub secret: String,
    pub fence: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractBounds {
    pub max_response_bytes: usize,
    pub max_pages: u16,
    pub page_size: u16,
    pub max_retries: u8,
    pub max_backoff_ms: u64,
    pub max_window_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractRedaction {
    pub source_text: bool,
    pub translated_text: bool,
    pub translator_identity: bool,
    pub comments: bool,
    pub screenshots: bool,
    pub glossary_content: bool,
    pub raw_api_body: bool,
    pub credential_material: bool,
    pub retained: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ContractAuthority {
    pub external_writes: bool,
    pub source_upload: bool,
    pub string_mutation: bool,
    pub translation_submission: bool,
    pub approval: bool,
    pub translation_build_trigger: bool,
    pub download: bool,
    pub webhook: bool,
    pub publication: bool,
    pub cms_registry: bool,
    pub connected: bool,
    pub durable_receipt: bool,
    pub verification: bool,
    pub outcome: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractRegistration {
    pub version_bound: bool,
    pub provider_bound: bool,
    pub digest_bound: bool,
    pub scope_bound: bool,
    pub reversible: bool,
    pub revocable: bool,
    pub fail_closed_on_drift: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ContractNativeClaims {
    pub connected: bool,
    pub native_provider: bool,
    pub durable_receipt: bool,
    pub adopted_outcome: bool,
    pub publication: bool,
    pub blocked_environment_is_native: bool,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CrowdinError {
    #[error("Crowdin Localization Result contract is invalid: {0}")]
    Contract(String),
    #[error("Crowdin Localization Result input is invalid: {0}")]
    InvalidInput(String),
    #[error("Crowdin Localization Result scope mismatch: {0}")]
    ScopeMismatch(String),
    #[error("Crowdin Localization Result contract digest mismatch")]
    ContractDigestMismatch,
    #[error("Crowdin Localization Result provider revision mismatch")]
    ProviderRevisionMismatch,
    #[error("Crowdin Localization Result registration is revoked")]
    RegistrationRevoked,
    #[error("Crowdin Localization Result registration drifted: {0}")]
    RegistrationDrift(String),
    #[error("Crowdin Localization Result proposal is stale or tampered")]
    StaleProposal,
    #[error("Crowdin Localization Result evidence is duplicated")]
    DuplicateEvidence,
    #[error("Crowdin Localization Result revision fence mismatch: {0}")]
    RevisionMismatch(String),
    #[error("Crowdin Localization Result evidence is incomplete: {0}")]
    IncompleteEvidence(String),
    #[error("Crowdin Localization Result provider response was too large: {size} bytes")]
    ResponseTooLarge { size: usize },
    #[error("Crowdin Localization Result transport failed: {0}")]
    Transport(#[from] CrowdinTransportError),
    #[error("Crowdin Localization Result model failed: {0}")]
    Model(#[from] ModelError),
    #[error("plugin runtime rejected Crowdin Localization Result: {0}")]
    Plugin(#[from] PluginError),
}

impl CrowdinLocalizationResultContract {
    pub fn baseline() -> Result<Self, CrowdinError> {
        let contract = serde_json::from_str::<Self>(CROWDIN_LOCALIZATION_RESULT_CONTRACT_JSON)
            .map_err(|error| CrowdinError::Contract(error.to_string()))?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), CrowdinError> {
        let operations = vec![
            "describe_capabilities",
            "register",
            "revoke_registration",
            "read_project_metadata",
            "read_language_coverage",
            "read_source_file_metadata",
            "read_translation_progress",
            "read_translation_build_status",
            "compile_localization_result_proposal",
            "record_localization_result",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let paths = vec![
            "/projects/{projectId}",
            "/projects/{projectId}/branches/{branchId}/languages/progress",
            "/projects/{projectId}/files/{fileId}",
            "/projects/{projectId}/files/{fileId}/languages/progress",
            "/projects/{projectId}/bundles",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let scope_required = vec![
            "organization",
            "crowdinProject",
            "sourceBranch",
            "sourceFile",
            "targetLanguage",
            "hartevoProject",
            "mission",
            "workProduct",
            "consentScope",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let scope_fence = vec![
            "pluginVersion",
            "contractVersion",
            "contractDigest",
            "providerId",
            "providerRevision",
            "organization",
            "crowdinProject",
            "crowdinProjectRevision",
            "sourceBranchIdAndRevision",
            "sourceFileIdAndRevision",
            "targetLanguage",
            "sourceRevisionDigest",
            "translationRevisionDigest",
            "buildDigest",
            "hartevoProjectIdAndRevision",
            "missionIdAndRevision",
            "workProductIdAndRevision",
            "consentScopeAndDigest",
            "secretReferenceDigest",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        if self.json_schema != "https://json-schema.org/draft/2020-12/schema"
            || self.contract_id
                != "https://hartevo.local/contracts/plugins/crowdin-localization-result/crowdin-localization-result.v1.json"
            || self.schema_version != CROWDIN_LOCALIZATION_RESULT_SCHEMA_VERSION
            || self.contract_version != CROWDIN_LOCALIZATION_RESULT_CONTRACT_VERSION
            || self.layer != 1
            || self.service.id != CROWDIN_LOCALIZATION_RESULT_SERVICE_ID
            || self.service.name != CROWDIN_LOCALIZATION_RESULT_SERVICE_NAME
            || self.service.version != CROWDIN_LOCALIZATION_RESULT_PLUGIN_VERSION_TEXT
            || !self.service.read_only
            || self.service.native_connected
            || self.service.operations != operations
            || self.provider.id != CROWDIN_PROVIDER_ID
            || self.provider.name != CROWDIN_PROVIDER_NAME
            || self.provider.version != CROWDIN_LOCALIZATION_RESULT_PLUGIN_VERSION_TEXT
            || self.provider.api != "Crowdin API v2"
            || self.provider.api_origin != CROWDIN_API_ORIGIN
            || self.provider.allowed_get_paths != paths
            || self.provider.accepted_provenance
                != vec!["fixture", "recording", "loopback", "blocked_env"]
            || self.provider.native
            || self.consumer.id != MISSION_CROWDIN_LOCALIZATION_RESULT_CONSUMER_ID
            || self.consumer.name != MISSION_CROWDIN_LOCALIZATION_RESULT_CONSUMER_NAME
            || !self.consumer.mission_bound
            || !self.consumer.project_bound
            || !self.consumer.work_product_bound
            || !self.consumer.consent_bound
            || self.consumer.adopts_outcome
            || self.consumer.publication_authority
            || self.consumer.truth_authority
            || self.scope.required != scope_required
            || self.scope.secret != "opaque_secret_reference_only"
            || self.scope.fence != scope_fence
            || self.bounds.max_response_bytes != MAX_RESPONSE_BYTES
            || self.bounds.max_pages != MAX_PAGES
            || self.bounds.page_size != PAGE_SIZE
            || self.bounds.max_retries != MAX_RETRIES
            || self.bounds.max_backoff_ms != MAX_BACKOFF_MS
            || self.bounds.max_window_seconds != MAX_WINDOW_SECONDS
            || !self.redaction.source_text
            || !self.redaction.translated_text
            || !self.redaction.translator_identity
            || !self.redaction.comments
            || !self.redaction.screenshots
            || !self.redaction.glossary_content
            || !self.redaction.raw_api_body
            || !self.redaction.credential_material
            || self.authority.external_writes
            || self.authority.source_upload
            || self.authority.string_mutation
            || self.authority.translation_submission
            || self.authority.approval
            || self.authority.translation_build_trigger
            || self.authority.download
            || self.authority.webhook
            || self.authority.publication
            || self.authority.cms_registry
            || self.authority.connected
            || self.authority.durable_receipt
            || self.authority.verification
            || self.authority.outcome
            || self.authority.work_product_adoption
            || !self.registration.version_bound
            || !self.registration.provider_bound
            || !self.registration.digest_bound
            || !self.registration.scope_bound
            || !self.registration.reversible
            || !self.registration.revocable
            || !self.registration.fail_closed_on_drift
            || self.native_claims.connected
            || self.native_claims.native_provider
            || self.native_claims.durable_receipt
            || self.native_claims.adopted_outcome
            || self.native_claims.publication
            || self.native_claims.blocked_environment_is_native
            || !self
                .official_api_references
                .iter()
                .any(|reference| reference == "https://support.crowdin.com/developer/api/v2/")
        {
            return Err(CrowdinError::Contract(
                "Crowdin Localization Result contract does not match the checked-in Layer-1 baseline"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}
