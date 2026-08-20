//! Governed Azure Resource Graph inventory result Layer-1 plugin.
//!
//! This standalone root exposes a typed, read-only inventory evidence seam
//! bounded by an allowlisted query AST, an exact tenant scope, and digest-only
//! selected properties. It has no arbitrary KQL, mutation, native Connected
//! claim, fleet-health authority, or kernel Outcome authority.

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

pub use consumer::{
    MissionAzureResourceConsumer, MissionAzureResourceResult, MissionAzureResourceResultState,
};
pub use model::*;
pub use provider::{
    AzureResourceGraphProvider, AzureResourceGraphRegistration,
    AzureResourceGraphRegistrationRequest, BlockedEnvCredentialResolver, CredentialResolver,
    EntraAccessToken, EntraCredentialError, EntraCredentialResolver, EnvironmentCredentialResolver,
    FixtureCredentialResolver, NativeProbe, NativeProbeStatus, continuation_binding_digest,
    native_probe_from_environment,
};
pub use service::{
    AzureResourceGraphCapability, AzureResourceGraphOperation, AzureResourceGraphService,
};
pub use transport::{
    AzureResourceGraphEndpoint, AzureResourceGraphHttpMethod, AzureResourceGraphHttpRequest,
    AzureResourceGraphHttpResponse, AzureResourceGraphTransport, AzureResourceGraphTransportError,
    BlockedEnvTransport, ContinuationToken, FakeAzureResourceGraphTransport,
    LoopbackAzureResourceGraphTransport, RecordingAzureResourceGraphTransport, RequestBounds,
};

pub const AZURE_RESOURCE_GRAPH_SCHEMA_VERSION: &str =
    "hartevo.azure-resource-graph-result-contract/v1";
pub const AZURE_RESOURCE_GRAPH_CONTRACT_VERSION: &str = "azure-resource-graph-result/v1";
pub const AZURE_RESOURCE_GRAPH_PLUGIN_ID: &str = "azure-resource-graph-result";
pub const AZURE_RESOURCE_GRAPH_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const AZURE_RESOURCE_GRAPH_API_VERSION: &str = "2022-10-01";
pub const AZURE_RESOURCE_GRAPH_API_ORIGIN: &str = "https://management.azure.com";
pub const AZURE_RESOURCE_GRAPH_API_PATH: &str = "/providers/Microsoft.ResourceGraph/resources";
pub const AZURE_RESOURCE_GRAPH_SERVICE_ID: &str = "azure-resource-graph.result";
pub const AZURE_RESOURCE_GRAPH_SERVICE_NAME: &str = "AzureResourceGraphService";
pub const AZURE_RESOURCE_GRAPH_PROVIDER_ID: &str = "azure-resource-graph.resources";
pub const AZURE_RESOURCE_GRAPH_PROVIDER_NAME: &str = "AzureResourceGraphProvider";
pub const MISSION_AZURE_RESOURCE_GRAPH_CONSUMER_ID: &str = "mission.azure-resource-graph-result";
pub const MISSION_AZURE_RESOURCE_GRAPH_CONSUMER_NAME: &str = "MissionAzureResourceConsumer";
pub const AZURE_RESOURCE_GRAPH_SERVICE_SCHEMA: &str =
    "hartevo.azure-resource-graph-result-service/v1";
pub const AZURE_RESOURCE_GRAPH_PROVIDER_SCHEMA: &str = "hartevo.azure-resource-graph-provider/v1";
pub const MISSION_AZURE_RESOURCE_GRAPH_CONSUMER_SCHEMA: &str =
    "hartevo.mission-azure-resource-consumer/v1";
pub const AZURE_RESOURCE_GRAPH_PROVIDER_REVISION: &str = "azure-resource-graph-2022-10-01-r1";
pub const AZURE_RESOURCE_GRAPH_NATIVE_PROBE_ENV: &str = "HARTEVO_AZURE_RESOURCE_GRAPH_NATIVE_PROBE";
pub const AZURE_RESOURCE_GRAPH_NATIVE_PROBE_GATE: &str =
    "HARTEVO_AZURE_RESOURCE_GRAPH_NATIVE_PROBE=1";
pub const AZURE_RESOURCE_GRAPH_ACCESS_TOKEN_ENV: &str = "HARTEVO_AZURE_RESOURCE_GRAPH_ACCESS_TOKEN";

pub const AZURE_RESOURCE_GRAPH_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/azure-resource-graph-result/azure-resource-graph-result.v1.json"
);

#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(AZURE_RESOURCE_GRAPH_CONTRACT_JSON.as_bytes())
}

#[must_use]
pub const fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Build the plugin-runtime contribution set for one exact Project/Mission
/// generation. Mounting remains an explicit host operation.
pub fn plugin_definition(scope: PluginScope) -> Result<PluginDefinition, AzureResourceGraphError> {
    let plugin_id = PluginId::new(AZURE_RESOURCE_GRAPH_PLUGIN_ID)?;
    let service_id = ServiceId::new(AZURE_RESOURCE_GRAPH_SERVICE_ID)?;
    let provider_id = ProviderId::new(AZURE_RESOURCE_GRAPH_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(MISSION_AZURE_RESOURCE_GRAPH_CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(AZURE_RESOURCE_GRAPH_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(AZURE_RESOURCE_GRAPH_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(MISSION_AZURE_RESOURCE_GRAPH_CONSUMER_SCHEMA),
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
pub struct AzureResourceGraphContract {
    #[serde(rename = "$schema")]
    pub schema_url: String,
    #[serde(rename = "$id")]
    pub contract_id: String,
    pub title: String,
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub layer: u8,
    pub service: AzureResourceGraphServiceContract,
    pub provider: AzureResourceGraphProviderContract,
    pub consumer: AzureResourceGraphConsumerContract,
    pub read_only: bool,
    pub mutating_provider_operations: Vec<String>,
    pub authority: AzureResourceGraphAuthorityContract,
    pub registration: AzureResourceGraphRegistrationContract,
    pub scope_fence: Vec<String>,
    pub allowlist: AzureResourceGraphAllowlistContract,
    pub bounds: AzureResourceGraphBoundsContract,
    pub transport_provenance: Vec<String>,
    pub native_gap: AzureResourceGraphNativeGapContract,
    pub honest_native_gap: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureResourceGraphServiceContract {
    pub id: String,
    pub name: String,
    pub version: String,
    pub read_only: bool,
    pub operations: Vec<String>,
    pub external_writes: bool,
    pub live_external_io: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct AzureResourceGraphProviderContract {
    pub id: String,
    pub name: String,
    pub version: String,
    pub api_version: String,
    pub path: String,
    pub method: String,
    pub authentication: String,
    pub transport_provenance: Vec<String>,
    pub arbitrary_kql: bool,
    pub raw_resource_payload: bool,
    pub raw_properties: bool,
    pub raw_tags: bool,
    pub external_writes: bool,
    pub native: bool,
    pub connected: bool,
    pub reversible: bool,
    pub revocable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureResourceGraphConsumerContract {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub adopts_outcome: bool,
    pub kernel_authority: bool,
    pub truth_authority: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct AzureResourceGraphAuthorityContract {
    pub external_writes: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub durable_receipt: bool,
    pub verification_authority: bool,
    pub kernel_authority: bool,
    pub outcome_authority: bool,
    pub fleet_health_authority: bool,
    pub deployment_authority: bool,
    pub policy_authority: bool,
    pub raw_kql: bool,
    pub raw_properties: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureResourceGraphRegistrationContract {
    pub bound_fields: Vec<String>,
    pub reversible: bool,
    pub revocable: bool,
    pub fail_closed_on_drift: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureResourceGraphAllowlistContract {
    pub resource_types: Vec<String>,
    pub properties: Vec<String>,
    pub methods: Vec<String>,
    pub path: String,
    pub forbidden: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureResourceGraphBoundsContract {
    pub max_response_bytes: usize,
    pub max_resources: usize,
    pub max_scopes: usize,
    pub max_resource_types: usize,
    pub max_properties: usize,
    pub max_pages: u16,
    pub page_size: u16,
    pub max_identifier_bytes: usize,
    pub max_diagnostic_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureResourceGraphNativeGapContract {
    pub status: String,
    pub deferred_to: String,
    pub fail_closed_cases: Vec<String>,
}

impl AzureResourceGraphContract {
    pub fn baseline() -> Result<Self, AzureResourceGraphError> {
        let contract = serde_json::from_str::<Self>(AZURE_RESOURCE_GRAPH_CONTRACT_JSON)
            .map_err(|error| AzureResourceGraphError::Contract(error.to_string()))?;
        contract.validate()?;
        Ok(contract)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<(), AzureResourceGraphError> {
        let expected_operations = AzureResourceGraphOperation::ALL
            .iter()
            .map(|operation| operation.as_str().to_owned())
            .collect::<Vec<_>>();
        let expected_provenance = vec![
            "fixture".to_owned(),
            "recording".to_owned(),
            "loopback".to_owned(),
            "BLOCKED_ENV".to_owned(),
        ];
        let expected_types = AzureResourceType::ALL
            .iter()
            .map(|kind| kind.code().to_owned())
            .collect::<Vec<_>>();
        let expected_properties = AzureResourceProperty::ALL
            .iter()
            .map(|property| property.code().to_owned())
            .collect::<Vec<_>>();
        if self.schema_version != AZURE_RESOURCE_GRAPH_SCHEMA_VERSION
            || self.contract_version != AZURE_RESOURCE_GRAPH_CONTRACT_VERSION
            || self.plugin_version != AZURE_RESOURCE_GRAPH_PLUGIN_VERSION_TEXT
            || self.layer != 1
            || self.service.id != AZURE_RESOURCE_GRAPH_SERVICE_ID
            || self.service.name != AZURE_RESOURCE_GRAPH_SERVICE_NAME
            || self.service.version != AZURE_RESOURCE_GRAPH_PLUGIN_VERSION_TEXT
            || !self.service.read_only
            || self.service.operations != expected_operations
            || self.service.external_writes
            || self.service.live_external_io
            || self.provider.id != AZURE_RESOURCE_GRAPH_PROVIDER_ID
            || self.provider.name != AZURE_RESOURCE_GRAPH_PROVIDER_NAME
            || self.provider.version != AZURE_RESOURCE_GRAPH_PLUGIN_VERSION_TEXT
            || self.provider.api_version != AZURE_RESOURCE_GRAPH_API_VERSION
            || self.provider.path != AZURE_RESOURCE_GRAPH_API_PATH
            || self.provider.method != "POST"
            || self.provider.authentication != "opaque_secret_reference"
            || self.provider.transport_provenance != expected_provenance
            || self.provider.arbitrary_kql
            || self.provider.raw_resource_payload
            || self.provider.raw_properties
            || self.provider.raw_tags
            || self.provider.external_writes
            || self.provider.native
            || self.provider.connected
            || !self.provider.reversible
            || !self.provider.revocable
            || self.consumer.id != MISSION_AZURE_RESOURCE_GRAPH_CONSUMER_ID
            || self.consumer.name != MISSION_AZURE_RESOURCE_GRAPH_CONSUMER_NAME
            || self.consumer.adopts_outcome
            || self.consumer.kernel_authority
            || self.consumer.truth_authority
            || !self.read_only
            || !self.mutating_provider_operations.is_empty()
            || self.authority.external_writes
            || self.authority.connected
            || self.authority.native_provider
            || self.authority.durable_receipt
            || self.authority.verification_authority
            || self.authority.kernel_authority
            || self.authority.outcome_authority
            || self.authority.fleet_health_authority
            || self.authority.deployment_authority
            || self.authority.policy_authority
            || self.authority.raw_kql
            || self.authority.raw_properties
            || !self.registration.reversible
            || !self.registration.revocable
            || !self.registration.fail_closed_on_drift
            || self.allowlist.resource_types != expected_types
            || self.allowlist.properties != expected_properties
            || self.allowlist.methods != ["POST"]
            || self.allowlist.path != AZURE_RESOURCE_GRAPH_API_PATH
            || self.bounds.max_response_bytes != MAX_RESPONSE_BYTES
            || self.bounds.max_resources != MAX_RESOURCES
            || self.bounds.max_scopes != MAX_SCOPES
            || self.bounds.max_resource_types != AzureResourceType::ALL.len()
            || self.bounds.max_properties != AzureResourceProperty::ALL.len()
            || self.bounds.max_pages != MAX_PAGES
            || self.bounds.page_size != PAGE_SIZE
            || self.bounds.max_identifier_bytes != MAX_IDENTIFIER_BYTES
            || self.bounds.max_diagnostic_bytes != MAX_DIAGNOSTIC_BYTES
            || self.transport_provenance != expected_provenance
            || self.native_gap.status != "BLOCKED_ENV"
            || !self.honest_native_gap.contains("Layer-2")
            || !self.honest_native_gap.contains("arbitrary KQL")
            || !self.honest_native_gap.contains("Connected")
        {
            return Err(AzureResourceGraphError::Contract(
                "Azure Resource Graph contract does not match the checked-in Layer-1 baseline"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AzureResourceGraphError {
    #[error("BLOCKED_ENV: native Microsoft Entra authority is unavailable")]
    BlockedEnv,
    #[error("Azure Resource Graph input is invalid: {0}")]
    InvalidInput(String),
    #[error("Azure Resource Graph contract is invalid: {0}")]
    Contract(String),
    #[error("Azure Resource Graph scope mismatch: {0}")]
    ScopeMismatch(String),
    #[error("Azure Resource Graph plugin version mismatch")]
    VersionMismatch,
    #[error("Azure Resource Graph contract digest mismatch")]
    ContractDigestMismatch,
    #[error("Azure Resource Graph provider identity mismatch")]
    ProviderIdentityMismatch,
    #[error("Azure Resource Graph registration is revoked")]
    RegistrationRevoked,
    #[error("Azure Resource Graph registration is not revoked")]
    RegistrationNotRevoked,
    #[error("Azure Resource Graph registration drifted: {0}")]
    RegistrationDrift(String),
    #[error("Azure Resource Graph credential is unavailable")]
    CredentialUnavailable,
    #[error("Azure Resource Graph credential reference is revoked")]
    SecretRevoked,
    #[error("Azure Resource Graph provider revision drifted")]
    ProviderRevisionDrift,
    #[error("Azure Resource Graph response exceeded its byte bound: {size} bytes")]
    ResponseTooLarge { size: usize },
    #[error("Azure Resource Graph response receipt is invalid")]
    InvalidResponseReceipt,
    #[error("Azure Resource Graph continuation binding is invalid")]
    ContinuationRejected,
    #[error("Azure Resource Graph continuation repeated or exceeded its bound")]
    ContinuationReplay,
    #[error("Azure Resource Graph result bound was exceeded")]
    ResultBoundExceeded,
    #[error("Azure Resource Graph response could not be decoded: {0}")]
    Decode(String),
    #[error("Azure Resource Graph transport failed: {0}")]
    Transport(String),
    #[error("Azure Resource Graph proposal is invalid or stale")]
    InvalidProposal,
    #[error("Azure Resource Graph proposal replay was rejected")]
    ReplayDetected,
    #[error("Azure Resource Graph observation receipt is invalid")]
    InvalidObservationReceipt,
    #[error("Azure Resource Graph plugin runtime rejected the definition: {0}")]
    Plugin(PluginError),
}

impl From<PluginError> for AzureResourceGraphError {
    fn from(error: PluginError) -> Self {
        Self::Plugin(error)
    }
}

impl From<model::ModelError> for AzureResourceGraphError {
    fn from(error: model::ModelError) -> Self {
        Self::InvalidInput(error.to_string())
    }
}

impl From<transport::AzureResourceGraphTransportError> for AzureResourceGraphError {
    fn from(error: transport::AzureResourceGraphTransportError) -> Self {
        match error {
            transport::AzureResourceGraphTransportError::BlockedEnv => Self::BlockedEnv,
            transport::AzureResourceGraphTransportError::CredentialUnavailable => {
                Self::CredentialUnavailable
            }
            transport::AzureResourceGraphTransportError::ResponseTooLarge { size } => {
                Self::ResponseTooLarge { size }
            }
            transport::AzureResourceGraphTransportError::InvalidRequest(detail)
            | transport::AzureResourceGraphTransportError::Decode(detail)
            | transport::AzureResourceGraphTransportError::Timeout(detail)
            | transport::AzureResourceGraphTransportError::Transport(detail) => {
                Self::Transport(detail)
            }
        }
    }
}

impl From<provider::EntraCredentialError> for AzureResourceGraphError {
    fn from(error: provider::EntraCredentialError) -> Self {
        match error {
            provider::EntraCredentialError::BlockedEnv => Self::BlockedEnv,
            provider::EntraCredentialError::Unavailable => Self::CredentialUnavailable,
            provider::EntraCredentialError::SecretRevoked => Self::SecretRevoked,
        }
    }
}
