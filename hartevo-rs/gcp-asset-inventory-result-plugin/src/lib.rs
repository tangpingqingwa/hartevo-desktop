//! Standalone Layer-1 governed GCP Cloud Asset Inventory result plugin.
//!
//! The crate is intentionally limited to typed `searchAllResources`
//! proposal/read/record/verify seams, redacted evidence, and Mission
//! observation. It never resolves OAuth or service-account credentials,
//! executes a live Google request, exports to BigQuery, mutates a resource,
//! retains raw resource payloads/tags/PII, claims Connected/native authority,
//! or adopts an Outcome/Work Product.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::type_complexity
)]

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

pub use consumer::{
    ConsumerError, MissionGcpAssetConsumer, MissionGcpAssetInventoryConsumer,
    MissionGcpAssetInventoryResult, MissionGcpAssetInventoryState, MissionGcpAssetResult,
};
pub use model::*;
pub use provider::{
    BlockedEnvGcpAssetInventoryTransport, FakeGcpAssetInventoryProvider,
    FakeGcpAssetInventoryTransport, GcpAssetInventoryProvider, GcpAssetInventoryProviderDefinition,
    GcpAssetInventoryProviderError, GcpAssetInventoryTransport, LoopbackGcpAssetInventoryTransport,
    OpaqueCursor, OpaquePageToken, ProviderDefinitionError, ProviderFailureClass,
    ProviderProvenance, RecordingGcpAssetInventoryTransport, SearchAllResourcesPage,
    SearchAllResourcesProposal, SearchAllResourcesRecord, SearchAllResourcesRequest,
    SearchResponseStatus, fake_page_token_for_page, provider_failure_projection,
};
pub use service::{
    GcpAssetInventoryCapability, GcpAssetInventoryOperation, GcpAssetInventoryRegistration,
    GcpAssetInventoryService, GcpAssetInventoryServiceDefinition, GcpAssetInventoryServiceError,
    RegistrationError, RegistrationState, SearchAllResourcesRead, consumer_id,
    contract_json_is_embedded, provider_revision,
};

pub const GCP_ASSET_INVENTORY_SCHEMA_VERSION: &str =
    "hartevo.gcp-asset-inventory-result-contract/v1";
pub const GCP_ASSET_INVENTORY_CONTRACT_VERSION: &str = "gcp-asset-inventory-result/v1";
pub const GCP_ASSET_INVENTORY_PLUGIN_ID: &str = "gcp-asset-inventory-result";
pub const GCP_ASSET_INVENTORY_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const GCP_ASSET_INVENTORY_API_VERSION: &str = "v1";
pub const GCP_ASSET_INVENTORY_SERVICE_ID: &str = "gcp.asset-inventory";
pub const GCP_ASSET_INVENTORY_SERVICE_NAME: &str = "GcpAssetInventoryService";
pub const GCP_ASSET_INVENTORY_PROVIDER_ID: &str = "gcp.cloud-asset.search-all-resources";
pub const GCP_ASSET_INVENTORY_PROVIDER_SCHEMA: &str =
    "hartevo.gcp-cloud-asset-search-all-resources-provider/v1";
pub const GCP_ASSET_INVENTORY_PROVIDER_REVISION: &str =
    "gcp-cloud-asset-search-all-resources-v1-r1";
pub const GCP_ASSET_INVENTORY_SERVICE_SCHEMA: &str =
    "hartevo.gcp-asset-inventory-result-service/v1";
pub const MISSION_GCP_ASSET_INVENTORY_CONSUMER_ID: &str = "mission.gcp.asset-inventory";
pub const MISSION_GCP_ASSET_INVENTORY_CONSUMER_SCHEMA: &str =
    "hartevo.mission-gcp-asset-inventory-consumer/v1";
pub const GCP_ASSET_INVENTORY_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/gcp-asset-inventory-result/gcp-asset-inventory-result.v1.json"
);
pub const GCP_ASSET_INVENTORY_BLOCKED_ENV: &str = "BLOCKED_ENV";

pub fn contract_digest() -> Digest {
    Digest::from_bytes(GCP_ASSET_INVENTORY_CONTRACT_JSON.as_bytes())
}

pub fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Builds a runtime contribution set for one exact Project/Mission scope.
/// Runtime mounting remains a host concern and does not create native GCP
/// authority.
pub fn plugin_definition(scope: PluginScope) -> Result<PluginDefinition, PluginError> {
    let plugin_id = PluginId::new(GCP_ASSET_INVENTORY_PLUGIN_ID)?;
    let service_id = ServiceId::new(GCP_ASSET_INVENTORY_SERVICE_ID)?;
    let provider_id = ProviderId::new(GCP_ASSET_INVENTORY_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(MISSION_GCP_ASSET_INVENTORY_CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(GCP_ASSET_INVENTORY_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(GCP_ASSET_INVENTORY_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(MISSION_GCP_ASSET_INVENTORY_CONSUMER_SCHEMA),
        )?],
        events: Vec::new(),
        ui_surfaces: Vec::new(),
    };
    PluginDefinition::new(plugin_id, version, scope, contributions)
}

#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[error("GCP Asset Inventory Layer-1 error: {message}")]
pub struct GcpAssetInventoryError {
    pub message: String,
}

/// Layer-1 authority facts are deliberately constant and negative for native
/// claims. A later host integration must introduce its own authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn external_effect() -> bool {
        false
    }

    pub const fn raw_resource_payload() -> bool {
        false
    }

    pub const fn bigquery_export() -> bool {
        false
    }

    pub const fn ownership_health_deployability_authority() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use serde::Deserialize;

    use super::{
        GCP_ASSET_INVENTORY_API_VERSION, GCP_ASSET_INVENTORY_BLOCKED_ENV,
        GCP_ASSET_INVENTORY_CONTRACT_JSON, GCP_ASSET_INVENTORY_CONTRACT_VERSION,
        GCP_ASSET_INVENTORY_PROVIDER_ID, GCP_ASSET_INVENTORY_SCHEMA_VERSION,
        GCP_ASSET_INVENTORY_SERVICE_ID, GcpAssetInventoryServiceDefinition, Layer1Authority,
        MISSION_GCP_ASSET_INVENTORY_CONSUMER_ID, contract_digest,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        layer: u8,
        api_version: String,
        service: ServiceDocument,
        provider: ProviderDocument,
        consumer: ConsumerDocument,
        authority: AuthorityDocument,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ServiceDocument {
        id: String,
        read_only: bool,
        connected: bool,
        native: bool,
        live_execution: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderDocument {
        id: String,
        native: bool,
        live_execution: bool,
        big_query_export: bool,
        resolves_credentials: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConsumerDocument {
        id: String,
        mission_bound: bool,
        project_bound: bool,
        work_product_bound: bool,
        adopts_outcome: bool,
        truth_authority: bool,
        ownership_authority: bool,
        health_authority: bool,
        deployability_authority: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AuthorityDocument {
        external_writes: bool,
        resource_mutation: bool,
        big_query_export: bool,
        raw_resource_payload: bool,
        raw_response_body: bool,
        connected: bool,
        native_provider: bool,
        credential_resolution: bool,
        work_product_adoption: bool,
        ownership: bool,
        health: bool,
        deployability: bool,
    }

    #[test]
    fn contract_document_is_layer_one_and_honest() {
        let document = serde_json::from_str::<ContractDocument>(GCP_ASSET_INVENTORY_CONTRACT_JSON)
            .expect("GCP Asset Inventory contract JSON");
        assert_eq!(document.schema_version, GCP_ASSET_INVENTORY_SCHEMA_VERSION);
        assert_eq!(
            document.contract_version,
            GCP_ASSET_INVENTORY_CONTRACT_VERSION
        );
        assert_eq!(document.layer, 1);
        assert_eq!(document.api_version, GCP_ASSET_INVENTORY_API_VERSION);
        assert_eq!(document.service.id, GCP_ASSET_INVENTORY_SERVICE_ID);
        assert!(document.service.read_only);
        assert!(!document.service.connected);
        assert!(!document.service.native);
        assert!(!document.service.live_execution);
        assert_eq!(document.provider.id, GCP_ASSET_INVENTORY_PROVIDER_ID);
        assert!(!document.provider.native);
        assert!(!document.provider.live_execution);
        assert!(!document.provider.big_query_export);
        assert!(!document.provider.resolves_credentials);
        assert_eq!(
            document.consumer.id,
            MISSION_GCP_ASSET_INVENTORY_CONSUMER_ID
        );
        assert!(document.consumer.mission_bound);
        assert!(document.consumer.project_bound);
        assert!(document.consumer.work_product_bound);
        assert!(!document.consumer.adopts_outcome);
        assert!(!document.consumer.truth_authority);
        assert!(!document.consumer.ownership_authority);
        assert!(!document.consumer.health_authority);
        assert!(!document.consumer.deployability_authority);
        assert!(!document.authority.external_writes);
        assert!(!document.authority.resource_mutation);
        assert!(!document.authority.big_query_export);
        assert!(!document.authority.raw_resource_payload);
        assert!(!document.authority.raw_response_body);
        assert!(!document.authority.connected);
        assert!(!document.authority.native_provider);
        assert!(!document.authority.credential_resolution);
        assert!(!document.authority.work_product_adoption);
        assert!(!document.authority.ownership);
        assert!(!document.authority.health);
        assert!(!document.authority.deployability);
        assert_eq!(GCP_ASSET_INVENTORY_BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::external_effect());
        assert!(!Layer1Authority::raw_resource_payload());
        assert!(!Layer1Authority::bigquery_export());
        assert!(!Layer1Authority::ownership_health_deployability_authority());
        assert!(!Layer1Authority::adopted_outcome());
        assert_eq!(contract_digest().as_str().len(), 64);
        assert!(GcpAssetInventoryServiceDefinition::new().validate().is_ok());
    }
}
