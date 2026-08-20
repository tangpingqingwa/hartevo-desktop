//! Standalone Layer-1 governed Azure Resource Health result plugin.
//!
//! This crate exposes bounded availability-status and event-list evidence
//! through typed service/provider/consumer seams. It has no native HTTPS
//! transport, Entra credential resolver, restart/redeploy path, support-case
//! path, health mutation, recommendation executor, outage-causality claim, or
//! kernel Outcome authority.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::result_large_err)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::struct_excessive_bools)]

use std::collections::BTreeMap;

use hartevo_plugin_runtime::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId, Digest as RuntimeDigest,
    PluginContributions, PluginDefinition, PluginError, PluginId, PluginScope, PluginVersion,
    ProviderCardinality, ProviderDefinition as RuntimeProviderDefinition, ProviderId,
    ServiceDefinition, ServiceId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    ConsumerError, MissionAzureResourceHealthConsumer, MissionAzureResourceHealthConsumerError,
    MissionAzureResourceHealthResult, MissionAzureResourceHealthState, MissionResultState,
};
pub use model::*;
pub use provider::{
    AvailabilityStatusRead, AzureResourceHealthProvider, AzureResourceHealthProviderDefinition,
    AzureResourceHealthProviderError, AzureResourceHealthRequest, AzureResourceHealthResponse,
    AzureResourceHealthTransport, AzureResourceHealthTransportError,
    BlockedEnvAzureResourceHealthTransport, EventListRead, FakeAzureResourceHealthTransport,
    FixtureAzureResourceHealthTransport, FixtureTransport, LoopbackAzureResourceHealthTransport,
    LoopbackTransport, ProviderDefinition, RecordingAzureResourceHealthTransport,
    RecordingTransport, TransportError,
};
pub use service::{
    AzureResourceHealthProposal, AzureResourceHealthRecord, AzureResourceHealthService,
    AzureResourceHealthServiceDefinition, AzureResourceHealthServiceError,
    AzureResourceHealthVerification,
};

pub type AzureResourceHealthEvidenceState = EvidenceState;
pub type AzureResourceHealthEventSummary = ResourceHealthEventSummary;
pub type AzureResourceHealthEventStatus = EventStatus;
pub type AzureResourceHealthAvailabilityState = AvailabilityState;
pub type AzureResourceHealthSecretReference = SecretReference;

pub const AZURE_RESOURCE_HEALTH_SCHEMA_VERSION: &str = "hartevo.azure-resource-health-result/v1";
pub const AZURE_RESOURCE_HEALTH_CONTRACT_VERSION: &str = "azure-resource-health-result-e1/v1";
pub const AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const AZURE_RESOURCE_HEALTH_SERVICE_ID: &str = "azure.resource-health.result";
pub const AZURE_RESOURCE_HEALTH_SERVICE_NAME: &str = "AzureResourceHealthService";
pub const AZURE_RESOURCE_HEALTH_PROVIDER_ID: &str = "azure.resource-health.management";
pub const AZURE_RESOURCE_HEALTH_PROVIDER_NAME: &str = "AzureResourceHealthProvider";
pub const MISSION_AZURE_RESOURCE_HEALTH_CONSUMER_ID: &str = "mission.azure.resource-health";
pub const MISSION_AZURE_RESOURCE_HEALTH_CONSUMER_NAME: &str = "MissionAzureResourceHealthConsumer";
pub const AZURE_RESOURCE_HEALTH_API_ORIGIN: &str = "https://management.azure.com";
pub const AZURE_RESOURCE_HEALTH_API_VERSION: &str = "2025-05-01";
pub const AZURE_RESOURCE_HEALTH_API_REVISION: &str = "azure-resource-health-rest-2025-05-01";
pub const AZURE_RESOURCE_HEALTH_PROVIDER_REVISION: &str = "azure-resource-health-rest-2025-05-01";
pub const AZURE_RESOURCE_HEALTH_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/azure-resource-health-result/azure-resource-health-result.v1.json"
);
pub const AZURE_RESOURCE_HEALTH_MAX_RESPONSE_BYTES: usize = model::MAX_RESPONSE_BYTES;
pub const AZURE_RESOURCE_HEALTH_MAX_EVENTS: usize = model::MAX_EVENTS;

pub const AZURE_RESOURCE_HEALTH_AVAILABILITY_PATH: &str =
    model::AZURE_RESOURCE_HEALTH_OPERATION_AVAILABILITY_PATH;
pub const AZURE_RESOURCE_HEALTH_EVENTS_PATH: &str =
    model::AZURE_RESOURCE_HEALTH_OPERATION_EVENTS_PATH;

pub const AZURE_RESOURCE_HEALTH_RESULT_SCHEMA_VERSION: &str = AZURE_RESOURCE_HEALTH_SCHEMA_VERSION;
pub const AZURE_RESOURCE_HEALTH_RESULT_CONTRACT_VERSION: &str =
    AZURE_RESOURCE_HEALTH_CONTRACT_VERSION;

#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(AZURE_RESOURCE_HEALTH_CONTRACT_JSON.as_bytes())
}

#[must_use]
pub fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    #[must_use]
    pub const fn connected() -> bool {
        false
    }

    #[must_use]
    pub const fn native_provider() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_provider_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn independent_readback() -> bool {
        false
    }

    #[must_use]
    pub const fn causal_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn recovery_authority() -> bool {
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

    #[must_use]
    pub const fn kernel_authority() -> bool {
        false
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AzureResourceHealthError {
    #[error("Azure Resource Health contract is invalid: {0}")]
    Contract(String),
    #[error(transparent)]
    Plugin(#[from] PluginError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureResourceHealthContract {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub layer: u8,
    pub authority: ContractAuthority,
    pub provider: ContractProvider,
    pub bounds: ContractBounds,
    pub registration: ContractRegistration,
    pub exact_scope: Vec<String>,
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractAuthority {
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub durable_provider_receipt: bool,
    pub independent_readback: bool,
    pub verification_authority: bool,
    pub causal_authority: bool,
    pub recovery_authority: bool,
    pub external_writes: bool,
    pub support_case_authority: bool,
    pub outcome_authority: bool,
    pub kernel_authority: bool,
    pub health_mutation: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractProvider {
    pub id: String,
    pub name: String,
    pub version: String,
    pub api_version: String,
    pub api_revision: String,
    pub origin: String,
    pub allowlisted_get_paths: Vec<String>,
    pub permissions: Vec<String>,
    pub transport_provenance: Vec<String>,
    pub native_https: bool,
    pub native_entra_resolution: bool,
    pub connected: bool,
    pub raw_request_body: bool,
    pub raw_response_body: bool,
    pub raw_descriptions: bool,
    pub raw_recommendations: bool,
    pub raw_tags: bool,
    pub raw_tenant_pii: bool,
    pub credentials: bool,
    pub external_writes: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractBounds {
    pub max_event_window_days: i64,
    pub max_response_bytes: usize,
    pub max_events: usize,
    pub max_affected_resource_digests_per_event: usize,
    pub max_cursor_bytes: usize,
    pub max_identifier_bytes: usize,
    pub max_region_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractRegistration {
    pub version_bound: bool,
    pub contract_digest_bound: bool,
    pub provider_digest_bound: bool,
    pub api_digest_bound: bool,
    pub permission_digest_bound: bool,
    pub resource_digest_bound: bool,
    pub resource_revision_bound: bool,
    pub event_window_digest_bound: bool,
    pub scope_digest_bound: bool,
    pub secret_reference_digest_bound: bool,
    pub evidence_digest_bound: bool,
    pub reversible: bool,
    pub revocable: bool,
    pub rotation_on_state_change: bool,
    pub fail_closed_on: Vec<String>,
}

impl AzureResourceHealthContract {
    pub fn baseline() -> Result<Self, AzureResourceHealthError> {
        let contract = serde_json::from_str::<Self>(AZURE_RESOURCE_HEALTH_CONTRACT_JSON)
            .map_err(|error| AzureResourceHealthError::Contract(error.to_string()))?;
        contract.validate()?;
        Ok(contract)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<(), AzureResourceHealthError> {
        let authority = &self.authority;
        let provider = &self.provider;
        let registration = &self.registration;
        if self.schema_version != AZURE_RESOURCE_HEALTH_SCHEMA_VERSION
            || self.contract_version != AZURE_RESOURCE_HEALTH_CONTRACT_VERSION
            || self.plugin_version != AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT
            || self.layer != 1
            || !authority.read_only
            || !authority.proposal_only
            || authority.connected
            || authority.native_provider
            || authority.durable_provider_receipt
            || authority.independent_readback
            || authority.verification_authority
            || authority.causal_authority
            || authority.recovery_authority
            || authority.external_writes
            || authority.support_case_authority
            || authority.outcome_authority
            || authority.kernel_authority
            || authority.health_mutation
            || provider.id != AZURE_RESOURCE_HEALTH_PROVIDER_ID
            || provider.version != AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT
            || provider.api_version != AZURE_RESOURCE_HEALTH_API_VERSION
            || provider.api_revision != AZURE_RESOURCE_HEALTH_API_REVISION
            || provider.native_https
            || provider.native_entra_resolution
            || provider.connected
            || provider.raw_request_body
            || provider.raw_response_body
            || provider.raw_descriptions
            || provider.raw_recommendations
            || provider.raw_tags
            || provider.raw_tenant_pii
            || provider.credentials
            || provider.external_writes
            || self.bounds.max_event_window_days != model::MAX_EVENT_WINDOW_DAYS
            || self.bounds.max_response_bytes != model::MAX_RESPONSE_BYTES
            || self.bounds.max_events != model::MAX_EVENTS
            || self.bounds.max_affected_resource_digests_per_event
                != model::MAX_AFFECTED_RESOURCE_DIGESTS_PER_EVENT
            || self.bounds.max_cursor_bytes != model::MAX_CURSOR_BYTES
            || self.bounds.max_identifier_bytes != model::MAX_IDENTIFIER_BYTES
            || self.bounds.max_region_bytes != model::MAX_REGION_BYTES
            || !registration.version_bound
            || !registration.contract_digest_bound
            || !registration.provider_digest_bound
            || !registration.api_digest_bound
            || !registration.permission_digest_bound
            || !registration.resource_digest_bound
            || !registration.resource_revision_bound
            || !registration.event_window_digest_bound
            || !registration.scope_digest_bound
            || !registration.secret_reference_digest_bound
            || !registration.evidence_digest_bound
            || !registration.reversible
            || !registration.revocable
            || !registration.rotation_on_state_change
        {
            return Err(AzureResourceHealthError::Contract(
                "contract document violates the Layer-1 authority, bounds, or registration fence"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn plugin_definition(scope: PluginScope) -> Result<PluginDefinition, AzureResourceHealthError> {
    let plugin_id = PluginId::new("azure-resource-health-result")?;
    let service_id = ServiceId::new(AZURE_RESOURCE_HEALTH_SERVICE_ID)?;
    let provider_id = ProviderId::new(AZURE_RESOURCE_HEALTH_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(MISSION_AZURE_RESOURCE_HEALTH_CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(AZURE_RESOURCE_HEALTH_SERVICE_ID),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![RuntimeProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(AZURE_RESOURCE_HEALTH_PROVIDER_ID),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(MISSION_AZURE_RESOURCE_HEALTH_CONSUMER_ID),
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

#[cfg(test)]
mod contract_document_tests {
    use super::{
        AZURE_RESOURCE_HEALTH_API_REVISION, AZURE_RESOURCE_HEALTH_API_VERSION,
        AZURE_RESOURCE_HEALTH_CONTRACT_VERSION, AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT,
        AZURE_RESOURCE_HEALTH_PROVIDER_ID, AZURE_RESOURCE_HEALTH_SCHEMA_VERSION,
        AzureResourceHealthContract, Layer1Authority,
    };

    #[test]
    fn contract_document_is_machine_readable_and_layer_one_honest() {
        let contract = AzureResourceHealthContract::baseline().expect("contract");
        assert_eq!(
            contract.schema_version,
            AZURE_RESOURCE_HEALTH_SCHEMA_VERSION
        );
        assert_eq!(
            contract.contract_version,
            AZURE_RESOURCE_HEALTH_CONTRACT_VERSION
        );
        assert_eq!(
            contract.plugin_version,
            AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT
        );
        assert_eq!(contract.layer, 1);
        assert_eq!(contract.provider.id, AZURE_RESOURCE_HEALTH_PROVIDER_ID);
        assert_eq!(
            contract.provider.api_version,
            AZURE_RESOURCE_HEALTH_API_VERSION
        );
        assert_eq!(
            contract.provider.api_revision,
            AZURE_RESOURCE_HEALTH_API_REVISION
        );
        assert!(!contract.authority.connected);
        assert!(!contract.authority.native_provider);
        assert!(!contract.authority.outcome_authority);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::outcome_authority());
    }
}
