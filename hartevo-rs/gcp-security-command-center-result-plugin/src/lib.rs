//! Standalone Layer-1 Google Cloud Security Command Center finding-result
//! plugin.
//!
//! The crate contributes bounded, read-only observation evidence. It has no
//! live credential resolver, no live HTTPS transport, no provider mutation,
//! no raw provider payload retention, no Connected/native claim, and no
//! durable Work Product adoption authority.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
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

use hartevo_plugin_runtime::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId, Digest as RuntimeDigest,
    PluginContributions, PluginDefinition, PluginError, PluginId, PluginScope,
    PluginVersion as RuntimePluginVersion, ProviderCardinality, ProviderDefinition, ProviderId,
    ServiceDefinition, ServiceId,
};

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{
    ConsumerError, MissionGcpSecurityCenterConsumer, MissionGcpSecurityCenterResult,
};
pub use model::GroupBy as SecurityCenterGroupBy;
pub use model::*;
pub use provider::{
    FindingsGroupProposal, FindingsListProposal, GcpSecurityCenterError, GcpSecurityCenterProvider,
    GcpSecurityCenterRegistration, GcpSecurityCenterRegistrationRequest, RegistrationState,
};
pub use service::{
    GcpSecurityCenterCapability, GcpSecurityCenterOperation, GcpSecurityCenterService, ServiceError,
};
pub use transport::{
    BlockedEnvGcpSecurityCenterTransport, BlockedEnvTransport, FakeGcpSecurityCenterTransport,
    FindingsGroupResponse, FindingsListResponse, FixtureGcpSecurityCenterTransport,
    GcpSecurityCenterTransport, LoopbackGcpSecurityCenterTransport, RecordedSecurityCenterRequest,
    RecordingGcpSecurityCenterTransport, SECURITY_CENTER_API_ORIGIN, SECURITY_CENTER_API_VERSION,
    SecurityCenterEndpoint, SecurityCenterHttpRequest, TransportError,
};

pub const GCP_SECURITY_CENTER_RESULT_SCHEMA_VERSION: &str =
    "hartevo.gcp-security-command-center-result-contract/v1";
pub const GCP_SECURITY_CENTER_RESULT_CONTRACT_VERSION: &str =
    "gcp-security-command-center-result/v1";
pub const GCP_SECURITY_CENTER_RESULT_PLUGIN_ID: &str = "gcp-security-command-center-result";
pub const GCP_SECURITY_CENTER_RESULT_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const GCP_SECURITY_CENTER_RESULT_SERVICE_ID: &str = "gcp.security-command-center.result";
pub const GCP_SECURITY_CENTER_RESULT_SERVICE_NAME: &str = "GcpSecurityCenterService";
pub const GCP_SECURITY_CENTER_RESULT_SERVICE_SCHEMA: &str =
    "hartevo.gcp-security-command-center-result-service/v1";
pub const GCP_SECURITY_CENTER_RESULT_PROVIDER_ID: &str = "gcp.security-command-center.findings";
pub const GCP_SECURITY_CENTER_RESULT_PROVIDER_NAME: &str = "GcpSecurityCenterProvider";
pub const GCP_SECURITY_CENTER_RESULT_PROVIDER_SCHEMA: &str =
    "hartevo.gcp-security-command-center-result-provider/v1";
pub const MISSION_GCP_SECURITY_CENTER_RESULT_CONSUMER_ID: &str =
    "mission.gcp-security-command-center.result";
pub const MISSION_GCP_SECURITY_CENTER_RESULT_CONSUMER_NAME: &str =
    "MissionGcpSecurityCenterConsumer";
pub const MISSION_GCP_SECURITY_CENTER_RESULT_CONSUMER_SCHEMA: &str =
    "hartevo.mission-gcp-security-command-center-result-consumer/v1";
pub const GCP_SECURITY_CENTER_RESULT_PROVIDER_REVISION: &str = "security-center-v1-r1";
pub const GCP_SECURITY_CENTER_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/gcp-security-command-center-result/gcp-security-command-center-result.v1.json"
);

pub fn contract_digest() -> Digest {
    sha256_digest(GCP_SECURITY_CENTER_RESULT_CONTRACT_JSON.as_bytes())
}

pub const fn plugin_version() -> model::PluginVersion {
    model::PluginVersion::V1
}

/// The only authority exposed by this crate: bounded evidence for a later
/// Mission decision, never Connected/native Truth or durable adoption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
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

/// Builds the plugin-runtime contribution set for one exact Project/Mission
/// generation. Mounting remains an explicit host lifecycle action.
pub fn plugin_definition(scope: PluginScope) -> Result<PluginDefinition, PluginError> {
    let plugin_id = PluginId::new(GCP_SECURITY_CENTER_RESULT_PLUGIN_ID)?;
    let service_id = ServiceId::new(GCP_SECURITY_CENTER_RESULT_SERVICE_ID)?;
    let provider_id = ProviderId::new(GCP_SECURITY_CENTER_RESULT_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(MISSION_GCP_SECURITY_CENTER_RESULT_CONSUMER_ID)?;
    let version = RuntimePluginVersion::new(1, 0, 0);
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(GCP_SECURITY_CENTER_RESULT_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(GCP_SECURITY_CENTER_RESULT_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(MISSION_GCP_SECURITY_CENTER_RESULT_CONSUMER_SCHEMA),
        )?],
        events: Vec::new(),
        ui_surfaces: Vec::new(),
    };
    PluginDefinition::new(plugin_id, version, scope, contributions)
}

#[cfg(test)]
mod contract_document_tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn contract_document_is_layer_one_and_non_native() {
        let document: Value =
            serde_json::from_str(GCP_SECURITY_CENTER_RESULT_CONTRACT_JSON).expect("contract JSON");
        assert_eq!(
            document["schemaVersion"],
            GCP_SECURITY_CENTER_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            GCP_SECURITY_CENTER_RESULT_CONTRACT_VERSION
        );
        assert_eq!(document["layer"], 1);
        assert_eq!(
            document["service"]["id"],
            GCP_SECURITY_CENTER_RESULT_SERVICE_ID
        );
        assert_eq!(
            document["provider"]["id"],
            GCP_SECURITY_CENTER_RESULT_PROVIDER_ID
        );
        assert_eq!(
            document["consumer"]["id"],
            MISSION_GCP_SECURITY_CENTER_RESULT_CONSUMER_ID
        );
        assert_eq!(document["service"]["connected"], false);
        assert_eq!(document["service"]["native"], false);
        assert_eq!(document["service"]["durableAdoption"], false);
        assert!(
            document["mutatingProviderOperations"]
                .as_array()
                .is_some_and(Vec::is_empty)
        );
        assert_eq!(document["redaction"]["sourcePropertiesRetained"], false);
        assert_eq!(document["redaction"]["piiRetained"], false);
        assert_eq!(document["nativeGap"]["blockedEnvNative"], false);
        assert_eq!(
            contract_digest(),
            sha256_digest(GCP_SECURITY_CENTER_RESULT_CONTRACT_JSON.as_bytes())
        );
    }
}
