//! Standalone Layer-1 governed AWS CloudTrail control-plane audit result.
//!
//! The crate is intentionally limited to bounded `LookupEvents` proposal,
//! recording, verification, and Mission consumption.  It never creates or
//! updates trails or event stores, executes Lake SQL, writes events, exports
//! raw audit logs, resolves access keys, claims Connected/native status, or
//! claims that an external AWS effect succeeded.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::if_not_else,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
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
    ConsumerError, MissionCloudTrailAuditConsumer, MissionCloudTrailAuditResult,
    MissionCloudTrailAuditState,
};
pub use model::*;
pub use provider::{
    AwsCloudTrailLookupTransport, AwsCloudTrailProvider, AwsCloudTrailProviderDefinition,
    AwsCloudTrailProviderError, BlockedEnvAwsCloudTrailTransport, FakeAwsCloudTrailProvider,
    FakeAwsCloudTrailTransport, LookupEventsPage, LookupEventsProposal, LookupEventsRecord,
    LookupEventsRequest, LookupResponseStatus, OpaqueCursor, ProviderFailureClass,
    ProviderProvenance, RecordingAwsCloudTrailTransport, fake_cursor_for_page,
};
pub use service::{
    AwsCloudTrailAuditOperation, AwsCloudTrailAuditService, AwsCloudTrailAuditServiceDefinition,
    AwsCloudTrailCapability, AwsCloudTrailRegistration, AwsCloudTrailServiceError,
    LookupEventsRead, RegistrationError, RegistrationState,
};

pub const AWS_CLOUDTRAIL_AUDIT_SCHEMA_VERSION: &str =
    "hartevo.aws-cloudtrail-audit-result-contract/v1";
pub const AWS_CLOUDTRAIL_AUDIT_CONTRACT_VERSION: &str = "aws-cloudtrail-audit-result/v1";
pub const AWS_CLOUDTRAIL_AUDIT_PLUGIN_ID: &str = "aws-cloudtrail-audit-result";
pub const AWS_CLOUDTRAIL_AUDIT_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const AWS_CLOUDTRAIL_API_VERSION: &str = "2013-11-01";
pub const AWS_CLOUDTRAIL_AUDIT_SERVICE_ID: &str = "aws.cloudtrail.audit";
pub const AWS_CLOUDTRAIL_AUDIT_SERVICE_NAME: &str = "AwsCloudTrailAuditService";
pub const AWS_CLOUDTRAIL_AUDIT_PROVIDER_ID: &str = "aws.cloudtrail.lookup-events";
pub const AWS_CLOUDTRAIL_AUDIT_PROVIDER_SCHEMA: &str = "hartevo.aws-cloudtrail-audit-provider/v1";
pub const AWS_CLOUDTRAIL_AUDIT_PROVIDER_REVISION: &str =
    "aws-cloudtrail-lookup-events-2013-11-01-r1";
pub const AWS_CLOUDTRAIL_AUDIT_SERVICE_SCHEMA: &str = "hartevo.aws-cloudtrail-audit-service/v1";
pub const MISSION_CLOUDTRAIL_AUDIT_CONSUMER_ID: &str = "mission.aws-cloudtrail.audit";
pub const MISSION_CLOUDTRAIL_AUDIT_CONSUMER_SCHEMA: &str =
    "hartevo.mission-aws-cloudtrail-audit-consumer/v1";
pub const AWS_CLOUDTRAIL_AUDIT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-cloudtrail-audit-result/aws-cloudtrail-audit-result.v1.json"
);
pub const AWS_CLOUDTRAIL_BLOCKED_ENV: &str = "BLOCKED_ENV";

pub fn contract_digest() -> Digest {
    Digest::from_bytes(AWS_CLOUDTRAIL_AUDIT_CONTRACT_JSON.as_bytes())
}

pub fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Builds a runtime contribution set for one exact Project/Mission scope.
/// Runtime mounting remains a host concern and does not create native AWS
/// authority.
pub fn plugin_definition(scope: PluginScope) -> Result<PluginDefinition, PluginError> {
    let plugin_id = PluginId::new(AWS_CLOUDTRAIL_AUDIT_PLUGIN_ID)?;
    let service_id = ServiceId::new(AWS_CLOUDTRAIL_AUDIT_SERVICE_ID)?;
    let provider_id = ProviderId::new(AWS_CLOUDTRAIL_AUDIT_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(MISSION_CLOUDTRAIL_AUDIT_CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(AWS_CLOUDTRAIL_AUDIT_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(AWS_CLOUDTRAIL_AUDIT_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(MISSION_CLOUDTRAIL_AUDIT_CONSUMER_SCHEMA),
        )?],
        events: Vec::new(),
        ui_surfaces: Vec::new(),
    };
    PluginDefinition::new(plugin_id, version, scope, contributions)
}

#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[error("AWS CloudTrail audit Layer-1 error: {message}")]
pub struct AwsCloudTrailAuditError {
    pub message: String,
}

/// Layer-1 authority facts are deliberately constant and negative for native
/// claims.  A later host integration must introduce its own authority.
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

    pub const fn raw_audit_log() -> bool {
        false
    }

    pub const fn successful_resource_state() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use serde::Deserialize;

    use super::{
        AWS_CLOUDTRAIL_API_VERSION, AWS_CLOUDTRAIL_AUDIT_CONTRACT_JSON,
        AWS_CLOUDTRAIL_AUDIT_CONTRACT_VERSION, AWS_CLOUDTRAIL_AUDIT_PROVIDER_ID,
        AWS_CLOUDTRAIL_AUDIT_SCHEMA_VERSION, AWS_CLOUDTRAIL_AUDIT_SERVICE_ID,
        AWS_CLOUDTRAIL_BLOCKED_ENV, AwsCloudTrailAuditServiceDefinition, Layer1Authority,
        MISSION_CLOUDTRAIL_AUDIT_CONSUMER_ID, contract_digest,
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
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderDocument {
        id: String,
        native: bool,
        live_execution: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConsumerDocument {
        id: String,
        mission_bound: bool,
        work_product_bound: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AuthorityDocument {
        external_writes: bool,
        raw_cloud_trail_event: bool,
        raw_response_body: bool,
        successful_external_effect: bool,
        connected: bool,
        native_provider: bool,
    }

    #[test]
    fn contract_document_is_layer_one_and_honest() {
        let document = serde_json::from_str::<ContractDocument>(AWS_CLOUDTRAIL_AUDIT_CONTRACT_JSON)
            .expect("CloudTrail contract JSON");
        assert_eq!(document.schema_version, AWS_CLOUDTRAIL_AUDIT_SCHEMA_VERSION);
        assert_eq!(
            document.contract_version,
            AWS_CLOUDTRAIL_AUDIT_CONTRACT_VERSION
        );
        assert_eq!(document.layer, 1);
        assert_eq!(document.api_version, AWS_CLOUDTRAIL_API_VERSION);
        assert_eq!(document.service.id, AWS_CLOUDTRAIL_AUDIT_SERVICE_ID);
        assert!(document.service.read_only);
        assert!(!document.service.connected);
        assert_eq!(document.provider.id, AWS_CLOUDTRAIL_AUDIT_PROVIDER_ID);
        assert!(!document.provider.native);
        assert!(!document.provider.live_execution);
        assert_eq!(document.consumer.id, MISSION_CLOUDTRAIL_AUDIT_CONSUMER_ID);
        assert!(document.consumer.mission_bound);
        assert!(document.consumer.work_product_bound);
        assert!(!document.authority.external_writes);
        assert!(!document.authority.raw_cloud_trail_event);
        assert!(!document.authority.raw_response_body);
        assert!(!document.authority.successful_external_effect);
        assert!(!document.authority.connected);
        assert!(!document.authority.native_provider);
        assert_eq!(AWS_CLOUDTRAIL_BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::external_effect());
        assert!(!Layer1Authority::raw_audit_log());
        assert!(!Layer1Authority::successful_resource_state());
        assert_eq!(contract_digest().as_str().len(), 64);
        assert!(
            AwsCloudTrailAuditServiceDefinition::new()
                .validate()
                .is_ok()
        );
    }
}
