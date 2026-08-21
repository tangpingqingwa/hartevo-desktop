//! Standalone Layer 1 Microsoft SharePoint knowledge-result plugin.
//!
//! The root owns only a typed Microsoft Graph v1.0 metadata/projection seam,
//! a redacted Mission proposal boundary, and its contract. It never exposes
//! raw bytes, content, download URLs, PII, native Connected status, or any
//! SharePoint mutation. Native Entra credentials, content readback, receipts,
//! verification, and Work Product adoption remain Layer 2 gaps.

#![deny(unsafe_code)]

mod consumer;
mod error;
mod model;
mod provider;
mod service;
mod transport;

pub use consumer::MissionSharePointKnowledgeConsumer;
pub use error::{
    EntraCredentialError, MicrosoftGraphSharePointProviderError, SharePointKnowledgeResultError,
    SharePointTransportError,
};
pub use model::*;
pub use provider::{
    BlockedEnvCredentialResolver, CredentialLease, EntraCredentialLease, EntraCredentialResolver,
    FixtureEntraCredentialResolver, MicrosoftGraphSharePointProvider,
    MicrosoftGraphSharePointProviderCall, MicrosoftGraphSharePointProviderState, ProviderCall,
    ProviderState, RegistrationRequest, SharePointRegistrationRequest,
    StaticEntraCredentialResolver,
};
pub use service::{
    SharePointKnowledgeResultOperation, SharePointKnowledgeResultService,
    SharePointKnowledgeResultServiceDefinition,
};
pub use transport::{
    BlockedEnvTransport, DriveItemDeltaPayload, DriveItemMetadataPayload, DriveItemSearchPayload,
    DriveItemVersionPayload, FakeSharePointTransport, FixtureSharePointTransport,
    LoopbackSharePointTransport, MicrosoftGraphOperation, MicrosoftGraphRequest,
    MicrosoftGraphResponse, MicrosoftGraphResponseBody, MicrosoftGraphSharePointTransport,
    RecordingMicrosoftGraphTransport, RecordingSharePointTransport, SharePointFixture,
    SharePointGraphOperation, SharePointRequestReceipt, SharePointTransport,
};

pub const SHAREPOINT_RESULT_SCHEMA_VERSION: &str = "hartevo.sharepoint-knowledge-result/v1";
pub const SHAREPOINT_CONTRACT_VERSION: &str = "EXT-SHAREPOINT-KNOWLEDGE-01-L1/v1";
pub const SHAREPOINT_PLUGIN_ID: &str = "sharepoint-knowledge-result";
pub const SHAREPOINT_PLUGIN_VERSION: &str = "1.0.0";
pub const SHAREPOINT_PROVIDER_ID: &str = "MicrosoftGraphSharePointProvider";
pub const SHAREPOINT_SERVICE_ID: &str = "SharePointKnowledgeResultService";
pub const SHAREPOINT_MISSION_CONSUMER_ID: &str = "MissionSharePointKnowledgeConsumer";
pub const SHAREPOINT_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/sharepoint-knowledge-result/sharepoint-knowledge-result.v1.json"
);
pub const SHAREPOINT_NATIVE_PROBE_ENV: &str = "HARTEVO_SHAREPOINT_NATIVE_PROBE";

pub fn contract_digest() -> Digest {
    sha256_digest(SHAREPOINT_RESULT_CONTRACT_JSON.as_bytes())
}

pub fn native_probe_from_environment() -> NativeProbe {
    provider::native_probe_from_environment()
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        SHAREPOINT_CONTRACT_VERSION, SHAREPOINT_RESULT_CONTRACT_JSON,
        SHAREPOINT_RESULT_SCHEMA_VERSION, SharePointKnowledgeResultServiceDefinition,
        contract_digest,
    };

    #[test]
    fn contract_freezes_scope_redaction_and_honest_native_gap() {
        let contract: Value =
            serde_json::from_str(SHAREPOINT_RESULT_CONTRACT_JSON).expect("contract JSON");
        assert_eq!(contract["schemaVersion"], SHAREPOINT_RESULT_SCHEMA_VERSION);
        assert_eq!(contract["contractVersion"], SHAREPOINT_CONTRACT_VERSION);
        assert_eq!(contract["layer"], 1);
        assert_eq!(contract["api"]["version"], "v1.0");
        assert_eq!(contract["api"]["odataNextLink"], true);
        assert_eq!(contract["api"]["opaqueNextLink"], true);
        assert_eq!(contract["scope"]["tenantFenced"], true);
        assert_eq!(contract["scope"]["nationalCloudFenced"], true);
        assert_eq!(contract["scope"]["permissionFenced"], true);
        assert_eq!(contract["readBoundaries"]["maxResponseFieldBytes"], 4096);
        assert_eq!(contract["redaction"]["rawBytes"], false);
        assert_eq!(contract["redaction"]["downloadUrls"], false);
        assert_eq!(contract["redaction"]["pii"], false);
        assert_eq!(contract["authority"]["upload"], false);
        assert_eq!(contract["authority"]["permissionMutation"], false);
        assert_eq!(contract["native"]["fixtureConnected"], false);
        assert_eq!(contract["native"]["recordingNative"], false);
        assert_eq!(contract["native"]["blockedEnvConnected"], false);
        assert_eq!(contract_digest().len(), 64);
    }

    #[test]
    fn service_definition_is_typed_and_read_only() {
        let definition = SharePointKnowledgeResultServiceDefinition::layer1();
        definition.validate().expect("valid Layer 1 definition");
        assert_eq!(definition.operations.len(), 7);
        assert!(definition.read_only);
        assert!(!definition.external_writes);
        assert!(!definition.durable_native_receipts);
        assert!(!definition.independent_readback);
        assert!(!definition.kernel_outcome_authority);
        assert!(!definition.work_product_adoption);
    }
}
