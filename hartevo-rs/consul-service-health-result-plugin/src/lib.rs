//! Standalone Layer-1 governed Consul service-health result seams.
//!
//! The crate deliberately stops at bounded, deterministic, redacted evidence
//! and a reversible proposal/record/verification seam.  It does not resolve a
//! Consul ACL token, perform a native HTTP request, write to Consul, mint a
//! kernel receipt, assert Truth, or adopt a Work Product.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    ConsumerError, MissionConsulServiceHealthConsumer, MissionConsulServiceHealthResult,
};
pub use model::{
    AdminPartition, CheckId, CheckStatus, ConsentCapability, ConsentScope, ConsulPermission,
    ConsulServiceHealthScope, ConsulServiceHealthScopeInput, Datacenter, Digest, EvidenceStatus,
    HttpsEndpoint, Mission, MissionId, MissionIdentity, ModelError, Namespace, NodeId, Permission,
    PermissionScope, Project, ProjectId, ProjectIdentity, ReadBounds, Revision, Scope,
    SecretReference, ServiceInstanceId, ServiceName, Tag, WorkProduct, WorkProductId,
    WorkProductIdentity,
};
pub use provider::{
    ACL_FILTERED_HEADER, BlockedEnvConsulHealthTransport, BlockedEnvTransport,
    CATALOG_SERVICE_PATH, CONSUL_INDEX_HEADER, CatalogServiceEntry, ConsulHealthProvider,
    ConsulHealthTransport, ConsulHttpRequest, ConsulHttpResponse, ConsulProviderDefinition,
    ConsulProviderRead, ConsulReadOperation, ConsulResponseBody, ConsulResponseOperation,
    ConsulServiceHealthReadRequest, FakeConsulHealthTransport, FakeTransport,
    FixtureConsulHealthTransport, FixtureTransport, HEALTH_SERVICE_PATH, HealthServiceEntry,
    HttpMethod, LoopbackConsulHealthTransport, LoopbackTransport, ProviderDefinition,
    ProviderDefinitionError, ProviderError, ProviderProvenance, RawCatalogServiceEntry, RawCheck,
    RawHealthServiceEntry, RawNode, RawService, RecordingConsulHealthTransport, RecordingTransport,
    TransportError, TransportFailure,
};
pub use service::{
    ConsulLocalRecord, ConsulRegistration, ConsulRegistrationError, ConsulServiceHealthEvidence,
    ConsulServiceHealthProposal, ConsulServiceHealthReadResult, ConsulServiceHealthResultService,
    ConsulVerification, FailureEvidence, ProviderFailure, RedactedCheck, RedactedServiceInstance,
    RedactionSummary, RegistrationState, ServiceError, VerificationState,
};

pub const PLUGIN_VERSION: &str = "0.1.0";
pub const SCHEMA_VERSION: &str = "hartevo-consul-service-health-result-contract/v1";
pub const CONTRACT_VERSION: &str = "consul-service-health-result-l1/v1";
pub const CONSUL_SERVICE_ID: &str = "consul.service-health.result";
pub const CONSUL_SERVICE_NAME: &str = "ConsulServiceHealthResultService";
pub const CONSUL_HEALTH_PROVIDER_ID: &str = "consul.health.read";
pub const CONSUL_HEALTH_PROVIDER_NAME: &str = "ConsulHealthProvider";
pub const CONSUL_HEALTH_PROVIDER_VERSION: &str = "consul-health-provider/v1";
pub const CONSUL_CONSUMER_ID: &str = "mission.consul.service-health";
pub const CONSUL_CONSUMER_NAME: &str = "MissionConsulServiceHealthConsumer";
pub const CONSUL_API_VERSION: &str = "v1";
pub const CONSUL_API_REVISION: &str = "health-service-catalog-service-v1";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/consul-service-health-result/consul-service-health-result.v1.json"
);

/// Compatibility aliases make the contract metadata easy to discover without
/// introducing a second set of identifiers.
pub const CONSUL_SERVICE_HEALTH_RESULT_CONTRACT_JSON: &str = CONTRACT_JSON;
pub const CONSUL_SERVICE_HEALTH_RESULT_SCHEMA_VERSION: &str = SCHEMA_VERSION;
pub const CONSUL_SERVICE_HEALTH_RESULT_CONTRACT_VERSION: &str = CONTRACT_VERSION;

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_JSON)
}

/// Layer-1 authority fence.  Every transport provenance, evidence, proposal,
/// record, and consumer result uses this false-only boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityBoundary {
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub truth: bool,
    pub consent: bool,
    pub effect: bool,
    pub receipt: bool,
    pub verification: bool,
    pub outcome: bool,
}

impl AuthorityBoundary {
    pub const fn layer_one() -> Self {
        Self {
            connected: false,
            native: false,
            first_party: false,
            truth: false,
            consent: false,
            effect: false,
            receipt: false,
            verification: false,
            outcome: false,
        }
    }

    pub const fn connected(self) -> bool {
        self.connected
    }

    pub const fn native(self) -> bool {
        self.native
    }

    pub const fn first_party(self) -> bool {
        self.first_party
    }

    pub const fn truth_authority(self) -> bool {
        self.truth
    }

    pub const fn consent_authority(self) -> bool {
        self.consent
    }

    pub const fn effect_authority(self) -> bool {
        self.effect
    }

    pub const fn receipt_authority(self) -> bool {
        self.receipt
    }

    pub const fn verification_authority(self) -> bool {
        self.verification
    }

    pub const fn outcome_authority(self) -> bool {
        self.outcome
    }

    pub const fn adopted(self) -> bool {
        self.outcome
    }
}

#[cfg(test)]
mod contract_document_tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn contract_document_is_layer_one_and_metadata_matches() {
        let document: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(document["schemaVersion"], SCHEMA_VERSION);
        assert_eq!(document["contractVersion"], CONTRACT_VERSION);
        assert_eq!(document["layer"], 1);
        assert_eq!(document["service"]["id"], CONSUL_SERVICE_ID);
        assert_eq!(document["provider"]["id"], CONSUL_HEALTH_PROVIDER_ID);
        assert_eq!(document["consumer"]["id"], CONSUL_CONSUMER_ID);
        assert!(!document["provider"]["connected"].as_bool().unwrap_or(true));
        assert!(!document["provider"]["native"].as_bool().unwrap_or(true));
        assert!(!document["provider"]["firstParty"].as_bool().unwrap_or(true));
        assert_eq!(document["blockedEnvironment"], BLOCKED_ENV);
        assert_eq!(contract_digest(), Digest::from_text(CONTRACT_JSON));
        assert_eq!(
            AuthorityBoundary::layer_one(),
            AuthorityBoundary::layer_one()
        );
    }
}
