//! Standalone Layer-1 Google Cloud Organization Policy evidence boundary.
//!
//! The crate owns typed, bounded read/proposal/record/verify seams for
//! organization-policy metadata. It does not resolve OAuth or service-account
//! credentials, perform live HTTPS, mutate policies or constraints, retain raw
//! policy values/members, claim effective authorization, or adopt Hartevo
//! Truth, Outcome, Receipt, or Work Product authority.

#![forbid(unsafe_code)]
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

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConsumerError, MissionGcpOrgPolicyConsumer, MissionGcpOrgPolicyResult,
    RecordedMissionGcpOrgPolicyResult,
};
pub use model::{
    AvailableConstraintSummary, ConstraintId, ConstraintKind, Digest, FolderId, GcpAuthKind,
    GcpOrgPolicyScope, GcpProjectId, GcpResource, GoogleAuthKind, MissionId, MissionRevision,
    MissionScope, ModelError, OpaquePageToken, OrganizationId, PermissionScope, PolicyId,
    PolicyRevision, PolicyRuleMode, PolicySource, PolicyState, PolicySummary, ProjectId,
    ProjectRevision, ReadBounds, ReadOperation, RedactionSummary, ResourceId, ResourceKind,
    Revision, SecretReference, UntrustedAvailableConstraint, UntrustedPolicy, WorkProductId,
    WorkProductRevision,
};
pub use provider::{
    BlockedEnvTransport, ConstraintPage, FixtureGcpOrgPolicyTransport, GcpOrgPolicyProvider,
    GcpOrgPolicyProviderDefinition, GcpOrgPolicyReadRecord, GcpOrgPolicyTransport,
    GetEffectivePolicyRequest, GetPolicyRequest, GetPolicyResponse,
    ListAvailableConstraintsRequest, ListConstraintsPage, ListConstraintsRequest,
    ListPoliciesRequest, LoopbackGcpOrgPolicyTransport, PolicyPage, ProviderError,
    RecordingGcpOrgPolicyTransport, TransportCall, TransportError, TransportFailure,
    TransportProvenance,
};
pub use service::{
    AuthorityBoundary, GcpOrgPolicyEvidence, GcpOrgPolicyProposal, GcpOrgPolicyReadResult,
    GcpOrgPolicyRegistration, GcpOrgPolicyService, GcpOrgPolicyServiceError,
    RecordedGcpOrgPolicyResult, RegistrationState, RegistrationTransition, ServiceDefinition,
    VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.gcp-org-policy-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-GCP-ORG-POLICY-01-L1/v1";
pub const PLUGIN_ID: &str = "gcp.organization-policy.result";
pub const SERVICE_ID: &str = "gcp.organization-policy.result.read";
pub const PROVIDER_ID: &str = "gcp.organization-policy.recording";
pub const PROVIDER_API_REVISION: &str =
    "organization-policy-v2-list-get-effective-policy-constraints-1";
pub const CONSUMER_ID: &str = "mission.gcp-org-policy.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const API_VERSION: &str = "v2";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.gcp-org-policy-result/v1|layer=1|service=gcp.organization-policy.result.read|provider=gcp.organization-policy.recording|consumer=mission.gcp-org-policy.consumer";

pub const LAYER1_PERMISSIONS: [&str; 5] = [
    "orgpolicy.policies.list",
    "orgpolicy.policies.get",
    "orgpolicy.policies.getEffectivePolicy",
    "orgpolicy.constraints.list",
    "mission.scope",
];

pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/gcp-org-policy-result/gcp-org-policy-result.v1.json");

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

/// Layer 1's explicit authority boundary. Every method is a compile-time
/// discoverable reminder that this crate is review-only and non-native.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }

    pub const fn durable_provider_receipt() -> bool {
        false
    }

    pub const fn effective_authorization() -> bool {
        false
    }

    pub const fn policy_truth_authority() -> bool {
        false
    }

    pub const fn adopts_outcome() -> bool {
        false
    }

    pub const fn adopts_work_product() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use serde::Deserialize;

    use super::{
        API_VERSION, BLOCKED_ENV, CONSUMER_ID, CONTRACT_DIGEST_INPUT, CONTRACT_JSON,
        CONTRACT_SCHEMA, CONTRACT_VERSION, EVIDENCE_LEVEL, Layer1Authority, PROVIDER_API_REVISION,
        PROVIDER_ID, SERVICE_ID, contract_digest,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        plugin_id: String,
        layer: u8,
        evidence_level: String,
        digest_input: String,
        contract_digest: String,
        service: ServiceDocument,
        provider: ProviderDocument,
        consumer: ConsumerDocument,
        credentials: CredentialsDocument,
        native_claims: NativeClaims,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ServiceDocument {
        id: String,
        read_only: bool,
        proposal_only: bool,
        external_writes: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderDocument {
        id: String,
        api_version: String,
        api_revision: String,
        native: bool,
        connected: bool,
        first_party: bool,
        read_only: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConsumerDocument {
        id: String,
        adopts_outcome: bool,
        adopts_work_product: bool,
        effective_authorization: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CredentialsDocument {
        serialized: bool,
        raw_material_accepted: bool,
        native_resolution: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NativeClaims {
        connected: bool,
        native_provider: bool,
        first_party: bool,
        durable_provider_receipt: bool,
        effective_authorization: bool,
        policy_truth_authority: bool,
        blocked_environment_is_native: bool,
    }

    #[test]
    fn contract_is_layer_one_and_matches_exported_boundary() {
        let document = serde_json::from_str::<ContractDocument>(CONTRACT_JSON)
            .expect("GCP Organization Policy contract JSON");
        assert_eq!(document.schema_version, CONTRACT_SCHEMA);
        assert_eq!(document.contract_version, CONTRACT_VERSION);
        assert_eq!(document.plugin_id, super::PLUGIN_ID);
        assert_eq!(document.layer, 1);
        assert_eq!(document.evidence_level, EVIDENCE_LEVEL);
        assert_eq!(document.digest_input, CONTRACT_DIGEST_INPUT);
        assert_eq!(document.contract_digest, contract_digest().as_str());
        assert_eq!(document.service.id, SERVICE_ID);
        assert!(document.service.read_only);
        assert!(document.service.proposal_only);
        assert!(!document.service.external_writes);
        assert_eq!(document.provider.id, PROVIDER_ID);
        assert_eq!(document.provider.api_version, API_VERSION);
        assert_eq!(document.provider.api_revision, PROVIDER_API_REVISION);
        assert!(!document.provider.native);
        assert!(!document.provider.connected);
        assert!(!document.provider.first_party);
        assert!(document.provider.read_only);
        assert_eq!(document.consumer.id, CONSUMER_ID);
        assert!(!document.consumer.adopts_outcome);
        assert!(!document.consumer.adopts_work_product);
        assert!(!document.consumer.effective_authorization);
        assert!(!document.credentials.serialized);
        assert!(!document.credentials.raw_material_accepted);
        assert!(!document.credentials.native_resolution);
        assert!(!document.native_claims.connected);
        assert!(!document.native_claims.native_provider);
        assert!(!document.native_claims.first_party);
        assert!(!document.native_claims.durable_provider_receipt);
        assert!(!document.native_claims.effective_authorization);
        assert!(!document.native_claims.policy_truth_authority);
        assert!(!document.native_claims.blocked_environment_is_native);
        assert_eq!(BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::effective_authorization());
        assert!(!Layer1Authority::policy_truth_authority());
        assert!(!Layer1Authority::adopts_outcome());
        assert!(!Layer1Authority::adopts_work_product());
    }
}
