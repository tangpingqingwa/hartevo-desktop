//! Layer-1 governed AWS Organizations hierarchy and policy evidence.
//!
//! This crate is intentionally a standalone nested Cargo workspace. It owns
//! typed read/proposal/record/verify seams for the three bounded AWS
//! Organizations list operations, but it is not an AWS Organizations control
//! plane. It never creates or moves accounts/OUs, changes policy attachments,
//! resolves credentials, retains policy documents, or claims connected/native
//! authority.

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

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{ConsumerError, MissionAwsOrganizationsConsumer, MissionAwsOrganizationsResult};
pub use model::{
    AccountId, AttachmentDirection, AttachmentObservation, AttachmentState, AuthorityKind,
    AwsOrganizationsScope, ConsentBinding, Digest, EvidenceDigests, GovernanceTargetKind,
    HierarchyNode, MissionBinding, MissionId, ModelError, OpaquePageToken, OrganizationHierarchy,
    OrganizationId, OrganizationalUnitId, PermissionScope, PolicyArn, PolicyId, PolicyIdentity,
    PolicyRevision, PolicySummary, PolicyType, ProjectId, ReadBounds, ReadOperation, Registration,
    RegistrationRevocation, RegistrationState, RevisionId, RootId, SecretReference,
    SigV4SecretReference, TargetId, TargetReference, WorkProductId,
};
pub use provider::{
    AwsOrganizationsProvider, AwsOrganizationsProviderDefinition, AwsOrganizationsReadRecord,
    AwsOrganizationsRecordPage, AwsOrganizationsTransport, BlockedEnvTransport,
    FixtureAwsOrganizationsTransport, ListPoliciesForTargetPage, ListPoliciesForTargetRequest,
    ListPoliciesPage, ListPoliciesRequest, ListTargetsForPolicyPage, ListTargetsForPolicyRequest,
    LoopbackAwsOrganizationsTransport, ProviderError, ProviderProvenance,
    RecordingAwsOrganizationsTransport, TransportCall, TransportError, TransportFailure,
};
pub use service::{
    AuthorityBoundary, AwsOrganizationsGovernanceEvidence, AwsOrganizationsGovernanceProposal,
    AwsOrganizationsGovernanceService, AwsOrganizationsReadRequest, AwsOrganizationsReadResult,
    ContractDocumentError, EvidenceStatus, PaginationEvidence, RedactionSummary, ServiceDefinition,
    ServiceError,
};

pub const AWS_ORGANIZATIONS_GOVERNANCE_SCHEMA_VERSION: &str =
    "hartevo-aws-organizations-governance-result-contract/v1";
pub const AWS_ORGANIZATIONS_GOVERNANCE_CONTRACT_VERSION: &str =
    "aws-organizations-governance-result-e1/v1";
pub const AWS_ORGANIZATIONS_GOVERNANCE_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-organizations-governance-result/aws-organizations-governance-result.v1.json"
);
pub const AWS_ORGANIZATIONS_GOVERNANCE_SERVICE_ID: &str = "aws.organizations.governance.result";
pub const AWS_ORGANIZATIONS_GOVERNANCE_PROVIDER_ID: &str = "aws.organizations.read";
pub const AWS_ORGANIZATIONS_GOVERNANCE_CONSUMER_ID: &str = "mission.aws.organizations.governance";
pub const AWS_ORGANIZATIONS_API_VERSION: &str = "2016-11-28";
pub const AWS_ORGANIZATIONS_PROVIDER_VERSION: &str = "aws-organizations-provider/v1";
pub const AWS_ORGANIZATIONS_EVIDENCE_LEVEL: &str = "E1";
pub const AWS_ORGANIZATIONS_BLOCKED_ENV: &str = "BLOCKED_ENV";

/// Layer 1's explicit authority boundary.
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

    pub const fn effective_authorization() -> bool {
        false
    }

    pub const fn policy_truth_authority() -> bool {
        false
    }

    pub const fn durable_receipt() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use serde::Deserialize;

    use super::{
        AWS_ORGANIZATIONS_API_VERSION, AWS_ORGANIZATIONS_BLOCKED_ENV,
        AWS_ORGANIZATIONS_GOVERNANCE_CONSUMER_ID, AWS_ORGANIZATIONS_GOVERNANCE_CONTRACT_JSON,
        AWS_ORGANIZATIONS_GOVERNANCE_CONTRACT_VERSION, AWS_ORGANIZATIONS_GOVERNANCE_PROVIDER_ID,
        AWS_ORGANIZATIONS_GOVERNANCE_SCHEMA_VERSION, AWS_ORGANIZATIONS_GOVERNANCE_SERVICE_ID,
        AWS_ORGANIZATIONS_PROVIDER_VERSION, Layer1Authority,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        evidence_level: String,
        layer: u8,
        service: ServiceDocument,
        provider: ProviderDocument,
        consumer: ConsumerDocument,
        native_claims: NativeClaims,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ServiceDocument {
        id: String,
        read_only: bool,
        live_execution: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderDocument {
        id: String,
        api_version: String,
        provider_version: String,
        native: bool,
        first_party: bool,
        connected: bool,
        read_only: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConsumerDocument {
        id: String,
        adopts_outcome: bool,
        truth_authority: bool,
        effective_authorization: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NativeClaims {
        connected: bool,
        native_provider: bool,
        first_party: bool,
        durable_receipt: bool,
        effective_authorization: bool,
        policy_truth_authority: bool,
        blocked_environment_is_native: bool,
    }

    #[test]
    fn contract_document_is_layer_one_and_matches_code() {
        let document =
            serde_json::from_str::<ContractDocument>(AWS_ORGANIZATIONS_GOVERNANCE_CONTRACT_JSON)
                .expect("AWS Organizations contract JSON");
        assert_eq!(
            document.schema_version,
            AWS_ORGANIZATIONS_GOVERNANCE_SCHEMA_VERSION
        );
        assert_eq!(
            document.contract_version,
            AWS_ORGANIZATIONS_GOVERNANCE_CONTRACT_VERSION
        );
        assert_eq!(document.evidence_level, "E1");
        assert_eq!(document.layer, 1);
        assert_eq!(document.service.id, AWS_ORGANIZATIONS_GOVERNANCE_SERVICE_ID);
        assert!(document.service.read_only);
        assert!(!document.service.live_execution);
        assert_eq!(
            document.provider.id,
            AWS_ORGANIZATIONS_GOVERNANCE_PROVIDER_ID
        );
        assert_eq!(document.provider.api_version, AWS_ORGANIZATIONS_API_VERSION);
        assert_eq!(
            document.provider.provider_version,
            AWS_ORGANIZATIONS_PROVIDER_VERSION
        );
        assert!(document.provider.read_only);
        assert!(!document.provider.native);
        assert!(!document.provider.first_party);
        assert!(!document.provider.connected);
        assert_eq!(
            document.consumer.id,
            AWS_ORGANIZATIONS_GOVERNANCE_CONSUMER_ID
        );
        assert!(!document.consumer.adopts_outcome);
        assert!(!document.consumer.truth_authority);
        assert!(!document.consumer.effective_authorization);
        assert!(!document.native_claims.connected);
        assert!(!document.native_claims.native_provider);
        assert!(!document.native_claims.first_party);
        assert!(!document.native_claims.durable_receipt);
        assert!(!document.native_claims.effective_authorization);
        assert!(!document.native_claims.policy_truth_authority);
        assert!(!document.native_claims.blocked_environment_is_native);
        assert_eq!(AWS_ORGANIZATIONS_BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::effective_authorization());
        assert!(!Layer1Authority::policy_truth_authority());
        assert!(!Layer1Authority::durable_receipt());
    }
}
