//! Standalone Layer-1 AWS Entity Resolution match-evidence result boundary.
//!
//! This crate is intentionally below Hartevo Truth, Consent, Effect, Receipt,
//! Verification, Outcome, and durable Work Product authority. It models only
//! bounded workflow/schema/namespace metadata, digest-only dry-run match
//! proposals, reversible registration, and redacted Mission recording.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_excessive_bools,
    clippy::struct_field_names,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::similar_names
)]

use sha2::{Digest as ShaDigest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionAwsEntityResolutionConsumer, MissionAwsEntityResolutionResult, ProposalDisposition,
    RecordedAwsEntityResolutionResult,
};
pub use error::{AwsEntityResolutionError, AwsEntityResolutionTransportError, Result};
pub use model::*;
pub use provider::{
    AwsEntityResolutionOperation, AwsEntityResolutionProvider,
    AwsEntityResolutionProviderDefinition, AwsEntityResolutionTransport, BlockedEnvTransport,
    FixtureTransport, GetIdNamespaceRequest, GetMatchIdRequest, GetMatchIdResponse,
    GetMatchingWorkflowRequest, GetSchemaMappingRequest, IdNamespaceResponse,
    ListIdNamespacesRequest, ListIdNamespacesResponse, LoopbackTransport, MatchingWorkflowResponse,
    RecordedRequest, RecordingTransport, SchemaMappingResponse,
};
pub use service::{
    AwsEntityResolutionRegistration, AwsEntityResolutionResult, AwsEntityResolutionResultProposal,
    AwsEntityResolutionResultService, CapabilityDescription, FailureEvidence, RegistrationStatus,
    RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-entity-resolution-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-ENTITY-RESOLUTION-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-entity-resolution-result/v1|layer=1|service=aws.entity-resolution.result.read|provider=aws.entity-resolution.result.recording|consumer=mission.aws-entity-resolution.consumer";
pub const CONTRACT_DIGEST: &str =
    "da7bd0a4191183bf97e2cba6f98ecc19c731d170d42a2f627b3bc741a91dfefd";
pub const EVIDENCE_DIGEST_INPUT: &str =
    "hartevo.aws-entity-resolution-result/evidence/v1|redacted-match-group-rule-result-digests";
pub const PLUGIN_ID: &str = "aws.entity-resolution.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.entity-resolution.result.read";
pub const PROVIDER_ID: &str = "aws.entity-resolution.result.recording";
pub const PROVIDER_API_REVISION: &str =
    "list-id-namespaces-get-id-namespace-get-matching-workflow-get-schema-mapping-get-match-id-1";
pub const PROVIDER_REVISION: u64 = 1;
pub const CONSUMER_ID: &str = "mission.aws-entity-resolution.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-entity-resolution-result/contract.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_FIELD_BYTES: usize = 255;
pub const MAX_RECORD_FIELDS: usize = 32;
pub const MAX_PAGE_SIZE: u16 = 25;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

pub const LAYER1_PERMISSIONS: [&str; 6] = [
    "entityresolution:ListIdNamespaces",
    "entityresolution:GetIdNamespace",
    "entityresolution:GetMatchingWorkflow",
    "entityresolution:GetSchemaMapping",
    "entityresolution:GetMatchId",
    "mission.scope",
];

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

pub fn evidence_contract_digest() -> model::Digest {
    model::Digest::from_text(EVIDENCE_DIGEST_INPUT)
}

#[cfg(test)]
mod contract_tests {
    use serde::Deserialize;

    use super::{
        CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA,
        CONTRACT_VERSION, EVIDENCE_LEVEL, PLUGIN_ID, PROVIDER_ID, SERVICE_ID, contract_digest,
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
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ServiceDocument {
        id: String,
        read_only: bool,
        external_writes: bool,
        identity_mutation: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderDocument {
        id: String,
        connected_evidence: bool,
        native_evidence: bool,
        first_party_evidence: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConsumerDocument {
        id: String,
        adopts_outcome: bool,
        adopts_work_product: bool,
        identity_authority: bool,
    }

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract = serde_json::from_str::<ContractDocument>(CONTRACT_JSON)
            .expect("checked AWS Entity Resolution contract");
        assert_eq!(contract.schema_version, CONTRACT_SCHEMA);
        assert_eq!(contract.contract_version, CONTRACT_VERSION);
        assert_eq!(contract.plugin_id, PLUGIN_ID);
        assert_eq!(contract.layer, 1);
        assert_eq!(contract.evidence_level, EVIDENCE_LEVEL);
        assert_eq!(contract.digest_input, CONTRACT_DIGEST_INPUT);
        assert_eq!(contract.contract_digest, CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert_eq!(contract.service.id, SERVICE_ID);
        assert!(contract.service.read_only);
        assert!(!contract.service.external_writes);
        assert!(!contract.service.identity_mutation);
        assert_eq!(contract.provider.id, PROVIDER_ID);
        assert!(!contract.provider.connected_evidence);
        assert!(!contract.provider.native_evidence);
        assert!(!contract.provider.first_party_evidence);
        assert_eq!(contract.consumer.id, CONSUMER_ID);
        assert!(!contract.consumer.adopts_outcome);
        assert!(!contract.consumer.adopts_work_product);
        assert!(!contract.consumer.identity_authority);
    }
}
