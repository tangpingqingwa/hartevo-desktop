//! Standalone Layer-1 AWS Clean Rooms protected-query result boundary.
//!
//! This crate is intentionally below Hartevo Truth, Consent, Effect, Receipt,
//! Verification, Outcome, and durable Work Product authority. It models only
//! bounded Clean Rooms metadata reads, digest fences, reversible registration,
//! and a Mission-scoped proposal/record seam. Recording, fixture, loopback,
//! and `BLOCKED_ENV` transports are always non-connected, non-native, and
//! non-first-party.

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
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

use sha2::{Digest as ShaDigest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionAwsCleanRoomsConsumer, MissionAwsCleanRoomsResult, ProposalDisposition,
    RecordedAwsCleanRoomsResult,
};
pub use error::{AwsCleanRoomsQueryResultError, AwsCleanRoomsTransportError, Result};
pub use model::*;
pub use provider::{
    AwsCleanRoomsOperation, AwsCleanRoomsProvider, AwsCleanRoomsProviderDefinition,
    AwsCleanRoomsTransport, BlockedEnvTransport, FixtureTransport, GetProtectedQueryRequest,
    GetProtectedQueryResponse, ListProtectedQueriesRequest, ListProtectedQueriesResponse,
    LoopbackTransport, RecordedRequest, RecordingTransport,
};
pub use service::{
    AwsCleanRoomsQueryResultProposal, AwsCleanRoomsQueryResultRegistration,
    AwsCleanRoomsQueryResultService, AwsCleanRoomsRegistration, CapabilityDescription,
    FailureEvidence, ProtectedQueryEvidenceRequest, RegistrationStatus,
    RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};

pub type AwsCleanRoomsError = AwsCleanRoomsQueryResultError;
pub type AwsCleanRoomsScope = AwsCleanRoomsQueryResultScope;

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-clean-rooms-query-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-CLEAN-ROOMS-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-clean-rooms-query-result/v1|layer=1|service=aws.clean-rooms.query-result.read|provider=aws.clean-rooms.query-result.recording|consumer=mission.aws-clean-rooms-query-result.consumer|api=clean-rooms-get-protected-query-list-protected-queries-2020-05-04-r1";
pub const CONTRACT_DIGEST: &str =
    "9f0c9b2ebda9e446370974997c08f9a5b76cbb4efe3d893394b58a719daaf1fd";
pub const EVIDENCE_CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-clean-rooms-query-result/evidence/v1|states=SUBMITTED,STARTED,CANCELLING,SUCCESS,FAILED,CANCELLED,TIMED_OUT,PARTIAL,ACCESS_LOST,PROVIDER_UNKNOWN,TAMPERED,REVOKED|redaction=member-identities,sql-text,privacy-budget-values,differential-privacy-values,result-configuration,s3-output|provenance=recording,fixture,loopback,blocked_env";
pub const EVIDENCE_CONTRACT_DIGEST: &str =
    "e2ec2a7771698b060ce32aba9364710c92b6a655625195a9870708b2f50d8da2";
pub const PLUGIN_ID: &str = "aws.clean-rooms.query-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.clean-rooms.query-result.read";
pub const PROVIDER_ID: &str = "aws.clean-rooms.query-result.recording";
pub const PROVIDER_API_REVISION: &str =
    "clean-rooms-get-protected-query-list-protected-queries-2020-05-04-r1";
pub const CONSUMER_ID: &str = "mission.aws-clean-rooms-query-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-clean-rooms-query-result/contract.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_METADATA_TEXT_BYTES: usize = 16 * 1024;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

pub const LAYER1_PERMISSIONS: [&str; 5] = [
    "cleanrooms:GetCollaboration",
    "cleanrooms:GetMembership",
    "cleanrooms:GetProtectedQuery",
    "cleanrooms:ListProtectedQueries",
    "mission.scope",
];

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

pub fn evidence_contract_digest() -> String {
    sha256_hex(EVIDENCE_CONTRACT_DIGEST_INPUT.as_bytes())
}

#[cfg(test)]
mod contract_tests {
    use serde::Deserialize;

    use super::{
        CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA,
        CONTRACT_VERSION, EVIDENCE_CONTRACT_DIGEST, EVIDENCE_CONTRACT_DIGEST_INPUT, EVIDENCE_LEVEL,
        PLUGIN_ID, PROVIDER_ID, SERVICE_ID, contract_digest, evidence_contract_digest,
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
    }

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract = serde_json::from_str::<ContractDocument>(CONTRACT_JSON)
            .expect("checked AWS Clean Rooms contract");
        assert_eq!(contract.schema_version, CONTRACT_SCHEMA);
        assert_eq!(contract.contract_version, CONTRACT_VERSION);
        assert_eq!(contract.plugin_id, PLUGIN_ID);
        assert_eq!(contract.layer, 1);
        assert_eq!(contract.evidence_level, EVIDENCE_LEVEL);
        assert_eq!(contract.digest_input, CONTRACT_DIGEST_INPUT);
        assert_eq!(contract.contract_digest, CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert_eq!(evidence_contract_digest(), EVIDENCE_CONTRACT_DIGEST);
        assert_eq!(EVIDENCE_CONTRACT_DIGEST_INPUT.split('|').count(), 4);
        assert_eq!(contract.service.id, SERVICE_ID);
        assert!(contract.service.read_only);
        assert!(!contract.service.external_writes);
        assert_eq!(contract.provider.id, PROVIDER_ID);
        assert!(!contract.provider.connected_evidence);
        assert!(!contract.provider.native_evidence);
        assert!(!contract.provider.first_party_evidence);
        assert_eq!(contract.consumer.id, CONSUMER_ID);
        assert!(!contract.consumer.adopts_outcome);
        assert!(!contract.consumer.adopts_work_product);
    }
}
