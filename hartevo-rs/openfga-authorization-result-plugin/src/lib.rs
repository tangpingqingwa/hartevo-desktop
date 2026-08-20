//! Standalone Layer-1 governed OpenFGA authorization-result boundary.
//!
//! This crate is intentionally below Hartevo Truth, Consent, Effect, Receipt,
//! Verification, Outcome, Work Product, and kernel authorization authority.
//! It exposes only bounded model/check/tuple reads, digest fences, reversible
//! registration, redacted receipts, and a Mission-scoped review-only seam.
//! Every available transport is non-connected and non-native.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::collapsible_if,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

use sha2::{Digest as ShaDigest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionOpenFgaAuthorizationConsumer, MissionOpenFgaAuthorizationResult,
    OpenFgaProposalDisposition, RecordedOpenFgaAuthorizationResult,
};
pub use error::{OpenFgaAuthorizationResultError, OpenFgaTransportError, Result};
pub use model::*;
pub use provider::{
    AuthorizationCheckRequest, AuthorizationCheckResponse, BlockedEnvTransport, Cursor,
    FakeTransport, FixtureTransport, LoopbackTransport, ModelReadRequest, ModelReadResponse,
    OpenFgaObservation, OpenFgaOperation, OpenFgaProvider, OpenFgaProviderDefinition,
    OpenFgaProviderFailure, OpenFgaTransport, RecordedRequest, RecordingTransport,
    TupleReadRequest, TupleReadResponse,
};
pub use service::{
    CapabilityDescription, FailureEvidence, OpenFgaAuthorizationResultContract,
    OpenFgaAuthorizationResultProposal, OpenFgaAuthorizationResultRegistration,
    OpenFgaAuthorizationResultService, OpenFgaEvidenceRequest, OpenFgaRegistration,
    RegistrationStatus, RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.openfga-authorization-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-OPENFGA-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.openfga-authorization-result/v1|layer=1|service=openfga.authorization.result.read|provider=openfga.authorization.result.recording|consumer=mission.openfga-authorization.consumer|api=openfga-read-authorization-model-check-tuples-r1";
pub const CONTRACT_DIGEST: &str =
    "dadcf5a4a4e010fba0b87623070fbe8613ddfa4041c237bab2b931f0f1be461b";
pub const PLUGIN_ID: &str = "openfga.authorization.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "openfga.authorization.result.read";
pub const PROVIDER_ID: &str = "openfga.authorization.result.recording";
pub const PROVIDER_API_REVISION: &str = "openfga-read-authorization-model-check-tuples-r1";
pub const CONSUMER_ID: &str = "mission.openfga-authorization.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_TUPLES: usize = 100;
pub const MAX_MODEL_TYPES: u16 = 128;
pub const MAX_MODEL_RELATIONS: u16 = 512;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const LAYER1_PERMISSIONS: [&str; 4] = [
    "openfga:ReadAuthorizationModel",
    "openfga:Check",
    "openfga:Read",
    "mission.scope",
];
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/openfga-authorization-result/openfga-authorization-result.v1.json"
);

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

/// Layer-1 is intentionally unable to claim native connectivity or authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }

    pub const fn durable_provider_receipt() -> bool {
        false
    }

    pub const fn authorization_authority() -> bool {
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

    use super::*;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        plugin_version: String,
        plugin_id: String,
        layer: String,
        evidence_level: String,
        digest_input: String,
        contract_digest: String,
        service: ServiceDocument,
        provider: ProviderDocument,
        consumer: ConsumerDocument,
        credentials: CredentialsDocument,
        scope: ScopeDocument,
        registration: RegistrationDocument,
        pagination: PaginationDocument,
        projection: ProjectionDocument,
        receipts: ReceiptsDocument,
        evidence: EvidenceDocument,
        provenance: ProvenanceDocument,
        authority_boundary: AuthorityBoundaryDocument,
        forbidden_effects: Vec<String>,
        layer2_gaps: Vec<String>,
        honest_native_gap: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ServiceDocument {
        id: String,
        read_only: bool,
        proposal_only: bool,
        external_writes: bool,
        tuple_writes: bool,
        authorization_authority: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderDocument {
        id: String,
        api_revision: String,
        allowed_transports: Vec<String>,
        connected: bool,
        native: bool,
        first_party: bool,
        provider_receipt: bool,
        tuple_writes: bool,
        authorization_authority: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConsumerDocument {
        id: String,
        scope: Vec<String>,
        adopts_outcome: bool,
        adopts_work_product: bool,
        truth_authority: bool,
        authorization_authority: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CredentialsDocument {
        serialized: bool,
        raw_material_accepted: bool,
        resolved_by_layer: u8,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ScopeDocument {
        required: Vec<String>,
        identifiers_in_evidence: String,
        raw_identifiers: bool,
        raw_model_json: bool,
        raw_tuple_keys: bool,
        max_pages: u16,
        max_page_size: u16,
        max_tuples: usize,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RegistrationDocument {
        reversible: bool,
        revocable: bool,
        binding_digests: Vec<String>,
        permissions: Vec<String>,
        forbidden_permissions: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct PaginationDocument {
        cursor_digest_only: bool,
        max_pages: u16,
        max_tuples: usize,
        loop_rejected: bool,
        filter_drift_rejected: bool,
    }

    #[derive(Debug, Deserialize)]
    struct ProjectionDocument {
        model: Vec<String>,
        #[serde(rename = "authorizationCheck")]
        authorization_check: Vec<String>,
        tuples: Vec<String>,
        #[serde(rename = "rawModelJson")]
        raw_model_json: bool,
        #[serde(rename = "rawTupleKeys")]
        raw_tuple_keys: bool,
        #[serde(rename = "rawIdentifiers")]
        raw_identifiers: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ReceiptsDocument {
        request: ReceiptDocument,
        cost: ReceiptDocument,
    }

    #[derive(Debug, Deserialize)]
    struct ReceiptDocument {
        redacted: bool,
        #[serde(rename = "durableProviderReceipt", default)]
        durable_provider_receipt: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct EvidenceDocument {
        required_digests: Vec<String>,
        states: Vec<String>,
        tamper_rejected: bool,
        replay_conflict_rejected: bool,
        revocation_rejected: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProvenanceDocument {
        connected: bool,
        native: bool,
        first_party: bool,
        provider_receipt: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AuthorityBoundaryDocument {
        owns: Vec<String>,
        does_not_own: Vec<String>,
    }

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let baseline = OpenFgaAuthorizationResultContract::baseline().expect("contract baseline");
        assert_eq!(baseline.digest().as_str(), CONTRACT_DIGEST);
        let contract = serde_json::from_str::<ContractDocument>(CONTRACT_JSON)
            .expect("checked OpenFGA contract");
        assert_eq!(contract.schema_version, CONTRACT_SCHEMA);
        assert_eq!(contract.contract_version, CONTRACT_VERSION);
        assert_eq!(contract.plugin_version, PLUGIN_VERSION);
        assert_eq!(contract.plugin_id, PLUGIN_ID);
        assert_eq!(contract.layer, "Layer-1");
        assert_eq!(contract.evidence_level, EVIDENCE_LEVEL);
        assert_eq!(contract.digest_input, CONTRACT_DIGEST_INPUT);
        assert_eq!(contract.contract_digest, CONTRACT_DIGEST);
        assert_eq!(contract_digest().as_str(), CONTRACT_DIGEST);
        assert_eq!(contract.service.id, SERVICE_ID);
        assert!(contract.service.read_only);
        assert!(contract.service.proposal_only);
        assert!(!contract.service.external_writes);
        assert!(!contract.service.tuple_writes);
        assert!(!contract.service.authorization_authority);
        assert_eq!(contract.provider.id, PROVIDER_ID);
        assert_eq!(contract.provider.api_revision, PROVIDER_API_REVISION);
        assert!(
            contract
                .provider
                .allowed_transports
                .contains(&"fake".to_owned())
        );
        assert!(!contract.provider.connected);
        assert!(!contract.provider.native);
        assert!(!contract.provider.first_party);
        assert!(!contract.provider.provider_receipt);
        assert!(!contract.provider.tuple_writes);
        assert!(!contract.provider.authorization_authority);
        assert_eq!(contract.consumer.id, CONSUMER_ID);
        assert_eq!(contract.consumer.scope.len(), 15);
        assert!(!contract.consumer.adopts_outcome);
        assert!(!contract.consumer.adopts_work_product);
        assert!(!contract.consumer.truth_authority);
        assert!(!contract.consumer.authorization_authority);
        assert!(!contract.credentials.serialized);
        assert!(!contract.credentials.raw_material_accepted);
        assert_eq!(contract.credentials.resolved_by_layer, 2);
        assert_eq!(contract.scope.identifiers_in_evidence, "digest_only");
        assert_eq!(contract.scope.required.len(), 15);
        assert!(!contract.scope.raw_identifiers);
        assert!(!contract.scope.raw_model_json);
        assert!(!contract.scope.raw_tuple_keys);
        assert_eq!(contract.scope.max_pages, MAX_PAGES);
        assert_eq!(contract.scope.max_page_size, MAX_PAGE_SIZE);
        assert_eq!(contract.scope.max_tuples, MAX_TUPLES);
        assert!(contract.registration.reversible);
        assert!(contract.registration.revocable);
        assert!(
            contract
                .registration
                .binding_digests
                .contains(&"consentDigest".to_owned())
        );
        assert!(
            contract
                .registration
                .binding_digests
                .contains(&"revisionDigest".to_owned())
        );
        assert!(
            contract
                .registration
                .permissions
                .iter()
                .all(|permission| !permission.contains("Write"))
        );
        assert!(
            contract
                .registration
                .forbidden_permissions
                .iter()
                .any(|permission| permission.contains("WriteTuple"))
        );
        assert!(contract.pagination.cursor_digest_only);
        assert_eq!(contract.pagination.max_pages, MAX_PAGES);
        assert_eq!(contract.pagination.max_tuples, MAX_TUPLES);
        assert!(contract.pagination.loop_rejected);
        assert!(contract.pagination.filter_drift_rejected);
        assert!(!contract.projection.model.is_empty());
        assert!(!contract.projection.authorization_check.is_empty());
        assert!(!contract.projection.tuples.is_empty());
        assert!(!contract.projection.raw_model_json);
        assert!(!contract.projection.raw_tuple_keys);
        assert!(!contract.projection.raw_identifiers);
        assert!(contract.receipts.request.redacted);
        assert!(contract.receipts.cost.redacted);
        assert!(!contract.receipts.request.durable_provider_receipt);
        assert!(!contract.receipts.cost.durable_provider_receipt);
        assert!(
            contract
                .evidence
                .required_digests
                .contains(&"modelDigest".to_owned())
        );
        assert!(
            contract
                .evidence
                .required_digests
                .contains(&"checkDigest".to_owned())
        );
        assert!(
            contract
                .evidence
                .required_digests
                .contains(&"tupleDigest".to_owned())
        );
        assert!(contract.evidence.states.contains(&"denied".to_owned()));
        assert!(contract.evidence.states.contains(&"stale".to_owned()));
        assert!(
            contract
                .evidence
                .states
                .contains(&"rate_limited".to_owned())
        );
        assert!(contract.evidence.tamper_rejected);
        assert!(contract.evidence.replay_conflict_rejected);
        assert!(contract.evidence.revocation_rejected);
        assert!(!contract.provenance.connected);
        assert!(!contract.provenance.native);
        assert!(!contract.provenance.first_party);
        assert!(!contract.provenance.provider_receipt);
        assert!(!contract.authority_boundary.owns.is_empty());
        assert!(!contract.authority_boundary.does_not_own.is_empty());
        assert!(
            contract
                .forbidden_effects
                .iter()
                .any(|effect| effect == "WriteTuple")
        );
        assert!(!contract.layer2_gaps.is_empty());
        assert!(contract.honest_native_gap.contains("BLOCKED_ENV"));
    }

    #[test]
    fn authority_is_constantly_non_native_and_non_authoritative() {
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::authorization_authority());
        assert!(!Layer1Authority::adopts_outcome());
        assert!(!Layer1Authority::adopts_work_product());
    }
}
