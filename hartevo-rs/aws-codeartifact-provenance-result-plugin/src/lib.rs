//! Standalone Layer-1 AWS CodeArtifact package provenance result boundary.
//!
//! This crate owns only bounded metadata reads, digest fences, reversible
//! registration, and a Mission-scoped proposal/recording seam. It is below
//! Hartevo Truth, Effect, Receipt, Verification, Outcome, and Work Product
//! authority. No transport in this crate can claim Connected or native
//! evidence.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::collapsible_if,
    clippy::format_push_string,
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

use sha2::{Digest as ShaDigest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionAwsCodeArtifactConsumer, MissionAwsCodeArtifactResult, ProposalDisposition,
    RecordedAwsCodeArtifactResult,
};
pub use error::{AwsCodeArtifactProvenanceError, AwsCodeArtifactTransportError, Result};
pub use model::*;
pub use provider::{
    AwsCodeArtifactOperation, AwsCodeArtifactProvider, AwsCodeArtifactProviderDefinition,
    AwsCodeArtifactTransport, BlockedEnvTransport, DescribePackageVersionRequest,
    DescribePackageVersionResponse, FixtureTransport, ListPackageVersionDependenciesRequest,
    ListPackageVersionDependenciesResponse, ListPackageVersionsRequest,
    ListPackageVersionsResponse, LoopbackTransport, RecordedRequest, RecordingTransport,
};
pub use service::{
    AwsCodeArtifactContract, AwsCodeArtifactContractError, AwsCodeArtifactEvidenceState,
    AwsCodeArtifactProvenanceProposal, AwsCodeArtifactProvenanceRegistration,
    AwsCodeArtifactProvenanceService, AwsCodeArtifactProvenanceServiceDefinition,
    AwsCodeArtifactReadRequest, AwsCodeArtifactVerificationFailure,
    AwsCodeArtifactVerificationReport, CapabilityDescription, FailureEvidence, RegistrationStatus,
    RegistrationTransitionEvidence,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-codeartifact-provenance-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-CODEARTIFACT-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-codeartifact-provenance-result/v1|layer=1|service=aws.codeartifact.provenance-result.read|provider=aws.codeartifact.provenance-result.recording|consumer=mission.aws-codeartifact-provenance.consumer";
pub const CONTRACT_DIGEST: &str =
    "0c6cb280c809bbfa518a7b761ce486595f3b3c05cd6fcd690d9239f332f92606";
pub const PLUGIN_ID: &str = "aws.codeartifact.provenance-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.codeartifact.provenance-result.read";
pub const PROVIDER_ID: &str = "aws.codeartifact.provenance-result.recording";
pub const PROVIDER_API_VERSION: &str = "2018-09-22";
pub const PROVIDER_API_REVISION: &str =
    "codeartifact-list-package-versions-describe-package-version-list-dependencies-1";
pub const CONSUMER_ID: &str = "mission.aws-codeartifact-provenance.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_DEPENDENCIES: usize = 128;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

pub const LAYER1_PERMISSIONS: [&str; 4] = [
    "codeartifact:ListPackageVersions",
    "codeartifact:DescribePackageVersion",
    "codeartifact:ListPackageVersionDependencies",
    "mission.scope",
];

pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-codeartifact-provenance-result/contract.v1.json");

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

/// Validate the checked-in contract without involving root Cargo or kernel
/// authority.
pub fn validate_contract() -> std::result::Result<(), AwsCodeArtifactContractError> {
    AwsCodeArtifactContract::baseline()?.validate()
}

#[cfg(test)]
mod contract_tests {
    use super::{
        BLOCKED_ENV, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON,
        CONTRACT_SCHEMA, CONTRACT_VERSION, EVIDENCE_LEVEL, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID,
        SERVICE_ID, contract_digest, validate_contract,
    };
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractIdentity {
        schema_version: String,
        contract_version: String,
        plugin_version: String,
        plugin_id: String,
        layer: u8,
        evidence_level: String,
        digest_input: String,
        contract_digest: String,
        service: ServiceIdentity,
        provider: ProviderIdentity,
        consumer: ConsumerIdentity,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ServiceIdentity {
        id: String,
        read_only: bool,
        external_writes: bool,
        kernel_authority: bool,
        outcome_adoption: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderIdentity {
        id: String,
        connected_evidence: bool,
        native_evidence: bool,
        provider_receipt: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConsumerIdentity {
        id: String,
        adopts_outcome: bool,
        adopts_work_product: bool,
        truth_authority: bool,
    }

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract =
            serde_json::from_str::<ContractIdentity>(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(contract.schema_version, CONTRACT_SCHEMA);
        assert_eq!(contract.contract_version, CONTRACT_VERSION);
        assert_eq!(contract.plugin_version, PLUGIN_VERSION);
        assert_eq!(contract.plugin_id, PLUGIN_ID);
        assert_eq!(contract.layer, 1);
        assert_eq!(contract.evidence_level, EVIDENCE_LEVEL);
        assert_eq!(contract.digest_input, CONTRACT_DIGEST_INPUT);
        assert_eq!(contract.contract_digest, CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert_eq!(contract.service.id, SERVICE_ID);
        assert!(contract.service.read_only);
        assert!(!contract.service.external_writes);
        assert!(!contract.service.kernel_authority);
        assert!(!contract.service.outcome_adoption);
        assert_eq!(contract.provider.id, PROVIDER_ID);
        assert!(!contract.provider.connected_evidence);
        assert!(!contract.provider.native_evidence);
        assert!(!contract.provider.provider_receipt);
        assert_eq!(contract.consumer.id, CONSUMER_ID);
        assert!(!contract.consumer.adopts_outcome);
        assert!(!contract.consumer.adopts_work_product);
        assert!(!contract.consumer.truth_authority);
        assert_eq!(BLOCKED_ENV, "BLOCKED_ENV");
        validate_contract().expect("contract validation");
    }
}
