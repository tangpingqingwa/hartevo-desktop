//! Standalone Layer-1 AWS ACM certificate metadata result boundary.
//!
//! The crate is below Hartevo Truth, Effect, Receipt, Verification, Outcome,
//! and durable Work Product authority. It provides only bounded ACM
//! List/Search/Describe metadata reads, digest fences, reversible registration,
//! a Mission-scoped decision proposal, and redacted idempotent recording.
//! Native SigV4 execution, certificate lifecycle effects, validation effects,
//! certificate bytes, private keys, and production TLS certification are not
//! represented here.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
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
    ConsumerError, MissionAwsAcmCertificateConsumer, MissionAwsAcmConsumer, MissionAwsAcmResult,
    MissionAwsAcmResultRecord, ProposalDisposition, RecordedAwsAcmResult,
};
pub use model::*;
pub use provider::{
    AwsAcmProvider, AwsAcmProviderDefinition, AwsAcmTransport, AwsAcmTransportError,
    BlockedEnvAwsAcmTransport, BlockedEnvTransport, DescribeCertificateRequest,
    DescribeCertificateResponse, FixtureAwsAcmTransport, FixtureTransport, ListCertificatesRequest,
    ListCertificatesResponse, LoopbackAwsAcmTransport, LoopbackTransport, ProviderDefinitionError,
    RecordedRequest, RecordingAwsAcmTransport, RecordingTransport, SearchCertificatesRequest,
    SearchCertificatesResponse,
};
pub use service::{
    AwsAcmCapabilities, AwsAcmCertificateEvidence, AwsAcmCertificateProposal,
    AwsAcmCertificateService, AwsAcmCostReceipt, AwsAcmReadRequest, AwsAcmRegistration,
    AwsAcmRequestReceipt, AwsAcmService, AwsAcmServiceError, CertificateEvidenceState,
    ContractDocumentError, EvidenceDigests, EvidenceState, FailureEvidence, FailureReason,
    RegistrationState, RegistrationTransitionReceipt, VerificationFailure, VerificationReport,
};

pub type AwsAcmCertificateRegistration = AwsAcmRegistration;
pub type AwsAcmCertificateResult = AwsAcmCertificateProposal;

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-acm-certificate-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-ACM-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-acm-certificate-result/v1|layer=1|service=aws.acm.certificate-result.read|provider=aws.acm.certificate-result.recording|consumer=mission.aws-acm-certificate.consumer";
pub const CONTRACT_DIGEST: &str =
    "15c1dcdd2a17488c2345f1957f6d92b0381ecf706c46427a3305bbdf9cf24e80";
pub const PLUGIN_ID: &str = "aws.acm.certificate-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const ACM_SERVICE_ID: &str = "aws.acm.certificate-result.read";
pub const ACM_PROVIDER_ID: &str = "aws.acm.certificate-result.recording";
pub const ACM_PROVIDER_VERSION: &str = "1.0.0";
pub const ACM_API_REVISION: &str = "acm-list-search-describe-certificate-1";
pub const ACM_CONSUMER_ID: &str = "mission.aws-acm-certificate.consumer";
pub const SERVICE_ID: &str = ACM_SERVICE_ID;
pub const PROVIDER_ID: &str = ACM_PROVIDER_ID;
pub const PROVIDER_API_REVISION: &str = ACM_API_REVISION;
pub const CONSUMER_ID: &str = ACM_CONSUMER_ID;
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const AWS_ACM_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-acm-certificate-result/contract.v1.json");

pub const LAYER1_PERMISSIONS: [&str; 4] = [
    "acm:ListCertificates",
    "acm:SearchCertificates",
    "acm:DescribeCertificate",
    "mission.scope",
];

pub type AwsAcmOperation = AcmOperation;
pub type AwsAcmProviderError = AwsAcmTransportError;

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

pub fn plugin_version() -> (u16, u16, u16) {
    (1, 0, 0)
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_is_layer_one_and_non_native() {
        let document = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .expect("valid ACM contract JSON");
        assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(document["contractVersion"], CONTRACT_VERSION);
        assert_eq!(document["pluginId"], PLUGIN_ID);
        assert_eq!(document["contractDigest"], CONTRACT_DIGEST);
        assert_eq!(contract_digest().as_str(), CONTRACT_DIGEST);
        assert_eq!(document["layer"], 1);
        assert_eq!(document["provider"]["connectedEvidence"], false);
        assert_eq!(document["provider"]["nativeEvidence"], false);
        assert_eq!(document["provider"]["firstPartyEvidence"], false);
        assert_eq!(document["consumer"]["adoptsOutcome"], false);
        assert_eq!(document["authority"]["connected"], false);
        assert_eq!(document["authority"]["native"], false);
        assert_eq!(document["authority"]["productionTlsCertification"], false);
    }
}
