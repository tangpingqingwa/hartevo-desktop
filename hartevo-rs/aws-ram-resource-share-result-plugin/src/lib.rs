//! Standalone Layer-1 governed AWS Resource Access Manager resource-share
//! evidence slice.
//!
//! The crate owns typed, bounded read/proposal/record/verify seams for AWS RAM
//! share, resource, principal, managed-permission, and invitation metadata. It
//! never resolves credentials, performs native HTTPS, grants or changes access,
//! accepts or rejects invitations, retains raw account/ARN/policy material, or
//! adopts Hartevo Truth, Effect, Receipt, Verification, or Outcome authority.

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

pub use consumer::{ConsumerError, MissionAwsRamConsumer, MissionAwsRamResult};
pub use model::*;
pub use provider::{
    AwsRamProvider, AwsRamProviderDefinition, AwsRamProviderError, AwsRamProviderIdentity,
    AwsRamTransport, BlockedEnvTransport, FakeAwsRamTransport, FixtureAwsRamTransport,
    LoopbackAwsRamTransport, ProviderDefinitionError, RecordingAwsRamTransport, TransportCall,
};
pub use service::{
    AuthorityBoundary, AwsRamCapabilities, AwsRamContract, AwsRamEvidence, AwsRamProposal,
    AwsRamReadResult, AwsRamRecordReceipt, AwsRamRegistration, AwsRamResourceShareService,
    AwsRamVerification, ContractDocumentError, RedactionSummary, RegistrationError,
    RegistrationStatus, RegistrationTransitionEvidence, ServiceError,
};

pub type AwsRamReadPage = RamReadPage;
pub type AwsRamReadRequest = RamReadRequest;
pub type AwsRamEvidenceState = RamEvidenceState;

pub const AWS_RAM_SCHEMA_VERSION: &str = "hartevo-aws-ram-resource-share-result-contract/v1";
pub const AWS_RAM_CONTRACT_VERSION: &str = "EXT-AWS-RAM-01-L1/v1";
pub const AWS_RAM_PLUGIN_VERSION: &str = "1.0.0";
pub const AWS_RAM_PLUGIN_ID: &str = "aws.ram.resource-share.result";
pub const AWS_RAM_SERVICE_ID: &str = "aws.ram.resource-share.result";
pub const AWS_RAM_PROVIDER_ID: &str = "aws.ram";
pub const AWS_RAM_PROVIDER_VERSION: &str = "1.0.0";
pub const AWS_RAM_API_REVISION: &str = "ram-read-r1";
pub const AWS_RAM_CONSUMER_ID: &str = "mission.aws.ram.resource-share";
pub const AWS_RAM_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AWS_RAM_CONTRACT_DIGEST_INPUT: &str = "hartevo-aws-ram-resource-share-result-contract/v1|EXT-AWS-RAM-01-L1/v1|1.0.0|aws.ram.resource-share.result|ram-read-r1|GetResourceShares,ListResources,ListPrincipals,ListResourceSharePermissions,GetResourceShareInvitations";
pub const AWS_RAM_CONTRACT_DIGEST: &str =
    "d8f285cc41795a5c4ddfd1d57e0ee9fdc55f0f5ef90a760f63f51c4a535802af";
pub const AWS_RAM_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-ram-resource-share-result/aws-ram-resource-share-result.v1.json"
);

pub fn contract_digest() -> Digest {
    Digest::from_text(AWS_RAM_CONTRACT_DIGEST_INPUT)
}

pub const fn plugin_version() -> (u16, u16, u16) {
    (1, 0, 0)
}

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

    pub const fn provider_receipt() -> bool {
        false
    }

    pub const fn truth_authority() -> bool {
        false
    }

    pub const fn effective_authorization() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_is_layer_one_and_honest() {
        let contract = AwsRamContract::baseline().expect("valid RAM contract");
        assert_eq!(contract.digest(), contract_digest());
        assert_eq!(contract.value()["contractDigest"], AWS_RAM_CONTRACT_DIGEST);
        assert_eq!(contract.value()["schemaVersion"], AWS_RAM_SCHEMA_VERSION);
        assert_eq!(
            contract.value()["contractVersion"],
            AWS_RAM_CONTRACT_VERSION
        );
        assert_eq!(contract.value()["pluginId"], AWS_RAM_PLUGIN_ID);
        assert_eq!(contract.value()["layer"], "Layer-1");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::provider_receipt());
        assert!(!Layer1Authority::truth_authority());
        assert!(!Layer1Authority::effective_authorization());
        assert_eq!(AWS_RAM_BLOCKED_ENV, "BLOCKED_ENV");
    }
}
