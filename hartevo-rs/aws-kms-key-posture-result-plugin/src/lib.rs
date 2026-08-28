//! Standalone Layer-1 AWS KMS key-posture evidence boundary.
//!
//! This crate owns only typed, bounded, read/propose/record/verify seams. It
//! never resolves credentials, signs a native SigV4 request, retains key
//! material or grant principals, performs cryptographic operations, mutates a
//! KMS resource, claims connected/native/first-party authority, or adopts a
//! Hartevo Outcome or Work Product.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::collapsible_if,
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
    ConsumerError, MissionAwsKmsConsumer, MissionAwsKmsDecisionState, MissionAwsKmsInput,
    MissionAwsKmsResult,
};
pub use model::*;
pub use provider::{
    AwsKmsDescribeKeyRecord, AwsKmsKeyPostureProvider, AwsKmsListAliasesRecord,
    AwsKmsListAliasesRecordPage, AwsKmsListGrantsRecord, AwsKmsListGrantsRecordPage,
    AwsKmsListKeysRecord, AwsKmsListKeysRecordPage, AwsKmsProvider, AwsKmsProviderDefinition,
    AwsKmsProviderError, AwsKmsReadRecord, AwsKmsRotationRecord, AwsKmsTransport,
    BlockedEnvAwsKmsTransport, DescribeKeyRequest, DescribeKeyResponse, FixtureAwsKmsTransport,
    GetKeyRotationStatusRequest, GetKeyRotationStatusResponse, KmsReadBounds, ListAliasesPage,
    ListAliasesRequest, ListGrantsPage, ListGrantsRequest, ListKeysPage, ListKeysRequest,
    LoopbackAwsKmsTransport, RecordingAwsKmsTransport, RotationStatusResponse, TransportCall,
    TransportError, TransportFailure,
};
pub use service::{
    AuthorityBoundary, AwsKmsCapabilities, AwsKmsKeyPostureEvidence, AwsKmsKeyPostureProposal,
    AwsKmsKeyPostureReadResult, AwsKmsKeyPostureRecord, AwsKmsKeyPostureRegistration,
    AwsKmsKeyPostureService, AwsKmsReadRecordEnvelope, AwsKmsReadRequest, EvidenceDigests,
    RedactionSummary, RegistrationState, ServiceError,
};

pub const AWS_KMS_KEY_POSTURE_SCHEMA_VERSION: &str =
    "hartevo.aws-kms-key-posture-result.contract/v1";
pub const AWS_KMS_KEY_POSTURE_CONTRACT_VERSION: &str = "aws-kms-key-posture-result/v1";
pub const AWS_KMS_KEY_POSTURE_PLUGIN_VERSION: &str = "1.0.0";
pub const AWS_KMS_KEY_POSTURE_SERVICE_ID: &str = "hartevo.aws.kms.key-posture-result";
pub const AWS_KMS_KEY_POSTURE_PROVIDER_ID: &str = "aws.kms.key-posture.read";
pub const AWS_KMS_KEY_POSTURE_CONSUMER_ID: &str = "mission.aws.kms.key-posture";
pub const AWS_KMS_API_VERSION: &str = "2014-11-01";
pub const AWS_KMS_PROVIDER_VERSION: &str = "aws-kms-provider/v1";
pub const AWS_KMS_API_REVISION: &str =
    "kms-list-keys-describe-key-rotation-status-list-aliases-list-grants-r1";
pub const AWS_KMS_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AWS_KMS_KEY_POSTURE_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-kms-key-posture-result/aws-kms-key-posture-result.v1.json"
);

pub const AWS_KMS_SCHEMA_VERSION: &str = AWS_KMS_KEY_POSTURE_SCHEMA_VERSION;
pub const AWS_KMS_CONTRACT_VERSION: &str = AWS_KMS_KEY_POSTURE_CONTRACT_VERSION;
pub const AWS_KMS_SERVICE_ID: &str = AWS_KMS_KEY_POSTURE_SERVICE_ID;
pub const AWS_KMS_PROVIDER_ID: &str = AWS_KMS_KEY_POSTURE_PROVIDER_ID;
pub const AWS_KMS_CONSUMER_ID: &str = AWS_KMS_KEY_POSTURE_CONSUMER_ID;
pub const AWS_KMS_CONTRACT_JSON: &str = AWS_KMS_KEY_POSTURE_CONTRACT_JSON;

pub fn contract_digest() -> Digest {
    Digest::from_text(AWS_KMS_KEY_POSTURE_CONTRACT_JSON)
}

pub const fn plugin_version() -> (u16, u16, u16) {
    (1, 0, 0)
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        AWS_KMS_API_REVISION, AWS_KMS_API_VERSION, AWS_KMS_BLOCKED_ENV,
        AWS_KMS_KEY_POSTURE_CONSUMER_ID, AWS_KMS_KEY_POSTURE_CONTRACT_JSON,
        AWS_KMS_KEY_POSTURE_CONTRACT_VERSION, AWS_KMS_KEY_POSTURE_PROVIDER_ID,
        AWS_KMS_KEY_POSTURE_SCHEMA_VERSION, AWS_KMS_KEY_POSTURE_SERVICE_ID,
        AWS_KMS_PROVIDER_VERSION, contract_digest,
    };

    #[test]
    fn contract_is_layer_one_read_only_and_non_native() {
        let document: Value =
            serde_json::from_str(AWS_KMS_KEY_POSTURE_CONTRACT_JSON).expect("KMS contract JSON");
        assert_eq!(
            document["schemaVersion"],
            AWS_KMS_KEY_POSTURE_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            AWS_KMS_KEY_POSTURE_CONTRACT_VERSION
        );
        assert_eq!(document["service"]["id"], AWS_KMS_KEY_POSTURE_SERVICE_ID);
        assert_eq!(document["provider"]["id"], AWS_KMS_KEY_POSTURE_PROVIDER_ID);
        assert_eq!(document["provider"]["apiVersion"], AWS_KMS_API_VERSION);
        assert_eq!(document["provider"]["apiRevision"], AWS_KMS_API_REVISION);
        assert_eq!(
            document["provider"]["providerVersion"],
            AWS_KMS_PROVIDER_VERSION
        );
        assert_eq!(document["consumer"]["id"], AWS_KMS_KEY_POSTURE_CONSUMER_ID);
        assert_eq!(document["layer"], "Layer-1");
        assert_eq!(document["nativeClaims"]["connected"], false);
        assert_eq!(document["nativeClaims"]["nativeProvider"], false);
        assert_eq!(document["nativeClaims"]["firstParty"], false);
        assert_eq!(
            document["nativeClaims"]["blockedEnvironmentIsNative"],
            false
        );
        assert_eq!(AWS_KMS_BLOCKED_ENV, "BLOCKED_ENV");
        assert_eq!(contract_digest().as_str().len(), 64);
    }
}
