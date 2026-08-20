//! Standalone Layer-1 AWS S3 bucket durability posture result boundary.
//!
//! The crate owns only typed, bounded S3 metadata read seams for bucket
//! versioning, default encryption, lifecycle configuration, replication
//! configuration, and bucket location. It emits redacted evidence and a
//! Mission-scoped review proposal. It never resolves credentials, performs
//! native SigV4/HTTPS, reads objects or bucket policies, retains KMS material
//! or replication role ARNs, performs effects, or adopts a Work Product.

#![forbid(unsafe_code)]
#![allow(
    clippy::collapsible_if,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConsumerError, MissionAwsS3BucketConsumer, MissionAwsS3BucketResult, MissionAwsS3DecisionState,
    RecordedAwsS3BucketResult,
};
pub use error::{AwsS3BucketError, AwsS3TransportError, Result};
pub use model::*;
pub use provider::{
    AwsS3Operation, AwsS3OperationRequest, AwsS3Provider, AwsS3ProviderDefinition, AwsS3Transport,
    BlockedEnvAwsS3Transport, BlockedEnvTransport, FakeAwsS3Transport, FixtureAwsS3Transport,
    FixtureTransport, LoopbackAwsS3Transport, LoopbackTransport, OpaqueMarker, RecordedRequest,
    RecordingAwsS3Transport, RecordingTransport,
};
pub use service::{
    AwsS3BucketService, AwsS3BucketServiceDefinition, AwsS3CapabilityDescription,
    AwsS3EvidenceState, AwsS3Proposal, AwsS3ReadEvidence, AwsS3ReadResult, AwsS3RecordReceipt,
    AwsS3Registration, AwsS3RegistrationTransition, AwsS3VerificationReport, RegistrationState,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-s3-bucket-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-S3-BUCKET-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-s3-bucket-result/v1|layer=1|service=aws.s3.bucket.result.read|provider=aws.s3.bucket.result.recording|consumer=mission.aws-s3-bucket.consumer|api=s3-2006-03-01-get-bucket-durability-posture-r1";
pub const CONTRACT_DIGEST: &str =
    "2ad76d9c3f5280ec41cd7433bc5e237177c505adb2b7631d47aee99634be4b1b";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-s3-bucket-result/contract.v1.json");
pub const PLUGIN_ID: &str = "aws.s3.bucket.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.s3.bucket.result.read";
pub const PROVIDER_ID: &str = "aws.s3.bucket.result.recording";
pub const PROVIDER_VERSION: &str = "1.0.0";
pub const PROVIDER_API_REVISION: &str = "s3-2006-03-01-get-bucket-durability-posture-r1";
pub const API_VERSION: &str = "2006-03-01";
pub const CONSUMER_ID: &str = "mission.aws-s3-bucket.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_ALLOWLISTED_BUCKETS: usize = 16;
pub const MAX_MARKER_BYTES: usize = 4 * 1024;
pub const MAX_PAGE_SIZE: u16 = 1;
pub const MAX_PAGES: u16 = 4;
pub const MAX_REQUESTS_PER_READ: u16 = 20;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

pub const LAYER1_PERMISSIONS: [&str; 6] = [
    "s3:GetBucketVersioning",
    "s3:GetBucketEncryption",
    "s3:GetBucketLifecycleConfiguration",
    "s3:GetBucketReplication",
    "s3:GetBucketLocation",
    "mission.scope",
];

pub const FORBIDDEN_EFFECTS: [&str; 20] = [
    "s3:ListAllMyBuckets",
    "s3:ListBucket",
    "s3:GetObject",
    "s3:GetObjectVersion",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:PutBucketPolicy",
    "s3:DeleteBucketPolicy",
    "s3:PutBucketEncryption",
    "s3:PutBucketLifecycleConfiguration",
    "s3:PutBucketReplication",
    "kms:Decrypt",
    "iam:PassRole",
    "raw_object_keys",
    "raw_object_bytes",
    "raw_bucket_policy_json",
    "raw_kms_material",
    "raw_replication_role_arns",
    "outcome.adopt",
    "verified_work_product_adoption",
];

pub(crate) fn contract_digest() -> model::Digest {
    model::Digest::parse(CONTRACT_DIGEST).expect("checked S3 contract digest")
}

pub(crate) fn api_digest() -> model::Digest {
    model::Digest::from_parts(
        "aws-s3-api/v1",
        &[
            ("version", API_VERSION.to_owned()),
            ("revision", PROVIDER_API_REVISION.to_owned()),
            (
                "operations",
                "GetBucketVersioning,GetBucketEncryption,GetBucketLifecycleConfiguration,GetBucketReplication,GetBucketLocation".to_owned(),
            ),
        ],
    )
}

pub(crate) fn plugin_version_digest() -> model::Digest {
    model::Digest::from_text(PLUGIN_VERSION)
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        API_VERSION, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON,
        CONTRACT_SCHEMA, CONTRACT_VERSION, EVIDENCE_LEVEL, PLUGIN_ID, PLUGIN_VERSION,
        PROVIDER_API_REVISION, PROVIDER_ID, PROVIDER_VERSION, SERVICE_ID, contract_digest,
    };

    #[test]
    fn checked_contract_is_versioned_layer_one_and_non_native() {
        let document = serde_json::from_str::<Value>(CONTRACT_JSON).expect("S3 contract JSON");
        assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(document["contractVersion"], CONTRACT_VERSION);
        assert_eq!(document["pluginId"], PLUGIN_ID);
        assert_eq!(document["pluginVersion"], PLUGIN_VERSION);
        assert_eq!(document["layer"], "Layer-1");
        assert_eq!(document["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(document["digestInput"], CONTRACT_DIGEST_INPUT);
        assert_eq!(document["contractDigest"], CONTRACT_DIGEST);
        assert_eq!(contract_digest().as_str(), CONTRACT_DIGEST);
        assert_eq!(document["service"]["id"], SERVICE_ID);
        assert!(document["service"]["readOnly"].as_bool().unwrap_or(false));
        assert!(
            !document["service"]["externalWrites"]
                .as_bool()
                .unwrap_or(true)
        );
        assert_eq!(document["provider"]["id"], PROVIDER_ID);
        assert_eq!(document["provider"]["version"], PROVIDER_VERSION);
        assert_eq!(document["provider"]["apiVersion"], API_VERSION);
        assert_eq!(document["provider"]["apiRevision"], PROVIDER_API_REVISION);
        assert!(!document["provider"]["connected"].as_bool().unwrap_or(true));
        assert!(!document["provider"]["native"].as_bool().unwrap_or(true));
        assert!(!document["provider"]["firstParty"].as_bool().unwrap_or(true));
        assert_eq!(document["consumer"]["id"], CONSUMER_ID);
        assert!(
            !document["consumer"]["adoptsOutcome"]
                .as_bool()
                .unwrap_or(true)
        );
        assert!(
            !document["consumer"]["adoptsWorkProduct"]
                .as_bool()
                .unwrap_or(true)
        );
    }
}
