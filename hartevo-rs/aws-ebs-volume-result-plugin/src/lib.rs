//! Standalone Layer-1 AWS EBS volume and snapshot posture result boundary.
//!
//! This crate owns only bounded, digest-fenced metadata read/proposal/record/
//! verify seams. Recording, fixture, loopback, and `BLOCKED_ENV` transports
//! are always non-connected, non-native, and non-first-party. No storage
//! mutation, block bytes, KMS material, kernel authority, or native Connected
//! claim is available here.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::fn_params_excessive_bools,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::unnecessary_wraps
)]

use sha2::{Digest as ShaDigest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionAwsEbsConsumer, MissionAwsEbsResult, ProposalDisposition, RecordedAwsEbsResult,
};
pub use error::{AwsEbsTransportError, AwsEbsVolumeError, Result};
pub use model::*;
pub use provider::{
    AwsEbsProvider, AwsEbsProviderDefinition, AwsEbsTransport, BlockedEnvTransport,
    DescribeFastSnapshotRestoresRequest, DescribeFastSnapshotRestoresResponse,
    DescribeSnapshotsRequest, DescribeSnapshotsResponse, DescribeVolumeStatusRequest,
    DescribeVolumeStatusResponse, DescribeVolumesRequest, DescribeVolumesResponse,
    FixtureTransport, LoopbackTransport, RecordingTransport, RequestFence, TransportCall,
    filter_digest,
};
pub use service::{
    AwsEbsEvidenceRequest, AwsEbsRegistration, AwsEbsServiceError, AwsEbsVolumeProposal,
    AwsEbsVolumeRegistration, AwsEbsVolumeService, CapabilityDescription, EvidenceState,
    FailureEvidence, RegistrationStatus, RegistrationTransitionEvidence, VerificationFailure,
    VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-ebs-volume-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWSEBS-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-ebs-volume-result/v1|layer=1|service=aws.ec2.ebs-volume-result.read|provider=aws.ec2.ebs-volume-result.recording|consumer=mission.aws-ebs-volume.consumer";
pub const CONTRACT_DIGEST: &str =
    "19a15e4743282ac95c46bdd716e0d773245a04d5021ad48563ed344967cfd880";
pub const PLUGIN_ID: &str = "aws.ec2.ebs-volume-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.ec2.ebs-volume-result.read";
pub const PROVIDER_ID: &str = "aws.ec2.ebs-volume-result.recording";
pub const API_REVISION: &str = "ec2-describe-volumes-status-snapshots-fsr-2016-11-15-v1";
pub const CONSUMER_ID: &str = "mission.aws-ebs-volume.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const EVIDENCE_SCHEMA_INPUT: &str = "hartevo.aws-ebs-volume-result/evidence/v1";
pub const EVIDENCE_SCHEMA_DIGEST: &str =
    "997e7fee478d3c54f0eea550e3eedf982a53da9d8a8fc9eddff4f83eb830b6c4";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-ebs-volume-result/contract.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_STATUS_AGE_SECONDS: i64 = 300;

pub const LAYER1_PERMISSIONS: [&str; 5] = [
    "ec2:DescribeVolumes",
    "ec2:DescribeVolumeStatus",
    "ec2:DescribeSnapshots",
    "ec2:DescribeFastSnapshotRestores",
    "mission.scope",
];

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

pub fn evidence_schema_digest() -> String {
    sha256_hex(EVIDENCE_SCHEMA_INPUT.as_bytes())
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA,
        CONTRACT_VERSION, EVIDENCE_LEVEL, EVIDENCE_SCHEMA_DIGEST, PLUGIN_ID, PROVIDER_ID,
        SERVICE_ID, contract_digest, evidence_schema_digest,
    };

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract = serde_json::from_str::<Value>(CONTRACT_JSON).expect("checked EBS contract");
        assert_eq!(contract["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(contract["contractVersion"], CONTRACT_VERSION);
        assert_eq!(contract["pluginId"], PLUGIN_ID);
        assert_eq!(contract["layer"], 1);
        assert_eq!(contract["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(contract["digestInput"], CONTRACT_DIGEST_INPUT);
        assert_eq!(contract["contractDigest"], CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert_eq!(evidence_schema_digest(), EVIDENCE_SCHEMA_DIGEST);
        assert_eq!(contract["service"]["id"], SERVICE_ID);
        assert_eq!(contract["service"]["readOnly"], true);
        assert_eq!(contract["service"]["externalWrites"], false);
        assert_eq!(contract["provider"]["id"], PROVIDER_ID);
        assert_eq!(contract["provider"]["connectedEvidence"], false);
        assert_eq!(contract["provider"]["nativeEvidence"], false);
        assert_eq!(contract["consumer"]["id"], CONSUMER_ID);
        assert_eq!(contract["consumer"]["adoptsOutcome"], false);
        assert_eq!(contract["consumer"]["adoptsWorkProduct"], false);
        assert_eq!(contract["credentials"]["serialized"], false);
        assert_eq!(contract["scope"]["identifiersInEvidence"], "digest_only");
        assert_eq!(contract["provenance"]["connectedClaim"], false);
        assert_eq!(contract["provenance"]["nativeClaim"], false);
        assert_eq!(
            contract["authorityBoundary"]["doesNotOwn"][0],
            "Hartevo Truth"
        );
    }
}
