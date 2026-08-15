//! Standalone Layer-1 AWS IoT SiteWise measurement-history result boundary.
//!
//! This crate owns only bounded, read-only provider evidence for one exact
//! asset property and Mission scope. It never resolves credentials, performs
//! native HTTPS, ingests or writes measurements, controls gateways/devices, or
//! adopts Hartevo Truth, Effect, Receipt, Verification, Outcome, or Work
//! Product authority. Fixture, recording, loopback, and `BLOCKED_ENV`
//! provenance are always non-connected, non-native, and non-first-party.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::return_self_not_must_use,
    clippy::needless_pass_by_value,
    clippy::struct_excessive_bools,
    clippy::struct_field_names,
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
    MissionAwsIoTSiteWiseConsumer, MissionAwsIoTSiteWiseMeasurementConsumer,
    MissionAwsIoTSiteWiseResult, ProposalDisposition, RecordedAwsIoTSiteWiseResult,
};
pub use error::{AwsIoTSiteWiseMeasurementError, AwsIoTSiteWiseTransportError, Result};
pub use model::*;
pub use provider::{
    AwsIoTSiteWiseOperation, AwsIoTSiteWiseProvider, AwsIoTSiteWiseProviderDefinition,
    AwsIoTSiteWiseTransport, BlockedEnvTransport, DescribeAssetPropertyRequest,
    DescribeAssetPropertyResponse, DescribeAssetRequest, DescribeAssetResponse, FixtureTransport,
    GetAssetPropertyValueHistoryRequest, ListAssetsRequest, ListAssetsResponse, LoopbackTransport,
    MeasurementHistoryResponse, RecordedRequest, RecordingTransport,
};
pub use service::{
    AwsIoTSiteWiseMeasurementProposal, AwsIoTSiteWiseMeasurementRegistration,
    AwsIoTSiteWiseMeasurementService, AwsIoTSiteWiseRegistration, CapabilityDescription,
    FailureEvidence, MeasurementEvidenceRequest, RegistrationStatus,
    RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-iot-sitewise-measurement-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWSIOTSITEWISE-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-iot-sitewise-measurement-result/v1|layer=1|service=aws.iot-sitewise.measurement-result.read|provider=aws.iot-sitewise.measurement-result.recording|consumer=mission.aws-iot-sitewise-measurement.consumer";
pub const CONTRACT_DIGEST: &str =
    "14abc3693d98aaa7dc1f2ce1251a8247a8b1b48b39f985746a052a768f731687";
pub const PLUGIN_ID: &str = "aws.iot-sitewise.measurement-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.iot-sitewise.measurement-result.read";
pub const PROVIDER_ID: &str = "aws.iot-sitewise.measurement-result.recording";
pub const PROVIDER_API_REVISION: &str =
    "sitewise-list-assets-describe-asset-describe-property-get-history-1";
pub const CONSUMER_ID: &str = "mission.aws-iot-sitewise-measurement.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
pub const LAYER1_PERMISSIONS: [&str; 5] = [
    "iotsitewise:ListAssets",
    "iotsitewise:DescribeAsset",
    "iotsitewise:DescribeAssetProperty",
    "iotsitewise:GetAssetPropertyValueHistory",
    "mission.scope",
];
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-iot-sitewise-measurement-result/contract.v1.json");

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA,
        CONTRACT_VERSION, EVIDENCE_LEVEL, PLUGIN_ID, PROVIDER_ID, SERVICE_ID, contract_digest,
    };

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract = serde_json::from_str::<Value>(CONTRACT_JSON).expect("checked contract");
        assert_eq!(contract["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(contract["contractVersion"], CONTRACT_VERSION);
        assert_eq!(contract["pluginId"], PLUGIN_ID);
        assert_eq!(contract["layer"], 1);
        assert_eq!(contract["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(contract["digestInput"], CONTRACT_DIGEST_INPUT);
        assert_eq!(contract["contractDigest"], CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert_eq!(contract["service"]["id"], SERVICE_ID);
        assert_eq!(contract["provider"]["id"], PROVIDER_ID);
        assert_eq!(contract["consumer"]["id"], CONSUMER_ID);
        assert_eq!(contract["service"]["readOnly"], true);
        assert_eq!(contract["service"]["externalWrites"], false);
        assert_eq!(contract["provider"]["connectedEvidence"], false);
        assert_eq!(contract["provider"]["nativeEvidence"], false);
        assert_eq!(contract["provider"]["firstPartyEvidence"], false);
    }
}
