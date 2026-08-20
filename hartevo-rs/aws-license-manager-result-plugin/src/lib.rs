//! Standalone Layer-1 AWS License Manager result boundary.
//!
//! This crate is intentionally below Hartevo Truth, Consent, Effect, Receipt,
//! Verification, Outcome, and durable Work Product authority. It exposes only
//! bounded normalized reads, digest fences, reversible registration, and a
//! Mission-scoped proposal/record seam. Every available transport is
//! recording, fixture, loopback, or `BLOCKED_ENV` and is non-native.

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

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    LicenseManagerDecisionState, MissionAwsLicenseManagerConsumer, MissionAwsLicenseManagerResult,
};
pub use error::{AwsLicenseManagerError, AwsLicenseManagerTransportError, Result};
pub use model::*;
pub use provider::{
    AwsLicenseManagerOperation, AwsLicenseManagerProvider, AwsLicenseManagerProviderDefinition,
    AwsLicenseManagerTransport, BlockedEnvAwsLicenseManagerTransport, BlockedEnvTransport,
    FixtureAwsLicenseManagerTransport, FixtureTransport, GetLicenseConfigurationPage,
    GetLicenseConfigurationRequest, ListLicenseConfigurationsPage,
    ListLicenseConfigurationsRequest, ListUsageForLicenseConfigurationPage,
    ListUsageForLicenseConfigurationRequest, LoopbackAwsLicenseManagerTransport, LoopbackTransport,
    OpaquePageToken, RecordedRequest, RecordingAwsLicenseManagerTransport, RecordingTransport,
};
pub use service::{
    AwsLicenseManagerCapability, AwsLicenseManagerProposal, AwsLicenseManagerRecord,
    AwsLicenseManagerRegistration, AwsLicenseManagerRegistrationRequest,
    AwsLicenseManagerResultEvidence, AwsLicenseManagerService, AwsLicenseManagerVerification,
    CapabilityDescription, EvidenceFailure, RegistrationState, RegistrationTransitionEvidence,
    VerificationFailure, VerificationReport,
};

pub const AWS_LICENSE_MANAGER_SCHEMA_VERSION: &str =
    "hartevo.aws-license-manager-result-contract/v1";
pub const AWS_LICENSE_MANAGER_CONTRACT_VERSION: &str = "EXT-AWS-LICENSE-MANAGER-01-L1/v1";
pub const AWS_LICENSE_MANAGER_PLUGIN_ID: &str = "aws-license-manager-result";
pub const AWS_LICENSE_MANAGER_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const AWS_LICENSE_MANAGER_API_VERSION: &str = "2019-08-08";
pub const AWS_LICENSE_MANAGER_SERVICE_ID: &str = "aws.license-manager.result.read";
pub const AWS_LICENSE_MANAGER_SERVICE_NAME: &str = "AwsLicenseManagerService";
pub const AWS_LICENSE_MANAGER_PROVIDER_ID: &str = "aws.license-manager.result.recording";
pub const AWS_LICENSE_MANAGER_PROVIDER_NAME: &str = "AwsLicenseManagerProvider";
pub const AWS_LICENSE_MANAGER_PROVIDER_REVISION: &str = "license-manager-list-get-usage-1";
pub const MISSION_AWS_LICENSE_MANAGER_CONSUMER_ID: &str =
    "mission.aws-license-manager-result.consumer";
pub const AWS_LICENSE_MANAGER_CONSUMER_ID: &str = MISSION_AWS_LICENSE_MANAGER_CONSUMER_ID;
pub const MISSION_AWS_LICENSE_MANAGER_CONSUMER_NAME: &str = "MissionAwsLicenseManagerConsumer";
pub const AWS_LICENSE_MANAGER_CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-license-manager-result/v1|layer=1|service=aws.license-manager.result.read|provider=aws.license-manager.result.recording|consumer=mission.aws-license-manager-result.consumer|contract=EXT-AWS-LICENSE-MANAGER-01-L1/v1";
pub const AWS_LICENSE_MANAGER_CONTRACT_DIGEST: &str =
    "c0d80b90844503b0b4d6202ab6cee8f4a2b30f509617da5b71bcbc7ab6d2f0c2";
pub const AWS_LICENSE_MANAGER_MAX_IDENTIFIER_BYTES: usize = 256;
pub const AWS_LICENSE_MANAGER_MAX_PAGE_SIZE: u16 = 100;
pub const AWS_LICENSE_MANAGER_MAX_PAGES: u16 = 4;
pub const AWS_LICENSE_MANAGER_MAX_USAGE_ITEMS: usize = 400;
pub const AWS_LICENSE_MANAGER_MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const AWS_LICENSE_MANAGER_MAX_USAGE_WINDOW_DAYS: i64 = 366;
pub const AWS_LICENSE_MANAGER_PERMISSIONS: [&str; 4] = [
    "license-manager:ListLicenseConfigurations",
    "license-manager:GetLicenseConfiguration",
    "license-manager:ListUsageForLicenseConfiguration",
    "mission.scope",
];
pub const AWS_LICENSE_MANAGER_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-license-manager-result/contract.v1.json");

pub fn contract_digest() -> model::Digest {
    model::Digest::from_text(AWS_LICENSE_MANAGER_CONTRACT_DIGEST_INPUT)
}

pub fn provider_digest() -> model::Digest {
    model::Digest::from_fields(
        "hartevo.aws-license-manager-provider/v1",
        &[
            AWS_LICENSE_MANAGER_PROVIDER_ID.to_owned(),
            AWS_LICENSE_MANAGER_PROVIDER_REVISION.to_owned(),
            AWS_LICENSE_MANAGER_API_VERSION.to_owned(),
            AWS_LICENSE_MANAGER_PERMISSIONS.join("\n"),
            "ListLicenseConfigurations".to_owned(),
            "GetLicenseConfiguration".to_owned(),
            "ListUsageForLicenseConfiguration".to_owned(),
        ],
    )
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        AWS_LICENSE_MANAGER_CONTRACT_DIGEST, AWS_LICENSE_MANAGER_CONTRACT_DIGEST_INPUT,
        AWS_LICENSE_MANAGER_CONTRACT_JSON, AWS_LICENSE_MANAGER_CONTRACT_VERSION,
        AWS_LICENSE_MANAGER_SCHEMA_VERSION, AWS_LICENSE_MANAGER_SERVICE_ID,
        MISSION_AWS_LICENSE_MANAGER_CONSUMER_ID, contract_digest,
    };

    #[test]
    fn machine_contract_is_layer_one_and_non_native() {
        let value: Value = serde_json::from_str(AWS_LICENSE_MANAGER_CONTRACT_JSON)
            .expect("valid License Manager contract JSON");
        assert_eq!(
            value["schemaVersion"].as_str(),
            Some(AWS_LICENSE_MANAGER_SCHEMA_VERSION)
        );
        assert_eq!(
            value["contractVersion"].as_str(),
            Some(AWS_LICENSE_MANAGER_CONTRACT_VERSION)
        );
        assert_eq!(value["layer"].as_u64(), Some(1));
        assert_eq!(
            value["digestInput"].as_str(),
            Some(AWS_LICENSE_MANAGER_CONTRACT_DIGEST_INPUT)
        );
        assert_eq!(
            value["contractDigest"].as_str(),
            Some(AWS_LICENSE_MANAGER_CONTRACT_DIGEST)
        );
        assert_eq!(
            contract_digest().as_str(),
            AWS_LICENSE_MANAGER_CONTRACT_DIGEST
        );
        assert_eq!(
            value["service"]["id"].as_str(),
            Some(AWS_LICENSE_MANAGER_SERVICE_ID)
        );
        assert_eq!(
            value["consumer"]["id"].as_str(),
            Some(MISSION_AWS_LICENSE_MANAGER_CONSUMER_ID)
        );
        assert_eq!(value["service"]["externalWrites"].as_bool(), Some(false));
        assert_eq!(value["provider"]["nativeEvidence"].as_bool(), Some(false));
        assert!(value["authorityBoundary"]["doesNotOwn"].is_array());
    }
}
