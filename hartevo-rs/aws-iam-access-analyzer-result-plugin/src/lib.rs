//! Standalone Layer-1 AWS IAM Access Analyzer result boundary.
//!
//! This crate is deliberately below Hartevo Truth, Consent, Effect, Receipt,
//! Verification, and Outcome authority. It models exact AWS scope, bounded
//! finding/policy-validation evidence, digest fences, and reversible
//! registration. Recording, fake, loopback, and `BLOCKED_ENV` transports are
//! all non-connected, non-native, and non-first-party.

#![forbid(unsafe_code)]
#![allow(
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::return_self_not_must_use,
    clippy::single_match_else,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments
)]

use std::fmt::Write as _;

use serde::Serialize;
use sha2::{Digest as Sha2Digest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::*;
pub use error::{AwsIamAccessAnalyzerError, AwsIamProviderError, AwsIamTransportError, Result};
pub use model::*;
pub use provider::*;
pub use service::*;

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-iam-access-analyzer-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-IAM-ACCESS-ANALYZER-01-L1/v1";
pub const PLUGIN_ID: &str = "aws.iam.access-analyzer.result";
pub const OBJECTIVE_TYPE: &str = "permission_analysis";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-iam-access-analyzer-result/v1|layer=1|service=aws.iam.access-analyzer.result.read|provider=aws.iam.access-analyzer.result.recording|consumer=mission.aws-iam-access-analyzer.consumer";
pub const SERVICE_ID: &str = "aws.iam.access-analyzer.result.read";
pub const PROVIDER_ID: &str = "aws.iam.access-analyzer.result.recording";
pub const PROVIDER_API_REVISION: &str = "access-analyzer-list-findings-v2-validate-policy-read-1";
pub const CONSUMER_ID: &str = "mission.aws-iam-access-analyzer.consumer";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-iam-access-analyzer-result/contract.v1.json");

pub const MAX_POLICY_BYTES: usize = 256 * 1024;
pub const MAX_FINDING_ID_BYTES: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 4 * 1024;
pub const MAX_FILTERS: usize = 8;
pub const MAX_CRITERION_VALUES: usize = 20;
pub const MAX_PAGE_SIZE: u32 = 100;
pub const MAX_PAGES: u16 = 32;
pub const MAX_FINDINGS: usize = 512;
pub const MAX_RETRY_ATTEMPTS: u8 = 8;
pub const MAX_BACKOFF_MILLIS: u64 = 60_000;

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

pub(crate) fn digest_serialized<T: Serialize>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("contract values must serialize");
    Digest::from_bytes(bytes)
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn valid_text(value: &str, max_bytes: usize, whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (whitespace || !value.chars().any(char::is_whitespace))
}

pub(crate) fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        CONSUMER_ID, CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION,
        EVIDENCE_LEVEL, OBJECTIVE_TYPE, PLUGIN_ID, PROVIDER_API_REVISION, PROVIDER_ID, SERVICE_ID,
        contract_digest,
    };

    #[test]
    fn contract_is_layer_one_and_non_native() {
        let document: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(document["contractVersion"], CONTRACT_VERSION);
        assert_eq!(document["pluginId"], PLUGIN_ID);
        assert_eq!(document["objectiveType"], OBJECTIVE_TYPE);
        assert_eq!(document["layer"], 1);
        assert_eq!(document["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(document["digestInput"], CONTRACT_DIGEST_INPUT);
        assert_eq!(document["contractDigest"], contract_digest().as_str());
        assert_eq!(document["service"]["id"], SERVICE_ID);
        assert_eq!(document["provider"]["id"], PROVIDER_ID);
        assert_eq!(document["provider"]["apiRevision"], PROVIDER_API_REVISION);
        assert_eq!(document["consumer"]["id"], CONSUMER_ID);
        assert!(!document["provider"]["connectedEvidence"].as_bool().unwrap());
        assert!(!document["provider"]["nativeEvidence"].as_bool().unwrap());
        assert!(!document["consumer"]["adoptsOutcome"].as_bool().unwrap());
        assert!(!document["consumer"]["truthAuthority"].as_bool().unwrap());
        assert!(
            !document["consumer"]["leastPrivilegeCertification"]
                .as_bool()
                .unwrap()
        );
    }
}
