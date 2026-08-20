//! Standalone Layer-1 AWS DynamoDB table-posture result boundary.
//!
//! This crate intentionally stays below Hartevo Truth, Consent, Effect,
//! Receipt, Verification, Outcome, and durable Work Product authority. It
//! models bounded DynamoDB metadata reads, digest fences, reversible
//! registration, redacted recording, and a Mission-facing review seam. It
//! does not resolve credentials, sign live SigV4 requests, read items, mutate
//! tables, restore/export tables, or claim connected/native evidence.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::collapsible_if,
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
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionAwsDynamoDbConsumer, MissionAwsDynamoDbResult, ProposalDisposition,
    RecordedAwsDynamoDbResult,
};
pub use error::{AwsDynamoDbTableError, AwsDynamoDbTransportError, Result};
pub use model::*;
pub use provider::{
    AwsDynamoDbOperation, AwsDynamoDbProvider, AwsDynamoDbProviderDefinition, AwsDynamoDbTransport,
    BlockedEnvTransport, DescribeContinuousBackupsRequest, DescribeContinuousBackupsResponse,
    DescribeTableRequest, DescribeTableResponse, DescribeTimeToLiveRequest,
    DescribeTimeToLiveResponse, FixtureTransport, ListTablesRequest, ListTablesResponse,
    ListTagsOfResourceRequest, ListTagsOfResourceResponse, LoopbackTransport, RecordedRequest,
    RecordingTransport,
};
pub use service::{
    AwsDynamoDbTableCapabilities, AwsDynamoDbTableEvidence, AwsDynamoDbTableProposal,
    AwsDynamoDbTableReadRequest, AwsDynamoDbTableReadResult, AwsDynamoDbTableRecord,
    AwsDynamoDbTableRegistration, AwsDynamoDbTableService, AwsDynamoDbTableVerifiedRecord,
    RegistrationStatus, RegistrationTransitionEvidence, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-dynamodb-table-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-DYNAMODB-01-L1/v1";
pub const PLUGIN_ID: &str = "aws.dynamodb.table-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.dynamodb.table.read";
pub const PROVIDER_ID: &str = "aws.dynamodb.table.recording";
pub const PROVIDER_API_REVISION: &str = "dynamodb-list-tables-describe-table-describe-continuous-backups-describe-time-to-live-list-tags-of-resource-1";
pub const CONSUMER_ID: &str = "mission.aws-dynamodb-table.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const AWS_DYNAMODB_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-dynamodb-table-result/v1|layer=1|service=aws.dynamodb.table.read|provider=aws.dynamodb.table.recording|consumer=mission.aws-dynamodb-table.consumer";
pub const CONTRACT_DIGEST: &str =
    "a86242dbbca033232efbcb4c68547873f1ae9f386aa338a4695e66bc8927a83c";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-dynamodb-table-result/contract.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_ARN_BYTES: usize = 2_048;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
pub const MAX_TAG_KEYS: usize = 64;
pub const MAX_INDEXES: usize = 32;
pub const MAX_REPLICAS: usize = 32;
pub const LAYER1_PERMISSIONS: [&str; 6] = [
    "dynamodb:ListTables",
    "dynamodb:DescribeTable",
    "dynamodb:DescribeContinuousBackups",
    "dynamodb:DescribeTimeToLive",
    "dynamodb:ListTagsOfResource",
    "mission.scope",
];

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

/// Layer-1 authority is intentionally all false. These methods make the
/// boundary inspectable without granting any Hartevo kernel authority.
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

    pub const fn kernel_truth_authority() -> bool {
        false
    }

    pub const fn kernel_effect_authority() -> bool {
        false
    }

    pub const fn outcome_adoption() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn checked_contract_matches_the_typed_layer_one_boundary() {
        let document = serde_json::from_str::<Value>(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(document["contractVersion"], CONTRACT_VERSION);
        assert_eq!(document["pluginId"], PLUGIN_ID);
        assert_eq!(document["pluginVersion"], PLUGIN_VERSION);
        assert_eq!(document["layer"], 1);
        assert_eq!(document["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(document["digestInput"], CONTRACT_DIGEST_INPUT);
        assert_eq!(document["contractDigest"], CONTRACT_DIGEST);
        assert_eq!(contract_digest().as_str(), CONTRACT_DIGEST);
        assert_eq!(document["service"]["type"], "AwsDynamoDbTableService");
        assert_eq!(document["provider"]["type"], "AwsDynamoDbProvider");
        assert_eq!(document["consumer"]["type"], "MissionAwsDynamoDbConsumer");
        assert_eq!(document["provider"]["connected"], false);
        assert_eq!(document["provider"]["native"], false);
        assert_eq!(document["provider"]["firstParty"], false);
        assert_eq!(document["consumer"]["adoptsOutcome"], false);
        assert_eq!(document["consumer"]["truthAuthority"], false);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::outcome_adoption());
    }
}
