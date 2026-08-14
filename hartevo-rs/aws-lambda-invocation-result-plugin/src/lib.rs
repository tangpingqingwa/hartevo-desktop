//! Standalone Layer-1 AWS Lambda invocation-result boundary.
//!
//! The crate is intentionally below Hartevo Truth, Consent, Effect, Receipt,
//! Verification, and Outcome authority. It models exact AWS Lambda scope,
//! bounded invocation/result metadata, digest fences, and reversible
//! registration. Recording, fake, loopback, and `BLOCKED_ENV` transports are
//! all non-connected, non-native, and non-first-party.

#![forbid(unsafe_code)]

use std::fmt::Write as _;

use serde::Serialize;
use sha2::{Digest as Sha2Digest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    AwsLambdaInvocationResultProposal, AwsLambdaResultRecordingLog, MissionAwsLambdaResultConsumer,
    ProposalDisposition, RecordedAwsLambdaResult,
};
pub use error::{
    AwsLambdaInvocationResultError, AwsLambdaProviderError, AwsLambdaTransportError, Result,
};
pub use model::*;
pub use provider::{
    AwsLambdaHttpStatus, AwsLambdaProvider, AwsLambdaTransport, BlockedEnvTransport, FakeTransport,
    FunctionLookupRequest, FunctionLookupResponse, InvocationRequest, LoopbackTransport,
    ProviderInvocationResponse, RecordedRequest, RecordedRequestKind, RecordingTransport,
};
pub use service::{
    AwsLambdaInvocationResultService, AwsLambdaRegistration, AwsLambdaRegistrationRegistry,
    CapabilityDescription, ProviderIdentity, RegistrationReceipt, RegistrationTransitionEvidence,
    ScopeDescription,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-lambda-invocation-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWSLAMBDA-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-lambda-invocation-result/v1|layer=1|service=aws.lambda.invocation-result.read|provider=aws.lambda.invocation-result.recording|consumer=mission.aws-lambda-result.consumer";
pub const CONTRACT_DIGEST: &str =
    "7ddfdddd160398a4b93d843a26bb516b30cdef42860a3ed6b38095ca4331e127";
pub const PLUGIN_ID: &str = "aws.lambda.invocation-result";
pub const OBJECTIVE_TYPE: &str = "deployment_verification";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.lambda.invocation-result.read";
pub const PROVIDER_ID: &str = "aws.lambda.invocation-result.recording";
pub const PROVIDER_API_REVISION: &str = "lambda-invoke-get-function-read-1";
pub const CONSUMER_ID: &str = "mission.aws-lambda-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-lambda-invocation-result/contract.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_REGION_BYTES: usize = 128;
pub const MAX_FUNCTION_NAME_BYTES: usize = 64;
pub const MAX_ALIAS_BYTES: usize = 128;
pub const MAX_VERSION_BYTES: usize = 32;
pub const MAX_SYNCHRONOUS_INPUT_BYTES: u64 = 6 * 1024 * 1024;
pub const MAX_ASYNCHRONOUS_INPUT_BYTES: u64 = 1024 * 1024;
pub const MAX_RESPONSE_BYTES: u64 = 6 * 1024 * 1024;
pub const MAX_RETRY_ATTEMPTS: u8 = 8;
pub const MAX_FUNCTION_TIMEOUT_MILLIS: u64 = 15 * 60 * 1000;
pub const MAX_BACKOFF_MILLIS: u64 = 60_000;
pub const MAX_EVIDENCE_BYTES: u64 = 1024 * 1024;

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

pub(crate) fn digest_serialized<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("contract values must serialize");
    sha256_hex(&bytes)
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(crate) fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
    allow_internal_whitespace: bool,
) -> Result<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
        || (!allow_internal_whitespace && value.chars().any(char::is_whitespace))
    {
        Err(AwsLambdaInvocationResultError::InvalidText { field })
    } else {
        Ok(())
    }
}

pub(crate) fn validate_identifier(value: &str, field: &'static str) -> Result<()> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES, false)
}

pub(crate) fn validate_digest(value: &str, field: &'static str) -> Result<()> {
    if valid_digest(value) {
        Ok(())
    } else {
        Err(AwsLambdaInvocationResultError::InvalidDigest { field })
    }
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

#[cfg(test)]
mod contract_tests {
    use serde::Deserialize;

    use super::{
        CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION,
        EVIDENCE_LEVEL, PLUGIN_ID, contract_digest,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        plugin_id: String,
        layer: u8,
        evidence_level: String,
        digest_input: String,
        contract_digest: String,
    }

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract = serde_json::from_str::<ContractDocument>(CONTRACT_JSON)
            .expect("checked AWS Lambda contract");
        assert_eq!(contract.schema_version, CONTRACT_SCHEMA);
        assert_eq!(contract.contract_version, CONTRACT_VERSION);
        assert_eq!(contract.plugin_id, PLUGIN_ID);
        assert_eq!(contract.layer, 1);
        assert_eq!(contract.evidence_level, EVIDENCE_LEVEL);
        assert_eq!(contract.digest_input, CONTRACT_DIGEST_INPUT);
        assert_eq!(contract.contract_digest, CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert!(!CONTRACT_DIGEST.contains("REPLACED"));
    }
}
