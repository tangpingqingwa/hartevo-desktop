//! Standalone Layer-1 governed Amazon Athena query-result boundary.
//!
//! This crate deliberately stops below Hartevo Truth, Consent, Effect,
//! Receipt, Verification, Outcome, and durable Work Product authority.  It
//! exposes only bounded, digest-backed query-execution evidence and an
//! optional metadata/shape projection.  It never starts or cancels a query,
//! reads an S3 output object, retains SQL text or result values, or claims
//! native/connected/first-party evidence.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

use sha2::{Digest as ShaDigest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod query;
pub mod service;

pub use consumer::{
    ConsumerError, MissionAwsAthenaConsumer, MissionAwsAthenaResult, ProposalDisposition,
    RecordedAwsAthenaResult,
};
pub use error::{AwsAthenaQueryResultError, AwsAthenaTransportError, Result};
pub use model::*;
pub use provider::{
    AwsAthenaOperation, AwsAthenaProvider, AwsAthenaProviderDefinition, AwsAthenaTransport,
    BlockedEnvTransport, FixtureTransport, GetQueryExecutionRequest, GetQueryExecutionResponse,
    GetQueryResultsRequest, GetQueryResultsResponse, LoopbackTransport, RecordedRequest,
    RecordingTransport,
};
pub use query::{
    AthenaQueryMode, ParameterizedAthenaQuery, QueryCompileError, QueryParameter,
    QueryParameterType,
};
pub use service::{
    AwsAthenaEvidenceRequest, AwsAthenaQueryResultProposal, AwsAthenaQueryResultRegistration,
    AwsAthenaQueryResultService, AwsAthenaRegistration, CapabilityDescription, FailureEvidence,
    RegistrationStatus, RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};

pub type AwsAthenaScope = AwsAthenaQueryResultScope;
pub type AwsAthenaQueryResult = AwsAthenaQueryResultProposal;
pub type AwsAthenaService<T> = AwsAthenaQueryResultService<T>;

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-athena-query-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-ATHENA-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-athena-query-result/v1|layer=1|service=aws.athena.query-result.read|provider=aws.athena.query-result.recording|consumer=mission.aws-athena-query-result.consumer|api=athena-get-query-execution-get-query-results-2017-05-18-r1";
pub const CONTRACT_DIGEST: &str =
    "4e260db03b3ed2fd45f2f4f1536584b85922f414c78f7bbf0133d3e4a3e530bf";
pub const EVIDENCE_CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-athena-query-result/evidence/v1|states=QUEUED,RUNNING,SUCCEEDED,FAILED,CANCELLED,PARTIAL,EXPIRED,ACCESS_LOST,PROVIDER_UNKNOWN,TAMPERED,REVOKED,STALE|redaction=secret-reference,sigv4,sql-text,parameter-values,execution-id,output-location,result-rows,page-token|provenance=recording,fixture,loopback,blocked_env";
pub const EVIDENCE_CONTRACT_DIGEST: &str =
    "6f7040fcdb163a34a7a8d5ea9b4720b66310296a871ff2daef8ed4c02983611e";
pub const PLUGIN_ID: &str = "aws.athena.query-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.athena.query-result.read";
pub const PROVIDER_ID: &str = "aws.athena.query-result.recording";
pub const PROVIDER_API_REVISION: &str =
    "athena-get-query-execution-get-query-results-2017-05-18-r1";
pub const CONSUMER_ID: &str = "mission.aws-athena-query-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";

pub const LAYER1_PERMISSIONS: [&str; 5] = [
    "athena:GetQueryExecution",
    "athena:GetQueryResults",
    "mission.scope",
    "project.scope",
    "work_product.scope",
];

pub const FORBIDDEN_EFFECTS: [&str; 12] = [
    "athena:StartQueryExecution",
    "athena:StopQueryExecution",
    "s3:GetObject",
    "arbitrary_sql",
    "ddl",
    "dml",
    "ctas",
    "unload",
    "multi_statement",
    "unbounded_rows",
    "raw_result_values",
    "work_product_adoption",
];

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_QUERY_BYTES: usize = 16 * 1024;
pub const MAX_PAGE_TOKEN_BYTES: usize = 4 * 1024;
pub const MAX_RESULT_ROWS: u32 = 1_000;
pub const MAX_RESULT_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_RESULT_PAGES: u16 = 8;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-athena-query-result/aws-athena-query-result.v1.json"
);

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

pub fn evidence_contract_digest() -> String {
    sha256_hex(EVIDENCE_CONTRACT_DIGEST_INPUT.as_bytes())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsAthenaQueryResultContract {
    value: serde_json::Value,
}

impl AwsAthenaQueryResultContract {
    pub fn baseline() -> Result<Self> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|_| AwsAthenaQueryResultError::ContractDrift)?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(CONTRACT_DIGEST_INPUT)
    }

    pub fn validate(&self) -> Result<()> {
        let object = self
            .value
            .as_object()
            .ok_or(AwsAthenaQueryResultError::ContractDrift)?;
        for key in [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "pluginId",
            "layer",
            "evidenceLevel",
            "digestInput",
            "contractDigest",
            "service",
            "provider",
            "consumer",
            "credentials",
            "scope",
            "queryPolicy",
            "registration",
            "pagination",
            "projection",
            "receipts",
            "evidence",
            "provenance",
            "authorityBoundary",
            "forbiddenEffects",
            "layer2Gaps",
        ] {
            if !object.contains_key(key) {
                return Err(AwsAthenaQueryResultError::ContractDrift);
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(CONTRACT_SCHEMA)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(PLUGIN_VERSION)
            || object.get("pluginId").and_then(serde_json::Value::as_str) != Some(PLUGIN_ID)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
            || object
                .get("evidenceLevel")
                .and_then(serde_json::Value::as_str)
                != Some(EVIDENCE_LEVEL)
            || object
                .get("digestInput")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST_INPUT)
            || object
                .get("contractDigest")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST)
            || contract_digest() != CONTRACT_DIGEST
        {
            return Err(AwsAthenaQueryResultError::ContractDrift);
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsAthenaQueryResultError::ContractDrift)?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || service.get("startsQueries") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsAthenaQueryResultError::ContractDrift);
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsAthenaQueryResultError::ContractDrift)?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(PROVIDER_API_REVISION)
            || provider.get("connectedEvidence") != Some(&serde_json::Value::Bool(false))
            || provider.get("nativeEvidence") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstPartyEvidence") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsAthenaQueryResultError::ContractDrift);
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsAthenaQueryResultError::ContractDrift)?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsAthenaQueryResultError::ContractDrift);
        }
        for effect in FORBIDDEN_EFFECTS {
            if !object
                .get("forbiddenEffects")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(effect)))
            {
                return Err(AwsAthenaQueryResultError::ContractDrift);
            }
        }
        Ok(())
    }
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

    pub const fn durable_provider_receipt() -> bool {
        false
    }

    pub const fn starts_queries() -> bool {
        false
    }

    pub const fn cancels_queries() -> bool {
        false
    }

    pub const fn reads_s3_objects() -> bool {
        false
    }

    pub const fn truth_authority() -> bool {
        false
    }

    pub const fn adopts_outcome() -> bool {
        false
    }

    pub const fn adopts_work_product() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_is_pinned_to_layer_one_and_honest_provenance() {
        let contract = AwsAthenaQueryResultContract::baseline().expect("Athena contract");
        assert_eq!(contract.digest().as_str(), CONTRACT_DIGEST);
        assert_eq!(evidence_contract_digest().len(), 64);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::starts_queries());
        assert!(!Layer1Authority::cancels_queries());
        assert!(!Layer1Authority::reads_s3_objects());
        assert!(!Layer1Authority::truth_authority());
        assert!(!Layer1Authority::adopts_outcome());
        assert!(!Layer1Authority::adopts_work_product());
    }
}
