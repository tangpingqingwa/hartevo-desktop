//! Standalone Layer-1 governed AWS CloudFront distribution result boundary.
//!
//! This crate is intentionally below Hartevo Truth, Consent, Effect, Receipt,
//! Verification, Outcome, and durable Work Product authority. It models only
//! bounded CloudFront distribution reads, digest fences, reversible
//! registration, redacted request/cost receipts, and a Mission-scoped
//! proposal/record seam. Recording, fixture, loopback, and `BLOCKED_ENV`
//! transports are always non-connected, non-native, and non-first-party.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::fn_params_excessive_bools,
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
pub mod service;

pub use consumer::{
    MissionAwsCloudFrontConsumer, MissionAwsCloudFrontResult, ProposalDisposition,
    RecordedAwsCloudFrontResult,
};
pub use error::{AwsCloudFrontDistributionError, AwsCloudFrontTransportError, Result};
pub use model::*;
pub use provider::{
    AwsCloudFrontOperation, AwsCloudFrontProvider, AwsCloudFrontProviderDefinition,
    AwsCloudFrontTransport, BlockedEnvTransport, Cursor, FixtureTransport,
    GetDistributionConfigRequest, GetDistributionConfigResponse, GetDistributionRequest,
    GetDistributionResponse, ListDistributionsRequest, ListDistributionsResponse,
    LoopbackTransport, RecordedRequest, RecordingTransport,
};
pub use service::{
    AwsCloudFrontDistributionProposal, AwsCloudFrontDistributionRegistration,
    AwsCloudFrontDistributionService, AwsCloudFrontRegistration, CapabilityDescription,
    CloudFrontEvidenceRequest, FailureEvidence, RegistrationStatus, RegistrationTransitionEvidence,
    VerificationFailure, VerificationReport,
};

pub type AwsCloudFrontScope = AwsCloudFrontDistributionScope;
pub type CloudFrontDistributionIdentity = DistributionIdentity;
pub type CloudFrontDistributionProjection = DistributionProjection;
pub type AwsCloudFrontDistributionResult = AwsCloudFrontDistributionProposal;
pub type AwsCloudFrontService<T> = AwsCloudFrontDistributionService<T>;

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-cloudfront-distribution-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-CLOUDFRONT-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-cloudfront-distribution-result/v1|layer=1|service=aws.cloudfront.distribution.result.read|provider=aws.cloudfront.distribution.result.recording|consumer=mission.aws-cloudfront-distribution.consumer|api=cloudfront-list-distributions-get-distribution-get-distribution-config-2020-05-31-r1";
pub const CONTRACT_DIGEST: &str =
    "3405ab8d6eda76e26f8f3b0c6cfe2252ca8836460e9b1c382d0d57ef18c1345b";
pub const PLUGIN_ID: &str = "aws.cloudfront.distribution.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.cloudfront.distribution.result.read";
pub const PROVIDER_ID: &str = "aws.cloudfront.distribution.result.recording";
pub const API_REVISION: &str =
    "cloudfront-list-distributions-get-distribution-get-distribution-config-2020-05-31-r1";
pub const CONSUMER_ID: &str = "mission.aws-cloudfront-distribution.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const LAYER1_PERMISSIONS: [&str; 4] = [
    "cloudfront:ListDistributions",
    "cloudfront:GetDistribution",
    "cloudfront:GetDistributionConfig",
    "mission.scope",
];
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 8;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_ALIAS_COUNT: usize = 100;
pub const MAX_ORIGIN_COUNT: usize = 100;
pub const MAX_BEHAVIOR_COUNT: usize = 100;
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-cloudfront-distribution-result/aws-cloudfront-distribution-result.v1.json"
);

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsCloudFrontDistributionContract {
    value: serde_json::Value,
}

impl AwsCloudFrontDistributionContract {
    pub fn baseline() -> Result<Self> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|_| AwsCloudFrontDistributionError::ContractDrift)?;
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
            .ok_or(AwsCloudFrontDistributionError::ContractDrift)?;
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
            "registration",
            "pagination",
            "projection",
            "receipts",
            "provenance",
            "authorityBoundary",
            "forbiddenEffects",
            "layer2Gaps",
        ] {
            if !object.contains_key(key) {
                return Err(AwsCloudFrontDistributionError::ContractDrift);
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
            return Err(AwsCloudFrontDistributionError::ContractDrift);
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCloudFrontDistributionError::ContractDrift)?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsCloudFrontDistributionError::ContractDrift);
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCloudFrontDistributionError::ContractDrift)?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(API_REVISION)
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsCloudFrontDistributionError::ContractDrift);
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCloudFrontDistributionError::ContractDrift)?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsCloudFrontDistributionError::ContractDrift);
        }
        for forbidden in [
            "UpdateDistribution",
            "CreateInvalidation",
            "mutate_distribution",
            "generate_signed_url",
            "generate_signed_cookie",
            "capture_viewer_request",
            "export_raw_config",
            "adopt_verified_work_product",
        ] {
            if !object
                .get("forbiddenEffects")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(forbidden)))
            {
                return Err(AwsCloudFrontDistributionError::ContractDrift);
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
        let contract = AwsCloudFrontDistributionContract::baseline().expect("contract");
        assert_eq!(contract.digest().as_str(), CONTRACT_DIGEST);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::adopts_outcome());
        assert!(!Layer1Authority::adopts_work_product());
    }
}
