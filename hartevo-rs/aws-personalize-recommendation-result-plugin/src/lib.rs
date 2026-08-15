//! Standalone Layer-1 governed Amazon Personalize recommendation evidence.
//!
//! The crate is intentionally below Hartevo Truth, Consent, Effect, Receipt,
//! Verification, Outcome, and durable Work Product authority. It models only
//! bounded campaign/recommender metadata and recommendation/ranking projections
//! with fixture, recording, loopback, and `BLOCKED_ENV` transports. It never
//! resolves native credentials, opens native HTTPS, mutates Personalize
//! resources, trains/imports models, reads profiles/catalog/context, or claims
//! connected, native, or first-party evidence.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
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
    MissionAwsPersonalizeConsumer, MissionAwsPersonalizeResult, ProposalDisposition,
    RecordedAwsPersonalizeResult,
};
pub use error::{AwsPersonalizeRecommendationError, AwsPersonalizeTransportError, Result};
pub use model::*;
pub use provider::{
    AwsPersonalizeOperation, AwsPersonalizeProvider, AwsPersonalizeProviderDefinition,
    AwsPersonalizeTransport, BlockedEnvTransport, DescribeCampaignRequest,
    DescribeCampaignResponse, DescribeRecommenderRequest, DescribeRecommenderResponse,
    FixtureTransport, GetPersonalizedRankingRequest, GetPersonalizedRankingResponse,
    GetRecommendationsRequest, GetRecommendationsResponse, LoopbackTransport, RecordedRequest,
    RecordingTransport,
};
pub use service::{
    AwsPersonalizeRecommendationProposal, AwsPersonalizeRecommendationRegistration,
    AwsPersonalizeRecommendationService, AwsPersonalizeRegistration, CapabilityDescription,
    FailureEvidence, RegistrationStatus, RegistrationTransitionEvidence, ServiceDefinition,
    VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-personalize-recommendation-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-PERSONALIZE-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-personalize-recommendation-result/v1|layer=1|service=aws.personalize.recommendation-result.read|provider=aws.personalize.recommendation-result.recording|consumer=mission.aws-personalize-recommendation.consumer|api=personalize-describe-campaign-describe-recommender-get-recommendations-get-personalized-ranking-2018-05-22-r1";
pub const CONTRACT_DIGEST: &str =
    "578f9339c556ab0cca2d32d449b38feb8d7d50c659b344655780cd4ee97cb6aa";
pub const PLUGIN_ID: &str = "aws.personalize.recommendation-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.personalize.recommendation-result.read";
pub const PROVIDER_ID: &str = "aws.personalize.recommendation-result.recording";
pub const PROVIDER_API_REVISION: &str = "personalize-describe-campaign-describe-recommender-get-recommendations-get-personalized-ranking-2018-05-22-r1";
pub const CONSUMER_ID: &str = "mission.aws-personalize-recommendation.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const PERSONALIZE_API_VERSION: &str = "2018-05-22";
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_FAILURE_REASON_BYTES: usize = 256;
pub const MAX_RESULTS: u16 = 50;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const LAYER1_PERMISSIONS: [&str; 5] = [
    "personalize:DescribeCampaign",
    "personalize:DescribeRecommender",
    "personalize:GetRecommendations",
    "personalize:GetPersonalizedRanking",
    "mission.scope",
];
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-personalize-recommendation-result/aws-personalize-recommendation-result.v1.json"
);

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

pub fn evidence_policy_digest() -> Digest {
    Digest::from_parts(
        "aws-personalize-evidence-policy/v1",
        &[
            ("api_revision", PROVIDER_API_REVISION.to_owned()),
            ("max_results", MAX_RESULTS.to_string()),
            ("max_response_bytes", MAX_RESPONSE_BYTES.to_string()),
            (
                "redaction",
                "identifier_digest_rank_score_bucket_only".to_owned(),
            ),
            ("pagination", "false".to_owned()),
        ],
    )
}

pub fn validate_contract_document() -> Result<()> {
    let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
        .map_err(|_| AwsPersonalizeRecommendationError::ContractDrift)?;
    let object = value
        .as_object()
        .ok_or(AwsPersonalizeRecommendationError::ContractDrift)?;
    let required = [
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
        "scope",
        "allowlistedSeams",
        "bounds",
        "digests",
        "registration",
        "projections",
        "transportProvenance",
        "authorityBoundary",
        "forbiddenEffects",
        "layer2Gaps",
    ];
    if required.iter().any(|key| !object.contains_key(*key)) {
        return Err(AwsPersonalizeRecommendationError::ContractDrift);
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
        return Err(AwsPersonalizeRecommendationError::ContractDrift);
    }
    let service = object
        .get("service")
        .and_then(serde_json::Value::as_object)
        .ok_or(AwsPersonalizeRecommendationError::ContractDrift)?;
    if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
        || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
        || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
        || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
        || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
    {
        return Err(AwsPersonalizeRecommendationError::ContractDrift);
    }
    let provider = object
        .get("provider")
        .and_then(serde_json::Value::as_object)
        .ok_or(AwsPersonalizeRecommendationError::ContractDrift)?;
    if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
        || provider
            .get("apiRevision")
            .and_then(serde_json::Value::as_str)
            != Some(PROVIDER_API_REVISION)
        || provider.get("connected") != Some(&serde_json::Value::Bool(false))
        || provider.get("native") != Some(&serde_json::Value::Bool(false))
        || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
        || provider.get("profileRead") != Some(&serde_json::Value::Bool(false))
        || provider.get("catalogRead") != Some(&serde_json::Value::Bool(false))
        || provider.get("contextRead") != Some(&serde_json::Value::Bool(false))
        || provider.get("modelMutation") != Some(&serde_json::Value::Bool(false))
    {
        return Err(AwsPersonalizeRecommendationError::ContractDrift);
    }
    let consumer = object
        .get("consumer")
        .and_then(serde_json::Value::as_object)
        .ok_or(AwsPersonalizeRecommendationError::ContractDrift)?;
    if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
        || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
        || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
        || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
    {
        return Err(AwsPersonalizeRecommendationError::ContractDrift);
    }
    for key in ["connected", "nativeProvider", "firstPartyEvidence"] {
        if object
            .get("authorityBoundary")
            .and_then(serde_json::Value::as_object)
            .and_then(|boundary| boundary.get(key))
            != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsPersonalizeRecommendationError::ContractDrift);
        }
    }
    Ok(())
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_document_is_layer_one_and_non_native() {
        assert!(validate_contract_document().is_ok());
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert_eq!(BLOCKED_ENV, "BLOCKED_ENV");
        assert_eq!(LAYER1_PERMISSIONS.len(), 5);
    }

    #[test]
    fn evidence_policy_is_stable_and_bounded() {
        assert_eq!(evidence_policy_digest(), evidence_policy_digest());
        assert_eq!(MAX_RESULTS, 50);
        assert_eq!(MAX_RESPONSE_BYTES, 1_048_576);
    }
}
