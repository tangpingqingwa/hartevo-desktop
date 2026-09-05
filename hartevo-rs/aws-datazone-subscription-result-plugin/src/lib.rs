//! Standalone Layer-1 governed Amazon DataZone asset/subscription evidence.
//!
//! This crate is intentionally below Hartevo Truth, Consent, Effect, Receipt,
//! Verification, Outcome, and durable Work Product authority. It models only
//! bounded digest-only DataZone reads, reversible registration, fail-closed
//! drift fences, and a Mission-scoped proposal/record seam. Recording,
//! fixture, loopback, and `BLOCKED_ENV` transports are always non-connected,
//! non-native, and non-first-party.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::cast_possible_truncation,
    clippy::collapsible_if,
    clippy::if_not_else,
    clippy::fn_params_excessive_bools,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
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
    MissionAwsDataZoneConsumer, MissionAwsDataZoneResult, MissionAwsDataZoneSubscriptionResult,
    MissionAwsDataZoneSubscriptionResultConsumer, ProposalDisposition,
    RecordedAwsDataZoneSubscriptionResult,
};
pub use error::{AwsDataZoneSubscriptionResultError, AwsDataZoneTransportError, Result};
pub use model::*;
pub use provider::{
    AwsDataZoneOperation, AwsDataZoneProvider, AwsDataZoneProviderDefinition, AwsDataZoneTransport,
    BlockedEnvTransport, FixtureTransport, GetAssetRequest, GetAssetResponse,
    GetSubscriptionRequest, GetSubscriptionRequestDetailsRequest,
    GetSubscriptionRequestDetailsResponse, GetSubscriptionResponse,
    ListSubscriptionRequestsRequest, ListSubscriptionRequestsResponse, LoopbackTransport,
    RecordedRequest, RecordingTransport,
};
pub use service::{
    AwsDataZoneService, AwsDataZoneServiceDefinition, AwsDataZoneSubscriptionProposal,
    AwsDataZoneSubscriptionRegistration, AwsDataZoneSubscriptionResult,
    AwsDataZoneSubscriptionResultProposal, AwsDataZoneSubscriptionResultRegistration,
    AwsDataZoneSubscriptionResultService, AwsDataZoneSubscriptionService, CapabilityDescription,
    DataZoneEvidenceRequest, FailureEvidence, RegistrationStatus, RegistrationTransitionEvidence,
    ServiceDefinition, VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-datazone-subscription-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWSDATAZONE-01-L1/v1";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-datazone-subscription-result/v1|layer=1|service=aws.datazone.subscription-result.read|provider=aws.datazone.subscription-result.recording|consumer=mission.aws-datazone-subscription-result.consumer|api=datazone-get-asset-get-subscription-request-details-get-subscription-list-subscription-requests-2023-05-26-r1";
pub const CONTRACT_DIGEST: &str =
    "087b6490d4543d61e6fd8acf77479ef28257f9c5556ccc56ed5a1c701d722e26";
pub const PLUGIN_ID: &str = "aws.datazone.subscription-result";
pub const SERVICE_ID: &str = "aws.datazone.subscription-result.read";
pub const PROVIDER_ID: &str = "aws.datazone.subscription-result.recording";
pub const PROVIDER_API_REVISION: &str = "datazone-get-asset-get-subscription-request-details-get-subscription-list-subscription-requests-2023-05-26-r1";
pub const CONSUMER_ID: &str = "mission.aws-datazone-subscription-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 50;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const LAYER1_PERMISSIONS: [&str; 5] = [
    "datazone:GetAsset",
    "datazone:GetSubscriptionRequestDetails",
    "datazone:GetSubscription",
    "datazone:ListSubscriptionRequests",
    "mission.scope",
];
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-datazone-subscription-result/contract.v1.json");

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsDataZoneSubscriptionResultContract {
    value: serde_json::Value,
}

impl AwsDataZoneSubscriptionResultContract {
    pub fn baseline() -> Result<Self> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|_| AwsDataZoneSubscriptionResultError::ContractDrift)?;
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
            .ok_or(AwsDataZoneSubscriptionResultError::ContractDrift)?;
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
            "evidence",
            "provenance",
            "authorityBoundary",
            "forbiddenEffects",
            "layer2Gaps",
            "honestNativeGap",
        ] {
            if !object.contains_key(key) {
                return Err(AwsDataZoneSubscriptionResultError::ContractDrift);
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
            return Err(AwsDataZoneSubscriptionResultError::ContractDrift);
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsDataZoneSubscriptionResultError::ContractDrift)?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsDataZoneSubscriptionResultError::ContractDrift);
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsDataZoneSubscriptionResultError::ContractDrift)?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(PROVIDER_API_REVISION)
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsDataZoneSubscriptionResultError::ContractDrift);
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsDataZoneSubscriptionResultError::ContractDrift)?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsDataZoneSubscriptionResultError::ContractDrift);
        }
        let projection = object
            .get("projection")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsDataZoneSubscriptionResultError::ContractDrift)?;
        for key in [
            "rawSchemas",
            "rawMetadataForms",
            "principals",
            "dataAccess",
            "subscriptionGrantEffects",
        ] {
            if projection.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(AwsDataZoneSubscriptionResultError::ContractDrift);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract = AwsDataZoneSubscriptionResultContract::baseline().expect("contract");
        assert_eq!(contract.digest().as_str(), CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert!(!contract.value()["provider"]["connected"].as_bool().unwrap());
        assert!(!contract.value()["provider"]["native"].as_bool().unwrap());
        assert!(
            !contract.value()["provider"]["firstParty"]
                .as_bool()
                .unwrap()
        );
    }
}
