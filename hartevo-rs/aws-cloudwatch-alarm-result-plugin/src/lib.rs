//! Standalone Layer-1 governed AWS CloudWatch alarm result slice.
//!
//! The crate provides typed exact scope, opaque SigV4 references, reversible
//! registration, bounded CloudWatch read seams, redacted evidence receipts,
//! proposal/record/verify, and a Mission-facing consumer. It deliberately
//! does not resolve credentials, sign native requests, claim connected/native/
//! first-party evidence, mutate AWS, retrieve logs, retain raw dimensions or
//! datapoints, certify production SLOs, or adopt Hartevo Outcome authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
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
pub mod model;
pub mod provider;
pub mod service;

use thiserror::Error;

pub use consumer::{ConsumerError, MissionAwsCloudWatchConsumer, MissionAwsCloudWatchResult};
pub use model::*;
pub use provider::{
    AwsCloudWatchOperationError, AwsCloudWatchProvider, AwsCloudWatchProviderDefinition,
    AwsCloudWatchProviderError, AwsCloudWatchProviderIdentity, AwsCloudWatchTransport,
    AwsCloudWatchTransportError, BlockedEnvAwsCloudWatchTransport, BlockedEnvTransport,
    DescribeAlarmsRequest, DescribeAlarmsResponse, FixtureAwsCloudWatchTransport, FixtureTransport,
    GetMetricDataRequest, GetMetricDataResponse, ListMetricsRequest, ListMetricsResponse,
    LoopbackAwsCloudWatchTransport, LoopbackTransport, ProviderError, RecordedRequest,
    RecordingAwsCloudWatchTransport, RecordingTransport, TransportError,
};
pub use service::{
    AwsCloudWatchAlarmProposal, AwsCloudWatchAlarmRecordReceipt, AwsCloudWatchAlarmRegistration,
    AwsCloudWatchAlarmService, AwsCloudWatchAlarmServiceError, AwsCloudWatchAlarmVerifiedRecord,
    AwsCloudWatchCapabilities, AwsCloudWatchReadResult, RegistrationError, RegistrationState,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-cloudwatch-alarm-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-CLOUDWATCH-ALARM-01-L1/v1";
pub const PLUGIN_ID: &str = "aws.cloudwatch.alarm-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.cloudwatch.alarm-result.read";
pub const PROVIDER_ID: &str = "aws.cloudwatch.alarm-result.recording";
pub const PROVIDER_API_REVISION: &str = "cloudwatch-describe-alarms-get-metric-data-list-metrics-1";
pub const API_REVISION: &str = PROVIDER_API_REVISION;
pub const CONSUMER_ID: &str = "mission.aws-cloudwatch-alarm.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-cloudwatch-alarm-result/contract.v1.json");

pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_PAGES: u16 = 4;
pub const MAX_REQUESTS_PER_READ: u16 = 8;
pub const MAX_RETRIES: u8 = 2;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_WINDOW_SECONDS: i64 = 86_400;
pub const MAX_DATAPOINTS: usize = 1_000;
pub const MAX_METRIC_RESULTS: usize = 8;
pub const MAX_RECEIPTS: usize = 8;
pub const MAX_PROVIDER_ERRORS: usize = 8;
pub const MAX_IDENTIFIER_BYTES: usize = 255;

pub fn contract_digest() -> Digest {
    model::sha256_digest(CONTRACT_JSON.as_bytes())
}

pub const fn plugin_version() -> (u16, u16, u16) {
    (1, 0, 0)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsCloudWatchAlarmContract {
    value: serde_json::Value,
}

impl AwsCloudWatchAlarmContract {
    pub fn baseline() -> Result<Self, AwsCloudWatchContractError> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|error| AwsCloudWatchContractError::InvalidJson(error.to_string()))?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<(), AwsCloudWatchContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(AwsCloudWatchContractError::Shape(
                "contract is not an object",
            ))?;
        for key in [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginId",
            "pluginVersion",
            "layer",
            "service",
            "provider",
            "consumer",
            "credentials",
            "scope",
            "registration",
            "bounds",
            "evidence",
            "redaction",
            "authorityBoundary",
            "provenance",
            "layer2Gaps",
            "forbidden",
        ] {
            if !object.contains_key(key) {
                return Err(AwsCloudWatchContractError::Shape(
                    "required contract key missing",
                ));
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
            || object.get("pluginId").and_then(serde_json::Value::as_str) != Some(PLUGIN_ID)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(PLUGIN_VERSION)
            || object.get("layer") != Some(&serde_json::Value::from(1_u8))
        {
            return Err(AwsCloudWatchContractError::Identity(
                "contract identity drifted",
            ));
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCloudWatchContractError::Shape(
                "service is not an object",
            ))?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("type").and_then(serde_json::Value::as_str)
                != Some("AwsCloudWatchAlarmService")
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("recordingOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || service.get("kernelAuthority") != Some(&serde_json::Value::Bool(false))
            || service.get("outcomeAdoption") != Some(&serde_json::Value::Bool(false))
            || service.get("productionSloCertification") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsCloudWatchContractError::Authority(
                "service authority drifted",
            ));
        }
        let expected_service_operations = [
            "describe_capabilities",
            "register",
            "revoke_registration",
            "reverse_registration",
            "restore_registration",
            "read_bounded",
            "propose",
            "record",
            "verify",
        ];
        if !array_matches(service.get("operations"), &expected_service_operations) {
            return Err(AwsCloudWatchContractError::Identity(
                "service operations drifted",
            ));
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCloudWatchContractError::Shape(
                "provider is not an object",
            ))?;
        let expected_provider_operations = ["DescribeAlarms", "GetMetricData", "ListMetrics"];
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider.get("type").and_then(serde_json::Value::as_str)
                != Some("AwsCloudWatchProvider")
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(PROVIDER_API_REVISION)
            || !array_matches(
                provider.get("allowlistedOperations"),
                &expected_provider_operations,
            )
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || provider.get("providerReceipt") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsCloudWatchContractError::Authority(
                "provider allowlist or provenance drifted",
            ));
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCloudWatchContractError::Shape(
                "consumer is not an object",
            ))?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("type").and_then(serde_json::Value::as_str)
                != Some("MissionAwsCloudWatchConsumer")
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
            || consumer.get("certificationAuthority") != Some(&serde_json::Value::Bool(false))
            || consumer.get("productionSloCertification") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsCloudWatchContractError::Authority(
                "consumer authority drifted",
            ));
        }
        let credentials = object
            .get("credentials")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCloudWatchContractError::Shape(
                "credentials is not an object",
            ))?;
        for key in ["serialized", "rawMaterialAccepted"] {
            if credentials.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(AwsCloudWatchContractError::Authority(
                    "credential boundary widened",
                ));
            }
        }
        let provenance = object
            .get("provenance")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCloudWatchContractError::Shape(
                "provenance is not an object",
            ))?;
        for key in [
            "connectedClaim",
            "nativeClaim",
            "firstPartyClaim",
            "providerReceipt",
            "blockedEnvironmentIsNative",
        ] {
            if provenance.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(AwsCloudWatchContractError::Authority(
                    "provenance claim widened",
                ));
            }
        }
        let forbidden = object
            .get("forbidden")
            .and_then(serde_json::Value::as_array)
            .ok_or(AwsCloudWatchContractError::Shape("forbidden list missing"))?;
        for required in [
            "PutMetricData",
            "alarm_create_update_delete",
            "alarm_action_execution",
            "dashboard_mutation",
            "log_retrieval",
            "arbitrary_metric_scan",
            "claim_production_slo",
            "claim_outcome_certification",
            "adopt_kernel_outcome",
        ] {
            if !forbidden
                .iter()
                .any(|entry| entry.as_str() == Some(required))
            {
                return Err(AwsCloudWatchContractError::Boundary(
                    "forbidden operation missing",
                ));
            }
        }
        Ok(())
    }
}

fn array_matches(value: Option<&serde_json::Value>, expected: &[&str]) -> bool {
    let Some(values) = value.and_then(serde_json::Value::as_array) else {
        return false;
    };
    values.len() == expected.len()
        && values
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual.as_str() == Some(*expected))
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsCloudWatchContractError {
    #[error("AWS CloudWatch contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("AWS CloudWatch contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("AWS CloudWatch contract identity is invalid: {0}")]
    Identity(&'static str),
    #[error("AWS CloudWatch contract authority boundary is invalid: {0}")]
    Authority(&'static str),
    #[error("AWS CloudWatch contract forbidden boundary is invalid: {0}")]
    Boundary(&'static str),
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

    pub const fn provider_receipt() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }

    pub const fn production_slo_certification() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_in_contract_matches_typed_boundary() {
        let contract = AwsCloudWatchAlarmContract::baseline().expect("contract");
        assert_eq!(contract.digest(), contract_digest());
        assert_eq!(plugin_version(), (1, 0, 0));
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::provider_receipt());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::production_slo_certification());
    }
}
