//! Standalone Layer-1 governed AWS Route 53 health-check result slice.
//!
//! This crate provides typed scope, reversible registration, bounded Route 53
//! health reads, redacted evidence, a review-only Mission proposal, recording,
//! and verification. It deliberately does not resolve credentials, perform
//! native SigV4/HTTPS, mutate Route 53, export raw endpoint data, certify
//! uptime, or adopt Hartevo kernel Truth/Consent/Effect/Receipt/Verification/
//! Outcome/Work Product authority.

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
    clippy::single_match_else,
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

pub use consumer::{
    ConsumerError, MissionAwsRoute53Consumer, MissionAwsRoute53DecisionState,
    MissionAwsRoute53HealthConsumer, MissionAwsRoute53HealthResult, MissionAwsRoute53Result,
};
pub use model::*;
pub use provider::{
    AwsRoute53HealthProvider, AwsRoute53HealthProviderDefinition, AwsRoute53HealthProviderIdentity,
    AwsRoute53HealthTransport, AwsRoute53Provider, AwsRoute53ProviderDefinition,
    AwsRoute53ProviderIdentity, BlockedEnvAwsRoute53Transport, BlockedEnvTransport,
    FakeAwsRoute53Transport, FixtureAwsRoute53Transport, FixtureTransport, GetHealthCheckRequest,
    GetHealthCheckStatusRequest, ListHealthChecksRequest, LoopbackAwsRoute53Transport,
    LoopbackTransport, ProviderDefinitionError, ProviderError, ProviderProvenance,
    RecordingAwsRoute53Transport, RecordingTransport, TransportCall, TransportError,
    TransportFailure, is_access_loss, is_throttle, is_timeout,
};
pub use service::{
    AwsRoute53HealthCapabilities, AwsRoute53HealthProposal, AwsRoute53HealthRecordReceipt,
    AwsRoute53HealthRegistration, AwsRoute53HealthService, AwsRoute53HealthServiceError,
    AwsRoute53HealthVerifiedRecord, AwsRoute53Proposal, AwsRoute53ReadResult, RegistrationError,
    RegistrationState, RevocationEvidence,
};

pub const AWS_ROUTE53_HEALTH_SCHEMA_VERSION: &str = "hartevo.aws-route53-health-result.contract/v1";
pub const AWS_ROUTE53_HEALTH_CONTRACT_VERSION: &str = "aws-route53-health-result/v1";
pub const AWS_ROUTE53_HEALTH_PLUGIN_VERSION: &str = "1.0.0";
pub const AWS_ROUTE53_HEALTH_SERVICE_ID: &str = "hartevo.aws.route53.health-result";
pub const AWS_ROUTE53_HEALTH_PROVIDER_ID: &str = "aws.route53.health";
pub const AWS_ROUTE53_HEALTH_PROVIDER_VERSION: &str = "1.0.0";
pub const AWS_ROUTE53_HEALTH_API_REVISION: &str = "aws-route53-health-read-r1";
pub const AWS_ROUTE53_HEALTH_CONSUMER_ID: &str = "mission.aws.route53.health-result";
pub const AWS_ROUTE53_HEALTH_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AWS_ROUTE53_HEALTH_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-route53-health-result/aws-route53-health-result.v1.json"
);

pub const CONTRACT_SCHEMA: &str = AWS_ROUTE53_HEALTH_SCHEMA_VERSION;
pub const CONTRACT_VERSION: &str = AWS_ROUTE53_HEALTH_CONTRACT_VERSION;
pub const PLUGIN_VERSION: &str = AWS_ROUTE53_HEALTH_PLUGIN_VERSION;
pub const SERVICE_ID: &str = AWS_ROUTE53_HEALTH_SERVICE_ID;
pub const PROVIDER_ID: &str = AWS_ROUTE53_HEALTH_PROVIDER_ID;
pub const CONSUMER_ID: &str = AWS_ROUTE53_HEALTH_CONSUMER_ID;
pub const CONTRACT_JSON: &str = AWS_ROUTE53_HEALTH_CONTRACT_JSON;

pub fn contract_digest() -> Digest {
    model::sha256_digest(AWS_ROUTE53_HEALTH_CONTRACT_JSON.as_bytes())
}

pub const fn plugin_version() -> (u16, u16, u16) {
    (1, 0, 0)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsRoute53HealthContract {
    value: serde_json::Value,
}

impl AwsRoute53HealthContract {
    pub fn baseline() -> Result<Self, AwsRoute53HealthContractError> {
        let value = serde_json::from_str::<serde_json::Value>(AWS_ROUTE53_HEALTH_CONTRACT_JSON)
            .map_err(|error| AwsRoute53HealthContractError::InvalidJson(error.to_string()))?;
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

    pub fn validate(&self) -> Result<(), AwsRoute53HealthContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(AwsRoute53HealthContractError::Shape(
                "contract is not an object",
            ))?;
        for key in [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "layer",
            "service",
            "provider",
            "consumer",
            "scope",
            "registration",
            "bounds",
            "evidence",
            "redaction",
            "authority",
            "honesty",
            "layer2Gaps",
            "forbidden",
        ] {
            if !object.contains_key(key) {
                return Err(AwsRoute53HealthContractError::Shape(
                    "required contract key missing",
                ));
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(AWS_ROUTE53_HEALTH_SCHEMA_VERSION)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_ROUTE53_HEALTH_CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_ROUTE53_HEALTH_PLUGIN_VERSION)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
        {
            return Err(AwsRoute53HealthContractError::Identity(
                "contract identity drifted",
            ));
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsRoute53HealthContractError::Shape(
                "service is not an object",
            ))?;
        if service.get("id").and_then(serde_json::Value::as_str)
            != Some(AWS_ROUTE53_HEALTH_SERVICE_ID)
            || service
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AwsRoute53HealthService")
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsRoute53HealthContractError::Identity(
                "service identity drifted",
            ));
        }
        let operations = service
            .get("operations")
            .and_then(serde_json::Value::as_array)
            .ok_or(AwsRoute53HealthContractError::Shape(
                "service operation list missing",
            ))?;
        let expected_service_operations = [
            "describe_capabilities",
            "register",
            "revoke_registration",
            "read_bounded",
            "propose",
            "record",
            "verify",
        ];
        if operations.len() != expected_service_operations.len()
            || operations
                .iter()
                .zip(expected_service_operations)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err(AwsRoute53HealthContractError::Identity(
                "service operation list drifted",
            ));
        }
        let operations = service
            .get("readOperations")
            .and_then(serde_json::Value::as_array)
            .ok_or(AwsRoute53HealthContractError::Shape(
                "Route 53 read operation list missing",
            ))?;
        let expected_operations = ["ListHealthChecks", "GetHealthCheck", "GetHealthCheckStatus"];
        if operations.len() != expected_operations.len()
            || operations
                .iter()
                .zip(expected_operations)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err(AwsRoute53HealthContractError::Identity(
                "Route 53 read operation list drifted",
            ));
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsRoute53HealthContractError::Shape(
                "provider is not an object",
            ))?;
        if provider.get("id").and_then(serde_json::Value::as_str)
            != Some(AWS_ROUTE53_HEALTH_PROVIDER_ID)
            || provider
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AwsRoute53Provider")
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsRoute53HealthContractError::Identity(
                "provider identity drifted",
            ));
        }
        let allowlisted = provider
            .get("allowlistedOperations")
            .and_then(serde_json::Value::as_array)
            .ok_or(AwsRoute53HealthContractError::Shape(
                "provider operation allowlist missing",
            ))?;
        if allowlisted
            != &[
                serde_json::Value::String("ListHealthChecks".to_owned()),
                serde_json::Value::String("GetHealthCheck".to_owned()),
                serde_json::Value::String("GetHealthCheckStatus".to_owned()),
            ]
        {
            return Err(AwsRoute53HealthContractError::Identity(
                "provider operation allowlist drifted",
            ));
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsRoute53HealthContractError::Shape(
                "consumer is not an object",
            ))?;
        if consumer.get("id").and_then(serde_json::Value::as_str)
            != Some(AWS_ROUTE53_HEALTH_CONSUMER_ID)
            || consumer
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("MissionAwsRoute53Consumer")
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
            || consumer.get("certificationAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsRoute53HealthContractError::Identity(
                "consumer identity drifted",
            ));
        }
        let authority = object
            .get("authority")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsRoute53HealthContractError::Shape(
                "authority is not an object",
            ))?;
        for key in [
            "externalWrites",
            "healthCheckMutation",
            "calculatedCheckMutation",
            "dnsRecordMutation",
            "failoverMutation",
            "credentialResolution",
            "rawResponseRead",
            "certification",
            "connected",
            "native",
            "firstParty",
            "durableReceipt",
            "verification",
            "kernelTruth",
            "kernelConsent",
            "kernelEffect",
            "kernelOutcome",
            "workProductAdoption",
        ] {
            if authority.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(AwsRoute53HealthContractError::Boundary(
                    "Layer-1 authority widened",
                ));
            }
        }
        let forbidden = object
            .get("forbidden")
            .and_then(serde_json::Value::as_array)
            .ok_or(AwsRoute53HealthContractError::Shape(
                "forbidden list missing",
            ))?;
        for required in [
            "create_health_check",
            "update_health_check",
            "delete_health_check",
            "mutate_calculated_health_check",
            "change_dns_record",
            "change_failover_policy",
            "read_or_export_raw_ip_address",
            "read_or_export_raw_endpoint",
            "serialize_secret_material",
            "resolve_live_credentials",
            "claim_connected",
            "claim_native",
            "claim_first_party",
            "claim_uptime_certification",
            "adopt_kernel_truth_consent_effect_receipt_verification_or_outcome",
            "adopt_work_product",
        ] {
            if !forbidden
                .iter()
                .any(|entry| entry.as_str() == Some(required))
            {
                return Err(AwsRoute53HealthContractError::Boundary(
                    "forbidden operation missing",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsRoute53HealthContractError {
    #[error("AWS Route 53 health contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("AWS Route 53 health contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("AWS Route 53 health contract identity is invalid: {0}")]
    Identity(&'static str),
    #[error("AWS Route 53 health contract authority boundary is invalid: {0}")]
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

    pub const fn durable_receipt() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }

    pub const fn work_product_adoption() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_in_contract_matches_typed_boundary() {
        let contract = AwsRoute53HealthContract::baseline().expect("contract");
        assert_eq!(contract.digest(), contract_digest());
        assert_eq!(plugin_version(), (1, 0, 0));
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::work_product_adoption());
    }
}
