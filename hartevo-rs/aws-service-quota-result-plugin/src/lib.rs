//! Standalone Layer-1 governed AWS Service Quotas posture result slice.
//!
//! The crate exposes typed scope, opaque-secret registration, bounded
//! allowlisted read seams, digest-only quota posture, proposal/record/verify
//! paths, and a Mission decision proposal. It deliberately does not resolve
//! credentials, execute native SigV4, perform live HTTPS, request quota
//! increases, mutate quota templates/support cases, retain usage series, claim
//! capacity/infrastructure guarantees, or adopt Hartevo kernel authority.

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

use serde_json::Value;
use thiserror::Error;

pub use consumer::{
    ConsumerError, MissionAwsServiceQuotaConsumer, MissionAwsServiceQuotaConsumerError,
    MissionAwsServiceQuotaDecision, MissionAwsServiceQuotaDecisionState,
    MissionAwsServiceQuotaResult, MissionAwsServiceQuotaResultConsumer,
};
pub use model::*;
pub use provider::{
    AwsServiceQuotaProvider, AwsServiceQuotaProviderError, AwsServiceQuotaProviderIdentity,
    AwsServiceQuotaTransport, BlockedEnvAwsServiceQuotaTransport, BlockedEnvTransport,
    FakeAwsServiceQuotaTransport, FixtureAwsServiceQuotaTransport, FixtureTransport,
    LoopbackAwsServiceQuotaTransport, LoopbackTransport, ProviderDefinitionError,
    ProviderProvenance, RecordingAwsServiceQuotaTransport, RecordingTransport, is_access_loss,
};
pub use service::{
    AwsServiceQuotaCapabilities, AwsServiceQuotaEvidence, AwsServiceQuotaProposal,
    AwsServiceQuotaReadResult, AwsServiceQuotaRecordReceipt, AwsServiceQuotaRegistration,
    AwsServiceQuotaResultService, AwsServiceQuotaService, AwsServiceQuotaServiceError,
    AwsServiceQuotaServiceErrorAlias, AwsServiceQuotaServiceResult, AwsServiceQuotaVerifiedRecord,
    RegistrationError, RegistrationState, evidence_binding_digest, service_digest,
};

pub const AWS_SERVICE_QUOTA_SCHEMA_VERSION: &str = "hartevo.aws-service-quota-result.contract/v1";
pub const AWS_SERVICE_QUOTA_CONTRACT_VERSION: &str = "aws-service-quota-result/v1";
pub const AWS_SERVICE_QUOTA_PLUGIN_VERSION: &str = "1.0.0";
pub const AWS_SERVICE_QUOTA_SERVICE_ID: &str = "hartevo.aws.service-quota.result";
pub const AWS_SERVICE_QUOTA_PROVIDER_ID: &str = "aws.servicequotas";
pub const AWS_SERVICE_QUOTA_PROVIDER_VERSION: &str = "1.0.0";
pub const AWS_SERVICE_QUOTA_API_REVISION: &str = "aws-service-quotas-read-r1";
pub const AWS_SERVICE_QUOTA_API_VERSION: &str = "2019-06-24";
pub const AWS_SERVICE_QUOTA_CONSUMER_ID: &str = "mission.aws.service-quota.result";
pub const AWS_SERVICE_QUOTA_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AWS_SERVICE_QUOTA_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-service-quota-result/aws-service-quota-result.v1.json"
);

pub fn contract_digest() -> Digest {
    model::sha256_digest(AWS_SERVICE_QUOTA_CONTRACT_JSON.as_bytes())
}

pub const fn plugin_version() -> (u16, u16, u16) {
    (1, 0, 0)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsServiceQuotaContract {
    value: Value,
}

impl AwsServiceQuotaContract {
    pub fn baseline() -> Result<Self, AwsServiceQuotaContractError> {
        let value = serde_json::from_str::<Value>(AWS_SERVICE_QUOTA_CONTRACT_JSON)
            .map_err(|error| AwsServiceQuotaContractError::InvalidJson(error.to_string()))?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<(), AwsServiceQuotaContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(AwsServiceQuotaContractError::Shape(
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
            "pagination",
            "evidence",
            "redaction",
            "authority",
            "honesty",
            "layer2Gaps",
            "forbidden",
        ] {
            if !object.contains_key(key) {
                return Err(AwsServiceQuotaContractError::Shape(
                    "required contract key missing",
                ));
            }
        }
        if object.get("schemaVersion").and_then(Value::as_str)
            != Some(AWS_SERVICE_QUOTA_SCHEMA_VERSION)
            || object.get("contractVersion").and_then(Value::as_str)
                != Some(AWS_SERVICE_QUOTA_CONTRACT_VERSION)
            || object.get("pluginVersion").and_then(Value::as_str)
                != Some(AWS_SERVICE_QUOTA_PLUGIN_VERSION)
            || object.get("layer").and_then(Value::as_str) != Some("Layer-1")
        {
            return Err(AwsServiceQuotaContractError::Identity(
                "contract identity drifted",
            ));
        }
        let service = object.get("service").and_then(Value::as_object).ok_or(
            AwsServiceQuotaContractError::Shape("service is not an object"),
        )?;
        if service.get("id").and_then(Value::as_str) != Some(AWS_SERVICE_QUOTA_SERVICE_ID)
            || service.get("implementation").and_then(Value::as_str)
                != Some("AwsServiceQuotaService")
            || service.get("readOnly") != Some(&Value::Bool(true))
            || service.get("proposalOnly") != Some(&Value::Bool(true))
            || service.get("recordingOnly") != Some(&Value::Bool(true))
            || service.get("liveExecution") != Some(&Value::Bool(false))
            || service.get("externalWrites") != Some(&Value::Bool(false))
        {
            return Err(AwsServiceQuotaContractError::Identity(
                "service identity or authority drifted",
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
        let service_operations = service.get("operations").and_then(Value::as_array).ok_or(
            AwsServiceQuotaContractError::Shape("service operations missing"),
        )?;
        if service_operations.len() != expected_service_operations.len()
            || service_operations
                .iter()
                .zip(expected_service_operations)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err(AwsServiceQuotaContractError::Identity(
                "service operation allowlist drifted",
            ));
        }
        let provider = object.get("provider").and_then(Value::as_object).ok_or(
            AwsServiceQuotaContractError::Shape("provider is not an object"),
        )?;
        let expected_provider_operations = [
            "ListServiceQuotas",
            "GetServiceQuota",
            "GetAWSDefaultServiceQuota",
            "ListRequestedServiceQuotaChangeHistoryByQuota",
        ];
        let provider_operations = provider
            .get("allowlistedOperations")
            .and_then(Value::as_array)
            .ok_or(AwsServiceQuotaContractError::Shape(
                "provider operation allowlist missing",
            ))?;
        if provider.get("id").and_then(Value::as_str) != Some(AWS_SERVICE_QUOTA_PROVIDER_ID)
            || provider.get("implementation").and_then(Value::as_str)
                != Some("AwsServiceQuotaProvider")
            || provider.get("version").and_then(Value::as_str)
                != Some(AWS_SERVICE_QUOTA_PROVIDER_VERSION)
            || provider.get("apiRevision").and_then(Value::as_str)
                != Some(AWS_SERVICE_QUOTA_API_REVISION)
            || provider.get("apiVersion").and_then(Value::as_str)
                != Some(AWS_SERVICE_QUOTA_API_VERSION)
            || provider.get("native") != Some(&Value::Bool(false))
            || provider.get("connected") != Some(&Value::Bool(false))
            || provider.get("firstParty") != Some(&Value::Bool(false))
            || provider.get("externalWrites") != Some(&Value::Bool(false))
            || provider.get("providerReceipt") != Some(&Value::Bool(false))
            || provider_operations.len() != expected_provider_operations.len()
            || provider_operations
                .iter()
                .zip(expected_provider_operations)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err(AwsServiceQuotaContractError::Identity(
                "provider identity or allowlist drifted",
            ));
        }
        let consumer = object.get("consumer").and_then(Value::as_object).ok_or(
            AwsServiceQuotaContractError::Shape("consumer is not an object"),
        )?;
        if consumer.get("id").and_then(Value::as_str) != Some(AWS_SERVICE_QUOTA_CONSUMER_ID)
            || consumer.get("implementation").and_then(Value::as_str)
                != Some("MissionAwsServiceQuotaConsumer")
            || consumer.get("adoptsOutcome") != Some(&Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&Value::Bool(false))
        {
            return Err(AwsServiceQuotaContractError::Identity(
                "consumer authority drifted",
            ));
        }
        let authority = object.get("authority").and_then(Value::as_object).ok_or(
            AwsServiceQuotaContractError::Shape("authority is not an object"),
        )?;
        for key in [
            "externalWrites",
            "quotaIncrease",
            "quotaTemplateMutation",
            "supportCaseMutation",
            "quotaUtilizationReportStart",
            "autoscaling",
            "infrastructureMutation",
            "financialGuarantee",
            "infrastructureGuarantee",
            "credentialResolution",
            "connected",
            "native",
            "firstParty",
            "durableReceipt",
            "verificationAuthority",
            "kernelOutcomeAdoption",
            "truthAuthority",
        ] {
            if authority.get(key) != Some(&Value::Bool(false)) {
                return Err(AwsServiceQuotaContractError::Boundary(
                    "Layer-1 authority widened",
                ));
            }
        }
        let forbidden = object.get("forbidden").and_then(Value::as_array).ok_or(
            AwsServiceQuotaContractError::Shape("forbidden list missing"),
        )?;
        for required in [
            "RequestServiceQuotaIncrease",
            "PutServiceQuotaIncreaseRequestIntoTemplate",
            "StartQuotaUtilizationReport",
            "CreateSupportCase",
            "retain_raw_usage_series",
            "claim_connected",
            "claim_native",
            "claim_capacity_guarantee",
            "claim_infrastructure_guarantee",
            "adopt_kernel_outcome",
        ] {
            if !forbidden
                .iter()
                .any(|entry| entry.as_str() == Some(required))
            {
                return Err(AwsServiceQuotaContractError::Boundary(
                    "forbidden operation or claim missing",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsServiceQuotaContractError {
    #[error("AWS Service Quotas contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("AWS Service Quotas contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("AWS Service Quotas contract identity is invalid: {0}")]
    Identity(&'static str),
    #[error("AWS Service Quotas contract authority boundary is invalid: {0}")]
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

    pub const fn durable_provider_receipt() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }

    pub const fn capacity_guarantee() -> bool {
        false
    }

    pub const fn infrastructure_guarantee() -> bool {
        false
    }

    pub const fn financial_guarantee() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_in_contract_matches_typed_boundary() {
        let contract = AwsServiceQuotaContract::baseline().expect("contract");
        assert_eq!(contract.digest(), contract_digest());
        assert_eq!(plugin_version(), (1, 0, 0));
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::capacity_guarantee());
    }
}
