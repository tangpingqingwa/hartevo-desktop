//! Standalone Layer-1 governed AWS API Gateway deployment result plugin.
//!
//! This crate supplies typed exact scope, reversible registration, bounded
//! GetStage/GetDeployment/GetDeployments evidence, proposal/record/verify
//! envelopes, and a Mission consumer.  It deliberately does not resolve live
//! credentials, sign native SigV4 requests, invoke an API, mutate a stage or
//! deployment, certify availability, or adopt kernel Truth/Consent/Effect/
//! Receipt/Verification/Outcome authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
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

pub use consumer::{
    ConsumerError, MissionAwsApiGatewayConsumer, MissionAwsApiGatewayConsumerError,
    MissionAwsApiGatewayDecision, MissionAwsApiGatewayDecisionState, MissionAwsApiGatewayResult,
};
pub use model::*;
pub use provider::{
    AwsApiGatewayDeploymentPage, AwsApiGatewayDeploymentRequest, AwsApiGatewayDeploymentResponse,
    AwsApiGatewayDeploymentsPage, AwsApiGatewayDeploymentsRequest,
    AwsApiGatewayListDeploymentsPage, AwsApiGatewayProvider, AwsApiGatewayProviderDefinition,
    AwsApiGatewayProviderError, AwsApiGatewayProviderIdentity, AwsApiGatewayStagePage,
    AwsApiGatewayStageRequest, AwsApiGatewayStageResponse, AwsApiGatewayTransport,
    BlockedEnvAwsApiGatewayTransport, BlockedEnvTransport, FakeAwsApiGatewayTransport,
    FixtureAwsApiGatewayTransport, GetDeploymentRequest, GetDeploymentsRequest, GetStageRequest,
    LoopbackAwsApiGatewayTransport, LoopbackTransport, ProviderDefinitionError, ProviderError,
    RecordedRequest, RecordingAwsApiGatewayTransport, TransportError, is_access_loss,
};
pub use service::{
    AwsApiGatewayProposal, AwsApiGatewayReadRequest, AwsApiGatewayReadResult,
    AwsApiGatewayRecordReceipt, AwsApiGatewayRegistration, AwsApiGatewayResultService,
    AwsApiGatewayService, AwsApiGatewayServiceError, AwsApiGatewayVerifiedRecord,
    ContractDocumentError, RegistrationError, RegistrationState,
};

pub const AWS_API_GATEWAY_SCHEMA_VERSION: &str = "hartevo.aws-api-gateway-result.contract/v1";
pub const AWS_API_GATEWAY_CONTRACT_VERSION: &str = "aws-api-gateway-result/v1";
pub const AWS_API_GATEWAY_PLUGIN_VERSION: &str = "1.0.0";
pub const AWS_API_GATEWAY_SERVICE_ID: &str = "hartevo.aws.api-gateway.deployment-result";
pub const AWS_API_GATEWAY_PROVIDER_ID: &str = "aws.api-gateway";
pub const AWS_API_GATEWAY_PROVIDER_VERSION: &str = "aws-api-gateway-provider/v1";
pub const AWS_API_GATEWAY_API_REVISION: &str = "aws-apigateway-read-r1";
pub const AWS_API_GATEWAY_API_VERSION_REST: &str = "2015-07-09";
pub const AWS_API_GATEWAY_API_VERSION_HTTP: &str = "2018-11-29";
pub const AWS_API_GATEWAY_CONSUMER_ID: &str = "mission.aws.api-gateway.deployment-result";
pub const AWS_API_GATEWAY_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AWS_API_GATEWAY_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-api-gateway-result/aws-api-gateway-result.v1.json"
);

pub fn contract_digest() -> Digest {
    model::sha256_digest(AWS_API_GATEWAY_CONTRACT_JSON.as_bytes())
}

pub const fn plugin_version() -> (u16, u16, u16) {
    (1, 0, 0)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsApiGatewayContract {
    value: serde_json::Value,
}

impl AwsApiGatewayContract {
    pub fn baseline() -> Result<Self, ContractDocumentError> {
        let value = serde_json::from_str::<serde_json::Value>(AWS_API_GATEWAY_CONTRACT_JSON)
            .map_err(|_| ContractDocumentError::InvalidJson)?;
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

    pub fn validate(&self) -> Result<(), ContractDocumentError> {
        let object = self
            .value
            .as_object()
            .ok_or(ContractDocumentError::InvalidShape)?;
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
                return Err(ContractDocumentError::InvalidShape);
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(AWS_API_GATEWAY_SCHEMA_VERSION)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_API_GATEWAY_CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_API_GATEWAY_PLUGIN_VERSION)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
        {
            return Err(ContractDocumentError::IdentityDrift);
        }

        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::InvalidShape)?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(AWS_API_GATEWAY_SERVICE_ID)
            || service
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AwsApiGatewayService")
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractDocumentError::IdentityDrift);
        }
        let expected_operations = [
            "describe_capabilities",
            "register",
            "revoke_registration",
            "read_get_stage",
            "read_get_deployment",
            "read_get_deployments",
            "propose",
            "record",
            "verify",
        ];
        let operations = service
            .get("operations")
            .and_then(serde_json::Value::as_array)
            .ok_or(ContractDocumentError::InvalidShape)?;
        if operations.len() != expected_operations.len()
            || operations
                .iter()
                .zip(expected_operations)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err(ContractDocumentError::IdentityDrift);
        }

        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::InvalidShape)?;
        let allowed_operations = provider
            .get("allowlistedOperations")
            .and_then(serde_json::Value::as_array)
            .ok_or(ContractDocumentError::InvalidShape)?;
        if provider.get("id").and_then(serde_json::Value::as_str)
            != Some(AWS_API_GATEWAY_PROVIDER_ID)
            || provider
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AwsApiGatewayProvider")
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || allowed_operations
                != &[
                    serde_json::Value::String("GetStage".to_owned()),
                    serde_json::Value::String("GetDeployment".to_owned()),
                    serde_json::Value::String("GetDeployments".to_owned()),
                ]
        {
            return Err(ContractDocumentError::IdentityDrift);
        }

        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::InvalidShape)?;
        if consumer.get("id").and_then(serde_json::Value::as_str)
            != Some(AWS_API_GATEWAY_CONSUMER_ID)
            || consumer
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("MissionAwsApiGatewayConsumer")
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
            || consumer.get("certificationAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractDocumentError::IdentityDrift);
        }

        let scope = object
            .get("scope")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::InvalidShape)?;
        let required_scope = scope
            .get("required")
            .and_then(serde_json::Value::as_array)
            .ok_or(ContractDocumentError::InvalidShape)?;
        for required in [
            "account_id",
            "region",
            "rest_or_http_api_kind",
            "api_id_and_revision",
            "stage_name_and_revision",
            "api_deployment_id_and_revision",
            "commit_or_configuration_digest",
            "project_id_and_revision",
            "mission_id_and_revision",
            "work_product_id_and_revision",
            "deployment_id_and_revision",
            "permission_digest",
            "secret_reference_digest",
            "scope_digest",
        ] {
            if !required_scope
                .iter()
                .any(|value| value.as_str() == Some(required))
            {
                return Err(ContractDocumentError::IdentityDrift);
            }
        }

        let authority = object
            .get("authority")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::InvalidShape)?;
        for key in [
            "externalWrites",
            "createStage",
            "updateStage",
            "deleteStage",
            "createDeployment",
            "updateDeployment",
            "deleteDeployment",
            "routeMutation",
            "integrationMutation",
            "apiInvocation",
            "credentialResolution",
            "availabilityCertification",
            "connected",
            "native",
            "firstParty",
            "durableReceipt",
            "verificationAuthority",
            "kernelTruthAuthority",
            "consentAuthority",
            "effectAuthority",
            "outcomeAdoption",
        ] {
            if authority.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(ContractDocumentError::AuthorityEscalation);
            }
        }

        let honesty = object
            .get("honesty")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::InvalidShape)?;
        for key in [
            "blockedEnvironmentIsNative",
            "fixtureIsNative",
            "recordingIsNative",
            "loopbackIsNative",
            "connectedClaims",
            "firstPartyClaims",
            "metadataIsAvailabilityCertification",
        ] {
            if honesty.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(ContractDocumentError::AuthorityEscalation);
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

    pub const fn durable_receipt() -> bool {
        false
    }

    pub const fn truth_authority() -> bool {
        false
    }

    pub const fn consent_authority() -> bool {
        false
    }

    pub const fn effect_authority() -> bool {
        false
    }

    pub const fn outcome_adoption() -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContractValidationError {
    #[error(transparent)]
    Document(#[from] ContractDocumentError),
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_in_contract_matches_layer_one_boundary() {
        let contract = AwsApiGatewayContract::baseline().expect("contract");
        assert_eq!(contract.digest(), contract_digest());
        assert_eq!(plugin_version(), (1, 0, 0));
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::truth_authority());
        assert!(!Layer1Authority::outcome_adoption());
    }
}
