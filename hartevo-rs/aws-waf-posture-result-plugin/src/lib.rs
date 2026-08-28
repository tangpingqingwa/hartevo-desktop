//! Standalone Layer-1 AWS WAF posture evidence.
//!
//! This crate defines a bounded, read/proposal/record/verify seam for the AWS
//! WAF `ListWebACLs`, `GetWebACL`, and `ListResourcesForWebACL` operations. It
//! deliberately has no AWS SDK, signer, credential resolver, HTTPS client,
//! mutation operation, sampled-request reader, or kernel authority.

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

pub use consumer::{
    ConsumerError, MissionAwsWafConsumer, MissionAwsWafDecision, MissionAwsWafDecisionState,
    MissionAwsWafResult, MissionDeploymentDecision,
};
pub use model::*;
pub use provider::{
    AwsWafPostureProvider, AwsWafProvider, AwsWafProviderDefinition, AwsWafProviderError,
    AwsWafTransport, BlockedEnvAwsWafTransport, BlockedEnvTransport, FixtureAwsWafTransport,
    GetWebAclRequest, GetWebAclResponse, ListResourcesForWebAclPage, ListResourcesForWebAclRequest,
    ListWebAclsPage, ListWebAclsRequest, LoopbackAwsWafTransport, ProviderDefinition,
    RecordingAwsWafTransport, TransportCall, TransportError,
};
pub use service::{
    AuthorityBoundary, AwsWafPostureEvidence, AwsWafPostureProposal, AwsWafPostureProposalResult,
    AwsWafPostureReadResult, AwsWafPostureRecord, AwsWafPostureRecordReceipt,
    AwsWafPostureRegistration, AwsWafPostureRegistrationReceipt, AwsWafPostureService,
    AwsWafPostureServiceDefinition, AwsWafRegistration, EvidenceDigests, EvidenceStatus,
    PaginationEvidence, Registration, RegistrationRevocation, RegistrationState, ServiceDefinition,
    ServiceError,
};

pub const AWS_WAF_POSTURE_SCHEMA_VERSION: &str = "hartevo.aws-waf-posture-result.contract/v1";
pub const AWS_WAF_POSTURE_RESULT_SCHEMA_VERSION: &str = AWS_WAF_POSTURE_SCHEMA_VERSION;
pub const AWS_WAF_POSTURE_CONTRACT_VERSION: &str = "EXT-AWS-WAF-01-L1/v1";
pub const AWS_WAF_POSTURE_RESULT_CONTRACT_VERSION: &str = AWS_WAF_POSTURE_CONTRACT_VERSION;
pub const AWS_WAF_POSTURE_PLUGIN_VERSION: &str = "1.0.0";
pub const AWS_WAF_POSTURE_SERVICE_ID: &str = "aws.waf.posture.result";
pub const AWS_WAF_POSTURE_PROVIDER_ID: &str = "aws.waf.posture.result.recording";
pub const AWS_WAF_POSTURE_PROVIDER_VERSION: &str = "1.0.0";
pub const AWS_WAF_POSTURE_SERVICE_VERSION: &str = "1.0.0";
pub const AWS_WAF_API_VERSION: &str = "2019-04-23";
pub const AWS_WAF_POSTURE_API_REVISION: &str =
    "waf-list-web-acls-get-web-acl-list-resources-for-web-acl-r1";
pub const AWS_WAF_POSTURE_PROVIDER_REVISION: &str = AWS_WAF_POSTURE_API_REVISION;
pub const AWS_WAF_POSTURE_EVIDENCE_LEVEL: &str = "E1";
pub const AWS_WAF_POSTURE_CONSUMER_ID: &str = "mission.aws-waf-posture.consumer";
pub const AWS_WAF_POSTURE_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AWS_WAF_BLOCKED_ENV: &str = AWS_WAF_POSTURE_BLOCKED_ENV;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_ARN_BYTES: usize = 2_048;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_READ: u16 = 12;
pub const MAX_WEB_ACLS: usize = 32;
pub const MAX_RESOURCES: usize = 128;
pub const MAX_RULE_SUMMARIES: usize = 256;

/// The contract is the exact bytes shipped with this standalone root.
pub const AWS_WAF_POSTURE_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-waf-posture-result/aws-waf-posture-result.v1.json"
);

/// Layer 1 has no native, connected, first-party, receipt, or kernel authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }

    pub const fn durable_provider_receipt() -> bool {
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

    pub const fn verification_authority() -> bool {
        false
    }

    pub const fn outcome_authority() -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContractDocumentError {
    #[error("AWS WAF contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("AWS WAF contract is missing a required field: {0}")]
    MissingField(&'static str),
    #[error("AWS WAF contract identity drifted: {0}")]
    Identity(&'static str),
    #[error("AWS WAF contract authority boundary widened: {0}")]
    Authority(&'static str),
    #[error("AWS WAF contract redaction boundary drifted: {0}")]
    Redaction(&'static str),
}

/// Parsed and validated contract document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsWafPostureContract {
    value: serde_json::Value,
}

impl AwsWafPostureContract {
    pub fn baseline() -> Result<Self, ContractDocumentError> {
        let value = serde_json::from_str::<serde_json::Value>(AWS_WAF_POSTURE_CONTRACT_JSON)
            .map_err(|error| ContractDocumentError::InvalidJson(error.to_string()))?;
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
            .ok_or(ContractDocumentError::Identity("document is not an object"))?;
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
            "provenance",
            "authorityBoundary",
            "layer2Gaps",
            "forbidden",
        ] {
            if !object.contains_key(key) {
                return Err(ContractDocumentError::MissingField(key));
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(AWS_WAF_POSTURE_SCHEMA_VERSION)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_WAF_POSTURE_CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_WAF_POSTURE_PLUGIN_VERSION)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
        {
            return Err(ContractDocumentError::Identity("contract version or layer"));
        }

        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::Identity("service"))?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(AWS_WAF_POSTURE_SERVICE_ID)
            || service
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AwsWafPostureService")
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractDocumentError::Identity("service authority"));
        }
        let expected_operations = [
            "describe_capabilities",
            "register",
            "revoke_registration",
            "read_bounded",
            "propose",
            "record",
            "verify",
        ];
        if service
            .get("operations")
            .and_then(serde_json::Value::as_array)
            .is_none_or(|operations| {
                operations.len() != expected_operations.len()
                    || operations
                        .iter()
                        .zip(expected_operations)
                        .any(|(actual, expected)| actual.as_str() != Some(expected))
            })
        {
            return Err(ContractDocumentError::Identity("service operations"));
        }

        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::Identity("provider"))?;
        if provider.get("id").and_then(serde_json::Value::as_str)
            != Some(AWS_WAF_POSTURE_PROVIDER_ID)
            || provider
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AwsWafProvider")
            || provider
                .get("apiVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_WAF_API_VERSION)
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractDocumentError::Identity("provider authority"));
        }
        let expected_provider_operations = ["ListWebACLs", "GetWebACL", "ListResourcesForWebACL"];
        if provider
            .get("allowlistedOperations")
            .and_then(serde_json::Value::as_array)
            .is_none_or(|operations| {
                operations.len() != expected_provider_operations.len()
                    || operations
                        .iter()
                        .zip(expected_provider_operations)
                        .any(|(actual, expected)| actual.as_str() != Some(expected))
            })
        {
            return Err(ContractDocumentError::Identity(
                "provider operation allowlist",
            ));
        }

        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::Identity("consumer"))?;
        if consumer.get("id").and_then(serde_json::Value::as_str)
            != Some(AWS_WAF_POSTURE_CONSUMER_ID)
            || consumer
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("MissionAwsWafConsumer")
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
            || consumer.get("effectiveAuthorization") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractDocumentError::Identity("consumer authority"));
        }

        let provenance = object
            .get("provenance")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::Identity("provenance"))?;
        for key in ["fixture", "recording", "loopback", "blockedEnv"] {
            if provenance
                .get(key)
                .and_then(serde_json::Value::as_object)
                .is_none_or(|value| {
                    value.get("connected") != Some(&serde_json::Value::Bool(false))
                        || value.get("native") != Some(&serde_json::Value::Bool(false))
                        || value.get("firstParty") != Some(&serde_json::Value::Bool(false))
                })
            {
                return Err(ContractDocumentError::Authority("provenance claims"));
            }
        }

        let redaction = object
            .get("redaction")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::Redaction("redaction"))?;
        for key in [
            "ruleStatements",
            "ipSets",
            "requestBodies",
            "sampledRequests",
            "rawProviderPayload",
            "rawNextToken",
            "secretMaterial",
            "unboundedLogs",
        ] {
            if redaction.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(ContractDocumentError::Redaction(key));
            }
        }

        let authority = object
            .get("authorityBoundary")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::Authority("authority boundary"))?;
        for key in [
            "truth",
            "consent",
            "effect",
            "receipt",
            "verification",
            "outcome",
            "credentialResolution",
            "nativeSigV4",
            "liveHttps",
            "wafMutation",
            "sampledRequestRead",
        ] {
            if authority.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(ContractDocumentError::Authority(key));
            }
        }
        Ok(())
    }
}

pub fn contract_digest() -> Digest {
    Digest::from_bytes(AWS_WAF_POSTURE_CONTRACT_JSON.as_bytes())
}

pub fn validate_contract_document() -> Result<(), ContractDocumentError> {
    AwsWafPostureContract::baseline().map(|_| ())
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn shipped_contract_is_valid_and_layer_one_is_honest() {
        validate_contract_document().expect("contract validates");
        assert_eq!(
            AwsWafPostureContract::baseline().unwrap().digest(),
            contract_digest()
        );
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::truth_authority());
        assert!(!Layer1Authority::consent_authority());
        assert!(!Layer1Authority::effect_authority());
        assert!(!Layer1Authority::verification_authority());
        assert!(!Layer1Authority::outcome_authority());
    }
}
