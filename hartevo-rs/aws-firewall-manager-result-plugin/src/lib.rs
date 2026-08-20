//! Standalone Layer-1 AWS Firewall Manager policy/compliance result boundary.
//!
//! This crate owns only typed, bounded, redacted control-plane evidence seams
//! for `ListPolicies`, `GetPolicy`, `ListComplianceStatus`, and
//! `GetComplianceDetail`. It never signs native SigV4 requests, resolves
//! credentials, mutates Firewall Manager, reads WAF or Network Firewall
//! data-plane bodies, performs remediation/effects, issues durable native
//! receipts, rereads native state independently, or adopts a Mission Outcome.
//!
//! Fixture, fake, recording, loopback, and `BLOCKED_ENV` transports are
//! deliberately always non-connected, non-native, and non-first-party.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

use thiserror::Error;

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConsumerError, MissionAwsFirewallManagerConsumer, MissionAwsFirewallManagerResult,
    RecordedAwsFirewallManagerResult,
};
pub use error::{
    AwsFirewallManagerError, ModelError, ProviderError, Result, ServiceError, TransportError,
    TransportFailure,
};
pub use model::*;
pub use provider::{
    AwsFirewallManagerProvider, AwsFirewallManagerProviderDefinition,
    AwsFirewallManagerProviderError, AwsFirewallManagerTransport,
    BlockedEnvAwsFirewallManagerTransport, BlockedEnvTransport, FakeAwsFirewallManagerTransport,
    FakeTransport, FixtureAwsFirewallManagerTransport, FixtureTransport,
    LoopbackAwsFirewallManagerTransport, LoopbackTransport, RecordedRequest,
    RecordingAwsFirewallManagerTransport, RecordingTransport,
};
pub use service::{
    AwsFirewallManagerEvidence, AwsFirewallManagerProposal, AwsFirewallManagerReadRequest,
    AwsFirewallManagerReadResult, AwsFirewallManagerRecord, AwsFirewallManagerRecordReceipt,
    AwsFirewallManagerRegistration, AwsFirewallManagerService, AwsFirewallManagerServiceError,
    AwsFirewallManagerVerifiedRecord, RegistrationState, VerificationFailure, VerificationReport,
};

pub type AwsFirewallManagerResult = AwsFirewallManagerProposal;

pub const AWS_FIREWALL_MANAGER_SCHEMA_VERSION: &str =
    "hartevo.aws-firewall-manager-result.contract/v1";
pub const AWS_FIREWALL_MANAGER_CONTRACT_VERSION: &str = "EXT-AWS-FIREWALL-MANAGER-01-L1/v1";
pub const AWS_FIREWALL_MANAGER_PLUGIN_ID: &str = "aws.firewall-manager.result";
pub const AWS_FIREWALL_MANAGER_PLUGIN_VERSION: &str = "1.0.0";
pub const AWS_FIREWALL_MANAGER_SERVICE_ID: &str = "aws.firewall-manager.result.read";
pub const AWS_FIREWALL_MANAGER_PROVIDER_ID: &str = "aws.firewall-manager.result.recording";
pub const AWS_FIREWALL_MANAGER_PROVIDER_VERSION: &str = "1.0.0";
pub const AWS_FIREWALL_MANAGER_API_VERSION: &str = "2018-01-01";
pub const AWS_FIREWALL_MANAGER_API_REVISION: &str = "aws-fms-policy-compliance-read-r1";
pub const AWS_FIREWALL_MANAGER_CONSUMER_ID: &str = "mission.aws.firewall-manager.result";
pub const AWS_FIREWALL_MANAGER_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AWS_FIREWALL_MANAGER_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-firewall-manager-result/aws-firewall-manager-result.v1.json"
);

pub fn contract_digest() -> Digest {
    Digest::from_bytes(AWS_FIREWALL_MANAGER_CONTRACT_JSON.as_bytes())
}

pub const fn plugin_version() -> (u16, u16, u16) {
    (1, 0, 0)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsFirewallManagerContract {
    value: serde_json::Value,
}

impl AwsFirewallManagerContract {
    pub fn baseline() -> std::result::Result<Self, AwsFirewallManagerContractError> {
        let value =
            serde_json::from_str::<serde_json::Value>(AWS_FIREWALL_MANAGER_CONTRACT_JSON)
                .map_err(|error| AwsFirewallManagerContractError::InvalidJson(error.to_string()))?;
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

    pub fn validate(&self) -> std::result::Result<(), AwsFirewallManagerContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(AwsFirewallManagerContractError::Shape(
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
            "scope",
            "registration",
            "bounds",
            "reads",
            "evidence",
            "redaction",
            "provenance",
            "authority",
            "forbidden",
            "layer2Gaps",
        ] {
            if !object.contains_key(key) {
                return Err(AwsFirewallManagerContractError::Shape(key));
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(AWS_FIREWALL_MANAGER_SCHEMA_VERSION)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_FIREWALL_MANAGER_CONTRACT_VERSION)
            || object.get("pluginId").and_then(serde_json::Value::as_str)
                != Some(AWS_FIREWALL_MANAGER_PLUGIN_ID)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_FIREWALL_MANAGER_PLUGIN_VERSION)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
        {
            return Err(AwsFirewallManagerContractError::Identity(
                "contract identity drifted",
            ));
        }

        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsFirewallManagerContractError::Shape("service"))?;
        if service.get("id").and_then(serde_json::Value::as_str)
            != Some(AWS_FIREWALL_MANAGER_SERVICE_ID)
            || service.get("type").and_then(serde_json::Value::as_str)
                != Some("AwsFirewallManagerService")
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsFirewallManagerContractError::Identity(
                "service boundary drifted",
            ));
        }
        let expected_operations = [
            "describe_capabilities",
            "register",
            "revoke_registration",
            "reverse_registration",
            "read_bounded",
            "propose",
            "record",
            "verify",
        ];
        let operations = service
            .get("operations")
            .and_then(serde_json::Value::as_array)
            .ok_or(AwsFirewallManagerContractError::Shape("service operations"))?;
        if operations.len() != expected_operations.len()
            || operations
                .iter()
                .zip(expected_operations)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err(AwsFirewallManagerContractError::Identity(
                "service operations drifted",
            ));
        }

        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsFirewallManagerContractError::Shape("provider"))?;
        if provider.get("type").and_then(serde_json::Value::as_str)
            != Some("AwsFirewallManagerProvider")
            || provider.get("id").and_then(serde_json::Value::as_str)
                != Some(AWS_FIREWALL_MANAGER_PROVIDER_ID)
            || provider
                .get("apiVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_FIREWALL_MANAGER_API_VERSION)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_FIREWALL_MANAGER_API_REVISION)
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsFirewallManagerContractError::Identity(
                "provider boundary drifted",
            ));
        }
        let provider_operations = provider
            .get("operations")
            .and_then(serde_json::Value::as_array)
            .ok_or(AwsFirewallManagerContractError::Shape(
                "provider operations",
            ))?;
        if provider_operations
            != &[
                serde_json::Value::String("ListPolicies".to_owned()),
                serde_json::Value::String("GetPolicy".to_owned()),
                serde_json::Value::String("ListComplianceStatus".to_owned()),
                serde_json::Value::String("GetComplianceDetail".to_owned()),
            ]
        {
            return Err(AwsFirewallManagerContractError::Identity(
                "provider operation allowlist drifted",
            ));
        }

        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsFirewallManagerContractError::Shape("consumer"))?;
        if consumer.get("type").and_then(serde_json::Value::as_str)
            != Some("MissionAwsFirewallManagerConsumer")
            || consumer.get("id").and_then(serde_json::Value::as_str)
                != Some(AWS_FIREWALL_MANAGER_CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsFirewallManagerContractError::Identity(
                "consumer boundary drifted",
            ));
        }

        let provenance = object
            .get("provenance")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsFirewallManagerContractError::Shape("provenance"))?;
        for key in [
            "connectedClaim",
            "nativeClaim",
            "firstPartyClaim",
            "providerReceipt",
        ] {
            if provenance.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(AwsFirewallManagerContractError::Boundary(
                    "provenance widened",
                ));
            }
        }
        for transport in ["fixture", "fake", "recording", "loopback", "blockedEnv"] {
            if provenance
                .get(transport)
                .and_then(serde_json::Value::as_str)
                != Some("non_native_non_connected_non_first_party")
            {
                return Err(AwsFirewallManagerContractError::Boundary(
                    "transport provenance widened",
                ));
            }
        }

        let authority = object
            .get("authority")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsFirewallManagerContractError::Shape("authority"))?;
        for key in [
            "externalWrites",
            "policyMutation",
            "adminAssociation",
            "remediation",
            "effectAuthority",
            "rawPolicyRead",
            "credentialResolution",
            "durableNativeReceipt",
            "independentNativeReread",
            "certification",
            "connected",
            "native",
            "kernelOutcomeAdoption",
            "workProductAdoption",
        ] {
            if authority.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(AwsFirewallManagerContractError::Boundary(
                    "Layer-1 authority widened",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsFirewallManagerContractError {
    #[error("contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("contract key or shape is missing: {0}")]
    Shape(&'static str),
    #[error("contract identity is invalid: {0}")]
    Identity(&'static str),
    #[error("contract authority boundary is invalid: {0}")]
    Boundary(&'static str),
}

/// Compile-time representation of the Layer-1 authority boundary.
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

    pub const fn effect_authority() -> bool {
        false
    }

    pub const fn outcome_adoption() -> bool {
        false
    }

    pub const fn durable_native_receipt() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract = AwsFirewallManagerContract::baseline().expect("checked contract");
        assert_eq!(contract.digest(), contract_digest());
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::effect_authority());
        assert!(!Layer1Authority::outcome_adoption());
        assert!(!Layer1Authority::durable_native_receipt());
    }
}
