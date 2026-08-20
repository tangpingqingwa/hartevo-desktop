//! Standalone Layer-1 governed Amazon Detective investigation evidence.
//!
//! The crate intentionally stops below native SigV4/HTTPS, graph-search
//! authority, mutation authority, kernel authority, durable native receipts,
//! and verified Work Product adoption. It exposes only bounded read,
//! proposal, record, and verify seams for the four allowlisted Detective
//! operations.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::collapsible_if,
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
    ConsumerError, MissionAwsDetectiveConsumer, MissionAwsDetectiveDecisionState,
    MissionAwsDetectiveResult,
};
pub use model::*;
pub use provider::*;
pub use service::*;

pub const AWS_DETECTIVE_SCHEMA_VERSION: &str = "hartevo-aws-detective-result-contract/v1";
pub const AWS_DETECTIVE_CONTRACT_VERSION: &str = "EXT-AWS-DETECTIVE-01-L1/v1";
pub const AWS_DETECTIVE_PLUGIN_VERSION: &str = "1.0.0";
pub const AWS_DETECTIVE_SERVICE_ID: &str = "aws.detective.result";
pub const AWS_DETECTIVE_PROVIDER_ID: &str = "aws.detective.read";
pub const AWS_DETECTIVE_PROVIDER_VERSION: &str = "aws-detective-provider/v1";
pub const AWS_DETECTIVE_API_VERSION: &str = "2018-10-26";
pub const AWS_DETECTIVE_PROVIDER_REVISION: &str = "aws-detective-read-r1";
pub const AWS_DETECTIVE_CONSUMER_ID: &str = "mission.aws-detective.consumer";
pub const AWS_DETECTIVE_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AWS_DETECTIVE_EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const AWS_DETECTIVE_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-detective-result/aws-detective-result.v1.json");

// Stable short aliases used by adjacent standalone result slices.
pub const CONTRACT_SCHEMA: &str = AWS_DETECTIVE_SCHEMA_VERSION;
pub const CONTRACT_VERSION: &str = AWS_DETECTIVE_CONTRACT_VERSION;
pub const PLUGIN_ID: &str = "aws.detective.result";
pub const PLUGIN_VERSION: &str = AWS_DETECTIVE_PLUGIN_VERSION;
pub const SERVICE_ID: &str = AWS_DETECTIVE_SERVICE_ID;
pub const PROVIDER_ID: &str = AWS_DETECTIVE_PROVIDER_ID;
pub const PROVIDER_API_VERSION: &str = AWS_DETECTIVE_API_VERSION;
pub const PROVIDER_API_REVISION: &str = AWS_DETECTIVE_PROVIDER_REVISION;
pub const CONSUMER_ID: &str = AWS_DETECTIVE_CONSUMER_ID;
pub const EVIDENCE_LEVEL: &str = AWS_DETECTIVE_EVIDENCE_LEVEL;
pub const CONTRACT_JSON: &str = AWS_DETECTIVE_CONTRACT_JSON;

/// The only Layer-1 authority claims made by this crate.
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

    pub const fn graph_search() -> bool {
        false
    }

    pub const fn mutation_authority() -> bool {
        false
    }

    pub const fn kernel_authority() -> bool {
        false
    }

    pub const fn durable_receipt() -> bool {
        false
    }

    pub const fn verified_work_product_adoption() -> bool {
        false
    }
}

pub fn contract_digest() -> Digest {
    sha256_digest(AWS_DETECTIVE_CONTRACT_JSON.as_bytes())
}

pub const fn plugin_version() -> (u16, u16, u16) {
    (1, 0, 0)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsDetectiveContract {
    value: Value,
}

impl AwsDetectiveContract {
    pub fn baseline() -> Result<Self, AwsDetectiveContractError> {
        let value = serde_json::from_str::<Value>(AWS_DETECTIVE_CONTRACT_JSON)
            .map_err(|error| AwsDetectiveContractError::InvalidJson(error.to_string()))?;
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

    pub fn validate(&self) -> Result<(), AwsDetectiveContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(AwsDetectiveContractError::Shape(
                "contract is not an object",
            ))?;
        for key in [
            "schemaVersion",
            "contractVersion",
            "pluginId",
            "pluginVersion",
            "evidenceLevel",
            "layer",
            "service",
            "provider",
            "consumer",
            "scope",
            "digests",
            "reads",
            "redaction",
            "authority",
            "nativeClaims",
            "forbidden",
            "layer2Exits",
        ] {
            if !object.contains_key(key) {
                return Err(AwsDetectiveContractError::Shape(
                    "required contract key missing",
                ));
            }
        }
        if object.get("schemaVersion").and_then(Value::as_str) != Some(AWS_DETECTIVE_SCHEMA_VERSION)
            || object.get("contractVersion").and_then(Value::as_str)
                != Some(AWS_DETECTIVE_CONTRACT_VERSION)
            || object.get("pluginId").and_then(Value::as_str) != Some(PLUGIN_ID)
            || object.get("pluginVersion").and_then(Value::as_str)
                != Some(AWS_DETECTIVE_PLUGIN_VERSION)
            || object.get("evidenceLevel").and_then(Value::as_str)
                != Some(AWS_DETECTIVE_EVIDENCE_LEVEL)
            || object.get("layer").and_then(Value::as_u64) != Some(1)
        {
            return Err(AwsDetectiveContractError::Identity(
                "contract identity drifted",
            ));
        }

        let service = object
            .get("service")
            .and_then(Value::as_object)
            .ok_or(AwsDetectiveContractError::Shape("service is not an object"))?;
        let service_operations = service.get("operations").and_then(Value::as_array).ok_or(
            AwsDetectiveContractError::Shape("service operations are missing"),
        )?;
        let expected_service_operations = [
            "ListInvestigations",
            "GetInvestigation",
            "ListIndicators",
            "ListMembers",
            "Register",
            "RevokeRegistration",
            "Read",
            "Propose",
            "Record",
            "Verify",
        ];
        if service.get("id").and_then(Value::as_str) != Some(AWS_DETECTIVE_SERVICE_ID)
            || service.get("implementation").and_then(Value::as_str) != Some("AwsDetectiveService")
            || service.get("readOnly") != Some(&Value::Bool(true))
            || service.get("proposalOnly") != Some(&Value::Bool(true))
            || service.get("liveExecution") != Some(&Value::Bool(false))
            || service_operations.len() != expected_service_operations.len()
            || service_operations
                .iter()
                .zip(expected_service_operations)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err(AwsDetectiveContractError::Identity(
                "service identity or operations drifted",
            ));
        }

        let provider = object.get("provider").and_then(Value::as_object).ok_or(
            AwsDetectiveContractError::Shape("provider is not an object"),
        )?;
        let operations = provider
            .get("allowlistedOperations")
            .and_then(Value::as_array)
            .ok_or(AwsDetectiveContractError::Shape(
                "provider operation allowlist is missing",
            ))?;
        let expected_operations = [
            "ListInvestigations",
            "GetInvestigation",
            "ListIndicators",
            "ListMembers",
        ];
        if provider.get("id").and_then(Value::as_str) != Some(AWS_DETECTIVE_PROVIDER_ID)
            || provider.get("implementation").and_then(Value::as_str)
                != Some("AwsDetectiveProvider")
            || provider.get("apiVersion").and_then(Value::as_str) != Some(AWS_DETECTIVE_API_VERSION)
            || provider.get("providerVersion").and_then(Value::as_str)
                != Some(AWS_DETECTIVE_PROVIDER_VERSION)
            || provider.get("native") != Some(&Value::Bool(false))
            || provider.get("firstParty") != Some(&Value::Bool(false))
            || provider.get("connected") != Some(&Value::Bool(false))
            || provider.get("readOnly") != Some(&Value::Bool(true))
            || provider.get("externalWrites") != Some(&Value::Bool(false))
            || operations.len() != expected_operations.len()
            || operations
                .iter()
                .zip(expected_operations)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err(AwsDetectiveContractError::Identity(
                "provider identity or allowlist drifted",
            ));
        }

        let permission_actions = provider
            .get("permissionActions")
            .and_then(Value::as_array)
            .ok_or(AwsDetectiveContractError::Shape(
                "provider permission allowlist is missing",
            ))?;
        let expected_permissions = [
            "detective:ListInvestigations",
            "detective:GetInvestigation",
            "detective:ListIndicators",
            "detective:ListMembers",
        ];
        if permission_actions.len() != expected_permissions.len()
            || permission_actions
                .iter()
                .zip(expected_permissions)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err(AwsDetectiveContractError::Boundary(
                "provider permission allowlist drifted",
            ));
        }

        let consumer = object.get("consumer").and_then(Value::as_object).ok_or(
            AwsDetectiveContractError::Shape("consumer is not an object"),
        )?;
        if consumer.get("id").and_then(Value::as_str) != Some(AWS_DETECTIVE_CONSUMER_ID)
            || consumer.get("implementation").and_then(Value::as_str)
                != Some("MissionAwsDetectiveConsumer")
            || consumer.get("adoptsOutcome") != Some(&Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&Value::Bool(false))
            || consumer.get("effectiveAuthorization") != Some(&Value::Bool(false))
        {
            return Err(AwsDetectiveContractError::Identity(
                "consumer identity drifted",
            ));
        }

        let authority = object.get("authority").and_then(Value::as_object).ok_or(
            AwsDetectiveContractError::Shape("authority is not an object"),
        )?;
        for key in [
            "connected",
            "native",
            "firstParty",
            "externalWrites",
            "graphSearch",
            "graphMutation",
            "memberMutation",
            "datasourceMutation",
            "investigationStart",
            "investigationStateMutation",
            "kernelAuthority",
            "durableReceipt",
        ] {
            if authority.get(key) != Some(&Value::Bool(false)) {
                return Err(AwsDetectiveContractError::Boundary(
                    "Layer-1 authority widened",
                ));
            }
        }

        let native_claims = object
            .get("nativeClaims")
            .and_then(Value::as_object)
            .ok_or(AwsDetectiveContractError::Shape(
                "native claims are not an object",
            ))?;
        for key in [
            "connected",
            "nativeProvider",
            "firstParty",
            "durableReceipt",
            "effectiveAuthorization",
            "truthAuthority",
            "blockedEnvironmentIsNative",
        ] {
            if native_claims.get(key) != Some(&Value::Bool(false)) {
                return Err(AwsDetectiveContractError::Boundary("native claim widened"));
            }
        }

        let forbidden = object.get("forbidden").and_then(Value::as_array).ok_or(
            AwsDetectiveContractError::Shape("forbidden list is missing"),
        )?;
        for required in [
            "StartInvestigation",
            "UpdateInvestigationState",
            "SearchGraph",
            "CreateMembers",
            "DeleteMembers",
            "UpdateDatasourcePackages",
            "retain_entity_arn",
            "retain_entity_email",
            "retain_raw_graph_edges",
            "adopt_kernel_authority",
        ] {
            if !forbidden
                .iter()
                .any(|entry| entry.as_str() == Some(required))
            {
                return Err(AwsDetectiveContractError::Boundary(
                    "forbidden operation missing",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsDetectiveContractError {
    #[error("AWS Detective contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("AWS Detective contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("AWS Detective contract identity is invalid: {0}")]
    Identity(&'static str),
    #[error("AWS Detective contract widens Layer-1 authority: {0}")]
    Boundary(&'static str),
}

#[cfg(test)]
mod contract_tests {
    use super::{
        AWS_DETECTIVE_API_VERSION, AWS_DETECTIVE_BLOCKED_ENV, AWS_DETECTIVE_CONSUMER_ID,
        AWS_DETECTIVE_CONTRACT_VERSION, AWS_DETECTIVE_PROVIDER_ID, AWS_DETECTIVE_SCHEMA_VERSION,
        AWS_DETECTIVE_SERVICE_ID, AwsDetectiveContract, Layer1Authority,
    };

    #[test]
    fn contract_is_valid_and_authority_is_false() {
        AwsDetectiveContract::baseline().expect("checked contract");
        assert_eq!(
            AWS_DETECTIVE_SCHEMA_VERSION,
            "hartevo-aws-detective-result-contract/v1"
        );
        assert_eq!(AWS_DETECTIVE_CONTRACT_VERSION, "EXT-AWS-DETECTIVE-01-L1/v1");
        assert_eq!(AWS_DETECTIVE_SERVICE_ID, "aws.detective.result");
        assert_eq!(AWS_DETECTIVE_PROVIDER_ID, "aws.detective.read");
        assert_eq!(AWS_DETECTIVE_CONSUMER_ID, "mission.aws-detective.consumer");
        assert_eq!(AWS_DETECTIVE_API_VERSION, "2018-10-26");
        assert_eq!(AWS_DETECTIVE_BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::graph_search());
        assert!(!Layer1Authority::mutation_authority());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::verified_work_product_adoption());
    }
}
