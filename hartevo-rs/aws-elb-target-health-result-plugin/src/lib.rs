//! Standalone Layer-1 governed AWS ELB target-health result slice.
//!
//! This crate owns only typed scope, reversible/revocable registration,
//! bounded ELBv2 read seams, deterministic redacted evidence, request/cost
//! receipts, and a Mission review proposal.  It deliberately does not resolve
//! credentials, perform native SigV4/HTTPS, mutate listeners/rules/targets or
//! health checks, shift traffic, execute targets, certify availability, or
//! adopt Hartevo kernel Truth/Consent/Effect/Receipt/Verification/Outcome or
//! Work Product authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConsumerError, MissionAwsElbConsumer, MissionAwsElbDecisionState, MissionAwsElbResult,
    MissionAwsElbTargetHealthConsumer, MissionAwsElbTargetHealthResult, RecordedAwsElbResult,
};
pub use model::*;
pub use provider::{
    AwsElbProvider, AwsElbProviderDefinition, AwsElbProviderError, AwsElbProviderIdentity,
    AwsElbTransport, AwsElbTransportError, BlockedEnvAwsElbTransport, BlockedEnvTransport,
    DescribeLoadBalancersPage, DescribeTargetGroupsPage, DescribeTargetHealthPage, FakeTransport,
    FixtureAwsElbTransport, FixtureTransport, LoopbackAwsElbTransport, LoopbackTransport,
    ProviderDefinitionError, ProviderError, RecordingAwsElbTransport, RecordingTransport,
    is_access_loss, is_throttle, is_timeout,
};
pub use service::{
    AwsElbHealthEvidence, AwsElbHealthProposal, AwsElbReadResult, AwsElbRecordReceipt,
    AwsElbRegistration, AwsElbService, AwsElbTargetHealthCapabilities, AwsElbTargetHealthEvidence,
    AwsElbTargetHealthProposal, AwsElbTargetHealthRegistration, AwsElbTargetHealthService,
    AwsElbTargetHealthServiceDefinition, AwsElbTargetHealthServiceError, AwsElbVerifiedRecord,
    RegistrationTransitionEvidence,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-elb-target-health-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWSELB-01-L1/v1";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const PLUGIN_ID: &str = "aws.elb.target-health-result";
pub const SERVICE_ID: &str = "aws.elb.target-health-result.read";
pub const PROVIDER_ID: &str = "aws.elb.target-health-result.recording";
pub const PROVIDER_VERSION: &str = "1.0.0";
pub const PROVIDER_API_REVISION: &str = "elasticloadbalancingv2-describe-load-balancers-describe-target-groups-describe-target-health-1";
pub const CONSUMER_ID: &str = "mission.aws-elb-target-health.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-elb-target-health-result/v1|layer=1|service=aws.elb.target-health-result.read|provider=aws.elb.target-health-result.recording|consumer=mission.aws-elb-target-health.consumer";
pub const CONTRACT_DIGEST: &str =
    "33a744d79f5c2849a05848bbb79757785a5054f0190c594498233050bdc61a30";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-elb-target-health-result/aws-elb-target-health-result.v1.json"
);

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

pub const fn plugin_version() -> (u16, u16, u16) {
    (1, 0, 0)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsElbTargetHealthContract {
    value: serde_json::Value,
}

#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum ContractError {
    #[error("AWS ELB target-health contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("AWS ELB target-health contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("AWS ELB target-health contract identity is invalid: {0}")]
    Identity(&'static str),
    #[error("AWS ELB target-health contract authority is unsafe: {0}")]
    Authority(&'static str),
}

impl AwsElbTargetHealthContract {
    pub fn baseline() -> Result<Self, ContractError> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|error| ContractError::InvalidJson(error.to_string()))?;
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

    pub fn validate(&self) -> Result<(), ContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(ContractError::Shape("contract is not an object"))?;
        for key in [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "layer",
            "digestInput",
            "contractDigest",
            "pluginId",
            "service",
            "provider",
            "consumer",
            "credentials",
            "scope",
            "registration",
            "bounds",
            "pagination",
            "projection",
            "permissions",
            "evidence",
            "receipts",
            "redaction",
            "authority",
            "honesty",
            "layer2Gaps",
            "forbidden",
        ] {
            if !object.contains_key(key) {
                return Err(ContractError::Shape("required contract key missing"));
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
            || object.get("layer").and_then(serde_json::Value::as_u64) != Some(1)
            || object
                .get("digestInput")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST_INPUT)
            || object
                .get("contractDigest")
                .and_then(serde_json::Value::as_str)
                != Some(contract_digest().as_str())
            || object.get("pluginId").and_then(serde_json::Value::as_str) != Some(PLUGIN_ID)
        {
            return Err(ContractError::Identity("contract identity drifted"));
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("service definition missing"))?;
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("provider definition missing"))?;
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("consumer definition missing"))?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AwsElbTargetHealthService")
            || provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AwsElbProvider")
            || consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("MissionAwsElbConsumer")
        {
            return Err(ContractError::Identity(
                "service, provider, or consumer identity drifted",
            ));
        }
        if service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
            || consumer.get("certificationAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractError::Authority(
                "Layer-1 authority flags are unsafe",
            ));
        }
        let operations = provider
            .get("allowlistedOperations")
            .and_then(serde_json::Value::as_array)
            .ok_or(ContractError::Shape("provider operation allowlist missing"))?;
        let expected_operations = [
            "DescribeLoadBalancers",
            "DescribeTargetGroups",
            "DescribeTargetHealth",
        ];
        if operations.len() != expected_operations.len()
            || operations
                .iter()
                .zip(expected_operations)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err(ContractError::Identity(
                "provider operation allowlist drifted",
            ));
        }
        let transports = provider
            .get("acceptedTransports")
            .and_then(serde_json::Value::as_array)
            .ok_or(ContractError::Shape("accepted transport list missing"))?;
        for transport in ["fixture", "recording", "loopback", BLOCKED_ENV] {
            if !transports
                .iter()
                .any(|value| value.as_str() == Some(transport))
            {
                return Err(ContractError::Shape(
                    "required deterministic transport missing",
                ));
            }
        }
        let permissions = object
            .get("permissions")
            .and_then(serde_json::Value::as_object)
            .and_then(|value| value.get("required"))
            .and_then(serde_json::Value::as_array)
            .ok_or(ContractError::Shape("permission allowlist missing"))?;
        for permission in [
            "elasticloadbalancing:DescribeLoadBalancers",
            "elasticloadbalancing:DescribeTargetGroups",
            "elasticloadbalancing:DescribeTargetHealth",
            "mission.scope",
        ] {
            if !permissions
                .iter()
                .any(|value| value.as_str() == Some(permission))
            {
                return Err(ContractError::Identity("required permission missing"));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
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

    pub const fn availability_certification() -> bool {
        false
    }

    pub const fn outcome_authority() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_in_contract_matches_typed_boundary() {
        let contract = AwsElbTargetHealthContract::baseline().expect("valid contract");
        assert_eq!(contract.digest(), contract_digest());
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::availability_certification());
        assert!(!Layer1Authority::outcome_authority());
    }
}
