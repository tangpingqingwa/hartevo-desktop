//! Standalone Layer-1 governed AWS Network Firewall posture evidence.
//!
//! The crate owns typed, bounded read/proposal/record/verify seams and a
//! Mission-facing review projection. It deliberately has no AWS SDK, native
//! SigV4 resolver, live HTTP client, mutation operation, packet/flow-log path,
//! durable provider receipt, or Hartevo Truth/Consent/Effect/Outcome authority.

#![forbid(unsafe_code)]
#![allow(
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

pub use consumer::{
    ConsumerError, MissionAwsNetworkFirewallConsumer, MissionAwsNetworkFirewallResult,
};
pub use model::*;
pub use provider::{
    AwsNetworkFirewallProvider, AwsNetworkFirewallProviderDefinition,
    AwsNetworkFirewallProviderError, AwsNetworkFirewallTransport,
    BlockedEnvAwsNetworkFirewallTransport, BlockedEnvTransport, DescribeFirewallPolicyRequest,
    DescribeFirewallPolicyResponse, DescribeFirewallRequest, DescribeFirewallResponse,
    FirewallDescription, FirewallListItem, FirewallPolicyDescription,
    FixtureAwsNetworkFirewallTransport, FixtureTransport, ListFirewallsPage, ListFirewallsRequest,
    LoopbackAwsNetworkFirewallTransport, LoopbackTransport, ProviderError, ProviderProvenance,
    RecordingAwsNetworkFirewallTransport, RecordingTransport, TransportCall, TransportError,
    TransportFailure,
};
pub use service::{
    AuthorityBoundary, AwsNetworkFirewallCapabilities, AwsNetworkFirewallListRecord,
    AwsNetworkFirewallPostureEvidence, AwsNetworkFirewallPostureProposal,
    AwsNetworkFirewallPostureRegistration, AwsNetworkFirewallPostureService,
    AwsNetworkFirewallReadRecord, AwsNetworkFirewallReadRequest, AwsNetworkFirewallReadResult,
    EvidenceStatus, PaginationEvidence, RedactionSummary, RegistrationState,
    RegistrationTransition, ServiceError, ServiceVersion,
};

pub const AWS_NETWORK_FIREWALL_SCHEMA_VERSION: &str =
    "hartevo.aws-network-firewall-posture-result.contract/v1";
pub const AWS_NETWORK_FIREWALL_CONTRACT_VERSION: &str = "aws-network-firewall-posture-result/v1";
pub const AWS_NETWORK_FIREWALL_PLUGIN_VERSION: &str = "1.0.0";
pub const AWS_NETWORK_FIREWALL_SERVICE_ID: &str = "hartevo.aws.network-firewall.posture-result";
pub const AWS_NETWORK_FIREWALL_PROVIDER_ID: &str = "aws.network-firewall.read";
pub const AWS_NETWORK_FIREWALL_PROVIDER_VERSION: &str = "aws-network-firewall-provider/v1";
pub const AWS_NETWORK_FIREWALL_API_VERSION: &str = "2018-02-08";
pub const AWS_NETWORK_FIREWALL_API_REVISION: &str = "aws-network-firewall-read-r1";
pub const AWS_NETWORK_FIREWALL_CONSUMER_ID: &str = "mission.aws.network-firewall.posture";
pub const AWS_NETWORK_FIREWALL_EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const AWS_NETWORK_FIREWALL_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AWS_NETWORK_FIREWALL_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-network-firewall-posture-result/aws-network-firewall-posture-result.v1.json"
);
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-network-firewall-posture-result.contract/v1|layer=1|service=hartevo.aws.network-firewall.posture-result|provider=aws.network-firewall.read|consumer=mission.aws.network-firewall.posture|api=2018-02-08";
pub const CONTRACT_DIGEST_HEX: &str =
    "8be2c7cbdfe7bc7f59c832f4f2e3230e13f1710dc3bbe619b15dbcf3669505ff";

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 4_096;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_FIREWALLS: usize = 128;
pub const MAX_ENDPOINTS: usize = 128;
pub const MAX_RULE_GROUP_REFERENCES: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_READ: u16 = 8;

/// Layer-1's intentionally negative authority claims.
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

    pub const fn durable_receipt() -> bool {
        false
    }

    pub const fn effective_authorization() -> bool {
        false
    }

    pub const fn policy_truth_authority() -> bool {
        false
    }

    pub const fn kernel_outcome_adoption() -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum ContractError {
    #[error("AWS Network Firewall contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("AWS Network Firewall contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("AWS Network Firewall contract identity is invalid: {0}")]
    Identity(&'static str),
    #[error("AWS Network Firewall contract authority boundary is invalid: {0}")]
    Boundary(&'static str),
}

/// Checked contract document used by local and CI contract gates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsNetworkFirewallContract {
    value: serde_json::Value,
}

impl AwsNetworkFirewallContract {
    pub fn baseline() -> Result<Self, ContractError> {
        let value = serde_json::from_str::<serde_json::Value>(AWS_NETWORK_FIREWALL_CONTRACT_JSON)
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
            "contractDigestInput",
            "contractDigest",
            "service",
            "provider",
            "consumer",
            "registration",
            "scope",
            "bounds",
            "reads",
            "evidence",
            "redaction",
            "authority",
            "nativeClaims",
            "forbidden",
            "layer2Gaps",
        ] {
            if !object.contains_key(key) {
                return Err(ContractError::Shape("required contract key missing"));
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(AWS_NETWORK_FIREWALL_SCHEMA_VERSION)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_NETWORK_FIREWALL_CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_NETWORK_FIREWALL_PLUGIN_VERSION)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
            || object
                .get("contractDigestInput")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST_INPUT)
            || object
                .get("contractDigest")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST_HEX)
        {
            return Err(ContractError::Identity("contract identity drifted"));
        }

        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("service is not an object"))?;
        if service.get("id").and_then(serde_json::Value::as_str)
            != Some(AWS_NETWORK_FIREWALL_SERVICE_ID)
            || service
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AwsNetworkFirewallPostureService")
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("recordingOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || service.get("kernelAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractError::Identity("service boundary drifted"));
        }
        let operations = service
            .get("operations")
            .and_then(serde_json::Value::as_array)
            .ok_or(ContractError::Shape("service operations are missing"))?;
        for operation in [
            "list_firewalls",
            "describe_firewall",
            "describe_firewall_policy",
            "propose",
            "record",
            "verify",
        ] {
            if !operations
                .iter()
                .any(|entry| entry.as_str() == Some(operation))
            {
                return Err(ContractError::Identity(
                    "required service operation missing",
                ));
            }
        }

        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("provider is not an object"))?;
        if provider.get("id").and_then(serde_json::Value::as_str)
            != Some(AWS_NETWORK_FIREWALL_PROVIDER_ID)
            || provider
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("AwsNetworkFirewallProvider")
            || provider
                .get("apiVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_NETWORK_FIREWALL_API_VERSION)
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractError::Identity("provider boundary drifted"));
        }
        let expected_operations = [
            "ListFirewalls",
            "DescribeFirewall",
            "DescribeFirewallPolicy",
        ];
        let provider_operations = provider
            .get("allowlistedOperations")
            .and_then(serde_json::Value::as_array)
            .ok_or(ContractError::Shape("provider operation allowlist missing"))?;
        if provider_operations.len() != expected_operations.len()
            || provider_operations
                .iter()
                .zip(expected_operations)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err(ContractError::Identity(
                "provider operation allowlist drifted",
            ));
        }

        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("consumer is not an object"))?;
        if consumer.get("id").and_then(serde_json::Value::as_str)
            != Some(AWS_NETWORK_FIREWALL_CONSUMER_ID)
            || consumer
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("MissionAwsNetworkFirewallConsumer")
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
            || consumer.get("effectiveAuthorization") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractError::Identity("consumer boundary drifted"));
        }

        let authority = object
            .get("authority")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("authority is not an object"))?;
        for key in [
            "externalWrites",
            "firewallMutation",
            "firewallPolicyMutation",
            "ruleGroupMutation",
            "vpcAttachmentMutation",
            "packetOrFlowLogRead",
            "credentialResolution",
            "connected",
            "native",
            "firstParty",
            "durableReceipt",
            "verificationAuthority",
            "kernelOutcomeAdoption",
            "workProductAdoption",
        ] {
            if authority.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(ContractError::Boundary("Layer-1 authority widened"));
            }
        }

        let native_claims = object
            .get("nativeClaims")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("nativeClaims is not an object"))?;
        for key in [
            "connected",
            "nativeProvider",
            "firstParty",
            "durableReceipt",
            "effectiveAuthorization",
            "policyTruthAuthority",
            "blockedEnvironmentIsNative",
            "fixtureIsNative",
            "recordingIsNative",
            "loopbackIsNative",
        ] {
            if native_claims.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(ContractError::Boundary("native claim widened"));
            }
        }

        let forbidden = object
            .get("forbidden")
            .and_then(serde_json::Value::as_array)
            .ok_or(ContractError::Shape("forbidden list missing"))?;
        for required in [
            "CreateFirewall",
            "UpdateFirewall",
            "DeleteFirewall",
            "AssociateFirewallPolicy",
            "UpdateFirewallPolicy",
            "CreateRuleGroup",
            "mutate_vpc_attachment",
            "read_packet_payload",
            "read_flow_logs",
            "resolve_live_sigv4_secret",
            "claim_connected",
            "claim_native",
            "adopt_kernel_outcome",
        ] {
            if !forbidden
                .iter()
                .any(|entry| entry.as_str() == Some(required))
            {
                return Err(ContractError::Boundary("forbidden operation missing"));
            }
        }
        Ok(())
    }
}

pub fn contract_digest() -> Digest {
    Digest::parse(CONTRACT_DIGEST_HEX.to_owned()).expect("static contract digest")
}

#[cfg(test)]
mod contract_tests {
    use super::{
        AWS_NETWORK_FIREWALL_API_VERSION, AWS_NETWORK_FIREWALL_BLOCKED_ENV,
        AWS_NETWORK_FIREWALL_CONSUMER_ID, AWS_NETWORK_FIREWALL_PROVIDER_ID,
        AWS_NETWORK_FIREWALL_SERVICE_ID, AwsNetworkFirewallContract, Layer1Authority,
    };

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        AwsNetworkFirewallContract::baseline().expect("contract validates");
        assert_eq!(AWS_NETWORK_FIREWALL_API_VERSION, "2018-02-08");
        assert_eq!(
            AWS_NETWORK_FIREWALL_PROVIDER_ID,
            "aws.network-firewall.read"
        );
        assert_eq!(
            AWS_NETWORK_FIREWALL_SERVICE_ID,
            "hartevo.aws.network-firewall.posture-result"
        );
        assert_eq!(
            AWS_NETWORK_FIREWALL_CONSUMER_ID,
            "mission.aws.network-firewall.posture"
        );
        assert_eq!(AWS_NETWORK_FIREWALL_BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::effective_authorization());
        assert!(!Layer1Authority::kernel_outcome_adoption());
    }
}
