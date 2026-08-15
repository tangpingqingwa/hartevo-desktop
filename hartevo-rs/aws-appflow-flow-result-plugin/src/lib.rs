//! Standalone Layer-1 AWS AppFlow flow-execution result boundary.
//!
//! The crate owns only typed, bounded ListFlows/DescribeFlow/
//! DescribeFlowExecutionRecords projections and deterministic
//! read/proposal/record/verify behavior. It has no native HTTP client, live
//! SigV4 resolver, flow effect, source/target record access, kernel authority,
//! provider receipt, or Work Product adoption authority.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionAwsAppFlowConsumer, MissionAwsAppFlowResult, ProposalDisposition,
    RecordedAwsAppFlowResult,
};
pub use error::{AwsAppFlowResultError, AwsAppFlowTransportError, Result};
pub use model::*;
pub use provider::{
    AwsAppFlowProvider, AwsAppFlowProviderDefinition, AwsAppFlowTransport, BlockedEnvTransport,
    FixtureTransport, LoopbackTransport, RecordedRequest, RecordingTransport,
};
pub use service::{
    AwsAppFlowRegistration, AwsAppFlowResultProposal, AwsAppFlowResultService,
    CapabilityDescription, DecisionProposal, ReadLimits, RegistrationStatus,
    RegistrationTransitionEvidence, RetryEvidence, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-appflow-flow-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-APPFLOW-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-appflow-flow-result/v1|layer=1|service=aws.appflow.flow-result.read|provider=aws.appflow.flow-result.recording|consumer=mission.aws-appflow-flow-result.consumer";
pub const CONTRACT_DIGEST: &str =
    "ed9d6f03f4d9b4694e56af960ce13056e4fd6f50b427f1d6aa5c71c9aa7c1e73";
pub const PLUGIN_ID: &str = "aws.appflow.flow-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.appflow.flow-result.read";
pub const PROVIDER_ID: &str = "aws.appflow.flow-result.recording";
pub const PROVIDER_API_REVISION: &str =
    "appflow-list-flows-describe-flow-describe-flow-execution-records-1";
pub const CONSUMER_ID: &str = "mission.aws-appflow-flow-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-appflow-flow-result/contract.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
pub const MAX_COUNTER_VALUE: u64 = 1_000_000_000_000;

pub fn contract_digest() -> model::Digest {
    model::Digest::from_text(CONTRACT_DIGEST_INPUT)
}

/// Validate the checked-in versioned contract without consulting host wiring.
pub fn validate_contract() -> Result<()> {
    let document: Value =
        serde_json::from_str(CONTRACT_JSON).map_err(|_| AwsAppFlowResultError::ContractInvalid)?;
    let expected = [
        ("schemaVersion", CONTRACT_SCHEMA),
        ("contractVersion", CONTRACT_VERSION),
        ("pluginId", PLUGIN_ID),
        ("evidenceLevel", EVIDENCE_LEVEL),
    ];
    for (field, value) in expected {
        if document.get(field) != Some(&Value::String(value.to_owned())) {
            return Err(AwsAppFlowResultError::ContractInvalid);
        }
    }
    if document.get("layer") != Some(&Value::from(1))
        || document.get("digestInput") != Some(&Value::String(CONTRACT_DIGEST_INPUT.to_owned()))
        || document.get("contractDigest")
            != Some(&Value::String(contract_digest().as_str().to_owned()))
        || CONTRACT_DIGEST != contract_digest().as_str()
    {
        return Err(AwsAppFlowResultError::ContractInvalid);
    }
    let service = document
        .get("service")
        .ok_or(AwsAppFlowResultError::ContractInvalid)?;
    let provider = document
        .get("provider")
        .ok_or(AwsAppFlowResultError::ContractInvalid)?;
    let consumer = document
        .get("consumer")
        .ok_or(AwsAppFlowResultError::ContractInvalid)?;
    if service.get("id") != Some(&Value::String(SERVICE_ID.to_owned()))
        || provider.get("id") != Some(&Value::String(PROVIDER_ID.to_owned()))
        || provider.get("apiRevision") != Some(&Value::String(PROVIDER_API_REVISION.to_owned()))
        || consumer.get("id") != Some(&Value::String(CONSUMER_ID.to_owned()))
        || service.get("externalWrites") != Some(&Value::Bool(false))
        || provider.get("connectedEvidence") != Some(&Value::Bool(false))
        || provider.get("nativeEvidence") != Some(&Value::Bool(false))
        || provider.get("firstPartyEvidence") != Some(&Value::Bool(false))
    {
        return Err(AwsAppFlowResultError::ContractInvalid);
    }
    let operations = provider
        .get("operations")
        .and_then(Value::as_array)
        .ok_or(AwsAppFlowResultError::ContractInvalid)?;
    let expected_operations = [
        "appflow:ListFlows",
        "appflow:DescribeFlow",
        "appflow:DescribeFlowExecutionRecords",
    ];
    if operations
        .iter()
        .map(Value::as_str)
        .ne(expected_operations.iter().copied().map(Some))
    {
        return Err(AwsAppFlowResultError::ContractInvalid);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginDescriptor {
    pub plugin_id: String,
    pub version: String,
    pub contract_version: String,
    pub contract_digest: model::Digest,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
}

pub fn plugin_descriptor() -> PluginDescriptor {
    PluginDescriptor {
        plugin_id: PLUGIN_ID.to_owned(),
        version: PLUGIN_VERSION.to_owned(),
        contract_version: CONTRACT_VERSION.to_owned(),
        contract_digest: contract_digest(),
        service_id: SERVICE_ID.to_owned(),
        provider_id: PROVIDER_ID.to_owned(),
        consumer_id: CONSUMER_ID.to_owned(),
    }
}
