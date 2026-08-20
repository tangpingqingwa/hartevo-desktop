//! Standalone Layer-1 AWS CloudFormation drift evidence boundary.
//!
//! This crate owns only bounded, typed CloudFormation reads, digest fences,
//! reversible registration, redacted proposal/recording seams, and a
//! Mission-scoped non-authoritative consumer. Recording, fixture, loopback,
//! and `BLOCKED_ENV` transports are always non-connected, non-native, and
//! non-first-party. There is no stack mutation, template/property retention,
//! remediation, credential resolution, or child layer.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionAwsCloudFormationConsumer, MissionAwsCloudFormationDriftConsumer,
    MissionAwsCloudFormationDriftConsumerResult, MissionAwsCloudFormationDriftResult,
    MissionAwsCloudFormationResult, ProposalDisposition,
};
pub use error::{
    AwsCloudFormationDriftError, AwsCloudFormationError, AwsCloudFormationTransportError, Result,
};
pub use model::*;
pub use provider::{
    AwsCloudFormationOperation, AwsCloudFormationProvider, AwsCloudFormationProviderDefinition,
    AwsCloudFormationProviderDefinitionError, AwsCloudFormationProviderError,
    AwsCloudFormationTransport, BlockedEnvAwsCloudFormationTransport, BlockedEnvTransport,
    FixtureTransport, LoopbackTransport, ProviderProvenance, QueuedTransport, RecordedRequest,
    RecordedRequestKind, RecordingTransport,
};
pub use service::{
    AwsCloudFormationDriftProposal, AwsCloudFormationDriftRegistration,
    AwsCloudFormationDriftResultService, AwsCloudFormationDriftService, AwsCloudFormationProposal,
    AwsCloudFormationRecordReceipt, AwsCloudFormationRegistration,
    AwsCloudFormationRegistrationReceipt, AwsCloudFormationService, AwsCloudFormationServiceError,
    CapabilityDescription, CloudFormationDriftProposal, CloudFormationDriftRegistration,
    CloudFormationVerificationReport, RecordedAwsCloudFormationDriftResult, RegistrationStatus,
    RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-cloudformation-drift-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-CLOUDFORMATION-DRIFT-01-L1/v1";
pub const PLUGIN_ID: &str = "aws.cloudformation.drift-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.cloudformation.drift-result.read";
pub const PROVIDER_ID: &str = "aws.cloudformation.drift-result.recording";
pub const PROVIDER_API_REVISION: &str = "cloudformation-describe-stacks-describe-stack-events-detect-stack-drift-describe-stack-drift-detection-status-describe-stack-resource-drifts-1";
pub const CONSUMER_ID: &str = "mission.aws-cloudformation-drift.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-cloudformation-drift-result/v1|layer=1|service=aws.cloudformation.drift-result.read|provider=aws.cloudformation.drift-result.recording|consumer=mission.aws-cloudformation-drift.consumer";
pub const CONTRACT_DIGEST: &str =
    "40b171d684c1a1ece03529d55b32df946e5ac52d216427e863e8318ad12cce06";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-cloudformation-drift-result/contract.v1.json");

pub const LAYER1_PERMISSIONS: [&str; 6] = [
    "cloudformation:DescribeStacks",
    "cloudformation:DescribeStackEvents",
    "cloudformation:DetectStackDrift",
    "cloudformation:DescribeStackDriftDetectionStatus",
    "cloudformation:DescribeStackResourceDrifts",
    "mission.scope",
];

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_LOGICAL_RESOURCE_IDS: usize = 200;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_POLLS: u16 = 4;
pub const MAX_EVENTS: usize = 256;
pub const MAX_RESOURCES: usize = 512;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_RESPONSE_BYTES_USIZE: usize = 1024 * 1024;
pub const MAX_RETRIES: u8 = 2;

pub const AWS_CLOUDFORMATION_DRIFT_SCHEMA_VERSION: &str = CONTRACT_SCHEMA;
pub const AWS_CLOUDFORMATION_DRIFT_CONTRACT_VERSION: &str = CONTRACT_VERSION;
pub const AWS_CLOUDFORMATION_DRIFT_PLUGIN_VERSION: &str = PLUGIN_VERSION;
pub const AWS_CLOUDFORMATION_DRIFT_SERVICE_ID: &str = SERVICE_ID;
pub const AWS_CLOUDFORMATION_DRIFT_PROVIDER_ID: &str = PROVIDER_ID;
pub const AWS_CLOUDFORMATION_DRIFT_CONSUMER_ID: &str = CONSUMER_ID;
pub const AWS_CLOUDFORMATION_DRIFT_API_REVISION: &str = PROVIDER_API_REVISION;
pub const AWS_CLOUDFORMATION_BLOCKED_ENV: &str = "BLOCKED_ENV";

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

pub fn api_digest() -> Digest {
    Digest::from_parts(
        "aws-cloudformation-api/v1",
        &LAYER1_PERMISSIONS
            .iter()
            .map(|permission| ("permission", (*permission).to_owned()))
            .collect::<Vec<_>>(),
    )
}

pub fn plugin_version() -> (u16, u16, u16) {
    (1, 0, 0)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsCloudFormationDriftContract {
    value: serde_json::Value,
}

impl AwsCloudFormationDriftContract {
    pub fn baseline() -> std::result::Result<Self, AwsCloudFormationContractError> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|error| AwsCloudFormationContractError::InvalidJson(error.to_string()))?;
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

    pub fn validate(&self) -> std::result::Result<(), AwsCloudFormationContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(AwsCloudFormationContractError::Shape(
                "contract is not an object",
            ))?;
        for key in [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginId",
            "layer",
            "service",
            "provider",
            "consumer",
            "credentials",
            "scope",
            "registration",
            "pagination",
            "evidence",
            "provenance",
            "authorityBoundary",
            "layer2Gaps",
        ] {
            if !object.contains_key(key) {
                return Err(AwsCloudFormationContractError::Shape(
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
            || object.get("layer").and_then(serde_json::Value::as_u64) != Some(1)
            || object
                .get("contractDigest")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST)
            || object
                .get("digestInput")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST_INPUT)
        {
            return Err(AwsCloudFormationContractError::Identity(
                "contract identity drifted",
            ));
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCloudFormationContractError::Shape(
                "service is not an object",
            ))?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("recordingOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || service.get("kernelAuthority") != Some(&serde_json::Value::Bool(false))
            || service.get("outcomeAdoption") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsCloudFormationContractError::Boundary(
                "service authority widened",
            ));
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCloudFormationContractError::Shape(
                "provider is not an object",
            ))?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(PROVIDER_API_REVISION)
            || provider.get("connectedEvidence") != Some(&serde_json::Value::Bool(false))
            || provider.get("nativeEvidence") != Some(&serde_json::Value::Bool(false))
            || provider.get("providerReceipt") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsCloudFormationContractError::Boundary(
                "provider authority widened",
            ));
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCloudFormationContractError::Shape(
                "consumer is not an object",
            ))?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsCloudFormationContractError::Boundary(
                "consumer authority widened",
            ));
        }
        let credentials = object
            .get("credentials")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCloudFormationContractError::Shape(
                "credentials is not an object",
            ))?;
        if credentials.get("serialized") != Some(&serde_json::Value::Bool(false))
            || credentials.get("rawMaterialAccepted") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsCloudFormationContractError::Boundary(
                "credential boundary widened",
            ));
        }
        let evidence = object
            .get("evidence")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCloudFormationContractError::Shape(
                "evidence is not an object",
            ))?;
        for key in [
            "tamperRejected",
            "revocationRejected",
            "rawPropertiesAreNeverRetained",
        ] {
            if evidence.get(key) != Some(&serde_json::Value::Bool(true)) {
                return Err(AwsCloudFormationContractError::Boundary(
                    "evidence safety fence widened",
                ));
            }
        }
        let provenance = object
            .get("provenance")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCloudFormationContractError::Shape(
                "provenance is not an object",
            ))?;
        for key in [
            "connectedClaim",
            "nativeClaim",
            "firstPartyClaim",
            "providerReceipt",
        ] {
            if provenance.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(AwsCloudFormationContractError::Boundary(
                    "provenance claim widened",
                ));
            }
        }
        let forbidden = object
            .get("registration")
            .and_then(serde_json::Value::as_object)
            .and_then(|value| value.get("forbiddenPermissions"))
            .and_then(serde_json::Value::as_array)
            .ok_or(AwsCloudFormationContractError::Shape(
                "forbidden permission list missing",
            ))?;
        for required in [
            "cloudformation:CreateStack",
            "cloudformation:UpdateStack",
            "cloudformation:DeleteStack",
            "cloudformation:ExecuteChangeSet",
            "outcome.adopt",
        ] {
            if !forbidden
                .iter()
                .any(|entry| entry.as_str() == Some(required))
            {
                return Err(AwsCloudFormationContractError::Boundary(
                    "forbidden mutation permission missing",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum AwsCloudFormationContractError {
    #[error("AWS CloudFormation contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("AWS CloudFormation contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("AWS CloudFormation contract identity is invalid: {0}")]
    Identity(&'static str),
    #[error("AWS CloudFormation contract authority boundary is invalid: {0}")]
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

    pub const fn provider_receipt() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }

    pub const fn raw_properties() -> bool {
        false
    }

    pub const fn remediation() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_in_contract_matches_typed_boundary() {
        let contract = AwsCloudFormationDriftContract::baseline().expect("contract");
        assert_eq!(contract.digest().as_str(), CONTRACT_DIGEST);
        assert_eq!(contract_digest().as_str(), CONTRACT_DIGEST);
        assert_eq!(plugin_version(), (1, 0, 0));
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::provider_receipt());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::raw_properties());
        assert!(!Layer1Authority::remediation());
    }
}
