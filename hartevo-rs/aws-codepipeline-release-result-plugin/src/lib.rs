//! Standalone Layer-1 AWS CodePipeline release-result boundary.
//!
//! The crate owns typed scope, bounded read seams, redacted metadata, digest
//! fences, reversible registration, proposal, and Mission-scoped recording.
//! It deliberately does not resolve or sign SigV4 credentials, claim native
//! or connected evidence, mutate CodePipeline, retain raw logs/artifacts/
//! secrets, or adopt Hartevo kernel Outcome authority.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

use std::fmt::Write as _;

use serde::Serialize;
use sha2::{Digest as Sha2Digest, Sha256};
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    AwsCodePipelineRecordingLog, MissionAwsCodePipelineConsumer, MissionAwsCodePipelineResult,
    ProposalDisposition, RecordedAwsCodePipelineResult,
};
pub use model::*;
pub use provider::{
    ActionExecutionPage, AwsCodePipelineProvider, AwsCodePipelineProviderError,
    AwsCodePipelineTransport, BlockedEnvAwsCodePipelineTransport, BlockedEnvTransport,
    FakeAwsCodePipelineTransport, FakeTransport, FixtureAwsCodePipelineTransport,
    GetPipelineExecutionRequest, GetPipelineStateRequest, ListActionExecutionsRequest,
    ListPipelineExecutionsRequest, LoopbackAwsCodePipelineTransport, LoopbackTransport,
    PipelineExecutionPage, PipelineExecutionResponse, PipelineStateResponse, RecordedRequest,
    RecordingAwsCodePipelineTransport, RecordingTransport,
};
pub use service::{
    AwsCodePipelineCapabilityDescription, AwsCodePipelineReadRequest, AwsCodePipelineRegistration,
    AwsCodePipelineRegistrationReceipt, AwsCodePipelineRegistrationRegistry,
    AwsCodePipelineReleaseEvidence, AwsCodePipelineReleaseProposal,
    AwsCodePipelineReleaseResultService, AwsCodePipelineReleaseService,
    AwsCodePipelineVerificationFailure, AwsCodePipelineVerificationReport, CapabilityDescription,
    RegistrationReceipt, RegistrationStatus, RegistrationTransitionEvidence,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-codepipeline-release-result.contract/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-CODEPIPELINE-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-codepipeline-release-result.contract/v1|layer=1|service=aws.codepipeline.release-result.read|provider=aws.codepipeline.release-result.recording|consumer=mission.aws-codepipeline-release-result.consumer";
pub const CONTRACT_DIGEST: &str =
    "a03812002cd3f80f47091831a408058502fae215dd429ad1f53ffc00e0024555";
pub const PLUGIN_ID: &str = "aws.codepipeline.release-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.codepipeline.release-result.read";
pub const PROVIDER_ID: &str = "aws.codepipeline.release-result.recording";
pub const PROVIDER_API_REVISION: &str = "aws-codepipeline-release-read-r1";
pub const CONSUMER_ID: &str = "mission.aws-codepipeline-release-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-codepipeline-release-result/contract.v1.json");

pub const MAX_PAGE_SIZE: usize = 50;
pub const MAX_PAGES: usize = 4;
pub const MAX_PIPELINE_EXECUTIONS: usize = 128;
pub const MAX_ACTION_EXECUTIONS: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_SECRET_REFERENCE_BYTES: usize = 512;
pub const MAX_RETRIES: u8 = 2;

/// Provider failures retain only typed status/category metadata. Provider
/// response bodies, raw error strings, headers, credentials, and tokens are
/// intentionally not representable here.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsCodePipelineTransportError {
    #[error("BLOCKED_ENV: AWS CodePipeline native transport is disabled")]
    BlockedEnv,
    #[error("AWS CodePipeline returned client status {status}")]
    ClientError { status: u16 },
    #[error("AWS CodePipeline request was invalid")]
    BadRequest,
    #[error("AWS CodePipeline credentials were not authorized")]
    Unauthorized,
    #[error("AWS CodePipeline access was forbidden")]
    Forbidden,
    #[error("AWS CodePipeline pipeline or execution was not found")]
    NotFound,
    #[error("AWS CodePipeline request conflicted with provider state")]
    Conflict,
    #[error("AWS CodePipeline request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS CodePipeline provider returned server status {status}")]
    ServerError { status: u16 },
    #[error("AWS CodePipeline transport timed out")]
    Timeout,
    #[error("AWS CodePipeline access was lost while reading evidence")]
    AccessLost,
    #[error("AWS CodePipeline returned a partial response")]
    Partial,
    #[error("AWS CodePipeline response was invalid")]
    InvalidResponse,
    #[error("AWS CodePipeline recording transport is out of scripted responses")]
    Unavailable,
}

impl AwsCodePipelineTransportError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::ClientError { status } | Self::ServerError { status } => Some(*status),
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::BlockedEnv
            | Self::Timeout
            | Self::AccessLost
            | Self::Partial
            | Self::InvalidResponse
            | Self::Unavailable => None,
        }
    }

    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::Forbidden | Self::AccessLost
        )
    }

    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::ServerError { .. } | Self::Timeout | Self::Unavailable
        )
    }
}

/// Semantic errors are bounded and contain no provider body or secret data.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsCodePipelineReleaseError {
    #[error("invalid text in {field}")]
    InvalidText { field: &'static str },
    #[error("invalid identifier in {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("invalid positive revision in {field}")]
    InvalidRevision { field: &'static str },
    #[error("invalid opaque non-serializing SigV4 SecretReference")]
    InvalidSecretReference,
    #[error("invalid exact AWS CodePipeline/Mission scope")]
    InvalidScope,
    #[error("invalid read-only permission snapshot")]
    InvalidPermissionSnapshot,
    #[error("invalid registration binding")]
    InvalidRegistration,
    #[error("registration already exists")]
    RegistrationAlreadyExists,
    #[error("registration is unknown")]
    RegistrationUnknown,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("registration is not active")]
    RegistrationInactive,
    #[error("registration, version, contract, provider, scope, or permission fence drifted")]
    RegistrationDrift,
    #[error("provider definition drifted")]
    ProviderDrift,
    #[error("contract definition drifted")]
    ContractDrift,
    #[error("exact scope does not match")]
    ScopeMismatch,
    #[error("list filter does not match its bound scope")]
    FilterMismatch,
    #[error("pagination cursor does not match the bound filter")]
    CursorMismatch,
    #[error("response request binding does not match the request")]
    RequestBindingMismatch,
    #[error("provider page or response was tampered")]
    PageTampered,
    #[error("provider response exceeded its byte bound")]
    ResponseTooLarge,
    #[error("provider pagination exceeded its bound")]
    PaginationLimit,
    #[error("provider pagination cursor repeated")]
    PaginationLoop,
    #[error("provider returned an out-of-scope entry")]
    OutOfScope,
    #[error("the bound execution was replaced")]
    ExecutionReplaced,
    #[error("the bound stage or action was replaced")]
    StageActionReplaced,
    #[error("provider evidence was truncated and is review-only")]
    TruncatedEvidence,
    #[error("provider evidence redaction boundary was violated")]
    RedactionViolation,
    #[error("proposal is invalid")]
    InvalidProposal,
    #[error("recording idempotency key was replayed with different evidence")]
    ReplayConflict,
    #[error("opaque SecretReference is revoked")]
    SecretRevoked,
    #[error("provider error: {0}")]
    Transport(#[from] AwsCodePipelineTransportError),
}

pub type Result<T> = std::result::Result<T, AwsCodePipelineReleaseError>;

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

pub(crate) fn digest_serialized<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("bounded contract values must serialize");
    sha256_hex(&bytes)
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
    allow_internal_whitespace: bool,
) -> Result<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
        || (!allow_internal_whitespace && value.chars().any(char::is_whitespace))
    {
        Err(AwsCodePipelineReleaseError::InvalidText { field })
    } else {
        Ok(())
    }
}

pub(crate) fn validate_identifier(value: &str, field: &'static str) -> Result<()> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES, false)?;
    if value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'+' | b'=' | b'@')
    }) {
        Ok(())
    } else {
        Err(AwsCodePipelineReleaseError::InvalidIdentifier { field })
    }
}

pub(crate) fn validate_revision(value: u64, field: &'static str) -> Result<()> {
    if value == 0 {
        Err(AwsCodePipelineReleaseError::InvalidRevision { field })
    } else {
        Ok(())
    }
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

/// Checked contract document used by the runtime and contract gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsCodePipelineContract {
    value: serde_json::Value,
}

impl AwsCodePipelineContract {
    pub fn baseline() -> std::result::Result<Self, AwsCodePipelineContractError> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|error| AwsCodePipelineContractError::InvalidJson(error.to_string()))?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    pub fn digest(&self) -> String {
        contract_digest()
    }

    pub fn validate(&self) -> std::result::Result<(), AwsCodePipelineContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(AwsCodePipelineContractError::Shape(
                "contract is not an object",
            ))?;
        for key in [
            "$schema",
            "schemaVersion",
            "contractVersion",
            "pluginId",
            "layer",
            "evidenceLevel",
            "digestInput",
            "contractDigest",
            "service",
            "provider",
            "consumer",
            "credentials",
            "scope",
            "registration",
            "bounds",
            "evidence",
            "provenance",
            "authorityBoundary",
            "forbidden",
            "honestNativeGap",
        ] {
            if !object.contains_key(key) {
                return Err(AwsCodePipelineContractError::Shape(
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
                .get("evidenceLevel")
                .and_then(serde_json::Value::as_str)
                != Some(EVIDENCE_LEVEL)
            || object
                .get("digestInput")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST_INPUT)
            || object
                .get("contractDigest")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST)
        {
            return Err(AwsCodePipelineContractError::Identity(
                "contract identity drifted",
            ));
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCodePipelineContractError::Shape(
                "service is not an object",
            ))?;
        if service.get("type").and_then(serde_json::Value::as_str)
            != Some("AwsCodePipelineReleaseService")
            || service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("access").and_then(serde_json::Value::as_str) != Some("read_only")
        {
            return Err(AwsCodePipelineContractError::Boundary(
                "service widened beyond read-only",
            ));
        }
        let expected_service_operations = [
            "describe_capabilities",
            "register_scope",
            "revoke_registration",
            "reverse_registration",
            "read_bounded",
            "propose",
            "record",
            "verify",
        ];
        if service
            .get("operations")
            .and_then(serde_json::Value::as_array)
            .is_none_or(|operations| {
                operations.len() != expected_service_operations.len()
                    || operations
                        .iter()
                        .zip(expected_service_operations)
                        .any(|(actual, expected)| actual.as_str() != Some(expected))
            })
        {
            return Err(AwsCodePipelineContractError::Identity(
                "service operations drifted",
            ));
        }
        let expected_provider_operations = [
            "GetPipelineState",
            "GetPipelineExecution",
            "ListPipelineExecutions",
            "ListActionExecutions",
        ];
        if service
            .get("providerOperations")
            .and_then(serde_json::Value::as_array)
            .is_none_or(|operations| {
                operations.len() != expected_provider_operations.len()
                    || operations
                        .iter()
                        .zip(expected_provider_operations)
                        .any(|(actual, expected)| actual.as_str() != Some(expected))
            })
        {
            return Err(AwsCodePipelineContractError::Identity(
                "provider operations drifted",
            ));
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCodePipelineContractError::Shape(
                "provider is not an object",
            ))?;
        if provider.get("type").and_then(serde_json::Value::as_str)
            != Some("AwsCodePipelineProvider")
            || provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(PROVIDER_API_REVISION)
        {
            return Err(AwsCodePipelineContractError::Identity(
                "provider identity drifted",
            ));
        }
        let allowed_provenance = provider
            .get("allowedTransportProvenance")
            .and_then(serde_json::Value::as_array)
            .ok_or(AwsCodePipelineContractError::Shape(
                "provider provenance missing",
            ))?;
        if *allowed_provenance
            != [
                serde_json::Value::String("recording".to_owned()),
                serde_json::Value::String("fixture".to_owned()),
                serde_json::Value::String("loopback".to_owned()),
                serde_json::Value::String("blocked_env".to_owned()),
            ]
        {
            return Err(AwsCodePipelineContractError::Boundary(
                "transport provenance widened",
            ));
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCodePipelineContractError::Shape(
                "consumer is not an object",
            ))?;
        if consumer.get("type").and_then(serde_json::Value::as_str)
            != Some("MissionAwsCodePipelineConsumer")
            || consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsCodePipelineContractError::Boundary(
                "consumer authority widened",
            ));
        }
        let credentials = object
            .get("credentials")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCodePipelineContractError::Shape(
                "credentials are not an object",
            ))?;
        if credentials.get("serialized") != Some(&serde_json::Value::Bool(false))
            || credentials.get("rawMaterialAccepted") != Some(&serde_json::Value::Bool(false))
            || credentials.get("kind").and_then(serde_json::Value::as_str) != Some("sigv4")
        {
            return Err(AwsCodePipelineContractError::Boundary(
                "credential boundary widened",
            ));
        }
        let mutations = provider
            .get("mutations")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCodePipelineContractError::Shape(
                "provider mutation boundary missing",
            ))?;
        for key in [
            "StartPipelineExecution",
            "StopPipelineExecution",
            "UpdatePipeline",
            "artifactDownload",
            "rawLogs",
            "resolveCredential",
        ] {
            if mutations.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(AwsCodePipelineContractError::Boundary(
                    "provider mutation boundary widened",
                ));
            }
        }
        let forbidden = object
            .get("forbidden")
            .and_then(serde_json::Value::as_array)
            .ok_or(AwsCodePipelineContractError::Shape(
                "forbidden list missing",
            ))?;
        for required in [
            "StartPipelineExecution",
            "StopPipelineExecution",
            "UpdatePipeline",
            "download_artifact",
            "read_raw_logs",
            "serialize_secret_material",
            "adopt_kernel_outcome",
        ] {
            if !forbidden
                .iter()
                .any(|entry| entry.as_str() == Some(required))
            {
                return Err(AwsCodePipelineContractError::Boundary(
                    "forbidden operation missing",
                ));
            }
        }
        Ok(())
    }
}

pub type AwsCodePipelineReleaseContract = AwsCodePipelineContract;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsCodePipelineContractError {
    #[error("AWS CodePipeline contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("AWS CodePipeline contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("AWS CodePipeline contract identity is invalid: {0}")]
    Identity(&'static str),
    #[error("AWS CodePipeline contract boundary is invalid: {0}")]
    Boundary(&'static str),
}

#[cfg(test)]
mod contract_tests {
    use super::{
        BLOCKED_ENV, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA,
        CONTRACT_VERSION, EVIDENCE_LEVEL, PLUGIN_ID, contract_digest,
    };

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract = super::AwsCodePipelineContract::baseline().expect("checked contract");
        assert_eq!(contract.digest(), CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert_eq!(contract.value()["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(contract.value()["contractVersion"], CONTRACT_VERSION);
        assert_eq!(contract.value()["pluginId"], PLUGIN_ID);
        assert_eq!(contract.value()["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(contract.value()["digestInput"], CONTRACT_DIGEST_INPUT);
        assert!(CONTRACT_JSON.contains(BLOCKED_ENV));
        assert!(!CONTRACT_JSON.contains("REPLACED"));
        assert_eq!(contract.value()["layer"], 1);
    }
}
