//! Standalone Layer-1 Azure Data Factory pipeline-result boundary.
//!
//! The crate exposes only bounded, typed read proposals for the three
//! allowlisted Azure Data Factory management operations. It deliberately has
//! no native HTTP client, Entra resolver, trigger/cancel/rerun path, raw
//! provider payload store, log or artifact reader, or kernel authority.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::result_large_err)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::struct_excessive_bools)]

use serde_json::Value;
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionAzureDataFactoryConsumer, MissionAzureDataFactoryConsumerError,
    MissionAzureDataFactoryResult,
};
pub use model::*;
pub use provider::{
    ActivityRunsQueryRequest, ActivityRunsQueryResponse, AzureDataFactoryOperation,
    AzureDataFactoryProvider, AzureDataFactoryProviderDefinition, AzureDataFactoryProviderError,
    AzureDataFactoryRequest, AzureDataFactoryResponse, AzureDataFactoryTransport,
    AzureDataFactoryTransportError, BlockedEnvTransport, FixtureTransport, GetPipelineRequest,
    GetPipelineResponse, GetPipelineRunRequest, GetPipelineRunResponse, LoopbackTransport,
    ProviderReadSet, ProviderTransportError, RecordedRequest, RecordingTransport,
};
pub use service::{
    AzureDataFactoryCapabilities, AzureDataFactoryEvidence, AzureDataFactoryPipelineResultEvidence,
    AzureDataFactoryPipelineResultProposal, AzureDataFactoryPipelineResultRecord,
    AzureDataFactoryPipelineResultService, AzureDataFactoryPipelineResultServiceError,
    AzureDataFactoryRegistration, RegistrationStatus, RegistrationTransitionEvidence,
    VerificationReport,
};

pub type AzureDataFactoryPipelineResultScope = AzureDataFactoryScope;
pub type AzureDataFactoryPipelineScope = AzureDataFactoryScope;
pub type AzureDataFactorySecretReference = SecretReference;
pub type AzureDataFactoryPipelineResultStatus = PipelineStatus;

pub const CONTRACT_SCHEMA: &str = "hartevo.azure-data-factory-pipeline-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AZURE-DATA-FACTORY-01-L1/v1";
pub const PLUGIN_ID: &str = "azure.data-factory.pipeline.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "azure.data-factory.pipeline.result.read";
pub const PROVIDER_ID: &str = "azure.data-factory.management";
pub const PROVIDER_VERSION: &str = "1.0.0";
pub const API_VERSION: &str = "2018-06-01";
pub const API_REVISION: &str = "azure-data-factory-pipeline-runs-get-activity-runs-query-by-pipeline-run-pipelines-get-2018-06-01-r1";
pub const CONSUMER_ID: &str = "mission.azure.data-factory.pipeline.result";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const API_ORIGIN: &str = "https://management.azure.com";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.azure-data-factory-pipeline-result/v1|layer=1|service=azure.data-factory.pipeline.result.read|provider=azure.data-factory.management|consumer=mission.azure.data-factory.pipeline.result|api=azure-data-factory-pipeline-runs-get-activity-runs-query-by-pipeline-run-pipelines-get-2018-06-01-r1";
pub const CONTRACT_DIGEST: &str =
    "827af5bbbec5f50c420017403fea68cdcb90edb5c38e2fd1144bfe85e689fab5";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/azure-data-factory-pipeline-result/azure-data-factory-pipeline-result.v1.json"
);

pub const MAX_ACTIVITY_WINDOW_DAYS: i64 = 7;
pub const MAX_PAGES: usize = 16;
pub const MAX_PAGE_SIZE: usize = 128;
pub const MAX_ACTIVITIES: usize = 512;
pub const MAX_ACTIVITY_TYPE_DIGESTS: usize = 128;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_CONTINUATION_BYTES: usize = 512;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Errors are semantic and never contain provider response bodies, raw
/// continuation tokens, credentials, logs, artifacts, or activity payloads.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AzureDataFactoryPipelineResultError {
    #[error("invalid text in {field}")]
    InvalidText { field: &'static str },
    #[error("invalid digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("invalid Project/Mission/Work Product scope")]
    InvalidScope,
    #[error("invalid activity time window")]
    InvalidActivityWindow,
    #[error("required Azure Data Factory read permission is missing")]
    MissingPermission,
    #[error("permission digest does not match its permissions")]
    PermissionDigestMismatch,
    #[error("invalid opaque SecretReference")]
    InvalidSecretReference,
    #[error("SecretReference is revoked")]
    SecretRevoked,
    #[error("registration is invalid or drifted")]
    InvalidRegistration,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("registration is not revoked")]
    RegistrationNotRevoked,
    #[error("registration is not reversed")]
    RegistrationNotReversed,
    #[error("scope binding does not match")]
    ScopeMismatch,
    #[error("provider evidence was tampered")]
    Tampered,
    #[error("provider response exceeded its bound")]
    ResponseTooLarge,
    #[error("provider activity pagination exceeded its bound")]
    PaginationLimit,
    #[error("provider activity continuation repeated")]
    PaginationLoop,
    #[error("opaque continuation binding does not match")]
    ContinuationMismatch,
    #[error("provider returned an invalid response shape")]
    InvalidProviderResponse,
    #[error("provider access was lost")]
    AccessLost,
    #[error("provider status is unknown")]
    ProviderUnknown,
    #[error("recording replay conflicts with existing evidence")]
    ReplayConflict,
    #[error("redaction boundary was violated")]
    RedactionViolation,
    #[error("contract metadata drifted")]
    ContractDrift,
    #[error("transport error: {0}")]
    Transport(#[from] provider::ProviderTransportError),
}

pub type Result<T> = std::result::Result<T, AzureDataFactoryPipelineResultError>;

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(crate) fn digest_serialized<T: serde::Serialize>(value: &T) -> model::Digest {
    model::Digest::from_bytes(
        &serde_json::to_vec(value).expect("bounded contract values must serialize"),
    )
}

/// Returns the versioned contract binding used by every registration and
/// proposal. The digest input is intentionally independent of the JSON file,
/// so it cannot be changed accidentally without changing this Rust constant.
#[must_use]
pub fn contract_digest() -> model::Digest {
    model::Digest::from_text(CONTRACT_DIGEST_INPUT)
}

/// Performs the local contract/metadata checks required before a plugin is
/// registered. This is deliberately small and deterministic; a full JSON
/// Schema validator belongs to the repository gate, not the provider seam.
pub fn validate_contract() -> Result<()> {
    let document = serde_json::from_str::<Value>(CONTRACT_JSON)
        .map_err(|_| AzureDataFactoryPipelineResultError::ContractDrift)?;
    let object = document
        .as_object()
        .ok_or(AzureDataFactoryPipelineResultError::ContractDrift)?;
    for key in [
        "$schema",
        "$id",
        "schemaVersion",
        "contractVersion",
        "pluginVersion",
        "pluginId",
        "layer",
        "evidenceLevel",
        "digestInput",
        "contractDigest",
        "typedSurface",
        "service",
        "provider",
        "consumer",
        "exactScope",
        "permissions",
        "authentication",
        "normalization",
        "bounds",
        "pagination",
        "digests",
        "registration",
        "receipts",
        "evidence",
        "forbiddenEffects",
        "nativeGap",
        "honesty",
    ] {
        if !object.contains_key(key) {
            return Err(AzureDataFactoryPipelineResultError::ContractDrift);
        }
    }
    if object.get("schemaVersion").and_then(Value::as_str) != Some(CONTRACT_SCHEMA)
        || object.get("contractVersion").and_then(Value::as_str) != Some(CONTRACT_VERSION)
        || object.get("pluginVersion").and_then(Value::as_str) != Some(PLUGIN_VERSION)
        || object.get("pluginId").and_then(Value::as_str) != Some(PLUGIN_ID)
        || object.get("layer").and_then(Value::as_u64) != Some(1)
        || object.get("evidenceLevel").and_then(Value::as_str) != Some(EVIDENCE_LEVEL)
        || object.get("digestInput").and_then(Value::as_str) != Some(CONTRACT_DIGEST_INPUT)
        || object.get("contractDigest").and_then(Value::as_str) != Some(CONTRACT_DIGEST)
        || contract_digest().as_str() != CONTRACT_DIGEST
    {
        return Err(AzureDataFactoryPipelineResultError::ContractDrift);
    }
    let authority = object
        .get("authority")
        .and_then(Value::as_object)
        .ok_or(AzureDataFactoryPipelineResultError::ContractDrift)?;
    for key in [
        "readOnly",
        "proposalOnly",
        "recordingOnly",
        "connected",
        "nativeProvider",
        "externalWrites",
        "outcomeAuthority",
    ] {
        if !authority.contains_key(key) {
            return Err(AzureDataFactoryPipelineResultError::ContractDrift);
        }
    }
    if authority.get("readOnly") != Some(&Value::Bool(true))
        || authority.get("proposalOnly") != Some(&Value::Bool(true))
        || authority.get("recordingOnly") != Some(&Value::Bool(true))
        || authority.get("connected") != Some(&Value::Bool(false))
        || authority.get("nativeProvider") != Some(&Value::Bool(false))
        || authority.get("externalWrites") != Some(&Value::Bool(false))
        || authority.get("outcomeAuthority") != Some(&Value::Bool(false))
    {
        return Err(AzureDataFactoryPipelineResultError::ContractDrift);
    }
    let provider = object
        .get("provider")
        .and_then(Value::as_object)
        .ok_or(AzureDataFactoryPipelineResultError::ContractDrift)?;
    if provider.get("id").and_then(Value::as_str) != Some(PROVIDER_ID)
        || provider.get("apiVersion").and_then(Value::as_str) != Some(API_VERSION)
        || provider.get("apiRevision").and_then(Value::as_str) != Some(API_REVISION)
        || provider.get("connected") != Some(&Value::Bool(false))
        || provider.get("nativeHttps") != Some(&Value::Bool(false))
        || provider.get("nativeEntraResolution") != Some(&Value::Bool(false))
        || provider.get("externalWrites") != Some(&Value::Bool(false))
    {
        return Err(AzureDataFactoryPipelineResultError::ContractDrift);
    }
    let service = object
        .get("service")
        .and_then(Value::as_object)
        .ok_or(AzureDataFactoryPipelineResultError::ContractDrift)?;
    if service.get("id").and_then(Value::as_str) != Some(SERVICE_ID)
        || service.get("externalWrites") != Some(&Value::Bool(false))
        || service.get("kernelAuthority") != Some(&Value::Bool(false))
    {
        return Err(AzureDataFactoryPipelineResultError::ContractDrift);
    }
    let consumer = object
        .get("consumer")
        .and_then(Value::as_object)
        .ok_or(AzureDataFactoryPipelineResultError::ContractDrift)?;
    if consumer.get("id").and_then(Value::as_str) != Some(CONSUMER_ID)
        || consumer.get("adoptsOutcome") != Some(&Value::Bool(false))
        || consumer.get("kernelAuthority") != Some(&Value::Bool(false))
    {
        return Err(AzureDataFactoryPipelineResultError::ContractDrift);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    #[must_use]
    pub const fn connected() -> bool {
        false
    }

    #[must_use]
    pub const fn native_provider() -> bool {
        false
    }

    #[must_use]
    pub const fn first_party() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_provider_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn external_writes() -> bool {
        false
    }

    #[must_use]
    pub const fn kernel_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn outcome_authority() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::{CONTRACT_DIGEST, CONTRACT_JSON, contract_digest, validate_contract};

    #[test]
    fn contract_is_versioned_layer_one_and_non_native() {
        validate_contract().expect("contract metadata is valid");
        assert_eq!(contract_digest().as_str(), CONTRACT_DIGEST);
        assert!(CONTRACT_JSON.contains("BLOCKED_ENV"));
        assert!(CONTRACT_JSON.contains("queryActivityruns"));
        assert!(CONTRACT_JSON.contains("trigger_pipeline"));
    }
}
