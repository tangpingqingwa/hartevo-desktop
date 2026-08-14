//! Standalone Layer-1 Modal FunctionCall job-result read, proposal, and
//! recording boundary.
//!
//! The crate deliberately contains no Modal SDK, HTTPS client, keyring,
//! container/sandbox control, raw result/log/file store, provider receipt, or
//! Outcome adoption path. Its transports are recording-only test seams and
//! are always non-native, non-connected, and non-first-party.

#![forbid(unsafe_code)]

use std::fmt::Write as _;

use serde::Serialize;
use sha2::{Digest as Sha2Digest, Sha256};
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    JobResultProposal, MissionModalJobConsumer, ModalJobResultRecordingLog, ProposalDisposition,
    RecordedModalJobResult,
};
pub use model::{
    AppDeploymentKind, AppIdentity, Digest, EnvironmentIdentity, FailureCode, FunctionCallIdentity,
    FunctionCallProjection, FunctionIdentity, HostIdentity, InputIdentity, JobStatus,
    MissionIdentity, ModalScope, PermissionSnapshot, PluginVersion, ProjectIdentity,
    ProjectionCompleteness, RegistrationId, RegistrationStatus, ResultEvidence, RetryPolicy,
    SecretKind, SecretReference, TransportProvenance, UsageEvidence, WorkProductIdentity,
    WorkspaceIdentity,
};
pub use provider::{
    BlockedEnvTransport, FakeTransport, FunctionHandle, FunctionLookupRequest,
    FunctionLookupResponse, LoopbackTransport, ModalHttpStatus, ModalProvider, ModalProviderError,
    ModalTransport, ModalTransportError, PollRequest, ProviderCallResponse, RecordedRequest,
    RecordedRequestKind, RecordingTransport, SpawnRequest,
};
pub use service::{
    CapabilityDescription, ModalJobResultService, ModalRegistration, ModalRegistrationRegistry,
    ProviderIdentity, RegistrationReceipt, ScopeDescription,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.modal-job-result-contract/v1";
pub const CONTRACT_VERSION: &str = "modal-job-result-01-layer-1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.modal-job-result-contract/v1|layer=1|service=modal.job-result.read|provider=modal.cloud.job-result.recording|consumer=mission.modal-job-result.consumer";
pub const CONTRACT_DIGEST: &str =
    "fee180888ece9a56cd55eb36179de450faa221465041270db456ad7e1115c554";
pub const PLUGIN_ID: &str = "modal.job-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "modal.job-result.read";
pub const PROVIDER_ID: &str = "modal.cloud.job-result.recording";
pub const PROVIDER_API_REVISION: &str = "modal-function-call-read-1";
pub const CONSUMER_ID: &str = "mission.modal-job-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/modal-job-result/contract.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_SERIALIZED_INPUT_BYTES: u64 = 64 * 1024;
pub const MAX_CAPTURED_RESULT_BYTES: u64 = 64 * 1024;
pub const MAX_SERIALIZED_RESULT_BYTES: u64 = 64 * 1024;
pub const MAX_REPORTED_RESULT_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_EVIDENCE_BYTES: u64 = 1024 * 1024;
pub const MAX_RUNTIME_MILLIS: u64 = 7 * 24 * 60 * 60 * 1000;
pub const MAX_POLL_ATTEMPTS: u8 = 16;
pub const MAX_RETRY_ATTEMPTS: u8 = 8;
pub const MAX_BACKOFF_MILLIS: u64 = 60_000;
pub const MAX_FUNCTION_TIMEOUT_MILLIS: u64 = 24 * 60 * 60 * 1000;
pub const RESULT_EXPIRY_SECONDS: u64 = 7 * 24 * 60 * 60;

/// A safe Layer-1 failure. Variants carry bounded classification only; no
/// provider response body, log line, credential, or file path is retained.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModalJobResultError {
    #[error("invalid text in {field}")]
    InvalidText { field: &'static str },
    #[error("invalid identifier in {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("invalid HTTPS host")]
    InvalidHttpsHost,
    #[error("invalid opaque SecretReference")]
    InvalidSecretReference,
    #[error("invalid exact Modal scope")]
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
    #[error("registration/provider/permission/scope binding drifted")]
    RegistrationDrift,
    #[error("scope does not match the exact registered Modal scope")]
    ScopeMismatch,
    #[error("Modal host identity drifted")]
    HostDrift,
    #[error("Modal Workspace identity drifted")]
    WorkspaceDrift,
    #[error("Modal App deployment identity drifted")]
    AppDrift,
    #[error("Modal Function identity drifted")]
    FunctionDrift,
    #[error("Modal Environment identity drifted")]
    EnvironmentDrift,
    #[error("Modal FunctionCall identity drifted")]
    CallDrift,
    #[error("serialized input identity drifted")]
    InputDrift,
    #[error("retry policy identity drifted")]
    RetryDrift,
    #[error("Mission identity or revision drifted")]
    MissionDrift,
    #[error("Project identity or revision drifted")]
    ProjectDrift,
    #[error("Work Product identity or revision drifted")]
    WorkProductDrift,
    #[error("Mission revision is stale")]
    StaleMissionRevision,
    #[error("ephemeral Modal App lookup is refused")]
    EphemeralAppLookup,
    #[error("Modal App is not deployed")]
    AppNotDeployed,
    #[error("function call is already terminal")]
    CallAlreadyTerminal,
    #[error("bounded poll limit was reached")]
    PollLimitExceeded,
    #[error("poll backoff exceeded its bound")]
    PollBackoffExceeded,
    #[error("result or serialized input exceeded its bound")]
    ResultTooLarge,
    #[error("provider response exceeded its byte bound")]
    ResponseTooLarge,
    #[error("serialization evidence exceeded its byte bound")]
    SerializationLimit,
    #[error("evidence is truncated and cannot be complete")]
    TruncatedEvidence,
    #[error("evidence is redacted and cannot be adopted")]
    RedactedEvidence,
    #[error("provider evidence was tampered")]
    TamperedEvidence,
    #[error("recording idempotency key was replayed with different evidence")]
    ReplayConflict,
    #[error("provider access was lost")]
    AccessLost,
    #[error("secret reference was revoked")]
    SecretRevoked,
    #[error("provider error: {0}")]
    Provider(#[from] ModalProviderError),
    #[error("transport error: {0}")]
    Transport(#[from] ModalTransportError),
}

pub type Result<T> = std::result::Result<T, ModalJobResultError>;

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

pub(crate) fn digest_serialized<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("contract values must serialize");
    sha256_hex(&bytes)
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(crate) fn validate_text(value: &str, field: &'static str, max_bytes: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(ModalJobResultError::InvalidText { field })
    } else {
        Ok(())
    }
}

pub(crate) fn validate_identifier(value: &str, field: &'static str) -> Result<()> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES)
}

pub(crate) fn validate_digest(value: &str, field: &'static str) -> Result<()> {
    if valid_digest(value) {
        Ok(())
    } else {
        Err(ModalJobResultError::InvalidDigest { field })
    }
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

#[cfg(test)]
mod contract_tests {
    use serde::Deserialize;

    use super::{
        CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION,
        EVIDENCE_LEVEL, PLUGIN_ID, contract_digest,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        plugin_id: String,
        layer: u8,
        evidence_level: String,
        digest_input: String,
        contract_digest: String,
    }

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract = serde_json::from_str::<ContractDocument>(CONTRACT_JSON)
            .expect("checked Modal contract");
        assert_eq!(contract.schema_version, CONTRACT_SCHEMA);
        assert_eq!(contract.contract_version, CONTRACT_VERSION);
        assert_eq!(contract.plugin_id, PLUGIN_ID);
        assert_eq!(contract.layer, 1);
        assert_eq!(contract.evidence_level, EVIDENCE_LEVEL);
        assert_eq!(contract.digest_input, CONTRACT_DIGEST_INPUT);
        assert_eq!(contract.contract_digest, CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
    }
}
