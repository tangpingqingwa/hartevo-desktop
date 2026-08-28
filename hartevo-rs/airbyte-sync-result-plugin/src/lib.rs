//! Layer-1 Airbyte Cloud sync-result read, proposal, and recording boundary.
//!
//! This crate is intentionally standalone. It owns typed scope and provider
//! evidence only: no HTTP client, keyring, live sync effect, raw record store,
//! Hartevo kernel authority, or Outcome adoption path is present. Recording,
//! fake, loopback, and `BLOCKED_ENV` transports are all explicitly non-native
//! and non-connected.

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
    AirbyteSyncResultProposal, MissionAirbyteSyncConsumer, ProposalDisposition, RecordedSyncResult,
    SyncResultRecordingLog,
};
pub use model::{
    AirbyteScope, AttemptIdentity, CatalogEntry, CatalogProjection, ConnectionIdentity,
    DestinationIdentity, Digest, JobIdentity, MissionId, PermissionSnapshot, PluginVersion,
    ProjectId, ProjectionCompleteness, RegistrationId, RegistrationStatus, ResourceIdentity,
    SchemaFingerprint, SecretKind, SecretReference, SourceIdentity, StreamIdentity,
    SyncAttemptProjection, SyncAttemptStatus, TransportProvenance, WorkProductId,
    WorkspaceIdentity,
};
pub use provider::{
    AirbyteCloudProvider, AirbyteProviderError, AirbyteTransport, AirbyteTransportError,
    AttemptReadRequest, AttemptResponse, BlockedEnvTransport, CatalogPage, CatalogReadRequest,
    FakeTransport, LoopbackTransport, ProviderAttemptRecord, RecordingTransport,
};
pub use service::{
    AirbyteRegistration, AirbyteRegistrationRegistry, AirbyteSyncResultService, ProviderIdentity,
    RegistrationReceipt,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.airbyte-sync-result-contract/v1";
pub const CONTRACT_VERSION: &str = "airbyte-sync-result-01-layer-1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.airbyte-sync-result-contract/v1|layer=1|service=airbyte.sync-result.read|provider=airbyte.cloud.sync-result.recording|consumer=mission.airbyte-sync-result.consumer";
pub const CONTRACT_DIGEST: &str =
    "c3196fdf965431a8de0a91385f7beb7262b3dbb2c633900391be7234dc0aee0f";
pub const PLUGIN_ID: &str = "airbyte.sync-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "airbyte.sync-result.read";
pub const PROVIDER_ID: &str = "airbyte.cloud.sync-result.recording";
pub const PROVIDER_API_REVISION: &str = "cloud-sync-result-read-1";
pub const CONSUMER_ID: &str = "mission.airbyte-sync-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/airbyte-sync-result/contract.v1.json");

pub const MAX_PAGE_SIZE: usize = 100;
pub const MAX_CATALOG_PAGES: usize = 16;
pub const MAX_CATALOG_ENTRIES: usize = 256;
pub const MAX_PAGE_TOKEN_BYTES: usize = 512;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_RECORD_COUNT: u64 = 100_000_000;
pub const MAX_EVIDENCE_BYTES: u64 = 1024 * 1024;

/// A Layer-1 failure that never contains credential material or unbounded
/// provider response text.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum AirbyteSyncResultError {
    #[error("invalid text in {field}")]
    InvalidText { field: &'static str },
    #[error("invalid identifier in {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("invalid HTTPS workspace host")]
    InvalidWorkspaceHost,
    #[error("invalid opaque SecretReference")]
    InvalidSecretReference,
    #[error("invalid exact Airbyte scope")]
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
    #[error("registration integrity or revision drifted")]
    RegistrationDrift,
    #[error("scope does not match the exact registered workspace/resource/run scope")]
    ScopeMismatch,
    #[error("workspace identity drifted")]
    WorkspaceDrift,
    #[error("source identity drifted")]
    SourceDrift,
    #[error("destination identity drifted")]
    DestinationDrift,
    #[error("connection identity drifted")]
    ConnectionDrift,
    #[error("stream identity drifted")]
    StreamDrift,
    #[error("job identity drifted")]
    JobDrift,
    #[error("attempt identity drifted")]
    AttemptDrift,
    #[error("source and destination schema fingerprints do not match")]
    SchemaMismatch,
    #[error("proposal is invalid")]
    InvalidProposal,
    #[error("recording idempotency key was replayed with different evidence")]
    ReplayConflict,
    #[error("recording is truncated and cannot be treated as complete evidence")]
    TruncatedEvidence,
    #[error("provider response or evidence was tampered")]
    TamperedEvidence,
    #[error("provider page token repeated")]
    PaginationLoop,
    #[error("provider pagination exceeded its bound")]
    PaginationLimit,
    #[error("provider response exceeded its byte bound")]
    ResponseTooLarge,
    #[error("provider returned an out-of-scope catalog entry")]
    OutOfScope,
    #[error("provider error: {0}")]
    Provider(#[from] AirbyteProviderError),
    #[error("transport error: {0}")]
    Transport(#[from] AirbyteTransportError),
}

pub type Result<T> = std::result::Result<T, AirbyteSyncResultError>;

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
        Err(AirbyteSyncResultError::InvalidText { field })
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
        Err(AirbyteSyncResultError::InvalidDigest { field })
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
        contract_digest: String,
        digest_input: String,
    }

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract = serde_json::from_str::<ContractDocument>(CONTRACT_JSON)
            .expect("checked Airbyte contract");
        assert_eq!(contract.schema_version, CONTRACT_SCHEMA);
        assert_eq!(contract.contract_version, CONTRACT_VERSION);
        assert_eq!(contract.plugin_id, PLUGIN_ID);
        assert_eq!(contract.layer, 1);
        assert_eq!(contract.evidence_level, EVIDENCE_LEVEL);
        assert_eq!(contract.digest_input, CONTRACT_DIGEST_INPUT);
        assert_eq!(contract.contract_digest, CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert!(!CONTRACT_DIGEST.contains("REPLACED"));
    }
}
