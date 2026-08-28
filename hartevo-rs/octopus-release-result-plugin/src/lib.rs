//! Standalone Layer-1 Octopus release-result read, proposal, and recording boundary.
//!
//! The crate owns only typed, bounded, redacted evidence.  Its transport seam
//! is deliberately limited to fixture, recording, loopback, and BLOCKED_ENV
//! modes; it has no live credential resolver, native connection, external
//! write, deployment authority, raw task-log/script/package retention, generic
//! deployment registry, or kernel authority.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

use std::fmt::Write as _;

use serde::Serialize;
use sha2::{Digest as Sha2Digest, Sha256};
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{
    MissionOctopusReleaseConsumer, OctopusReleaseResultProposal, OctopusReleaseResultRecordingLog,
    RecordedOctopusReleaseResult,
};
pub use model::*;
pub use provider::{
    OctopusProvider, OctopusProviderState, OctopusReadRequest, OctopusResultProjection,
    ProjectionCompleteness, ProjectionStatus,
};
pub use service::{
    CapabilityDescription, OctopusRegistration, OctopusRegistrationRequest,
    OctopusRegistrationStatus, OctopusReleaseResultService, RegistrationReceipt,
    RegistrationTransition,
};
pub use transport::{
    BlockedEnvOctopusTransport, FakeOctopusTransport, FixtureOctopusTransport,
    LoopbackOctopusTransport, OctopusEndpoint, OctopusHttpRequest, OctopusHttpResponse,
    OctopusReceipt, OctopusResponseBody, OctopusTransport, OctopusTransportError,
    RecordingOctopusTransport, TransportProvenance,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.octopus-release-result-contract/v1";
pub const CONTRACT_VERSION: &str = "octopus-release-result-01-layer-1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.octopus-release-result-contract/v1|layer=1|service=octopus.release-result.service|provider=octopus.release-result.provider|consumer=mission.octopus-release-result.consumer";
pub const CONTRACT_DIGEST: &str =
    "585eba1b322e7b95adb6323197dfa3ee2971d3a50adbc767d8289cd33170cd7a";
pub const PLUGIN_ID: &str = "octopus.release-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "octopus.release-result.service";
pub const PROVIDER_ID: &str = "octopus.release-result.provider";
pub const CONSUMER_ID: &str = "mission.octopus-release-result.consumer";
pub const API_REVISION: &str = "octopus-rest-api-v1-layer1-r1";
pub const PROVIDER_REVISION: &str = "octopus-rest-release-result-r1";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/octopus-release-result/contract.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_METADATA_BYTES: usize = 65_536;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_PAGES: usize = 8;
pub const MAX_ITEMS_PER_COLLECTION: usize = 128;
pub const MAX_RECEIPTS: usize = 16;
pub const MAX_TARGETS: usize = 64;
pub const MAX_STATE_BYTES: usize = 128;

/// Semantic errors never contain provider payloads, credentials, logs, or
/// package bytes.  Provider and transport errors are similarly redacted.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum OctopusReleaseResultError {
    #[error("invalid text in {field}")]
    InvalidText { field: &'static str },
    #[error("invalid identifier in {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("invalid HTTPS Octopus server origin")]
    InvalidServerOrigin,
    #[error("invalid opaque SecretReference")]
    InvalidSecretReference,
    #[error("SecretReference is not bound to this exact scope")]
    SecretScopeMismatch,
    #[error("SecretReference is not bound to this permission snapshot")]
    SecretPermissionMismatch,
    #[error("SecretReference is revoked")]
    SecretRevoked,
    #[error("invalid exact Octopus/Mission/Project/Consent scope")]
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
    #[error("registration version, contract, provider, scope, or digest drifted")]
    RegistrationDrift,
    #[error("exact Octopus/Mission/Project/Consent scope does not match")]
    ScopeMismatch,
    #[error("provider evidence was tampered")]
    TamperedEvidence,
    #[error("provider evidence redaction boundary was violated")]
    RedactionViolation,
    #[error("provider response exceeded its byte bound")]
    ResponseTooLarge,
    #[error("provider pagination exceeded its bound")]
    PaginationLimit,
    #[error("provider returned an out-of-scope entry")]
    OutOfScope,
    #[error("provider returned malformed metadata")]
    MalformedProviderData,
    #[error("provider access was lost")]
    AccessLost,
    #[error("provider state is unknown")]
    ProviderUnknown,
    #[error("recording idempotency key was replayed with different evidence")]
    ReplayConflict,
    #[error("proposal is invalid")]
    InvalidProposal,
    #[error("contract document is invalid")]
    InvalidContract,
    #[error("BLOCKED_ENV prevents provider access")]
    BlockedEnv,
    #[error("transport error: {0}")]
    Transport(#[from] transport::OctopusTransportError),
}

pub type Result<T> = std::result::Result<T, OctopusReleaseResultError>;

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

pub(crate) fn digest_serialized<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("bounded contract values must serialize");
    sha256_hex(&bytes)
}

pub(crate) fn digest_serialized_with_domain<T: Serialize>(domain: &str, value: &T) -> String {
    #[derive(Serialize)]
    struct DomainValue<'a, T> {
        domain: &'a str,
        value: &'a T,
    }

    digest_serialized(&DomainValue { domain, value })
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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
        Err(OctopusReleaseResultError::InvalidText { field })
    } else {
        Ok(())
    }
}

pub(crate) fn validate_identifier(value: &str, field: &'static str) -> Result<()> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES, false)?;
    if value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'+' | b'=')
    }) {
        Ok(())
    } else {
        Err(OctopusReleaseResultError::InvalidIdentifier { field })
    }
}

/// Digest of the stable contract identity input.  The input is intentionally
/// separate from the JSON document's mutable formatting so registration
/// fences do not change because whitespace changed.
pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT).expect("contract digest input is valid")
}

pub fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Validate the checked-in contract's identity, allowlist, state vocabulary,
/// and non-native authority markers.
pub fn validate_contract_document() -> Result<()> {
    let document = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
        .map_err(|_| OctopusReleaseResultError::InvalidContract)?;
    let object = document
        .as_object()
        .ok_or(OctopusReleaseResultError::InvalidContract)?;
    let string = |key: &str| object.get(key).and_then(serde_json::Value::as_str);
    if string("schemaVersion") != Some(CONTRACT_SCHEMA)
        || string("contractVersion") != Some(CONTRACT_VERSION)
        || string("pluginId") != Some(PLUGIN_ID)
        || object.get("layer").and_then(serde_json::Value::as_u64) != Some(1)
        || string("evidenceLevel") != Some(EVIDENCE_LEVEL)
        || string("contractDigestInput") != Some(CONTRACT_DIGEST_INPUT)
        || string("contractDigest") != Some(CONTRACT_DIGEST)
        || CONTRACT_DIGEST != contract_digest().as_str()
    {
        return Err(OctopusReleaseResultError::InvalidContract);
    }

    let service = object
        .get("service")
        .and_then(serde_json::Value::as_object)
        .ok_or(OctopusReleaseResultError::InvalidContract)?;
    if service.get("type").and_then(serde_json::Value::as_str)
        != Some("OctopusReleaseResultService")
        || service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
        || service.get("readOnly").and_then(serde_json::Value::as_bool) != Some(true)
        || service
            .get("externalWrites")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
        || service
            .get("kernelAuthority")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
    {
        return Err(OctopusReleaseResultError::InvalidContract);
    }

    let provider = object
        .get("provider")
        .and_then(serde_json::Value::as_object)
        .ok_or(OctopusReleaseResultError::InvalidContract)?;
    if provider.get("type").and_then(serde_json::Value::as_str) != Some("OctopusProvider")
        || provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
        || provider
            .get("apiRevision")
            .and_then(serde_json::Value::as_str)
            != Some(API_REVISION)
        || provider
            .get("providerRevision")
            .and_then(serde_json::Value::as_str)
            != Some(PROVIDER_REVISION)
        || provider
            .get("connected")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
        || provider.get("native").and_then(serde_json::Value::as_bool) != Some(false)
        || provider
            .get("liveTransport")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
    {
        return Err(OctopusReleaseResultError::InvalidContract);
    }

    let consumer = object
        .get("consumer")
        .and_then(serde_json::Value::as_object)
        .ok_or(OctopusReleaseResultError::InvalidContract)?;
    if consumer.get("type").and_then(serde_json::Value::as_str)
        != Some("MissionOctopusReleaseConsumer")
        || consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
        || consumer
            .get("mutatesExternalState")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
        || consumer
            .get("adoptsOutcome")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
        || consumer
            .get("adoptsWorkProduct")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
    {
        return Err(OctopusReleaseResultError::InvalidContract);
    }

    let operations = provider
        .get("operations")
        .and_then(serde_json::Value::as_array)
        .ok_or(OctopusReleaseResultError::InvalidContract)?;
    if operations.is_empty()
        || operations.iter().any(|operation| {
            operation
                .as_str()
                .is_none_or(|value| !value.starts_with("GET "))
        })
    {
        return Err(OctopusReleaseResultError::InvalidContract);
    }

    let expected_provenance = ["recording", "fixture", "loopback", "blocked_env"];
    let provenance = provider
        .get("allowedTransportProvenance")
        .and_then(serde_json::Value::as_array)
        .ok_or(OctopusReleaseResultError::InvalidContract)?;
    if provenance.len() != expected_provenance.len()
        || provenance
            .iter()
            .zip(expected_provenance)
            .any(|(actual, expected)| actual.as_str() != Some(expected))
    {
        return Err(OctopusReleaseResultError::InvalidContract);
    }

    let projection = object
        .get("projection")
        .and_then(serde_json::Value::as_object)
        .ok_or(OctopusReleaseResultError::InvalidContract)?;
    let expected_states = [
        "queued",
        "running",
        "succeeded",
        "failed",
        "canceled",
        "paused",
        "partial",
        "retention-gap",
        "access-lost",
        "provider-unknown",
    ];
    let states = projection
        .get("states")
        .and_then(serde_json::Value::as_array)
        .ok_or(OctopusReleaseResultError::InvalidContract)?;
    if states.len() != expected_states.len()
        || states
            .iter()
            .zip(expected_states)
            .any(|(actual, expected)| actual.as_str() != Some(expected))
    {
        return Err(OctopusReleaseResultError::InvalidContract);
    }

    let forbidden = object
        .get("forbiddenLayer1Effects")
        .and_then(serde_json::Value::as_array)
        .ok_or(OctopusReleaseResultError::InvalidContract)?;
    for effect in [
        "create_release",
        "trigger_deployment",
        "cancel_deployment",
        "approve_deployment",
        "mutate_variables",
        "mutate_tenant",
        "control_runbook",
        "control_worker",
        "retain_raw_task_logs",
        "retain_raw_scripts",
        "retain_package_bytes",
        "generic_deployment_registry",
        "kernel_authority",
    ] {
        if !forbidden.iter().any(|value| value.as_str() == Some(effect)) {
            return Err(OctopusReleaseResultError::InvalidContract);
        }
    }
    Ok(())
}

#[cfg(test)]
mod contract_tests {
    use super::{CONTRACT_DIGEST, contract_digest, validate_contract_document};

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        validate_contract_document().expect("checked Octopus contract");
        assert_eq!(contract_digest().as_str(), CONTRACT_DIGEST);
        assert!(!CONTRACT_DIGEST.contains("TO_BE_FILLED"));
    }
}
