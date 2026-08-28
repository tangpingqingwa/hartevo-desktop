//! Standalone Layer-1 App Store Connect release-result boundary.
//!
//! This crate owns bounded, typed, redacted observations from the official
//! App Store Connect REST resource and relationship paths.  It deliberately
//! has no live credential resolver, JWT signer, HTTPS client, upload path,
//! metadata mutation, tester/build-group mutation, submission/release effect,
//! binary download, or kernel authority.

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
    MissionMobileReleaseConsumer, MobileReleaseEvidenceProposal, MobileReleaseRecordingLog,
    RecordedMobileReleaseEvidence,
};
pub use model::*;
pub use provider::{
    AppStoreConnectProvider, AppStoreConnectProviderState, AppStoreConnectReadRequest,
    AppStoreConnectResultProjection, ProjectionCompleteness, ProjectionStatus,
};
pub use service::{
    AppStoreConnectCapabilityDescription, AppStoreConnectRegistration,
    AppStoreConnectRegistrationRequest, AppStoreConnectRegistrationStatus,
    AppStoreConnectReleaseResultService, AppStoreConnectReleaseService, RegistrationReceipt,
    RegistrationTransition,
};
pub use transport::{
    AppStoreConnectEndpoint, AppStoreConnectHttpMethod, AppStoreConnectHttpRequest,
    AppStoreConnectHttpResponse, AppStoreConnectReceipt, AppStoreConnectTransport,
    AppStoreConnectTransportError, BlockedEnvAppStoreConnectTransport,
    FixtureAppStoreConnectTransport, JwtAlgorithm, JwtRedaction, LoopbackAppStoreConnectTransport,
    RecordingAppStoreConnectTransport, TransportProvenance,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.appstoreconnect-release-result-contract/v1";
pub const CONTRACT_VERSION: &str = "appstoreconnect-release-result-01-layer-1/v1";
pub const PLUGIN_ID: &str = "appstoreconnect.release-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "appstoreconnect.release-result.service";
pub const PROVIDER_ID: &str = "appstoreconnect.release-result.provider";
pub const CONSUMER_ID: &str = "mission.mobile-release.consumer";
pub const API_REVISION: &str = "appstoreconnect-rest-api-v1-layer1-r1";
pub const PROVIDER_REVISION: &str = "appstoreconnect-release-result-r1";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.appstoreconnect-release-result-contract/v1|layer=1|service=appstoreconnect.release-result.service|provider=appstoreconnect.release-result.provider|consumer=mission.mobile-release.consumer";
pub const CONTRACT_DIGEST: &str =
    "0044b91a9955b2e6a27ce2009531d513ead23bed8192776d6e94533b192152e2";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/appstoreconnect-release-result/contract.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_METADATA_BYTES: usize = 65_536;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_PAGES: usize = 8;
pub const MAX_ITEMS_PER_PAGE: usize = 128;
pub const MAX_RECEIPTS: usize = 32;
pub const MAX_RELATIONSHIPS: usize = 64;
pub const MAX_RELATIONSHIP_DEPTH: usize = 8;

/// Semantic errors never carry provider payloads, credentials, JWTs, or
/// private-key bytes.  Transport errors are intentionally equally redacted.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AppStoreConnectReleaseResultError {
    #[error("invalid text in {field}")]
    InvalidText { field: &'static str },
    #[error("invalid identifier in {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("invalid HTTPS App Store Connect API origin")]
    InvalidApiOrigin,
    #[error("invalid exact App Store Connect/Mission/Project/Work Product scope")]
    InvalidScope,
    #[error("invalid read-only permission snapshot")]
    InvalidPermissionSnapshot,
    #[error("invalid opaque SecretReference")]
    InvalidSecretReference,
    #[error("SecretReference is not bound to this exact scope")]
    SecretScopeMismatch,
    #[error("SecretReference is not bound to this permission snapshot")]
    SecretPermissionMismatch,
    #[error("SecretReference is revoked")]
    SecretRevoked,
    #[error("invalid registration")]
    InvalidRegistration,
    #[error("registration already exists")]
    RegistrationAlreadyExists,
    #[error("registration is unknown")]
    RegistrationUnknown,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("registration version, contract, provider, scope, permission, or digest drifted")]
    RegistrationDrift,
    #[error("exact App Store Connect/Mission/Project/Work Product scope does not match")]
    ScopeMismatch,
    #[error("provider resource revision does not match the pinned scope")]
    RevisionMismatch,
    #[error("provider artifact does not match the pinned artifact")]
    ArtifactMismatch,
    #[error("provider evidence was tampered")]
    TamperedEvidence,
    #[error("provider evidence redaction boundary was violated")]
    RedactionViolation,
    #[error("provider response exceeded its byte bound")]
    ResponseTooLarge,
    #[error("provider pagination exceeded its bound")]
    PaginationLimit,
    #[error("provider relationship traversal looped")]
    RelationshipLoop,
    #[error("provider returned an out-of-scope entry")]
    OutOfScope,
    #[error("provider returned malformed metadata")]
    MalformedProviderData,
    #[error("provider access was lost")]
    AccessLost,
    #[error("provider resource expired")]
    Expired,
    #[error("provider resource was removed or is no longer visible")]
    Removed,
    #[error("provider state is unknown")]
    ProviderUnknown,
    #[error("recording idempotency key was replayed with different evidence")]
    ReplayConflict,
    #[error("proposal is invalid")]
    InvalidProposal,
    #[error("contract document is invalid")]
    InvalidContract,
    #[error("BLOCKED_ENV prevents native provider access")]
    BlockedEnv,
    #[error("transport error: {0}")]
    Transport(#[from] transport::AppStoreConnectTransportError),
}

pub type Result<T> = std::result::Result<T, AppStoreConnectReleaseResultError>;

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
        Err(AppStoreConnectReleaseResultError::InvalidText { field })
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
        Err(AppStoreConnectReleaseResultError::InvalidIdentifier { field })
    }
}

/// Stable contract identity digest.  It is independent of JSON whitespace so
/// registration identity does not change when the checked-in document is
/// reformatted.
pub fn contract_digest() -> Digest {
    let digest = Digest::from_text(CONTRACT_DIGEST_INPUT).expect("contract digest input is valid");
    debug_assert_eq!(digest.as_str(), CONTRACT_DIGEST);
    digest
}

/// Stable provider implementation digest used by registration and evidence.
pub fn provider_digest() -> Digest {
    Digest::from_parts(
        "appstoreconnect-release-result/provider/v1",
        [
            ("id".to_owned(), PROVIDER_ID.to_owned()),
            ("api".to_owned(), API_REVISION.to_owned()),
            ("revision".to_owned(), PROVIDER_REVISION.to_owned()),
            ("transport".to_owned(), "GET-only-redacted".to_owned()),
        ],
    )
}

/// Validate the checked-in contract's identity, allowlist, and non-native
/// authority markers.  This is deliberately local and deterministic.
pub fn validate_contract_document() -> Result<()> {
    let document = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
        .map_err(|_| AppStoreConnectReleaseResultError::InvalidContract)?;
    let object = document
        .as_object()
        .ok_or(AppStoreConnectReleaseResultError::InvalidContract)?;
    let string = |key: &str| object.get(key).and_then(serde_json::Value::as_str);
    if string("schemaVersion") != Some(CONTRACT_SCHEMA)
        || string("contractVersion") != Some(CONTRACT_VERSION)
        || string("pluginId") != Some(PLUGIN_ID)
        || string("pluginVersion") != Some(PLUGIN_VERSION)
        || object.get("layer").and_then(serde_json::Value::as_u64) != Some(1)
        || string("evidenceLevel") != Some(EVIDENCE_LEVEL)
        || string("contractDigestInput") != Some(CONTRACT_DIGEST_INPUT)
        || string("contractDigest") != Some(contract_digest().as_str())
    {
        return Err(AppStoreConnectReleaseResultError::InvalidContract);
    }

    let service = object
        .get("service")
        .and_then(serde_json::Value::as_object)
        .ok_or(AppStoreConnectReleaseResultError::InvalidContract)?;
    if service.get("type").and_then(serde_json::Value::as_str)
        != Some("AppStoreConnectReleaseService")
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
        return Err(AppStoreConnectReleaseResultError::InvalidContract);
    }

    let provider = object
        .get("provider")
        .and_then(serde_json::Value::as_object)
        .ok_or(AppStoreConnectReleaseResultError::InvalidContract)?;
    if provider.get("type").and_then(serde_json::Value::as_str) != Some("AppStoreConnectProvider")
        || provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
        || provider
            .get("apiRevision")
            .and_then(serde_json::Value::as_str)
            != Some(API_REVISION)
        || provider
            .get("providerRevision")
            .and_then(serde_json::Value::as_str)
            != Some(PROVIDER_REVISION)
        || provider.get("native").and_then(serde_json::Value::as_bool) != Some(false)
        || provider
            .get("connected")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
        || provider
            .get("liveTransport")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
    {
        return Err(AppStoreConnectReleaseResultError::InvalidContract);
    }

    let consumer = object
        .get("consumer")
        .and_then(serde_json::Value::as_object)
        .ok_or(AppStoreConnectReleaseResultError::InvalidContract)?;
    if consumer.get("type").and_then(serde_json::Value::as_str)
        != Some("MissionMobileReleaseConsumer")
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
        return Err(AppStoreConnectReleaseResultError::InvalidContract);
    }

    let operations = provider
        .get("operations")
        .and_then(serde_json::Value::as_array)
        .ok_or(AppStoreConnectReleaseResultError::InvalidContract)?;
    if operations.is_empty()
        || operations.iter().any(|operation| {
            operation
                .as_str()
                .is_none_or(|value| !value.starts_with("GET "))
        })
    {
        return Err(AppStoreConnectReleaseResultError::InvalidContract);
    }

    let expected_provenance = ["recording", "fixture", "loopback", "blocked_env"];
    let provenance = provider
        .get("allowedTransportProvenance")
        .and_then(serde_json::Value::as_array)
        .ok_or(AppStoreConnectReleaseResultError::InvalidContract)?;
    if provenance.len() != expected_provenance.len()
        || provenance
            .iter()
            .zip(expected_provenance)
            .any(|(actual, expected)| actual.as_str() != Some(expected))
    {
        return Err(AppStoreConnectReleaseResultError::InvalidContract);
    }

    let projection = object
        .get("projection")
        .and_then(serde_json::Value::as_object)
        .ok_or(AppStoreConnectReleaseResultError::InvalidContract)?;
    for key in [
        "redacted",
        "connected",
        "native",
        "outcomeAdopted",
        "workProductAdopted",
    ] {
        if projection.get(key).and_then(serde_json::Value::as_bool)
            != Some(matches!(key, "redacted"))
        {
            return Err(AppStoreConnectReleaseResultError::InvalidContract);
        }
    }

    let forbidden = object
        .get("forbiddenLayer1Effects")
        .and_then(serde_json::Value::as_array)
        .ok_or(AppStoreConnectReleaseResultError::InvalidContract)?;
    for effect in [
        "upload_binary",
        "download_binary",
        "download_screenshot",
        "create_app_store_version",
        "mutate_metadata",
        "submit_for_review",
        "add_tester",
        "remove_tester",
        "add_build_to_beta_group",
        "remove_build_from_beta_group",
        "publish_release",
        "release_version",
        "jwt_serialization",
        "private_key_retention",
        "kernel_truth_authority",
        "kernel_consent_authority",
        "kernel_effect_authority",
        "kernel_receipt_authority",
        "kernel_verification_authority",
        "kernel_outcome_authority",
        "work_product_adoption",
    ] {
        if !forbidden.iter().any(|value| value.as_str() == Some(effect)) {
            return Err(AppStoreConnectReleaseResultError::InvalidContract);
        }
    }
    Ok(())
}

#[cfg(test)]
mod contract_tests {
    use super::{CONTRACT_DIGEST_INPUT, contract_digest, validate_contract_document};

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        validate_contract_document().expect("checked App Store Connect contract");
        assert_eq!(contract_digest().as_str(), super::CONTRACT_DIGEST);
        assert!(!CONTRACT_DIGEST_INPUT.contains("TO_BE_FILLED"));
    }
}
