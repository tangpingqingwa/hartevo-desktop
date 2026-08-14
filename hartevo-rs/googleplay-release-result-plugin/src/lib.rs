//! Standalone Layer-1 Google Play release-result boundary.
//!
//! This crate owns a bounded Android Publisher release read, a canonical
//! Mission proposal, and below-kernel recording.  It has no edit, upload,
//! track-mutation, publishing, rollout, halt, listing, credential-storage, or
//! kernel Truth/Consent/Effect/Receipt/Verification/Outcome authority.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{
    GooglePlayReleaseProposal, GooglePlayReleaseRecordingLog, MissionAndroidReleaseConsumer,
    RecordedGooglePlayReleaseResult,
};
pub use model::*;
pub use provider::{
    BlockedEnvCredentialResolver, CredentialError, GoogleCredentialResolver, GooglePlayProvider,
    GooglePlayProviderState, GooglePlayReadRequest,
};
pub use service::{
    CapabilityDescription, GooglePlayRegistration, GooglePlayRegistrationRequest,
    GooglePlayRegistrationStatus, GooglePlayReleaseService, RegistrationReceipt,
    RegistrationTransition,
};
pub use transport::{
    BlockedEnvGooglePlayTransport, FakeGooglePlayTransport, FixtureGooglePlayTransport,
    GooglePlayEndpoint, GooglePlayHttpMethod, GooglePlayHttpRequest, GooglePlayHttpResponse,
    GooglePlayResponseBody, GooglePlayResponseReceipt, GooglePlayTransport,
    GooglePlayTransportError, LoopbackGooglePlayTransport, RecordingGooglePlayTransport,
    TransportProvenance, UreqGooglePlayTransport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.googleplay-release-result-contract/v1";
pub const CONTRACT_VERSION: &str = "googleplay-release-result-01-layer-1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.googleplay-release-result-contract/v1|layer=1|service=googleplay.release-result.service|provider=googleplay.release-result.provider|consumer=mission.googleplay-release-result.consumer";
pub const PLUGIN_ID: &str = "googleplay.release-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "googleplay.release-result.service";
pub const PROVIDER_ID: &str = "googleplay.release-result.provider";
pub const CONSUMER_ID: &str = "mission.googleplay-release-result.consumer";
pub const API_REVISION: &str = "android-publisher-rest-v3-r1";
pub const PROVIDER_REVISION: &str = "googleplay-android-publisher-release-r1";
pub const GOOGLE_PLAY_API_ORIGIN: &str = "https://androidpublisher.googleapis.com";
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_RELEASES: usize = 20;
pub const MAX_VERSION_CODES_PER_RELEASE: usize = 20;
pub const MAX_RECEIPTS: usize = 20;

pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/googleplay-release-result/googleplay-release-result.v1.json"
);

/// A small semantic version used in capability descriptions and registration
/// fences without importing the protected desktop workspace.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PluginVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl PluginVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl std::fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

pub type Result<T> = std::result::Result<T, GooglePlayReleaseResultError>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GooglePlayReleaseResultError {
    #[error("invalid text in {field}")]
    InvalidText { field: &'static str },
    #[error("invalid identifier in {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid SHA-256 digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("invalid opaque SecretReference")]
    InvalidSecretReference,
    #[error("invalid credential material")]
    InvalidCredential,
    #[error("credential lease expired")]
    CredentialExpired,
    #[error("credential resolution is unavailable")]
    CredentialUnavailable,
    #[error("invalid exact Google Play/Mission/Project/Work Product scope")]
    InvalidScope,
    #[error("opaque SecretReference is not bound to the exact scope")]
    SecretScopeMismatch,
    #[error("opaque SecretReference is not bound to the permission snapshot")]
    SecretPermissionMismatch,
    #[error("opaque SecretReference is revoked")]
    SecretRevoked,
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
    #[error("registration version, contract, provider, permission, secret, or scope drifted")]
    RegistrationDrift,
    #[error(
        "Google Play release evidence is outside the registered package/track/form-factor scope"
    )]
    ScopeMismatch,
    #[error("Google Play release is stale or obsolete")]
    StaleRelease,
    #[error("Google Play release version code and artifact digest binding mismatch")]
    VersionCodeArtifactMismatch,
    #[error("Google Play lifecycle state is not in the Layer-1 allowlist")]
    UnsupportedLifecycleState,
    #[error("Google Play rollout bucket is invalid")]
    InvalidRollout,
    #[error("provider returned invalid release data")]
    InvalidProviderData,
    #[error("provider returned more than the bounded maximum for {field}")]
    BoundExceeded { field: &'static str },
    #[error("provider evidence is empty or partial and cannot be adopted")]
    PartialEvidence,
    #[error("provider evidence is tampered")]
    TamperedEvidence,
    #[error("provider evidence is invalid")]
    InvalidEvidence,
    #[error("proposal is not a complete, exact-scope release candidate")]
    NonAdoptableProposal,
    #[error("recording replay conflicts with an existing proposal")]
    ReplayConflict,
    #[error("contract document is invalid")]
    InvalidContract,
    #[error("BLOCKED_ENV prevents native credential or provider access")]
    BlockedEnv,
    #[error("Google Play transport error: {0}")]
    Transport(#[from] transport::GooglePlayTransportError),
}

pub fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

pub fn contract_digest() -> model::Digest {
    model::Digest::from_text(CONTRACT_DIGEST_INPUT)
}

pub fn provider_digest() -> model::Digest {
    model::Digest::from_parts(
        "googleplay-release-result/provider/v1",
        [
            ("plugin".to_owned(), PLUGIN_ID.to_owned()),
            ("provider".to_owned(), PROVIDER_ID.to_owned()),
            ("api_revision".to_owned(), API_REVISION.to_owned()),
            ("provider_revision".to_owned(), PROVIDER_REVISION.to_owned()),
        ],
    )
}

pub(crate) fn digest_serialized<T: Serialize>(value: &T) -> model::Digest {
    let bytes = serde_json::to_vec(value).expect("bounded contract values must serialize");
    model::Digest::from_text(&String::from_utf8_lossy(&bytes))
}

pub(crate) fn digest_serialized_with_domain<T: Serialize>(
    domain: &str,
    value: &T,
) -> model::Digest {
    #[derive(Serialize)]
    struct DomainValue<'a, T> {
        domain: &'a str,
        value: &'a T,
    }
    digest_serialized(&DomainValue { domain, value })
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
        Err(GooglePlayReleaseResultError::InvalidText { field })
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
        Err(GooglePlayReleaseResultError::InvalidIdentifier { field })
    }
}

/// Validate the checked-in JSON's identity and authority boundary.  The
/// schema document is intentionally kept as a data contract in the assigned
/// root; this semantic validator is the scoped contract gate for the crate.
pub fn validate_contract_document() -> Result<()> {
    let document: serde_json::Value = serde_json::from_str(CONTRACT_JSON)
        .map_err(|_| GooglePlayReleaseResultError::InvalidContract)?;
    let object = document
        .as_object()
        .ok_or(GooglePlayReleaseResultError::InvalidContract)?;
    let string = |key: &str| object.get(key).and_then(serde_json::Value::as_str);
    if string("schemaVersion") != Some(CONTRACT_SCHEMA)
        || string("contractVersion") != Some(CONTRACT_VERSION)
        || string("pluginId") != Some(PLUGIN_ID)
        || string("contractDigestInput") != Some(CONTRACT_DIGEST_INPUT)
        || string("contractDigest") != Some(contract_digest().as_str())
        || object.get("layer").and_then(serde_json::Value::as_u64) != Some(1)
    {
        return Err(GooglePlayReleaseResultError::InvalidContract);
    }
    let service = object
        .get("service")
        .and_then(serde_json::Value::as_object)
        .ok_or(GooglePlayReleaseResultError::InvalidContract)?;
    if service.get("type").and_then(serde_json::Value::as_str) != Some("GooglePlayReleaseService")
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
        return Err(GooglePlayReleaseResultError::InvalidContract);
    }
    let provider = object
        .get("provider")
        .and_then(serde_json::Value::as_object)
        .ok_or(GooglePlayReleaseResultError::InvalidContract)?;
    if provider.get("type").and_then(serde_json::Value::as_str) != Some("GooglePlayProvider")
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
    {
        return Err(GooglePlayReleaseResultError::InvalidContract);
    }
    let consumer = object
        .get("consumer")
        .and_then(serde_json::Value::as_object)
        .ok_or(GooglePlayReleaseResultError::InvalidContract)?;
    if consumer.get("type").and_then(serde_json::Value::as_str)
        != Some("MissionAndroidReleaseConsumer")
        || consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
        || consumer
            .get("mutatesExternalState")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
        || consumer
            .get("adoptsWorkProduct")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
    {
        return Err(GooglePlayReleaseResultError::InvalidContract);
    }
    let bounds = object
        .get("bounds")
        .and_then(serde_json::Value::as_object)
        .ok_or(GooglePlayReleaseResultError::InvalidContract)?;
    if bounds
        .get("maxReleases")
        .and_then(serde_json::Value::as_u64)
        != Some(MAX_RELEASES as u64)
        || bounds
            .get("maxVersionCodesPerRelease")
            .and_then(serde_json::Value::as_u64)
            != Some(MAX_VERSION_CODES_PER_RELEASE as u64)
        || bounds
            .get("maxResponseBytes")
            .and_then(serde_json::Value::as_u64)
            != Some(MAX_RESPONSE_BYTES as u64)
    {
        return Err(GooglePlayReleaseResultError::InvalidContract);
    }
    let lifecycle = object
        .get("allowlistedEvidence")
        .and_then(serde_json::Value::as_array)
        .ok_or(GooglePlayReleaseResultError::InvalidContract)?;
    if !lifecycle.iter().any(|value| {
        value.as_str() == Some(
            "lifecycleState:DRAFT|NOT_SENT_FOR_REVIEW|IN_REVIEW|APPROVED_NOT_PUBLISHED|NOT_APPROVED|PUBLISHED",
        )
    }) {
        return Err(GooglePlayReleaseResultError::InvalidContract);
    }
    let credentials = object
        .get("credentials")
        .and_then(serde_json::Value::as_object)
        .ok_or(GooglePlayReleaseResultError::InvalidContract)?;
    if credentials
        .get("serialized")
        .and_then(serde_json::Value::as_bool)
        != Some(false)
        || credentials
            .get("accessTokensRetained")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
        || credentials
            .get("privateKeyBytesRetained")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
    {
        return Err(GooglePlayReleaseResultError::InvalidContract);
    }
    let provenance = object
        .get("provenance")
        .and_then(serde_json::Value::as_object)
        .ok_or(GooglePlayReleaseResultError::InvalidContract)?;
    if provenance
        .get("nativeConnectedClaim")
        .and_then(serde_json::Value::as_bool)
        != Some(false)
    {
        return Err(GooglePlayReleaseResultError::InvalidContract);
    }
    Ok(())
}

// This compile-time use keeps the digest implementation intentionally
// obvious when reading the crate's dependency surface.
#[allow(dead_code)]
fn _sha256_identity(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}
