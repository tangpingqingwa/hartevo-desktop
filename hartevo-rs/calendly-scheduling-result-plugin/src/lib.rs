//! Standalone Layer-1 Calendly scheduled meeting-result evidence.
//!
//! The crate deliberately exposes a typed service/provider/Mission-consumer
//! seam without becoming a kernel, calendar, booking, or external-effect
//! authority. Its controlled providers only project bounded metadata from
//! fixtures, recordings, loopback recordings, or the honest BLOCKED_ENV
//! state.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

use std::fmt::Write as _;

use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub mod model;
pub mod provider;
pub mod service;

pub use model::*;
pub use provider::*;
pub use service::*;

/// The exact versioned contract bytes owned by this standalone root.
pub const CONTRACT_DOCUMENT: &str =
    include_str!("../../../contracts/plugins/calendly-scheduling-result/contract.v1.json");
pub const PLUGIN_ID: &str = "hartevo.calendly-scheduling-result";
pub const SERVICE_ID: &str = "calendly.scheduling-result.service";
pub const PROVIDER_ID: &str = "calendly.scheduling-result.provider";
pub const CONSUMER_ID: &str = "mission.calendly-meeting.consumer";
pub const API_ORIGIN: &str = "https://api.calendly.com";
pub const API_REVISION: &str = "v2";
pub const PROVIDER_REVISION: &str = "calendly-api-v2-layer1-r1";
pub const IMPLEMENTATION_REVISION: &str = "calendly-scheduling-result-layer1-r1";
pub const DEFAULT_PLUGIN_VERSION: PluginVersion = PluginVersion::new(1, 0, 0);
pub const MAX_PAGES: u16 = 8;
pub const MAX_INVITEES: usize = 32;
pub const MAX_WEBHOOK_SIGNALS: usize = 32;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_DATE_WINDOW_DAYS: u64 = 31;
pub const MAX_TIMESTAMP_SKEW_MILLIS: u64 = 300_000;
pub const MAX_WEBHOOK_AGE_MILLIS: u64 = 86_400_000;

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub(crate) fn digest_serialized<T: serde::Serialize>(
    value: &T,
) -> Result<Digest, CalendlySchedulingResultError> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| CalendlySchedulingResultError::Serialization)?;
    Digest::new(sha256_hex(&bytes))
}

pub(crate) fn digest_serialized_with_domain<T: serde::Serialize>(
    domain: &str,
    value: &T,
) -> Result<Digest, CalendlySchedulingResultError> {
    #[derive(serde::Serialize)]
    struct DomainBody<'a, T> {
        domain: &'a str,
        value: &'a T,
    }
    digest_serialized(&DomainBody { domain, value })
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn valid_identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'+' | b'=')
        })
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CalendlySchedulingResultError {
    #[error("identifier is invalid")]
    InvalidIdentifier,
    #[error("digest is invalid")]
    InvalidDigest,
    #[error("serialization failed")]
    Serialization,
    #[error("scope is invalid")]
    InvalidScope,
    #[error("date window is invalid or exceeds the Layer-1 bound")]
    InvalidDateWindow,
    #[error("permission lease is invalid")]
    InvalidPermissionLease,
    #[error("permission lease is expired")]
    PermissionLeaseExpired,
    #[error("secret reference is invalid")]
    InvalidSecretReference,
    #[error("secret reference does not bind the exact scope")]
    SecretScopeMismatch,
    #[error("secret reference does not bind the permission lease")]
    SecretPermissionMismatch,
    #[error("secret reference is revoked")]
    SecretRevoked,
    #[error("secret reference was already revoked")]
    SecretAlreadyRevoked,
    #[error("registration plugin version drifted")]
    RegistrationVersionMismatch,
    #[error("registration contract digest drifted")]
    RegistrationContractMismatch,
    #[error("registration provider digest drifted")]
    RegistrationProviderMismatch,
    #[error("registration API revision drifted")]
    RegistrationApiRevisionMismatch,
    #[error("registration implementation digest drifted")]
    RegistrationImplementationMismatch,
    #[error("registration permission digest drifted")]
    RegistrationPermissionMismatch,
    #[error("registration scope digest drifted")]
    RegistrationScopeMismatch,
    #[error("registration event revision drifted")]
    RegistrationEventRevisionMismatch,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("Mission/Project/Work Product scope does not match")]
    MissionScopeMismatch,
    #[error("Mission revision is stale")]
    StaleMissionRevision,
    #[error("Project revision is stale")]
    StaleProjectRevision,
    #[error("Work Product revision is stale")]
    StaleWorkProductRevision,
    #[error("event revision is stale")]
    StaleEventRevision,
    #[error("webhook signal is too old and may be a replay")]
    WebhookReplay,
    #[error("webhook signal timestamp is too far in the future")]
    WebhookFutureTimestamp,
    #[error("duplicate webhook delivery id")]
    DuplicateWebhookDelivery,
    #[error("page budget was exceeded")]
    PageBudgetExceeded,
    #[error("provider pagination cursor repeated")]
    PaginationLoop,
    #[error("provider cursor expired")]
    CursorExpired,
    #[error("provider revision drifted during the read")]
    ProviderRevisionDrift,
    #[error("permission digest drifted during the read")]
    PermissionDigestDrift,
    #[error("scheduled event identity does not match the registered scope")]
    EventScopeMismatch,
    #[error("event type identity does not match the registered scope")]
    EventTypeScopeMismatch,
    #[error("organization or user identity does not match the registered scope")]
    OrganizationUserScopeMismatch,
    #[error("provider returned malformed metadata")]
    MalformedProviderData,
    #[error("provider error: {0}")]
    Provider(#[from] ProviderError),
}

/// SHA-256 of the exact contract document, exposed as a contract identity and
/// never as a content or credential digest.
pub fn contract_digest() -> Result<Digest, CalendlySchedulingResultError> {
    Digest::new(sha256_hex(CONTRACT_DOCUMENT.as_bytes()))
}

/// SHA-256 identity for the provider implementation revision.
pub fn implementation_digest() -> Result<Digest, CalendlySchedulingResultError> {
    Digest::from_text(IMPLEMENTATION_REVISION)
}

/// SHA-256 identity for the provider API/mode boundary.
pub fn provider_digest() -> Result<Digest, CalendlySchedulingResultError> {
    Digest::from_text(&format!("{PROVIDER_ID}|{API_REVISION}|{PROVIDER_REVISION}"))
}

/// Validate the checked-in contract identity and Layer-1 honesty markers.
/// This is intentionally a small contract gate, not a host/catalog authority.
pub fn validate_contract_document() -> Result<(), CalendlySchedulingResultError> {
    let document = serde_json::from_str::<serde_json::Value>(CONTRACT_DOCUMENT)
        .map_err(|_| CalendlySchedulingResultError::Serialization)?;
    let object = document
        .as_object()
        .ok_or(CalendlySchedulingResultError::MalformedProviderData)?;
    let is_string = |key: &str, expected: &str| {
        object.get(key).and_then(serde_json::Value::as_str) == Some(expected)
    };
    if !is_string("schema", "hartevo.calendly-scheduling-result/contract")
        || !is_string("contractVersion", "1.0.0")
        || object.get("layer").and_then(serde_json::Value::as_u64) != Some(1)
        || !is_string("pluginId", PLUGIN_ID)
    {
        return Err(CalendlySchedulingResultError::MalformedProviderData);
    }
    let service = object
        .get("service")
        .and_then(serde_json::Value::as_object)
        .ok_or(CalendlySchedulingResultError::MalformedProviderData)?;
    if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
        || service
            .get("implementation")
            .and_then(serde_json::Value::as_str)
            != Some("CalendlySchedulingResultService")
        || service.get("readOnly").and_then(serde_json::Value::as_bool) != Some(true)
        || service
            .get("externalWrites")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
    {
        return Err(CalendlySchedulingResultError::MalformedProviderData);
    }
    let provider = object
        .get("provider")
        .and_then(serde_json::Value::as_object)
        .ok_or(CalendlySchedulingResultError::MalformedProviderData)?;
    if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
        || provider
            .get("implementation")
            .and_then(serde_json::Value::as_str)
            != Some("CalendlyProvider")
        || provider
            .get("connected")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
        || provider.get("native").and_then(serde_json::Value::as_bool) != Some(false)
        || provider
            .get("firstParty")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
    {
        return Err(CalendlySchedulingResultError::MalformedProviderData);
    }
    Ok(())
}
