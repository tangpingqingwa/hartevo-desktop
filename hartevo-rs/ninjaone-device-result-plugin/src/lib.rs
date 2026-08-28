#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::manual_let_else,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]
//! Standalone Layer-1 NinjaOne endpoint-device result evidence.
//!
//! This crate is intentionally a bounded read/proposal/recording seam. It has
//! no native HTTP client, OAuth resolver, endpoint-control effect, raw activity
//! log store, generic connector registry, or Hartevo Kernel authority.

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::*;
pub use model::*;
pub use provider::*;
pub use service::*;
pub use transport::*;

pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo.ninjaone-device-result.contract/v1";
pub const CONTRACT_VERSION: &str = "EXT-NINJAONE-01-L1/v1";
pub const PLUGIN_ID: &str = "ninjaone.device-result";
pub const SERVICE_ID: &str = "ninjaone.device-result.service";
pub const SERVICE_NAME: &str = "NinjaOneDeviceResultService";
pub const PROVIDER_ID: &str = "ninjaone.device-health";
pub const PROVIDER_NAME: &str = "NinjaOneProvider";
pub const CONSUMER_ID: &str = "mission.ninjaone-device-result";
pub const CONSUMER_NAME: &str = "MissionNinjaOneDeviceConsumer";
pub const NINJAONE_API_ORIGIN: &str = "https://app.ninjarmm.com";
pub const NINJAONE_API_REVISION: &str = "ninjaone-public-api-v2-r1";
pub const IMPLEMENTATION_REVISION: &str = "ninjaone-device-result-layer1-r1";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_PAGES: usize = 4;
pub const MAX_PAGE_SIZE: usize = 100;
pub const MAX_ALERTS: usize = 64;
pub const MAX_PATCHES: usize = 64;
pub const MAX_ACTIVITIES: usize = 32;
pub const MAX_RECEIPTS: usize = 16;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_TEXT_BYTES: usize = 256;
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/ninjaone-device-result/contract.v1.json");

pub type Result<T> = std::result::Result<T, NinjaOneError>;

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as ShaDigest, Sha256};

    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn canonical_digest<T: serde::Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("bounded NinjaOne value serializes");
    Digest::from_bytes(&bytes)
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn valid_identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'+')
        })
}

/// Validate the checked-in contract identity and the Layer-1 honesty markers.
/// Full JSON-Schema evaluation remains a host/CI concern; this gate protects
/// the constants that the typed registration and provider use.
pub fn validate_contract() -> Result<()> {
    let document: serde_json::Value =
        serde_json::from_str(CONTRACT_JSON).map_err(|_| NinjaOneError::MalformedContract)?;
    let object = document
        .as_object()
        .ok_or(NinjaOneError::MalformedContract)?;
    let string_is = |key: &str, expected: &str| {
        object.get(key).and_then(serde_json::Value::as_str) == Some(expected)
    };
    let projection_array_contains = |expected: &str| {
        object
            .get("projection")
            .and_then(serde_json::Value::as_object)
            .and_then(|projection| projection.get("states"))
            .and_then(serde_json::Value::as_array)
            .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(expected)))
    };
    let service = object
        .get("service")
        .and_then(serde_json::Value::as_object)
        .ok_or(NinjaOneError::MalformedContract)?;
    let provider = object
        .get("provider")
        .and_then(serde_json::Value::as_object)
        .ok_or(NinjaOneError::MalformedContract)?;
    let consumer = object
        .get("consumer")
        .and_then(serde_json::Value::as_object)
        .ok_or(NinjaOneError::MalformedContract)?;
    let honesty = object
        .get("honesty")
        .and_then(serde_json::Value::as_object)
        .ok_or(NinjaOneError::MalformedContract)?;
    let registration = object
        .get("registration")
        .and_then(serde_json::Value::as_object)
        .ok_or(NinjaOneError::MalformedContract)?;
    if !string_is("schemaVersion", CONTRACT_SCHEMA_VERSION)
        || !string_is("contractVersion", CONTRACT_VERSION)
        || object.get("layer").and_then(serde_json::Value::as_u64) != Some(1)
        || !string_is("pluginId", PLUGIN_ID)
        || service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
        || service
            .get("implementation")
            .and_then(serde_json::Value::as_str)
            != Some(SERVICE_NAME)
        || service.get("readOnly").and_then(serde_json::Value::as_bool) != Some(true)
        || service
            .get("externalWrites")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
        || provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
        || provider
            .get("implementation")
            .and_then(serde_json::Value::as_str)
            != Some(PROVIDER_NAME)
        || provider
            .get("connected")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
        || provider.get("native").and_then(serde_json::Value::as_bool) != Some(false)
        || consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
        || consumer
            .get("implementation")
            .and_then(serde_json::Value::as_str)
            != Some(CONSUMER_NAME)
        || !projection_array_contains("healthy")
        || !projection_array_contains("provider_unknown")
        || honesty
            .get("fixtureNative")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
        || honesty
            .get("recordingNative")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
        || honesty
            .get("loopbackNative")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
        || honesty
            .get("blockedEnvNative")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
        || registration
            .get("reversible")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        || registration
            .get("revocable")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        || registration
            .get("secretSerializable")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
    {
        return Err(NinjaOneError::MalformedContract);
    }
    Ok(())
}

/// SHA-256 identity of the exact checked-in contract bytes.
pub fn contract_digest() -> Digest {
    Digest::from_bytes(CONTRACT_JSON.as_bytes())
}

/// SHA-256 identity of the provider API/mode boundary.
pub fn provider_digest() -> Digest {
    Digest::from_text(format!(
        "{PROVIDER_ID}|{NINJAONE_API_ORIGIN}|{NINJAONE_API_REVISION}|GET|layer1"
    ))
}

/// SHA-256 identity of this standalone implementation revision.
pub fn implementation_digest() -> Digest {
    Digest::from_text(IMPLEMENTATION_REVISION)
}
