#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::doc_markdown,
    clippy::manual_let_else,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]
#![doc = "Standalone Layer-1 Fivetran sync-result plugin."]
//!
//! This crate is a bounded read/proposal/recording boundary for Fivetran data
//! movement. It has no native HTTP client, API-key resolver, sync effect,
//! webhook authority, destination read-back, generic connector registry,
//! durable provider receipt, or Domain Kernel authority.

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{
    MissionFivetranSyncConsumer, MissionFivetranSyncObservation, MissionFivetranSyncResult,
};
pub use model::*;
pub use provider::{FivetranProvider, FivetranProviderState};
pub use service::{FivetranServiceDefinition, FivetranSyncResultService};
pub use transport::*;

pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo.fivetran-sync-result.contract/v1";
pub const CONTRACT_VERSION: &str = "EXT-FIVETRAN-01-L1/v1";
pub const PLUGIN_ID: &str = "fivetran.sync-result";
pub const SERVICE_ID: &str = "fivetran.sync-result";
pub const SERVICE_NAME: &str = "FivetranSyncResultService";
pub const PROVIDER_ID: &str = "fivetran.data-movement";
pub const PROVIDER_NAME: &str = "FivetranProvider";
pub const CONSUMER_ID: &str = "mission.fivetran-sync-result";
pub const CONSUMER_NAME: &str = "MissionFivetranSyncConsumer";
pub const PLUGIN_VERSION: Version = Version::new(1, 0, 0);
pub const FIVETRAN_API_REVISION: &str = "fivetran-rest-connections-r1";
pub const FIVETRAN_API_ORIGIN: &str = "https://api.fivetran.com";
pub const FIVETRAN_API_ACCEPT: &str = "application/json;version=2";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_PAGE_ITEMS: usize = 100;
pub const MAX_PAGES: usize = 4;
pub const MAX_SCHEMAS: usize = 256;
pub const MAX_TABLES: usize = 4_096;
pub const MAX_COLUMNS: usize = 65_536;
pub const MAX_STATE_FIELDS: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/fivetran-sync-result/fivetran-sync-result.v1.json");

pub type Result<T> = std::result::Result<T, FivetranError>;

/// Validates the checked-in versioned contract's identity and Layer-1
/// invariants. Full JSON-Schema evaluation remains a host/CI concern.
pub fn validate_contract() -> Result<()> {
    let document: serde_json::Value =
        serde_json::from_str(CONTRACT_JSON).map_err(|_| FivetranError::MalformedContract)?;
    let object = document
        .as_object()
        .ok_or(FivetranError::MalformedContract)?;
    let const_value = |path: &[&str]| -> Option<&serde_json::Value> {
        let mut value = object.get(path[0])?;
        for key in &path[1..] {
            value = value.as_object()?.get(*key)?;
        }
        value.get("const")
    };
    let matches = |path: &[&str], expected: &str| {
        const_value(path).and_then(serde_json::Value::as_str) == Some(expected)
    };
    if !matches(&["properties", "schemaVersion"], CONTRACT_SCHEMA_VERSION)
        || !matches(&["properties", "contractVersion"], CONTRACT_VERSION)
        || !matches(
            &["properties", "service", "properties", "implementation"],
            SERVICE_NAME,
        )
        || !matches(
            &["properties", "provider", "properties", "implementation"],
            PROVIDER_NAME,
        )
        || !matches(
            &["properties", "consumer", "properties", "implementation"],
            CONSUMER_NAME,
        )
    {
        return Err(FivetranError::MalformedContract);
    }
    Ok(())
}

/// SHA-256 digest of the checked-in contract bytes.
pub fn contract_digest() -> Digest {
    Digest::from_bytes(CONTRACT_JSON.as_bytes())
}
