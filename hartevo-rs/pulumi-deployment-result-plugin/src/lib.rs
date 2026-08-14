//! Layer-1 Pulumi Cloud deployment-result capability.
//!
//! The crate is a standalone nested workspace. It exposes a typed read seam,
//! bounded evidence and deterministic recording/proposal behavior, while
//! deliberately excluding deployment effects, mutation, raw provider payloads,
//! kernel authority, and Outcome adoption.

#![forbid(unsafe_code)]

mod consumer;
mod error;
mod model;
mod provider;
mod service;
mod transport;

pub use consumer::*;
pub use error::*;
pub use model::*;
pub use provider::*;
pub use service::*;
pub use transport::*;

pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/pulumi-deployment-result/pulumi-deployment-result.v1.schema.json"
);

/// Layer-1's honest native boundary. No current path claims Connected/native
/// evidence or performs a deployment effect, mutation, raw export, or Outcome
/// adoption.
pub const NATIVE_GAP: &str = "BLOCKED_ENV: native Pulumi credential resolution, durable deployment effects, terminal reconciliation, independent resource read-back, and verified Mission Outcome adoption are optional Layer 2 gaps";

pub(crate) fn digest_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest as Sha2Digest, Sha256};

    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub(crate) fn digest_json<T: serde::Serialize + ?Sized>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("contract values serialize");
    digest_bytes(&bytes)
}

pub(crate) fn digest_text(value: &str) -> String {
    digest_bytes(value.as_bytes())
}

pub(crate) fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
}

pub(crate) fn valid_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn valid_cursor(value: &str) -> bool {
    valid_identifier(value, model::MAX_CURSOR_BYTES)
}

pub const SCHEMA_VERSION: &str = "hartevo.pulumi-deployment-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-PULUMI-01-L1/v1";
pub const PLUGIN_ID: &str = "hartevo.pulumi-deployment-result";
pub const PLUGIN_VERSION: PluginVersion = PluginVersion::new(1, 0, 0);
pub const PROVIDER_ID: &str = "pulumi.cloud.deployment";
pub const PROVIDER_VERSION: PluginVersion = PluginVersion::new(1, 0, 0);
pub const SERVICE_ID: &str = "pulumi.deployment.result.read";
pub const CONSUMER_ID: &str = "mission.pulumi.deployment.result";
pub const PULUMI_CLOUD_API_BASE_URL: &str = "https://api.pulumi.com";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const LAYER: u8 = 1;

pub fn contract_digest() -> String {
    digest_bytes(CONTRACT_JSON.as_bytes())
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn embedded_contract_is_versioned_bounded_and_non_authoritative() {
        let contract: Value = serde_json::from_str(CONTRACT_JSON).expect("valid contract JSON");
        assert_eq!(
            contract["properties"]["schemaVersion"]["const"],
            SCHEMA_VERSION
        );
        assert_eq!(
            contract["properties"]["contractVersion"]["const"],
            CONTRACT_VERSION
        );
        assert_eq!(contract["properties"]["layer"]["const"], LAYER);
        assert_eq!(
            contract["properties"]["service"]["properties"]["externalWrites"]["const"],
            false
        );
        assert_eq!(
            contract["properties"]["service"]["properties"]["outcomeAdoption"]["const"],
            false
        );
        assert_eq!(
            contract["properties"]["provider"]["properties"]["nativeStatus"]["const"],
            BLOCKED_ENV
        );
        assert_eq!(
            contract["properties"]["provider"]["properties"]["connectedEvidence"]["const"],
            false
        );
        assert_eq!(contract_digest().len(), 71);
        assert!(NATIVE_GAP.starts_with(BLOCKED_ENV));
    }
}
