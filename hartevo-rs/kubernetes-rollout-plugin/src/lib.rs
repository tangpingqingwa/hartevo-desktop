//! Layer-1 Kubernetes rollout capability for Hartevo.
//!
//! This crate is intentionally standalone.  It defines a typed service,
//! provider seam, and Mission result consumer without importing Store,
//! keyring, browser profile, or kernel authority.  The only execution surface
//! is bounded read/proposal/recording evidence.  The default provider is
//! `BLOCKED_ENV`; a recording transport is useful for adversarial tests but
//! can never become connected or native evidence.

#![forbid(unsafe_code)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::*;
pub use model::*;
pub use provider::*;
pub use service::*;

use serde::Serialize;
use sha2::{Digest as Sha2Digest, Sha256};

pub const CONTRACT_VERSION: &str = "kubernetes-rollout/v1";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const KUBERNETES_API_REVISION: &str = "apps/v1";
pub const SERVICE_ID: &str = "kubernetes.rollout.read";
pub const PROVIDER_ID: &str = "kubernetes.api.rollout";
pub const MISSION_CONSUMER_ID: &str = "mission.kubernetes.rollout.result";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const LAYER: u8 = 1;

const CONTRACT_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../contracts/plugins/kubernetes-rollout/kubernetes-rollout.v1.schema.json"
));

/// Returns the SHA-256 digest of the exact versioned contract file shipped by
/// the repository.  Registration binds this digest instead of relying on a
/// mutable catalog or manifest.
pub fn contract_digest() -> String {
    digest_bytes(CONTRACT_BYTES)
}

pub(crate) fn digest_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("sha256:{:x}", digest.finalize())
}

pub(crate) fn digest_text(text: &str) -> String {
    digest_bytes(text.as_bytes())
}

pub(crate) fn digest_json<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("all contract values are serializable");
    digest_bytes(&bytes)
}

pub(crate) fn valid_sha256_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn valid_identifier(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
}

pub(crate) fn valid_kubernetes_name(value: &str) -> bool {
    valid_identifier(value, 253)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_.".contains(&byte)
        })
        && !value.starts_with(['-', '.'])
        && !value.ends_with(['-', '.'])
}

pub(crate) fn valid_digest_map<K: Ord>(values: &std::collections::BTreeMap<K, String>) -> bool {
    !values.is_empty() && values.values().all(|digest| valid_sha256_digest(digest))
}
