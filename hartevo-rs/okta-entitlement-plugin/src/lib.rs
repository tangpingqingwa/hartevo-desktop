//! Read-only Layer-1 Okta entitlement evidence.
//!
//! This crate is deliberately below Hartevo Identity, Project, Mission,
//! Consent, Effect, Receipt, Verification, and Outcome authority.  It carries
//! provider evidence and deterministic proposals only.  No method in this
//! crate mints a token, performs an Okta mutation, or adopts an Outcome.

mod canonical;
mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::MissionOktaEntitlementConsumer;
pub use model::*;
pub use provider::*;
pub use service::*;

pub const PLUGIN_ID: &str = "hartevo.okta.entitlement-evidence";
pub const PLUGIN_VERSION: &str = "okta-entitlement-layer1/v1";
pub const CONTRACT_VERSION: &str = "okta-entitlement-layer1/v1";
pub const PROVIDER_ID: &str = "okta";
pub const PROVIDER_API_REVISION: &str = "okta-system-log-and-entitlement/v1";
pub const CAPABILITY_ID: &str = "okta.entitlement.evidence.read";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/okta-entitlement/contract.v1.json");

pub const REQUIRED_USER_READ_SCOPE: &str = "okta.users.read";
pub const REQUIRED_GROUP_READ_SCOPE: &str = "okta.groups.read";
pub const REQUIRED_APPLICATION_READ_SCOPE: &str = "okta.apps.read";
pub const REQUIRED_SYSTEM_LOG_READ_SCOPE: &str = "okta.logs.read";

pub const MAX_PAGE_SIZE: usize = 100;
pub const MAX_PAGES: usize = 100;
pub const MAX_ITEMS: usize = 10_000;
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_SYSTEM_LOG_WINDOW_SECONDS: i64 = 86_400;
pub const MAX_SYSTEM_LOG_EVENTS: usize = 500;

/// The exact contract digest used by registrations and evidence fences.
pub fn contract_digest() -> String {
    canonical::sha256_hex(CONTRACT_JSON.as_bytes())
}

/// The Layer-1 authority surface is always external evidence only.
pub const fn connected() -> bool {
    false
}

/// Layer 1 does not expose native HTTPS/provider authority.
pub const fn native() -> bool {
    false
}

/// Layer 1 never exposes provider mutation authority.
pub const fn mutation_authority() -> bool {
    false
}
