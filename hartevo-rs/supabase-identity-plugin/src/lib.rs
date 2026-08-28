//! Read-only Supabase identity, grant, and RLS policy evidence.
//!
//! The crate is intentionally standalone.  It does not join Hartevo's root
//! workspace and it does not import the domain kernel.  Its values are
//! provider evidence and non-durable proposals only: Supabase is never
//! treated as Hartevo Identity, Consent, Effect, Receipt, Verification,
//! Outcome, or Truth authority.

mod canonical;
mod consumer;
mod error;
mod model;
mod provider;
mod service;

pub use consumer::{MissionSupabaseIdentityConsumer, MissionSupabasePolicyConsumer};
pub use error::{SupabaseIdentityError, SupabaseProviderError};
pub use model::*;
pub use provider::*;
pub use service::{SupabaseIdentityPolicyService, SupabaseIdentityService};

pub const PLUGIN_ID: &str = "hartevo.supabase.identity-policy";
pub const PLUGIN_VERSION: &str = "supabase-identity-policy-layer1/v1";
pub const CONTRACT_VERSION: &str = "supabase-identity-policy-layer1/v1";
pub const PROVIDER_ID: &str = "supabase";
pub const PROVIDER_API_REVISION: &str = "supabase-management-auth-postgrest-metadata/v1";
pub const CAPABILITY_ID: &str = "supabase.identity.rls-policy.evidence.read";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/supabase-identity-plugin/contract.v1.json");

pub const MAX_ROLES: usize = 32;
pub const MAX_TABLES: usize = 64;
pub const MAX_COLUMNS_PER_TABLE: usize = 64;
pub const MAX_FUNCTIONS: usize = 32;
pub const MAX_GRANTS: usize = 512;
pub const MAX_POLICIES: usize = 512;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// The digest bound into registration and all evidence records.
pub fn contract_digest() -> String {
    canonical::sha256_hex(CONTRACT_JSON.as_bytes())
}

/// Layer 1 never asserts a live connection, including fixture, recording,
/// loopback, and BLOCKED_ENV seams.
pub const fn connected() -> bool {
    false
}

/// Layer 1 has no native provider implementation.
pub const fn native() -> bool {
    false
}

/// This plugin can propose a policy decision but cannot execute or adopt one.
pub const fn mutation_authority() -> bool {
    false
}

/// Supabase is external evidence, not Hartevo identity or truth authority.
pub const fn identity_authority() -> bool {
    false
}

/// Supabase policy metadata is not a Hartevo truth source.
pub const fn truth_authority() -> bool {
    false
}
