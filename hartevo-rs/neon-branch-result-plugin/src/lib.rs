//! Layer 1 Neon branch and verified-query result boundary.
//!
//! This crate is deliberately standalone and proposal/recording only. It
//! models an exact Neon organization/project/branch/endpoint/database/role
//! scope and an exact Hartevo Mission binding, but it does not create or
//! delete live branches, mutate endpoints, execute DDL/DML, expose a
//! connection string, or claim native Connected evidence.

#![forbid(unsafe_code)]

mod consumer;
mod error;
mod model;
mod provider;
mod service;

pub use consumer::MissionDatabaseResultConsumer;
pub use error::{InputViolation, NeonBranchResultError, NeonProviderError};
pub use model::*;
pub use provider::{
    NeonBranchResultProvider, NeonControlPlaneTransport, PostgresQueryTransport,
    RecordingNeonBranchResultProvider, RecordingNeonControlPlaneTransport,
    RecordingPostgresQueryTransport,
};
pub use service::NeonBranchResultService;

/// The versioned JSON contract shipped with this crate.
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/neon-branch-result/neon-branch-result.v1.json");

/// Layer 1's honest native boundary.
pub const NATIVE_GAP: &str = "BLOCKED_ENV: live Neon branch lifecycle, endpoint mutation, DDL/DML, live query/readback, repeatable-read verification, ambiguous-create recovery, and durable Work Product adoption are Layer 2 gaps";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_contract_is_versioned_and_native_claims_are_blocked() {
        let contract: serde_json::Value = serde_json::from_str(CONTRACT_JSON).expect("contract");
        assert_eq!(contract["schemaVersion"], NEON_BRANCH_RESULT_SCHEMA_VERSION);
        assert_eq!(
            contract["contractVersion"],
            NEON_BRANCH_RESULT_CONTRACT_VERSION
        );
        assert_eq!(contract["layer"], 1);
        assert!(!NativeStatus::BlockedEnv.is_native());
        assert!(!EvidenceSource::Fixture.is_native());
        assert!(!TransportMode::Loopback.is_native());
    }
}
