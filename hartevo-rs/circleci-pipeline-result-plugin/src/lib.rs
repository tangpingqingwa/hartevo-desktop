//! Standalone Layer-1 CircleCI pipeline-result plugin.
//!
//! The crate owns a typed CircleCI service/provider/Mission consumer seam for
//! bounded read, proposal, recording, and digest verification. It has no
//! native HTTPS client, keyring, Store, Effect authority, scheduler, raw-log
//! retention, artifact-byte download, or kernel Outcome authority. Fixture,
//! recording, and loopback transports are deterministic evidence sources, not
//! Connected/native claims.

#![deny(unsafe_code)]

mod consumer;
mod error;
mod model;
mod provider;
mod service;
mod transport;

pub use consumer::MissionCircleCiPipelineConsumer;
pub use error::{CircleCiPipelineResultError, CircleCiProviderError};
pub use model::*;
pub use provider::{
    BlockedEnvCredentialResolver, CircleCiCredentialResolver, CircleCiProvider,
    CircleCiProviderState, StaticCircleCiCredentialResolver,
};
pub use service::{
    CircleCiPipelineResultOperation, CircleCiPipelineResultService,
    CircleCiPipelineResultServiceDefinition,
};
pub use transport::{
    CircleCiEndpoint, CircleCiFixture, CircleCiFixtureTransport, CircleCiPage,
    CircleCiPipelineResponse, CircleCiTransport, CircleCiTransportOperation,
    CircleCiTransportOutcome, CircleCiTransportReceipt, FakeCircleCiTransport, FixtureFailure,
    LoopbackCircleCiTransport, RawApproval, RawArtifactMetadata, RawJob, RawPipeline, RawWorkflow,
    RecordingCircleCiTransport, SecretMaterial,
};

pub const CIRCLECI_RESULT_SCHEMA_VERSION: &str = "hartevo.circleci-pipeline-result/v1";
pub const CIRCLECI_RESULT_CONTRACT_VERSION: &str = "EXT-CIRCLECI-01-L1/v1";
pub const CIRCLECI_API_VERSION: &str = "v2";
pub const CIRCLECI_API_BASE_PATH: &str = "/api/v2";
pub const CIRCLECI_SECRET_REFERENCE_ENV: &str = "HARTEVO_CIRCLECI_SECRET_REFERENCE";
pub const CIRCLECI_PLUGIN_ID: &str = "circleci-pipeline-result";
pub const CIRCLECI_PLUGIN_VERSION: u64 = 1;
pub const CIRCLECI_PROVIDER_ID: &str = "CircleCiProvider";
pub const CIRCLECI_PROVIDER_VERSION: u64 = 1;
pub const CIRCLECI_SERVICE_ID: &str = "CircleCiPipelineResultService";
pub const CIRCLECI_MISSION_CONSUMER_ID: &str = "MissionCircleCiPipelineConsumer";
pub const CIRCLECI_RESULT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/circleci-pipeline-result/contract.v1.json");

pub fn contract_digest() -> Digest {
    sha256_digest(CIRCLECI_RESULT_CONTRACT_JSON.as_bytes())
}

/// Explicit Layer-1 authority declaration. All capabilities are false because
/// this root slice cannot mutate CircleCI, retain native receipts, or decide a
/// kernel Truth/Outcome.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReadOnlyAuthority;

impl ReadOnlyAuthority {
    pub const fn external_write() -> bool {
        false
    }

    pub const fn trigger() -> bool {
        false
    }

    pub const fn rerun() -> bool {
        false
    }

    pub const fn cancel() -> bool {
        false
    }

    pub const fn approve() -> bool {
        false
    }

    pub const fn config_mutation() -> bool {
        false
    }

    pub const fn ssh_or_debug() -> bool {
        false
    }

    pub const fn raw_logs() -> bool {
        false
    }

    pub const fn artifact_bytes() -> bool {
        false
    }

    pub const fn generic_ci_registry() -> bool {
        false
    }

    pub const fn deployment_scheduler() -> bool {
        false
    }

    pub const fn kernel_authority() -> bool {
        false
    }

    pub const fn outcome_adoption() -> bool {
        false
    }

    pub const fn durable_native_receipt() -> bool {
        false
    }

    pub const fn native_connected() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        CIRCLECI_RESULT_CONTRACT_JSON, CIRCLECI_RESULT_CONTRACT_VERSION,
        CIRCLECI_RESULT_SCHEMA_VERSION, CircleCiPipelineResultServiceDefinition, ReadOnlyAuthority,
        contract_digest,
    };

    #[test]
    fn contract_freezes_layer_one_scope_redaction_and_native_gap() {
        let contract: Value =
            serde_json::from_str(CIRCLECI_RESULT_CONTRACT_JSON).expect("CircleCI contract JSON");
        assert_eq!(contract["schemaVersion"], CIRCLECI_RESULT_SCHEMA_VERSION);
        assert_eq!(
            contract["contractVersion"],
            CIRCLECI_RESULT_CONTRACT_VERSION
        );
        assert_eq!(contract["layer"], 1);
        assert_eq!(contract["evidence"]["pageTokenPagination"], true);
        assert_eq!(contract["registration"]["reversible"], true);
        assert_eq!(contract["registration"]["versionFenced"], true);
        assert_eq!(contract["registration"]["contractFenced"], true);
        assert_eq!(contract["registration"]["providerFenced"], true);
        assert_eq!(contract["registration"]["permissionFenced"], true);
        assert_eq!(contract["redaction"]["secretMaterial"], false);
        assert_eq!(contract["redaction"]["rawLogs"], false);
        assert_eq!(contract["redaction"]["artifactBytes"], false);
        assert_eq!(contract["authority"]["trigger"], false);
        assert_eq!(contract["authority"]["rerun"], false);
        assert_eq!(contract["authority"]["cancel"], false);
        assert_eq!(contract["authority"]["approve"], false);
        assert_eq!(contract["authority"]["kernelAuthority"], false);
        assert_eq!(contract_digest().len(), 64);
        assert!(!ReadOnlyAuthority::external_write());
        assert!(!ReadOnlyAuthority::trigger());
        assert!(!ReadOnlyAuthority::rerun());
        assert!(!ReadOnlyAuthority::cancel());
        assert!(!ReadOnlyAuthority::approve());
        assert!(!ReadOnlyAuthority::config_mutation());
        assert!(!ReadOnlyAuthority::ssh_or_debug());
        assert!(!ReadOnlyAuthority::raw_logs());
        assert!(!ReadOnlyAuthority::artifact_bytes());
        assert!(!ReadOnlyAuthority::generic_ci_registry());
        assert!(!ReadOnlyAuthority::deployment_scheduler());
        assert!(!ReadOnlyAuthority::kernel_authority());
        assert!(!ReadOnlyAuthority::outcome_adoption());
        assert!(!ReadOnlyAuthority::durable_native_receipt());
        assert!(!ReadOnlyAuthority::native_connected());
    }

    #[test]
    fn service_definition_is_typed_and_read_only() {
        let definition = CircleCiPipelineResultServiceDefinition::layer1();
        definition.validate().expect("valid service definition");
        assert_eq!(definition.operations.len(), 8);
        assert!(definition.read_only);
        assert!(!definition.external_writes);
        assert!(!definition.durable_native_receipts);
        assert!(!definition.kernel_outcome_authority);
        assert!(!definition.native_connected);
    }
}
