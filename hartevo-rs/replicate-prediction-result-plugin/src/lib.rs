//! Standalone Layer-1 Replicate prediction-result capability.
//!
//! The crate binds one exact account, model version-or-deployment, prediction,
//! status, metric, output URL-expiry, Project, Mission, and Work Product scope
//! to bounded read/proposal/recording evidence. It has no live HTTP client,
//! output download, prompt or raw-log retention, prediction mutation,
//! webhook/model/deployment mutation, generic model registry, Store, keyring,
//! kernel, or Outcome-adoption authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

mod consumer;
mod model;
mod provider;
mod service;

#[cfg(test)]
mod adversarial_tests;

pub use consumer::{
    AdoptionAvailability, ConsumerError, MissionReplicateResult, MissionReplicateResultConsumer,
    MissionResultState,
};
pub use model::{
    AccountId, ApiHost, DeploymentId, Digest, MAX_OUTPUT_URLS, MAX_PAGE_SIZE, MAX_PAGE_TOKEN_BYTES,
    MAX_RUNTIME_METRIC_MILLIS, MetricScope, MissionId, MissionScope, ModelBinding, ModelError,
    ModelId, ModelTarget, ModelVersion, OpaquePageToken, OutputEvidence, OutputUrlEvidence,
    OutputUrlExpiryScope, PermissionScope, PluginVersion, PredictionId, PredictionScope,
    PredictionStatus, ProjectId, ProjectScope, ProviderErrorEvidence, ProviderErrorKind,
    ProviderPredictionStatus, RedactionState, ReplicateAccountId, ReplicateDigestSet,
    ReplicateModelId, ReplicatePredictionId, ReplicatePredictionRecord,
    ReplicateProviderDefinition, ReplicateRegistration, ReplicateScope, Revision,
    RevocationReceipt, RuntimeMetrics, SecretKind, SecretReference, StatusExpectation, Timestamp,
    VersionOrDeployment, WorkProductId, WorkProductScope,
};
pub use provider::{
    BlockedEnvTransport, FakeReplicateTransport, FixtureReplicateTransport,
    LoopbackReplicateTransport, MAX_LIST_PAGES, PredictionGetRequest, PredictionListRequest,
    PredictionPage, ProviderListObservation, ProviderObservation, ProviderProvenance,
    RecordingReplicateTransport, ReplicateProvider, ReplicateProviderError, ReplicateProviderState,
    ReplicateTransport, RetryPolicy, TransportError,
};
pub use service::{
    ReplicatePredictionEvidence, ReplicatePredictionListProposal,
    ReplicatePredictionResultProposal, ReplicatePredictionResultService,
    ReplicateServiceDefinition, ServiceError,
};

pub const SCHEMA_VERSION: &str = "hartevo.replicate-prediction-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-REPLICATE-01-L1/v1";
pub const PLUGIN_ID: &str = "hartevo.replicate-prediction-result";
pub const SERVICE_ID: &str = "ReplicatePredictionResultService";
pub const PROVIDER_ID: &str = "replicate";
pub const CONSUMER_ID: &str = "MissionReplicateResultConsumer";
pub const SERVICE_VERSION: model::PluginVersion = model::PluginVersion::new(1, 0, 0);
pub const PROVIDER_VERSION: model::PluginVersion = model::PluginVersion::new(1, 0, 0);
pub const CONSUMER_VERSION: model::PluginVersion = model::PluginVersion::new(1, 0, 0);
pub const EVIDENCE_LEVEL: &str = "L1";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const OFFICIAL_HOST: &str = "https://api.replicate.com";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/replicate-prediction-result/replicate-prediction-result.v1.json"
);

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_JSON)
}

/// Layer 1 is explicitly below Connected/native, Store, kernel, and Outcome
/// authority. These const markers make the boundary easy for audits to assert.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReadOnlyAuthority;

impl ReadOnlyAuthority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn external_writes() -> bool {
        false
    }

    pub const fn output_download() -> bool {
        false
    }

    pub const fn prompt_retention() -> bool {
        false
    }

    pub const fn raw_log_retention() -> bool {
        false
    }

    pub const fn model_registry() -> bool {
        false
    }

    pub const fn kernel_authority() -> bool {
        false
    }

    pub const fn outcome_adoption() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn contract_is_versioned_layer_one_and_native_honest() {
        let contract: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(contract["schemaVersion"], SCHEMA_VERSION);
        assert_eq!(contract["contractVersion"], CONTRACT_VERSION);
        assert_eq!(contract["plugin"]["id"], PLUGIN_ID);
        assert_eq!(contract["service"]["id"], SERVICE_ID);
        assert_eq!(contract["service"]["consumer"], CONSUMER_ID);
        assert_eq!(contract["provider"]["id"], PROVIDER_ID);
        assert_eq!(contract["layer"], 1);
        assert_eq!(contract["childLayer"], false);
        assert_eq!(contract["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(contract["provider"]["nativeStatus"], BLOCKED_ENV);
        assert_eq!(contract["provider"]["connectedEvidence"], false);
        assert_eq!(contract["provider"]["nativeEvidence"], false);
        assert_eq!(contract["service"]["readOnly"], true);
        assert_eq!(contract["service"]["externalWrites"], false);
        assert_eq!(contract["service"]["kernelAuthority"], false);
        assert_eq!(contract["service"]["outcomeAdoption"], false);
        assert!(!ReadOnlyAuthority::connected());
        assert!(!ReadOnlyAuthority::native_provider());
        assert!(!ReadOnlyAuthority::external_writes());
        assert!(!ReadOnlyAuthority::output_download());
        assert!(!ReadOnlyAuthority::prompt_retention());
        assert!(!ReadOnlyAuthority::raw_log_retention());
        assert!(!ReadOnlyAuthority::model_registry());
        assert!(!ReadOnlyAuthority::kernel_authority());
        assert!(!ReadOnlyAuthority::outcome_adoption());
        assert!(contract_digest().is_valid());
    }
}
