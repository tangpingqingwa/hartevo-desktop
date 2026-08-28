//! Layer-1 Google Cloud Run deployment-result capability.
//!
//! This is a standalone nested workspace. It exposes typed Cloud Run service,
//! provider, and Mission-consumer seams for bounded GET-shaped evidence,
//! proposal compilation, recording, and digest verification. It imports no
//! Hartevo Store, keyring, browser profile, application, desktop, domain,
//! storage, catalog, or kernel authority.

#![forbid(unsafe_code)]

mod consumer;
mod error;
mod model;
mod provider;
mod service;
mod transport;

pub use consumer::{MissionCloudRunDeploymentConsumer, MissionCloudRunDeploymentResult};
pub use error::{CloudRunDeploymentResultError, CloudRunTransportError};
pub use model::*;
pub use provider::{
    BlockedEnvCredentialResolver, CLOUD_RUN_CREDENTIAL_ENVIRONMENT_VARIABLE,
    CLOUD_RUN_NATIVE_GATE_ENVIRONMENT_VARIABLE, CloudRunCredentialResolver,
    CloudRunDeploymentResultProvider, CloudRunProvider, CloudRunProviderState,
    CloudRunRecordingProvider, EnvironmentCloudRunCredentialResolver,
    StaticCloudRunCredentialResolver,
};
pub use service::{
    CloudRunDeploymentResultService, CloudRunReadOnlyService, CloudRunServiceDefinition,
    CloudRunServiceOperation,
};
pub use transport::{
    CloudRunApiTransport, CloudRunRecordingTransport, CloudRunTransport,
    CloudRunTransportOperation, FakeCloudRunTransport, RecordingCloudRunTransport, RetryPolicy,
    SecretMaterial, UreqCloudRunTransport,
};

pub const SCHEMA_VERSION: &str = "hartevo.cloud-run-deployment-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-CLOUDRUN-01-L1/v1";
pub const PLUGIN_ID: &str = "hartevo.cloud-run-deployment-result";
pub const PLUGIN_VERSION: PluginVersion = PluginVersion::new(1, 0, 0);
pub const PROVIDER_ID: &str = "cloud-run";
pub const PROVIDER_VERSION: PluginVersion = PluginVersion::new(1, 0, 0);
pub const SERVICE_ID: &str = "CloudRunDeploymentResultService";
pub const CONSUMER_ID: &str = "MissionCloudRunDeploymentConsumer";
pub const CLOUD_RUN_API_BASE_URL: &str = "https://run.googleapis.com/apis/run.googleapis.com/v2";
pub const NATIVE_GAP: &str = "BLOCKED_ENV: native OAuth/service-account resolution, live Cloud Run HTTPS reads, consented create/patch/delete and traffic/IAM effects, durable receipts, independent URL read-back, and verified Work Product adoption remain Layer 2 gaps";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/cloud-run-deployment-result/cloud-run-deployment-result.v1.json"
);

pub fn contract_digest() -> Digest {
    Digest::from_bytes(CONTRACT_JSON.as_bytes())
}

/// Compile-time authority marker for audits and adversarial tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReadOnlyAuthority;

impl ReadOnlyAuthority {
    pub const fn store() -> bool {
        false
    }

    pub const fn keyring() -> bool {
        false
    }

    pub const fn browser_profile() -> bool {
        false
    }

    pub const fn external_writes() -> bool {
        false
    }

    pub const fn traffic_mutation() -> bool {
        false
    }

    pub const fn iam_mutation() -> bool {
        false
    }

    pub const fn raw_logs() -> bool {
        false
    }

    pub const fn kernel_authority() -> bool {
        false
    }

    pub const fn native_connected() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn embedded_contract_is_versioned_read_only_and_native_honest() {
        let document: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(document["schemaVersion"], SCHEMA_VERSION);
        assert_eq!(document["contractVersion"], CONTRACT_VERSION);
        assert_eq!(document["layer"], 1);
        assert_eq!(document["service"]["externalWrites"], false);
        assert_eq!(document["service"]["kernelAuthority"], false);
        assert_eq!(document["provider"]["connectedEvidence"], false);
        assert_eq!(
            document["provider"]["authentication"]["environmentExport"],
            false
        );
        assert_eq!(
            document["semantics"]["observedGeneration"],
            "exact_generation_required"
        );
        assert!(!ReadOnlyAuthority::store());
        assert!(!ReadOnlyAuthority::keyring());
        assert!(!ReadOnlyAuthority::browser_profile());
        assert!(!ReadOnlyAuthority::external_writes());
        assert!(!ReadOnlyAuthority::traffic_mutation());
        assert!(!ReadOnlyAuthority::iam_mutation());
        assert!(!ReadOnlyAuthority::raw_logs());
        assert!(!ReadOnlyAuthority::kernel_authority());
        assert!(!ReadOnlyAuthority::native_connected());
        assert_eq!(contract_digest().as_str().len(), 64);
    }
}
