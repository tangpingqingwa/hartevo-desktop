//! Layer-1 Amazon SageMaker endpoint deployment-result capability.
//!
//! The crate binds one exact account/region/endpoint/config/variant/model
//! revision/traffic snapshot to a Mission deployment-verification objective.
//! It reads only bounded typed metadata through recording/fake/fixture/loopback
//! seams, compiles a digest-fenced proposal, records an in-memory receipt, and
//! verifies provider fingerprints. It has no Store, keyring, kernel, mutation,
//! invocation, logs, data-capture payload, or Outcome-adoption authority.

#![forbid(unsafe_code)]

mod consumer;
mod error;
mod model;
mod provider;
mod service;
mod transport;

pub use consumer::{MissionSageMakerDeploymentConsumer, MissionSageMakerDeploymentResult};
pub use error::{Result, SageMakerEndpointResultError};
pub use model::*;
pub use provider::{SageMakerProvider, SageMakerProviderState, SageMakerReadOnlyProvider};
pub use service::{
    SageMakerEndpointResultService, SageMakerReadOnlyService, SageMakerServiceDefinition,
};
pub use transport::{
    BlockedEnvCredentialResolver, BlockedEnvSageMakerTransport, FakeSageMakerTransport,
    FixtureSageMakerTransport, LoopbackSageMakerTransport, RecordingSageMakerTransport,
    SageMakerTransport, SageMakerTransportError, SageMakerTransportOperation,
    SigV4CredentialMaterial, SigV4CredentialResolver, SigV4SageMakerTransport,
    StaticSigV4CredentialResolver,
};

pub const SCHEMA_VERSION: &str = "hartevo.sagemaker-endpoint-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-SAGEMAKER-01-L1/v1";
pub const PLUGIN_ID: &str = "hartevo.sagemaker-endpoint-result";
pub const PLUGIN_VERSION: PluginVersion = PluginVersion::new(1, 0, 0);
pub const PROVIDER_ID: &str = "sagemaker";
pub const PROVIDER_VERSION: PluginVersion = PluginVersion::new(1, 0, 0);
pub const SERVICE_ID: &str = "SageMakerEndpointResultService";
pub const CONSUMER_ID: &str = "MissionSageMakerDeploymentConsumer";
pub const NATIVE_GAP: &str = "BLOCKED_ENV: native SigV4 resolution, live SageMaker HTTPS reads, durable receipts, independent endpoint/config readback, and verified Work Product adoption remain Layer 2 gaps";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/sagemaker-endpoint-result/sagemaker-endpoint-result.v1.json"
);

pub fn contract_digest() -> Digest {
    Digest::from_bytes(CONTRACT_JSON.as_bytes())
}

/// Compile-time authority marker used by audits and adversarial tests.
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

    pub const fn endpoint_mutation() -> bool {
        false
    }

    pub const fn traffic_mutation() -> bool {
        false
    }

    pub const fn capacity_mutation() -> bool {
        false
    }

    pub const fn invoke_endpoint() -> bool {
        false
    }

    pub const fn raw_logs() -> bool {
        false
    }

    pub const fn raw_data_capture() -> bool {
        false
    }

    pub const fn kernel_authority() -> bool {
        false
    }

    pub const fn outcome_adoption() -> bool {
        false
    }

    pub const fn native_connected() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn embedded_contract_is_layer_one_read_only_and_native_honest() {
        let document: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(document["schemaVersion"], SCHEMA_VERSION);
        assert_eq!(document["contractVersion"], CONTRACT_VERSION);
        assert_eq!(document["layer"], 1);
        assert_eq!(document["service"]["readOnly"], true);
        assert_eq!(document["service"]["externalWrites"], false);
        assert_eq!(document["service"]["kernelAuthority"], false);
        assert_eq!(document["service"]["outcomeAdoption"], false);
        assert_eq!(document["provider"]["connectedEvidence"], false);
        assert_eq!(document["provider"]["nativeStatus"], "BLOCKED_ENV");
        assert_eq!(
            document["provider"]["authentication"]["serializedCredentials"],
            false
        );
        assert_eq!(contract_digest().as_str().len(), 64);
        assert!(!ReadOnlyAuthority::store());
        assert!(!ReadOnlyAuthority::keyring());
        assert!(!ReadOnlyAuthority::browser_profile());
        assert!(!ReadOnlyAuthority::external_writes());
        assert!(!ReadOnlyAuthority::endpoint_mutation());
        assert!(!ReadOnlyAuthority::traffic_mutation());
        assert!(!ReadOnlyAuthority::capacity_mutation());
        assert!(!ReadOnlyAuthority::invoke_endpoint());
        assert!(!ReadOnlyAuthority::raw_logs());
        assert!(!ReadOnlyAuthority::raw_data_capture());
        assert!(!ReadOnlyAuthority::kernel_authority());
        assert!(!ReadOnlyAuthority::outcome_adoption());
        assert!(!ReadOnlyAuthority::native_connected());
        assert!(!ReadOnlyAuthority::first_party());
    }
}
