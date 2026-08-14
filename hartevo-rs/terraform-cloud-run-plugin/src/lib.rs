//! Layer 1 HCP Terraform run, policy, cost, and apply-result proposal
//! capability.
//!
//! The crate is a standalone nested workspace. It contains a typed official
//! JSON:API read seam plus recording/fixture transports, but it has no
//! configuration upload, run creation, cancellation, discard, apply, policy
//! override, workspace/state/variable mutation, raw state/plan retention, or
//! Hartevo kernel authority.

#![forbid(unsafe_code)]

mod consumer;
mod error;
mod model;
mod provider;
mod service;
mod transport;

pub use consumer::{MissionTerraformRunConsumer, MissionTerraformRunResult};
pub use error::{TerraformCloudRunError, TerraformCloudTransportError};
pub use model::*;
pub use provider::{
    BlockedEnvCredentialResolver, EnvironmentTerraformCloudCredentialResolver,
    StaticTerraformCloudCredentialResolver, TERRAFORM_CLOUD_NATIVE_GATE_ENVIRONMENT_VARIABLE,
    TERRAFORM_CLOUD_TOKEN_ENVIRONMENT_VARIABLE, TerraformCloudCredentialResolver,
    TerraformCloudRunProvider, TerraformCloudRunProviderState, TerraformCloudRunRecordingProvider,
};
pub use service::{
    TerraformCloudRunReadOnlyService, TerraformCloudRunService, TerraformCloudRunServiceDefinition,
    TerraformCloudRunServiceOperation,
};
pub use transport::{
    RecordingTerraformCloudTransport, RetryPolicy, SecretMaterial,
    TerraformCloudRecordingTransport, TerraformCloudRunApiTransport, TerraformCloudRunTransport,
    TerraformCloudTransportOperation, TerraformCloudWorkspaceApiRecord,
    UreqTerraformCloudTransport,
};

/// The versioned JSON contract shipped with the crate.
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/terraform-cloud-run/terraform-cloud-run.v1.json");

/// Layer 1's honest native boundary. Native token resolution, configuration
/// upload/run creation, explicit apply effects, terminal reconciliation, and
/// durable Mission adoption remain Layer 2 gaps.
pub const NATIVE_GAP: &str = "BLOCKED_ENV: native token resolution, configuration-version creation/upload, durable run creation, explicit apply effect receipt, terminal reconciliation, policy/cost native read-back, and verified Mission Outcome adoption are Layer 2 gaps";

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

    pub const fn policy_override() -> bool {
        false
    }

    pub const fn raw_state_or_plan_retention() -> bool {
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
        assert_eq!(
            document["provider"]["authorizationObscured404"],
            "not_found_or_unauthorized"
        );
        assert_eq!(document["provider"]["connectedEvidence"], false);
        assert!(!ReadOnlyAuthority::store());
        assert!(!ReadOnlyAuthority::keyring());
        assert!(!ReadOnlyAuthority::browser_profile());
        assert!(!ReadOnlyAuthority::external_writes());
        assert!(!ReadOnlyAuthority::policy_override());
        assert!(!ReadOnlyAuthority::raw_state_or_plan_retention());
        assert!(!ReadOnlyAuthority::kernel_authority());
        assert!(!ReadOnlyAuthority::native_connected());
        assert_eq!(contract_digest().as_str().len(), 64);
    }
}
