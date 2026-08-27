//! Standalone Layer-1 HashiCorp Nomad deployment-result evidence.
//!
//! The crate owns only a bounded, redacted jobs/deployments/allocations
//! read/proposal/local-record/verify seam. It deliberately imports no
//! Hartevo Store, keyring, application, desktop, domain, storage, catalog,
//! connector, kernel, or effect authority.

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::if_not_else)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::similar_names)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::unnecessary_wraps)]

mod consumer;
mod error;
mod model;
mod provider;
mod service;

pub use consumer::{MissionNomadDeploymentConsumer, MissionNomadDeploymentResult};
pub use error::{NomadDeploymentResultError, NomadTransportError, Result};
pub use model::*;
pub use provider::{
    BlockedEnvNomadTransport, FakeNomadTransport, FixtureNomadTransport, LoopbackNomadTransport,
    NomadApiResponse, NomadBlockedEnvTransport, NomadFakeTransport, NomadFixtureTransport,
    NomadLoopbackTransport, NomadProvider, NomadProviderDefinition, NomadProviderSnapshot,
    NomadRecordingTransport, NomadTransport, NomadWireAllocation, NomadWireDeployment,
    NomadWireJob, NomadWireTaskGroup, RecordingNomadTransport, RecordingTransport,
};
pub use service::{
    NomadCapabilityDescription, NomadDeploymentRegistration, NomadDeploymentResultService,
    NomadDeploymentServiceDefinition,
};

pub const SCHEMA_VERSION: &str = "hartevo.nomad-deployment-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-NOMAD-01-L1/v1";
pub const PLUGIN_ID: &str = "nomad.deployment-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "nomad.deployment-result.read";
pub const PROVIDER_ID: &str = "nomad.deployment-result.recording";
pub const PROVIDER_VERSION: &str = "nomad-provider/v1";
pub const PROVIDER_API_REVISION: &str = "nomad-jobs-deployments-allocations-v1";
pub const CONSUMER_ID: &str = "mission.nomad-deployment.consumer";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_SCHEMA: &str = SCHEMA_VERSION;
pub const CONTRACT_DIGEST: &str =
    "cb9ad8b2d5e8b509f6790bbb3048204d822bcf77efaaf8bd7facbb7e00b5fef7";
pub const NOMAD_API_REVISION: &str = PROVIDER_API_REVISION;
pub const NOMAD_BLOCKED_ENV: &str = BLOCKED_ENV;
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.nomad-deployment-result/v1|layer=1|service=nomad.deployment-result.read|provider=nomad.deployment-result.recording|consumer=mission.nomad-deployment.consumer";
pub const NATIVE_GAP: &str = "BLOCKED_ENV: native Nomad ACL/Vault resolution, live HTTPS reads, durable provider receipts, independent deployment read-back, consented Nomad effects, and verified Work Product/Outcome adoption remain Layer-2 gaps";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/nomad-deployment-result/nomad-deployment-result.v1.json"
);

/// The contract digest is bound to the stable digest input, not to mutable
/// credential material or to an unbounded provider response.
pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

#[must_use]
pub const fn plugin_version() -> &'static str {
    PLUGIN_VERSION
}

pub fn provider_digest() -> Digest {
    NomadProviderDefinition::default().provider_digest
}

/// Layer 1's explicit authority boundary. Every method is a compile-time
/// discoverable false claim used by contract and adversarial tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuthorityBoundary;

impl AuthorityBoundary {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn first_party_provider() -> bool {
        false
    }

    pub const fn truth() -> bool {
        false
    }

    pub const fn consent() -> bool {
        false
    }

    pub const fn effect() -> bool {
        false
    }

    pub const fn receipt() -> bool {
        false
    }

    pub const fn verification() -> bool {
        false
    }

    pub const fn outcome() -> bool {
        false
    }

    pub const fn external_writes() -> bool {
        false
    }

    pub const fn work_product_adoption() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn embedded_contract_is_layer_one_and_native_honest() {
        let contract: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(contract["schemaVersion"], SCHEMA_VERSION);
        assert_eq!(contract["contractVersion"], CONTRACT_VERSION);
        assert_eq!(contract["layer"], 1);
        assert_eq!(contract["contractDigest"], contract_digest().as_str());
        assert_eq!(contract["service"]["type"], "NomadDeploymentResultService");
        assert_eq!(contract["provider"]["type"], "NomadProvider");
        assert_eq!(
            contract["consumer"]["type"],
            "MissionNomadDeploymentConsumer"
        );
        assert_eq!(contract["authority"]["externalWrites"], false);
        assert_eq!(contract["authority"]["truthAuthority"], false);
        assert_eq!(contract["authority"]["verificationAuthority"], false);
        assert_eq!(contract["provider"]["connectedEvidence"], false);
        assert_eq!(contract["provider"]["nativeEvidence"], false);
        assert_eq!(contract["provider"]["firstPartyEvidence"], false);
        assert_eq!(BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!AuthorityBoundary::connected());
        assert!(!AuthorityBoundary::native_provider());
        assert!(!AuthorityBoundary::first_party_provider());
        assert!(!AuthorityBoundary::truth());
        assert!(!AuthorityBoundary::consent());
        assert!(!AuthorityBoundary::effect());
        assert!(!AuthorityBoundary::receipt());
        assert!(!AuthorityBoundary::verification());
        assert!(!AuthorityBoundary::outcome());
        assert!(!AuthorityBoundary::external_writes());
        assert!(!AuthorityBoundary::work_product_adoption());
    }
}
