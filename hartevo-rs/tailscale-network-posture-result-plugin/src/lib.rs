//! Standalone Layer-1 Tailscale network posture evidence result boundary.
//!
//! The crate owns only bounded, typed read/proposal/recording seams and a
//! Mission-facing review projection. It does not resolve credentials, open
//! native HTTPS, connect to a tailnet, expose node addresses, mutate devices,
//! tags, ACLs, grants, or keys, certify access, or adopt a Work Product or
//! Outcome.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::collapsible_if,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::result_large_err,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::type_complexity,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConsumerError, MissionTailscaleNetworkConsumer, MissionTailscaleNetworkDecisionState,
    MissionTailscaleNetworkResult, RecordedTailscaleNetworkResult,
};
pub use model::*;
pub use provider::{
    BlockedEnvTailscaleTransport, BlockedEnvTransport, FakeTailscaleTransport, FakeTransport,
    FixtureTailscaleTransport, FixtureTransport, LoopbackTailscaleTransport, LoopbackTransport,
    RecordedRequest, RecordingTailscaleTransport, RecordingTransport, TailscaleCall,
    TailscaleProvider, TailscaleProviderDefinition, TailscaleProviderError, TailscaleTransport,
    TransportError,
};
pub use service::{
    EvidenceVerification, FailureEvidence, FailureKind, RecordDisposition, RedactionSummary,
    RegistrationState, RegistrationTransition, ServiceError, TailscaleCapabilities,
    TailscaleNetworkPostureEvidence, TailscaleNetworkPostureProposal,
    TailscaleNetworkPostureResult, TailscaleNetworkPostureResultService,
    TailscaleNetworkPostureResultServiceDefinition, TailscaleNetworkPostureService,
    TailscaleRecordReceipt, TailscaleRegistration, TailscaleVerificationReport,
    VerificationFailure,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.tailscale-network-posture-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-TAILSCALE-01-L1/v1";
pub const PLUGIN_ID: &str = "tailscale.network-posture-result";
pub const PLUGIN_VERSION: &str = "0.1.0";
pub const SERVICE_ID: &str = "tailscale.network-posture-result.read";
pub const PROVIDER_ID: &str = "tailscale.network-posture.recording";
pub const PROVIDER_VERSION: &str = "0.1.0";
pub const PROVIDER_API_REVISION: &str = "tailscale-api-v2-network-posture-read-r1";
pub const CONSUMER_ID: &str = "mission.tailscale-network-posture.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const TAILSCALE_API_DOCUMENTATION: &str = "https://tailscale.com/docs/reference/tailscale-api";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/tailscale-network-posture-result/tailscale-network-posture-result.v1.json"
);

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_DEVICES: usize = 128;
pub const MAX_TAGS: usize = 64;
pub const MAX_ACL_RULES: usize = 256;
pub const MAX_GRANTS: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_MINUTE: u16 = 60;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;

pub const LAYER1_PERMISSIONS: [&str; 8] = [
    "tailnet:read",
    "device:read",
    "device_posture:read",
    "tag:read",
    "acl:read",
    "grant:read",
    "mission.scope",
    "work_product.proposal",
];

pub const FORBIDDEN_EFFECTS: [&str; 15] = [
    "device:create",
    "device:update",
    "device:delete",
    "tag:write",
    "acl:write",
    "grant:write",
    "key:create",
    "key:revoke",
    "raw_node_addresses",
    "raw_acl_policy",
    "raw_grant_principals",
    "network_reachability_guarantee",
    "access_certification",
    "outcome.adopt",
    "verified_work_product_adoption",
];

/// Layer 1 exposes intentionally negative authority claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    #[must_use]
    pub const fn connected() -> bool {
        false
    }

    #[must_use]
    pub const fn native() -> bool {
        false
    }

    #[must_use]
    pub const fn first_party() -> bool {
        false
    }

    #[must_use]
    pub const fn network_reachability() -> bool {
        false
    }

    #[must_use]
    pub const fn effective_authorization() -> bool {
        false
    }

    #[must_use]
    pub const fn access_certification() -> bool {
        false
    }

    #[must_use]
    pub const fn device_mutation() -> bool {
        false
    }

    #[must_use]
    pub const fn acl_mutation() -> bool {
        false
    }

    #[must_use]
    pub const fn grant_mutation() -> bool {
        false
    }

    #[must_use]
    pub const fn key_mutation() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_provider_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn kernel_outcome_adoption() -> bool {
        false
    }

    #[must_use]
    pub const fn work_product_adoption() -> bool {
        false
    }
}

#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(CONTRACT_JSON.as_bytes())
}

#[must_use]
pub fn provider_manifest_digest() -> Digest {
    canonical_digest(&(
        PROVIDER_ID,
        PROVIDER_VERSION,
        PROVIDER_API_REVISION,
        TailscaleOperation::Devices,
        TailscaleOperation::DevicePosture,
        TailscaleOperation::AclPolicy,
        TailscaleOperation::Grants,
        false,
        false,
        false,
    ))
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn checked_contract_is_layer_one_and_explicitly_non_native() {
        let contract: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(contract["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(contract["contractVersion"], CONTRACT_VERSION);
        assert_eq!(contract["pluginId"], PLUGIN_ID);
        assert_eq!(contract["pluginVersion"], PLUGIN_VERSION);
        assert_eq!(contract["layer"], 1);
        assert_eq!(contract["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(contract["service"]["id"], SERVICE_ID);
        assert_eq!(contract["provider"]["id"], PROVIDER_ID);
        assert_eq!(contract["provider"]["apiRevision"], PROVIDER_API_REVISION);
        assert_eq!(contract["consumer"]["id"], CONSUMER_ID);
        assert_eq!(contract["nativeGap"]["status"], BLOCKED_ENV);
        assert_eq!(contract["nativeGap"]["connected"], false);
        assert_eq!(contract["provider"]["connected"], false);
        assert_eq!(contract["provider"]["native"], false);
        assert_eq!(contract["service"]["accessCertification"], false);
        assert_eq!(contract["authority"]["networkReachability"], false);
        assert_eq!(contract["authority"]["accessCertification"], false);
        assert_eq!(LAYER1_PERMISSIONS.len(), 8);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::network_reachability());
        assert!(!Layer1Authority::effective_authorization());
        assert!(!Layer1Authority::access_certification());
        assert!(!Layer1Authority::device_mutation());
        assert!(!Layer1Authority::acl_mutation());
        assert!(!Layer1Authority::grant_mutation());
        assert!(!Layer1Authority::key_mutation());
    }
}
