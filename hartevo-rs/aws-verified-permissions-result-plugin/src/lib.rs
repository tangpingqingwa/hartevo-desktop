//! Standalone Layer-1 AWS Verified Permissions `IsAuthorized` result slice.
//!
//! The crate exposes typed scope, read, proposal, record, and verification
//! seams.  It carries only identifiers and digests; it does not resolve live
//! credentials, send a native AWS request, mutate Cedar/policies, execute an
//! external Effect, mint a durable Receipt, or adopt a Work Product.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    AuthorizationAuthority, AuthorizationRecord, AuthorizationVerification, ConsumerError,
    ConsumerRegistration, MissionAwsVerifiedPermissionsConsumer,
    MissionAwsVerifiedPermissionsResult,
};
pub use model::{
    AccountId, Action, ActionReference, AdoptionAvailability, AuthorizationDecision, AwsRegion,
    AwsVerifiedPermissionsRegistration, AwsVerifiedPermissionsScope, ConsentReference,
    ConsentState, ConsumerId, Context, ContextReference, DeterminingPolicyMetadata, Digest,
    EffectGate, EffectReference, EffectState, EvidenceState, IsAuthorizedDecision,
    IsAuthorizedReadRequest, IsAuthorizedReadResponse, IsAuthorizedRequest,
    KernelAuthorizationFence, KernelConsentReference, KernelEffectReference, Mission, MissionId,
    ModelError, PolicyStore, PolicyStoreId, Principal, PrincipalReference, Project, ProjectId,
    Registration, RegistrationRevocation, RegistrationState, Resource, ResourceReference, Revision,
    SecretReference, SigV4SecretReference, SigV4SigningService, VerificationState, WorkProduct,
    WorkProductId,
};
pub use provider::{
    AuthorizationProposal, AwsVerifiedPermissionsProvider,
    AwsVerifiedPermissionsProviderDefinition, AwsVerifiedPermissionsProviderError,
    AwsVerifiedPermissionsServicesProvider, AwsVerifiedPermissionsTransport,
    AwsVerifiedPermissionsTransportError, BlockedEnvAwsVerifiedPermissionsTransport,
    BlockedEnvTransport, FakeAwsVerifiedPermissionsTransport, FakeTransport,
    FixtureAwsVerifiedPermissionsTransport, FixtureTransport, IsAuthorizedRead,
    LoopbackAwsVerifiedPermissionsTransport, LoopbackTransport, ProviderDefinition,
    ProviderDefinitionError, ProviderError, ProviderErrorKind, ProviderProvenance,
    RecordingAwsVerifiedPermissionsTransport, RecordingTransport, TransportError,
};
pub use service::{
    AwsVerifiedPermissionsCapability, AwsVerifiedPermissionsOperation,
    AwsVerifiedPermissionsService,
};

pub const AWS_VERIFIED_PERMISSIONS_SCHEMA_VERSION: &str =
    "hartevo-aws-verified-permissions-result-contract/v1";
pub const AWS_VERIFIED_PERMISSIONS_CONTRACT_VERSION: &str = "aws-verified-permissions-result-l1/v1";
pub const AWS_VERIFIED_PERMISSIONS_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-verified-permissions-result/aws-verified-permissions-result.v1.json"
);
pub const AWS_VERIFIED_PERMISSIONS_VERSION: &str = "1.0.0";
pub const AWS_VERIFIED_PERMISSIONS_SERVICE_ID: &str = "aws.verified-permissions.result";
pub const AWS_VERIFIED_PERMISSIONS_SERVICE_NAME: &str = "AwsVerifiedPermissionsService";
pub const AWS_VERIFIED_PERMISSIONS_SERVICE_SCHEMA: &str =
    "hartevo.aws-verified-permissions-service/v1";
pub const AWS_VERIFIED_PERMISSIONS_PROVIDER_ID: &str = "aws.verified-permissions";
pub const AWS_VERIFIED_PERMISSIONS_PROVIDER_NAME: &str = "AwsVerifiedPermissionsProvider";
pub const AWS_VERIFIED_PERMISSIONS_PROVIDER_VERSION: &str = "1.0.0";
pub const AWS_VERIFIED_PERMISSIONS_PROVIDER_SCHEMA: &str =
    "hartevo.aws-verified-permissions-provider/v1";
pub const AWS_VERIFIED_PERMISSIONS_CONSUMER_ID: &str = "mission.aws.verified-permissions.result";
pub const AWS_VERIFIED_PERMISSIONS_CONSUMER_NAME: &str = "MissionAwsVerifiedPermissionsConsumer";
pub const AWS_VERIFIED_PERMISSIONS_CONSUMER_SCHEMA: &str =
    "hartevo.mission-aws-verified-permissions-consumer/v1";
pub const AWS_VERIFIED_PERMISSIONS_BLOCKED_ENV: &str = "BLOCKED_ENV";

pub fn contract_digest() -> Digest {
    Digest::from_text(AWS_VERIFIED_PERMISSIONS_CONTRACT_JSON)
}

/// Layer 1 is evidence/proposal authority only.  Kernel Consent, Effect,
/// Receipt, Truth, and Work Product adoption remain outside this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn live_credential_resolution() -> bool {
        false
    }

    pub const fn policy_mutation() -> bool {
        false
    }

    pub const fn external_action_execution() -> bool {
        false
    }

    pub const fn durable_receipt() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }

    pub const fn truth_authority() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use serde_json::Value;

    use super::{
        AWS_VERIFIED_PERMISSIONS_BLOCKED_ENV, AWS_VERIFIED_PERMISSIONS_CONSUMER_ID,
        AWS_VERIFIED_PERMISSIONS_CONTRACT_JSON, AWS_VERIFIED_PERMISSIONS_CONTRACT_VERSION,
        AWS_VERIFIED_PERMISSIONS_PROVIDER_ID, AWS_VERIFIED_PERMISSIONS_SCHEMA_VERSION,
        AWS_VERIFIED_PERMISSIONS_SERVICE_ID, Layer1Authority,
    };

    #[test]
    fn contract_document_keeps_layer_one_honest() {
        let document: Value = serde_json::from_str(AWS_VERIFIED_PERMISSIONS_CONTRACT_JSON)
            .expect("AWS Verified Permissions contract JSON");
        assert_eq!(
            document["schemaVersion"],
            AWS_VERIFIED_PERMISSIONS_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            AWS_VERIFIED_PERMISSIONS_CONTRACT_VERSION
        );
        assert_eq!(document["layer"], 1);
        assert_eq!(
            document["service"]["id"],
            AWS_VERIFIED_PERMISSIONS_SERVICE_ID
        );
        assert_eq!(
            document["provider"]["id"],
            AWS_VERIFIED_PERMISSIONS_PROVIDER_ID
        );
        assert_eq!(
            document["consumer"]["id"],
            AWS_VERIFIED_PERMISSIONS_CONSUMER_ID
        );
        assert!(document["service"]["readOnly"].as_bool().unwrap_or(false));
        assert!(
            !document["service"]["liveExecution"]
                .as_bool()
                .unwrap_or(true)
        );
        assert!(!document["provider"]["native"].as_bool().unwrap_or(true));
        assert!(
            !document["nativeClaims"]["connected"]
                .as_bool()
                .unwrap_or(true)
        );
        assert!(
            !document["nativeClaims"]["blockedEnvironmentIsNative"]
                .as_bool()
                .unwrap_or(true)
        );
        assert_eq!(AWS_VERIFIED_PERMISSIONS_BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::live_credential_resolution());
        assert!(!Layer1Authority::policy_mutation());
        assert!(!Layer1Authority::external_action_execution());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::truth_authority());
    }
}
