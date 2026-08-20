//! Layer-1 governed Google Cloud Pub/Sub subscription posture result plugin.
//!
//! The crate is deliberately standalone. It models bounded configuration
//! reads from recorded, fixture, loopback, or blocked-environment transports.
//! It never pulls, acknowledges, publishes, seeks, detaches, mutates IAM or
//! configuration, retains message data, or claims kernel Truth, Consent,
//! Effect, Receipt, Verification, Outcome, Connected, native, or first-party
//! authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::manual_let_else,
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
    ConsumerError, MissionGcpPubsubConsumer, MissionGcpPubsubResult, MissionProjection,
    ProjectProjection, WorkProductProjection,
};
pub use model::{
    BoundedLabels, ConsumerId, DeadLetterPolicy, DeadLetterProjection, Digest, EvidenceDigests,
    ExpirationPolicy, FilterExpression, FilterProjection, GcpPubsubSubscriptionScope,
    GoogleAuthKind, MissionId, ModelError, OpaquePageToken, PermissionFence, ProjectId,
    ProviderErrorEvidence, ProviderErrorKind, ProviderId, ProviderResourceScopeProjection,
    PushConfiguration, PushEndpointProjection, PushWrapper, ResourceKind, ResourceProjection,
    RetryPolicy, Revision, SchemaEncoding, SchemaId, SchemaProjection, SchemaResource,
    SchemaSettings, SecretReference, ServiceId, SubscriptionConfiguration, SubscriptionId,
    SubscriptionPosture, SubscriptionProjection, SubscriptionResource, SubscriptionState,
    TopicConfiguration, TopicId, TopicProjection, TopicResource, TopicState, WorkProductId,
};
pub use provider::{
    BlockedEnvTransport, FixtureGcpPubsubTransport, GcpPubsubProvider, GcpPubsubProviderApi,
    GcpPubsubProviderDefinition, GcpPubsubTransport, GetSubscriptionRequest, GetTopicRequest,
    ListSubscriptionsRequest, ListSubscriptionsResponse, LoopbackTransport,
    ProviderDefinitionError, ProviderProvenance, RecordedRequest, RecordingGcpPubsubTransport,
    SubscriptionConfigurationResponse, TopicConfigurationResponse, TransportError,
};
pub use service::{
    GcpPubsubRegistration, GcpPubsubResultEvidence, GcpPubsubServiceDefinition,
    GcpPubsubSubscriptionResultProposal, GcpPubsubSubscriptionResultService, InspectionRequest,
    RegistrationStatus, RegistrationTransition, ServiceError,
};

pub const GCP_PUBSUB_SUBSCRIPTION_RESULT_SCHEMA_VERSION: &str =
    "hartevo-gcp-pubsub-subscription-result-contract/v1";
pub const GCP_PUBSUB_SUBSCRIPTION_RESULT_CONTRACT_VERSION: &str =
    "gcp-pubsub-subscription-result-e1/v1";
pub const GCP_PUBSUB_SUBSCRIPTION_RESULT_SERVICE_ID: &str = "gcp.pubsub.subscription.result";
pub const GCP_PUBSUB_SUBSCRIPTION_RESULT_PROVIDER_ID: &str = "gcp.pubsub.subscription";
pub const GCP_PUBSUB_SUBSCRIPTION_RESULT_CONSUMER_ID: &str =
    "mission.gcp.pubsub.subscription.result.consumer";
pub const GCP_PUBSUB_SUBSCRIPTION_RESULT_EVIDENCE_LEVEL: &str = "E1";
pub const GCP_PUBSUB_SUBSCRIPTION_RESULT_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const GCP_PUBSUB_SUBSCRIPTION_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/gcp-pubsub-subscription-result/gcp-pubsub-subscription-result.v1.json"
);

/// Layer-1 authority is intentionally all false. Configuration posture is
/// bounded evidence for a Mission decision, not delivery completion or kernel
/// Truth/Consent/Effect/Receipt/Verification/Outcome evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Layer1Authority {
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
}

impl Layer1Authority {
    pub const fn offline() -> Self {
        Self {
            connected: false,
            native_provider: false,
            first_party: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
        }
    }

    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn first_party() -> bool {
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
}

#[cfg(test)]
mod contract_document_tests {
    use serde::Deserialize;

    use super::{
        GCP_PUBSUB_SUBSCRIPTION_RESULT_BLOCKED_ENV, GCP_PUBSUB_SUBSCRIPTION_RESULT_CONSUMER_ID,
        GCP_PUBSUB_SUBSCRIPTION_RESULT_CONTRACT_JSON,
        GCP_PUBSUB_SUBSCRIPTION_RESULT_CONTRACT_VERSION,
        GCP_PUBSUB_SUBSCRIPTION_RESULT_EVIDENCE_LEVEL, GCP_PUBSUB_SUBSCRIPTION_RESULT_PROVIDER_ID,
        GCP_PUBSUB_SUBSCRIPTION_RESULT_SCHEMA_VERSION, GCP_PUBSUB_SUBSCRIPTION_RESULT_SERVICE_ID,
        Layer1Authority,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        evidence_level: String,
        layer: u8,
        service: ServiceDocument,
        provider: ProviderDocument,
        consumer: ConsumerDocument,
        native_claims: NativeClaims,
        posture_states: Vec<String>,
        read_policy: ReadPolicy,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ServiceDocument {
        id: String,
        read_only: bool,
        live_execution: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderDocument {
        id: String,
        native: bool,
        first_party: bool,
        message_effects: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConsumerDocument {
        id: String,
        mission_bound: bool,
        project_bound: bool,
        work_product_bound: bool,
        adopts_outcome: bool,
        truth_authority: bool,
        consent_authority: bool,
        effect_authority: bool,
        receipt_authority: bool,
        verification_authority: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NativeClaims {
        connected: bool,
        native_provider: bool,
        first_party: bool,
        durable_receipt: bool,
        truth_authority: bool,
        consent_authority: bool,
        effect_authority: bool,
        verification_authority: bool,
        outcome_authority: bool,
        blocked_environment_is_native: bool,
    }

    #[derive(Debug, Deserialize)]
    struct ReadPolicy {
        allow: Vec<String>,
        deny: Vec<String>,
    }

    #[test]
    fn contract_document_is_layer_one_read_only_and_bounded() {
        let document =
            serde_json::from_str::<ContractDocument>(GCP_PUBSUB_SUBSCRIPTION_RESULT_CONTRACT_JSON)
                .expect("Pub/Sub contract JSON");
        assert_eq!(
            document.schema_version,
            GCP_PUBSUB_SUBSCRIPTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document.contract_version,
            GCP_PUBSUB_SUBSCRIPTION_RESULT_CONTRACT_VERSION
        );
        assert_eq!(
            document.evidence_level,
            GCP_PUBSUB_SUBSCRIPTION_RESULT_EVIDENCE_LEVEL
        );
        assert_eq!(document.layer, 1);
        assert_eq!(
            document.service.id,
            GCP_PUBSUB_SUBSCRIPTION_RESULT_SERVICE_ID
        );
        assert!(document.service.read_only);
        assert!(!document.service.live_execution);
        assert_eq!(
            document.provider.id,
            GCP_PUBSUB_SUBSCRIPTION_RESULT_PROVIDER_ID
        );
        assert!(!document.provider.native);
        assert!(!document.provider.first_party);
        assert!(!document.provider.message_effects);
        assert_eq!(
            document.consumer.id,
            GCP_PUBSUB_SUBSCRIPTION_RESULT_CONSUMER_ID
        );
        assert!(document.consumer.mission_bound);
        assert!(document.consumer.project_bound);
        assert!(document.consumer.work_product_bound);
        assert!(!document.consumer.adopts_outcome);
        assert!(!document.consumer.truth_authority);
        assert!(!document.consumer.consent_authority);
        assert!(!document.consumer.effect_authority);
        assert!(!document.consumer.receipt_authority);
        assert!(!document.consumer.verification_authority);
        assert_eq!(
            document.posture_states,
            [
                "ACTIVE",
                "DETACHED",
                "EXPIRED",
                "MISCONFIGURED",
                "PARTIAL",
                "ACCESS_LOST",
                "PROVIDER_UNKNOWN",
                "TAMPERED",
                "REVOKED",
            ]
        );
        assert!(
            document
                .read_policy
                .allow
                .contains(&"get_topic_configuration".to_owned())
        );
        assert!(
            document
                .read_policy
                .allow
                .contains(&"get_subscription_configuration".to_owned())
        );
        assert!(
            document
                .read_policy
                .allow
                .contains(&"list_subscriptions".to_owned())
        );
        for denied in [
            "publish",
            "pull",
            "acknowledge",
            "seek",
            "detach",
            "message_body",
        ] {
            assert!(document.read_policy.deny.contains(&denied.to_owned()));
        }
        assert!(!document.native_claims.connected);
        assert!(!document.native_claims.native_provider);
        assert!(!document.native_claims.first_party);
        assert!(!document.native_claims.durable_receipt);
        assert!(!document.native_claims.truth_authority);
        assert!(!document.native_claims.consent_authority);
        assert!(!document.native_claims.effect_authority);
        assert!(!document.native_claims.verification_authority);
        assert!(!document.native_claims.outcome_authority);
        assert!(!document.native_claims.blocked_environment_is_native);
        assert_eq!(GCP_PUBSUB_SUBSCRIPTION_RESULT_BLOCKED_ENV, "BLOCKED_ENV");
        assert_eq!(Layer1Authority::offline(), Layer1Authority::offline());
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::truth());
        assert!(!Layer1Authority::consent());
        assert!(!Layer1Authority::effect());
        assert!(!Layer1Authority::receipt());
        assert!(!Layer1Authority::verification());
        assert!(!Layer1Authority::outcome());
    }
}
