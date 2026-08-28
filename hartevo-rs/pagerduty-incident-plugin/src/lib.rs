//! Hartevo Layer-1 PagerDuty incident-response and resolution-evidence seam.
//!
//! This standalone crate owns only typed provider models, bounded read
//! projections, reversible registration, non-mutating proposals, and a
//! raw-body webhook verification/replay seam.  It does not own Kernel
//! Project/Mission identity, Consent, Effect, Receipt, Verification, or
//! Outcome authority; those values are explicit scope inputs and proposal
//! fences here.

#![forbid(unsafe_code)]

mod consumer;
mod model;
mod provider;
mod registration;
mod transport;
mod webhook;

pub use consumer::{MissionPagerDutyIncidentConsumer, PagerDutyIncidentService};
pub use model::{
    AccountId, AlertProjection, AlertStatus, ApiRegion, AssignmentProjection,
    CapabilityDescription, ConsentId, ConsentReference, Digest, EscalationPolicyId, IncidentId,
    IncidentIdentity, IncidentProjection, IncidentState, IncidentStatus, MissionId, PagerDutyScope,
    ProjectId, ProjectionBounds, Provenance, ProviderIncidentTransition, RateLimitReceipt,
    RawAlertPayload, RawAssignmentPayload, RawIncidentPayload, RawTimelineEntryPayload,
    ResolutionEvidenceProposal, ResponseIntent, ResponseProposal, SecretKind, SecretReference,
    SelectedTimelineEvidence, ServiceId, TeamId, TimelineBounds, TimelineEntryProjection,
    TimelineKind, TimelinePageReceipt, TimelineProjection, TimelineReceipt, TimelineStopReason,
    TimelineWindow, Timestamp, WebhookSecretMaterial, WebhookSubscriptionId, canonical_digest,
};
pub use provider::{IncidentReadResult, PagerDutyIncidentProvider, ProviderError};
pub use registration::{
    CONSUMER_ID, CONTRACT_JSON, CONTRACT_SCHEMA_VERSION, CONTRACT_VERSION, PLUGIN_ID, PROVIDER_ID,
    PagerDutyRegistration, RegistrationAction, RegistrationError, RegistrationLifecycle,
    RegistrationReceipt, RegistrationRegistry, RegistrationSpec, SERVICE_ID, contract_digest,
    expected_api_region_host,
};
pub use transport::{
    BlockedEnvTransport, FakeTransport, IncidentPageResponse, IncidentRequest,
    PagerDutyIncidentTransport, ProbePayload, ProbeReceipt, ProbeRequest, ProbeResponse,
    RecordedRequest, RecordingTransport, TimelinePageRequest, TimelinePageResponse, TransportError,
};
pub use webhook::{
    VerifiedWebhookEnvelope, WebhookEnvelope, WebhookError, WebhookReplayFence, signature_for_test,
};

#[cfg(test)]
mod contract_document_tests {
    use serde::Deserialize;

    use super::{
        CONSUMER_ID, CONTRACT_JSON, CONTRACT_SCHEMA_VERSION, CONTRACT_VERSION, PLUGIN_ID,
        PROVIDER_ID, SERVICE_ID, contract_digest,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        plugin_id: String,
        layer: u8,
        provider: ProviderDocument,
        exact_scope: Vec<String>,
        operations: serde_json::Map<String, serde_json::Value>,
        forbidden_layer1_effects: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderDocument {
        id: String,
        service_id: String,
        consumer_id: String,
    }

    #[test]
    fn contract_is_versioned_typed_and_layer_one_only() {
        let document = serde_json::from_str::<ContractDocument>(CONTRACT_JSON)
            .expect("PagerDuty contract JSON");
        assert_eq!(document.schema_version, CONTRACT_SCHEMA_VERSION);
        assert_eq!(document.contract_version, CONTRACT_VERSION);
        assert_eq!(document.plugin_id, PLUGIN_ID);
        assert_eq!(document.layer, 1);
        assert_eq!(document.provider.id, PROVIDER_ID);
        assert_eq!(document.provider.service_id, SERVICE_ID);
        assert_eq!(document.provider.consumer_id, CONSUMER_ID);
        assert!(
            document
                .exact_scope
                .iter()
                .any(|field| field == "account_id")
        );
        assert!(
            document
                .exact_scope
                .iter()
                .any(|field| field == "consent_reference")
        );
        assert!(document.operations.contains_key("read_incident"));
        assert!(
            document
                .forbidden_layer1_effects
                .iter()
                .any(|effect| effect == "accept_live_webhook")
        );
        assert_eq!(contract_digest().as_str().len(), 64);
    }
}
