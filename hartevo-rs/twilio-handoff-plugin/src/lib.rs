//! Layer 1 Twilio SMS/WhatsApp Mission human-handoff boundary.
//!
//! This crate is intentionally independent from the Hartevo workspace.  It
//! owns the typed service, provider, Mission consumer, version/digest/scope
//! registration, deterministic fixture/loopback seams, truthful status
//! projection, and verification-only callback boundary for EXT-TWILIO-01.
//! There is no live Message create call, webhook listener, Store, keyring,
//! Browser Profile, or Effect authority here.

#![deny(unsafe_code)]

mod consumer;
mod error;
mod http;
mod model;
mod provider;
mod registration;
mod service;

pub use consumer::{MissionHandoffResult, MissionHandoffResultConsumer, MissionHandoffResultInput};
pub use error::TwilioHandoffError;
pub use http::{
    RecordingTwilioHttpsTransport, ReqwestTwilioHttpsTransport, TwilioHttpMethod,
    TwilioHttpOperation, TwilioHttpRequest, TwilioHttpResponse, TwilioHttpsTransport,
    TwilioTransportError,
};
pub use model::{
    DeliveryStatusProjection, DeliveryStatusRequest, E164PhoneNumber, EvidenceSource,
    HandoffProposal, HandoffProposalRequest, IdempotencyFingerprint, MessageBody, MissionId,
    MissionScope, ProjectId, ReceiptReadRequest, ReceiptRedactions, RedactedHandoffReceipt,
    RegistrationDigest, SecretMaterial, SecretReference, SourceResultDigest, StatusEvidence,
    TwilioAccountSid, TwilioCallbackRequest, TwilioCallbackSignature, TwilioChannel,
    TwilioCreateMessageRequest, TwilioMessageReceipt, TwilioMessageResource, TwilioMessageSid,
    TwilioMessageStatus, TwilioMessagingServiceSid, TwilioReadRequest, TwilioScope,
    TwilioSenderScope, VerifiedInboundSignal,
};
pub use provider::{
    RetryPolicy, TwilioHandoffProvider, TwilioProbeStatus, TwilioProviderProbe,
    verify_callback_signature,
};
pub use registration::{RegistrationRevocation, TwilioHandoffRegistration};
pub use service::TwilioHandoffService;

pub const TWILIO_HANDOFF_SCHEMA_VERSION: &str = "hartevo.twilio-handoff-plugin/v1";
pub const TWILIO_HANDOFF_CONTRACT_VERSION: &str = "ext-twilio-01-l1/v1";
pub const TWILIO_HANDOFF_PLUGIN_ID: &str = "twilio-handoff";
pub const TWILIO_HANDOFF_PLUGIN_VERSION: u32 = 1;
pub const TWILIO_HANDOFF_PROVIDER_ID: &str = "twilio.messaging.handoff";
pub const TWILIO_HANDOFF_SERVICE_ID: &str = "TwilioHandoffService";
pub const MISSION_HANDOFF_RESULT_CONSUMER_ID: &str = "MissionHandoffResultConsumer";
pub const TWILIO_NATIVE_ENV_GATE: &str = "HARTEVO_TWILIO_NATIVE";
pub const TWILIO_AUTH_TOKEN_ENV: &str = "HARTEVO_TWILIO_AUTH_TOKEN";
pub const TWILIO_CALLBACK_REPLAY_WINDOW_MS: u64 = 300_000;
pub const TWILIO_HANDOFF_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/twilio-handoff/twilio-handoff.v1.json");

pub fn twilio_handoff_contract_digest() -> String {
    model::sha256_hex(TWILIO_HANDOFF_CONTRACT_JSON.as_bytes())
}

pub fn validate_twilio_handoff_contract() -> Result<(), TwilioHandoffError> {
    let document: serde_json::Value =
        serde_json::from_str(TWILIO_HANDOFF_CONTRACT_JSON).map_err(|_| {
            TwilioHandoffError::Contract {
                reason: "checked-in contract is not valid JSON",
            }
        })?;
    let service_operations = document["operations"].as_array();
    let status_projection = document["statusProjection"]["truthful"].as_array();
    if document["schemaVersion"] != TWILIO_HANDOFF_SCHEMA_VERSION
        || document["contractVersion"] != TWILIO_HANDOFF_CONTRACT_VERSION
        || document["layer"] != 1
        || document["service"] != TWILIO_HANDOFF_SERVICE_ID
        || document["provider"] != "TwilioHandoffProvider"
        || document["consumer"] != MISSION_HANDOFF_RESULT_CONSUMER_ID
        || document["honestyBoundary"]["fixturesAreConnected"] != false
        || document["honestyBoundary"]["loopbackIsNative"] != false
        || document["honestyBoundary"]["blockedEnvIsConnected"] != false
        || document["honestyBoundary"]["liveMessageSend"] != false
        || document["honestyBoundary"]["liveWebhookAcceptance"] != false
        || service_operations.is_none_or(|operations| operations.len() != 4)
        || status_projection.is_none_or(|statuses| {
            !statuses.iter().any(|status| status == "queued")
                || !statuses.iter().any(|status| status == "sending")
                || !statuses.iter().any(|status| status == "sent")
                || !statuses.iter().any(|status| status == "delivered")
                || !statuses.iter().any(|status| status == "read")
                || !statuses.iter().any(|status| status == "failed")
        })
    {
        return Err(TwilioHandoffError::Contract {
            reason: "checked-in contract does not match the Layer 1 baseline",
        });
    }
    Ok(())
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_in_contract_is_layer_one_and_honest() {
        validate_twilio_handoff_contract().expect("Twilio contract");
        assert!(!EvidenceSource::Fixture.is_native());
        assert!(!EvidenceSource::Loopback.is_native());
        assert!(!EvidenceSource::BlockedEnv.is_native());
        assert!(!EvidenceSource::Fixture.is_connected());
        assert!(!EvidenceSource::Loopback.is_connected());
        assert!(!EvidenceSource::BlockedEnv.is_connected());
    }
}
