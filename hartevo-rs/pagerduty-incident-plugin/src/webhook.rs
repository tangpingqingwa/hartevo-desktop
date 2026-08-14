//! PagerDuty V3 webhook verification and replay fencing.
//!
//! Webhooks are change signals only.  This module verifies the raw body and
//! headers, emits digests, and never parses, stores, or applies an incident
//! change.  A later Layer-2 readback is required for provider state.

use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

use crate::model::{
    Digest, Provenance, Timestamp, WebhookSecretMaterial, WebhookSubscriptionId, canonical_digest,
};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum WebhookError {
    #[error("webhook subscription is empty or does not match the exact scope")]
    SubscriptionMismatch,
    #[error("webhook event identifier or type is invalid")]
    InvalidEvent,
    #[error("webhook occurred-at timestamp is outside the replay window")]
    StaleEvent,
    #[error("webhook signature is malformed")]
    InvalidSignatureEncoding,
    #[error("webhook signature does not verify over the raw body")]
    InvalidSignature,
    #[error("webhook event has already crossed the replay fence")]
    Replay,
    #[error("webhook replay window is invalid")]
    InvalidReplayWindow,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebhookEnvelope {
    pub subscription_id: WebhookSubscriptionId,
    pub signature: String,
    pub event_id: String,
    pub event_type: String,
    pub occurred_at: Timestamp,
}

impl WebhookEnvelope {
    pub fn validate(&self) -> Result<(), WebhookError> {
        if self.event_id.is_empty()
            || self.event_id.len() > 128
            || self.event_type.is_empty()
            || self.event_type.len() > 128
            || self.signature.trim().is_empty()
        {
            return Err(WebhookError::InvalidEvent);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedWebhookEnvelope {
    pub raw_body_digest: Digest,
    pub subscription_id: WebhookSubscriptionId,
    pub event_id: String,
    pub event_type: String,
    pub occurred_at: Timestamp,
    pub signature_version: String,
    pub replay_fence_revision: u64,
    pub change_signal_only: bool,
    pub requires_rest_readback: bool,
    pub provenance: Provenance,
}

#[derive(Clone, Debug, Default)]
pub struct WebhookReplayFence {
    max_age_seconds: i64,
    seen_event_ids: BTreeSet<String>,
    revision: u64,
}

impl WebhookReplayFence {
    pub fn new(max_age_seconds: i64) -> Result<Self, WebhookError> {
        if max_age_seconds <= 0 {
            return Err(WebhookError::InvalidReplayWindow);
        }
        Ok(Self {
            max_age_seconds,
            seen_event_ids: BTreeSet::new(),
            revision: 0,
        })
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn verify(
        &mut self,
        expected_subscription: &WebhookSubscriptionId,
        envelope: &WebhookEnvelope,
        raw_body: &[u8],
        secret: &WebhookSecretMaterial,
        now: Timestamp,
        provenance: Provenance,
    ) -> Result<VerifiedWebhookEnvelope, WebhookError> {
        envelope.validate()?;
        if &envelope.subscription_id != expected_subscription {
            return Err(WebhookError::SubscriptionMismatch);
        }
        let age = now.unix_seconds() - envelope.occurred_at.unix_seconds();
        if age.unsigned_abs() > self.max_age_seconds as u64 {
            return Err(WebhookError::StaleEvent);
        }
        verify_signature(raw_body, &envelope.signature, secret)?;
        if self.seen_event_ids.contains(&envelope.event_id) {
            return Err(WebhookError::Replay);
        }
        self.seen_event_ids.insert(envelope.event_id.clone());
        self.revision = self.revision.saturating_add(1);
        Ok(VerifiedWebhookEnvelope {
            raw_body_digest: Digest::from_bytes(raw_body),
            subscription_id: envelope.subscription_id.clone(),
            event_id: envelope.event_id.clone(),
            event_type: envelope.event_type.clone(),
            occurred_at: envelope.occurred_at,
            signature_version: "v1".to_owned(),
            replay_fence_revision: self.revision,
            change_signal_only: true,
            requires_rest_readback: true,
            provenance,
        })
    }
}

fn verify_signature(
    raw_body: &[u8],
    signature: &str,
    secret: &WebhookSecretMaterial,
) -> Result<(), WebhookError> {
    let encoded = signature
        .strip_prefix("v1=")
        .ok_or(WebhookError::InvalidSignatureEncoding)?;
    let bytes = STANDARD
        .decode(encoded)
        .or_else(|_| hex::decode(encoded))
        .map_err(|_| WebhookError::InvalidSignatureEncoding)?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| WebhookError::InvalidSignatureEncoding)?;
    mac.update(raw_body);
    mac.verify_slice(&bytes)
        .map_err(|_| WebhookError::InvalidSignature)
}

/// Testkit-only style helper for recording transports.  It creates the exact
/// `v1=` HMAC shape consumed by [`WebhookReplayFence::verify`]; it does not
/// create a subscription or accept a live webhook.
pub fn signature_for_test(secret: &WebhookSecretMaterial, raw_body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    mac.update(raw_body);
    format!("v1={}", STANDARD.encode(mac.finalize().into_bytes()))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct _WebhookDigestMaterial<'a> {
    envelope: &'a WebhookEnvelope,
    body_digest: &'a Digest,
}

#[allow(dead_code)]
fn _canonical_webhook_digest(envelope: &WebhookEnvelope, raw_body: &[u8]) -> Digest {
    canonical_digest(&_WebhookDigestMaterial {
        envelope,
        body_digest: &Digest::from_bytes(raw_body),
    })
}
