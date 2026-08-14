//! Webhook verification is an untrusted change-signal seam only.

use std::fmt;

use thiserror::Error;

use crate::model::{Digest, SecretReference, WebhookEnvelope, sha256_digest};

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum WebhookVerifierError {
    #[error("webhook signature verifier is unavailable")]
    Unavailable,
}

pub trait WebhookSignatureVerifier: fmt::Debug {
    fn verify(
        &self,
        credential: &SecretReference,
        envelope: &WebhookEnvelope,
    ) -> Result<bool, WebhookVerifierError>;
}

/// A controlled verifier for fixture and recording tests.  It stores only
/// digests, never a webhook secret, signature or payload.
#[derive(Clone, Debug)]
pub struct RecordingWebhookVerifier {
    expected_signature_digest: Option<Digest>,
    expected_payload_digest: Option<Digest>,
    accept: bool,
}

impl RecordingWebhookVerifier {
    pub fn accepting(signature: &str) -> Self {
        Self {
            expected_signature_digest: Some(sha256_digest(signature.as_bytes())),
            expected_payload_digest: None,
            accept: true,
        }
    }

    pub fn accepting_signature_and_payload(signature: &str, payload: &[u8]) -> Self {
        Self {
            expected_signature_digest: Some(sha256_digest(signature.as_bytes())),
            expected_payload_digest: Some(sha256_digest(payload)),
            accept: true,
        }
    }

    pub fn rejecting() -> Self {
        Self {
            expected_signature_digest: None,
            expected_payload_digest: None,
            accept: false,
        }
    }
}

impl WebhookSignatureVerifier for RecordingWebhookVerifier {
    fn verify(
        &self,
        _credential: &SecretReference,
        envelope: &WebhookEnvelope,
    ) -> Result<bool, WebhookVerifierError> {
        let signature_matches = self
            .expected_signature_digest
            .as_ref()
            .is_some_and(|digest| digest == &envelope.signature_digest);
        let payload_matches = self
            .expected_payload_digest
            .as_ref()
            .is_none_or(|digest| digest == &envelope.payload_digest);
        Ok(self.accept && signature_matches && payload_matches)
    }
}
