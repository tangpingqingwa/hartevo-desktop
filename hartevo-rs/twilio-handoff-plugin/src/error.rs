use thiserror::Error;

use crate::model::TwilioMessageStatus;

/// Errors at the Layer 1 Twilio handoff boundary.  Variants intentionally do
/// not include phone numbers, message bodies, callback payloads, or secret
/// material so they are safe to surface in diagnostics.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TwilioHandoffError {
    #[error("BLOCKED_ENV: Twilio native transport is disabled or credentials are unavailable")]
    BlockedEnv { variable: &'static str },
    #[error("Twilio handoff input is invalid for {field}: {reason}")]
    InvalidInput {
        field: &'static str,
        reason: &'static str,
    },
    #[error("Twilio channel is unsupported in Layer 1")]
    UnsupportedChannel,
    #[error("Twilio handoff contract is invalid: {reason}")]
    Contract { reason: &'static str },
    #[error("Twilio handoff scope does not match the registered Project/Mission scope")]
    ScopeMismatch,
    #[error("Twilio handoff registration is revoked")]
    RegistrationRevoked,
    #[error("Twilio handoff registration revision overflowed")]
    RegistrationRevisionOverflow,
    #[error("Twilio handoff registration digest is invalid")]
    RegistrationDigestInvalid,
    #[error("Twilio handoff receipt was not found")]
    ReceiptNotFound,
    #[error("Twilio handoff receipt query is ambiguous")]
    AmbiguousReceipt,
    #[error("Twilio handoff duplicate fingerprint has a conflicting binding")]
    DuplicateConflict,
    #[error("Twilio Message status cannot advance from {current:?} to {next:?}")]
    NonMonotonicStatus {
        current: TwilioMessageStatus,
        next: TwilioMessageStatus,
    },
    #[error("Twilio Message status is unsupported or ambiguous")]
    AmbiguousStatus,
    #[error("Twilio callback signature is invalid")]
    InvalidCallbackSignature,
    #[error("Twilio callback replay window was exceeded")]
    CallbackReplayWindow,
    #[error("Twilio callback is missing a required typed field")]
    CallbackFieldMissing,
    #[error("Twilio callback does not match the registered Message scope")]
    CallbackScopeMismatch,
    #[error("unverified Twilio callback cannot advance a receipt")]
    UnverifiedCallback,
    #[error("Twilio native message creation is not available in Layer 1")]
    LiveSendNotAvailable,
    #[error("Twilio native webhook acceptance is not available in Layer 1")]
    LiveWebhookNotAvailable,
    #[error("Twilio transport failed without exposing provider payload")]
    Transport,
    #[error("Twilio transport response was too large")]
    ResponseTooLarge,
    #[error("Twilio provider returned HTTP 429")]
    RateLimited { retry_after_ms: Option<u64> },
    #[error("Twilio provider request timed out")]
    Timeout,
    #[error("Twilio provider returned an ambiguous response")]
    AmbiguousResponse,
    #[error("Twilio provider response could not be decoded")]
    Decode,
}
