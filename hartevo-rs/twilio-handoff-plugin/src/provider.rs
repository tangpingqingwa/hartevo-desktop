use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::sync::{Arc, Mutex};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use serde_json::from_slice;
use sha1::Sha1;

use crate::error::TwilioHandoffError;
use crate::http::{
    RecordingTwilioHttpsTransport, ReqwestTwilioHttpsTransport, TwilioHttpRequest,
    TwilioHttpsTransport, TwilioTransportError,
};
use crate::model::{
    DeliveryStatusProjection, DeliveryStatusRequest, EvidenceSource, HandoffProposal,
    IdempotencyFingerprint, ReceiptBinding, ReceiptReadRequest, RedactedHandoffReceipt,
    SecretMaterial, SecretReference, StatusEvidence, TwilioAccountSid, TwilioCallbackRequest,
    TwilioChannel, TwilioCreateMessageRequest, TwilioMessageReceipt, TwilioMessageResource,
    TwilioMessageSid, TwilioMessageStatus, TwilioReadRequest, TwilioScope, VerifiedInboundSignal,
    callback_canonical_material, callback_digest, normalize_provider_phone,
};
use crate::registration::TwilioHandoffRegistration;

/// The exact bounded retry schedule is data, not a sleep side effect.  Layer 1
/// tests can prove its limits without contacting Twilio or blocking a test.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff_ms: 250,
            max_backoff_ms: 2_000,
        }
    }
}

impl RetryPolicy {
    pub fn new(
        max_attempts: u8,
        initial_backoff_ms: u64,
        max_backoff_ms: u64,
    ) -> Result<Self, TwilioHandoffError> {
        if !(1..=3).contains(&max_attempts)
            || initial_backoff_ms == 0
            || max_backoff_ms < initial_backoff_ms
        {
            return Err(TwilioHandoffError::InvalidInput {
                field: "retry policy",
                reason: "must be bounded to at most three attempts with positive backoff",
            });
        }
        Ok(Self {
            max_attempts,
            initial_backoff_ms,
            max_backoff_ms,
        })
    }

    pub fn backoff_ms_for_retry(&self, retry_number: u8) -> Option<u64> {
        if retry_number == 0 || retry_number >= self.max_attempts {
            return None;
        }
        let exponent = u32::from(retry_number.saturating_sub(1));
        let multiplier = 1_u64.checked_shl(exponent).unwrap_or(u64::MAX);
        Some(
            self.initial_backoff_ms
                .saturating_mul(multiplier)
                .min(self.max_backoff_ms),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TwilioProbeStatus {
    Connected,
    VerifiedFixtureNotConnected,
    VerifiedLoopbackNotConnected,
    NativeLayer1Gap,
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TwilioProviderProbe {
    pub status: TwilioProbeStatus,
    pub evidence_source: EvidenceSource,
    pub connected: bool,
    pub native: bool,
}

impl TwilioProviderProbe {
    pub const fn fixture() -> Self {
        Self {
            status: TwilioProbeStatus::VerifiedFixtureNotConnected,
            evidence_source: EvidenceSource::Fixture,
            connected: false,
            native: false,
        }
    }

    pub const fn loopback() -> Self {
        Self {
            status: TwilioProbeStatus::VerifiedLoopbackNotConnected,
            evidence_source: EvidenceSource::Loopback,
            connected: false,
            native: false,
        }
    }

    pub const fn blocked_env() -> Self {
        Self {
            status: TwilioProbeStatus::BlockedEnv,
            evidence_source: EvidenceSource::BlockedEnv,
            connected: false,
            native: false,
        }
    }

    pub const fn native_layer_one_gap() -> Self {
        Self {
            status: TwilioProbeStatus::NativeLayer1Gap,
            evidence_source: EvidenceSource::NativeHttps,
            connected: false,
            native: true,
        }
    }
}

/// Typed Twilio Message-resource provider.  The provider can record a local
/// proposal, project verified status, prepare a future create request, and
/// read through an injected HTTPS GET seam.  It has no executable send or
/// webhook-listener method.
pub struct TwilioHandoffProvider {
    registration: TwilioHandoffRegistration,
    secret_reference: SecretReference,
    transport: Arc<dyn TwilioHttpsTransport>,
    api_base_url: url::Url,
    evidence_source: EvidenceSource,
    retry_policy: RetryPolicy,
    receipts: Arc<Mutex<BTreeMap<IdempotencyFingerprint, TwilioMessageReceipt>>>,
}

impl fmt::Debug for TwilioHandoffProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TwilioHandoffProvider")
            .field("registration", &self.registration)
            .field("secret_reference", &self.secret_reference)
            .field("evidence_source", &self.evidence_source)
            .field("retry_policy", &self.retry_policy)
            .field("receipt_count", &self.receipt_count())
            .finish_non_exhaustive()
    }
}

impl TwilioHandoffProvider {
    pub fn recording(registration: TwilioHandoffRegistration) -> Result<Self, TwilioHandoffError> {
        let secret_reference = SecretReference::fixture(registration.scope.account_id.clone());
        let transport = Arc::new(RecordingTwilioHttpsTransport::fixture([]));
        Self::with_transport(
            registration,
            secret_reference,
            transport,
            EvidenceSource::Fixture,
            url::Url::parse("https://fixture.invalid/2010-04-01/")
                .expect("static fixture URL is valid"),
        )
    }

    pub fn fixture(registration: TwilioHandoffRegistration) -> Result<Self, TwilioHandoffError> {
        Self::recording(registration)
    }

    pub fn loopback(
        registration: TwilioHandoffRegistration,
        transport: Arc<dyn TwilioHttpsTransport>,
    ) -> Result<Self, TwilioHandoffError> {
        let secret_reference = SecretReference::new(
            registration.scope.account_id.clone(),
            "loopback-secret-reference",
        )?;
        Self::with_transport(
            registration,
            secret_reference,
            transport,
            EvidenceSource::Loopback,
            url::Url::parse("http://127.0.0.1/2010-04-01/").expect("static loopback URL is valid"),
        )
    }

    pub(crate) fn native(
        registration: TwilioHandoffRegistration,
    ) -> Result<Self, TwilioHandoffError> {
        let secret_reference = SecretReference::new(
            registration.scope.account_id.clone(),
            "environment-secret-reference",
        )?;
        let transport = Arc::new(
            ReqwestTwilioHttpsTransport::production().map_err(|_| TwilioHandoffError::Transport)?,
        );
        Self::with_transport(
            registration,
            secret_reference,
            transport,
            EvidenceSource::NativeHttps,
            url::Url::parse(ReqwestTwilioHttpsTransport::TWILIO_API_BASE_URL)
                .expect("static Twilio API URL is valid"),
        )
    }

    pub fn with_transport(
        registration: TwilioHandoffRegistration,
        secret_reference: SecretReference,
        transport: Arc<dyn TwilioHttpsTransport>,
        evidence_source: EvidenceSource,
        api_base_url: url::Url,
    ) -> Result<Self, TwilioHandoffError> {
        registration.validate()?;
        if secret_reference.account_id != registration.scope.account_id
            || secret_reference.provider_id != "twilio"
            || transport.evidence_source() != evidence_source
            || transport.is_native() != evidence_source.is_native()
        {
            return Err(TwilioHandoffError::ScopeMismatch);
        }
        if evidence_source == EvidenceSource::NativeHttps
            && env::var(crate::TWILIO_NATIVE_ENV_GATE).ok().as_deref() != Some("1")
        {
            return Err(TwilioHandoffError::BlockedEnv {
                variable: crate::TWILIO_NATIVE_ENV_GATE,
            });
        }
        validate_api_base_url(&api_base_url, evidence_source)?;
        Ok(Self {
            registration,
            secret_reference,
            transport,
            api_base_url,
            evidence_source,
            retry_policy: RetryPolicy::default(),
            receipts: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    pub fn from_environment(
        registration: TwilioHandoffRegistration,
    ) -> Result<Self, TwilioHandoffError> {
        let gate = env::var(crate::TWILIO_NATIVE_ENV_GATE).map_err(|_| {
            TwilioHandoffError::BlockedEnv {
                variable: crate::TWILIO_NATIVE_ENV_GATE,
            }
        })?;
        if gate != "1" {
            return Err(TwilioHandoffError::BlockedEnv {
                variable: crate::TWILIO_NATIVE_ENV_GATE,
            });
        }
        let credential =
            env::var(crate::TWILIO_AUTH_TOKEN_ENV).map_err(|_| TwilioHandoffError::BlockedEnv {
                variable: crate::TWILIO_AUTH_TOKEN_ENV,
            })?;
        if credential.trim().is_empty() {
            return Err(TwilioHandoffError::BlockedEnv {
                variable: crate::TWILIO_AUTH_TOKEN_ENV,
            });
        }
        // The credential is checked for availability only.  The provider does
        // not retain it; Layer 2 must resolve the SecretReference per request.
        Self::native(registration)
    }

    pub fn probe_from_environment(registration: &TwilioHandoffRegistration) -> TwilioProviderProbe {
        match Self::from_environment(registration.clone()) {
            Ok(provider) => provider.probe(),
            Err(TwilioHandoffError::BlockedEnv { .. }) => TwilioProviderProbe::blocked_env(),
            Err(_) => TwilioProviderProbe::native_layer_one_gap(),
        }
    }

    pub fn registration(&self) -> &TwilioHandoffRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &TwilioScope {
        &self.registration.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn evidence_source(&self) -> EvidenceSource {
        self.evidence_source
    }

    pub fn is_native(&self) -> bool {
        self.evidence_source.is_native()
    }

    pub const fn is_connected(&self) -> bool {
        false
    }

    pub fn probe(&self) -> TwilioProviderProbe {
        match self.evidence_source {
            EvidenceSource::Fixture => TwilioProviderProbe::fixture(),
            EvidenceSource::Loopback => TwilioProviderProbe::loopback(),
            EvidenceSource::BlockedEnv => TwilioProviderProbe::blocked_env(),
            EvidenceSource::NativeHttps => TwilioProviderProbe::native_layer_one_gap(),
        }
    }

    #[must_use]
    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    pub fn retry_policy(&self) -> RetryPolicy {
        self.retry_policy
    }

    pub fn receipt_count(&self) -> usize {
        self.receipts.lock().map_or(0, |receipts| receipts.len())
    }

    pub fn record_proposal(
        &self,
        proposal: &HandoffProposal,
        observed_at_ms: u64,
    ) -> Result<TwilioMessageReceipt, TwilioHandoffError> {
        self.ensure_active()?;
        if observed_at_ms == 0 {
            return Err(TwilioHandoffError::InvalidInput {
                field: "receipt observation timestamp",
                reason: "must be non-zero",
            });
        }
        proposal.validate_binding(self.registration.registration_digest(), self.scope())?;
        let mut receipts = self
            .receipts
            .lock()
            .map_err(|_| TwilioHandoffError::Transport)?;
        if let Some(existing) = receipts.get(&proposal.idempotency_fingerprint) {
            if existing.binding.source_result_digest != proposal.source_result_digest
                || existing.binding.scope_digest.as_str()
                    != self.registration.scope_digest().as_str()
            {
                return Err(TwilioHandoffError::DuplicateConflict);
            }
            return Ok(existing.clone());
        }
        let message_sid = fixture_message_sid(&proposal.idempotency_fingerprint)?;
        let evidence = match self.evidence_source {
            EvidenceSource::Fixture => StatusEvidence::Fixture,
            EvidenceSource::Loopback => StatusEvidence::Loopback,
            EvidenceSource::NativeHttps => StatusEvidence::NativeReadback,
            EvidenceSource::BlockedEnv => {
                return Err(TwilioHandoffError::BlockedEnv {
                    variable: crate::TWILIO_NATIVE_ENV_GATE,
                });
            }
        };
        let receipt = TwilioMessageReceipt {
            provider_message_sid: message_sid,
            binding: ReceiptBinding {
                provider_version: self.registration.plugin_version,
                registration_digest: self.registration.registration_digest.clone(),
                scope_digest: self.registration.scope_digest.clone(),
                mission_digest: self.scope().mission.digest(),
                source_result_digest: proposal.source_result_digest.clone(),
                idempotency_fingerprint: proposal.idempotency_fingerprint.clone(),
            },
            status: DeliveryStatusProjection {
                status: TwilioMessageStatus::Queued,
                observed_at_ms,
                evidence,
                monotonic: true,
            },
            scope: self.scope().clone(),
            message_body_digest: proposal.message_body_digest(),
            evidence_source: self.evidence_source,
            external_write_performed: false,
        };
        receipts.insert(proposal.idempotency_fingerprint.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn read_receipt(
        &self,
        request: &ReceiptReadRequest,
    ) -> Result<TwilioMessageReceipt, TwilioHandoffError> {
        self.ensure_active()?;
        self.validate_request_binding(&request.scope_digest, &request.registration_digest)?;
        let receipts = self
            .receipts
            .lock()
            .map_err(|_| TwilioHandoffError::Transport)?;
        let receipt = receipts
            .get(&request.idempotency_fingerprint)
            .ok_or(TwilioHandoffError::ReceiptNotFound)?;
        if request
            .provider_message_sid
            .as_ref()
            .is_some_and(|sid| sid != receipt.provider_message_sid())
        {
            return Err(TwilioHandoffError::AmbiguousReceipt);
        }
        Ok(receipt.clone())
    }

    pub fn read_redacted_receipt(
        &self,
        request: &ReceiptReadRequest,
    ) -> Result<RedactedHandoffReceipt, TwilioHandoffError> {
        Ok(self.read_receipt(request)?.redacted())
    }

    pub fn project_delivery_status(
        &self,
        request: &DeliveryStatusRequest,
    ) -> Result<DeliveryStatusProjection, TwilioHandoffError> {
        self.ensure_active()?;
        self.validate_request_binding(&request.scope_digest, &request.registration_digest)?;
        let mut receipts = self
            .receipts
            .lock()
            .map_err(|_| TwilioHandoffError::Transport)?;
        let receipt = receipts
            .get_mut(&request.idempotency_fingerprint)
            .ok_or(TwilioHandoffError::ReceiptNotFound)?;
        if receipt.provider_message_sid != request.provider_message_sid {
            return Err(TwilioHandoffError::AmbiguousReceipt);
        }
        if request.evidence.source() != self.evidence_source {
            return Err(TwilioHandoffError::ScopeMismatch);
        }
        if receipt.status.status == request.next_status {
            if request.observed_at_ms >= receipt.status.observed_at_ms {
                receipt.status.observed_at_ms = request.observed_at_ms;
                receipt.status.evidence = request.evidence;
            }
            return Ok(receipt.status.clone());
        }
        if !receipt.status.status.can_advance_to(request.next_status) {
            return Err(TwilioHandoffError::NonMonotonicStatus {
                current: receipt.status.status,
                next: request.next_status,
            });
        }
        receipt.status = DeliveryStatusProjection {
            status: request.next_status,
            observed_at_ms: request.observed_at_ms,
            evidence: request.evidence,
            monotonic: true,
        };
        Ok(receipt.status.clone())
    }

    /// Build the future Message-resource create payload.  Returning this
    /// typed request is the final Layer 1 boundary; no transport method can
    /// execute it.
    pub fn prepare_create_message(
        &self,
        proposal: &HandoffProposal,
        status_callback_url: Option<url::Url>,
    ) -> Result<TwilioCreateMessageRequest, TwilioHandoffError> {
        self.ensure_active()?;
        proposal.validate_binding(self.registration.registration_digest(), self.scope())?;
        if let Some(url) = &status_callback_url
            && (url.scheme() != "https" || url.host_str().is_none())
        {
            return Err(TwilioHandoffError::InvalidInput {
                field: "status callback URL",
                reason: "must be an HTTPS URL",
            });
        }
        Ok(TwilioCreateMessageRequest {
            account_id: self.scope().account_id.clone(),
            channel: self.scope().channel,
            sender: self.scope().sender.clone(),
            recipient: self.scope().recipient.clone(),
            message_body: proposal.message_body.clone(),
            idempotency_fingerprint: proposal.idempotency_fingerprint.clone(),
            status_callback_url,
        })
    }

    /// Read-only HTTPS Message-resource seam.  It is environment/secret
    /// gated and never promotes a provider to Connected evidence in Layer 1.
    pub fn read_remote_message(
        &self,
        request: &TwilioReadRequest,
        secret: &SecretMaterial,
    ) -> Result<TwilioMessageResource, TwilioHandoffError> {
        self.ensure_active()?;
        if request.account_id != self.scope().account_id {
            return Err(TwilioHandoffError::ScopeMismatch);
        }
        let http_request = TwilioHttpRequest::read_message(&self.api_base_url, request)?;
        let mut attempt = 1;
        loop {
            let response = self.transport.read_message(secret, &http_request);
            match response {
                Ok(response) => {
                    if response.status == 429 {
                        if let Some(delay) = self.retry_policy.backoff_ms_for_retry(attempt) {
                            let _ = delay;
                            attempt = attempt.saturating_add(1);
                            continue;
                        }
                        return Err(TwilioHandoffError::RateLimited {
                            retry_after_ms: None,
                        });
                    }
                    let resource: TwilioMessageResource =
                        from_slice(&response.body).map_err(|_| TwilioHandoffError::Decode)?;
                    resource.validate_against(self.scope())?;
                    return Ok(resource);
                }
                Err(TwilioTransportError::RateLimited { retry_after_ms }) => {
                    if self.retry_policy.backoff_ms_for_retry(attempt).is_some() {
                        attempt = attempt.saturating_add(1);
                        continue;
                    }
                    return Err(TwilioHandoffError::RateLimited { retry_after_ms });
                }
                Err(TwilioTransportError::Timeout) => {
                    if self.retry_policy.backoff_ms_for_retry(attempt).is_some() {
                        attempt = attempt.saturating_add(1);
                        continue;
                    }
                    return Err(TwilioHandoffError::Timeout);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Verify one already-received callback envelope and project it only
    /// after signature, replay-window, Message SID, account, and recipient
    /// bindings pass.  This is not a webhook listener and cannot accept an
    /// unverified callback.
    pub fn verify_inbound_signal(
        &self,
        callback: &TwilioCallbackRequest,
        auth_token: &SecretMaterial,
    ) -> Result<VerifiedInboundSignal, TwilioHandoffError> {
        self.ensure_active()?;
        if callback.received_at_ms.abs_diff(callback.event_at_ms)
            > crate::TWILIO_CALLBACK_REPLAY_WINDOW_MS
        {
            return Err(TwilioHandoffError::CallbackReplayWindow);
        }
        verify_callback_signature(callback, auth_token)?;
        let account_id = callback
            .form_parameters
            .get("AccountSid")
            .ok_or(TwilioHandoffError::CallbackFieldMissing)
            .and_then(TwilioAccountSid::new)?;
        let provider_message_sid = callback
            .form_parameters
            .get("MessageSid")
            .ok_or(TwilioHandoffError::CallbackFieldMissing)
            .and_then(TwilioMessageSid::new)?;
        let status = callback
            .form_parameters
            .get("MessageStatus")
            .ok_or(TwilioHandoffError::CallbackFieldMissing)
            .and_then(|value| TwilioMessageStatus::from_provider_value(value))?;
        let recipient = callback
            .form_parameters
            .get("To")
            .ok_or(TwilioHandoffError::CallbackFieldMissing)
            .and_then(|value| normalize_provider_phone(value))?;
        if account_id != self.scope().account_id || recipient != self.scope().recipient {
            return Err(TwilioHandoffError::CallbackScopeMismatch);
        }
        let fingerprint = {
            let receipts = self
                .receipts
                .lock()
                .map_err(|_| TwilioHandoffError::Transport)?;
            receipts
                .values()
                .find(|receipt| receipt.provider_message_sid == provider_message_sid)
                .map(|receipt| receipt.binding.idempotency_fingerprint.clone())
                .ok_or(TwilioHandoffError::ReceiptNotFound)?
        };
        let projection = self.project_delivery_status(&DeliveryStatusRequest {
            scope_digest: self.registration.scope_digest.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            idempotency_fingerprint: fingerprint.clone(),
            provider_message_sid: provider_message_sid.clone(),
            next_status: status,
            observed_at_ms: callback.received_at_ms,
            evidence: StatusEvidence::VerifiedCallback {
                source: self.evidence_source,
            },
        })?;
        Ok(VerifiedInboundSignal {
            provider_message_sid,
            account_id,
            status: projection.status,
            idempotency_fingerprint: fingerprint,
            callback_digest: callback_digest(&callback.callback_url, &callback.form_parameters),
            observed_at_ms: projection.observed_at_ms,
            evidence: projection.evidence,
        })
    }

    fn ensure_active(&self) -> Result<(), TwilioHandoffError> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(TwilioHandoffError::RegistrationRevoked);
        }
        Ok(())
    }

    fn validate_request_binding(
        &self,
        scope_digest: &crate::model::RegistrationDigest,
        registration_digest: &crate::model::RegistrationDigest,
    ) -> Result<(), TwilioHandoffError> {
        if scope_digest != self.registration.scope_digest()
            || registration_digest != self.registration.registration_digest()
        {
            return Err(TwilioHandoffError::ScopeMismatch);
        }
        Ok(())
    }
}

pub fn verify_callback_signature(
    callback: &TwilioCallbackRequest,
    auth_token: &SecretMaterial,
) -> Result<(), TwilioHandoffError> {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(auth_token.as_bytes())
        .map_err(|_| TwilioHandoffError::InvalidCallbackSignature)?;
    mac.update(
        callback_canonical_material(&callback.callback_url, &callback.form_parameters).as_bytes(),
    );
    let signature = STANDARD
        .decode(callback.signature.as_str())
        .map_err(|_| TwilioHandoffError::InvalidCallbackSignature)?;
    mac.verify_slice(&signature)
        .map_err(|_| TwilioHandoffError::InvalidCallbackSignature)
}

fn fixture_message_sid(
    fingerprint: &IdempotencyFingerprint,
) -> Result<TwilioMessageSid, TwilioHandoffError> {
    TwilioMessageSid::new(format!("SM{}", &fingerprint.as_str()[..32]))
}

fn validate_api_base_url(
    url: &url::Url,
    evidence_source: EvidenceSource,
) -> Result<(), TwilioHandoffError> {
    let is_loopback = url
        .host_str()
        .is_some_and(|host| matches!(host, "127.0.0.1" | "localhost" | "[::1]"));
    match evidence_source {
        EvidenceSource::NativeHttps if url.scheme() != "https" => {
            Err(TwilioHandoffError::InvalidInput {
                field: "Twilio API base URL",
                reason: "native transport requires HTTPS",
            })
        }
        EvidenceSource::Loopback if url.scheme() != "http" || !is_loopback => {
            Err(TwilioHandoffError::InvalidInput {
                field: "Twilio API base URL",
                reason: "loopback transport requires localhost HTTP",
            })
        }
        EvidenceSource::Fixture if url.host_str() != Some("fixture.invalid") => {
            Err(TwilioHandoffError::InvalidInput {
                field: "Twilio API base URL",
                reason: "fixture transport requires the fixture host",
            })
        }
        EvidenceSource::BlockedEnv => Err(TwilioHandoffError::BlockedEnv {
            variable: crate::TWILIO_NATIVE_ENV_GATE,
        }),
        _ => Ok(()),
    }
}

// Kept as a private type-level marker for the service/provider boundary.  It
// prevents accidental reintroduction of a stringly-typed JSON command path.
#[allow(dead_code)]
struct _TypedOnly(TwilioChannel);
