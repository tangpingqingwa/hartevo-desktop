use std::collections::BTreeMap;
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hartevo_twilio_handoff_plugin::{
    DeliveryStatusRequest, E164PhoneNumber, EvidenceSource, HandoffProposalRequest, MessageBody,
    MissionHandoffResultConsumer, MissionHandoffResultInput, MissionId, MissionScope, ProjectId,
    ReceiptReadRequest, RecordingTwilioHttpsTransport, RetryPolicy, SecretMaterial,
    SourceResultDigest, StatusEvidence, TwilioAccountSid, TwilioCallbackRequest,
    TwilioCallbackSignature, TwilioChannel, TwilioHandoffError, TwilioHandoffProvider,
    TwilioHandoffRegistration, TwilioHandoffService, TwilioHttpResponse, TwilioMessageSid,
    TwilioMessageStatus, TwilioMessagingServiceSid, TwilioReadRequest, TwilioScope,
    TwilioSenderScope, TwilioTransportError,
};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha1::Sha1;

const NOW_MS: u64 = 1_700_000_000_000;

fn account() -> TwilioAccountSid {
    TwilioAccountSid::new(format!("AC{}", "a".repeat(32))).expect("account SID")
}

fn message_sid() -> TwilioMessageSid {
    TwilioMessageSid::new(format!("SM{}", "c".repeat(32))).expect("message SID")
}

fn mission() -> MissionScope {
    MissionScope::new(
        ProjectId::new("project-1").expect("project"),
        MissionId::new("mission-1").expect("mission"),
    )
    .expect("mission scope")
}

fn phone() -> E164PhoneNumber {
    E164PhoneNumber::new("+15551234567").expect("phone")
}

fn sms_scope() -> TwilioScope {
    TwilioScope::new(
        account(),
        TwilioSenderScope::PhoneNumber(phone()),
        TwilioChannel::Sms,
        phone(),
        mission(),
    )
    .expect("SMS scope")
}

fn whatsapp_scope() -> TwilioScope {
    TwilioScope::new(
        account(),
        TwilioSenderScope::MessagingService(
            TwilioMessagingServiceSid::new(format!("MG{}", "b".repeat(32)))
                .expect("messaging service SID"),
        ),
        TwilioChannel::Whatsapp,
        phone(),
        mission(),
    )
    .expect("WhatsApp scope")
}

fn source_result_digest() -> SourceResultDigest {
    SourceResultDigest::new("d".repeat(64)).expect("source result digest")
}

fn registration(scope: TwilioScope) -> TwilioHandoffRegistration {
    TwilioHandoffRegistration::new(scope).expect("registration")
}

fn proposal(
    service: &TwilioHandoffService,
    scope: TwilioScope,
) -> hartevo_twilio_handoff_plugin::HandoffProposal {
    service
        .propose(
            HandoffProposalRequest::new(
                scope,
                source_result_digest(),
                MessageBody::new("Approval needed for the next bounded step").expect("body"),
            )
            .expect("proposal request"),
        )
        .expect("proposal")
}

fn status_request(
    registration: &TwilioHandoffRegistration,
    receipt: &hartevo_twilio_handoff_plugin::TwilioMessageReceipt,
    status: TwilioMessageStatus,
    observed_at_ms: u64,
    evidence: StatusEvidence,
) -> DeliveryStatusRequest {
    DeliveryStatusRequest {
        scope_digest: registration.scope_digest().clone(),
        registration_digest: registration.registration_digest().clone(),
        idempotency_fingerprint: receipt.redacted().idempotency_fingerprint.clone(),
        provider_message_sid: receipt.provider_message_sid().clone(),
        next_status: status,
        observed_at_ms,
        evidence,
    }
}

fn twilio_signature(url: &str, parameters: &BTreeMap<String, String>, token: &[u8]) -> String {
    type HmacSha1 = Hmac<Sha1>;
    let mut material = url.to_owned();
    for (name, value) in parameters {
        material.push_str(name);
        material.push_str(value);
    }
    let mut mac = HmacSha1::new_from_slice(token).expect("HMAC key");
    mac.update(material.as_bytes());
    STANDARD.encode(mac.finalize().into_bytes())
}

#[test]
fn sms_and_whatsapp_scopes_are_explicit_and_require_e164_recipients() {
    let sms = sms_scope();
    let whatsapp = whatsapp_scope();
    assert_eq!(sms.channel, TwilioChannel::Sms);
    assert_eq!(whatsapp.channel, TwilioChannel::Whatsapp);
    assert_ne!(sms.digest(), whatsapp.digest());
    assert_eq!(sms.recipient_address(), "+15551234567");
    assert_eq!(whatsapp.recipient_address(), "whatsapp:+15551234567");
    assert!(matches!(
        TwilioChannel::from_provider_value("mms"),
        Err(TwilioHandoffError::UnsupportedChannel)
    ));
    assert!(E164PhoneNumber::new("15551234567").is_err());
    assert!(E164PhoneNumber::new("+012345678").is_err());
}

#[test]
fn mission_consumer_emits_canonical_non_mutating_proposal_and_duplicate_receipt() {
    let scope = sms_scope();
    let registration = registration(scope.clone());
    let service = TwilioHandoffService::new(registration.clone()).expect("service");
    let consumer = MissionHandoffResultConsumer::new(registration.clone()).expect("consumer");
    let input = MissionHandoffResultInput::new(
        mission(),
        source_result_digest(),
        scope.clone(),
        MessageBody::new("Approval needed for the next bounded step").expect("body"),
    )
    .expect("input");

    let first = consumer
        .propose(&service, input.clone())
        .expect("first proposal");
    let second = consumer.propose(&service, input).expect("second proposal");
    assert_eq!(
        first.proposal.canonical_digest,
        second.proposal.canonical_digest
    );
    assert_eq!(
        first.proposal.idempotency_fingerprint,
        second.proposal.idempotency_fingerprint
    );
    assert!(first.proposal.is_non_mutating());
    assert!(first.is_adoptable());
    assert!(!first.external_mutation_performed);
    assert!(!first.native_connected);
    assert_eq!(
        first.proposal.registration_digest,
        *registration.registration_digest()
    );

    let provider = TwilioHandoffProvider::recording(registration.clone()).expect("provider");
    let first_receipt = service
        .record_receipt(&provider, &first.proposal, NOW_MS)
        .expect("recorded receipt");
    let duplicate_receipt = service
        .record_receipt(&provider, &first.proposal, NOW_MS + 1_000)
        .expect("duplicate receipt");
    assert_eq!(first_receipt, duplicate_receipt);
    assert_eq!(provider.receipt_count(), 1);
    assert_eq!(first_receipt.status().status, TwilioMessageStatus::Queued);
    assert!(!first_receipt.external_write_performed());

    let read_request = ReceiptReadRequest::new(
        registration.scope_digest().clone(),
        registration.registration_digest().clone(),
        first.proposal.idempotency_fingerprint.clone(),
        Some(first_receipt.provider_message_sid().clone()),
    );
    let redacted = service
        .read_receipt(&provider, &read_request)
        .expect("receipt")
        .redacted();
    let serialized = serde_json::to_string(&redacted).expect("redacted JSON");
    assert!(!serialized.contains("+15551234567"));
    assert!(!serialized.contains("Approval needed"));
    assert!(!serialized.contains("token-secret"));
    assert!(serialized.contains("phoneNumbers"));
    assert!(serialized.contains("messageBodies"));
    assert!(!format!("{first_receipt:?}").contains("+15551234567"));
    assert!(!format!("{first_receipt:?}").contains("Approval needed"));

    let tampered_read = ReceiptReadRequest::new(
        registration.scope_digest().clone(),
        hartevo_twilio_handoff_plugin::RegistrationDigest::new("e".repeat(64))
            .expect("tampered digest shape"),
        first.proposal.idempotency_fingerprint.clone(),
        None,
    );
    assert!(matches!(
        service.read_receipt(&provider, &tampered_read),
        Err(TwilioHandoffError::ScopeMismatch)
    ));
}

#[test]
fn status_projection_is_monotonic_and_preserves_failure_distinctions() {
    let scope = sms_scope();
    let registration = registration(scope.clone());
    let service = TwilioHandoffService::new(registration.clone()).expect("service");
    let provider = TwilioHandoffProvider::recording(registration.clone()).expect("provider");
    let proposal = proposal(&service, scope);
    let receipt = service
        .record_receipt(&provider, &proposal, NOW_MS)
        .expect("receipt");

    for (offset, status) in [
        (1, TwilioMessageStatus::Sending),
        (2, TwilioMessageStatus::Sent),
        (3, TwilioMessageStatus::Delivered),
        (4, TwilioMessageStatus::Read),
    ] {
        let projection = service
            .project_delivery_status(
                &provider,
                &status_request(
                    &registration,
                    &receipt,
                    status,
                    NOW_MS + offset,
                    StatusEvidence::Fixture,
                ),
            )
            .expect("monotonic status");
        assert_eq!(projection.status, status);
        assert!(projection.monotonic);
    }
    let regression = service.project_delivery_status(
        &provider,
        &status_request(
            &registration,
            &receipt,
            TwilioMessageStatus::Sent,
            NOW_MS + 10,
            StatusEvidence::Fixture,
        ),
    );
    assert!(matches!(
        regression,
        Err(TwilioHandoffError::NonMonotonicStatus {
            current: TwilioMessageStatus::Read,
            next: TwilioMessageStatus::Sent
        })
    ));

    let failed_provider = TwilioHandoffProvider::recording(registration.clone()).expect("provider");
    let failed_receipt = service
        .record_receipt(&failed_provider, &proposal, NOW_MS)
        .expect("failed receipt");
    service
        .project_delivery_status(
            &failed_provider,
            &status_request(
                &registration,
                &failed_receipt,
                TwilioMessageStatus::Sending,
                NOW_MS + 1,
                StatusEvidence::Fixture,
            ),
        )
        .expect("sending");
    let failed = service
        .project_delivery_status(
            &failed_provider,
            &status_request(
                &registration,
                &failed_receipt,
                TwilioMessageStatus::Failed,
                NOW_MS + 2,
                StatusEvidence::Fixture,
            ),
        )
        .expect("failed status");
    assert_eq!(failed.status, TwilioMessageStatus::Failed);
    assert!(failed.status.is_failure());
    assert!(
        service
            .project_delivery_status(
                &failed_provider,
                &status_request(
                    &registration,
                    &failed_receipt,
                    TwilioMessageStatus::Delivered,
                    NOW_MS + 3,
                    StatusEvidence::Fixture,
                ),
            )
            .is_err()
    );
}

#[test]
fn callback_hmac_is_verification_only_replay_fenced_and_tamper_safe() {
    let scope = sms_scope();
    let registration = registration(scope.clone());
    let service = TwilioHandoffService::new(registration.clone()).expect("service");
    let provider = TwilioHandoffProvider::recording(registration.clone()).expect("provider");
    let proposal = proposal(&service, scope.clone());
    let receipt = service
        .record_receipt(&provider, &proposal, NOW_MS)
        .expect("receipt");
    let token_bytes = b"token-secret";
    let token = SecretMaterial::new("token-secret").expect("secret");
    let callback_url = "https://handoff.example.test/twilio/status";
    let mut form = BTreeMap::from([
        ("AccountSid".to_owned(), scope.account_id.to_string()),
        (
            "MessageSid".to_owned(),
            receipt.provider_message_sid().to_string(),
        ),
        ("MessageStatus".to_owned(), "sent".to_owned()),
        ("To".to_owned(), "+15551234567".to_owned()),
    ]);
    let signature = twilio_signature(callback_url, &form, token_bytes);
    let callback = TwilioCallbackRequest::new(
        callback_url,
        TwilioCallbackSignature::new(signature.clone()).expect("signature"),
        form.clone(),
        NOW_MS,
        NOW_MS,
    )
    .expect("callback");
    let signal = service
        .verify_inbound_signal(&provider, &callback, &token)
        .expect("verified callback");
    assert_eq!(signal.status, TwilioMessageStatus::Sent);
    assert_eq!(
        signal.idempotency_fingerprint,
        proposal.idempotency_fingerprint
    );
    assert!(!provider.is_connected());

    form.insert("MessageStatus".to_owned(), "delivered".to_owned());
    let tampered = TwilioCallbackRequest::new(
        callback_url,
        TwilioCallbackSignature::new(signature.clone()).expect("signature"),
        form,
        NOW_MS + 1,
        NOW_MS + 1,
    )
    .expect("tampered callback");
    assert!(matches!(
        service.verify_inbound_signal(&provider, &tampered, &token),
        Err(TwilioHandoffError::InvalidCallbackSignature)
    ));

    let mut stale_form = BTreeMap::from([
        ("AccountSid".to_owned(), scope.account_id.to_string()),
        (
            "MessageSid".to_owned(),
            receipt.provider_message_sid().to_string(),
        ),
        ("MessageStatus".to_owned(), "delivered".to_owned()),
        ("To".to_owned(), "+15551234567".to_owned()),
    ]);
    let stale_event = NOW_MS - 300_001;
    let stale_signature = twilio_signature(callback_url, &stale_form, token_bytes);
    let stale = TwilioCallbackRequest::new(
        callback_url,
        TwilioCallbackSignature::new(stale_signature).expect("signature"),
        std::mem::take(&mut stale_form),
        stale_event,
        NOW_MS,
    )
    .expect("stale callback");
    assert!(matches!(
        service.verify_inbound_signal(&provider, &stale, &token),
        Err(TwilioHandoffError::CallbackReplayWindow)
    ));
}

#[test]
fn recording_readback_is_bounded_and_fixture_loopback_blocked_env_are_not_connected() {
    let scope = sms_scope();
    let registration = registration(scope.clone());
    let resource_sid = message_sid();
    let response_body = json!({
        "sid": resource_sid.to_string(),
        "account_sid": scope.account_id.to_string(),
        "status": "sent",
        "to": "+15551234567",
        "from": "+15551234567",
        "messaging_service_sid": null,
        "error_code": null
    })
    .to_string();
    let transport = RecordingTwilioHttpsTransport::loopback([
        Err(TwilioTransportError::RateLimited {
            retry_after_ms: Some(100),
        }),
        Err(TwilioTransportError::Timeout),
        Ok(TwilioHttpResponse::json(200, &response_body)),
    ]);
    let provider = TwilioHandoffProvider::loopback(registration, Arc::new(transport.clone()))
        .expect("loopback provider")
        .with_retry_policy(RetryPolicy::new(3, 10, 20).expect("retry policy"));
    let secret = SecretMaterial::new("token-secret").expect("secret");
    let resource = provider
        .read_remote_message(
            &TwilioReadRequest::new(scope.account_id.clone(), resource_sid),
            &secret,
        )
        .expect("fixture readback");
    assert_eq!(resource.status, TwilioMessageStatus::Sent);
    assert_eq!(transport.requests().len(), 3);
    assert_eq!(
        provider.probe().status,
        hartevo_twilio_handoff_plugin::TwilioProbeStatus::VerifiedLoopbackNotConnected
    );
    assert!(!provider.probe().connected);
    assert!(!provider.probe().native);
    assert!(!provider.is_connected());
    assert!(!format!("{secret:?}").contains("token-secret"));
    assert_eq!(RetryPolicy::default().backoff_ms_for_retry(1), Some(250));
    assert_eq!(RetryPolicy::default().backoff_ms_for_retry(2), Some(500));
    assert_eq!(RetryPolicy::default().backoff_ms_for_retry(3), None);

    let blocked = hartevo_twilio_handoff_plugin::TwilioProviderProbe::blocked_env();
    assert_eq!(blocked.evidence_source, EvidenceSource::BlockedEnv);
    assert!(!blocked.connected);
    assert!(!blocked.native);
}

#[test]
fn registration_is_digest_scope_bound_and_revocable() {
    let registration = registration(sms_scope());
    registration.validate().expect("valid registration");
    assert_eq!(registration.plugin_version, 1);
    assert_eq!(
        registration.scope_digest().as_str(),
        registration.scope.digest()
    );
    let mut revoked = registration.clone();
    let revocation = revoked.revoke().expect("revocation");
    assert!(!revoked.is_active());
    assert_eq!(revocation.scope_digest, *registration.scope_digest());
    assert_eq!(
        revocation.registration_digest,
        *registration.registration_digest()
    );
    let service = TwilioHandoffService::new(revoked).expect("revoked service shape");
    let error = service.propose(
        HandoffProposalRequest::new(
            registration.scope.clone(),
            source_result_digest(),
            MessageBody::new("blocked").expect("body"),
        )
        .expect("request"),
    );
    assert!(matches!(
        error,
        Err(TwilioHandoffError::RegistrationRevoked)
    ));
}
