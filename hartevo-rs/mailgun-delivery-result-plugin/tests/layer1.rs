use hartevo_mailgun_delivery_result_plugin as mailgun;

fn scope_with_consent(consent: mailgun::ConsentScope) -> mailgun::MailgunDeliveryResultScope {
    let spec = mailgun::MailgunDeliveryResultScopeSpec::new(
        mailgun::MailgunAccountId::new("account-fixture").expect("account"),
        mailgun::MailgunDomain::new("sandbox.example.test").expect("domain"),
        vec![mailgun::MailgunTag::new("campaign:fixture").expect("tag")],
        mailgun::MailgunMessageSelector::from_message_id("message-fixture").expect("message"),
        mailgun::MailgunEventSelector::any(),
        Some(
            mailgun::RecipientFingerprint::from_recipient("user@example.test").expect("recipient"),
        ),
        mailgun::ProjectBinding::new("project-fixture", 4).expect("project"),
        mailgun::MissionBinding::new("mission-fixture", 7).expect("mission"),
        mailgun::WorkProductBinding::new("work-product-fixture", 9).expect("work product"),
        consent,
        mailgun::Revision::new(3).expect("scope revision"),
        mailgun::Revision::new(5).expect("provider revision"),
    );
    mailgun::MailgunDeliveryResultScope::new(spec).expect("scope")
}

fn scope() -> mailgun::MailgunDeliveryResultScope {
    scope_with_consent(mailgun::ConsentScope::new("consent-fixture", 2).expect("consent"))
}

fn delivered_event(id: &str) -> mailgun::MailgunDeliveryEvent {
    mailgun::MailgunDeliveryEvent::fixture(
        id,
        "message-fixture",
        "user@example.test",
        mailgun::MailgunEventKind::Delivered,
        1_800_000_000,
    )
    .expect("event")
}

fn page(
    events: Vec<mailgun::MailgunDeliveryEvent>,
    next_cursor: Option<mailgun::Cursor>,
) -> mailgun::MailgunEventPage {
    mailgun::MailgunEventPage::new(
        events,
        next_cursor,
        Vec::new(),
        512,
        mailgun::RateLimitReceipt::new(300, Some(299), None, false).expect("rate limit"),
    )
    .expect("page")
}

fn secret() -> mailgun::SecretReference {
    mailgun::SecretReference::api_key("opaque-mailgun-keyring-handle", 8).expect("secret")
}

#[test]
fn contract_and_scope_are_redacted_and_layer_one_honest() {
    let contract = mailgun::MailgunDeliveryResultContract::baseline().expect("contract");
    assert_eq!(
        contract.value()["schemaVersion"],
        mailgun::CONTRACT_SCHEMA_VERSION
    );
    assert_eq!(
        contract.value()["contractVersion"],
        mailgun::CONTRACT_VERSION
    );
    assert_eq!(contract.value()["contractDigest"], mailgun::CONTRACT_DIGEST);
    assert_eq!(mailgun::contract_digest(), mailgun::CONTRACT_DIGEST);

    let current_scope = scope();
    let scope_json = serde_json::to_string(&current_scope).expect("scope JSON");
    for raw in [
        "account-fixture",
        "sandbox.example.test",
        "campaign:fixture",
        "message-fixture",
        "user@example.test",
    ] {
        assert!(!scope_json.contains(raw), "scope leaked {raw}");
    }
    let debug = format!("{:?}", secret());
    assert!(!debug.contains("opaque-mailgun-keyring-handle"));
    assert!(!mailgun::Layer1Authority::connected());
    assert!(!mailgun::Layer1Authority::native());
    assert!(!mailgun::Layer1Authority::first_party());
    assert!(!mailgun::Layer1Authority::durable_provider_receipt());
    assert!(!mailgun::Layer1Authority::outcome_authority());
}

#[test]
fn fixture_proposal_record_and_verify_are_bounded_and_idempotent() {
    let current_scope = scope();
    let provider = mailgun::MailgunProvider::new(
        current_scope,
        secret(),
        mailgun::FixtureMailgunTransport::new(page(vec![delivered_event("event-1")], None)),
    )
    .expect("provider");
    let mut service = mailgun::MailgunDeliveryResultService::new(provider).expect("service");
    let proposal = service.propose_at(1_800_000_001).expect("proposal");
    assert_eq!(proposal.evidence.state, mailgun::EvidenceState::Ready);
    assert_eq!(
        proposal.evidence.delivery_status,
        mailgun::DeliveryStatus::Delivered
    );
    assert!(proposal.evidence.complete);
    assert!(proposal.validate_integrity().is_ok());
    let report = service.verify(&proposal);
    assert!(report.valid);
    assert!(report.review_eligible);
    assert!(!proposal.can_be_adopted());
    assert!(!proposal.native && !proposal.connected && !proposal.first_party);

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for raw in [
        "opaque-mailgun-keyring-handle",
        "user@example.test",
        "message-fixture",
    ] {
        assert!(!serialized.contains(raw), "proposal leaked {raw}");
    }
    let first = service
        .record(&proposal, "mailgun-record-1")
        .expect("record");
    assert!(!first.replayed);
    assert!(first.validate_integrity().is_ok());
    let replay = service
        .record(&proposal, "mailgun-record-1")
        .expect("replay");
    assert!(replay.replayed);
    assert_eq!(service.record_count(), 1);
}

#[test]
fn bounded_pagination_binds_cursor_and_marks_truncation_partial() {
    let first_cursor = mailgun::Cursor::new("opaque-next-cursor").expect("cursor");
    let provider = mailgun::MailgunProvider::new(
        scope(),
        secret(),
        mailgun::RecordingMailgunTransport::from_pages(vec![
            Ok(page(vec![delivered_event("event-1")], Some(first_cursor))),
            Ok(page(vec![delivered_event("event-2")], None)),
        ]),
    )
    .expect("provider");
    let mut service = mailgun::MailgunDeliveryResultService::new(provider).expect("service");
    let request = service
        .default_request(1_800_000_001)
        .with_page_bounds(1, 2);
    let evidence = service.read_with_request(request).expect("evidence");
    assert_eq!(evidence.state, mailgun::EvidenceState::Ready);
    assert!(evidence.complete);
    assert_eq!(evidence.events.len(), 2);
    assert_eq!(service.provider().transport().requests().len(), 2);
    assert!(
        service.provider().transport().requests()[1]
            .cursor
            .is_some()
    );
    assert!(
        !serde_json::to_string(&service.provider().transport().requests()[1])
            .expect("request JSON")
            .contains("opaque-next-cursor")
    );

    let provider = mailgun::MailgunProvider::new(
        scope(),
        secret(),
        mailgun::FixtureMailgunTransport::new(page(
            vec![delivered_event("event-1")],
            Some(mailgun::Cursor::new("cursor-for-truncation").expect("cursor")),
        )),
    )
    .expect("provider");
    let mut service = mailgun::MailgunDeliveryResultService::new(provider).expect("service");
    let evidence = service
        .read_with_request(
            service
                .default_request(1_800_000_001)
                .with_page_bounds(1, 1),
        )
        .expect("partial evidence");
    assert_eq!(evidence.state, mailgun::EvidenceState::Partial);
    assert!(!evidence.complete);
}

#[test]
fn rate_limit_blocked_environment_and_partial_unknown_are_typed() {
    let provider = mailgun::MailgunProvider::new(
        scope(),
        secret(),
        mailgun::RecordingMailgunTransport::from_pages(vec![Err(
            mailgun::MailgunTransportError::RateLimited {
                retry_after_seconds: Some(12),
                attempt: 2,
            },
        )]),
    )
    .expect("provider");
    let mut service = mailgun::MailgunDeliveryResultService::new(provider).expect("service");
    let evidence = service.read().expect("rate evidence");
    assert_eq!(evidence.state, mailgun::EvidenceState::RateLimited);
    assert!(evidence.rate_limit.throttled);
    assert_eq!(evidence.backoff.retry_after_seconds, Some(12));
    assert!(!evidence.native && !evidence.connected);

    let provider =
        mailgun::MailgunProvider::new(scope(), secret(), mailgun::BlockedEnvMailgunTransport)
            .expect("provider");
    let mut service = mailgun::MailgunDeliveryResultService::new(provider).expect("service");
    let evidence = service.read().expect("blocked evidence");
    assert_eq!(evidence.state, mailgun::EvidenceState::ProviderUnknown);
    assert_eq!(
        evidence.classification,
        mailgun::EvidenceClassification::BlockedEnv
    );
    assert!(!evidence.native && !evidence.connected && !evidence.first_party);

    let provider = mailgun::MailgunProvider::new(
        scope(),
        secret(),
        mailgun::FixtureMailgunTransport::from_pages(vec![
            Ok(page(
                vec![delivered_event("event-1")],
                Some(mailgun::Cursor::new("unknown-next").expect("cursor")),
            )),
            Err(mailgun::MailgunTransportError::ProviderUnknown),
        ]),
    )
    .expect("provider");
    let mut service = mailgun::MailgunDeliveryResultService::new(provider).expect("service");
    let evidence = service.read().expect("partial unknown evidence");
    assert_eq!(evidence.state, mailgun::EvidenceState::Partial);
    assert_eq!(evidence.events.len(), 1);
}

#[test]
fn webhook_tamper_and_replay_are_fenced() {
    let event = delivered_event("event-webhook");
    let envelope = mailgun::MailgunWebhookEnvelope::fixture(
        "event-webhook",
        1_800_000_000,
        "opaque-webhook-token",
        &event,
    )
    .expect("webhook");
    let provider = mailgun::MailgunProvider::new(
        scope(),
        secret(),
        mailgun::FixtureMailgunTransport::from_pages(vec![
            Ok(page(vec![event.clone()], None)),
            Ok(page(vec![event], None)),
        ]),
    )
    .expect("provider");
    let mut service = mailgun::MailgunDeliveryResultService::new(provider).expect("service");
    let first = service
        .read_with_request(
            service
                .default_request(1_800_000_001)
                .with_webhook(envelope.clone()),
        )
        .expect("verified webhook");
    assert_eq!(first.state, mailgun::EvidenceState::Ready);
    assert!(first.webhook.as_ref().expect("webhook evidence").verified);
    let second = service
        .read_with_request(
            service
                .default_request(1_800_000_001)
                .with_webhook(envelope),
        )
        .expect("replayed webhook");
    assert_eq!(second.state, mailgun::EvidenceState::ReplayRejected);
    assert!(!second.webhook.as_ref().expect("replay evidence").verified);

    let provider = mailgun::MailgunProvider::new(
        scope(),
        secret(),
        mailgun::FixtureMailgunTransport::new(page(vec![delivered_event("event-tamper")], None)),
    )
    .expect("provider");
    let mut service = mailgun::MailgunDeliveryResultService::new(provider).expect("service");
    let tampered = mailgun::MailgunWebhookEnvelope::fixture(
        "event-tamper",
        1_800_000_000,
        "opaque-webhook-token",
        &delivered_event("event-tamper"),
    )
    .expect("webhook")
    .tampered();
    let evidence = service
        .read_with_request(
            service
                .default_request(1_800_000_001)
                .with_webhook(tampered),
        )
        .expect("tampered evidence");
    assert_eq!(evidence.state, mailgun::EvidenceState::Tampered);
    assert!(!evidence.webhook.as_ref().expect("tamper evidence").verified);
}

#[test]
fn consent_expiry_and_registration_revoke_are_fail_closed() {
    let expiring_scope = scope_with_consent(
        mailgun::ConsentScope::with_expiry("consent-expiring", 2, Some(100)).expect("consent"),
    );
    let provider = mailgun::MailgunProvider::new(
        expiring_scope,
        secret(),
        mailgun::FixtureMailgunTransport::new(page(vec![delivered_event("event-expired")], None)),
    )
    .expect("provider");
    let mut service = mailgun::MailgunDeliveryResultService::new(provider).expect("service");
    let evidence = service.read_at(101).expect("expired evidence");
    assert_eq!(evidence.state, mailgun::EvidenceState::Expired);
    assert!(service.provider().provenance() == mailgun::TransportProvenance::Fixture);

    let original = service.registration().registration_digest.clone();
    let _revocation = service.revoke_registration().expect("revoke");
    assert!(!service.registration().is_active());
    assert_ne!(service.registration().registration_digest, original);
    assert!(service.read().is_err());
    service.restore_registration().expect("restore");
    assert!(service.registration().is_active());
    assert_ne!(service.registration().registration_digest, original);
}

#[test]
fn mission_consumer_rejects_proposal_replay_and_preserves_exact_scope() {
    let current_scope = scope();
    let provider = mailgun::MailgunProvider::new(
        current_scope,
        secret(),
        mailgun::FixtureMailgunTransport::new(page(vec![delivered_event("event-consumer")], None)),
    )
    .expect("provider");
    let mut consumer = mailgun::MissionMailgunDeliveryConsumer::new(provider).expect("consumer");
    let proposal = consumer.propose().expect("proposal");
    let result = consumer.consume(&proposal).expect("consume");
    assert_eq!(
        result.state,
        mailgun::MissionMailgunDeliveryResultState::DecisionReady
    );
    assert_eq!(result.project, consumer.service().scope().project);
    assert_eq!(result.mission, consumer.service().scope().mission);
    assert_eq!(result.work_product, consumer.service().scope().work_product);
    assert!(!result.adopts_outcome && !result.adopts_work_product);
    assert!(consumer.consume(&proposal).is_err());
}

fn assert_non_native_transport<T: mailgun::MailgunTransport>(
    transport: T,
    expected: &mailgun::TransportProvenance,
) {
    let provider = mailgun::MailgunProvider::new(scope(), secret(), transport).expect("provider");
    assert_eq!(&provider.provenance(), expected);
    assert!(!provider.definition().native);
    assert!(!provider.definition().connected);
    assert!(!provider.definition().first_party);
    let mut service = mailgun::MailgunDeliveryResultService::new(provider).expect("service");
    let evidence = service.read().expect("typed evidence");
    assert!(!evidence.native && !evidence.connected && !evidence.first_party);
}

#[test]
fn every_fixture_transport_is_explicitly_non_native_and_suppression_is_redacted() {
    assert_non_native_transport(
        mailgun::FixtureMailgunTransport::new(page(vec![delivered_event("fixture")], None)),
        &mailgun::TransportProvenance::Fixture,
    );
    assert_non_native_transport(
        mailgun::RecordingMailgunTransport::new(page(vec![delivered_event("recording")], None)),
        &mailgun::TransportProvenance::Recording,
    );
    assert_non_native_transport(
        mailgun::FakeMailgunTransport::new(page(vec![delivered_event("fake")], None)),
        &mailgun::TransportProvenance::Fake,
    );
    assert_non_native_transport(
        mailgun::LoopbackMailgunTransport::new(page(vec![delivered_event("loopback")], None)),
        &mailgun::TransportProvenance::Loopback,
    );
    assert_non_native_transport(
        mailgun::BlockedEnvMailgunTransport,
        &mailgun::TransportProvenance::BlockedEnv,
    );

    let mut transport = mailgun::FixtureMailgunTransport::new(page(Vec::new(), None));
    transport.push_suppressions(Ok(vec![
        mailgun::SuppressionMetadata::with_reason(
            mailgun::SuppressionCategory::Bounce,
            true,
            "private provider diagnostic",
        )
        .expect("suppression"),
    ]));
    let provider = mailgun::MailgunProvider::new(scope(), secret(), transport).expect("provider");
    let mut service = mailgun::MailgunDeliveryResultService::new(provider).expect("service");
    let evidence = service.read().expect("suppression evidence");
    assert_eq!(evidence.suppression.len(), 1);
    let serialized = serde_json::to_string(&evidence).expect("evidence JSON");
    assert!(!serialized.contains("private provider diagnostic"));
}
