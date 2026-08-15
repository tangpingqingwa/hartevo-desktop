use hartevo_nylas_communication_result_plugin as nylas;
use serde_json::json;

fn scope() -> nylas::NylasCommunicationScope {
    let spec = nylas::NylasCommunicationScopeSpec::new(
        nylas::NylasApplicationId::new("app-785").expect("application"),
        nylas::NylasGrantId::new("grant-785").expect("grant"),
        nylas::NylasMailboxId::new("mailbox-785").expect("mailbox"),
        nylas::NylasCalendarId::new("calendar-785").expect("calendar"),
        nylas::NylasThreadId::new("thread-785").expect("thread"),
        nylas::NylasMessageId::new("message-785").expect("message"),
        nylas::NylasEventId::new("event-785").expect("event"),
        nylas::ProjectBinding::new("project-785", 1).expect("project"),
        nylas::MissionBinding::new("mission-785", 1).expect("mission"),
        nylas::WorkProductBinding::new("work-product-785", 1).expect("work product"),
        nylas::NylasPermissionSnapshot::read_only(1).expect("permissions"),
        1,
    )
    .expect("scope spec");
    nylas::NylasCommunicationScope::new(spec).expect("scope")
}

fn secret() -> nylas::SecretReference {
    nylas::SecretReference::access_token("opaque-access-token-reference", 1).expect("secret")
}

fn messages_response() -> nylas::NylasResponse {
    nylas::NylasResponse::json(
        200,
        &json!({
            "data": [{
                "object": "message",
                "id": "message-785",
                "grant_id": "grant-785",
                "thread_id": "thread-785",
                "date": 1_720_000_000,
                "updated_at": 1_720_000_100,
                "subject": "Private subject must not cross the boundary",
                "body": "Private body must not cross the boundary",
                "from": [{"email": "sender@example.test"}],
                "to": [{"email": "recipient@example.test"}],
                "status": "delivered",
                "has_attachments": false,
                "unread": false,
                "starred": true
            }],
            "next_cursor": "cursor-785"
        }),
    )
}

#[test]
fn contract_is_machine_valid_and_every_transport_is_non_native() {
    let contract = nylas::NylasCommunicationResultContract::baseline().expect("contract");
    assert_eq!(contract.value()["contractVersion"], nylas::CONTRACT_VERSION);
    assert_eq!(contract.value()["contractDigest"], nylas::CONTRACT_DIGEST);

    for provenance in [
        nylas::NylasTransportProvenance::Fixture,
        nylas::NylasTransportProvenance::Recording,
        nylas::NylasTransportProvenance::Fake,
        nylas::NylasTransportProvenance::Loopback,
        nylas::NylasTransportProvenance::BlockedEnv,
    ] {
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
    }
}

#[test]
fn fixture_read_produces_redacted_deterministic_message_digest_and_receipts() {
    let scope = scope();
    let provider = nylas::NylasProvider::new(
        scope.clone(),
        secret(),
        nylas::FixtureNylasTransport::new(messages_response()),
    )
    .expect("provider");
    let mut service = nylas::NylasCommunicationResultService::new(provider).expect("service");
    let key = nylas::IdempotencyKey::new("message-read-785").expect("key");
    let request = nylas::NylasCommunicationRequest::messages(&scope, &key).expect("request");

    let evidence = service.read(&request).expect("evidence");
    assert_eq!(evidence.state, nylas::NylasEvidenceState::Delivered);
    let page = evidence.page().expect("page");
    assert_eq!(page.records.len(), 1);
    let record = &page.records[0];
    assert!(record.message_digest.is_some());
    assert!(record.thread_digest.is_none());
    assert_eq!(page.next_cursor_digest.as_ref().map(String::len), Some(64));
    assert_eq!(
        page.cursor_binding_digest,
        Some(request.cursor_binding_digest())
    );

    let serialized = serde_json::to_string(&evidence).expect("evidence serializes");
    assert!(!serialized.contains("Private body"));
    assert!(!serialized.contains("recipient@example.test"));
    assert!(!serialized.contains("Private subject"));
    assert!(!format!("{:?}", secret()).contains("opaque-access-token-reference"));

    let proposal = service.propose(&request).expect("proposal");
    let replay = service.propose(&request).expect("proposal replay");
    assert!(replay.replayed);
    assert_eq!(proposal.proposal_digest, replay.proposal_digest);
    assert!(service.verify_proposal(&proposal).is_ok());

    let record_key = nylas::IdempotencyKey::new("record-785").expect("record key");
    let receipt = service.record(&proposal, &record_key).expect("record");
    let replay_receipt = service
        .record(&proposal, &record_key)
        .expect("record replay");
    assert!(!receipt.replayed);
    assert!(replay_receipt.replayed);
    assert_eq!(receipt.record_digest, replay_receipt.record_digest);
}

#[test]
fn mission_consumer_is_scope_bound_and_replay_fenced() {
    let scope = scope();
    let provider = nylas::NylasProvider::new(
        scope.clone(),
        secret(),
        nylas::FixtureNylasTransport::new(messages_response()),
    )
    .expect("provider");
    let service = nylas::NylasCommunicationResultService::new(provider).expect("service");
    let mut consumer = nylas::MissionNylasCommunicationConsumer::from_service(service);
    let key = nylas::IdempotencyKey::new("consumer-read-785").expect("key");
    let request = nylas::NylasCommunicationRequest::messages(&scope, &key).expect("request");
    let proposal = consumer.propose(&request).expect("proposal");
    let result = consumer.consume(&proposal).expect("consume");
    assert_eq!(
        result.state,
        nylas::MissionNylasCommunicationResultState::Delivered
    );
    assert_eq!(result.consumer_id, nylas::CONSUMER_ID);
    assert!(result.review_only);
    assert!(!result.connected);
    assert!(!result.native_provider);
    assert!(!result.first_party);
    assert!(!result.outcome_authority);
    assert!(!result.work_product_adopted);
    assert_eq!(consumer.consumed_count(), 1);
    assert!(matches!(
        consumer.consume(&proposal),
        Err(nylas::MissionNylasCommunicationConsumerError::ReplayDetected)
    ));
}

#[test]
fn recording_transport_retains_only_redacted_requests_and_blocked_env_is_honest() {
    let scope = scope();
    let key = nylas::IdempotencyKey::new("recording-785").expect("key");
    let request = nylas::NylasCommunicationRequest::messages(&scope, &key).expect("request");
    let provider = nylas::NylasProvider::new(
        scope.clone(),
        secret(),
        nylas::RecordingNylasTransport::new(messages_response()),
    )
    .expect("provider");
    let mut service = nylas::NylasCommunicationResultService::new(provider).expect("service");
    service.read(&request).expect("recording read");
    let transport = service.provider().transport();
    assert_eq!(transport.requests().len(), 1);
    assert_eq!(
        transport.requests()[0].path,
        "/v3/grants/{grant_id}/messages"
    );
    assert!(
        !serde_json::to_string(transport.requests())
            .expect("request serializes")
            .contains("grant-785")
    );

    let provider =
        nylas::NylasProvider::new(scope.clone(), secret(), nylas::BlockedEnvNylasTransport)
            .expect("blocked provider");
    let mut service = nylas::NylasCommunicationResultService::new(provider).expect("service");
    let evidence = service.read(&request).expect("blocked evidence");
    assert_eq!(evidence.state, nylas::NylasEvidenceState::BlockedEnv);
    assert_eq!(
        evidence.provenance,
        nylas::NylasTransportProvenance::BlockedEnv
    );
    assert!(!evidence.connected);
    assert!(!evidence.native_provider);
    assert!(!evidence.first_party);
}

#[test]
fn calendar_event_thread_and_status_projections_are_bounded() {
    let scope = scope();
    let thread_body = json!({
        "data": [{
            "object": "thread",
            "id": "thread-785",
            "grant_id": "grant-785",
            "subject": "Thread subject",
            "message_ids": ["message-785"],
            "has_attachments": false
        }]
    });
    let calendar_body = json!({
        "data": [{
            "object": "calendar",
            "id": "calendar-785",
            "name": "Private calendar name",
            "description": "Private calendar description",
            "is_primary": true
        }]
    });
    let event_body = json!({
        "data": [{
            "object": "event",
            "id": "event-785",
            "calendar_id": "calendar-785",
            "title": "Private event title",
            "description": "Private event description",
            "when": {"start_time": 1_720_000_000},
            "participants": [{"email": "participant@example.test"}],
            "status": "cancelled",
            "cancelled": true,
            "busy": true
        }]
    });

    let thread_key = nylas::IdempotencyKey::new("thread-785").expect("thread key");
    let thread_request =
        nylas::NylasCommunicationRequest::threads(&scope, &thread_key).expect("thread request");
    let provider = nylas::NylasProvider::new(
        scope.clone(),
        secret(),
        nylas::FixtureNylasTransport::new(nylas::NylasResponse::json(200, &thread_body)),
    )
    .expect("thread provider");
    let mut service =
        nylas::NylasCommunicationResultService::new(provider).expect("thread service");
    let evidence = service.read(&thread_request).expect("thread evidence");
    assert_eq!(evidence.state, nylas::NylasEvidenceState::Complete);
    assert!(
        evidence.page().expect("thread page").records[0]
            .thread_digest
            .is_some()
    );

    let calendar_key = nylas::IdempotencyKey::new("calendar-785").expect("calendar key");
    let calendar_request = nylas::NylasCommunicationRequest::calendars(&scope, &calendar_key)
        .expect("calendar request");
    let provider = nylas::NylasProvider::new(
        scope.clone(),
        secret(),
        nylas::FixtureNylasTransport::new(nylas::NylasResponse::json(200, &calendar_body)),
    )
    .expect("calendar provider");
    let mut service =
        nylas::NylasCommunicationResultService::new(provider).expect("calendar service");
    let evidence = service.read(&calendar_request).expect("calendar evidence");
    assert_eq!(evidence.state, nylas::NylasEvidenceState::Complete);
    let serialized = serde_json::to_string(&evidence).expect("calendar serializes");
    assert!(!serialized.contains("Private calendar description"));

    let event_key = nylas::IdempotencyKey::new("event-785").expect("event key");
    let event_request =
        nylas::NylasCommunicationRequest::events(&scope, &event_key).expect("event request");
    let provider = nylas::NylasProvider::new(
        scope,
        secret(),
        nylas::FixtureNylasTransport::new(nylas::NylasResponse::json(200, &event_body)),
    )
    .expect("event provider");
    let mut service = nylas::NylasCommunicationResultService::new(provider).expect("event service");
    let evidence = service.read(&event_request).expect("event evidence");
    assert_eq!(evidence.state, nylas::NylasEvidenceState::Cancelled);
    let event = &evidence.page().expect("event page").records[0];
    assert!(event.event_digest.is_some());
    assert_eq!(event.participant_count, Some(1));
}

#[test]
fn access_loss_tamper_partial_provider_unknown_and_revocation_are_explicit() {
    let scope = scope();
    let key = nylas::IdempotencyKey::new("failure-states-785").expect("key");
    let request = nylas::NylasCommunicationRequest::messages(&scope, &key).expect("request");

    for (status, expected) in [
        (401, nylas::NylasEvidenceState::AccessLoss),
        (429, nylas::NylasEvidenceState::RateLimited),
        (206, nylas::NylasEvidenceState::Partial),
        (500, nylas::NylasEvidenceState::ProviderUnknown),
    ] {
        let provider = nylas::NylasProvider::new(
            scope.clone(),
            secret(),
            nylas::FixtureNylasTransport::new(nylas::NylasResponse::json(
                status,
                &json!({"data": []}),
            )),
        )
        .expect("provider");
        let mut service = nylas::NylasCommunicationResultService::new(provider).expect("service");
        let evidence = service.read(&request).expect("failure evidence");
        assert_eq!(evidence.state, expected);
    }

    let provider = nylas::NylasProvider::new(
        scope.clone(),
        secret(),
        nylas::FixtureNylasTransport::new(nylas::NylasResponse::new(
            200,
            b"not-json".to_vec(),
            nylas::NylasRateLimitReceipt::default(),
        )),
    )
    .expect("tamper provider");
    let mut service =
        nylas::NylasCommunicationResultService::new(provider).expect("tamper service");
    assert_eq!(
        service.read(&request).expect("tamper evidence").state,
        nylas::NylasEvidenceState::Tamper
    );

    let provider = nylas::NylasProvider::new(scope, secret(), nylas::FakeNylasTransport::default())
        .expect("unknown provider");
    let mut service =
        nylas::NylasCommunicationResultService::new(provider).expect("unknown service");
    assert_eq!(
        service.read(&request).expect("unknown evidence").state,
        nylas::NylasEvidenceState::ProviderUnknown
    );
    service.revoke_registration().expect("revoke");
    assert!(matches!(
        service.read(&request),
        Err(nylas::NylasCommunicationResultServiceError::RegistrationRevoked)
    ));
    service.restore_registration().expect("restore");
}
