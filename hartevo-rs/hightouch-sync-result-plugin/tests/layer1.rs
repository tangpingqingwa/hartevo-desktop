use hartevo_hightouch_sync_result_plugin as hightouch;
use serde_json::json;

fn scope() -> hightouch::HightouchSyncScope {
    hightouch::HightouchSyncScope::new(
        "workspace-1",
        "source-1",
        "model-1",
        "sync-1",
        "destination-1",
        "run-1",
        "commit-2026-08-15",
        hightouch::ProjectBinding::new("project-1", 4).expect("project"),
        hightouch::MissionBinding::new("mission-1", 5).expect("mission"),
        hightouch::WorkProductBinding::new("work-product-1", 6).expect("work product"),
    )
    .expect("scope")
}

fn response(run_status: &str) -> hightouch::HightouchResponse {
    hightouch::HightouchResponse::json(
        200,
        &json!({
            "workspace": {"id": "workspace-1", "status": "active", "region": "us"},
            "source": {"id": "source-1", "status": "active", "sourceType": "snowflake", "rows": [{"email": "private@example.test"}]},
            "model": {"id": "model-1", "sourceId": "source-1", "status": "active", "modelType": "sql", "query": "select private from users"},
            "destination": {"id": "destination-1", "status": "active", "destinationType": "salesforce", "configuration": {"token": "destination-secret"}},
            "sync": {"id": "sync-1", "modelId": "model-1", "destinationId": "destination-1", "status": "healthy", "enabled": true},
            "runs": [{"id": "run-1", "status": run_status, "startedAt": "2026-08-15T01:00:00Z", "finishedAt": "2026-08-15T01:01:00Z", "rowsQueried": 100, "rowsAdded": 60, "rowsChanged": 20, "rowsRemoved": 10, "rowsRejected": 0, "errorMessage": "private provider detail"}],
            "nextCursor": null,
            "rawSourceRows": [{"id": "row-1", "email": "private@example.test"}]
        }),
    )
    .expect("response")
}

fn secret(scope: &hightouch::HightouchSyncScope) -> hightouch::SecretReference {
    hightouch::SecretReference::api_key("opaque-api-key-handle", scope, 9).expect("secret")
}

fn service_with_fixture(
    run_status: &str,
) -> hightouch::HightouchSyncResultService<hightouch::FixtureHightouchTransport> {
    let scope = scope();
    let provider = hightouch::HightouchProvider::new(
        scope.clone(),
        secret(&scope),
        hightouch::FixtureHightouchTransport::new(response(run_status)),
    )
    .expect("provider");
    hightouch::HightouchSyncResultService::new(provider).expect("service")
}

fn recording_service(
    responses: impl IntoIterator<Item = hightouch::HightouchResponse>,
) -> (
    hightouch::HightouchSyncResultService<hightouch::RecordingHightouchTransport>,
    hightouch::RecordingHightouchTransport,
) {
    let scope = scope();
    let transport = hightouch::RecordingHightouchTransport::new(responses);
    let provider =
        hightouch::HightouchProvider::new(scope.clone(), secret(&scope), transport.clone())
            .expect("provider");
    (
        hightouch::HightouchSyncResultService::new(provider).expect("service"),
        transport,
    )
}

#[test]
fn contract_is_machine_checked_and_layer_one_authority_is_false() {
    hightouch::validate_contract().expect("contract");
    assert_eq!(hightouch::HIGHTOUCH_BLOCKED_ENV, "BLOCKED_ENV");
    assert_eq!(hightouch::contract_digest().as_str().len(), 64);
    assert_eq!(hightouch::provider_digest().as_str().len(), 64);
    assert!(!hightouch::Layer1Authority::connected());
    assert!(!hightouch::Layer1Authority::native_provider());
    assert!(!hightouch::Layer1Authority::external_writes());
    assert!(!hightouch::Layer1Authority::sync_effects());
    assert!(!hightouch::Layer1Authority::destination_writes());
    assert!(!hightouch::Layer1Authority::source_rows());
    assert!(!hightouch::Layer1Authority::raw_credentials());
    assert!(!hightouch::Layer1Authority::outcome_authority());
}

#[test]
fn successful_sync_result_is_bounded_redacted_and_deterministic() {
    let mut service = service_with_fixture("completed");
    let proposal = service.compile_proposal().expect("proposal");
    assert_eq!(
        proposal.evidence.state,
        hightouch::HightouchEvidenceState::Succeeded
    );
    assert!(proposal.recommendation.non_mutating);
    assert!(proposal.recommendation.provider_reported_only);
    assert!(!proposal.connected && !proposal.native);
    assert!(!proposal.outcome_adopted && !proposal.work_product_adopted);

    let encoded = serde_json::to_string(&proposal).expect("proposal serializes");
    for forbidden in [
        "opaque-api-key-handle",
        "private@example.test",
        "destination-secret",
        "private provider detail",
        "rawSourceRows",
        "opaque-next-cursor",
        "project-1",
        "mission-1",
        "work-product-1",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "serialized proposal leaked {forbidden}"
        );
    }

    let second = service.compile_proposal().expect("deterministic proposal");
    assert_eq!(proposal.evidence.digest(), second.evidence.digest());
    assert_eq!(proposal.digest(), second.digest());
    assert_eq!(proposal.evidence.runs.len(), 1);
    assert_eq!(proposal.evidence.runs[0].queried_rows, Some(100));
}

#[test]
fn all_resource_reads_are_get_only_and_recorded_without_raw_paths() {
    let item = response("completed");
    let (mut service, transport) = recording_service(vec![item; 6]);
    let _ = service.read().expect("metadata read");
    let requests = transport.requests();
    assert_eq!(requests.len(), 6);
    assert!(
        requests
            .iter()
            .all(|request| request.is_get() && request.is_allowlisted())
    );
    assert!(
        requests
            .iter()
            .any(|request| request.operation == hightouch::HightouchOperation::ListRuns)
    );
    let encoded = serde_json::to_string(&requests).expect("requests serialize");
    assert!(!encoded.contains("workspace-1"));
    assert!(!encoded.contains("/syncs/sync-1/runs"));
}

#[test]
fn blocked_env_is_denied_and_never_connected_or_native() {
    let scope = scope();
    let provider = hightouch::HightouchProvider::new(
        scope.clone(),
        secret(&scope),
        hightouch::BlockedEnvHightouchTransport,
    )
    .expect("provider");
    let mut service = hightouch::HightouchSyncResultService::new(provider).expect("service");
    let evidence = service.read().expect("blocked evidence");
    assert_eq!(evidence.state, hightouch::HightouchEvidenceState::Denied);
    assert_eq!(
        evidence.classification,
        hightouch::HightouchEvidenceClassification::BlockedEnv
    );
    assert_eq!(
        evidence.provenance,
        hightouch::TransportProvenance::BlockedEnv
    );
    assert!(!evidence.connected && !evidence.native);
    assert!(
        !serde_json::to_string(&evidence)
            .expect("evidence serializes")
            .contains("native Hightouch credentials")
    );
}

#[test]
fn registration_revoke_restore_rotates_digest_and_rejects_old_proposals() {
    let mut service = service_with_fixture("completed");
    let original = service.registration().registration_digest.clone();
    let proposal = service.compile_proposal().expect("proposal");
    let revoked = service.revoke_registration().expect("revoke");
    assert_eq!(revoked.previous_registration_digest, original);
    assert_ne!(revoked.registration_digest, original);
    assert!(matches!(
        service.read(),
        Err(hightouch::HightouchSyncResultServiceError::RegistrationRevoked)
    ));
    let restored = service.restore_registration().expect("restore");
    assert_ne!(restored.registration_digest, original);
    assert!(matches!(
        service.verify_proposal(&proposal),
        Err(
            hightouch::HightouchSyncResultServiceError::RegistrationRevoked
                | hightouch::HightouchSyncResultServiceError::EvidenceMismatch
        )
    ));
}

#[test]
fn mission_consumer_rejects_replay_and_records_idempotently() {
    let scope = scope();
    let provider = hightouch::HightouchProvider::new(
        scope.clone(),
        secret(&scope),
        hightouch::FixtureHightouchTransport::new(response("completed")),
    )
    .expect("provider");
    let mut consumer = hightouch::MissionHightouchSyncConsumer::new(provider).expect("consumer");
    let proposal = consumer.compile_proposal().expect("proposal");
    let result = consumer.consume(&proposal).expect("consume");
    assert_eq!(
        result.state,
        hightouch::MissionHightouchSyncResultState::DecisionReady
    );
    assert!(result.proposal_only && !result.native && !result.connected);
    assert!(matches!(
        consumer.consume(&proposal),
        Err(hightouch::MissionHightouchSyncConsumerError::ReplayDetected)
    ));
    let first = consumer
        .record(&proposal, "mission-record-1")
        .expect("record");
    assert!(!first.replayed && !first.receipt.replayed);
    let replay = consumer
        .record(&proposal, "mission-record-1")
        .expect("replay");
    assert!(replay.replayed && replay.receipt.replayed);
    replay.receipt.validate_integrity().expect("receipt");
}

#[test]
fn pagination_cursor_and_rate_limit_backoff_are_bounded_and_redacted() {
    let first = response("completed");
    let page_one = hightouch::HightouchResponse::json(
        200,
        &json!({"runs": [{"id": "run-1", "status": "running", "rowsQueried": 2}], "nextCursor": "opaque-next-cursor"}),
    )
    .expect("page one");
    let page_two = hightouch::HightouchResponse::json(
        200,
        &json!({"runs": [{"id": "run-1", "status": "completed", "rowsQueried": 100}], "nextCursor": null}),
    )
    .expect("page two");
    let (mut service, transport) = recording_service(vec![
        first.clone(),
        first.clone(),
        first.clone(),
        first.clone(),
        first,
        page_one,
        page_two,
    ]);
    let evidence = service.read().expect("paginated read");
    assert_eq!(evidence.page_count, 2);
    assert_eq!(evidence.cursor_digests.len(), 1);
    assert!(evidence.backoff.is_none());
    assert!(
        !serde_json::to_string(&evidence)
            .expect("evidence")
            .contains("opaque-next-cursor")
    );
    assert_eq!(transport.requests().len(), 7);

    let rate_limited = hightouch::HightouchResponse::json(
        429,
        &json!({"retryAfterSeconds": 7, "private": "provider detail"}),
    )
    .expect("rate limit");
    let success = response("completed");
    let mut responses = vec![success.clone(); 5];
    responses.push(rate_limited);
    responses.push(success);
    let (mut rate_service, _) = recording_service(responses);
    let rate_evidence = rate_service.read().expect("bounded retry");
    assert!(rate_evidence.backoff.is_some());
    assert_eq!(
        rate_evidence.state,
        hightouch::HightouchEvidenceState::Succeeded
    );
}

#[test]
fn partial_and_access_loss_are_non_adoptable() {
    let mut partial_service = service_with_fixture("partial");
    let partial = partial_service
        .compile_proposal()
        .expect("partial proposal");
    assert_eq!(
        partial.evidence.state,
        hightouch::HightouchEvidenceState::Partial
    );
    assert_eq!(
        partial.evidence.classification,
        hightouch::HightouchEvidenceClassification::Partial
    );
    assert!(!partial.recommendation.claims_delivery_truth);

    let denied = hightouch::HightouchResponse::json(403, &json!({"error": "access lost"}))
        .expect("denied response");
    let (mut denied_service, _) = recording_service([denied]);
    let denied = denied_service.read().expect("denied evidence");
    assert_eq!(denied.state, hightouch::HightouchEvidenceState::Denied);
    assert_eq!(
        denied.classification,
        hightouch::HightouchEvidenceClassification::Denied
    );
    assert_eq!(
        denied.failure.as_ref().and_then(|value| value.status_code),
        Some(403)
    );
    assert!(denied.proposal_only && !denied.connected && !denied.native);
}

#[test]
fn tamper_scope_revision_and_secret_redaction_fail_closed() {
    let tampered = response("completed")
        .with_declared_response_digest(hightouch::Digest::from_text("not-the-response-digest"));
    let scope = scope();
    let provider = hightouch::HightouchProvider::new(
        scope.clone(),
        secret(&scope),
        hightouch::FixtureHightouchTransport::new(tampered),
    )
    .expect("provider");
    let mut service = hightouch::HightouchSyncResultService::new(provider).expect("service");
    let evidence = service.read().expect("tampered evidence");
    assert_eq!(evidence.state, hightouch::HightouchEvidenceState::Tampered);

    assert!(scope.clone().with_revisions(0, 1, 1, 1, 1, 1, 1).is_err());
    let wrong_cursor =
        hightouch::HightouchCursor::for_scope("opaque-cursor", &scope).expect("cursor");
    assert!(wrong_cursor.validate_for_scope(&scope).is_ok());
    let unbound_cursor =
        hightouch::HightouchCursor::from_token("opaque-cursor").expect("unbound cursor");
    assert!(unbound_cursor.validate_for_scope(&scope).is_err());
    let encoded_cursor = serde_json::to_string(&wrong_cursor).expect("cursor");
    assert!(!encoded_cursor.contains("opaque-cursor"));
    assert!(!format!("{:?}", secret(&scope)).contains("opaque-api-key-handle"));
}
