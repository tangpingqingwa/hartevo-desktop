use chrono::{DateTime, Utc};
use hartevo_tines_automation_result_plugin as tines;
use serde_json::json;

fn timestamp(value: &str) -> DateTime<Utc> {
    value.parse().expect("valid fixture timestamp")
}

fn scope() -> tines::TinesAutomationScope {
    tines::TinesAutomationScope::new(tines::TinesAutomationScopeSpec {
        tenant: tines::TenantId::new("fixture.tines.io").expect("tenant"),
        story: tines::StoryId::new("7981").expect("story"),
        action: Some(tines::ActionId::new("73563").expect("action")),
        story_run: Some(tines::StoryRunGuid::new("run-5466").expect("story run")),
        event: Some(tines::EventId::new("1785421735").expect("event")),
        case_id: Some(tines::CaseId::new("case-42").expect("case")),
        time_window: tines::TimeWindow::from_rfc3339(
            "2026-08-01T00:00:00Z",
            "2026-08-10T00:00:00Z",
        )
        .expect("time window"),
        project: tines::ProjectBinding::new("project-1", 4).expect("project"),
        mission: tines::MissionBinding::new("mission-1", 5).expect("mission"),
        work_product: tines::WorkProductBinding::new("work-product-1", 6).expect("work product"),
        consent: tines::ConsentScope::new("consent-1", 7, timestamp("2026-08-31T00:00:00Z"))
            .expect("consent"),
        permissions: tines::TinesPermissionSet::read_only(),
    })
    .expect("scope")
}

fn secret() -> tines::SecretReference {
    tines::SecretReference::new("tines-live-token-must-not-escape", 8).expect("secret")
}

fn responses(status: u16) -> tines::RecordingTransport {
    let story = json!({
        "id": 7981,
        "name": "private story name",
        "description": "private story description",
        "mode": "LIVE",
        "published": true,
        "disabled": false,
        "tags": ["private-tag"],
        "owners": ["private-owner"],
        "updated_at": "2026-08-04T12:00:00Z"
    });
    let story_run = json!({
        "story_run": {
            "guid": "run-5466",
            "story_id": 7981,
            "status": "SUCCEEDED",
            "start_time": "2026-08-04T10:00:00Z",
            "end_time": "2026-08-04T10:00:03Z",
            "duration": 3,
            "action_count": 5,
            "event_count": 5
        }
    });
    let action = json!({
        "id": 73563,
        "story_id": 7981,
        "name": "private action name",
        "options": {"secret_input": "private-input"},
        "disabled": false,
        "blended_events_count": 5,
        "last_event_at": "2026-08-04T10:00:03Z",
        "updated_at": "2026-08-04T12:00:00Z"
    });
    let event = json!({
        "id": 1_785_421_735,
        "agent_id": 73563,
        "story_run_guid": "run-5466",
        "payload": {"credential": "private-payload", "case_content": "private-content"},
        "created_at": "2026-08-04T10:00:03Z",
        "updated_at": "2026-08-04T10:00:03Z",
        "re_emitted": false
    });
    let case_summary = json!({
        "case": {
            "id": "case-42",
            "status": "OPEN",
            "content": "private case content",
            "items_count": 2,
            "created_at": "2026-08-04T09:00:00Z",
            "updated_at": "2026-08-04T10:00:00Z"
        }
    });
    let audit_logs = json!({
        "audit_logs": [{
            "id": 19_990_840,
            "created_at": "2026-08-04T11:00:00Z",
            "operation_name": "ActionRun",
            "inputs": {"token": "private-audit-input"},
            "outputs": {"result": "private-audit-output"},
            "request_ip": "192.0.2.44",
            "user_email": "private@example.com",
            "story_id": 7981
        }],
        "meta": {"pages": 1, "per_page": 20, "count": 1}
    });
    tines::RecordingTransport::from_responses([
        (
            tines::TinesReadOperation::GetStory,
            tines::TinesResponse::json(status, &story),
        ),
        (
            tines::TinesReadOperation::GetStoryRunSummary,
            tines::TinesResponse::json(status, &story_run),
        ),
        (
            tines::TinesReadOperation::GetAction,
            tines::TinesResponse::json(status, &action),
        ),
        (
            tines::TinesReadOperation::GetEvent,
            tines::TinesResponse::json(status, &event),
        ),
        (
            tines::TinesReadOperation::GetCase,
            tines::TinesResponse::json(status, &case_summary),
        ),
        (
            tines::TinesReadOperation::ListAuditLogs,
            tines::TinesResponse::json(status, &audit_logs),
        ),
    ])
}

fn service(
    transport: impl tines::TinesTransport,
) -> tines::TinesAutomationResultService<impl tines::TinesTransport> {
    tines::TinesAutomationResultService::new(scope(), secret(), transport).expect("service")
}

fn recording_service() -> tines::TinesAutomationResultService<tines::RecordingTransport> {
    tines::TinesAutomationResultService::new(scope(), secret(), responses(200)).expect("service")
}

#[test]
fn bounded_proposal_is_deterministic_redacted_and_non_native() {
    let mut service = recording_service();
    let proposal = service.compile_proposal().expect("proposal");
    assert_eq!(proposal.state, tines::TinesEvidenceState::Succeeded);
    assert!(proposal.review_only && proposal.non_mutating);
    assert!(!proposal.claims_external_side_effect);
    assert!(!proposal.claims_remediation_success);
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    assert!(!proposal.provider_receipt && !proposal.outcome_adopted);
    assert!(!proposal.can_be_adopted());
    assert_eq!(proposal.evidence.audit_logs.len(), 1);
    assert_eq!(proposal.evidence.pages_read, 1);

    let serialized = serde_json::to_string(&proposal).expect("proposal serializes");
    for forbidden in [
        "tines-live-token-must-not-escape",
        "private story name",
        "private story description",
        "private action name",
        "private-input",
        "private-payload",
        "private-content",
        "private case content",
        "private-audit-input",
        "private-audit-output",
        "private@example.com",
        "192.0.2.44",
    ] {
        assert!(!serialized.contains(forbidden), "leaked {forbidden}");
    }

    let second = service.compile_proposal().expect("deterministic replay");
    assert_eq!(
        proposal.evidence.evidence_digest,
        second.evidence.evidence_digest
    );
    assert_eq!(proposal.proposal_digest, second.proposal_digest);

    let requests = service.provider().transport().requests();
    assert_eq!(requests.len(), 12);
    assert!(requests.iter().all(tines::TinesRequest::is_allowlisted));
    assert!(requests.iter().all(|request| {
        !serde_json::to_string(request)
            .expect("request serializes")
            .contains("tines-live-token-must-not-escape")
    }));
}

#[test]
fn mission_consumer_records_idempotently_without_adoption_authority() {
    let mut service = service(responses(200));
    let proposal = service.compile_proposal().expect("proposal");
    let mut consumer =
        tines::MissionTinesAutomationConsumer::new(scope(), service.registration().clone())
            .expect("consumer");
    let result = consumer.consume(&proposal).expect("consume");
    assert!(result.review_only);
    assert!(!result.connected && !result.native && !result.first_party);
    assert!(!result.outcome_adopted && !result.work_product_adopted);
    assert!(!result.can_be_adopted());

    let first = consumer
        .record(&proposal, "mission-idempotency-1")
        .expect("record");
    let replay = consumer
        .record(&proposal, "mission-idempotency-1")
        .expect("replay");
    assert!(!first.replayed && replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    consumer
        .verify_recording(&replay)
        .expect("recording integrity");
    consumer.readback_seam(&proposal).expect("readback seam");
}

#[test]
fn blocked_env_is_explicit_access_loss_and_never_connected() {
    let mut service = service(tines::BlockedEnvTransport);
    let proposal = service.compile_proposal().expect("blocked proposal");
    assert_eq!(proposal.state, tines::TinesEvidenceState::AccessLost);
    assert_eq!(
        proposal.evidence.classification,
        tines::EvidenceClassification::BlockedEnv
    );
    assert_eq!(
        proposal.evidence.provenance,
        tines::TransportProvenance::BlockedEnv
    );
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
}

#[test]
fn status_matrix_normalizes_access_rate_and_unknown_without_raw_body() {
    for (status, expected) in [
        (403, tines::TinesEvidenceState::AccessLost),
        (404, tines::TinesEvidenceState::AccessLost),
        (500, tines::TinesEvidenceState::ProviderUnknown),
    ] {
        let mut service = service(responses(status));
        let proposal = service.compile_proposal().expect("status proposal");
        assert_eq!(proposal.state, expected);
        assert!(!proposal.connected && !proposal.native && !proposal.first_party);
        assert!(
            !serde_json::to_string(&proposal)
                .expect("status proposal serializes")
                .contains("private")
        );
    }

    let rate_limited = tines::RecordingTransport::new(
        tines::TinesResponse::json(429, &json!({"message": "private rate detail"}))
            .with_retry_after(12),
    );
    let mut service = service(rate_limited);
    let proposal = service.compile_proposal().expect("rate proposal");
    assert_eq!(proposal.state, tines::TinesEvidenceState::RateLimited);
    assert_eq!(
        proposal
            .evidence
            .rate_limit
            .as_ref()
            .and_then(|receipt| receipt.retry_after_seconds),
        Some(12)
    );
}

#[test]
fn registration_revocation_rotation_and_tamper_fences_old_proposals() {
    let mut service = service(responses(200));
    let proposal = service.compile_proposal().expect("proposal");
    let original_registration = service.registration().registration_digest.clone();
    let revoked = service.revoke().expect("revoke");
    assert_eq!(revoked.previous_registration_digest, original_registration);
    assert_ne!(revoked.registration_digest, original_registration);
    assert!(matches!(
        service.read(),
        Err(tines::TinesAutomationResultError::RegistrationInactive)
    ));
    service.restore().expect("restore");
    assert_ne!(
        service.registration().registration_digest,
        original_registration
    );
    assert!(service.verify_proposal(&proposal).is_err());

    let mut tampered = service.compile_proposal().expect("fresh proposal");
    tampered.connected = true;
    assert!(matches!(
        service.verify_proposal(&tampered),
        Err(tines::TinesAutomationResultError::TamperedEvidence)
    ));
}

#[test]
fn stale_scope_and_out_of_window_evidence_fail_closed() {
    let mut original_service = service(responses(200));
    let proposal = original_service.compile_proposal().expect("proposal");
    let other_scope = tines::TinesAutomationScope::new(tines::TinesAutomationScopeSpec {
        story: tines::StoryId::new("other-story").expect("story"),
        ..scope().spec().clone()
    })
    .expect("other scope");
    let consumer = tines::MissionTinesAutomationConsumer::new(
        other_scope,
        original_service.registration().clone(),
    )
    .expect_err("scope mismatch must be rejected");
    let _ = consumer;

    let outside_event = json!({
        "id": 1_785_421_735,
        "agent_id": 73563,
        "story_run_guid": "run-5466",
        "payload": {"secret": "outside"},
        "created_at": "2026-09-01T10:00:03Z",
        "updated_at": "2026-09-01T10:00:03Z"
    });
    let mut outside_transport = responses(200);
    outside_transport.insert(
        tines::TinesReadOperation::GetEvent,
        tines::TinesResponse::json(200, &outside_event),
    );
    let mut outside_service = service(outside_transport);
    assert!(matches!(
        outside_service.read(),
        Err(tines::TinesAutomationResultError::OutOfScopeTime)
    ));
    assert!(
        !serde_json::to_string(&proposal)
            .expect("proposal serializes")
            .contains("outside")
    );
}

#[test]
fn rate_limit_backoff_and_response_bounds_are_enforced() {
    let too_long = tines::RecordingTransport::new(
        tines::TinesResponse::json(429, &json!({"retry": "private"}))
            .with_retry_after(tines::MAX_RETRY_AFTER_SECONDS + 1),
    );
    let mut rate_service = service(too_long);
    assert!(matches!(
        rate_service.read(),
        Err(tines::TinesAutomationResultError::RateLimited { .. })
    ));

    let oversized = tines::RecordingTransport::new(tines::TinesResponse::new(
        200,
        vec![b'x'; tines::MAX_RESPONSE_BYTES + 1],
    ));
    let mut oversized_service = service(oversized);
    assert!(matches!(
        oversized_service.read(),
        Err(tines::TinesAutomationResultError::ResponseTooLarge)
    ));
}

#[test]
fn partial_run_and_pagination_are_explicitly_bounded() {
    let mut partial_transport = responses(200);
    let partial_run = json!({
        "story_run": {
            "guid": "run-5466",
            "story_id": 7981,
            "status": "RUNNING",
            "start_time": "2026-08-04T10:00:00Z",
            "action_count": 5,
            "event_count": 2
        }
    });
    partial_transport.insert(
        tines::TinesReadOperation::GetStoryRunSummary,
        tines::TinesResponse::json(206, &partial_run),
    );
    let mut partial_service = service(partial_transport);
    let partial = partial_service
        .compile_proposal()
        .expect("partial proposal");
    assert_eq!(partial.state, tines::TinesEvidenceState::Partial);
    assert!(partial.evidence.partial);

    let mut paginated_transport = responses(200);
    let paginated_audit = json!({
        "audit_logs": [],
        "meta": {"pages": tines::MAX_PAGES + 1, "per_page": 100, "count": 0}
    });
    paginated_transport.insert(
        tines::TinesReadOperation::ListAuditLogs,
        tines::TinesResponse::json(200, &paginated_audit),
    );
    let mut paginated_service = service(paginated_transport);
    assert!(matches!(
        paginated_service.read(),
        Err(tines::TinesAutomationResultError::PaginationExceeded)
    ));
}

#[test]
fn secret_reference_is_opaque_even_in_debug_and_transport_receipts() {
    let secret = secret();
    let debug = format!("{secret:?}");
    assert!(!debug.contains("tines-live-token-must-not-escape"));
    assert!(debug.contains("<redacted>"));
    let scope = scope();
    let request = tines::TinesRequest::new(&scope, &secret, tines::TinesReadOperation::GetStory, 1)
        .expect("request");
    let serialized = serde_json::to_string(&request).expect("request serializes");
    assert!(!serialized.contains("tines-live-token-must-not-escape"));
    assert!(!serialized.contains("Authorization"));
}
