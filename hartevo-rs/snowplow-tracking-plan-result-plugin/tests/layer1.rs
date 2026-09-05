use hartevo_snowplow_tracking_plan_result_plugin as snowplow;
use serde_json::{Value, json};

fn scope() -> snowplow::SnowplowTrackingPlanScope {
    let spec = snowplow::SnowplowTrackingPlanScopeSpec::new(
        "organization-raw",
        "tracking-plan-raw",
        snowplow::ProjectBinding::new("project-raw", 1).expect("project"),
        snowplow::MissionBinding::new("mission-raw", 2).expect("mission"),
        snowplow::WorkProductBinding::new("work-product-raw", 3).expect("work product"),
        snowplow::SnowplowConsentScope::new("consent-reference-raw", 4).expect("consent"),
    )
    .expect("scope spec");
    snowplow::SnowplowTrackingPlanScope::new(spec).expect("scope")
}

fn secret() -> snowplow::SecretReference {
    snowplow::SecretReference::new("opaque-snowplow-secret-handle", 1).expect("secret")
}

fn plan_record(status: &str, version: u64, event_spec_id: &str) -> Value {
    json!({
        "id": "tracking-plan-raw",
        "name": "Private tracking plan name",
        "description": "private description",
        "status": status,
        "version": version,
        "eventSpecs": [{"id": event_spec_id}]
    })
}

fn event_spec_record(status: &str, version: u64, event_spec_id: &str) -> Value {
    json!({
        "id": event_spec_id,
        "name": "Private event specification name",
        "dataProductId": "tracking-plan-raw",
        "status": status,
        "version": version,
        "event": {
            "source": "iglu:com.example/ui_actions/jsonschema/1-0-0",
            "schema": {
                "type": "object",
                "properties": {"action": {"type": "string"}},
                "additionalProperties": false
            }
        }
    })
}

fn history_record(status: &str, version: u64, event_spec_id: &str) -> Value {
    json!({
        "eventSpecId": event_spec_id,
        "status": status,
        "version": version,
        "date": "2026-08-15T00:00:00Z",
        "author": "private-author-id",
        "message": "private change message",
        "event": {"schema": {"type": "object", "required": ["action"]}}
    })
}

fn responses(status: &str, event_spec_id: &str) -> Vec<snowplow::SnowplowApiResponse> {
    vec![
        snowplow::SnowplowApiResponse::json(
            200,
            &json!({"data": [plan_record(status, 7, event_spec_id)]}),
        ),
        snowplow::SnowplowApiResponse::json(
            200,
            &json!({"data": [event_spec_record("published", 3, event_spec_id)]}),
        ),
        snowplow::SnowplowApiResponse::json(
            200,
            &json!({"data": [history_record("deprecated", 3, event_spec_id)]}),
        ),
    ]
}

fn service_with_fixture(
    status: &str,
) -> snowplow::SnowplowTrackingPlanService<snowplow::FixtureSnowplowTransport> {
    let provider = snowplow::SnowplowProvider::new(
        scope(),
        secret(),
        snowplow::FixtureSnowplowTransport::from_responses(responses(status, "event-spec-raw")),
    )
    .expect("provider");
    snowplow::SnowplowTrackingPlanService::new(provider).expect("service")
}

#[test]
fn contract_is_pinned_and_all_authority_claims_are_false() {
    let contract = snowplow::SnowplowContract::baseline().expect("contract");
    assert_eq!(contract.value()["schemaVersion"], snowplow::CONTRACT_SCHEMA);
    assert_eq!(
        contract.value()["contractVersion"],
        snowplow::CONTRACT_VERSION
    );
    assert_eq!(contract.value()["pluginId"], snowplow::PLUGIN_ID);
    assert_eq!(contract.value()["authority"]["connected"], false);
    assert_eq!(contract.value()["authority"]["native"], false);
    assert_eq!(contract.value()["authority"]["firstParty"], false);
    assert_eq!(contract.value()["authority"]["eventIngestion"], false);
    assert_eq!(contract.value()["allowlist"]["writes"], json!([]));
    assert!(!snowplow::Layer1Authority::connected());
    assert!(!snowplow::Layer1Authority::native());
    assert!(!snowplow::Layer1Authority::first_party());
    assert!(!snowplow::Layer1Authority::external_writes());
}

#[test]
fn scope_secret_request_and_cursor_never_serialize_raw_values() {
    let scope = scope();
    let secret = secret();
    assert!(!format!("{secret:?}").contains("opaque-snowplow-secret-handle"));
    assert!(!format!("{scope:?}").contains("organization-raw"));

    let cursor =
        snowplow::SnowplowCursor::from_opaque("private-provider-cursor", scope.digest(), 2)
            .expect("cursor");
    let cursor_json = serde_json::to_string(&cursor).expect("cursor serializes");
    assert!(!cursor_json.contains("private-provider-cursor"));
    assert!(cursor_json.contains("cursorDigest"));

    let response = snowplow::SnowplowApiResponse::new(
        200,
        br#"{"data":[],"privateTelemetry":"do-not-export"}"#.to_vec(),
        snowplow::SnowplowRateLimitReceipt::default(),
    );
    let serialized_response = serde_json::to_string(&response).expect("response serializes");
    assert!(!serialized_response.contains("do-not-export"));
    assert!(!serialized_response.contains("privateTelemetry"));
    assert_ne!(secret.digest(), "opaque-snowplow-secret-handle");
}

#[test]
fn draft_active_and_archived_statuses_are_normalized_without_claims() {
    for (provider_status, expected) in [
        ("draft", snowplow::SnowplowEvidenceState::Draft),
        ("published", snowplow::SnowplowEvidenceState::Active),
        ("deprecated", snowplow::SnowplowEvidenceState::Archived),
    ] {
        let mut service = service_with_fixture(provider_status);
        let evidence = service.read().expect("evidence");
        assert_eq!(evidence.state, expected);
        assert_eq!(
            evidence.plan.as_ref().expect("plan").status,
            match expected {
                snowplow::SnowplowEvidenceState::Draft => {
                    snowplow::SnowplowTrackingPlanStatus::Draft
                }
                snowplow::SnowplowEvidenceState::Active => {
                    snowplow::SnowplowTrackingPlanStatus::Active
                }
                snowplow::SnowplowEvidenceState::Archived => {
                    snowplow::SnowplowTrackingPlanStatus::Archived
                }
                _ => unreachable!("status test case"),
            }
        );
        assert!(!evidence.connected && !evidence.native && !evidence.first_party);
        assert_eq!(
            evidence.event_specs[0].status,
            snowplow::SnowplowTrackingPlanStatus::Active
        );
        assert_eq!(
            evidence.history[0].status,
            snowplow::SnowplowTrackingPlanStatus::Archived
        );
        evidence.validate_integrity().expect("evidence digest");
    }
}

#[test]
fn schema_and_revision_digests_are_deterministic_and_order_independent() {
    let mut first = service_with_fixture("draft");
    let first_evidence = first.read().expect("first evidence");
    let first_plan = first_evidence.plan.clone().expect("plan");
    let first_event = first_evidence.event_specs[0].clone();
    let first_history = first_evidence.history[0].clone();

    let reordered = vec![
        snowplow::SnowplowApiResponse::json(
            200,
            &json!({"data": [plan_record("draft", 7, "event-spec-raw")]}),
        ),
        snowplow::SnowplowApiResponse::json(
            200,
            &json!({"data": [
                event_spec_record("published", 3, "event-spec-2"),
                event_spec_record("published", 3, "event-spec-raw")
            ]}),
        ),
        snowplow::SnowplowApiResponse::json(
            200,
            &json!({"data": [
                history_record("deprecated", 3, "event-spec-2"),
                history_record("deprecated", 3, "event-spec-raw")
            ]}),
        ),
    ];
    let provider = snowplow::SnowplowProvider::new(
        scope(),
        secret(),
        snowplow::FixtureSnowplowTransport::from_responses(reordered),
    )
    .expect("provider");
    let mut second = snowplow::SnowplowTrackingPlanService::new(provider).expect("service");
    let second_evidence = second.read().expect("second evidence");
    let second_plan = second_evidence.plan.clone().expect("plan");
    let raw_event_digest =
        snowplow::sha256_digest("snowplow-resource-id/v1|event-spec-raw".as_bytes());
    let second_event = second_evidence
        .event_specs
        .iter()
        .find(|event| event.id_digest == raw_event_digest)
        .expect("raw event spec");
    let second_history = second_evidence
        .history
        .iter()
        .find(|history| history.resource_digest == raw_event_digest)
        .expect("raw history");
    assert_eq!(first_plan.schema_digest, second_plan.schema_digest);
    assert_eq!(first_plan.revision_digest, second_plan.revision_digest);
    assert_eq!(first_event.schema_digest, second_event.schema_digest);
    assert_eq!(first_event.revision_digest, second_event.revision_digest);
    assert_eq!(first_history.schema_digest, second_history.schema_digest);
    assert_eq!(
        first_history.revision_digest,
        second_history.revision_digest
    );
}

#[test]
fn page_and_rate_receipts_are_bounded_and_cursors_are_opaque() {
    let first_page = snowplow::SnowplowApiResponse::json_with_rate_limit(
        200,
        &json!({
            "data": [event_spec_record("published", 1, "event-spec-raw")],
            "pagination": {"hasMore": true, "nextCursor": "private-provider-cursor"}
        }),
        snowplow::SnowplowRateLimitReceipt::new(60, Some(59), None, false).expect("rate"),
    );
    let second_page = snowplow::SnowplowApiResponse::json(
        200,
        &json!({
            "data": [event_spec_record("published", 2, "event-spec-2")],
            "pagination": {"hasMore": false}
        }),
    );
    let provider = snowplow::SnowplowProvider::new(
        scope(),
        secret(),
        snowplow::FixtureSnowplowTransport::from_responses([first_page, second_page]),
    )
    .expect("provider");
    let mut provider = provider;
    let first = provider.read_event_specs(1, None).expect("first page");
    let cursor = first.next_cursor.expect("opaque cursor");
    assert!(!format!("{cursor:?}").contains("private-provider-cursor"));
    assert!(
        !serde_json::to_string(&cursor)
            .expect("cursor serializes")
            .contains("private-provider-cursor")
    );
    assert_eq!(first.page_receipt.returned, 1);
    assert!(first.page_receipt.has_more);
    assert!(first.page_receipt.redacted);
    assert_eq!(first.rate_limit.remaining, Some(59));
    let second = provider
        .read_event_specs(1, Some(cursor))
        .expect("second page");
    assert_eq!(second.page_receipt.page_number, 2);
    assert!(!second.page_receipt.has_more);
    assert!(second.request.is_allowlisted());
}

#[test]
fn error_states_cover_missing_access_unknown_tamper_stale_and_blocked_env() {
    for (status_code, expected) in [
        (404, snowplow::SnowplowEvidenceState::Missing),
        (403, snowplow::SnowplowEvidenceState::AccessLoss),
        (500, snowplow::SnowplowEvidenceState::ProviderUnknown),
    ] {
        let response = snowplow::SnowplowApiResponse::new(
            status_code,
            b"{}".to_vec(),
            snowplow::SnowplowRateLimitReceipt::default(),
        );
        let provider = snowplow::SnowplowProvider::new(
            scope(),
            secret(),
            snowplow::FixtureSnowplowTransport::new(response),
        )
        .expect("provider");
        let mut service = snowplow::SnowplowTrackingPlanService::new(provider).expect("service");
        let evidence = service.read().expect("terminal evidence");
        assert_eq!(evidence.state, expected);
        assert!(!evidence.connected && !evidence.native);
    }

    let tampered = snowplow::SnowplowApiResponse::json(
        200,
        &json!({
            "data": [plan_record("draft", 1, "event-spec-raw")],
            "evidenceDigest": "0000000000000000000000000000000000000000000000000000000000000000"
        }),
    );
    let provider = snowplow::SnowplowProvider::new(
        scope(),
        secret(),
        snowplow::FixtureSnowplowTransport::new(tampered),
    )
    .expect("provider");
    let mut service = snowplow::SnowplowTrackingPlanService::new(provider).expect("service");
    let evidence = service.read().expect("tamper evidence");
    assert_eq!(evidence.state, snowplow::SnowplowEvidenceState::Tamper);
    assert!(
        evidence
            .diagnostics
            .contains(&snowplow::SnowplowDiagnostic::Tamper)
    );

    let mut stale_service = service_with_fixture("draft");
    let stale = stale_service
        .read_with_options(&snowplow::SnowplowReadOptions {
            expected_plan_revision: Some(999),
            ..snowplow::SnowplowReadOptions::default()
        })
        .expect("stale evidence");
    assert_eq!(stale.state, snowplow::SnowplowEvidenceState::Stale);

    let provider =
        snowplow::SnowplowProvider::new(scope(), secret(), snowplow::BlockedEnvSnowplowTransport)
            .expect("blocked provider");
    let mut blocked_service =
        snowplow::SnowplowTrackingPlanService::new(provider).expect("service");
    let blocked = blocked_service.read().expect("blocked evidence");
    assert_eq!(blocked.state, snowplow::SnowplowEvidenceState::AccessLoss);
    assert_eq!(
        blocked.provenance,
        snowplow::SnowplowTransportProvenance::BlockedEnv
    );
    assert!(
        blocked
            .diagnostics
            .contains(&snowplow::SnowplowDiagnostic::BlockedEnv)
    );
    assert!(!blocked.connected && !blocked.native && !blocked.first_party);
}

#[test]
fn partial_reads_are_bounded_and_do_not_claim_completeness() {
    let mut queued = responses("draft", "event-spec-raw");
    queued.insert(
        1,
        snowplow::SnowplowApiResponse::json(
            200,
            &json!({
                "data": [event_spec_record("published", 1, "event-spec-raw")],
                "pagination": {"hasMore": true, "nextCursor": "cursor-1"}
            }),
        ),
    );
    queued.insert(
        2,
        snowplow::SnowplowApiResponse::json(
            200,
            &json!({"data": [event_spec_record("published", 2, "event-spec-2")]}),
        ),
    );
    let provider = snowplow::SnowplowProvider::new(
        scope(),
        secret(),
        snowplow::FixtureSnowplowTransport::from_responses(queued),
    )
    .expect("provider");
    let mut service = snowplow::SnowplowTrackingPlanService::new(provider).expect("service");
    let evidence = service
        .read_with_options(&snowplow::SnowplowReadOptions {
            page_size: 1,
            max_pages_per_operation: 1,
            ..snowplow::SnowplowReadOptions::default()
        })
        .expect("partial evidence");
    assert_eq!(evidence.state, snowplow::SnowplowEvidenceState::Partial);
    assert!(evidence.page_receipts.len() <= 8);
    assert!(
        evidence
            .diagnostics
            .contains(&snowplow::SnowplowDiagnostic::PartialPages)
            || evidence
                .diagnostics
                .contains(&snowplow::SnowplowDiagnostic::ProviderUnknown)
    );
    assert!(!evidence.connected && !evidence.native);
}

#[test]
fn proposal_verification_recording_and_mission_consumer_are_replay_safe() {
    let mut service = service_with_fixture("published");
    let proposal = service.compile_proposal().expect("proposal");
    proposal.validate_integrity().expect("proposal digest");
    let verification = service.verify(&proposal).expect("verification");
    assert!(verification.verified);
    assert!(verification.read_only);
    assert!(!verification.connected && !verification.native && !verification.first_party);
    let recorded = service
        .record_observation(&proposal, "observation-key")
        .expect("record");
    assert!(!recorded.replayed);
    let replay = service
        .record_observation(&proposal, "observation-key")
        .expect("replay");
    assert!(replay.replayed);
    assert_eq!(service.record_count(), 1);

    let mut consumer =
        snowplow::MissionSnowplowTrackingPlanConsumer::new(scope(), service.registration().clone())
            .expect("consumer");
    let result = consumer.consume(&proposal).expect("consume");
    assert_eq!(result.consumer_id, snowplow::CONSUMER_ID);
    assert!(result.review_only);
    assert!(!result.can_be_adopted());
    assert!(!result.connected && !result.native && !result.first_party);
    assert!(!result.outcome_adopted && !result.work_product_adopted);
    let first = consumer
        .record(&proposal, "mission-record-key")
        .expect("record");
    let second = consumer
        .record(&proposal, "mission-record-key")
        .expect("replay");
    assert!(!first.replayed);
    assert!(second.replayed);
}

#[test]
fn registration_is_reversible_and_revocation_is_fail_closed() {
    let mut service = service_with_fixture("draft");
    let original = service.registration().registration_digest.clone();
    let receipt = service.revoke().expect("revoke");
    assert_eq!(receipt.previous_registration_digest, original);
    assert_ne!(receipt.registration_digest, original);
    let revoked = service.read().expect("revoked evidence");
    assert_eq!(revoked.state, snowplow::SnowplowEvidenceState::Revoked);
    assert!(matches!(
        service.compile_proposal(),
        Err(snowplow::SnowplowServiceError::RegistrationRevoked)
    ));
    service.restore().expect("restore");
    assert_ne!(service.registration().registration_digest, original);
}

#[test]
fn recording_and_loopback_are_truthful_non_native_provenance() {
    let payload = snowplow::SnowplowApiResponse::json(
        200,
        &json!({"data": [plan_record("draft", 1, "event-spec-raw")]}),
    );
    let recording_provider = snowplow::SnowplowProvider::new(
        scope(),
        secret(),
        snowplow::RecordingSnowplowTransport::new(payload.clone()),
    )
    .expect("recording provider");
    let mut recording_service =
        snowplow::SnowplowTrackingPlanService::new(recording_provider).expect("recording service");
    let recording_evidence = recording_service.read().expect("recording evidence");
    assert_eq!(
        recording_evidence.provenance,
        snowplow::SnowplowTransportProvenance::Recording
    );
    assert!(!recording_evidence.connected && !recording_evidence.native);
    let requests = recording_service.provider().transport().requests();
    assert_eq!(requests.len(), 3);
    let request_json = serde_json::to_string(&requests[0]).expect("request serializes");
    assert!(!request_json.contains("organization-raw"));
    assert!(!request_json.contains("tracking-plan-raw"));
    assert!(!request_json.contains("opaque-snowplow-secret-handle"));

    let loopback_provider = snowplow::SnowplowProvider::new(
        scope(),
        secret(),
        snowplow::LoopbackSnowplowTransport::new(payload),
    )
    .expect("loopback provider");
    let mut loopback_service =
        snowplow::SnowplowTrackingPlanService::new(loopback_provider).expect("loopback service");
    let loopback_evidence = loopback_service.read().expect("loopback evidence");
    assert_eq!(
        loopback_evidence.provenance,
        snowplow::SnowplowTransportProvenance::Loopback
    );
    assert!(!loopback_evidence.connected && !loopback_evidence.native);
}
