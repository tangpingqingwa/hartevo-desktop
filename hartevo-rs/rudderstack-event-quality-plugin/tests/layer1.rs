use std::collections::BTreeMap;

use hartevo_rudderstack_event_quality_plugin as rudderstack;
use serde_json::json;

fn scope() -> rudderstack::RudderStackScope {
    rudderstack::RudderStackScope::new(
        rudderstack::OrganizationScope::new("org-1", 1).expect("organization"),
        rudderstack::WorkspaceScope::new("workspace-1", 1).expect("workspace"),
        rudderstack::SourceScope::new("source-1", 1).expect("source"),
        Some(rudderstack::DestinationScope::new("destination-1", 1).expect("destination")),
        Some(rudderstack::TrackingPlanScope::new("plan-1", 1).expect("tracking plan")),
        rudderstack::ViolationScope::all(1).expect("violation scope"),
        rudderstack::ProjectScope::new("project-1", 1).expect("project"),
        rudderstack::MissionScope::new("mission-1", 1).expect("mission"),
        rudderstack::WorkProductScope::new("work-product-1", 1).expect("work product"),
        rudderstack::DateWindow::new("2026-08-01", "2026-08-07").expect("window"),
        rudderstack::RudderStackPermissionSet::least_privilege(1).expect("permissions"),
        rudderstack::PrivacyPolicy::strict_v1(),
    )
    .expect("scope")
}

fn secret() -> rudderstack::SecretReference {
    rudderstack::SecretReference::api_token("opaque-api-token-handle", 1).expect("secret")
}

fn source_metadata() -> rudderstack::RudderStackSourceMetadata {
    rudderstack::RudderStackSourceMetadata::new(
        "source-1",
        1,
        rudderstack::SourceType::Server,
        rudderstack::SourceState::Enabled,
        4,
        1,
        1,
    )
    .expect("source metadata")
}

fn tracking_plan(reversed: bool) -> rudderstack::RudderStackTrackingPlanVersion {
    let event_names = if reversed {
        vec!["Order Completed".to_owned(), "Checkout Started".to_owned()]
    } else {
        vec!["Checkout Started".to_owned(), "Order Completed".to_owned()]
    };
    let properties = if reversed {
        vec!["currency".to_owned(), "total".to_owned()]
    } else {
        vec!["total".to_owned(), "currency".to_owned()]
    };
    rudderstack::RudderStackTrackingPlanVersion::new(
        "plan-1",
        3,
        1,
        rudderstack::TrackingPlanState::Published,
        event_names,
        properties,
    )
    .expect("tracking plan version")
}

fn violations(reversed: bool) -> Vec<rudderstack::RudderStackSchemaViolationAggregate> {
    let first = rudderstack::RudderStackSchemaViolationAggregate::new(
        rudderstack::SchemaViolationKind::DatatypeMismatch,
        Some("Order Completed".to_owned()),
        Some("total".to_owned()),
        Some("plan-1".to_owned()),
        Some(3),
        2,
    )
    .expect("datatype violation");
    let second = rudderstack::RudderStackSchemaViolationAggregate::for_event(
        rudderstack::SchemaViolationKind::UnplannedEvent,
        "Checkout Started",
        1,
    )
    .expect("unplanned event");
    if reversed {
        vec![second, first]
    } else {
        vec![first, second]
    }
}

fn governance_metrics() -> rudderstack::RudderStackGovernanceMetrics {
    let mut counts = BTreeMap::new();
    counts.insert(rudderstack::SchemaViolationKind::DatatypeMismatch, 2);
    counts.insert(rudderstack::SchemaViolationKind::UnplannedEvent, 1);
    rudderstack::RudderStackGovernanceMetrics::new(
        rudderstack::DateWindow::new("2026-08-01", "2026-08-07").expect("window"),
        100,
        3,
        1,
        99,
        98,
        1,
        counts,
    )
    .expect("governance metrics")
}

fn delivery_health() -> Vec<rudderstack::RudderStackDeliveryHealthAggregate> {
    let value =
        rudderstack::RudderStackDeliveryHealthAggregate::new("destination-1", 1, 98, 1, 2, 1)
            .expect("delivery health");
    vec![value]
}

fn response(reversed: bool) -> rudderstack::RudderStackResponse {
    rudderstack::RudderStackResponse::complete(
        Some(source_metadata()),
        vec![tracking_plan(reversed)],
        violations(reversed),
        delivery_health(),
        Some(governance_metrics()),
    )
}

fn service_with<T: rudderstack::RudderStackTransport>(
    transport: T,
) -> rudderstack::RudderStackEventQualityService<T> {
    let provider =
        rudderstack::RudderStackProvider::new(scope(), secret(), transport).expect("provider");
    rudderstack::RudderStackEventQualityService::new(provider).expect("service")
}

#[test]
fn complete_fixture_is_aggregate_only_and_deterministic() {
    let mut first = service_with(rudderstack::FixtureRudderStackTransport::new(response(
        false,
    )));
    let mut second = service_with(rudderstack::FixtureRudderStackTransport::new(response(
        true,
    )));
    let evidence = first.read().expect("first evidence");
    let reordered = second.read().expect("reordered evidence");

    assert_eq!(evidence.state, rudderstack::EvidenceState::Complete);
    assert_eq!(evidence.evidence_digest, reordered.evidence_digest);
    assert_eq!(evidence.digest(), reordered.digest());
    assert!(evidence.is_usable());
    assert!(!evidence.connected && !evidence.native && !evidence.first_party);
    assert_eq!(evidence.violations.len(), 2);
    assert_eq!(evidence.tracking_plan_versions[0].version, 3);
    assert!(evidence.validate_digest().is_ok());

    let serialized = serde_json::to_string(&evidence).expect("evidence serializes");
    assert!(!serialized.contains("Checkout Started"));
    assert!(!serialized.contains("Order Completed"));
    assert!(!serialized.contains("total"));
    assert!(!serialized.contains("opaque-api-token-handle"));
}

#[test]
fn request_allowlist_and_recording_transport_never_retain_secrets_or_payloads() {
    let transport = rudderstack::RecordingRudderStackTransport::new(response(false));
    let mut service = service_with(transport.clone());
    let evidence = service.read().expect("recorded evidence");
    assert_eq!(evidence.state, rudderstack::EvidenceState::Complete);

    let requests = transport.requests();
    assert_eq!(requests.len(), 5);
    assert!(
        requests
            .iter()
            .all(rudderstack::RudderStackRequest::is_allowlisted)
    );
    assert!(
        requests
            .iter()
            .all(|request| request.method == rudderstack::RudderStackHttpMethod::Get)
    );
    let serialized = serde_json::to_string(&requests).expect("requests serialize");
    assert!(!serialized.contains("opaque-api-token-handle"));
    assert!(!serialized.contains("Checkout Started"));
}

#[test]
fn blocked_env_is_access_lost_and_negative_about_native_authority() {
    let mut service = service_with(rudderstack::BlockedEnvRudderStackTransport);
    let evidence = service.read().expect("blocked evidence");
    assert_eq!(evidence.state, rudderstack::EvidenceState::AccessLost);
    assert_eq!(
        evidence.classification,
        rudderstack::EvidenceClassification::BlockedEnv
    );
    assert_eq!(
        evidence.provenance,
        rudderstack::TransportProvenance::BlockedEnv
    );
    assert!(!evidence.connected && !evidence.native && !evidence.first_party);
    assert!(!rudderstack::Layer1Authority::connected());
    assert!(!rudderstack::Layer1Authority::native_provider());
    assert!(!rudderstack::Layer1Authority::first_party());
}

#[test]
fn status_matrix_is_normalized_without_fabricating_success() {
    for (status, expected) in [
        (401, rudderstack::EvidenceState::AccessLost),
        (403, rudderstack::EvidenceState::AccessLost),
        (429, rudderstack::EvidenceState::RateLimited),
        (500, rudderstack::EvidenceState::ProviderUnknown),
    ] {
        let mut service = service_with(rudderstack::FixtureRudderStackTransport::new(
            rudderstack::RudderStackResponse::with_status(status),
        ));
        let evidence = service.read().expect("status evidence");
        assert_eq!(evidence.state, expected);
        assert!(!evidence.connected && !evidence.native && !evidence.first_party);
        assert!(evidence.source_metadata.is_none());
    }
}

#[test]
fn partial_empty_access_and_tamper_states_are_explicit() {
    let mut partial = service_with(rudderstack::FixtureRudderStackTransport::new(
        rudderstack::RudderStackResponse::with_status(206),
    ));
    assert_eq!(
        partial.read().expect("partial evidence").state,
        rudderstack::EvidenceState::Partial
    );

    let mut empty = service_with(rudderstack::FixtureRudderStackTransport::new(
        rudderstack::RudderStackResponse::empty(204),
    ));
    assert_eq!(
        empty.read().expect("empty evidence").state,
        rudderstack::EvidenceState::Empty
    );

    let tampered = rudderstack::RudderStackResponse::builder(200)
        .source_metadata(Some(source_metadata()))
        .declared_response_digest(rudderstack::Digest::from_text("tampered-response"))
        .build();
    let mut tampered_service =
        service_with(rudderstack::FixtureRudderStackTransport::new(tampered));
    assert_eq!(
        tampered_service.read().expect("tamper evidence").state,
        rudderstack::EvidenceState::Tamper
    );
}

#[test]
fn stale_revisions_and_oversized_responses_fail_closed() {
    let stale_source = rudderstack::RudderStackSourceMetadata::new(
        "source-1",
        2,
        rudderstack::SourceType::Server,
        rudderstack::SourceState::Enabled,
        1,
        0,
        0,
    )
    .expect("stale fixture");
    let mut stale_service = service_with(rudderstack::FixtureRudderStackTransport::new(
        rudderstack::RudderStackResponse::complete(
            Some(stale_source),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
        ),
    ));
    assert_eq!(
        stale_service.read().expect("stale evidence").state,
        rudderstack::EvidenceState::Stale
    );

    let oversized = rudderstack::RudderStackResponse::builder(200)
        .reported_response_bytes(rudderstack::RUDDERSTACK_MAX_RESPONSE_BYTES + 1)
        .build();
    let mut oversized_service =
        service_with(rudderstack::FixtureRudderStackTransport::new(oversized));
    assert_eq!(
        oversized_service.read().expect("oversized evidence").state,
        rudderstack::EvidenceState::ProviderUnknown
    );
    assert!(
        rudderstack::RateLimitReceipt::new(
            rudderstack::RUDDERSTACK_MAX_REQUESTS_PER_MINUTE + 1,
            None,
            None,
            false,
        )
        .is_err()
    );
}

#[test]
fn registration_is_reversible_and_old_proposals_are_fenced() {
    let mut service = service_with(rudderstack::FixtureRudderStackTransport::new(response(
        false,
    )));
    let proposal = service.compile_proposal().expect("proposal");
    assert!(service.verify_proposal(&proposal).is_ok());
    let original = service.registration().registration_digest.clone();

    let revoked = service.revoke_registration().expect("revoke");
    assert_eq!(revoked.previous_registration_digest, original);
    assert_ne!(revoked.registration_digest, original);
    assert!(matches!(
        service.compile_proposal(),
        Err(rudderstack::RudderStackEventQualityServiceError::RegistrationRevoked)
    ));

    let restored = service.restore_registration().expect("restore");
    assert_ne!(restored.registration_digest, original);
    assert!(service.verify_proposal(&proposal).is_err());
    let fresh = service.compile_proposal().expect("fresh proposal");
    assert_ne!(fresh.proposal_digest, proposal.proposal_digest);
}

#[test]
fn mission_consumer_rejects_replay_and_only_projects_proposals() {
    let provider = rudderstack::RudderStackProvider::new(
        scope(),
        secret(),
        rudderstack::FixtureRudderStackTransport::new(response(false)),
    )
    .expect("provider");
    let mut consumer =
        rudderstack::MissionRudderStackEventConsumer::new(provider).expect("consumer");
    let proposal = consumer.compile_proposal().expect("proposal");
    let result = consumer.consume(&proposal).expect("consume");
    assert_eq!(result.state, rudderstack::MissionResultState::DecisionReady);
    assert!(result.proposal_only);
    assert!(!result.connected && !result.native && !result.first_party);
    assert!(!result.adopts_outcome && !result.truth_authority);
    assert!(matches!(
        consumer.consume(&proposal),
        Err(rudderstack::MissionRudderStackEventConsumerError::ReplayDetected)
    ));
}

#[test]
fn cursor_and_rate_receipts_keep_only_digests() {
    let request_digest = rudderstack::Digest::from_text("request");
    let cursor = rudderstack::CursorReceipt::from_opaque(
        Some("raw-provider-cursor"),
        1,
        50,
        true,
        request_digest.clone(),
    )
    .expect("cursor");
    assert!(
        !serde_json::to_string(&cursor)
            .expect("cursor serializes")
            .contains("raw-provider-cursor")
    );
    let rate = rudderstack::RateLimitReceipt::new(60, Some(59), None, false).expect("rate");
    let response = rudderstack::RudderStackResponse::builder(200)
        .cursor(Some(cursor))
        .rate_limit(rate)
        .build();
    let mut service = service_with(rudderstack::FixtureRudderStackTransport::new(response));
    let evidence = service.read().expect("cursor evidence");
    assert!(!evidence.cursor_receipts.is_empty());
    assert!(
        !serde_json::to_string(&evidence)
            .expect("evidence serializes")
            .contains("raw-provider-cursor")
    );
}

#[test]
fn proposal_record_and_verification_are_non_native() {
    let mut service = service_with(rudderstack::FixtureRudderStackTransport::new(response(
        false,
    )));
    let proposal = service.compile_proposal().expect("proposal");
    let verification = service.verify(&proposal).expect("verification");
    let receipt = service.record(&proposal).expect("record");
    let readback = service.read_back(&proposal).expect("typed readback");
    assert!(verification.verified);
    assert!(receipt.recorded);
    assert!(!receipt.durable && !receipt.native && !receipt.connected);
    assert!(!readback.independent_native_readback);
    assert!(!readback.native && !readback.connected && !readback.first_party);
    let serialized = serde_json::to_string(&proposal).expect("proposal serializes");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&serialized).unwrap()["proposalOnly"],
        json!(true)
    );
    assert!(!serialized.contains("opaque-api-token-handle"));
}
