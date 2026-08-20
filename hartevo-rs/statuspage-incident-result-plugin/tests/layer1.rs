use hartevo_statuspage_incident_result_plugin as statuspage;
use serde_json::json;

fn scope() -> statuspage::StatuspageIncidentResultScope {
    let spec = statuspage::StatuspageIncidentResultScopeSpec::new(
        statuspage::OrganizationBinding::new("org-1", 1).expect("organization"),
        statuspage::PageBinding::new("page-1", 2).expect("page"),
        vec![statuspage::ComponentBinding::new("comp-1", 3).expect("component")],
        vec![statuspage::ComponentGroupBinding::new("group-1", 4).expect("group")],
        statuspage::TimeWindow::new("2026-08-01T00:00:00Z", "2026-08-07T23:59:59Z", 5)
            .expect("window"),
        statuspage::ProjectBinding::new("project-1", 6).expect("project"),
        statuspage::MissionBinding::new("mission-1", 7).expect("mission"),
        statuspage::WorkProductBinding::new("work-product-1", 8).expect("work product"),
        statuspage::ConsentScope::new("consent-1", 9).expect("consent"),
        statuspage::StatuspageAcl::read_only(10).expect("permissions"),
    );
    statuspage::StatuspageIncidentResultScope::new(spec).expect("scope")
}

fn secret() -> statuspage::SecretReference {
    statuspage::SecretReference::new("host-keyring-statuspage-token", 11).expect("secret")
}

fn fixture_payload(include_maintenance: bool) -> serde_json::Value {
    json!({
        "page": {
            "id": "page-1",
            "name": "Private Status Page",
            "url": "https://private.example.test/status",
            "time_zone": "UTC",
            "updated_at": "2026-08-07T10:00:00Z"
        },
        "components": [{
            "id": "comp-1",
            "page_id": "page-1",
            "group_id": "group-1",
            "name": "Payments API",
            "status": "partial_outage",
            "description": "internal component description",
            "automation_email": "ops@example.test",
            "updated_at": "2026-08-02T10:00:00Z"
        }],
        "component_groups": [{
            "id": "group-1",
            "page_id": "page-1",
            "name": "Private API Group",
            "components": ["comp-1"],
            "updated_at": "2026-08-02T10:00:00Z"
        }],
        "incidents": [{
            "id": "incident-1",
            "page_id": "page-1",
            "name": "Database migration incident",
            "status": "investigating",
            "impact": "major",
            "created_at": "2026-08-02T09:00:00Z",
            "updated_at": "2026-08-02T10:00:00Z",
            "components": [{"id": "comp-1", "name": "Payments API"}],
            "postmortem_body": "private postmortem",
            "metadata": {"internal": "do not export"},
            "incident_updates": [{
                "id": "update-1",
                "incident_id": "incident-1",
                "status": "identified",
                "body": "private incident narrative",
                "created_at": "2026-08-02T10:00:00Z",
                "display_at": "2026-08-02T10:00:00Z",
                "affected_components": [{
                    "code": "comp-1",
                    "name": "Payments API",
                    "old_status": "operational",
                    "new_status": "partial_outage"
                }],
                "subscriber": "someone@example.test"
            }]
        }],
        "scheduled_maintenances": if include_maintenance { json!([{
            "id": "maintenance-1",
            "page_id": "page-1",
            "status": "scheduled",
            "scheduled_for": "2026-08-05T12:00:00Z",
            "scheduled_until": "2026-08-05T13:00:00Z",
            "components": [{"id": "comp-1"}],
            "incident_updates": []
        }]) } else { json!([]) },
        "internal_notes": "must never cross the provider boundary"
    })
}

#[allow(clippy::needless_pass_by_value)]
fn service_with(
    status: u16,
    payload: serde_json::Value,
) -> statuspage::StatuspageIncidentResultService<statuspage::FixtureStatuspageTransport> {
    let response = statuspage::StatuspageResponse::json(status, &payload);
    let provider = statuspage::StatuspageProvider::new(
        scope(),
        secret(),
        statuspage::FixtureStatuspageTransport::new(response),
    )
    .expect("provider");
    statuspage::StatuspageIncidentResultService::new(provider).expect("service")
}

#[test]
fn proposal_is_bounded_redacted_and_deterministic() {
    let mut service = service_with(200, fixture_payload(true));
    let proposal = service.compile_proposal().expect("proposal");
    assert_eq!(proposal.state(), statuspage::EvidenceState::Maintenance);
    assert_eq!(
        proposal.recommendation.disposition,
        statuspage::RecommendationDisposition::ReviewMaintenance
    );
    assert!(proposal.recommendation.non_mutating);
    assert!(proposal.recommendation.provider_reported_only);
    assert!(!proposal.recommendation.claims_customer_wide_uptime);
    assert!(!proposal.recommendation.claims_causality);
    assert!(!proposal.recommendation.claims_remediation);
    assert!(!proposal.recommendation.claims_business_outcome);
    assert!(!proposal.native && !proposal.connected && !proposal.first_party);
    assert!(!proposal.evidence.native && !proposal.evidence.connected);

    let serialized = serde_json::to_string(&proposal).expect("proposal serializes");
    assert!(!serialized.contains("host-keyring-statuspage-token"));
    assert!(!serialized.contains("Private Status Page"));
    assert!(!serialized.contains("private incident narrative"));
    assert!(!serialized.contains("private postmortem"));
    assert!(!serialized.contains("someone@example.test"));
    assert!(!serialized.contains("internal component description"));
    assert!(!serialized.contains("do not export"));

    let second = service.compile_proposal().expect("deterministic proposal");
    assert_eq!(proposal.evidence.digest(), second.evidence.digest());
    assert_eq!(proposal.digest(), second.digest());
}

#[test]
fn allowlisted_reads_are_get_only_and_digest_bound() {
    let provider = statuspage::StatuspageProvider::new(
        scope(),
        secret(),
        statuspage::RecordingStatuspageTransport::new(statuspage::StatuspageResponse::json(
            200,
            &fixture_payload(false),
        )),
    )
    .expect("provider");
    let mut service = statuspage::StatuspageIncidentResultService::new(provider).expect("service");
    let _ = service.read().expect("read");
    let requests = service.provider().transport().requests();
    assert_eq!(requests.len(), 5);
    assert_eq!(requests[0].path, "/pages/page-1");
    assert_eq!(requests[1].path, "/pages/page-1/components");
    assert_eq!(requests[2].path, "/pages/page-1/component-groups");
    assert_eq!(requests[3].path, "/pages/page-1/incidents");
    assert_eq!(requests[4].path, "/pages/page-1/incidents/scheduled");
    assert!(
        requests
            .iter()
            .all(statuspage::StatuspageRequest::is_allowlisted)
    );
    assert!(requests.iter().all(|request| {
        let serialized = serde_json::to_string(request).expect("request serializes");
        !serialized.contains("host-keyring-statuspage-token")
    }));
}

#[test]
fn statuses_are_normalized_and_unknown_values_do_not_become_authority() {
    let payload = json!({
        "page": {"id": "page-1"},
        "components": [{"id": "comp-1", "page_id": "page-1", "status": "new_provider_status"}],
        "component_groups": [],
        "incidents": [{
            "id": "incident-unknown",
            "page_id": "page-1",
            "status": "new_provider_status",
            "impact": "new_impact",
            "created_at": "2026-08-03T00:00:00Z",
            "components": ["comp-1"],
            "incident_updates": []
        }],
        "scheduled_maintenances": []
    });
    let mut service = service_with(200, payload);
    let evidence = service.read().expect("normalized evidence");
    assert_eq!(evidence.state, statuspage::EvidenceState::Complete);
    let result = evidence.result.expect("result");
    assert_eq!(
        result.incidents[0].status,
        statuspage::IncidentStatus::ProviderUnknown
    );
    assert_eq!(
        result.components[0].status,
        statuspage::ComponentStatus::ProviderUnknown
    );
    assert_eq!(
        result.incidents[0].impact,
        statuspage::IncidentImpact::ProviderUnknown
    );
}

#[test]
fn status_matrix_and_blocked_env_are_typed_and_disconnected() {
    for (status, expected) in [
        (420, statuspage::EvidenceState::RateLimited),
        (429, statuspage::EvidenceState::RateLimited),
        (401, statuspage::EvidenceState::AccessLost),
        (403, statuspage::EvidenceState::AccessLost),
        (404, statuspage::EvidenceState::AccessLost),
        (500, statuspage::EvidenceState::ProviderUnknown),
    ] {
        let mut service = service_with(status, json!({"message": "private diagnostic"}));
        let evidence = service.read().expect("status evidence");
        assert_eq!(evidence.state, expected);
        assert!(!evidence.native && !evidence.connected && !evidence.first_party);
        let serialized = serde_json::to_string(&evidence).expect("evidence serializes");
        assert!(!serialized.contains("private diagnostic"));
    }

    let provider = statuspage::StatuspageProvider::new(
        scope(),
        secret(),
        statuspage::BlockedEnvStatuspageTransport,
    )
    .expect("provider");
    let mut service = statuspage::StatuspageIncidentResultService::new(provider).expect("service");
    let evidence = service.read().expect("blocked evidence");
    assert_eq!(evidence.state, statuspage::EvidenceState::AccessLost);
    assert_eq!(
        evidence.classification,
        statuspage::EvidenceClassification::BlockedEnv
    );
    assert_eq!(
        evidence.provenance,
        statuspage::TransportProvenance::BlockedEnv
    );
    assert!(!evidence.native && !evidence.connected && !evidence.first_party);
}

#[test]
fn registration_is_reversible_but_digest_rotation_invalidates_old_proposals() {
    let mut service = service_with(200, fixture_payload(false));
    let original = service.registration().registration_digest.clone();
    let proposal = service.compile_proposal().expect("proposal");
    let revocation = service.provider_mut().revoke().expect("revoke");
    assert_eq!(revocation.previous_registration_digest, original);
    assert_ne!(revocation.registration_digest, original);
    assert!(matches!(
        service.read(),
        Err(statuspage::StatuspageIncidentResultServiceError::RegistrationRevoked)
    ));
    service.provider_mut().restore().expect("restore");
    assert_ne!(service.registration().registration_digest, original);
    assert!(matches!(
        service.verify_proposal(&proposal),
        Err(
            statuspage::StatuspageIncidentResultServiceError::RegistrationRevoked
                | statuspage::StatuspageIncidentResultServiceError::EvidenceMismatch
        )
    ));
    let restored = service.compile_proposal().expect("restored proposal");
    assert_ne!(restored.registration_digest, original);
}

#[test]
fn tamper_stale_consent_scope_and_replay_are_rejected() {
    let mut service = service_with(200, fixture_payload(false));
    let mut proposal = service.compile_proposal().expect("proposal");
    proposal.evidence.state = statuspage::EvidenceState::Partial;
    assert!(matches!(
        service.verify_proposal(&proposal),
        Err(statuspage::StatuspageIncidentResultServiceError::EvidenceMismatch)
    ));

    let stale = statuspage::ConsentScope::new("different-consent", 9).expect("stale consent");
    assert!(matches!(
        service.read_with_consent(&stale),
        Err(statuspage::StatuspageIncidentResultServiceError::ConsentMismatch)
    ));

    let provider = statuspage::StatuspageProvider::new(
        scope(),
        secret(),
        statuspage::FixtureStatuspageTransport::new(statuspage::StatuspageResponse::json(
            200,
            &fixture_payload(false),
        )),
    )
    .expect("provider");
    let mut consumer =
        statuspage::MissionStatuspageIncidentConsumer::new(provider).expect("consumer");
    let proposal = consumer.compile_proposal().expect("consumer proposal");
    let result = consumer.consume(&proposal).expect("consume");
    assert_eq!(
        result.state,
        statuspage::MissionStatuspageIncidentResultState::DecisionReady
    );
    assert!(result.proposal_only && !result.native && !result.connected && !result.adopts_outcome);
    assert!(matches!(
        consumer.consume(&proposal),
        Err(statuspage::MissionStatuspageIncidentConsumerError::ReplayDetected)
    ));
}

#[test]
fn bounds_malformed_and_partial_payloads_fail_closed() {
    assert!(statuspage::TimeWindow::new("2026-01-01", "2026-02-01", 1).is_err());
    assert!(statuspage::StatuspageAcl::new([], 1).is_err());
    assert!(statuspage::StatuspageRateLimitReceipt::new(61, None, None, false).is_err());

    let oversized = statuspage::StatuspageResponse::new(
        200,
        vec![b'x'; statuspage::MAX_RESPONSE_BYTES + 1],
        statuspage::StatuspageRateLimitReceipt::default(),
    );
    let provider = statuspage::StatuspageProvider::new(
        scope(),
        secret(),
        statuspage::FixtureStatuspageTransport::new(oversized),
    )
    .expect("provider");
    let mut service = statuspage::StatuspageIncidentResultService::new(provider).expect("service");
    let evidence = service.read().expect("oversized becomes typed failure");
    assert_eq!(evidence.state, statuspage::EvidenceState::ProviderUnknown);

    let malformed = statuspage::StatuspageResponse::new(
        200,
        b"not-json".to_vec(),
        statuspage::StatuspageRateLimitReceipt::default(),
    );
    let provider = statuspage::StatuspageProvider::new(
        scope(),
        secret(),
        statuspage::FixtureStatuspageTransport::new(malformed),
    )
    .expect("provider");
    let mut service = statuspage::StatuspageIncidentResultService::new(provider).expect("service");
    let evidence = service.read().expect("malformed becomes typed failure");
    assert_eq!(evidence.state, statuspage::EvidenceState::ProviderUnknown);

    let mut partial = fixture_payload(false);
    partial["partial"] = json!(true);
    let mut service = service_with(200, partial);
    let evidence = service.read().expect("partial evidence");
    assert_eq!(evidence.state, statuspage::EvidenceState::Partial);
    assert_eq!(
        evidence.classification,
        statuspage::EvidenceClassification::Partial
    );
}

#[test]
fn secret_reference_is_opaque_and_receipts_are_non_durable() {
    let secret = secret();
    let debug = format!("{secret:?}");
    assert!(!debug.contains("host-keyring-statuspage-token"));

    let mut service = service_with(200, fixture_payload(false));
    let proposal = service.compile_proposal().expect("proposal");
    let observation = service.record_observation(&proposal).expect("observation");
    assert!(observation.recorded);
    assert!(!observation.durable && !observation.native && !observation.connected);
    let readback = service.read_back(&proposal).expect("readback");
    assert!(!readback.independent_native_readback);
    assert!(!readback.native && !readback.connected);
}
