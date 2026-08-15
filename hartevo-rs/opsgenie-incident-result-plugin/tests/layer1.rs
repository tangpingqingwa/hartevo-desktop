use hartevo_opsgenie_incident_result_plugin::{
    BlockedEnvOpsgenieTransport, ConsentScope, Digest, EvidenceState,
    MissionOpsgenieIncidentConsumer, ModelError, OpsgenieAccountId, OpsgenieAlertAlias,
    OpsgenieAlertId, OpsgenieAlertPayload, OpsgenieEscalationId, OpsgenieEscalationPayload,
    OpsgenieIncidentId, OpsgenieIncidentPayload, OpsgenieIncidentResultScope,
    OpsgenieIncidentResultScopeSpec, OpsgeniePermissionSnapshot, OpsgenieProvider,
    OpsgenieRateLimitReceipt, OpsgenieReadSeam, OpsgenieRegion, OpsgenieResponse,
    OpsgenieScheduleId, OpsgenieSchedulePayload, OpsgenieServiceId, OpsgenieTeamId,
    OpsgenieTimelineEntryPayload, OpsgenieTimelinePayload, RecordingOpsgenieTransport,
    SecretReference, TransportProvenance,
};

fn scope() -> OpsgenieIncidentResultScope {
    OpsgenieIncidentResultScope::new(OpsgenieIncidentResultScopeSpec::new(
        OpsgenieAccountId::new("account-1").expect("account"),
        OpsgenieRegion::Us,
        OpsgenieTeamId::new("team-1").expect("team"),
        OpsgenieServiceId::new("service-1").expect("service"),
        OpsgenieAlertId::new("alert-1").expect("alert"),
        OpsgenieAlertAlias::new("alias-1").expect("alias"),
        OpsgenieIncidentId::new("incident-1").expect("incident"),
        OpsgenieScheduleId::new("schedule-1").expect("schedule"),
        OpsgenieEscalationId::new("escalation-1").expect("escalation"),
        hartevo_opsgenie_incident_result_plugin::OpsgenieTimelineId::new("timeline-1")
            .expect("timeline"),
        hartevo_opsgenie_incident_result_plugin::ProjectBinding::new("project-1", 4)
            .expect("Project"),
        hartevo_opsgenie_incident_result_plugin::MissionBinding::new("mission-1", 7)
            .expect("Mission"),
        hartevo_opsgenie_incident_result_plugin::WorkProductBinding::new("work-product-1", 3)
            .expect("Work Product"),
        ConsentScope::new("consent-opsgenie-1", 2).expect("consent"),
        OpsgeniePermissionSnapshot::least_privilege(5).expect("permissions"),
    ))
    .expect("exact Opsgenie scope")
}

fn secret() -> SecretReference {
    SecretReference::api_token("opsgenie-secret-token", 9).expect("opaque secret reference")
}

fn responses() -> (
    OpsgenieResponse,
    OpsgenieResponse,
    OpsgenieResponse,
    OpsgenieResponse,
    OpsgenieResponse,
) {
    let alert = OpsgenieResponse::json(
        200,
        &OpsgenieAlertPayload {
            id: "alert-1".to_owned(),
            alias: "alias-1".to_owned(),
            status: "open".to_owned(),
            priority: Some("P1".to_owned()),
            team_id: Some("team-1".to_owned()),
            service_id: Some("service-1".to_owned()),
            incident_id: Some("incident-1".to_owned()),
            created_at: Some("2026-08-15T00:00:00Z".to_owned()),
            updated_at: Some("2026-08-15T00:01:00Z".to_owned()),
            revision: 11,
        },
    );
    let timeline = OpsgenieResponse::new(
        200,
        br#"{"timeline":[{"id":"event-1","kind":"created","message":"private note must not escape"},{"id":"event-2","kind":"escalated","content":"private body"}] }"#.to_vec(),
        OpsgenieRateLimitReceipt::default(),
    );
    let incident = OpsgenieResponse::json(
        200,
        &OpsgenieIncidentPayload {
            id: "incident-1".to_owned(),
            status: "open".to_owned(),
            team_id: Some("team-1".to_owned()),
            service_id: Some("service-1".to_owned()),
            alerts: vec!["alert-1".to_owned()],
            revision: 12,
        },
    );
    let schedule = OpsgenieResponse::json(
        200,
        &OpsgenieSchedulePayload {
            id: "schedule-1".to_owned(),
            enabled: true,
            escalations: vec!["escalation-1".to_owned()],
            revision: 13,
        },
    );
    let escalation = OpsgenieResponse::json(
        200,
        &OpsgenieEscalationPayload {
            id: "escalation-1".to_owned(),
            schedule_id: Some("schedule-1".to_owned()),
            levels: vec!["level-1".to_owned()],
            revision: 14,
        },
    );
    (alert, timeline, incident, schedule, escalation)
}

fn recording_transport() -> RecordingOpsgenieTransport {
    let (alert, timeline, incident, schedule, escalation) = responses();
    let mut transport = RecordingOpsgenieTransport::new(alert.clone());
    transport.push_response(OpsgenieReadSeam::Alert, alert);
    transport.push_response(OpsgenieReadSeam::AlertTimeline, timeline);
    transport.push_response(OpsgenieReadSeam::Incident, incident);
    transport.push_response(OpsgenieReadSeam::Schedule, schedule);
    transport.push_response(OpsgenieReadSeam::Escalation, escalation);
    transport
}

#[test]
fn exact_scope_secret_and_registration_are_digest_bound_and_reversible() {
    let scope = scope();
    let secret = secret();
    let mut provider = OpsgenieProvider::new(scope.clone(), secret.clone(), recording_transport())
        .expect("provider");
    assert_eq!(provider.scope().digest(), scope.digest());
    assert_eq!(provider.scope().project().revision().get(), 4);
    assert_eq!(provider.scope().mission().revision().get(), 7);
    assert_eq!(provider.scope().work_product().revision().get(), 3);
    assert!(!format!("{secret:?}").contains("opsgenie-secret-token"));
    assert!(
        !serde_json::to_string(&secret)
            .expect("redacted secret JSON")
            .contains("opsgenie-secret-token")
    );
    let registration_before = provider.registration().registration_digest.clone();
    let revoked = provider.revoke().expect("revoke");
    assert_ne!(registration_before, revoked.registration_digest);
    assert!(provider.registration().is_revoked());
    provider.restore().expect("restore");
    assert!(provider.registration().is_active());
    assert_ne!(
        registration_before,
        provider.registration().registration_digest
    );
    assert!(
        serde_json::to_string(provider.registration())
            .expect("registration JSON")
            .contains("opsgenie.incident-result.recording")
    );
}

#[test]
fn recording_read_proposal_record_and_consume_are_non_native_and_redacted() {
    let provider =
        OpsgenieProvider::new(scope(), secret(), recording_transport()).expect("provider");
    let mut consumer = MissionOpsgenieIncidentConsumer::new(provider).expect("consumer");
    let proposal = consumer
        .compile_incident_result_proposal()
        .expect("proposal");
    assert_eq!(proposal.evidence.state, EvidenceState::Complete);
    assert!(proposal.evidence.is_actionable());
    assert!(proposal.proposal_only);
    assert!(!proposal.native);
    assert!(!proposal.connected);
    assert!(!proposal.first_party);
    assert!(!proposal.adopts_outcome);
    assert!(!proposal.adopts_work_product);
    assert_eq!(proposal.evidence.provenance, TransportProvenance::Recording);
    assert_eq!(proposal.evidence.request_receipts.len(), 5);
    assert!(
        proposal
            .evidence
            .request_receipts
            .iter()
            .all(|receipt| receipt.endpoint.starts_with("https://api.opsgenie.com/"))
    );
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!serialized.contains("private note must not escape"));
    assert!(!serialized.contains("private body"));
    let recorded = consumer
        .record_observation(&proposal)
        .expect("recording receipt");
    assert!(recorded.recorded);
    assert!(!recorded.durable);
    let result = consumer.consume(&proposal).expect("consume proposal");
    assert_eq!(
        result.state,
        hartevo_opsgenie_incident_result_plugin::MissionOpsgenieIncidentResultState::DecisionReady
    );
    assert!(!result.adopts_outcome);
    assert!(!result.adopts_work_product);
    assert_eq!(consumer.consume(&proposal), Err(hartevo_opsgenie_incident_result_plugin::MissionOpsgenieIncidentConsumerError::ReplayDetected));
}

#[test]
fn blocked_environment_is_typed_provider_unknown_and_never_connected() {
    let provider = OpsgenieProvider::new(scope(), secret(), BlockedEnvOpsgenieTransport)
        .expect("blocked provider");
    let mut consumer = MissionOpsgenieIncidentConsumer::new(provider).expect("consumer");
    let proposal = consumer.compile_proposal().expect("blocked proposal");
    assert_eq!(proposal.evidence.state, EvidenceState::ProviderUnknown);
    assert_eq!(
        proposal.evidence.provenance,
        TransportProvenance::BlockedEnv
    );
    assert!(!proposal.evidence.connected);
    assert!(!proposal.evidence.native);
    assert!(!proposal.evidence.first_party);
    assert_eq!(proposal.evidence.failures.len(), 1);
    assert_eq!(consumer.consume(&proposal).expect("blocked result").state, hartevo_opsgenie_incident_result_plugin::MissionOpsgenieIncidentResultState::ProviderUnknown);
}

#[test]
fn timeline_is_bounded_and_partial_when_provider_has_more_pages() {
    let (alert, _timeline, incident, schedule, escalation) = responses();
    let mut transport = RecordingOpsgenieTransport::new(alert.clone());
    transport.push_response(OpsgenieReadSeam::Alert, alert);
    for page in 0..4 {
        transport.push_response(
            OpsgenieReadSeam::AlertTimeline,
            OpsgenieResponse::json(
                200,
                &OpsgenieTimelinePayload {
                    timeline: vec![OpsgenieTimelineEntryPayload {
                        id: format!("event-{page}"),
                        kind: Some("created".to_owned()),
                        content_digest: Some(Digest::from_text(format!("body-{page}")).to_string()),
                    }],
                    next_page: Some(format!("page-{}", page + 1)),
                },
            ),
        );
    }
    transport.push_response(OpsgenieReadSeam::Incident, incident);
    transport.push_response(OpsgenieReadSeam::Schedule, schedule);
    transport.push_response(OpsgenieReadSeam::Escalation, escalation);
    let provider = OpsgenieProvider::new(scope(), secret(), transport).expect("provider");
    let mut consumer = MissionOpsgenieIncidentConsumer::new(provider).expect("consumer");
    let proposal = consumer.compile_proposal().expect("partial proposal");
    assert_eq!(proposal.evidence.state, EvidenceState::Partial);
    assert_eq!(
        proposal
            .evidence
            .result
            .timeline
            .expect("timeline")
            .page_count,
        4
    );
}

#[test]
fn malformed_or_scope_drift_does_not_become_evidence() {
    let (_, timeline, incident, schedule, escalation) = responses();
    let alert = OpsgenieResponse::json(
        200,
        &OpsgenieAlertPayload {
            id: "other-alert".to_owned(),
            alias: "alias-1".to_owned(),
            status: "open".to_owned(),
            priority: None,
            team_id: None,
            service_id: None,
            incident_id: None,
            created_at: None,
            updated_at: None,
            revision: 1,
        },
    );
    let mut transport = RecordingOpsgenieTransport::new(alert.clone());
    transport.push_response(OpsgenieReadSeam::Alert, alert);
    transport.push_response(OpsgenieReadSeam::AlertTimeline, timeline);
    transport.push_response(OpsgenieReadSeam::Incident, incident);
    transport.push_response(OpsgenieReadSeam::Schedule, schedule);
    transport.push_response(OpsgenieReadSeam::Escalation, escalation);
    let provider = OpsgenieProvider::new(scope(), secret(), transport).expect("provider");
    let mut consumer = MissionOpsgenieIncidentConsumer::new(provider).expect("consumer");
    assert!(matches!(
        consumer.read(),
        Err(hartevo_opsgenie_incident_result_plugin::MissionOpsgenieIncidentConsumerError::Service(
            hartevo_opsgenie_incident_result_plugin::OpsgenieIncidentResultServiceError::ScopeMismatch
        ))
    ));
    assert_eq!(
        OpsgenieRegion::parse("native").expect_err("invalid region"),
        ModelError::InvalidRegion
    );
}
