use std::fmt::Debug;

use hartevo_pagerduty_incident_plugin::{
    AlertStatus, ApiRegion, BlockedEnvTransport, ConsentId, ConsentReference, Digest,
    EscalationPolicyId, FakeTransport, IncidentId, IncidentIdentity, IncidentPageResponse,
    IncidentState, IncidentStatus, MissionId, MissionPagerDutyIncidentConsumer,
    PagerDutyIncidentProvider, PagerDutyScope, ProjectId, ProjectionBounds, Provenance,
    ProviderError, ProviderIncidentTransition, RateLimitReceipt, RawAlertPayload,
    RawAssignmentPayload, RawIncidentPayload, RawTimelineEntryPayload, RecordingTransport,
    RegistrationRegistry, RegistrationSpec, ResponseIntent, SecretKind, SecretReference, ServiceId,
    TeamId, TimelineBounds, TimelineKind, TimelinePageResponse, TimelineStopReason, TimelineWindow,
    Timestamp, TransportError, WebhookEnvelope, WebhookSecretMaterial, WebhookSubscriptionId,
    contract_digest, signature_for_test,
};

fn ts(value: i64) -> Timestamp {
    Timestamp::new(value).expect("positive timestamp")
}

fn scope() -> PagerDutyScope {
    let mission_id = MissionId::new("mission-pagerduty-1").expect("Mission id");
    let project_id = ProjectId::new("project-pagerduty-1").expect("Project id");
    let consent = ConsentReference::new(
        ConsentId::new("consent-pagerduty-1").expect("Consent id"),
        3,
        mission_id.clone(),
        project_id.clone(),
    )
    .expect("Consent reference");
    PagerDutyScope::new(
        ApiRegion::Us,
        hartevo_pagerduty_incident_plugin::AccountId::new("account-1").expect("account"),
        TeamId::new("team-1").expect("team"),
        ServiceId::new("service-1").expect("service"),
        EscalationPolicyId::new("escalation-1").expect("escalation policy"),
        IncidentIdentity::new(IncidentId::new("incident-1").expect("incident"), 101)
            .expect("incident identity"),
        mission_id,
        project_id,
        consent,
        WebhookSubscriptionId::new("subscription-1").expect("subscription"),
    )
    .expect("exact PagerDuty scope")
}

fn registration(
    scope: &PagerDutyScope,
) -> hartevo_pagerduty_incident_plugin::PagerDutyRegistration {
    let secret = SecretReference::new(
        "secret-ref-pagerduty-1",
        SecretKind::ApiToken,
        1,
        scope.digest(),
    )
    .expect("opaque API token reference");
    let spec = RegistrationSpec {
        registration_id: "pagerduty-registration-1".to_owned(),
        plugin_version: "1.0.0".to_owned(),
        contract_digest: contract_digest(),
        provider_revision: 7,
        scope: scope.clone(),
        secret_reference: secret,
    };
    let mut registry = RegistrationRegistry::new();
    registry
        .register(spec, ts(10))
        .expect("registration receipt");
    registry.current().cloned().expect("active registration")
}

fn rate(bytes: usize, request_id: &str) -> RateLimitReceipt {
    RateLimitReceipt {
        request_id: Some(request_id.to_owned()),
        limit: Some(60),
        remaining: Some(59),
        reset_at: Some(ts(2_000)),
        response_bytes: bytes,
    }
}

fn raw_assignment(scope: &PagerDutyScope, id: &str) -> RawAssignmentPayload {
    RawAssignmentPayload {
        assignment_id: id.to_owned(),
        assignee_reference: "Alice Private Email alice@example.test".to_owned(),
        team_id: scope.team_id.clone(),
        escalation_policy_id: scope.escalation_policy_id.clone(),
        assigned_at: ts(1_010),
    }
}

fn raw_alert(id: &str, status: AlertStatus) -> RawAlertPayload {
    RawAlertPayload {
        alert_id: id.to_owned(),
        status,
        deduplication_key: "sensitive-dedup-key".to_owned(),
        triggered_at: ts(1_011),
        resolved_at: (status == AlertStatus::Resolved).then(|| ts(1_030)),
        raw_body: b"raw-alert-body-private".to_vec(),
    }
}

fn raw_incident(
    scope: &PagerDutyScope,
    status: IncidentStatus,
    transition: ProviderIncidentTransition,
    resolved_at: Option<Timestamp>,
) -> RawIncidentPayload {
    RawIncidentPayload {
        api_region: scope.api_region,
        account_id: scope.account_id.clone(),
        team_id: scope.team_id.clone(),
        service_id: scope.service_id.clone(),
        escalation_policy_id: scope.escalation_policy_id.clone(),
        incident: scope.incident.clone(),
        status,
        transition,
        provider_revision: 7,
        created_at: ts(1_000),
        updated_at: ts(1_040),
        last_status_change_at: ts(1_039),
        resolved_at,
        priority: Some("P1".to_owned()),
        urgency: Some("high".to_owned()),
        assignments: vec![raw_assignment(scope, "assignment-1")],
        alerts: vec![raw_alert("alert-1", AlertStatus::Resolved)],
    }
}

fn raw_timeline_entry(id: &str, occurred_at: i64, content: &[u8]) -> RawTimelineEntryPayload {
    RawTimelineEntryPayload {
        entry_id: id.to_owned(),
        kind: TimelineKind::Note,
        occurred_at: ts(occurred_at),
        actor_reference: "Responder Bob bob@example.test".to_owned(),
        content: content.to_vec(),
    }
}

fn timeline_bounds(max_pages: usize) -> TimelineBounds {
    let contract_bounds = ProjectionBounds::default();
    TimelineBounds {
        page_size: 2,
        max_pages,
        max_items: 10,
        max_response_bytes: contract_bounds.max_response_bytes,
        window: TimelineWindow::new(
            ts(900),
            ts(1_900),
            contract_bounds.max_timeline_window_seconds,
        )
        .expect("timeline window"),
    }
}

#[test]
fn registration_is_exact_scope_bound_reversible_and_secret_opaque() {
    let scope = scope();
    let secret = SecretReference::new(
        "secret-ref-oauth-1",
        SecretKind::OAuthAccessToken,
        2,
        scope.digest(),
    )
    .expect("OAuth reference");
    let spec = RegistrationSpec {
        registration_id: "pagerduty-registration-reversible".to_owned(),
        plugin_version: "1.0.0".to_owned(),
        contract_digest: contract_digest(),
        provider_revision: 4,
        scope: scope.clone(),
        secret_reference: secret,
    };
    let mut registry = RegistrationRegistry::new();
    let registered = registry.register(spec, ts(10)).expect("register");
    assert_eq!(
        registered.action,
        hartevo_pagerduty_incident_plugin::RegistrationAction::Registered
    );
    let serialized = serde_json::to_string(registry.current().expect("registration JSON"))
        .expect("registration serializes");
    assert!(!serialized.contains("api-token-material"));
    assert!(!serialized.contains("oauth-secret-material"));

    let revoked = registry
        .revoke("pagerduty-registration-reversible", ts(20))
        .expect("revoke");
    assert_eq!(
        revoked.action,
        hartevo_pagerduty_incident_plugin::RegistrationAction::Revoked
    );
    assert!(registry.active().is_none());
    let restored = registry
        .restore("pagerduty-registration-reversible", ts(30))
        .expect("restore");
    assert_eq!(
        restored.action,
        hartevo_pagerduty_incident_plugin::RegistrationAction::Restored
    );
    assert!(registry.active().is_some());
    assert_ne!(
        registered.registration_revision,
        restored.registration_revision
    );
    assert_eq!(restored.scope_digest, scope.digest());

    let mut tampered = registry.current().cloned().expect("restored registration");
    tampered.registration_digest = Digest::from_text("tampered-registration");
    assert!(matches!(
        tampered.validate_integrity(),
        Err(hartevo_pagerduty_incident_plugin::RegistrationError::DigestMismatch)
    ));
}

#[test]
fn incident_and_alert_states_stay_distinct_through_retrigger_and_reopen() {
    let scope = scope();
    let mut transport = RecordingTransport::new();
    for (status, transition, resolved_at) in [
        (
            IncidentStatus::Triggered,
            ProviderIncidentTransition::None,
            None,
        ),
        (
            IncidentStatus::Triggered,
            ProviderIncidentTransition::None,
            None,
        ),
        (
            IncidentStatus::Acknowledged,
            ProviderIncidentTransition::None,
            None,
        ),
    ] {
        transport.push_incident_response(Ok(IncidentPageResponse {
            items: vec![raw_incident(&scope, status, transition, resolved_at)],
            rate_limit: rate(500, "incident"),
        }));
    }
    let mut provider = PagerDutyIncidentProvider::new(
        transport,
        registration(&scope),
        ProjectionBounds::default(),
    )
    .expect("provider");
    let first = provider
        .read_incident(None)
        .expect("first read")
        .incident
        .expect("incident");
    assert_eq!(first.state, IncidentState::Triggered);
    assert_eq!(first.alerts[0].status, AlertStatus::Resolved);

    let resolved = hartevo_pagerduty_incident_plugin::IncidentProjection {
        state: IncidentState::Resolved,
        ..first.clone()
    };
    let retriggered = provider
        .read_incident(Some(&resolved))
        .expect("retrigger read")
        .incident
        .expect("retriggered incident");
    assert_eq!(retriggered.state, IncidentState::Retriggered);
    assert_eq!(retriggered.provider_status, IncidentStatus::Triggered);

    let reopened = provider
        .read_incident(Some(&resolved))
        .expect("reopen read")
        .incident
        .expect("reopened incident");
    assert_eq!(reopened.state, IncidentState::Reopened);
    assert_eq!(reopened.provider_status, IncidentStatus::Acknowledged);
}

#[test]
fn empty_results_and_blocked_environment_never_claim_health_or_connection() {
    let scope = scope();
    let mut recording = RecordingTransport::new();
    recording.push_incident_response(Ok(IncidentPageResponse {
        items: Vec::new(),
        rate_limit: rate(200, "empty"),
    }));
    let mut provider = PagerDutyIncidentProvider::new(
        recording,
        registration(&scope),
        ProjectionBounds::default(),
    )
    .expect("recording provider");
    let empty = provider.read_incident(None).expect("empty read");
    assert!(empty.empty_result);
    assert!(!empty.empty_result_health_claim);

    let mut blocked = PagerDutyIncidentProvider::new(
        BlockedEnvTransport,
        registration(&scope),
        ProjectionBounds::default(),
    )
    .expect("blocked provider");
    assert_eq!(
        blocked.probe_registration(),
        Err(ProviderError::Transport(TransportError::BlockedEnv))
    );
    assert!(!Provenance::BlockedEnv.is_connected());
    assert!(!Provenance::BlockedEnv.is_native());
    assert!(!Provenance::BlockedEnv.is_first_party());
}

#[test]
fn timeline_is_bounded_rate_receipted_and_canonically_reordered() {
    let scope = scope();
    let mut transport = RecordingTransport::new();
    transport.insert_timeline_response(
        None,
        Ok(TimelinePageResponse {
            items: vec![
                raw_timeline_entry("entry-2", 1_200, b"private note 2"),
                raw_timeline_entry("entry-1", 1_100, b"private note 1"),
            ],
            next_cursor: Some("cursor-1".to_owned()),
            rate_limit: rate(400, "timeline-1"),
        }),
    );
    transport.insert_timeline_response(
        Some("cursor-1"),
        Ok(TimelinePageResponse {
            items: vec![raw_timeline_entry("entry-3", 1_300, b"private note 3")],
            next_cursor: None,
            rate_limit: rate(420, "timeline-2"),
        }),
    );
    let mut provider = PagerDutyIncidentProvider::new(
        transport,
        registration(&scope),
        ProjectionBounds::default(),
    )
    .expect("provider");
    let projection = provider
        .read_incident_timeline(timeline_bounds(3))
        .expect("bounded timeline");
    assert!(projection.receipt.complete);
    assert!(projection.receipt.reordered);
    assert_eq!(projection.receipt.page_count, 2);
    assert_eq!(projection.receipt.item_count, 3);
    assert_eq!(projection.entries[0].entry_id, "entry-1");
    assert_eq!(projection.entries[2].entry_id, "entry-3");
    assert_eq!(projection.receipt.pages[0].rate_limit.remaining, Some(59));
    let json = serde_json::to_string(&projection).expect("projection JSON");
    assert!(!json.contains("private note"));
    assert!(!json.contains("bob@example.test"));
}

#[test]
fn duplicate_pages_fail_closed_and_page_limits_are_explicit() {
    let scope = scope();
    let mut duplicate_transport = RecordingTransport::new();
    duplicate_transport.insert_timeline_response(
        None,
        Ok(TimelinePageResponse {
            items: vec![raw_timeline_entry("duplicate", 1_100, b"one")],
            next_cursor: Some("next".to_owned()),
            rate_limit: rate(200, "one"),
        }),
    );
    duplicate_transport.insert_timeline_response(
        Some("next"),
        Ok(TimelinePageResponse {
            items: vec![raw_timeline_entry("duplicate", 1_101, b"two")],
            next_cursor: None,
            rate_limit: rate(200, "two"),
        }),
    );
    let mut duplicate_provider = PagerDutyIncidentProvider::new(
        duplicate_transport,
        registration(&scope),
        ProjectionBounds::default(),
    )
    .expect("duplicate provider");
    assert!(matches!(
        duplicate_provider.read_incident_timeline(timeline_bounds(3)),
        Err(ProviderError::DuplicateTimelineEntry(_))
    ));

    let mut partial_transport = RecordingTransport::new();
    partial_transport.insert_timeline_response(
        None,
        Ok(TimelinePageResponse {
            items: vec![raw_timeline_entry("partial", 1_100, b"partial")],
            next_cursor: Some("still-more".to_owned()),
            rate_limit: rate(200, "partial"),
        }),
    );
    let mut partial_provider = PagerDutyIncidentProvider::new(
        partial_transport,
        registration(&scope),
        ProjectionBounds::default(),
    )
    .expect("partial provider");
    let projection = partial_provider
        .read_incident_timeline(timeline_bounds(1))
        .expect("bounded partial timeline");
    assert!(!projection.receipt.complete);
    assert_eq!(
        projection.receipt.stop_reason,
        TimelineStopReason::PageLimit
    );
}

#[test]
fn proposals_bind_mission_consent_revision_and_never_execute_or_adopt() {
    let scope = scope();
    let resolved = raw_incident(
        &scope,
        IncidentStatus::Resolved,
        ProviderIncidentTransition::None,
        Some(ts(1_050)),
    );
    let mut fake = FakeTransport::new();
    fake.push_incident_response(Ok(IncidentPageResponse {
        items: vec![resolved],
        rate_limit: rate(500, "resolved"),
    }));
    fake.insert_timeline_response(
        None,
        Ok(TimelinePageResponse {
            items: vec![raw_timeline_entry(
                "resolution-entry",
                1_050,
                b"raw resolution note",
            )],
            next_cursor: None,
            rate_limit: rate(300, "resolution-timeline"),
        }),
    );
    let provider =
        PagerDutyIncidentProvider::new(fake, registration(&scope), ProjectionBounds::default())
            .expect("provider");
    let mut consumer = MissionPagerDutyIncidentConsumer::new(provider, scope.clone(), 12)
        .expect("Mission consumer");
    let incident = consumer
        .read_incident(None)
        .expect("incident")
        .incident
        .expect("resolved incident");
    let timeline = consumer
        .read_incident_timeline(timeline_bounds(1))
        .expect("timeline");
    let proposal = consumer
        .compile_response_proposal(
            IncidentState::Resolved,
            ResponseIntent::Resolve {
                resolution_evidence_digest: Digest::from_text("resolution-intent"),
            },
            "mission-12-idempotency",
        )
        .expect("non-mutating proposal");
    assert!(!proposal.mutating_effect_allowed);
    assert!(!proposal.executed);
    assert!(proposal.exact_readback_required);
    assert_eq!(proposal.mission_revision, 12);
    assert_eq!(proposal.consent.project_id(), &scope.project_id);

    let evidence = consumer
        .verify_resolution_projection(&incident, &timeline, &["resolution-entry".to_owned()])
        .expect("resolution evidence proposal");
    assert!(!evidence.adopted_outcome);
    assert_eq!(evidence.provider_revision, 7);
    assert_eq!(evidence.selected_timeline.len(), 1);
    let serialized = serde_json::to_string(&(&proposal, &evidence, &incident, &timeline))
        .expect("proposal serialization");
    assert!(!serialized.contains("Alice Private Email"));
    assert!(!serialized.contains("raw resolution note"));
    assert!(!serialized.contains("raw-alert-body-private"));
}

#[test]
fn webhook_verification_is_raw_body_signed_subscription_bound_and_replay_fenced() {
    let scope = scope();
    let provider = PagerDutyIncidentProvider::new(
        BlockedEnvTransport,
        registration(&scope),
        ProjectionBounds::default(),
    )
    .expect("webhook provider");
    let mut consumer =
        MissionPagerDutyIncidentConsumer::new(provider, scope.clone(), 1).expect("consumer");
    let secret = WebhookSecretMaterial::new(b"webhook-secret-private");
    let body = br#"{"event":"incident.triggered"}"#;
    let envelope = WebhookEnvelope {
        subscription_id: scope.webhook_subscription_id.clone(),
        signature: signature_for_test(&secret, body),
        event_id: "event-1".to_owned(),
        event_type: "incident.triggered".to_owned(),
        occurred_at: ts(1_000),
    };
    let verified = consumer
        .verify_webhook_envelope(&envelope, body, &secret, ts(1_010))
        .expect("valid webhook");
    assert!(verified.change_signal_only);
    assert!(verified.requires_rest_readback);
    assert_eq!(verified.provenance, Provenance::BlockedEnv);
    assert!(
        !serde_json::to_string(&verified)
            .expect("verified webhook JSON")
            .contains("webhook-secret-private")
    );

    let replay = consumer.verify_webhook_envelope(&envelope, body, &secret, ts(1_010));
    assert_eq!(
        replay,
        Err(ProviderError::Webhook(
            hartevo_pagerduty_incident_plugin::WebhookError::Replay
        ))
    );

    let bad_body = br#"{"event":"incident.resolved"}"#;
    let bad_signature = WebhookEnvelope {
        event_id: "event-2".to_owned(),
        signature: envelope.signature.clone(),
        ..envelope.clone()
    };
    assert!(matches!(
        consumer.verify_webhook_envelope(&bad_signature, bad_body, &secret, ts(1_010)),
        Err(ProviderError::Webhook(
            hartevo_pagerduty_incident_plugin::WebhookError::InvalidSignature
        ))
    ));

    let wrong_subscription = WebhookEnvelope {
        subscription_id: WebhookSubscriptionId::new("other-subscription").expect("subscription"),
        event_id: "event-3".to_owned(),
        signature: signature_for_test(&secret, body),
        ..envelope
    };
    assert!(matches!(
        consumer.verify_webhook_envelope(&wrong_subscription, body, &secret, ts(1_010)),
        Err(ProviderError::Webhook(
            hartevo_pagerduty_incident_plugin::WebhookError::SubscriptionMismatch
        ))
    ));
}

#[test]
fn provider_and_raw_testkit_debug_are_redacted() {
    let scope = scope();
    let assignment = raw_assignment(&scope, "assignment-redaction");
    let alert = raw_alert("alert-redaction", AlertStatus::Triggered);
    let raw = raw_incident(
        &scope,
        IncidentStatus::Triggered,
        ProviderIncidentTransition::None,
        None,
    );
    assert!(!format!("{assignment:?}").contains("Alice Private Email"));
    assert!(!format!("{alert:?}").contains("raw-alert-body-private"));
    assert!(!format!("{raw:?}").contains("bob@example.test"));
}

#[allow(dead_code)]
fn _assert_debug<T: Debug>(value: &T) -> String {
    format!("{value:?}")
}
