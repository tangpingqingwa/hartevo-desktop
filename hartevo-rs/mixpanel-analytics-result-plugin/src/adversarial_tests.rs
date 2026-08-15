use super::*;

const COMPLETE_BODY: &str = r#"{
  "computed_at": "2026-08-15T01:02:03+00:00",
  "date_range": {
    "from_date": "2026-08-10T00:00:00+00:00",
    "to_date": "2026-08-12T23:59:59+00:00"
  },
  "headers": ["$event"],
  "series": {
    "signup": {
      "2026-08-10T00:00:00+00:00": 4,
      "2026-08-11T00:00:00+00:00": 7,
      "2026-08-12T00:00:00+00:00": 9
    },
    "checkout": {
      "2026-08-10T00:00:00+00:00": 2,
      "2026-08-11T00:00:00+00:00": 3,
      "2026-08-12T00:00:00+00:00": 5
    }
  }
}"#;

fn scope() -> MixpanelAnalyticsScope {
    MixpanelAnalyticsScope::new(
        ProjectScope::new(12345, 2).expect("project"),
        Some(WorkspaceId::new(67890).expect("workspace")),
        ReportId::new(24680).expect("report"),
        DateWindow::new(
            UtcDate::new("2026-08-10").expect("from"),
            UtcDate::new("2026-08-12").expect("to"),
        )
        .expect("window"),
        EventSelector::new([
            EventName::new("signup").expect("event"),
            EventName::new("checkout").expect("event"),
        ])
        .expect("selector"),
        MissionScope::new("mission-737", 4).expect("mission"),
        WorkProductScope::new("work-product-737", 8).expect("work product"),
        PrivacyPolicy::strict_v1(),
    )
    .expect("scope")
}

fn request(
    scope: &MixpanelAnalyticsScope,
    key: &str,
    seconds: i64,
) -> MixpanelAnalyticsResultRequest {
    MixpanelAnalyticsResultRequest::new(
        scope,
        Timestamp::new(seconds).expect("timestamp"),
        IdempotencyKey::new(key).expect("idempotency key"),
    )
}

fn make_secret(scope: &MixpanelAnalyticsScope) -> SecretReference {
    SecretReference::project_token("vault://mixpanel/project-token", scope, 3).expect("secret")
}

#[test]
fn fixture_read_is_bounded_and_consumer_is_evidence_only() {
    let scope = scope();
    let secret = make_secret(&scope);
    let mut service = MixpanelAnalyticsResultService::new(
        scope.clone(),
        secret,
        MixpanelProvider::fixture(COMPLETE_BODY),
    )
    .expect("service");
    let request = request(&scope, "read-1", 1_723_680_000);
    assert_eq!(
        request.path_and_query().expect("query"),
        "https://mixpanel.com/api/query/insights?project_id=12345&workspace_id=67890&bookmark_id=24680"
    );
    let proposal = service.read(request).expect("proposal");
    assert_eq!(proposal.status, ResultStatus::Complete);
    assert_eq!(proposal.evidence.series.len(), 2);
    assert!(proposal.evidence.redactions.is_strict());
    assert!(!proposal.connected);
    assert!(!proposal.native_provider);
    assert!(!proposal.first_party);
    assert!(!proposal.outcome_authority);
    assert!(
        serde_json::to_string(&proposal)
            .expect("serialized proposal")
            .contains("rawEventsIncluded")
    );

    let mut consumer =
        MissionMixpanelAnalyticsConsumer::new_bound(scope, proposal.registration_digest.clone());
    let consumed = consumer.consume(proposal.clone()).expect("consume");
    assert_eq!(consumed.state, MissionResultState::Complete);
    assert!(!consumed.adopted_work_product);
    assert!(!consumed.outcome_authority);
    assert!(!consumed.connected);
    assert!(!consumed.native_provider);
    assert!(!consumed.first_party);
    assert_eq!(consumer.consumed_count(), 1);
    assert_eq!(
        consumer.consume(proposal).expect_err("replay").to_string(),
        "proposal has already been consumed"
    );
}

#[test]
fn all_fixture_recording_fake_loopback_and_blocked_provenances_are_non_native() {
    let scope = scope();
    let request = request(&scope, "provenance", 1_723_680_000);
    let secret = make_secret(&scope);
    let mut fixture = MixpanelProvider::fixture(COMPLETE_BODY);
    let mut recording = MixpanelProvider::recording(COMPLETE_BODY);
    let mut fake = MixpanelProvider::fake(COMPLETE_BODY);
    let mut loopback = MixpanelProvider::loopback(COMPLETE_BODY);
    let mut blocked = MixpanelProvider::blocked_env();
    for evidence in [
        fixture.read(&request, &secret).expect("fixture"),
        recording.read(&request, &secret).expect("recording"),
        fake.read(&request, &secret).expect("fake"),
        loopback.read(&request, &secret).expect("loopback"),
        blocked.read(&request, &secret).expect("blocked env"),
    ] {
        assert!(!evidence.provenance.connected());
        assert!(!evidence.provenance.native());
        assert!(!evidence.provenance.first_party());
        assert!(evidence.redactions.is_strict());
    }
}

#[test]
fn mission_and_work_product_revision_fences_reject_tampered_requests() {
    let scope = scope();
    let secret = make_secret(&scope);
    let mut service = MixpanelAnalyticsResultService::new(
        scope.clone(),
        secret,
        MixpanelProvider::fixture(COMPLETE_BODY),
    )
    .expect("service");
    let stale_mission = request(&scope, "revision-mission", 1)
        .with_mission_revision(Revision::new(5).expect("revision"));
    assert!(matches!(
        service.read(stale_mission),
        Err(MixpanelAnalyticsResultServiceError::RequestOutOfScope)
    ));
    let stale_work_product = request(&scope, "revision-work-product", 1)
        .with_work_product_revision(Revision::new(9).expect("revision"));
    assert!(matches!(
        service.read(stale_work_product),
        Err(MixpanelAnalyticsResultServiceError::RequestOutOfScope)
    ));
    let scope_tamper =
        request(&scope, "scope-tamper", 1).with_scope_digest(Digest::from_text("different-scope"));
    assert!(matches!(
        service.read(scope_tamper),
        Err(MixpanelAnalyticsResultServiceError::RequestOutOfScope)
    ));
}

#[test]
fn idempotency_returns_the_same_proposal_without_a_second_provider_read() {
    let scope = scope();
    let secret = make_secret(&scope);
    let mut service = MixpanelAnalyticsResultService::new(
        scope.clone(),
        secret,
        MixpanelProvider::new(RecordingMixpanelTransport::new(COMPLETE_BODY)).expect("provider"),
    )
    .expect("service");
    let first_request = request(&scope, "same-key", 1);
    let first = service.read(first_request.clone()).expect("first");
    let second = service.read(first_request).expect("idempotent second");
    assert_eq!(first, second);
    assert_eq!(service.provider().transport().request_count(), 1);

    let conflicting = request(&scope, "same-key", 2);
    assert!(matches!(
        service.read(conflicting),
        Err(MixpanelAnalyticsResultServiceError::IdempotencyConflict)
    ));
}

#[test]
fn raw_user_pii_and_unknown_event_shapes_are_not_retained() {
    let body = r#"{
      "computed_at": "2026-08-15T01:02:03+00:00",
      "date_range": {"from_date": "2026-08-10", "to_date": "2026-08-12"},
      "headers": ["$event"],
      "series": {"signup": {"2026-08-10": 1}},
      "distinct_id": "alice@example.com",
      "user": {"email": "alice@example.com"}
    }"#;
    let scope = scope();
    let secret = make_secret(&scope);
    let mut provider = MixpanelProvider::fixture(body);
    let evidence = provider
        .read(&request(&scope, "pii", 1), &secret)
        .expect("provider evidence");
    assert_eq!(evidence.status, ResultStatus::ProviderUnknown);
    assert_eq!(evidence.error, Some(ProviderErrorKind::RawEventOrPii));
    assert!(
        serde_json::to_string(&evidence)
            .expect("evidence JSON")
            .contains("rawApiBodyDropped")
    );
    assert!(!format!("{provider:?}").contains("alice@example.com"));
    assert!(!format!("{evidence:?}").contains("alice@example.com"));
}

#[test]
fn response_scope_drift_is_redacted_into_a_provider_unknown_state() {
    let body = COMPLETE_BODY.replace("\"checkout\"", "\"unselected-event\"");
    let scope = scope();
    let secret = make_secret(&scope);
    let mut provider = MixpanelProvider::fixture(body);
    let evidence = provider
        .read(&request(&scope, "scope-drift", 1), &secret)
        .expect("provider evidence");
    assert_eq!(evidence.status, ResultStatus::ProviderUnknown);
    assert_eq!(evidence.error, Some(ProviderErrorKind::ScopeDrift));
    assert!(evidence.series.is_empty());
}

#[test]
fn partial_and_blocked_environment_states_are_explicit() {
    let scope = scope();
    let secret = make_secret(&scope);
    let mut partial = MixpanelProvider::new(RecordingMixpanelTransport::from_response(
        MixpanelHttpResponse::partial(COMPLETE_BODY),
    ))
    .expect("partial provider");
    let partial_evidence = partial
        .read(&request(&scope, "partial", 1), &secret)
        .expect("partial evidence");
    assert_eq!(partial_evidence.status, ResultStatus::Partial);

    let mut blocked = MixpanelProvider::blocked_env();
    let blocked_evidence = blocked
        .read(&request(&scope, "blocked", 1), &secret)
        .expect("blocked evidence");
    assert_eq!(blocked_evidence.status, ResultStatus::ProviderUnknown);
    assert_eq!(blocked_evidence.error, Some(ProviderErrorKind::BlockedEnv));
    assert!(!blocked_evidence.provenance.native());
}

#[test]
fn rate_limit_is_bounded_per_project_and_utc_hour() {
    let scope = scope();
    let secret = make_secret(&scope);
    let request = request(&scope, "rate-limit", 7_200);
    let mut provider = MixpanelProvider::fake(COMPLETE_BODY);
    for _ in 0..MIXPANEL_MAX_REQUESTS_PER_PROJECT_PER_UTC_HOUR {
        assert_eq!(
            provider
                .read(&request, &secret)
                .expect("bounded read")
                .status,
            ResultStatus::Complete
        );
    }
    let exhausted = provider
        .read(&request, &secret)
        .expect("rate limit evidence");
    assert_eq!(exhausted.status, ResultStatus::RateLimited);
    assert_eq!(exhausted.error, Some(ProviderErrorKind::QuotaExhausted));
}

#[test]
fn registration_and_secret_revocation_fail_closed() {
    let scope = scope();
    let secret = make_secret(&scope);
    let mut registration_service = MixpanelAnalyticsResultService::new(
        scope.clone(),
        secret,
        MixpanelProvider::fixture(COMPLETE_BODY),
    )
    .expect("service");
    registration_service
        .revoke_registration()
        .expect("revoke registration");
    assert!(matches!(
        registration_service.read(request(&scope, "revoked-registration", 1)),
        Err(MixpanelAnalyticsResultServiceError::RegistrationRevoked)
    ));

    let secret = make_secret(&scope);
    let mut secret_service = MixpanelAnalyticsResultService::new(
        scope.clone(),
        secret,
        MixpanelProvider::fixture(COMPLETE_BODY),
    )
    .expect("service");
    secret_service.revoke_secret().expect("revoke secret");
    assert!(matches!(
        secret_service.read(request(&scope, "revoked-secret", 1)),
        Err(MixpanelAnalyticsResultServiceError::SecretRevoked)
    ));
}

#[test]
fn tampered_evidence_and_tampered_proposal_are_rejected_before_replay_state_changes() {
    let scope = scope();
    let secret = make_secret(&scope);
    let mut service = MixpanelAnalyticsResultService::new(
        scope.clone(),
        secret,
        MixpanelProvider::fixture(COMPLETE_BODY),
    )
    .expect("service");
    let proposal = service
        .read(request(&scope, "tamper", 1))
        .expect("proposal");
    let mut consumer = MissionMixpanelAnalyticsConsumer::new(scope.clone());
    let mut evidence_tampered = proposal.clone();
    evidence_tampered.evidence.response_digest = Digest::from_text("tampered-response");
    assert_eq!(
        consumer
            .consume(evidence_tampered)
            .expect_err("tampered evidence"),
        ConsumerError::Tampered
    );
    assert_eq!(consumer.consumed_count(), 0);

    let mut proposal_tampered = proposal;
    proposal_tampered.proposal_digest = Digest::from_text("tampered-proposal");
    assert_eq!(
        consumer
            .consume(proposal_tampered)
            .expect_err("tampered proposal"),
        ConsumerError::Tampered
    );
    assert_eq!(consumer.consumed_count(), 0);
}

#[test]
fn opaque_secret_debug_contains_only_digests_and_revision() {
    let scope = scope();
    let secret = make_secret(&scope);
    let debug = format!("{secret:?}");
    assert!(debug.contains("project_token"));
    assert!(debug.contains("reference_digest"));
    assert!(debug.contains("credential_revision"));
    assert!(!debug.contains("vault://mixpanel/project-token"));
}
