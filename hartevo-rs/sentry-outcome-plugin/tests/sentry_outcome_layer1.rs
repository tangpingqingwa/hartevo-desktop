use chrono::{DateTime, Utc};
use hartevo_sentry_outcome_plugin::{
    AccessMode, BackoffPolicy, BlockedEnvSentryTransport, EvidenceClassification,
    FixtureSentryTransport, LoopbackSentryTransport, MissionOutcomeEvidenceConsumer,
    MissionOutcomeEvidenceRequest, OutcomeObservation, PluginVersion, ProbeStatus, Provenance,
    QueryCancellationToken, QueryReceiptStatus, QueryWindow, RecordedSentryPage,
    RegistrationStatus, SentryOutcomeError, SentryOutcomePluginDefinition, SentryOutcomeProvider,
    SentryQuery, SentryQueryKind, SentryQueryResult, SentryScope, SentryTransport, sha256_digest,
};

fn at(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .expect("fixture timestamp")
        .with_timezone(&Utc)
}

fn scope(project: &str, environment: &str) -> SentryScope {
    SentryScope::new(
        "organization-test",
        project,
        environment,
        "release-2026-08-14",
        "mission-test",
        11,
        "deployment-test",
        4,
    )
    .expect("scope")
}

fn window() -> QueryWindow {
    QueryWindow::new(at("2026-08-14T00:00:00Z"), at("2026-08-14T00:05:00Z")).expect("window")
}

fn issue_query(scope: SentryScope) -> hartevo_sentry_outcome_plugin::IssueQuery {
    hartevo_sentry_outcome_plugin::IssueQuery::new(scope, window(), 2, None).expect("issue query")
}

fn event_query(scope: SentryScope) -> hartevo_sentry_outcome_plugin::EventQuery {
    hartevo_sentry_outcome_plugin::EventQuery::new(scope, window(), 2, None, None)
        .expect("event query")
}

fn release_query(scope: SentryScope) -> hartevo_sentry_outcome_plugin::ReleaseQuery {
    hartevo_sentry_outcome_plugin::ReleaseQuery::new(scope, window(), 2, None)
        .expect("release query")
}

fn provider_for<T>(scope: &SentryScope, transport: T) -> SentryOutcomeProvider
where
    T: SentryTransport + 'static,
{
    SentryOutcomeProvider::for_scope(transport, scope.clone(), 1)
        .expect("registration")
        .with_backoff(BackoffPolicy::deterministic())
        .expect("backoff")
}

fn evidence_request(query: &SentryQuery) -> MissionOutcomeEvidenceRequest {
    MissionOutcomeEvidenceRequest::new(
        query,
        query.scope().mission_binding(),
        at("2026-08-14T00:05:01Z"),
        600,
    )
    .expect("evidence request")
}

#[test]
fn contract_registration_is_version_digest_scope_bound_and_reversible() {
    let definition = SentryOutcomePluginDefinition::layer1().expect("definition");
    assert_eq!(definition.service.access, AccessMode::ReadOnly);
    assert_eq!(definition.version, PluginVersion::V1);
    assert!(!definition.writes);
    assert!(!definition.webhooks);
    assert!(definition.reversible);

    let scope = scope("project-a", "production");
    let receipt = definition
        .bind(scope.clone(), 7)
        .expect("registration receipt");
    receipt.validate(&definition).expect("valid registration");
    assert_eq!(receipt.scope, scope);
    assert_eq!(receipt.status, RegistrationStatus::Active);

    let revocation = receipt.revoke();
    assert_eq!(revocation.status, RegistrationStatus::Revoked);
    assert_eq!(revocation.generation, 7);
    assert_eq!(revocation.scope_digest, receipt.scope.digest());
}

#[tokio::test]
async fn cursor_pages_and_mission_binding_are_recorded_without_native_claims() {
    let scope = scope("project-a", "production");
    let provider = provider_for(
        &scope,
        LoopbackSentryTransport::demo(&scope).expect("loopback"),
    );
    let query = issue_query(scope.clone());
    let query_as_enum = SentryQuery::issues(query.clone()).expect("typed query");
    let execution = provider
        .query_issues(query, &QueryCancellationToken::default())
        .await
        .expect("query");

    assert_eq!(execution.receipt.status, QueryReceiptStatus::Completed);
    assert_eq!(execution.receipt.page_receipts.len(), 2);
    assert_eq!(execution.receipt.cursor_receipts.len(), 2);
    assert!(
        execution.receipt.cursor_receipts[0]
            .next_cursor_digest
            .is_some()
    );
    execution.receipt.validate().expect("receipt");
    assert_eq!(execution.provenance, Provenance::Loopback);
    assert!(!execution.is_native());
    assert!(!execution.is_connected());
    assert_eq!(execution.result.as_ref().expect("result").len(), 2);

    let request = evidence_request(&query_as_enum);
    let evidence = MissionOutcomeEvidenceConsumer
        .consume(&request, &execution)
        .expect("evidence");
    assert_eq!(evidence.binding.mission_revision, 11);
    assert_eq!(evidence.binding.deployment_revision, 4);
    assert_eq!(evidence.classification, EvidenceClassification::Loopback);
    assert!(!evidence.native);
    assert!(!evidence.connected);
    assert!(!evidence.health_claim);
    assert!(!evidence.absence_is_success);
}

#[tokio::test]
async fn rate_limit_backoff_is_bounded_and_receipted() {
    let scope = scope("project-a", "production");
    let transport = LoopbackSentryTransport::demo(&scope)
        .expect("loopback")
        .with_fault(hartevo_sentry_outcome_plugin::RecordedFault::RateLimitedOnce);
    let provider = provider_for(&scope, transport);
    let execution = provider
        .query_events(event_query(scope), &QueryCancellationToken::default())
        .await
        .expect("rate-limited retry");

    assert_eq!(execution.receipt.status, QueryReceiptStatus::Completed);
    assert_eq!(execution.receipt.rate_limit_receipts.len(), 1);
    assert_eq!(
        execution.receipt.rate_limit_receipts[0].retry_after_seconds,
        Some(1)
    );
    assert_eq!(execution.receipt.rate_limit_receipts[0].backoff_seconds, 0);
    execution.receipt.validate().expect("rate-limit receipt");
}

#[tokio::test]
async fn response_tamper_and_fingerprint_mismatch_fail_closed() {
    let scope = scope("project-a", "production");
    let tampered = provider_for(
        &scope,
        LoopbackSentryTransport::demo(&scope)
            .expect("loopback")
            .with_fault(hartevo_sentry_outcome_plugin::RecordedFault::ResponseTampered),
    );
    let tamper_error = tampered
        .query_issues(
            issue_query(scope.clone()),
            &QueryCancellationToken::default(),
        )
        .await
        .expect_err("tamper must fail");
    assert_eq!(tamper_error, SentryOutcomeError::ResponseTampered);

    let fingerprint = provider_for(
        &scope,
        LoopbackSentryTransport::demo(&scope)
            .expect("loopback")
            .with_fault(hartevo_sentry_outcome_plugin::RecordedFault::FingerprintMismatch),
    );
    let fingerprint_error = fingerprint
        .query_events(event_query(scope), &QueryCancellationToken::default())
        .await
        .expect_err("fingerprint mismatch must fail");
    assert_eq!(fingerprint_error, SentryOutcomeError::FingerprintMismatch);
}

#[tokio::test]
async fn two_project_environment_scopes_cannot_cross_read() {
    let scope_a = scope("project-a", "production");
    let scope_b = scope("project-b", "staging");
    let provider = provider_for(
        &scope_a,
        LoopbackSentryTransport::demo(&scope_a)
            .expect("loopback")
            .with_fault(hartevo_sentry_outcome_plugin::RecordedFault::ScopeMismatch),
    );
    let error = provider
        .query_issues(
            issue_query(scope_a.clone()),
            &QueryCancellationToken::default(),
        )
        .await
        .expect_err("cross-scope page must fail");
    assert_eq!(error, SentryOutcomeError::ScopeMismatch);

    let registered_scope_error = provider
        .query_issues(issue_query(scope_b), &QueryCancellationToken::default())
        .await
        .expect_err("unregistered project/environment must fail");
    assert_eq!(registered_scope_error, SentryOutcomeError::ScopeMismatch);
}

#[tokio::test]
async fn fixture_redacts_payloads_and_never_reports_connected() {
    let scope = scope("project-a", "production");
    let provider = provider_for(
        &scope,
        FixtureSentryTransport::demo(&scope).expect("fixture"),
    );
    let query = event_query(scope.clone());
    let query_as_enum = SentryQuery::events(query.clone()).expect("typed query");
    let execution = provider
        .query_events(query, &QueryCancellationToken::default())
        .await
        .expect("fixture query");
    let event = match execution.result.as_ref().expect("fixture result") {
        SentryQueryResult::Events(events) => events.first().expect("event"),
        _ => panic!("expected event result"),
    };
    assert_eq!(
        event.message.as_ref().expect("redacted message").digest,
        sha256_digest(b"token-never-retained")
    );
    let debug = format!("{event:?}{provider:?}");
    assert!(!debug.contains("token-never-retained"));
    assert!(!execution.is_native());
    assert!(!execution.is_connected());

    let evidence = MissionOutcomeEvidenceConsumer
        .consume(&evidence_request(&query_as_enum), &execution)
        .expect("fixture evidence");
    assert_eq!(evidence.classification, EvidenceClassification::Fixture);
    assert!(!evidence.native);
    assert!(!evidence.connected);
    let probe = provider.probe(&scope, at("2026-08-14T00:05:00Z")).await;
    assert_eq!(probe.status, ProbeStatus::Reachable);
    assert!(!probe.native);
    assert!(!probe.connected);
}

#[tokio::test]
async fn blocked_environment_is_explicit_and_never_native() {
    let scope = scope("project-a", "production");
    let provider = provider_for(&scope, BlockedEnvSentryTransport);
    let query = event_query(scope.clone());
    let query_as_enum = SentryQuery::events(query.clone()).expect("typed query");
    let execution = provider
        .query_events(query, &QueryCancellationToken::default())
        .await
        .expect("blocked environment receipt");
    assert_eq!(execution.receipt.status, QueryReceiptStatus::BlockedEnv);
    assert_eq!(execution.provenance, Provenance::BlockedEnv);
    assert!(!execution.is_native());
    assert!(!execution.is_connected());
    let evidence = MissionOutcomeEvidenceConsumer
        .consume(&evidence_request(&query_as_enum), &execution)
        .expect("blocked evidence");
    assert_eq!(evidence.classification, EvidenceClassification::BlockedEnv);
    assert!(!evidence.native);
    assert!(!evidence.connected);
    assert_eq!(
        evidence.observation,
        OutcomeObservation::Unavailable {
            status: QueryReceiptStatus::BlockedEnv
        }
    );
    let probe = provider.probe(&scope, at("2026-08-14T00:05:00Z")).await;
    assert_eq!(probe.status, ProbeStatus::BlockedEnv);
    assert_eq!(probe.provenance, Provenance::BlockedEnv);
    assert!(!probe.native);
    assert!(!probe.connected);
}

#[tokio::test]
async fn zero_events_are_observed_without_becoming_a_health_claim() {
    let scope = scope("project-a", "production");
    let page = RecordedSentryPage::new(
        SentryQueryKind::Events,
        None,
        None,
        SentryQueryResult::Events(Vec::new()),
        at("2026-08-14T00:05:00Z"),
    )
    .expect("empty page");
    let provider = provider_for(
        &scope,
        FixtureSentryTransport::new(vec![page]).expect("fixture"),
    );
    let query = event_query(scope);
    let query_as_enum = SentryQuery::events(query.clone()).expect("typed query");
    let execution = provider
        .query_events(query, &QueryCancellationToken::default())
        .await
        .expect("empty observation");
    assert_eq!(execution.receipt.status, QueryReceiptStatus::NoResults);
    let evidence = MissionOutcomeEvidenceConsumer
        .consume(&evidence_request(&query_as_enum), &execution)
        .expect("empty evidence");
    assert_eq!(evidence.observation, OutcomeObservation::NoMatchingRecords);
    assert!(!evidence.health_claim);
    assert!(!evidence.absence_is_success);
}

#[tokio::test]
async fn release_read_preserves_release_and_deployment_scope() {
    let scope = scope("project-a", "production");
    let provider = provider_for(
        &scope,
        LoopbackSentryTransport::demo(&scope).expect("loopback"),
    );
    let query = release_query(scope.clone());
    let execution = provider
        .query_releases(query, &QueryCancellationToken::default())
        .await
        .expect("release query");
    let release = match execution.result.as_ref().expect("release result") {
        SentryQueryResult::Releases(releases) => releases.first().expect("release"),
        _ => panic!("expected release result"),
    };
    assert_eq!(release.version, scope.release);
    assert_eq!(
        release.deployment_id.as_deref(),
        Some(scope.deployment_id.as_str())
    );
    assert_eq!(execution.receipt.scope_digest, scope.digest());
}

#[tokio::test]
async fn stale_and_tampered_receipts_are_rejected_by_the_consumer() {
    let scope = scope("project-a", "production");
    let provider = provider_for(
        &scope,
        LoopbackSentryTransport::demo(&scope).expect("loopback"),
    );
    let query = issue_query(scope);
    let query_as_enum = SentryQuery::issues(query.clone()).expect("typed query");
    let execution = provider
        .query_issues(query, &QueryCancellationToken::default())
        .await
        .expect("query");
    let stale = MissionOutcomeEvidenceRequest::new(
        &query_as_enum,
        query_as_enum.scope().mission_binding(),
        at("2026-08-14T00:20:00Z"),
        60,
    )
    .expect("stale request");
    assert_eq!(
        MissionOutcomeEvidenceConsumer
            .consume(&stale, &execution)
            .expect_err("stale receipt"),
        SentryOutcomeError::StaleEvidence
    );

    let mut tampered = execution;
    tampered.receipt.source_result_digest = Some("f".repeat(64));
    assert!(matches!(
        MissionOutcomeEvidenceConsumer.consume(&evidence_request(&query_as_enum), &tampered),
        Err(SentryOutcomeError::ResponseTampered)
    ));
}

#[test]
fn https_transport_requires_https_and_secret_references_do_not_hold_tokens() {
    let reference = hartevo_sentry_outcome_plugin::SecretReference::new("SENTRY_TOKEN")
        .expect("secret reference");
    let debug = format!("{reference:?}");
    assert!(!debug.contains("token-never-retained"));
    let resolver = std::sync::Arc::new(hartevo_sentry_outcome_plugin::EnvironmentSecretResolver);
    let insecure = url::Url::parse("http://sentry.invalid").expect("url");
    assert_eq!(
        hartevo_sentry_outcome_plugin::HttpsSentryTransport::new(insecure, reference, resolver)
            .expect_err("HTTP must be rejected"),
        hartevo_sentry_outcome_plugin::SentryTransportError::InvalidEndpoint
    );
}
