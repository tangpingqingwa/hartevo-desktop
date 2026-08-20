use chrono::{DateTime, Utc};
use proptest::prelude::*;

use super::*;

type TestProvider = GithubDependabotProvider<RecordingGithubDependabotTransport>;

#[derive(Clone)]
struct Fixture {
    scope: GithubDependabotScope,
    permission: PermissionFence,
    secret: SecretReference,
    request: GithubDependabotReadRequest,
}

fn at(seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(seconds, 0).expect("timestamp")
}

fn fixture() -> Fixture {
    let permission = PermissionFence::readonly(
        PermissionId::new("github-dependabot-read").expect("permission id"),
        Revision::new(1).expect("permission revision"),
    )
    .expect("permission");
    let alerts = [
        DependabotAlertBinding::new(
            AlertNumber::new(1).expect("alert number"),
            Revision::new(1).expect("alert revision"),
            PackageEcosystem::Cargo,
            "serde",
            "Cargo.lock",
        )
        .expect("first alert binding"),
        DependabotAlertBinding::new(
            AlertNumber::new(2).expect("alert number"),
            Revision::new(1).expect("alert revision"),
            PackageEcosystem::Cargo,
            "tokio",
            "Cargo.toml",
        )
        .expect("second alert binding"),
    ];
    let scope = GithubDependabotScope::new(
        DeploymentBinding::new(
            DeploymentId::new("deployment-1").expect("deployment"),
            Revision::new(1).expect("deployment revision"),
        ),
        ProjectBinding::new(
            ProjectId::new("project-1").expect("project"),
            Revision::new(4).expect("project revision"),
        ),
        MissionBinding::new(
            MissionId::new("mission-1").expect("mission"),
            Revision::new(7).expect("mission revision"),
        ),
        WorkProductBinding::new(
            WorkProductId::new("work-product-1").expect("work product"),
            Revision::new(3).expect("work product revision"),
        ),
        GithubRepository::new(
            RepositoryOwner::new("hartevo").expect("owner"),
            RepositoryName::new("supply-chain").expect("repo"),
        ),
        RefName::new("refs/heads/main").expect("ref"),
        CommitSha::new("0123456789abcdef0123456789abcdef01234567").expect("commit"),
        alerts,
        permission.digest(),
    )
    .expect("scope");
    let secret =
        SecretReference::for_scope("app-secret-ref", &scope, GithubAuthKind::App).expect("secret");
    let request = GithubDependabotReadRequest::list(&scope, AlertFilter::all(), 50, 4, None)
        .expect("request");
    Fixture {
        scope,
        permission,
        secret,
        request,
    }
}

fn alert(_fixture: &Fixture, number: u64, state: AlertState, revision: u64) -> DependabotAlert {
    let (package, manifest) = match number {
        1 => ("serde", "Cargo.lock"),
        2 => ("tokio", "Cargo.toml"),
        _ => ("serde", "Cargo.lock"),
    };
    DependabotAlert::new(
        AlertNumber::new(number).expect("alert number"),
        Revision::new(revision).expect("alert revision"),
        state,
        PackageEcosystem::Cargo,
        package,
        manifest,
        [AdvisoryIdentifier::new("GHSA-test").expect("advisory")],
        Severity::High,
        Some(750),
        Some(1200),
        at(10),
        at(20),
    )
    .expect("alert")
}

fn page(
    fixture: &Fixture,
    page_number: u16,
    alerts: Vec<DependabotAlert>,
    next_cursor: Option<OpaqueCursor>,
) -> GithubDependabotReadPage {
    GithubDependabotReadPage::new(
        &fixture.request,
        page_number,
        alerts,
        next_cursor,
        128,
        ProviderRevision::new(GITHUB_DEPENDABOT_API_REVISION).expect("provider revision"),
    )
    .expect("page")
}

fn service_with(
    _fixture: &Fixture,
    responses: impl IntoIterator<Item = Result<GithubDependabotReadPage, TransportError>>,
    provenance: TransportProvenance,
) -> TestProvider {
    GithubDependabotProvider::new(
        RecordingGithubDependabotTransport::new(responses),
        "1.0.0",
        provenance,
    )
    .expect("provider")
}

fn registered_service(
    fixture: &Fixture,
    responses: impl IntoIterator<Item = Result<GithubDependabotReadPage, TransportError>>,
    provenance: TransportProvenance,
) -> GithubDependabotResultService<RecordingGithubDependabotTransport> {
    GithubDependabotResultService::new(
        fixture.scope.clone(),
        fixture.secret.clone(),
        fixture.permission.clone(),
        service_with(fixture, responses, provenance),
    )
    .expect("service")
}

#[test]
fn complete_lifecycle_is_mission_scoped_and_non_authoritative() {
    let fixture = fixture();
    let mut service = registered_service(
        &fixture,
        [Ok(page(
            &fixture,
            1,
            vec![
                alert(&fixture, 1, AlertState::Open, 1),
                alert(&fixture, 2, AlertState::Fixed, 1),
            ],
            None,
        ))],
        TransportProvenance::Recording,
    );
    let proposal = service
        .propose(fixture.request.clone(), at(30))
        .expect("proposal");
    assert_eq!(proposal.evidence.state, DependabotEvidenceState::Open);
    assert_eq!(proposal.evidence.open_alert_count(), 1);
    assert!(!proposal.evidence.provenance.connected());
    assert!(!proposal.evidence.provenance.native());
    assert!(!proposal.evidence.provenance.first_party());

    let consumer =
        MissionGithubDependabotConsumer::new(fixture.scope.clone(), service.registration().clone())
            .expect("consumer");
    let decision = consumer.consume(proposal.clone()).expect("decision");
    assert_eq!(decision.project_id.as_str(), "project-1");
    assert_eq!(decision.mission_id.as_str(), "mission-1");
    assert_eq!(decision.work_product_id.as_str(), "work-product-1");
    assert_eq!(
        decision.decision_state,
        MissionGithubDependabotDecisionState::ReviewRequired
    );
    assert!(decision.requires_human_review);
    assert!(!decision.remediation_authority);
    assert!(!decision.safe_to_promote);
    assert!(!decision.connected);
    assert!(!decision.native);
    assert!(!decision.first_party);
    assert!(!decision.adopted_outcome);
    assert!(!decision.truth_authority);

    let receipt = service.record_at(&proposal, at(31)).expect("record");
    assert!(!receipt.raw_provider_payload_retained);
    assert!(!receipt.remediation_instructions_retained);
    assert!(!receipt.durable_receipt);
    let verified = service.verify(&receipt).expect("verify");
    assert!(verified.verified);
    assert!(!verified.connected);
    assert!(!verified.native);
    assert!(!verified.first_party);
    assert!(!verified.adopted_outcome);

    let encoded_secret = serde_json::to_string(&fixture.secret).expect("opaque secret JSON");
    assert!(!encoded_secret.contains("app-secret-ref"));
    assert!(!format!("{:?}", fixture.secret).contains("app-secret-ref"));
}

#[test]
fn scope_revision_and_digest_fences_fail_closed() {
    let fixture = fixture();
    let mut service = registered_service(
        &fixture,
        [Ok(page(
            &fixture,
            1,
            vec![alert(&fixture, 1, AlertState::Open, 1)],
            None,
        ))],
        TransportProvenance::Fixture,
    );
    let mut wrong_scope_request = fixture.request.clone();
    wrong_scope_request.scope_digest = Digest::zero();
    assert!(matches!(
        service.read(wrong_scope_request),
        Err(GithubDependabotServiceError::ScopeMismatch(_))
    ));

    let mut stale_service = registered_service(
        &fixture,
        [Ok(page(
            &fixture,
            1,
            vec![alert(&fixture, 1, AlertState::Open, 2)],
            None,
        ))],
        TransportProvenance::Fixture,
    );
    let stale = stale_service
        .read(fixture.request.clone())
        .expect("stale read");
    assert_eq!(stale.evidence.state, DependabotEvidenceState::Partial);
    assert_eq!(
        stale.evidence.partial_reason,
        Some(PartialReason::StaleAlertRevision)
    );

    let mut tampered_page = page(
        &fixture,
        1,
        vec![alert(&fixture, 1, AlertState::Open, 1)],
        None,
    );
    tampered_page.page_digest = Digest::zero();
    let mut digest_service =
        registered_service(&fixture, [Ok(tampered_page)], TransportProvenance::Fixture);
    assert!(matches!(
        digest_service.read(fixture.request.clone()),
        Err(GithubDependabotServiceError::Provider(
            GithubDependabotProviderError::MalformedResponse
        ))
    ));
}

#[test]
fn pagination_replay_and_budget_are_partial() {
    let fixture = fixture();
    let cursor = OpaqueCursor::new("page-one").expect("cursor");
    let first = page(
        &fixture,
        1,
        vec![alert(&fixture, 1, AlertState::Open, 1)],
        Some(cursor.clone()),
    );
    let second = page(
        &fixture,
        2,
        vec![alert(&fixture, 2, AlertState::Fixed, 1)],
        Some(cursor),
    );
    let mut service = registered_service(
        &fixture,
        [Ok(first), Ok(second)],
        TransportProvenance::Recording,
    );
    let replay = service.read(fixture.request.clone()).expect("replay read");
    assert_eq!(replay.evidence.state, DependabotEvidenceState::Partial);
    assert_eq!(
        replay.evidence.partial_reason,
        Some(PartialReason::CursorReplay)
    );

    let one_page_request =
        GithubDependabotReadRequest::list(&fixture.scope, AlertFilter::all(), 50, 1, None)
            .expect("one page request");
    let next = OpaqueCursor::new("page-two").expect("next cursor");
    let first = GithubDependabotReadPage::new(
        &one_page_request,
        1,
        vec![alert(&fixture, 1, AlertState::Open, 1)],
        Some(next),
        128,
        ProviderRevision::new(GITHUB_DEPENDABOT_API_REVISION).expect("revision"),
    )
    .expect("page");
    let provider = GithubDependabotProvider::new(
        RecordingGithubDependabotTransport::new([Ok(first)]),
        "1.0.0",
        TransportProvenance::Recording,
    )
    .expect("provider");
    let mut budget_service = GithubDependabotResultService::new(
        fixture.scope.clone(),
        fixture.secret.clone(),
        fixture.permission.clone(),
        provider,
    )
    .expect("service");
    let bounded = budget_service
        .read(one_page_request.clone())
        .expect("bounded read");
    assert_eq!(bounded.evidence.state, DependabotEvidenceState::Partial);
    assert_eq!(
        bounded.evidence.partial_reason,
        Some(PartialReason::PageBudget)
    );
}

#[test]
fn missing_and_filter_mismatch_never_become_no_open_alerts() {
    let fixture = fixture();
    let mut service = registered_service(
        &fixture,
        [Ok(page(
            &fixture,
            1,
            vec![alert(&fixture, 1, AlertState::Fixed, 1)],
            None,
        ))],
        TransportProvenance::Fixture,
    );
    let missing = service.read(fixture.request.clone()).expect("missing read");
    assert_eq!(missing.evidence.state, DependabotEvidenceState::Partial);
    assert_eq!(
        missing.evidence.partial_reason,
        Some(PartialReason::MissingAlert)
    );

    let mut wrong_filter = fixture.request.clone();
    wrong_filter.filter = AlertFilter::new(
        [AlertState::Open],
        [Severity::Critical],
        [PackageEcosystem::Cargo],
    )
    .expect("filter");
    let wrong_alert = alert(&fixture, 1, AlertState::Open, 1);
    let wrong_page = GithubDependabotReadPage::new(
        &wrong_filter,
        1,
        vec![wrong_alert],
        None,
        128,
        ProviderRevision::new(GITHUB_DEPENDABOT_API_REVISION).expect("revision"),
    )
    .expect("page");
    let mut filter_service =
        registered_service(&fixture, [Ok(wrong_page)], TransportProvenance::Fixture);
    assert!(matches!(
        filter_service.read(wrong_filter),
        Err(GithubDependabotServiceError::ScopeMismatch(_))
    ));
}

#[test]
fn access_loss_throttle_timeout_and_blocked_env_are_typed() {
    for error in [
        TransportError::Unauthorized,
        TransportError::Forbidden,
        TransportError::NotFound,
    ] {
        let fixture = fixture();
        let mut service =
            registered_service(&fixture, [Err(error)], TransportProvenance::Recording);
        let evidence = service.read(fixture.request.clone()).expect("access read");
        assert_eq!(evidence.evidence.state, DependabotEvidenceState::AccessLoss);
    }

    let fixture = fixture();
    let mut service = registered_service(
        &fixture,
        [
            Err(TransportError::RateLimited {
                retry_after_seconds: Some(5),
            }),
            Err(TransportError::Timeout),
            Err(TransportError::ServerFailure {
                status_code: Some(503),
            }),
        ],
        TransportProvenance::Recording,
    );
    let unknown = service.read(fixture.request.clone()).expect("retry read");
    assert_eq!(
        unknown.evidence.state,
        DependabotEvidenceState::ProviderUnknown
    );
    assert_eq!(unknown.evidence.retry_count, 2);
    assert_eq!(unknown.evidence.request_count, 3);
    assert_eq!(unknown.evidence.provider_errors.len(), 3);
    assert_eq!(unknown.evidence.provider_errors[0].status_code, Some(429));

    let not_modified_fixture = fixture.clone();
    let mut not_modified = registered_service(
        &not_modified_fixture,
        [Err(TransportError::NotModified)],
        TransportProvenance::Recording,
    );
    let unchanged = not_modified
        .read(not_modified_fixture.request.clone())
        .expect("304 error read");
    assert_eq!(
        unchanged.evidence.state,
        DependabotEvidenceState::NotModified
    );
    assert_eq!(unchanged.evidence.provider_errors[0].status_code, Some(304));

    let blocked_fixture = fixture.clone();
    let blocked_provider = GithubDependabotProvider::new(
        BlockedEnvGithubDependabotTransport,
        "1.0.0",
        TransportProvenance::BlockedEnv,
    )
    .expect("blocked provider");
    let mut blocked = GithubDependabotResultService::new(
        blocked_fixture.scope.clone(),
        blocked_fixture.secret.clone(),
        blocked_fixture.permission.clone(),
        blocked_provider,
    )
    .expect("blocked service");
    let evidence = blocked
        .read(blocked_fixture.request.clone())
        .expect("blocked read");
    assert_eq!(
        evidence.evidence.state,
        DependabotEvidenceState::ProviderUnknown
    );
    assert!(!evidence.evidence.provenance.connected());
    assert!(!evidence.evidence.provenance.native());
    assert!(!evidence.evidence.provenance.first_party());
}

#[test]
fn not_modified_redaction_tamper_and_revocation_fences_hold() {
    let fixture = fixture();
    let not_modified_page = GithubDependabotReadPage::not_modified(
        &fixture.request,
        1,
        Some(Digest::from_text("etag")),
        ProviderRevision::new(GITHUB_DEPENDABOT_API_REVISION).expect("revision"),
    )
    .expect("304 page");
    let mut service = registered_service(
        &fixture,
        [Ok(not_modified_page)],
        TransportProvenance::Recording,
    );
    let evidence = service.read(fixture.request.clone()).expect("304 read");
    assert_eq!(
        evidence.evidence.state,
        DependabotEvidenceState::NotModified
    );
    assert_eq!(
        evidence.evidence.partial_reason,
        Some(PartialReason::NotModified)
    );
    assert!(evidence.evidence.not_modified);

    let mut proposal_service = registered_service(
        &fixture,
        [Ok(page(
            &fixture,
            1,
            vec![alert(&fixture, 1, AlertState::Open, 1)],
            None,
        ))],
        TransportProvenance::Recording,
    );
    let proposal = proposal_service
        .propose(fixture.request.clone(), at(40))
        .expect("proposal");
    let mut tampered_proposal = proposal.clone();
    tampered_proposal.evidence.state = DependabotEvidenceState::Fixed;
    assert!(tampered_proposal.validate().is_err());
    assert!(
        proposal_service
            .verify_proposal(&tampered_proposal)
            .is_err()
    );
    let mut receipt = proposal_service
        .record_at(&proposal, at(41))
        .expect("receipt");
    receipt.state = DependabotEvidenceState::Fixed;
    assert!(proposal_service.verify(&receipt).is_err());

    proposal_service.revoke_registration().expect("revoke");
    assert!(!proposal_service.is_active());
    assert!(proposal_service.read(fixture.request.clone()).is_err());
    assert!(proposal_service.record(&proposal).is_err());
    assert!(proposal_service.revoke_registration().is_err());
}

#[test]
fn parser_discards_raw_description_package_manifest_and_payload() {
    let fixture = fixture();
    let body = br#"[
      {
        "number": 1,
        "state": "open",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-02T00:00:00Z",
        "dependency": {
          "package": {"ecosystem": "cargo", "name": "serde"},
          "manifest": {"path": "Cargo.lock"}
        },
        "security_advisory": {
          "ghsa_id": "GHSA-test",
          "cve_id": "CVE-2026-0001",
          "severity": "high",
          "description": "do not retain this advisory description",
          "cvss": {"score": 7.5},
          "epss": {"percentage": 0.12}
        },
        "raw_provider_payload": "discard me"
      }
    ]"#;
    let page = GithubDependabotProvider::<RecordingGithubDependabotTransport>::parse_json_page(
        &fixture.request,
        1,
        body.len(),
        body,
        ProviderRevision::new(GITHUB_DEPENDABOT_API_REVISION).expect("revision"),
    )
    .expect("parsed page");
    let encoded = serde_json::to_string(&page).expect("page JSON");
    for forbidden in [
        "do not retain this advisory description",
        "raw_provider_payload",
        "discard me",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "raw field survived: {forbidden}"
        );
    }
    assert!(encoded.contains("GHSA-test"));
    assert!(encoded.contains("cargo"));
    assert!(!encoded.contains("serde"));
    assert!(!encoded.contains("Cargo.lock"));
}

#[test]
fn registration_and_consumer_reject_tamper_and_exact_scope_drift() {
    let fixture = fixture();
    let service = registered_service(
        &fixture,
        [Ok(page(
            &fixture,
            1,
            vec![alert(&fixture, 1, AlertState::Open, 1)],
            None,
        ))],
        TransportProvenance::Fixture,
    );
    let mut registration = service.registration().clone();
    registration.scope_digest = Digest::zero();
    assert!(MissionGithubDependabotConsumer::new(fixture.scope.clone(), registration).is_err());

    let mut wrong_scope = fixture.scope.clone();
    wrong_scope.commit_sha =
        CommitSha::new("fedcba9876543210fedcba9876543210fedcba98").expect("other commit");
    assert!(
        MissionGithubDependabotConsumer::new(wrong_scope, service.registration().clone()).is_err()
    );
}

proptest! {
    #[test]
    fn opaque_cursor_debug_and_json_never_retain_input(raw in "X{1,80}") {
        let cursor = OpaqueCursor::new(&raw).expect("bounded cursor");
        let debug = format!("{cursor:?}");
        let json = serde_json::to_string(&cursor).expect("cursor JSON");
        prop_assert!(!debug.contains(&raw));
        prop_assert!(!json.contains(&raw));
    }
}
