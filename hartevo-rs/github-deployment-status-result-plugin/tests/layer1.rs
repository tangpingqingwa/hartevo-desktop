use hartevo_github_deployment_status_result_plugin as github;
use serde_json::json;

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const RAW_DEPLOYMENT_URL: &str = "https://api.github.example/repos/acme/payments/deployments/33";
const RAW_STATUS_URL: &str =
    "https://api.github.example/repos/acme/payments/deployments/33/statuses/55";
const RAW_TARGET_URL: &str = "https://payments.example/deploy/55";
const RAW_LOG_URL: &str = "https://logs.example/deploy/55";
const RAW_SECRET: &str = "host-keyring-github-deployment-status";

fn scope() -> github::GithubDeploymentStatusScope {
    let organization = github::GithubOrganization::new("acme").expect("organization");
    let repository = github::GithubRepository::new(
        organization.clone(),
        github::GithubRepositoryName::new("payments").expect("repository"),
    )
    .expect("repository");
    let spec = github::GithubDeploymentStatusScopeSpec::new(
        github::GithubAppInstallationId::new(11).expect("installation"),
        organization,
        repository,
        github::GithubDeploymentId::new(33).expect("deployment"),
        github::GithubRef::new("refs/heads/main").expect("ref"),
        github::GithubCommitSha::new(COMMIT).expect("commit"),
        github::GithubEnvironment::new("production").expect("environment"),
        github::ProjectBinding::new("project-1", 4).expect("project"),
        github::MissionBinding::new("mission-1", 5).expect("mission"),
        github::WorkProductBinding::new("work-product-1", 6).expect("work product"),
        github::GithubDeploymentStatusPermissions::read_only(7).expect("permissions"),
    );
    github::GithubDeploymentStatusScope::new(spec).expect("scope")
}

fn deployment_response(
    ref_name: &str,
    sha: &str,
    environment: &str,
    created_at: &str,
    updated_at: &str,
) -> github::GithubDeploymentStatusResponse {
    github::GithubDeploymentStatusResponse::json(
        200,
        &json!({
            "id": 33,
            "ref": ref_name,
            "sha": sha,
            "environment": environment,
            "created_at": created_at,
            "updated_at": updated_at,
            "url": RAW_DEPLOYMENT_URL,
            "statuses_url": "https://api.github.example/repos/acme/payments/deployments/33/statuses",
            "payload": {"private": "payload must not be retained"},
            "creator": {"login": "reviewer-pii-must-not-be-retained"}
        }),
    )
}

fn status_value(id: u64, state: &str, created_at: &str, updated_at: &str) -> serde_json::Value {
    json!({
        "id": id,
        "deployment_id": 33,
        "environment": "production",
        "state": state,
        "created_at": created_at,
        "updated_at": updated_at,
        "deployment_url": RAW_DEPLOYMENT_URL,
        "environment_url": "https://payments.example/environments/production",
        "target_url": RAW_TARGET_URL,
        "log_url": RAW_LOG_URL,
        "url": RAW_STATUS_URL,
        "description": "private deployment description",
        "creator": {"login": "reviewer-pii-must-not-be-retained"}
    })
}

fn statuses_response(
    values: &serde_json::Value,
    next_page: Option<github::OpaquePageToken>,
) -> github::GithubDeploymentStatusResponse {
    github::GithubDeploymentStatusResponse::json_with_headers(200, values, None, next_page)
}

fn complete_fixture() -> github::GithubDeploymentStatusFixture {
    github::GithubDeploymentStatusFixture::new(
        deployment_response(
            "refs/heads/main",
            COMMIT,
            "production",
            "2026-08-15T00:00:00Z",
            "2026-08-15T00:01:00Z",
        ),
        vec![statuses_response(
            &json!([
                status_value(
                    55,
                    "success",
                    "2026-08-15T00:02:00Z",
                    "2026-08-15T00:03:00Z"
                ),
                status_value(
                    54,
                    "in_progress",
                    "2026-08-15T00:01:30Z",
                    "2026-08-15T00:01:45Z"
                )
            ]),
            None,
        )],
    )
}

fn service_with<T: github::GithubDeploymentStatusTransport>(
    transport: T,
) -> github::GithubDeploymentStatusService<T> {
    let current_scope = scope();
    let secret = github::SecretReference::app(RAW_SECRET, &current_scope, 3)
        .expect("opaque secret reference");
    let provider = github::GithubDeploymentStatusProvider::new(current_scope, secret, transport)
        .expect("provider");
    github::GithubDeploymentStatusService::new(provider).expect("service")
}

#[test]
fn complete_read_is_bound_and_url_pii_payloads_are_digest_only() {
    let mut service = service_with(github::RecordingGithubDeploymentStatusTransport::new(
        complete_fixture(),
    ));
    let evidence = service.read().expect("evidence");
    assert_eq!(
        evidence.state,
        github::GithubDeploymentStatusEvidenceState::Complete
    );
    assert_eq!(evidence.statuses.len(), 2);
    assert_eq!(
        evidence.latest_status.as_ref().expect("latest").state,
        github::GithubDeploymentStatusState::Success
    );
    assert!(!evidence.evidence_digest.is_empty());
    assert!(!evidence.native && !evidence.connected && !evidence.durable_receipt);
    assert!(evidence.is_review_only());
    assert!(!evidence.can_be_adopted());

    let serialized = serde_json::to_string(&evidence).expect("evidence serializes");
    for raw in [
        RAW_DEPLOYMENT_URL,
        RAW_STATUS_URL,
        RAW_TARGET_URL,
        RAW_LOG_URL,
        "private deployment description",
        "reviewer-pii-must-not-be-retained",
        RAW_SECRET,
    ] {
        assert!(!serialized.contains(raw), "raw value leaked: {raw}");
    }
    let debug = format!("{service:?}");
    assert!(!debug.contains(RAW_SECRET));
    let requests = service
        .provider()
        .transport()
        .requests()
        .iter()
        .map(|request| serde_json::to_string(request).expect("request serializes"))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(!requests.contains(RAW_SECRET));
    assert!(requests.contains("/deployments/33/statuses"));

    let proposal = service.compile_proposal().expect("proposal");
    assert_eq!(
        proposal.source_evidence_digest,
        proposal.evidence.evidence_digest
    );
    assert!(proposal.is_review_only());
    assert!(!proposal.can_be_adopted());
    service
        .verify_proposal(&proposal)
        .expect("proposal verifies");
    let receipt = service.record(&proposal).expect("recording seam");
    assert!(!receipt.durable_native_receipt && !receipt.native && !receipt.connected);
}

#[test]
fn mission_consumer_rejects_replay_and_never_adopts_outcome() {
    let current_scope = scope();
    let secret = github::SecretReference::oauth("opaque-oauth-reference", &current_scope, 1)
        .expect("secret reference");
    let provider = github::GithubDeploymentStatusProvider::new(
        current_scope,
        secret,
        github::FixtureGithubDeploymentStatusTransport::new(complete_fixture()),
    )
    .expect("provider");
    let mut consumer =
        github::MissionGithubDeploymentStatusConsumer::new(provider).expect("consumer");
    let proposal = consumer.compile_proposal().expect("proposal");
    let result = consumer.consume(&proposal).expect("consume");
    assert_eq!(
        result.state,
        github::MissionGithubDeploymentStatusResultState::DecisionReady
    );
    assert_eq!(
        result.latest_provider_state,
        Some(github::GithubDeploymentStatusState::Success)
    );
    assert!(!result.adopts_outcome && !result.native && !result.connected);
    assert!(matches!(
        consumer.consume(&proposal),
        Err(github::MissionGithubDeploymentStatusConsumerError::ReplayDetected)
    ));
}

#[test]
fn deployment_sha_and_environment_binding_fail_closed() {
    let wrong_sha = github::GithubDeploymentStatusFixture::new(
        deployment_response(
            "refs/heads/main",
            "fedcba9876543210fedcba9876543210fedcba98",
            "production",
            "2026-08-15T00:00:00Z",
            "2026-08-15T00:01:00Z",
        ),
        vec![],
    );
    let evidence = service_with(github::FixtureGithubDeploymentStatusTransport::new(
        wrong_sha,
    ))
    .read()
    .expect("typed scope mismatch evidence");
    assert_eq!(
        evidence.state,
        github::GithubDeploymentStatusEvidenceState::StaleState
    );
    assert_eq!(
        evidence.provider_error.expect("provider error").kind,
        github::GithubDeploymentStatusProviderErrorKind::ScopeMismatch
    );

    let wrong_environment = github::GithubDeploymentStatusFixture::new(
        deployment_response(
            "refs/heads/main",
            COMMIT,
            "staging",
            "2026-08-15T00:00:00Z",
            "2026-08-15T00:01:00Z",
        ),
        vec![],
    );
    let evidence = service_with(github::FixtureGithubDeploymentStatusTransport::new(
        wrong_environment,
    ))
    .read()
    .expect("typed environment mismatch evidence");
    assert_eq!(
        evidence.state,
        github::GithubDeploymentStatusEvidenceState::StaleState
    );
}

#[test]
fn status_history_is_order_independent_and_truncates_at_ninety_days() {
    let fixture = github::GithubDeploymentStatusFixture::new(
        deployment_response(
            "refs/heads/main",
            COMMIT,
            "production",
            "2026-05-01T00:00:00Z",
            "2026-08-15T00:10:00Z",
        ),
        vec![statuses_response(
            &json!([
                status_value(
                    51,
                    "pending",
                    "2026-05-10T00:00:00Z",
                    "2026-05-10T00:01:00Z"
                ),
                status_value(
                    55,
                    "success",
                    "2026-08-15T00:02:00Z",
                    "2026-08-15T00:03:00Z"
                )
            ]),
            None,
        )],
    );
    let evidence = service_with(github::FixtureGithubDeploymentStatusTransport::new(fixture))
        .read()
        .expect("history evidence");
    assert_eq!(
        evidence.state,
        github::GithubDeploymentStatusEvidenceState::HistoryTruncated
    );
    assert!(evidence.history_truncated);
    assert_eq!(evidence.statuses.len(), 1);
    assert_eq!(evidence.statuses[0].id, 55);
}

#[test]
fn paginated_statuses_are_bounded_and_opaque_tokens_are_digest_only() {
    let token = github::OpaquePageToken::new("opaque-next-page-token").expect("token");
    let fixture = github::GithubDeploymentStatusFixture::new(
        deployment_response(
            "refs/heads/main",
            COMMIT,
            "production",
            "2026-08-15T00:00:00Z",
            "2026-08-15T00:10:00Z",
        ),
        vec![
            statuses_response(
                &json!([status_value(
                    54,
                    "in_progress",
                    "2026-08-15T00:01:00Z",
                    "2026-08-15T00:02:00Z"
                )]),
                Some(token.clone()),
            ),
            statuses_response(
                &json!([status_value(
                    55,
                    "success",
                    "2026-08-15T00:03:00Z",
                    "2026-08-15T00:04:00Z"
                )]),
                None,
            ),
        ],
    );
    let mut service = service_with(github::RecordingGithubDeploymentStatusTransport::new(
        fixture,
    ));
    let evidence = service.read().expect("paginated evidence");
    assert_eq!(evidence.pages_read, 2);
    assert_eq!(evidence.statuses[0].id, 55);
    assert!(!evidence.history_truncated);
    let requests = service.provider().transport().requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[2].page, 1);
    assert_eq!(
        requests[2].page_token_digest.as_deref(),
        Some(token.digest().as_str())
    );
    let serialized = serde_json::to_string(&requests[2]).expect("request serializes");
    assert!(!serialized.contains("opaque-next-page-token"));
}

#[test]
fn mismatched_pagination_binding_is_rejected() {
    let other_scope = {
        let organization = github::GithubOrganization::new("other").expect("organization");
        let repository = github::GithubRepository::new(
            organization.clone(),
            github::GithubRepositoryName::new("repo").expect("repository"),
        )
        .expect("repository");
        github::GithubDeploymentStatusScope::new(github::GithubDeploymentStatusScopeSpec::new(
            github::GithubAppInstallationId::new(2).expect("installation"),
            organization,
            repository,
            github::GithubDeploymentId::new(2).expect("deployment"),
            github::GithubRef::new("refs/heads/main").expect("ref"),
            github::GithubCommitSha::new(COMMIT).expect("commit"),
            github::GithubEnvironment::new("production").expect("environment"),
            github::ProjectBinding::new("p", 1).expect("project"),
            github::MissionBinding::new("m", 1).expect("mission"),
            github::WorkProductBinding::new("w", 1).expect("work product"),
            github::GithubDeploymentStatusPermissions::read_only(1).expect("permissions"),
        ))
        .expect("other scope")
    };
    let token = github::OpaquePageToken::for_request(
        "wrong-scope-token",
        other_scope.digest(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .expect("bound token");
    let fixture = github::GithubDeploymentStatusFixture::new(
        deployment_response(
            "refs/heads/main",
            COMMIT,
            "production",
            "2026-08-15T00:00:00Z",
            "2026-08-15T00:10:00Z",
        ),
        vec![statuses_response(&json!([]), Some(token))],
    );
    let mut service = service_with(github::FixtureGithubDeploymentStatusTransport::new(fixture));
    let error = service
        .provider_mut()
        .read()
        .expect_err("pagination mismatch");
    assert_eq!(
        error.kind,
        github::GithubDeploymentStatusProviderErrorKind::PaginationMismatch
    );
}

#[test]
fn documented_http_errors_timeout_and_blocked_env_are_typed() {
    let cases = [
        (
            400,
            github::GithubDeploymentStatusProviderErrorKind::BadRequest,
        ),
        (
            401,
            github::GithubDeploymentStatusProviderErrorKind::Unauthenticated,
        ),
        (
            403,
            github::GithubDeploymentStatusProviderErrorKind::PermissionDenied,
        ),
        (
            404,
            github::GithubDeploymentStatusProviderErrorKind::NotFound,
        ),
        (
            409,
            github::GithubDeploymentStatusProviderErrorKind::Conflict,
        ),
        (
            422,
            github::GithubDeploymentStatusProviderErrorKind::UnprocessableEntity,
        ),
        (
            429,
            github::GithubDeploymentStatusProviderErrorKind::RateLimited,
        ),
        (
            500,
            github::GithubDeploymentStatusProviderErrorKind::ServerFailure,
        ),
        (
            503,
            github::GithubDeploymentStatusProviderErrorKind::ServerFailure,
        ),
    ];
    for (status, expected) in cases {
        let fixture = github::GithubDeploymentStatusFixture::new(
            github::GithubDeploymentStatusResponse::json(
                status,
                &json!({"message": "private provider diagnostic"}),
            ),
            vec![],
        );
        let evidence = service_with(github::FixtureGithubDeploymentStatusTransport::new(fixture))
            .read()
            .expect("typed provider error evidence");
        assert_eq!(
            evidence.provider_error.as_ref().expect("error").kind,
            expected
        );
        assert!(!evidence.native && !evidence.connected);
        let serialized = serde_json::to_string(&evidence).expect("error evidence serializes");
        assert!(!serialized.contains("private provider diagnostic"));
    }

    let mut blocked = service_with(github::BlockedEnvGithubDeploymentStatusTransport);
    let evidence = blocked.read().expect("blocked env evidence");
    assert_eq!(evidence.provenance, github::TransportProvenance::BlockedEnv);
    assert_eq!(
        evidence.provider_error.expect("blocked error").kind,
        github::GithubDeploymentStatusProviderErrorKind::BlockedEnv
    );
    assert!(!evidence.native && !evidence.connected);

    let mut timeout = service_with(TimeoutTransport);
    let evidence = timeout.read().expect("timeout evidence");
    assert_eq!(
        evidence.provider_error.expect("timeout error").kind,
        github::GithubDeploymentStatusProviderErrorKind::Timeout
    );
}

#[derive(Debug)]
struct TimeoutTransport;

impl github::GithubDeploymentStatusTransport for TimeoutTransport {
    fn provenance(&self) -> github::TransportProvenance {
        github::TransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        _request: &github::GithubDeploymentStatusRequest,
    ) -> Result<github::GithubDeploymentStatusResponse, github::GithubDeploymentStatusTransportError>
    {
        Err(github::GithubDeploymentStatusTransportError::Timeout)
    }
}

#[test]
fn stale_state_tamper_and_digest_fences_fail_closed() {
    let stale = github::GithubDeploymentStatusFixture::new(
        deployment_response(
            "refs/heads/main",
            COMMIT,
            "production",
            "2026-08-15T00:00:00Z",
            "2026-08-15T00:01:00Z",
        ),
        vec![statuses_response(
            &json!([status_value(
                55,
                "success",
                "2026-08-15T00:03:00Z",
                "2026-08-15T00:02:00Z"
            )]),
            None,
        )],
    );
    let evidence = service_with(github::FixtureGithubDeploymentStatusTransport::new(stale))
        .read()
        .expect("typed stale evidence");
    assert_eq!(
        evidence.provider_error.expect("stale error").kind,
        github::GithubDeploymentStatusProviderErrorKind::StaleState
    );

    let mut service = service_with(github::FixtureGithubDeploymentStatusTransport::new(
        complete_fixture(),
    ));
    let mut proposal = service.compile_proposal().expect("proposal");
    proposal.evidence.history_truncated = true;
    assert!(matches!(
        service.verify_proposal(&proposal),
        Err(github::GithubDeploymentStatusServiceError::EvidenceMismatch)
    ));
    let mut proposal = service.compile_proposal().expect("proposal");
    proposal.proposal_digest =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
    assert!(matches!(
        service.verify_proposal(&proposal),
        Err(github::GithubDeploymentStatusServiceError::ProposalTampered)
    ));
}

#[test]
fn registration_revocation_rotates_digest_and_invalidates_old_proposals() {
    let mut service = service_with(github::FixtureGithubDeploymentStatusTransport::new(
        complete_fixture(),
    ));
    let proposal = service.compile_proposal().expect("proposal");
    let original = service.registration().registration_digest.clone();
    let revocation = service.revoke_registration().expect("revoke");
    assert_eq!(revocation.previous_registration_digest, original);
    assert_eq!(revocation.registration_revision.value(), 2);
    assert_ne!(service.registration().registration_digest, original);
    assert!(matches!(
        service.read(),
        Err(github::GithubDeploymentStatusServiceError::RegistrationRevoked)
    ));
    service.restore_registration().expect("restore");
    assert_eq!(service.registration().registration_revision.value(), 3);
    assert_ne!(service.registration().registration_digest, original);
    assert!(matches!(
        service.verify_proposal(&proposal),
        Err(github::GithubDeploymentStatusServiceError::EvidenceMismatch)
    ));
    let restored = service.compile_proposal().expect("restored proposal");
    assert_ne!(restored.registration_digest, original);
}

#[test]
fn zero_revisions_and_incomplete_permissions_are_rejected() {
    assert!(github::Revision::new(0).is_err());
    assert!(github::GithubDeploymentStatusPermissions::read_only(0).is_err());
    assert!(
        github::GithubDeploymentStatusPermissions::new(
            [github::GithubDeploymentStatusPermission::DeploymentsRead],
            1,
        )
        .is_err()
    );
    assert!(github::ProjectBinding::new("project-1", 0).is_err());
    assert!(github::MissionBinding::new("mission-1", 0).is_err());
    assert!(github::WorkProductBinding::new("work-product-1", 0).is_err());
}

#[test]
fn all_non_native_transports_remain_honest() {
    let mut fixture = service_with(github::FixtureGithubDeploymentStatusTransport::new(
        complete_fixture(),
    ));
    let fixture_proposal = fixture.compile_proposal().expect("fixture proposal");
    assert_eq!(
        fixture_proposal.evidence.provenance,
        github::TransportProvenance::Fixture
    );
    assert!(!fixture_proposal.native && !fixture_proposal.connected);

    let mut recording = service_with(github::RecordingGithubDeploymentStatusTransport::new(
        complete_fixture(),
    ));
    let recording_proposal = recording.compile_proposal().expect("recording proposal");
    assert_eq!(
        recording_proposal.evidence.provenance,
        github::TransportProvenance::Recording
    );
    assert!(!recording_proposal.native && !recording_proposal.connected);

    let mut loopback = service_with(github::LoopbackGithubDeploymentStatusTransport::new(
        complete_fixture(),
    ));
    let loopback_proposal = loopback.compile_proposal().expect("loopback proposal");
    assert_eq!(
        loopback_proposal.evidence.provenance,
        github::TransportProvenance::Loopback
    );
    assert!(!loopback_proposal.native && !loopback_proposal.connected);
}
