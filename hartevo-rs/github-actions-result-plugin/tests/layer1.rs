use hartevo_github_actions_result_plugin as github;
use serde_json::json;

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const ARTIFACT_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn scope() -> github::GithubActionsScope {
    let organization = github::GithubOrganization::new("acme").expect("organization");
    let repository = github::GithubRepository::new(
        organization.clone(),
        github::GithubRepositoryName::new("payments").expect("repository"),
    )
    .expect("repository scope");
    let spec = github::GithubActionsScopeSpec::new(
        github::GithubAppInstallationId::new(11).expect("installation"),
        organization,
        repository,
        github::GithubWorkflowId::new(22).expect("workflow"),
        github::GithubWorkflowRunId::new(33).expect("run"),
        github::GithubJobId::new(44).expect("job"),
        github::GithubRunAttempt::new(2).expect("attempt"),
        github::GithubCommitSha::new(COMMIT).expect("commit"),
        github::ProjectBinding::new("project-1", 4).expect("project"),
        github::MissionBinding::new("mission-1", 5).expect("mission"),
        github::WorkProductBinding::new("work-product-1", 6).expect("work product"),
        github::GithubActionsPermissions::read_only(7).expect("permissions"),
    );
    github::GithubActionsScope::new(spec).expect("scope")
}

fn run_response(
    status: &str,
    conclusion: Option<&str>,
    head_sha: &str,
) -> github::GithubActionsResponse {
    github::GithubActionsResponse::json(
        200,
        &json!({
            "id": 33,
            "workflow_id": 22,
            "run_attempt": 2,
            "status": status,
            "conclusion": conclusion,
            "head_sha": head_sha,
            "created_at": "2026-08-15T00:00:00Z",
            "updated_at": "2026-08-15T00:01:00Z",
            "run_started_at": "2026-08-15T00:00:01Z"
        }),
    )
}

fn jobs_response(jobs: &serde_json::Value) -> github::GithubActionsResponse {
    github::GithubActionsResponse::json(
        200,
        &json!({
            "total_count": jobs.as_array().map_or(0, Vec::len),
            "jobs": jobs
        }),
    )
}

fn artifacts_response(artifacts: &serde_json::Value) -> github::GithubActionsResponse {
    github::GithubActionsResponse::json(
        200,
        &json!({
            "total_count": artifacts.as_array().map_or(0, Vec::len),
            "artifacts": artifacts
        }),
    )
}

fn completed_fixture() -> github::GithubActionsFixture {
    github::GithubActionsFixture::new(
        run_response("completed", Some("success"), COMMIT),
        vec![jobs_response(&json!([
            {
                "id": 44,
                "name": "test",
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-08-15T00:00:02Z",
                "completed_at": "2026-08-15T00:00:30Z"
            }
        ]))],
        vec![artifacts_response(&json!([
            {
                "id": 55,
                "name": "bounded-report",
                "size_in_bytes": 128,
                "digest": format!("sha256:{ARTIFACT_DIGEST}"),
                "expired": false,
                "expires_at": "2026-09-15T00:00:00Z"
            }
        ]))],
    )
}

fn service_with<T: github::GithubActionsTransport>(
    transport: T,
) -> github::GithubActionsResultService<T> {
    let current_scope = scope();
    let secret = github::SecretReference::app("host-keyring-github-app", &current_scope, 3)
        .expect("secret reference");
    let provider =
        github::GithubActionsProvider::new(current_scope, secret, transport).expect("provider");
    github::GithubActionsResultService::new(provider).expect("service")
}

#[test]
fn bounded_metadata_proposal_and_recording_are_digest_fenced() {
    let mut service = service_with(github::RecordingGithubActionsTransport::new(
        completed_fixture(),
    ));
    let proposal = service.compile_proposal().expect("proposal");
    assert_eq!(
        proposal.evidence.state,
        github::GithubActionsEvidenceState::Complete
    );
    assert_eq!(proposal.evidence.jobs.len(), 1);
    assert_eq!(proposal.evidence.artifacts.len(), 1);
    assert!(!proposal.evidence.version_digest.is_empty());
    assert!(!proposal.evidence.contract_digest.is_empty());
    assert!(!proposal.evidence.provider_digest.is_empty());
    assert!(!proposal.evidence.permission_digest.is_empty());
    assert!(!proposal.evidence.scope_digest.is_empty());
    assert!(!proposal.evidence.evidence_digest.is_empty());
    assert!(!proposal.native && !proposal.connected && !proposal.green_ci_claim);
    assert!(!proposal.evidence.authority.native);
    assert!(!proposal.evidence.authority.connected);
    assert!(!proposal.evidence.authority.outcome_authority);

    let serialized = serde_json::to_string(&proposal).expect("proposal serializes");
    assert!(!serialized.contains("host-keyring-github-app"));
    assert!(!serialized.contains("artifactZip"));
    let recording = service
        .provider()
        .transport()
        .requests()
        .iter()
        .map(|request| serde_json::to_string(request).expect("request serializes"))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(!recording.contains("host-keyring-github-app"));
    assert!(recording.contains("workflow_run"));
    assert!(recording.contains("/repos/"));

    let receipt = service.record(&proposal).expect("recording receipt");
    assert!(!receipt.durable_native_receipt);
    assert!(!receipt.native && !receipt.connected);
    service.verify(&proposal).expect("proposal verifies");
}

#[test]
fn mission_consumer_rejects_replay_and_never_adopts_outcome() {
    let current_scope = scope();
    let secret = github::SecretReference::oauth("opaque-oauth-reference", &current_scope, 1)
        .expect("secret reference");
    let provider = github::GithubActionsProvider::new(
        current_scope,
        secret,
        github::FixtureGithubActionsTransport::new(completed_fixture()),
    )
    .expect("provider");
    let mut consumer = github::MissionGithubActionsConsumer::new(provider).expect("consumer");
    let proposal = consumer.compile_proposal().expect("proposal");
    let result = consumer.consume(&proposal).expect("consume");
    assert_eq!(
        result.state,
        github::MissionGithubActionsResultState::DecisionReady
    );
    assert!(!result.adopts_outcome && !result.native && !result.connected);
    assert!(!result.green_ci_claim);
    assert!(matches!(
        consumer.consume(&proposal),
        Err(github::MissionGithubActionsConsumerError::ReplayDetected)
    ));
}

#[test]
fn missing_jobs_are_partial_and_do_not_become_green_ci() {
    let fixture = github::GithubActionsFixture::new(
        run_response("completed", Some("success"), COMMIT),
        vec![jobs_response(&json!([]))],
        vec![artifacts_response(&json!([]))],
    );
    let mut service = service_with(github::FixtureGithubActionsTransport::new(fixture));
    let evidence = service.read().expect("typed partial evidence");
    assert_eq!(evidence.state, github::GithubActionsEvidenceState::Partial);
    assert!(evidence.run.is_none());
    assert!(!evidence.green_ci_claim && !evidence.authority.green_ci_authority);
}

#[test]
fn status_transitions_and_expired_artifacts_fail_closed() {
    let in_progress = github::GithubActionsFixture::new(
        run_response("in_progress", None, COMMIT),
        vec![jobs_response(&json!([
            { "id": 44, "name": "test", "status": "in_progress", "conclusion": null, "started_at": null, "completed_at": null }
        ]))],
        vec![artifacts_response(&json!([]))],
    );
    let mut service = service_with(github::FixtureGithubActionsTransport::new(in_progress));
    assert_eq!(
        service.read().expect("in-progress evidence").state,
        github::GithubActionsEvidenceState::RunInProgress
    );

    let expired = github::GithubActionsFixture::new(
        run_response("completed", Some("failure"), COMMIT),
        vec![jobs_response(&json!([
            { "id": 44, "name": "test", "status": "completed", "conclusion": "failure", "started_at": null, "completed_at": null }
        ]))],
        vec![artifacts_response(&json!([
            { "id": 55, "name": "old", "size_in_bytes": 1, "digest": format!("sha256:{ARTIFACT_DIGEST}"), "expired": true, "expires_at": "2026-08-01T00:00:00Z" }
        ]))],
    );
    let mut service = service_with(github::FixtureGithubActionsTransport::new(expired));
    assert_eq!(
        service.read().expect("expired evidence").state,
        github::GithubActionsEvidenceState::ArtifactExpired
    );
}

#[test]
fn etag_and_opaque_pagination_are_redacted_and_replayed() {
    let etag = github::OpaqueEtag::new("W/\"run-v1\"").expect("etag");
    let cursor = github::OpaquePageToken::new("opaque-next-page-token").expect("cursor");
    let fixture = github::GithubActionsFixture::new(
        github::GithubActionsResponse::json_with_headers(
            200,
            &json!({
                "id": 33, "workflow_id": 22, "run_attempt": 2, "status": "completed",
                "conclusion": "success", "head_sha": COMMIT,
                "created_at": "2026-08-15T00:00:00Z", "updated_at": "2026-08-15T00:01:00Z",
                "run_started_at": "2026-08-15T00:00:01Z"
            }),
            Some(etag.clone()),
            None,
        ),
        vec![
            github::GithubActionsResponse::json_with_headers(
                200,
                &json!({
                    "total_count": 2,
                    "jobs": [{ "id": 44, "name": "test", "status": "completed", "conclusion": "success", "started_at": null, "completed_at": null }]
                }),
                None,
                Some(cursor.clone()),
            ),
            github::GithubActionsResponse::json(
                200,
                &json!({
                    "total_count": 2,
                    "jobs": [{ "id": 45, "name": "lint", "status": "completed", "conclusion": "success", "started_at": null, "completed_at": null }]
                }),
            ),
        ],
        vec![artifacts_response(&json!([]))],
    );
    let mut service = service_with(github::RecordingGithubActionsTransport::new(fixture));
    let first = service.read().expect("first page read");
    assert_eq!(first.state, github::GithubActionsEvidenceState::Complete);
    let second = service.read().expect("etag replay");
    assert_eq!(first.run, second.run);
    assert_eq!(first.response_digest, second.response_digest);
    let requests = service.provider().transport().requests();
    assert_eq!(requests[1].page, 0);
    assert!(requests[2].page_token_digest.is_some());
    assert!(requests[4].etag_digest.is_some());
    let serialized = serde_json::to_string(&requests[2]).expect("request serializes");
    assert!(!serialized.contains("opaque-next-page-token"));
    assert!(!serialized.contains("run-v1"));
}

#[test]
fn http_errors_and_blocked_env_never_claim_connection() {
    let unauthorized = github::GithubActionsFixture::new(
        github::GithubActionsResponse::json(401, &json!({ "message": "secret diagnostic" })),
        vec![jobs_response(&json!([]))],
        vec![artifacts_response(&json!([]))],
    );
    let mut service = service_with(github::FixtureGithubActionsTransport::new(unauthorized));
    let evidence = service.read().expect("access loss evidence");
    assert_eq!(
        evidence.state,
        github::GithubActionsEvidenceState::AccessLost
    );
    assert!(!evidence.connected && !evidence.native);
    let serialized = serde_json::to_string(&evidence).expect("evidence serializes");
    assert!(!serialized.contains("secret diagnostic"));

    let blocked_scope = scope();
    let blocked_secret =
        github::SecretReference::app("blocked-secret", &blocked_scope, 1).expect("blocked secret");
    let provider = github::GithubActionsProvider::new(
        blocked_scope,
        blocked_secret,
        github::BlockedEnvGithubActionsTransport,
    )
    .expect("blocked provider");
    let mut blocked = github::GithubActionsResultService::new(provider).expect("blocked service");
    let evidence = blocked.read().expect("blocked evidence");
    assert_eq!(evidence.provenance, github::TransportProvenance::BlockedEnv);
    assert!(!evidence.connected && !evidence.native);
}

#[derive(Debug)]
struct TimeoutTransport;

impl github::GithubActionsTransport for TimeoutTransport {
    fn provenance(&self) -> github::TransportProvenance {
        github::TransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        _request: &github::GithubActionsRequest,
    ) -> Result<github::GithubActionsResponse, github::GithubActionsTransportError> {
        Err(github::GithubActionsTransportError::Timeout)
    }
}

#[test]
fn documented_http_statuses_and_timeout_fail_closed() {
    let cases = [
        (400, github::GithubActionsEvidenceState::ProviderUnknown),
        (403, github::GithubActionsEvidenceState::AccessLost),
        (404, github::GithubActionsEvidenceState::AccessLost),
        (409, github::GithubActionsEvidenceState::ProviderUnknown),
        (429, github::GithubActionsEvidenceState::RateLimited),
        (500, github::GithubActionsEvidenceState::ProviderUnknown),
        (503, github::GithubActionsEvidenceState::ProviderUnknown),
    ];
    for (status, expected) in cases {
        let fixture = github::GithubActionsFixture::new(
            github::GithubActionsResponse::json(
                status,
                &json!({ "message": "bounded diagnostic" }),
            ),
            vec![jobs_response(&json!([]))],
            vec![artifacts_response(&json!([]))],
        );
        let mut service = service_with(github::FixtureGithubActionsTransport::new(fixture));
        let evidence = service.read().expect("typed HTTP error evidence");
        assert_eq!(evidence.state, expected);
        assert!(!evidence.native && !evidence.connected);
    }

    let mut service = service_with(TimeoutTransport);
    let evidence = service.read().expect("typed timeout evidence");
    assert_eq!(
        evidence.state,
        github::GithubActionsEvidenceState::ProviderUnknown
    );
    assert!(!evidence.native && !evidence.connected);
}

#[test]
fn registration_is_reversible_and_old_proposals_are_stale() {
    let mut service = service_with(github::FixtureGithubActionsTransport::new(
        completed_fixture(),
    ));
    let proposal = service.compile_proposal().expect("proposal");
    let original = service.registration().registration_digest.clone();
    let revocation = service.revoke_registration().expect("revoke");
    assert_eq!(revocation.previous_registration_digest, original);
    assert_ne!(service.registration().registration_digest, original);
    assert!(matches!(
        service.read(),
        Err(github::GithubActionsResultServiceError::RegistrationRevoked)
    ));
    service.restore_registration().expect("restore");
    assert_ne!(service.registration().registration_digest, original);
    assert!(service.verify(&proposal).is_err());
    let restored = service.compile_proposal().expect("restored proposal");
    assert_ne!(restored.registration_digest, original);
}
