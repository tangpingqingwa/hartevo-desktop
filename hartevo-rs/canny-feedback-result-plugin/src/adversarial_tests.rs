use super::*;

const FIXTURE_BODY: &str = r#"{
  "board": {"id": "board-1", "postCount": 1, "isPrivate": false, "name": "Roadmap"},
  "posts": [{
    "id": "post-1",
    "status": "planned",
    "category": {"id": "cat-1", "name": "Product"},
    "roadmaps": [{"id": "roadmap-1", "name": "Now"}],
    "commentCount": 1,
    "score": 3,
    "title": "A feedback title that is deliberately not retained"
  }],
  "comments": [{
    "id": "comment-1",
    "postID": "post-1",
    "body": "A comment containing alice@example.com must be dropped",
    "author": {"email": "alice@example.com", "name": "Alice"}
  }],
  "votes": [{
    "id": "vote-1",
    "postID": "post-1",
    "user": {"email": "voter@example.com"}
  }],
  "statusChanges": [{"id": "change-1", "postID": "post-1", "status": "planned"}],
  "categories": [{"id": "cat-1", "boardID": "board-1", "postCount": 1}],
  "roadmaps": [{"id": "roadmap-1", "postCount": 1, "archived": false}],
  "hasMore": false
}"#;

fn scope() -> CannyFeedbackScope {
    CannyFeedbackScope::new(
        ProjectScope::new("project-1", 2).expect("project"),
        WorkspaceScope::new("workspace-1", 2).expect("workspace"),
        BoardScope::new("board-1", 3).expect("board"),
        PostScope::new("post-1", 4).expect("post"),
        CommentScope::all(5).expect("comments"),
        VoteWindow::new("2026-08-01", "2026-08-15", 6).expect("vote window"),
        StatusScope::strict_default(7).expect("statuses"),
        CategoryScope::new(8, [CategoryId::new("cat-1").expect("category")]).expect("categories"),
        RoadmapScope::all(9).expect("roadmaps"),
        MissionScope::new("mission-1", 10).expect("Mission"),
        WorkProductScope::new("work-product-1", 11).expect("Work Product"),
        PrivacyPolicy::strict_v1(),
    )
    .expect("scope")
}

fn request(scope: &CannyFeedbackScope, key: &str) -> CannyFeedbackResultRequest {
    CannyFeedbackResultRequest::new(
        scope,
        Timestamp::new(1_723_680_000).expect("timestamp"),
        IdempotencyKey::new(key).expect("idempotency key"),
    )
    .expect("request")
}

fn secret(scope: &CannyFeedbackScope) -> SecretReference {
    SecretReference::api_key("vault://canny/api-key", scope, 3).expect("secret")
}

fn make_service(scope: CannyFeedbackScope) -> CannyFeedbackResultService<FixtureCannyTransport> {
    let secret = secret(&scope);
    CannyFeedbackResultService::new(
        scope,
        secret,
        CannyProvider::new(FixtureCannyTransport::new(FIXTURE_BODY)).expect("provider"),
    )
    .expect("service")
}

fn assert_non_native<T: CannyFeedbackTransport>(
    mut provider: CannyProvider<T>,
    request: &CannyFeedbackResultRequest,
    secret: &SecretReference,
) {
    let evidence = provider.read(request, secret).expect("evidence");
    assert!(!evidence.provenance.native());
    assert!(!evidence.provenance.connected());
    assert!(evidence.redactions.is_strict());
}

#[test]
fn fixture_read_is_bounded_redacted_and_mission_consumable() {
    let scope = scope();
    let mut service = make_service(scope.clone());
    let proposal = service.read(request(&scope, "read-1")).expect("proposal");
    assert_eq!(proposal.status, CannyFeedbackResultStatus::Planned);
    assert_eq!(proposal.evidence.posts.len(), 1);
    assert_eq!(proposal.evidence.comments.len(), 1);
    assert_eq!(proposal.evidence.vote_aggregates[0].count, 1);
    assert!(proposal.evidence.redactions.is_strict());
    assert!(proposal.evidence.redactions.voter_identity_dropped > 0);
    assert!(proposal.evidence.redactions.author_identity_dropped > 0);
    assert!(!proposal.connected);
    assert!(!proposal.native_provider);
    assert!(!proposal.feedback_mutation);
    assert!(!proposal.voter_pii_included);
    assert!(!proposal.causal_demand_claim);
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!serialized.contains("alice@example.com"));
    assert!(!serialized.contains("A comment containing"));

    let mut consumer =
        MissionCannyFeedbackConsumer::new_bound(scope, proposal.registration_digest.clone());
    let result = consumer.consume(proposal.clone()).expect("consume");
    assert_eq!(result.state, MissionResultState::Planned);
    assert!(!result.connected);
    assert!(!result.native_provider);
    assert!(!result.adopted_work_product);
    assert!(!result.outcome_authority);
    assert_eq!(consumer.consumed_count(), 1);
    assert_eq!(
        consumer.consume(proposal).expect_err("replay"),
        ConsumerError::Replay
    );
}

#[test]
fn all_layer_one_provenances_are_non_native() {
    let scope = scope();
    let request = request(&scope, "provenance");
    let secret = secret(&scope);
    assert_non_native(
        CannyProvider::new(FixtureCannyTransport::new(FIXTURE_BODY)).expect("fixture"),
        &request,
        &secret,
    );
    assert_non_native(
        CannyProvider::new(RecordingCannyTransport::new(FIXTURE_BODY)).expect("recording"),
        &request,
        &secret,
    );
    assert_non_native(
        CannyProvider::new(FakeCannyTransport::new(FIXTURE_BODY)).expect("fake"),
        &request,
        &secret,
    );
    assert_non_native(
        CannyProvider::new(LoopbackCannyTransport::new(FIXTURE_BODY)).expect("loopback"),
        &request,
        &secret,
    );
    let mut blocked = CannyProvider::new(BlockedEnvCannyTransport).expect("blocked provider");
    let evidence = blocked.read(&request, &secret).expect("blocked evidence");
    assert_eq!(evidence.status, CannyFeedbackResultStatus::ProviderUnknown);
    assert_eq!(evidence.error, Some(ProviderErrorKind::BlockedEnv));
    assert_eq!(evidence.provenance, ProviderProvenance::BlockedEnv);
    assert!(!evidence.provenance.native());
}

#[test]
fn idempotency_is_digest_bound_and_does_not_reread_recording_transport() {
    let scope = scope();
    let secret = secret(&scope);
    let provider =
        CannyProvider::new(RecordingCannyTransport::new(FIXTURE_BODY)).expect("recording provider");
    let mut service =
        CannyFeedbackResultService::new(scope.clone(), secret, provider).expect("service");
    let first_request = request(&scope, "same-key");
    let first = service.read(first_request.clone()).expect("first");
    let second = service.read(first_request).expect("same request");
    assert_eq!(first, second);
    assert_eq!(service.provider().transport().request_count(), 1);
    let conflicting = CannyFeedbackResultRequest::new(
        &scope,
        Timestamp::new(1_723_680_001).expect("timestamp"),
        IdempotencyKey::new("same-key").expect("key"),
    )
    .expect("request");
    assert_eq!(
        service.read(conflicting).expect_err("conflict"),
        CannyFeedbackResultServiceError::IdempotencyConflict
    );
}

#[test]
fn revision_scope_and_tamper_fences_fail_closed() {
    let scope = scope();
    let mut service = make_service(scope.clone());
    let stale_mission = request(&scope, "stale-mission")
        .with_mission_revision(Revision::new(99).expect("revision"));
    assert_eq!(
        service.read(stale_mission).expect_err("stale Mission"),
        CannyFeedbackResultServiceError::RequestOutOfScope
    );
    let scope_tamper =
        request(&scope, "scope-tamper").with_scope_digest(Digest::from_text("different-scope"));
    assert_eq!(
        service.read(scope_tamper).expect_err("scope tamper"),
        CannyFeedbackResultServiceError::RequestOutOfScope
    );
    let proposal = service
        .read(request(&scope, "proposal-tamper"))
        .expect("proposal");
    let mut tampered = proposal.clone();
    tampered.evidence.posts[0].vote_count = 9_999;
    assert_eq!(
        service.verify(&tampered).expect_err("tampered proposal"),
        CannyFeedbackResultServiceError::ProposalTampered
    );
}

#[test]
fn rate_limit_partial_access_loss_and_denied_are_typed() {
    let scope = scope();
    let secret = secret(&scope);
    let cases = [
        (
            CannyHttpResponse::new(429, "{}"),
            CannyFeedbackResultStatus::RateLimited,
            ProviderErrorKind::RateLimited,
        ),
        (
            CannyHttpResponse::partial(FIXTURE_BODY),
            CannyFeedbackResultStatus::Partial,
            ProviderErrorKind::Partial,
        ),
        (
            CannyHttpResponse::new(404, "{}"),
            CannyFeedbackResultStatus::AccessLost,
            ProviderErrorKind::AccessLost,
        ),
        (
            CannyHttpResponse::new(403, "{}"),
            CannyFeedbackResultStatus::Denied,
            ProviderErrorKind::Denied,
        ),
    ];
    for (response, status, error) in cases {
        let provider =
            CannyProvider::new(RecordingCannyTransport::from_response(response)).expect("provider");
        let mut provider = provider;
        let evidence = provider
            .read(&request(&scope, "error-case"), &secret)
            .expect("typed error evidence");
        assert_eq!(evidence.status, status);
        assert_eq!(evidence.error, Some(error));
    }
}

#[test]
fn registration_and_secret_revoke_are_digest_bound_and_reversible_receipted() {
    let scope = scope();
    let secret = secret(&scope);
    let provider = CannyProvider::new(FixtureCannyTransport::new(FIXTURE_BODY)).expect("provider");
    let mut service =
        CannyFeedbackResultService::new(scope.clone(), secret, provider).expect("service");
    let registration_digest = service.registration_digest().clone();
    let revocation = service.revoke_registration().expect("revoke");
    assert_eq!(revocation.registration_digest, registration_digest);
    assert!(revocation.reversible);
    assert_eq!(
        service
            .read(request(&scope, "after-revoke"))
            .expect_err("revoked"),
        CannyFeedbackResultServiceError::RegistrationRevoked
    );

    let mut second = make_service(scope.clone());
    second.revoke_secret().expect("revoke secret");
    assert_eq!(
        second
            .read(request(&scope, "secret-revoked"))
            .expect_err("secret revoked"),
        CannyFeedbackResultServiceError::SecretRevoked
    );
}

#[test]
fn secret_reference_is_opaque_and_non_serializing() {
    let scope = scope();
    let secret = SecretReference::api_key("super-secret-api-key", &scope, 1).expect("secret");
    let serialized = serde_json::to_string(&secret).expect("secret JSON");
    assert_eq!(serialized, r#"{"opaque":true}"#);
    assert!(!format!("{secret:?}").contains("super-secret-api-key"));
    assert!(secret.is_opaque());
}
