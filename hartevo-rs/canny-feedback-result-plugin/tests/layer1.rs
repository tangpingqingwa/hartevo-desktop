use hartevo_canny_feedback_result_plugin::{
    BoardScope, CANNY_MAX_REQUESTS_PER_SCOPE_PER_UTC_HOUR, CannyFeedbackResultRequest,
    CannyFeedbackResultStatus, CannyFeedbackScope, CannyProvider, CategoryId, CategoryScope,
    CommentScope, IdempotencyKey, MissionScope, PostScope, PrivacyPolicy, ProjectScope,
    ProviderErrorKind, RoadmapScope, SecretReference, StatusScope, Timestamp, VoteWindow,
    WorkProductScope,
};

const BODY: &str = r#"{
  "board": {"id":"board-1","postCount":1},
  "posts": [{"id":"post-1","status":"open","category":{"id":"cat-1"},"commentCount":0,"score":2}],
  "items": [{"id":"vote-1","post":{"id":"post-1"},"user":{"id":"voter-1"}}]
}"#;

fn scope() -> CannyFeedbackScope {
    CannyFeedbackScope::new(
        ProjectScope::new("project-1", 1).expect("project"),
        hartevo_canny_feedback_result_plugin::WorkspaceScope::new("workspace-1", 1)
            .expect("workspace"),
        BoardScope::new("board-1", 1).expect("board"),
        PostScope::new("post-1", 1).expect("post"),
        CommentScope::all(1).expect("comment"),
        VoteWindow::new("2026-01-01", "2026-01-02", 1).expect("window"),
        StatusScope::strict_default(1).expect("status"),
        CategoryScope::new(1, [CategoryId::new("cat-1").expect("category")])
            .expect("category scope"),
        RoadmapScope::all(1).expect("roadmap"),
        MissionScope::new("mission-1", 1).expect("Mission"),
        WorkProductScope::new("work-product-1", 1).expect("Work Product"),
        PrivacyPolicy::strict_v1(),
    )
    .expect("scope")
}

fn request(scope: &CannyFeedbackScope, key: &str) -> CannyFeedbackResultRequest {
    CannyFeedbackResultRequest::new(
        scope,
        Timestamp::new(3_600).expect("timestamp"),
        IdempotencyKey::new(key).expect("key"),
    )
    .expect("request")
}

#[test]
fn public_provider_constructors_cover_fixture_loopback_and_blocked_env() {
    let scope = scope();
    let secret = SecretReference::api_key("vault://canny/key", &scope, 1).expect("secret");
    let request = request(&scope, "public-provider");
    let mut fixture = CannyProvider::fixture(BODY);
    let evidence = fixture.read(&request, &secret).expect("fixture evidence");
    assert_eq!(evidence.status, CannyFeedbackResultStatus::Open);
    assert_eq!(evidence.vote_aggregates[0].count, 1);

    let mut loopback = CannyProvider::loopback(BODY);
    assert!(
        !loopback
            .read(&request, &secret)
            .expect("loopback evidence")
            .provenance
            .is_native()
    );

    let mut blocked = CannyProvider::blocked_env();
    let blocked = blocked.read(&request, &secret).expect("blocked evidence");
    assert_eq!(blocked.error, Some(ProviderErrorKind::BlockedEnv));
    assert!(!blocked.provenance.is_native());
}

#[test]
fn public_provider_quota_returns_bounded_rate_limit_with_backoff() {
    let scope = scope();
    let secret = SecretReference::api_key("vault://canny/key", &scope, 1).expect("secret");
    let mut provider = CannyProvider::fake(BODY);
    for index in 0..CANNY_MAX_REQUESTS_PER_SCOPE_PER_UTC_HOUR {
        let evidence = provider
            .read(&request(&scope, &format!("quota-{index}")), &secret)
            .expect("bounded read");
        assert_ne!(evidence.status, CannyFeedbackResultStatus::RateLimited);
    }
    let evidence = provider
        .read(&request(&scope, "quota-overflow"), &secret)
        .expect("typed rate limit");
    assert_eq!(evidence.status, CannyFeedbackResultStatus::RateLimited);
    assert_eq!(evidence.error, Some(ProviderErrorKind::RateLimited));
    assert_eq!(evidence.retry_after_seconds, Some(60));
}
