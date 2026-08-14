use chrono::{DateTime, Duration, Utc};
use hartevo_frameio_review_result_plugin::{
    AccountId, AssetId, AssetVersionId, BlockedEnvFrameIoTransport, ConsentScope, Digest,
    FRAME_IO_REVIEW_RESULT_CONTRACT_VERSION, FRAME_IO_REVIEW_RESULT_PLUGIN_VERSION,
    FixtureFrameIoTransport, FrameIoApprovalStatus, FrameIoApprovalSummary, FrameIoAssetSummary,
    FrameIoBounds, FrameIoCommentSummary, FrameIoGetRequest, FrameIoProjectId, FrameIoProvider,
    FrameIoProviderError, FrameIoReadOperation, FrameIoReviewLinkState, FrameIoReviewLinkSummary,
    FrameIoReviewProposalRequest, FrameIoReviewResultService, FrameIoReviewStatus,
    FrameIoRevisionFence, FrameIoScope, FrameIoSnapshot, FrameIoTransportError,
    FrameIoTransportProvenance, FrameIoVersionSummary, LoopbackFrameIoTransport,
    MissionFrameIoReviewConsumer, MissionFrameIoReviewState, MissionId, ModelError, OpaqueCursor,
    ProjectId, RecordingFrameIoTransport, Revision, SecretReference, WorkProductId,
    contract_digest,
};

const AT: &str = "2026-08-14T12:00:00Z";

fn at() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(AT)
        .expect("fixed test time")
        .with_timezone(&Utc)
}

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("non-zero revision")
}

fn all_operations() -> [FrameIoReadOperation; 5] {
    [
        FrameIoReadOperation::AssetMetadata,
        FrameIoReadOperation::AssetVersion,
        FrameIoReadOperation::ReviewLink,
        FrameIoReadOperation::ApprovalStatus,
        FrameIoReadOperation::CommentSummary,
    ]
}

struct Fixture {
    scope: FrameIoScope,
    secret: SecretReference,
    bounds: FrameIoBounds,
    window: hartevo_frameio_review_result_plugin::ObservationWindow,
    snapshot: FrameIoSnapshot,
}

fn fixture() -> Fixture {
    let now = at();
    let consent = ConsentScope::new(
        all_operations(),
        now + Duration::days(2),
        Digest::from_text("human-consent-frameio-review-v1"),
    )
    .expect("consent");
    let scope = FrameIoScope::new(
        AccountId::new("account-1").expect("account"),
        FrameIoProjectId::new("frameio-project-1").expect("Frame.io project"),
        AssetId::new("asset-1").expect("asset"),
        AssetVersionId::new("version-7").expect("version"),
        hartevo_frameio_review_result_plugin::ReviewLinkId::new("review-link-1")
            .expect("review link"),
        ProjectId::new("hartevo-project-1").expect("project"),
        revision(4),
        MissionId::new("mission-1").expect("mission"),
        revision(9),
        WorkProductId::new("creative-work-product-1").expect("work product"),
        revision(12),
        Digest::from_text("permission-snapshot-v1"),
        consent,
        FrameIoRevisionFence {
            asset_revision: revision(20),
            version_revision: revision(21),
            review_link_revision: revision(22),
            comment_revision: revision(23),
        },
    )
    .expect("scope");
    let secret =
        SecretReference::new("frameio-secret-reference-1", &scope, revision(3)).expect("secret");
    let bounds = FrameIoBounds::default();
    let window = hartevo_frameio_review_result_plugin::ObservationWindow::new(
        now - Duration::hours(2),
        now - Duration::hours(1),
    )
    .expect("window");
    let asset = FrameIoAssetSummary::new(
        scope.asset_id.clone(),
        scope.frameio_project_id.clone(),
        FrameIoReviewStatus::Ready,
        now - Duration::minutes(10),
        scope.revision_fence.asset_revision,
    );
    let version = FrameIoVersionSummary::new(
        scope.asset_id.clone(),
        scope.asset_version_id.clone(),
        FrameIoReviewStatus::InReview,
        now - Duration::minutes(9),
        scope.revision_fence.version_revision,
    );
    let review_link = FrameIoReviewLinkSummary::new(
        scope.review_link_id.clone(),
        FrameIoReviewLinkState::Active,
        FrameIoApprovalStatus::Pending,
        Some(now + Duration::days(1)),
        3,
        now - Duration::minutes(8),
        scope.revision_fence.review_link_revision,
    );
    let approval = FrameIoApprovalSummary::new(
        FrameIoApprovalStatus::Pending,
        now - Duration::minutes(7),
        scope.revision_fence.review_link_revision,
    );
    let comments = FrameIoCommentSummary::new(
        2,
        1,
        1,
        1,
        1,
        Some(now - Duration::minutes(6)),
        Some(now - Duration::minutes(5)),
        false,
        scope.revision_fence.comment_revision,
    )
    .expect("comments");
    let snapshot = FrameIoSnapshot::new(
        &scope,
        secret.credential_revision(),
        "frameio-v2-recording-r1",
        Some(asset),
        Some(version),
        Some(review_link),
        Some(approval),
        Some(comments),
        None,
    )
    .expect("snapshot");
    Fixture {
        scope,
        secret,
        bounds,
        window,
        snapshot,
    }
}

fn fixture_service() -> FrameIoReviewResultService<FixtureFrameIoTransport> {
    let fixture = fixture();
    let provider = FrameIoProvider::new(
        FixtureFrameIoTransport::new(fixture.snapshot),
        "frameio-v2-recording-r1",
        FrameIoTransportProvenance::Fixture,
    )
    .expect("provider");
    FrameIoReviewResultService::new(fixture.scope, fixture.secret, provider).expect("service")
}

fn request(fixture: &Fixture) -> FrameIoReviewProposalRequest {
    FrameIoReviewProposalRequest::new(
        all_operations(),
        fixture.bounds,
        fixture.window.clone(),
        fixture.scope.work_product_revision,
    )
    .expect("proposal request")
}

#[test]
fn fixture_read_is_bounded_redacted_and_mission_pending() {
    let fixture = fixture();
    let request = request(&fixture);
    let mut service = FrameIoReviewResultService::new(
        fixture.scope.clone(),
        fixture.secret.clone(),
        FrameIoProvider::new(
            FixtureFrameIoTransport::new(fixture.snapshot),
            "frameio-v2-recording-r1",
            FrameIoTransportProvenance::Fixture,
        )
        .expect("provider"),
    )
    .expect("service");
    let proposal = service.propose(request.clone(), at()).expect("proposal");
    assert_eq!(proposal.status(), FrameIoReviewStatus::InReview);
    assert_eq!(proposal.evidence.receipts.len(), 5);
    assert_eq!(
        proposal
            .evidence
            .comments
            .as_ref()
            .expect("comments")
            .total_count,
        2
    );
    assert!(proposal.evidence.redactions.media_urls);
    assert!(proposal.evidence.redactions.signed_urls);
    assert!(proposal.evidence.redactions.raw_comments);
    assert!(proposal.evidence.redactions.reviewer_pii);
    assert!(proposal.evidence.redactions.drawings);
    assert!(proposal.evidence.redactions.binaries);
    assert!(!proposal.connected);
    assert!(!proposal.native_evidence);
    assert!(!proposal.outcome_authority);
    assert!(!proposal.is_adopted());
    assert!(
        !serde_json::to_string(&proposal)
            .expect("safe proposal JSON")
            .contains("frameio-secret-reference-1")
    );
    assert!(!format!("{:?}", fixture.secret).contains("frameio-secret-reference-1"));

    let mut consumer =
        MissionFrameIoReviewConsumer::new(fixture.scope, service.registration()).expect("consumer");
    let result = consumer.consume(proposal).expect("Mission result");
    assert_eq!(result.state, MissionFrameIoReviewState::PendingDecision);
    assert_eq!(result.status, FrameIoReviewStatus::InReview);
    assert!(!result.connected);
    assert!(!result.native_evidence);
    assert!(!result.outcome_authority);
    assert!(!result.work_product_adoption);
}

#[test]
fn blocked_environment_is_unknown_and_never_connected() {
    let fixture = fixture();
    let request = request(&fixture);
    let provider = FrameIoProvider::new(
        BlockedEnvFrameIoTransport,
        "frameio-v2-blocked-env-r1",
        FrameIoTransportProvenance::BlockedEnv,
    )
    .expect("provider");
    let mut service =
        FrameIoReviewResultService::new(fixture.scope, fixture.secret, provider).expect("service");
    let proposal = service.propose(request, at()).expect("blocked proposal");
    assert_eq!(proposal.status(), FrameIoReviewStatus::ProviderUnknown);
    assert!(proposal.evidence.receipts.is_empty());
    assert_eq!(proposal.evidence.failures.len(), 5);
    assert_eq!(
        proposal.evidence.provenance,
        FrameIoTransportProvenance::BlockedEnv
    );
    assert!(!proposal.connected);
    assert!(!proposal.native_evidence);
}

#[test]
fn rate_limit_retries_are_bounded_and_recorded() {
    let fixture = fixture();
    let request = request(&fixture);
    let mut transport = RecordingFrameIoTransport::default();
    transport.push_error(FrameIoTransportError::rate_limited());
    transport.push_error(FrameIoTransportError::rate_limited());
    for operation in all_operations() {
        let get_request = FrameIoGetRequest::new(
            &fixture.scope,
            &fixture.secret,
            operation,
            fixture.bounds,
            fixture.window.clone(),
            1,
            None,
        )
        .expect("get request");
        transport.push_response(
            fixture
                .snapshot
                .response_for(&get_request)
                .expect("fixture response"),
        );
    }
    let provider = FrameIoProvider::new(
        transport,
        "frameio-v2-recording-r1",
        FrameIoTransportProvenance::Recording,
    )
    .expect("provider");
    let mut service =
        FrameIoReviewResultService::new(fixture.scope, fixture.secret, provider).expect("service");
    let proposal = service.propose(request, at()).expect("proposal");
    assert_eq!(proposal.evidence.retries.len(), 2);
    assert_eq!(proposal.evidence.receipts[0].attempts, 3);
    assert!(proposal.evidence.retries[0].backoff_ms < proposal.evidence.retries[1].backoff_ms);
    assert_eq!(proposal.status(), FrameIoReviewStatus::InReview);
}

#[test]
fn tampering_and_replay_are_rejected_by_the_mission_consumer() {
    let fixture = fixture();
    let request = request(&fixture);
    let mut service = fixture_service();
    let proposal = service.propose(request, at()).expect("proposal");
    let mut consumer =
        MissionFrameIoReviewConsumer::new(fixture.scope, service.registration()).expect("consumer");
    let mut tampered = proposal.clone();
    tampered.evidence.status = FrameIoReviewStatus::Approved;
    assert!(consumer.validate_only(&tampered).is_err());
    let first = consumer.consume(proposal.clone()).expect("first consume");
    assert_eq!(first.status, FrameIoReviewStatus::InReview);
    assert!(consumer.consume(proposal).is_err());
}

#[test]
fn scope_drift_is_rejected_before_evidence_is_consumed() {
    let fixture = fixture();
    let get_request = FrameIoGetRequest::new(
        &fixture.scope,
        &fixture.secret,
        FrameIoReadOperation::AssetMetadata,
        fixture.bounds,
        fixture.window.clone(),
        1,
        None,
    )
    .expect("get request");
    let mut response = fixture
        .snapshot
        .response_for(&get_request)
        .expect("fixture response");
    response.scope_digest = Digest::from_text("scope-drift");
    response.response_digest = response
        .recompute_digest()
        .expect("tampered response digest");
    let mut transport = RecordingFrameIoTransport::default();
    transport.push_response(response);
    let provider = FrameIoProvider::new(
        transport,
        "frameio-v2-recording-r1",
        FrameIoTransportProvenance::Recording,
    )
    .expect("provider");
    let mut service =
        FrameIoReviewResultService::new(fixture.scope, fixture.secret, provider).expect("service");
    let single_request = FrameIoReviewProposalRequest::new(
        [FrameIoReadOperation::AssetMetadata],
        fixture.bounds,
        fixture.window,
        service.scope().work_product_revision,
    )
    .expect("request");
    assert!(matches!(
        service.propose(single_request, at()),
        Err(
            hartevo_frameio_review_result_plugin::FrameIoServiceError::Provider(
                FrameIoProviderError::ScopeMismatch
            )
        )
    ));
}

#[test]
fn cursor_is_opaque_and_nonempty_bounds_are_enforced() {
    let cursor = OpaqueCursor::new("opaque-provider-cursor").expect("cursor");
    let serialized = serde_json::to_string(&cursor).expect("cursor serialization");
    assert_eq!(serialized, format!("\"{}\"", cursor.digest().as_str()));
    assert!(!serialized.contains("opaque-provider-cursor"));
    assert!(matches!(
        OpaqueCursor::new(""),
        Err(ModelError::InvalidCursor)
    ));
    assert!(FrameIoBounds::new(0, 1, 1, 1, 1, 1).is_err());
    assert!(FrameIoBounds::new(1, 1, 1, 1, 1, 1).is_ok());
}

#[test]
fn contract_and_registration_are_version_and_provider_bound() {
    let contract =
        hartevo_frameio_review_result_plugin::FrameIoContract::baseline().expect("contract");
    assert_eq!(contract.digest(), contract_digest());
    assert_eq!(
        contract.contract_version,
        FRAME_IO_REVIEW_RESULT_CONTRACT_VERSION
    );
    assert_eq!(
        contract.service.version,
        FRAME_IO_REVIEW_RESULT_PLUGIN_VERSION
    );
    let service = fixture_service();
    assert_eq!(service.registration().contract_digest, contract_digest());
    assert_eq!(service.registration().provider_id, "frameio.api");
    assert_eq!(
        service.registration().scope_digest,
        service.scope().digest()
    );
    assert_eq!(
        service.provider().definition().provenance,
        FrameIoTransportProvenance::Fixture
    );
}

#[test]
fn loopback_transport_has_no_native_claim() {
    let fixture = fixture();
    let provider = FrameIoProvider::new(
        LoopbackFrameIoTransport::new(fixture.snapshot),
        "frameio-loopback-r1",
        FrameIoTransportProvenance::Loopback,
    )
    .expect("provider");
    assert!(!provider.is_native());
    assert!(!provider.is_connected());
}
