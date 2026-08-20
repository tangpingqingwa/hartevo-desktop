use hartevo_deepgram_transcript_result_plugin as deepgram;
use serde_json::json;

use deepgram::{
    AudioFingerprint, BlockedEnvCredentialResolver, BlockedEnvTransport, ConsentId,
    ConsentReference, DeepgramHost, DeepgramModelFeatures, DeepgramModelRevision,
    DeepgramPageToken, DeepgramProjectId, DeepgramProjectReference, DeepgramProvider,
    DeepgramProviderError, DeepgramRegistration, DeepgramRegistrationRegistry, DeepgramResultError,
    DeepgramRetryPolicy, DeepgramScope, DeepgramTranscriptResultService, DeepgramTransportError,
    DeepgramUtteranceWindow, FakeTransport, LoopbackTransport, MissionDeepgramTranscriptConsumer,
    MissionId, ModelId, ProjectId, ProjectReference, RawSegment, RegistrationId, RequestId,
    RequestOperation, SecretReference, SegmentId, StaticApiKeyCredentialResolver,
    TranscriptFixture, TranscriptStatus, TransportProvenance, WorkProductId, WorkProductReference,
};

fn scope() -> DeepgramScope {
    scope_with_project("project-1")
}

fn scope_with_project(project_id: &str) -> DeepgramScope {
    let host = DeepgramHost::new("https://api.deepgram.com/").expect("host");
    let provider_project = DeepgramProjectReference::new(
        DeepgramProjectId::new("dg-project-1").expect("Deepgram project"),
        1,
    )
    .expect("provider project");
    let request = deepgram::DeepgramRequestReference::new(
        RequestId::new("request-1").expect("request"),
        1,
        RequestOperation::ListenRead,
        deepgram::Digest::from_text("model=nova-3;utterances=true"),
    )
    .expect("request");
    let audio = AudioFingerprint::new("fixture-audio-fingerprint", 1).expect("audio fingerprint");
    let model = DeepgramModelRevision::new(
        ModelId::new("nova-3").expect("model"),
        Some(String::from("2025-01")),
        Some(String::from("en-US")),
        1,
        DeepgramModelFeatures::default(),
    )
    .expect("model revision");
    let window = DeepgramUtteranceWindow::new(
        deepgram::model::WindowId::new("window-1").expect("window"),
        1,
        0,
        None,
        10,
        4,
        16,
    )
    .expect("window");
    let project = ProjectReference::new(ProjectId::new(project_id).expect("Project"), 1)
        .expect("Project reference");
    let mission = deepgram::MissionReference::new(MissionId::new("mission-1").expect("Mission"), 1)
        .expect("Mission reference");
    let work_product = WorkProductReference::new(
        WorkProductId::new("work-product-1").expect("Work Product"),
        1,
    )
    .expect("Work Product reference");
    let consent = ConsentReference::new(
        ConsentId::new("consent-1").expect("consent"),
        1,
        "bounded-transcript-result-review",
    )
    .expect("consent");
    DeepgramScope::new(
        host,
        provider_project,
        request,
        audio,
        model,
        window,
        project,
        mission,
        work_product,
        consent,
    )
    .expect("scope")
}

fn registration(scope: DeepgramScope) -> DeepgramRegistration {
    let secret =
        SecretReference::api_key("opaque-deepgram-key-reference", scope.digest().as_str(), 1)
            .expect("opaque secret reference");
    DeepgramRegistration::new(
        RegistrationId::new("registration-1").expect("registration"),
        scope,
        secret,
        1,
    )
    .expect("registration")
}

fn segments() -> Vec<RawSegment> {
    vec![
        RawSegment::new(
            SegmentId::new("utt-1").expect("segment"),
            0,
            900,
            1,
            Some(0),
            0.94,
            "redacted first utterance",
        ),
        RawSegment::new(
            SegmentId::new("utt-2").expect("segment"),
            1_000,
            1_900,
            1,
            Some(1),
            0.91,
            "redacted second utterance",
        ),
    ]
}

fn fixture(scope: &DeepgramScope, status: &str) -> TranscriptFixture {
    TranscriptFixture::from_segments(scope, status, segments()).expect("fixture")
}

fn provider(
    registration: &DeepgramRegistration,
    fixture: TranscriptFixture,
) -> DeepgramProvider<FakeTransport, StaticApiKeyCredentialResolver> {
    DeepgramProvider::new(
        registration.clone(),
        FakeTransport::new(fixture),
        StaticApiKeyCredentialResolver::api_key("fixture-only-secret-material"),
    )
    .expect("provider")
}

#[test]
fn contract_and_registration_are_redacted_and_layer_one_only() {
    let contract: serde_json::Value =
        serde_json::from_str(deepgram::CONTRACT_JSON).expect("contract");
    assert_eq!(contract["authority"]["connected"], false);
    assert_eq!(contract["authority"]["native"], false);
    assert_eq!(contract["authority"]["mediaWrites"], false);
    assert_eq!(contract["authority"]["workProductAdoption"], false);
    assert_eq!(
        deepgram::contract_digest().as_str(),
        deepgram::CONTRACT_DIGEST
    );

    let scope = scope();
    let registration = registration(scope.clone());
    let serialized = serde_json::to_string(&registration).expect("redacted registration receipt");
    assert!(!serialized.contains("opaque-deepgram-key-reference"));
    assert!(
        !format!("{:?}", registration.secret_reference()).contains("opaque-deepgram-key-reference")
    );
    assert_eq!(registration.scope().digest(), scope.digest());
}

#[test]
fn completed_projection_contains_only_bounded_metadata_and_digests() {
    let scope = scope();
    let registration = registration(scope.clone());
    let mut provider = provider(&registration, fixture(&scope, "completed"));
    let evidence = provider.read_transcript_result().expect("evidence");

    assert_eq!(evidence.status, TranscriptStatus::Completed);
    assert!(evidence.complete);
    assert_eq!(evidence.segment_count, 2);
    assert!(evidence.segment_digest.is_valid());
    assert!(evidence.content_digest.is_valid());
    assert!(evidence.evidence_digest.is_valid());
    assert_eq!(evidence.provenance, TransportProvenance::Fake);
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert!(!evidence.first_party);
    evidence.validate_integrity().expect("evidence integrity");

    let json = serde_json::to_string(&evidence).expect("evidence JSON");
    assert!(!json.contains("redacted first utterance"));
    assert!(!json.contains("redacted second utterance"));
    assert!(!json.contains("rawAudio"));
    assert!(!json.contains("audioBytes"));
    assert!(json.contains("contentDigest"));
}

#[test]
fn status_projection_is_typed_and_unknown_provider_text_becomes_a_digest() {
    for (raw, expected) in [
        ("denied", TranscriptStatus::Denied),
        ("partial", TranscriptStatus::Partial),
        ("expired", TranscriptStatus::Expired),
        ("rate_limited", TranscriptStatus::RateLimited),
    ] {
        let scope = scope();
        let registration = registration(scope.clone());
        let mut provider = provider(&registration, fixture(&scope, raw));
        let evidence = provider.read_transcript_result().expect("typed status");
        assert_eq!(evidence.status, expected);
        assert!(!evidence.complete);
    }

    let scope = scope();
    let registration = registration(scope.clone());
    let mut provider = provider(&registration, fixture(&scope, "deepgram-future-state"));
    let evidence = provider.read_transcript_result().expect("unknown status");
    assert!(matches!(
        evidence.status,
        TranscriptStatus::ProviderUnknown { .. }
    ));
    let json = serde_json::to_string(&evidence).expect("unknown status JSON");
    assert!(!json.contains("deepgram-future-state"));
}

#[test]
fn transport_denied_partial_expired_rate_limit_and_tamper_are_typed() {
    let scope = scope();
    let registration = registration(scope.clone());

    let denied_fixture = fixture(&scope, "completed");
    let mut denied = DeepgramProvider::new(
        registration.clone(),
        FakeTransport::new(denied_fixture).with_error(DeepgramTransportError::Unauthorized401),
        StaticApiKeyCredentialResolver::api_key("fixture-secret"),
    )
    .expect("denied provider");
    assert_eq!(denied.read().unwrap_err(), DeepgramProviderError::Denied);

    let mut partial = DeepgramProvider::new(
        registration.clone(),
        FakeTransport::new(fixture(&scope, "completed"))
            .with_error(DeepgramTransportError::PartialResponse),
        StaticApiKeyCredentialResolver::api_key("fixture-secret"),
    )
    .expect("partial provider");
    assert_eq!(partial.read().unwrap_err(), DeepgramProviderError::Partial);

    let mut expired = DeepgramProvider::new(
        registration.clone(),
        FakeTransport::new(fixture(&scope, "completed"))
            .with_error(DeepgramTransportError::Expired),
        StaticApiKeyCredentialResolver::api_key("fixture-secret"),
    )
    .expect("expired provider");
    assert_eq!(expired.read().unwrap_err(), DeepgramProviderError::Expired);

    let policy = DeepgramRetryPolicy::new(2, 30).expect("retry policy");
    let mut rate_limited = DeepgramProvider::with_retry_policy(
        registration.clone(),
        FakeTransport::new(fixture(&scope, "completed")).with_errors(vec![
            DeepgramTransportError::RateLimited {
                retry_after_seconds: 60,
            },
            DeepgramTransportError::RateLimited {
                retry_after_seconds: 60,
            },
        ]),
        StaticApiKeyCredentialResolver::api_key("fixture-secret"),
        policy,
    )
    .expect("rate limit provider");
    assert_eq!(
        rate_limited.read().unwrap_err(),
        DeepgramProviderError::RateLimited {
            retry_after_seconds: 30,
            attempts: 2,
        }
    );

    let original = fixture(&scope, "completed");
    let mut tampered_page = original.pages()[0].clone();
    tampered_page.payload_digest = deepgram::Digest::from_text("tampered-page");
    let tampered =
        TranscriptFixture::from_pages_unchecked(vec![tampered_page]).expect("tamper fixture");
    let mut tampered_provider = provider(&registration, tampered);
    assert_eq!(
        tampered_provider.read().unwrap_err(),
        DeepgramProviderError::Tamper
    );
}

#[test]
fn bounded_window_pagination_replay_duplicate_and_redaction_fail_closed() {
    let expected_scope = scope();
    let registered = registration(expected_scope.clone());

    let all_segments = segments();
    let projected: Vec<_> = all_segments.iter().map(RawSegment::projected).collect();
    let token = DeepgramPageToken::new("opaque-page-token").expect("token");
    let snapshot = deepgram::RawTranscriptSnapshot::for_scope(&expected_scope, "completed")
        .expect("snapshot")
        .with_expected_digests(
            deepgram::segment_digest_for(&projected),
            deepgram::content_digest_for(&projected),
        );
    let page_one = deepgram::RawTranscriptPage::new(
        snapshot.clone(),
        vec![all_segments[0].clone()],
        Some(token.clone()),
    )
    .expect("page one");
    let page_two = deepgram::RawTranscriptPage::new(snapshot, vec![all_segments[1].clone()], None)
        .expect("page two");
    let two_pages = TranscriptFixture::new(vec![page_one, page_two]).expect("two pages");
    let mut paged = provider(&registered, two_pages);
    let evidence = paged.read().expect("paged evidence");
    assert_eq!(evidence.segment_page_count, 2);
    assert_eq!(paged.transport().request_count(), 2);

    let repeat_snapshot = deepgram::RawTranscriptSnapshot::for_scope(&expected_scope, "completed")
        .expect("snapshot")
        .with_expected_digests(
            deepgram::Digest::from_text("not-used"),
            deepgram::Digest::from_text("not-used"),
        );
    let repeat_one = deepgram::RawTranscriptPage::new(
        repeat_snapshot.clone(),
        vec![all_segments[0].clone()],
        Some(token.clone()),
    )
    .expect("repeat page one");
    let repeat_two = deepgram::RawTranscriptPage::new(
        repeat_snapshot,
        vec![all_segments[1].clone()],
        Some(token),
    )
    .expect("repeat page two");
    let repeated = TranscriptFixture::new(vec![repeat_one, repeat_two]).expect("repeated fixture");
    let mut repeated_provider = provider(&registered, repeated);
    assert_eq!(
        repeated_provider.read().unwrap_err(),
        DeepgramProviderError::PaginationLoop
    );

    let limited_scope = {
        let mut value = scope_with_project("project-1");
        value.utterance_window.page_size = 1;
        value.utterance_window.max_segments = 1;
        value
    };
    let limited_registration = registration(limited_scope.clone());
    let mut limited = provider(&limited_registration, fixture(&limited_scope, "completed"));
    assert_eq!(
        limited.read().unwrap_err(),
        DeepgramProviderError::SegmentLimit
    );

    let mut unredacted_segments = segments();
    unredacted_segments[0] = RawSegment::unredacted_for_test(
        SegmentId::new("utt-unredacted").expect("segment"),
        0,
        100,
        1,
        None,
        0.8,
        "private transcript text",
    );
    let unredacted_fixture =
        TranscriptFixture::from_segments(&expected_scope, "completed", unredacted_segments)
            .expect("unredacted fixture");
    let mut unredacted = provider(&registered, unredacted_fixture);
    assert_eq!(
        unredacted.read().unwrap_err(),
        DeepgramProviderError::UnredactedContent
    );
}

#[test]
fn exact_scope_revision_consent_and_registration_lifecycle_are_fenced() {
    let expected_scope = scope();
    let registered = registration(expected_scope.clone());
    let drifted_scope = scope_with_project("project-drift");
    let snapshot = deepgram::RawTranscriptSnapshot::for_scope(&drifted_scope, "completed")
        .expect("drift snapshot");
    let drift_fixture = TranscriptFixture::from_segments(&drifted_scope, "completed", segments())
        .expect("drift fixture");
    let mut drift_page = drift_fixture.pages()[0].clone();
    drift_page.snapshot = snapshot.with_expected_digests(
        drift_page.snapshot.expected_segment_digest.clone(),
        drift_page.snapshot.expected_content_digest.clone(),
    );
    drift_page.refresh_digest();
    let drift_fixture =
        TranscriptFixture::from_pages_unchecked(vec![drift_page]).expect("drift fixture");
    let mut drifted = provider(&registered, drift_fixture);
    assert_eq!(
        drifted.read().unwrap_err(),
        DeepgramProviderError::HartevoProjectDrift
    );

    let revoked = registered.clone();
    revoked.revoke().expect("revoke");
    assert_eq!(revoked.state(), deepgram::RegistrationState::Revoked);
    assert_eq!(
        DeepgramProvider::new(
            revoked,
            FakeTransport::new(fixture(&expected_scope, "completed")),
            StaticApiKeyCredentialResolver::api_key("fixture-secret"),
        )
        .unwrap_err(),
        DeepgramProviderError::RegistrationRevoked
    );

    let restore = registration(expected_scope.clone());
    restore.revoke().expect("revoke");
    restore.restore().expect("restore");
    restore.reverse().expect("reverse");
    assert_eq!(restore.state(), deepgram::RegistrationState::Reversed);

    let secret_revoked = registration(expected_scope.clone());
    secret_revoked.revoke_secret_reference();
    let mut secret_provider = provider(&secret_revoked, fixture(&expected_scope, "completed"));
    assert_eq!(
        secret_provider.read().unwrap_err(),
        DeepgramProviderError::SecretRevoked
    );
}

#[test]
fn proposal_recording_is_redacted_revision_bound_and_idempotent() {
    let scope = scope();
    let registration = registration(scope.clone());
    let mut service = DeepgramTranscriptResultService::new(registration.clone()).expect("service");
    let mut provider = provider(&registration, fixture(&scope, "completed"));
    let evidence = service.read_result(&mut provider).expect("evidence");
    let mut consumer =
        MissionDeepgramTranscriptConsumer::for_registration(&registration).expect("consumer");
    let proposal = service
        .compile_proposal(&consumer, &evidence, "proposal-1")
        .expect("proposal");
    assert_eq!(
        proposal.disposition,
        deepgram::DeepgramProposalDisposition::DecisionPending
    );
    assert!(proposal.is_review_only());
    assert!(!proposal.can_be_adopted());
    assert!(!consumer.can_adopt_work_product());
    assert!(!consumer.can_adopt_outcome());

    let first = service
        .record_proposal(&mut consumer, &proposal, "idempotency-1")
        .expect("recording");
    assert!(!first.replayed);
    assert!(!first.durable_provider_receipt);
    let replay = service
        .record_proposal(&mut consumer, &proposal, "idempotency-1")
        .expect("replay");
    assert!(replay.replayed);

    let second = service
        .compile_proposal(&consumer, &evidence, "proposal-2")
        .expect("second proposal");
    assert_eq!(
        service
            .record_proposal(&mut consumer, &second, "idempotency-1")
            .unwrap_err(),
        DeepgramResultError::IdempotencyConflict
    );

    let mut consuming_consumer = MissionDeepgramTranscriptConsumer::for_registration(&registration)
        .expect("consuming consumer");
    let mission_result = consuming_consumer
        .consume(proposal, evidence)
        .expect("Mission result");
    assert!(mission_result.observation.review_only);
    assert!(!mission_result.observation.native);
    assert!(!mission_result.observation.outcome_adoption);
    assert_eq!(consuming_consumer.consumed_count(), 1);
}

#[test]
fn registry_recording_loopback_and_blocked_env_never_claim_native() {
    let scope = scope();
    let registration = registration(scope.clone());
    let id = registration.id().clone();
    let mut registry = DeepgramRegistrationRegistry::default();
    registry.register(registration.clone()).expect("register");
    assert_eq!(
        registry.register(registration.clone()).unwrap_err(),
        DeepgramResultError::RegistrationAlreadyExists
    );
    registry.revoke(&id).expect("registry revoke");
    registry.restore(&id).expect("registry restore");

    let fixture = fixture(&scope, "completed");
    let mut recording = DeepgramProvider::new(
        registration.clone(),
        deepgram::RecordingTransport::new(fixture.clone()),
        StaticApiKeyCredentialResolver::api_key("fixture-secret"),
    )
    .expect("recording");
    let recording_evidence = recording.read().expect("recording evidence");
    assert_eq!(
        recording_evidence.provenance,
        TransportProvenance::Recording
    );
    assert!(!recording_evidence.connected);
    assert!(!recording_evidence.native);

    let mut loopback = DeepgramProvider::new(
        registration.clone(),
        LoopbackTransport::new(fixture),
        StaticApiKeyCredentialResolver::api_key("fixture-secret"),
    )
    .expect("loopback");
    let loopback_evidence = loopback.read().expect("loopback evidence");
    assert_eq!(loopback_evidence.provenance, TransportProvenance::Loopback);
    assert!(!loopback_evidence.connected);
    assert!(!loopback_evidence.native);

    let blocked = DeepgramProvider::new(
        registration,
        BlockedEnvTransport::default(),
        BlockedEnvCredentialResolver,
    )
    .expect("blocked provider");
    let description = blocked.describe_scope().expect("scope description");
    assert_eq!(description.provenance, TransportProvenance::BlockedEnv);
    assert!(!description.connected);
    assert!(!description.native);
    assert!(!description.first_party);
}

#[test]
fn operations_record_only_digests_not_page_tokens_or_transcript_text() {
    let scope = scope();
    let registration = registration(scope.clone());
    let mut provider = DeepgramProvider::new(
        registration,
        deepgram::RecordingTransport::new(fixture(&scope, "completed")),
        StaticApiKeyCredentialResolver::api_key("fixture-secret"),
    )
    .expect("provider");
    provider.read().expect("evidence");
    let json = serde_json::to_string(&provider.operations()).expect("operations JSON");
    assert!(!json.contains("opaque-page-token"));
    assert!(!json.contains("redacted first utterance"));
    assert!(json.contains("requestDigest"));
    assert!(json.contains("provenance"));
}

#[allow(dead_code)]
fn _request_constructor_is_bounded() {
    let _ = json!({"utterances": true});
}
