use hartevo_assemblyai_transcript_result_plugin::model::{content_digest_for, segment_digest_for};
use hartevo_assemblyai_transcript_result_plugin::{
    AssemblyAiPermissionSnapshot, AssemblyAiProvider, AssemblyAiProviderError,
    AssemblyAiProviderIdentity, AssemblyAiRegistration, AssemblyAiRegistrationRegistry,
    AssemblyAiResultError, AssemblyAiScope, AssemblyAiTranscriptResultService, AssemblyAiTransport,
    AssemblyAiTransportError, AssemblyAiTransportOperation, BlockedEnvCredentialResolver,
    BlockedEnvTransport, ConfigId, Digest, FakeTransport, LoopbackTransport, MissionId,
    MissionTranscriptResultConsumer, ModelId, ModelRevision, ProjectId, ProviderUnknownStatus,
    RawTranscriptPage, RawTranscriptSnapshot, RawUtterance, RecordingTransport, RegistrationId,
    RegistrationState, SecretReference, SegmentId, SegmentScope, SourceId, SourceReference,
    StaticApiKeyCredentialResolver, TranscriptConfigRevision, TranscriptFixture,
    TranscriptPageToken, TranscriptReference, TranscriptStatusProjection, TransportProvenance,
    WorkProductId, WorkProductReference,
};

fn scope() -> AssemblyAiScope {
    AssemblyAiScope::new(
        hartevo_assemblyai_transcript_result_plugin::AssemblyAiHost::new(
            "https://api.assemblyai.com",
        )
        .expect("host"),
        hartevo_assemblyai_transcript_result_plugin::AccountId::new("account-1").expect("account"),
        SourceReference::new(SourceId::new("source-1").expect("source id"), 1).expect("source"),
        TranscriptReference::new(
            hartevo_assemblyai_transcript_result_plugin::TranscriptId::new("transcript-1")
                .expect("transcript id"),
            1,
        )
        .expect("transcript"),
        ModelRevision::new(
            Some(ModelId::new("universal-2").expect("speech model")),
            Some(ModelId::new("assemblyai-default").expect("language model")),
            Some(ModelId::new("assemblyai-default").expect("acoustic model")),
            1,
        )
        .expect("model"),
        TranscriptConfigRevision::new(
            ConfigId::new("config-1").expect("config id"),
            1,
            Some(String::from("en_us")),
            true,
            true,
            true,
            true,
            true,
        )
        .expect("configuration"),
        SegmentScope::new(1, 2, 4, 8).expect("segment scope"),
        hartevo_assemblyai_transcript_result_plugin::MissionReference::new(
            MissionId::new("mission-1").expect("mission id"),
            1,
        )
        .expect("Mission"),
        hartevo_assemblyai_transcript_result_plugin::ProjectReference::new(
            ProjectId::new("project-1").expect("project id"),
            1,
        )
        .expect("Project"),
        WorkProductReference::new(
            WorkProductId::new("work-product-1").expect("Work Product id"),
            1,
        )
        .expect("Work Product"),
        AssemblyAiPermissionSnapshot::read_only(1).expect("permissions"),
    )
    .expect("scope")
}

fn registration(scope: &AssemblyAiScope) -> AssemblyAiRegistration {
    AssemblyAiRegistration::new(
        RegistrationId::new("registration-1").expect("registration id"),
        scope.clone(),
        SecretReference::api_key("opaque-api-key-reference", scope.digest().as_str(), 1)
            .expect("secret reference"),
        scope.permission.clone(),
        AssemblyAiProviderIdentity::new(1, "assemblyai-layer1-recording-1").expect("provider"),
        1,
    )
    .expect("registration")
}

fn utterances(scope: &AssemblyAiScope) -> Vec<RawUtterance> {
    let _ = scope;
    vec![
        RawUtterance::new(
            SegmentId::new("segment-1").expect("segment"),
            Some(String::from("A")),
            0,
            900,
            0.91,
            "redacted utterance one",
        ),
        RawUtterance::new(
            SegmentId::new("segment-2").expect("segment"),
            Some(String::from("B")),
            901,
            1_800,
            0.81,
            "redacted utterance two",
        ),
        RawUtterance::new(
            SegmentId::new("segment-3").expect("segment"),
            Some(String::from("A")),
            1_801,
            2_400,
            0.77,
            "redacted utterance three",
        ),
    ]
}

fn fixture(scope: &AssemblyAiScope, status: &str) -> TranscriptFixture {
    TranscriptFixture::from_utterances(scope, status, utterances(scope)).expect("fixture")
}

fn provider(
    scope: &AssemblyAiScope,
    fixture: TranscriptFixture,
) -> AssemblyAiProvider<FakeTransport, StaticApiKeyCredentialResolver> {
    AssemblyAiProvider::new(
        registration(scope),
        FakeTransport::new(fixture),
        StaticApiKeyCredentialResolver::api_key("fixture-key"),
    )
    .expect("provider")
}

#[test]
fn contract_capabilities_and_opaque_redaction_are_layer_one_only() {
    let scope = scope();
    let registration = registration(&scope);
    let service = AssemblyAiTranscriptResultService::new(registration.clone()).expect("service");
    let capability = service.describe_capabilities();
    assert!(capability.read_only);
    assert!(capability.can_read_transcript);
    assert!(capability.can_propose_work_product);
    assert!(capability.can_record_proposal);
    assert!(!capability.connected);
    assert!(!capability.native);
    assert!(!capability.first_party);
    assert!(!capability.can_upload_audio);
    assert!(!capability.can_fetch_arbitrary_media);
    assert!(!capability.can_submit_transcript);
    assert!(!capability.can_poll_transcript);
    assert!(!capability.can_retain_raw_audio);
    assert!(!capability.can_export_raw_transcript);
    assert!(!capability.can_mutate_speaker_identity);
    assert!(!capability.can_train_model);
    assert!(!capability.external_write);
    assert!(!capability.can_adopt_work_product);
    assert!(!capability.can_adopt_outcome);

    let secret = registration.secret_reference();
    assert!(!format!("{secret:?}").contains("opaque-api-key-reference"));
    assert!(
        !format!(
            "{:?}",
            StaticApiKeyCredentialResolver::api_key("fixture-key")
        )
        .contains("fixture-key")
    );

    let projection = service
        .read_transcript(&mut provider(&scope, fixture(&scope, "completed")))
        .expect("projection");
    let serialized = serde_json::to_string(&projection).expect("projection serialization");
    assert!(!serialized.contains("redacted utterance one"));
    assert!(!serialized.contains("fixture-key"));
    assert!(!projection.connected);
    assert!(!projection.native);
    assert!(!projection.first_party);
    projection.validate_integrity().expect("projection digest");
}

#[test]
fn all_provider_statuses_are_finite_and_unknown_is_digest_only() {
    let statuses = [
        ("queued", TranscriptStatusProjection::Queued),
        ("processing", TranscriptStatusProjection::Processing),
        ("completed", TranscriptStatusProjection::Completed),
        ("error", TranscriptStatusProjection::Error),
        ("canceled", TranscriptStatusProjection::Canceled),
        ("expired", TranscriptStatusProjection::Expired),
    ];
    for (raw, expected) in statuses {
        let scope = scope();
        let mut provider = provider(&scope, fixture(&scope, raw));
        let projection = provider.read_transcript().expect("status projection");
        assert_eq!(projection.status, expected);
    }

    let scope = scope();
    let projection = provider(&scope, fixture(&scope, "provider-new-status"))
        .read_transcript()
        .expect("unknown status projection");
    assert_eq!(
        projection.status,
        TranscriptStatusProjection::ProviderUnknown(ProviderUnknownStatus {
            code_digest: Digest::from_text("provider-new-status"),
        })
    );
    assert!(
        !serde_json::to_string(&projection)
            .expect("projection JSON")
            .contains("provider-new-status")
    );
}

#[test]
fn exact_scope_component_drift_fails_closed() {
    let expected = scope();
    let cases = [
        ("host", AssemblyAiProviderError::HostDrift),
        ("account", AssemblyAiProviderError::AccountDrift),
        ("source", AssemblyAiProviderError::SourceDrift),
        ("transcript", AssemblyAiProviderError::TranscriptDrift),
        ("model", AssemblyAiProviderError::ModelDrift),
        ("configuration", AssemblyAiProviderError::ConfigurationDrift),
        ("segment", AssemblyAiProviderError::SegmentScopeDrift),
        ("mission", AssemblyAiProviderError::MissionDrift),
        ("project", AssemblyAiProviderError::ProjectDrift),
        ("work_product", AssemblyAiProviderError::WorkProductDrift),
        ("permission", AssemblyAiProviderError::PermissionDrift),
    ];
    for (component, expected_error) in cases {
        let mut drifted = expected.clone();
        match component {
            "host" => {
                drifted.host = hartevo_assemblyai_transcript_result_plugin::AssemblyAiHost::new(
                    "https://api.eu.assemblyai.com",
                )
                .expect("drift host");
            }
            "account" => {
                drifted.account =
                    hartevo_assemblyai_transcript_result_plugin::AccountId::new("account-drift")
                        .expect("drift account");
            }
            "source" => {
                drifted.source =
                    SourceReference::new(SourceId::new("source-drift").expect("source id"), 2)
                        .expect("drift source");
            }
            "transcript" => {
                drifted.transcript = TranscriptReference::new(
                    hartevo_assemblyai_transcript_result_plugin::TranscriptId::new(
                        "transcript-drift",
                    )
                    .expect("transcript id"),
                    2,
                )
                .expect("drift transcript");
            }
            "model" => {
                drifted.model = ModelRevision::new(
                    Some(ModelId::new("universal-3-5-pro").expect("model")),
                    drifted.model.language_model.clone(),
                    drifted.model.acoustic_model.clone(),
                    2,
                )
                .expect("drift model");
            }
            "configuration" => {
                drifted.configuration = TranscriptConfigRevision::new(
                    ConfigId::new("config-drift").expect("config"),
                    2,
                    Some(String::from("fr")),
                    true,
                    true,
                    true,
                    true,
                    true,
                )
                .expect("drift config");
            }
            "segment" => {
                drifted.segment = SegmentScope::new(2, 2, 4, 8).expect("drift segment");
            }
            "mission" => {
                drifted.mission =
                    hartevo_assemblyai_transcript_result_plugin::MissionReference::new(
                        MissionId::new("mission-drift").expect("mission"),
                        2,
                    )
                    .expect("drift Mission");
            }
            "project" => {
                drifted.project =
                    hartevo_assemblyai_transcript_result_plugin::ProjectReference::new(
                        ProjectId::new("project-drift").expect("Project"),
                        2,
                    )
                    .expect("drift Project");
            }
            "work_product" => {
                drifted.work_product = WorkProductReference::new(
                    WorkProductId::new("work-product-drift").expect("Work Product"),
                    2,
                )
                .expect("drift Work Product");
            }
            "permission" => {
                drifted.permission =
                    AssemblyAiPermissionSnapshot::read_only(2).expect("permission");
            }
            _ => unreachable!(),
        }
        let mut provider = provider(&expected, fixture(&drifted, "completed"));
        assert_eq!(provider.read_transcript().unwrap_err(), expected_error);
    }
}

#[test]
fn language_model_configuration_and_status_changes_are_fenced() {
    let expected = scope();
    let snapshot = RawTranscriptSnapshot::for_scope(&expected, "completed").expect("snapshot");
    let mut page = RawTranscriptPage::new(snapshot, Vec::new(), None).expect("page");
    page.snapshot.language_code = Some(String::from("fr"));
    page.refresh_digest();
    let mut language_provider = provider(
        &expected,
        TranscriptFixture::from_pages(vec![page]).expect("language drift fixture"),
    );
    assert_eq!(
        language_provider.read_transcript().unwrap_err(),
        AssemblyAiProviderError::ConfigurationDrift
    );

    let mut page = RawTranscriptPage::new(
        RawTranscriptSnapshot::for_scope(&expected, "completed").expect("snapshot"),
        Vec::new(),
        None,
    )
    .expect("page");
    page.snapshot.status = String::from("processing");
    page = page.with_expected_digests(segment_digest_for(&[]), content_digest_for(&[]));
    page.refresh_digest();
    let mut status_provider = provider(
        &expected,
        TranscriptFixture::from_pages(vec![page]).expect("status drift fixture"),
    );
    let projection = status_provider
        .read_transcript()
        .expect("status is projected");
    assert_eq!(projection.status, TranscriptStatusProjection::Processing);
}

#[test]
fn bounded_pagination_detects_replay_limit_and_duplicate_segments() {
    let scope = scope();
    let mut multi_page_provider = provider(&scope, fixture(&scope, "completed"));
    let projection = multi_page_provider
        .read_transcript()
        .expect("three segments across pages");
    assert_eq!(projection.utterance_count, 3);
    assert_eq!(multi_page_provider.transport().operations().len(), 2);

    let limited_scope = {
        let mut value = scope.clone();
        value.segment = SegmentScope::new(1, 1, 1, 8).expect("limited segment scope");
        value
    };
    let mut limited = provider(&limited_scope, fixture(&limited_scope, "completed"));
    assert_eq!(
        limited.read_transcript().unwrap_err(),
        AssemblyAiProviderError::PaginationLimit
    );

    let token = TranscriptPageToken::new("same-page-token").expect("token");
    let first_page = RawTranscriptPage::new(
        RawTranscriptSnapshot::for_scope(&scope, "completed").expect("snapshot"),
        vec![utterances(&scope)[0].clone()],
        Some(token.clone()),
    )
    .expect("page")
    .with_expected_digests(Digest::from_text("segment"), Digest::from_text("content"));
    let second_page = RawTranscriptPage::new(
        RawTranscriptSnapshot::for_scope(&scope, "completed").expect("snapshot"),
        vec![utterances(&scope)[1].clone()],
        Some(token.clone()),
    )
    .expect("page")
    .with_request_page_token(Some(token))
    .with_expected_digests(Digest::from_text("segment"), Digest::from_text("content"));
    let mut repeated = provider(
        &scope,
        TranscriptFixture::from_pages(vec![first_page, second_page]).expect("repeated fixture"),
    );
    assert_eq!(
        repeated.read_transcript().unwrap_err(),
        AssemblyAiProviderError::PaginationLoop
    );

    let mut duplicate_segments = utterances(&scope);
    duplicate_segments[1].segment_id = duplicate_segments[0].segment_id.clone();
    let mut duplicate = provider(
        &scope,
        TranscriptFixture::from_utterances(&scope, "completed", duplicate_segments)
            .expect("duplicate fixture"),
    );
    assert_eq!(
        duplicate.read_transcript().unwrap_err(),
        AssemblyAiProviderError::DuplicateSegment
    );
}

#[test]
fn segment_content_status_and_registration_digests_fail_closed() {
    let expected = scope();
    let one = utterances(&expected)[0].clone();
    let projected_one = hartevo_assemblyai_transcript_result_plugin::UtteranceEvidence {
        segment_id: one.segment_id.clone(),
        speaker_label: one.speaker_label.clone(),
        start_ms: one.start_ms,
        end_ms: one.end_ms,
        confidence: one.confidence,
        content_digest: one.content_digest.clone(),
    };
    let correct_segment = segment_digest_for(std::slice::from_ref(&projected_one));
    let wrong_content = Digest::from_text("wrong-content");
    let page = RawTranscriptPage::new(
        RawTranscriptSnapshot::for_scope(&expected, "completed").expect("snapshot"),
        vec![one],
        None,
    )
    .expect("page")
    .with_expected_digests(correct_segment, wrong_content);
    let mut content = provider(
        &expected,
        TranscriptFixture::from_pages(vec![page]).expect("content mismatch fixture"),
    );
    assert_eq!(
        content.read_transcript().unwrap_err(),
        AssemblyAiProviderError::ContentMismatch
    );

    let one = utterances(&expected)[0].clone();
    let page = RawTranscriptPage::new(
        RawTranscriptSnapshot::for_scope(&expected, "completed").expect("snapshot"),
        vec![one],
        None,
    )
    .expect("page")
    .with_expected_digests(
        Digest::from_text("wrong-segment"),
        Digest::from_text("wrong"),
    );
    let mut segment = provider(
        &expected,
        TranscriptFixture::from_pages(vec![page]).expect("segment mismatch fixture"),
    );
    assert_eq!(
        segment.read_transcript().unwrap_err(),
        AssemblyAiProviderError::SegmentMismatch
    );

    let mut unredacted = RawTranscriptPage::new(
        RawTranscriptSnapshot::for_scope(&expected, "completed").expect("snapshot"),
        vec![RawUtterance::unredacted_for_test(
            SegmentId::new("segment-unredacted").expect("segment"),
            Some(String::from("A")),
            0,
            10,
            0.5,
            "secret text",
        )],
        None,
    )
    .expect("page");
    unredacted.refresh_digest();
    let mut redaction_provider = provider(
        &expected,
        TranscriptFixture::from_pages(vec![unredacted]).expect("redaction fixture"),
    );
    assert_eq!(
        redaction_provider.read_transcript().unwrap_err(),
        AssemblyAiProviderError::UnredactedContent
    );

    let mut invalid_confidence = RawTranscriptPage::new(
        RawTranscriptSnapshot::for_scope(&expected, "completed").expect("snapshot"),
        vec![RawUtterance {
            confidence: 1.5,
            ..utterances(&expected)[0].clone()
        }],
        None,
    )
    .expect("page");
    invalid_confidence.refresh_digest();
    let mut confidence_provider = provider(
        &expected,
        TranscriptFixture::from_pages(vec![invalid_confidence]).expect("confidence fixture"),
    );
    assert_eq!(
        confidence_provider.read_transcript().unwrap_err(),
        AssemblyAiProviderError::InvalidConfidence
    );

    let mut projection = provider(&expected, fixture(&expected, "completed"))
        .read_transcript()
        .expect("projection");
    projection.content_digest = Digest::from_text("tampered");
    assert_eq!(
        projection.validate_integrity().unwrap_err(),
        AssemblyAiResultError::ContentMismatch
    );
}

#[test]
fn transport_http_classes_timeout_server_error_malformed_and_access_loss_are_typed() {
    let errors = [
        AssemblyAiTransportError::Unauthorized401,
        AssemblyAiTransportError::Forbidden403,
        AssemblyAiTransportError::NotFound404,
        AssemblyAiTransportError::Conflict409,
        AssemblyAiTransportError::RateLimited429,
        AssemblyAiTransportError::Timeout,
        AssemblyAiTransportError::Server5xx { status: 503 },
        AssemblyAiTransportError::MalformedResponse,
        AssemblyAiTransportError::PartialResponse,
        AssemblyAiTransportError::AccessLost,
    ];
    for error in errors {
        let expected = scope();
        let mut provider = AssemblyAiProvider::new(
            registration(&expected),
            FakeTransport::new(fixture(&expected, "completed")).with_error(error.clone()),
            StaticApiKeyCredentialResolver::api_key("fixture-key"),
        )
        .expect("provider");
        assert_eq!(
            provider.read_transcript().unwrap_err(),
            AssemblyAiProviderError::Transport(error)
        );
    }

    let expected = scope();
    let mut blocked = AssemblyAiProvider::new(
        registration(&expected),
        BlockedEnvTransport::new(),
        StaticApiKeyCredentialResolver::api_key("fixture-key"),
    )
    .expect("blocked provider");
    assert_eq!(
        blocked.read_transcript().unwrap_err(),
        AssemblyAiProviderError::Transport(AssemblyAiTransportError::EnvironmentBlocked)
    );
}

#[test]
fn recording_loopback_and_blocked_env_never_claim_native_connected_first_party() {
    let expected = scope();
    let fixture = fixture(&expected, "completed");
    let mut recording = AssemblyAiProvider::new(
        registration(&expected),
        RecordingTransport::new(fixture.clone()),
        StaticApiKeyCredentialResolver::api_key("fixture-key"),
    )
    .expect("recording provider");
    let recording_projection = recording.read_transcript().expect("recording projection");
    assert_eq!(
        recording_projection.provenance,
        TransportProvenance::Recording
    );
    assert!(!recording_projection.connected);
    assert!(!recording_projection.native);
    assert!(!recording_projection.first_party);
    assert_eq!(recording.transport().request_count(), 2);
    assert!(!recording.transport().recording_digest().as_str().is_empty());

    let mut loopback = AssemblyAiProvider::new(
        registration(&expected),
        LoopbackTransport::new(fixture),
        StaticApiKeyCredentialResolver::api_key("fixture-key"),
    )
    .expect("loopback provider");
    let loopback_projection = loopback.read_transcript().expect("loopback projection");
    assert_eq!(
        loopback_projection.provenance,
        TransportProvenance::Loopback
    );
    assert!(!loopback_projection.connected);
    assert!(!loopback_projection.native);
    assert!(!loopback_projection.first_party);

    let scope_description = loopback.describe_scope().expect("scope description");
    assert!(!scope_description.connected);
    assert!(!scope_description.native);
    assert!(!scope_description.first_party);
    let blocked_scope = AssemblyAiProvider::new(
        registration(&expected),
        BlockedEnvTransport::new(),
        BlockedEnvCredentialResolver,
    )
    .expect("blocked scope provider")
    .describe_scope()
    .expect("blocked scope");
    assert_eq!(blocked_scope.provenance, TransportProvenance::BlockedEnv);
    assert!(!blocked_scope.connected);
    assert!(!blocked_scope.native);
    assert!(!blocked_scope.first_party);
}

#[test]
fn mission_proposal_is_decision_pending_recorded_idempotently_without_adoption() {
    let expected = scope();
    let registered = registration(&expected);
    let mut service = AssemblyAiTranscriptResultService::new(registered.clone()).expect("service");
    let mut provider = provider(&expected, fixture(&expected, "completed"));
    let projection = service.read_transcript(&mut provider).expect("projection");
    let mut consumer =
        MissionTranscriptResultConsumer::for_registration(&registered).expect("consumer");
    let proposal = service
        .compile_work_product_proposal(&consumer, &projection, "proposal-1")
        .expect("proposal");
    assert_eq!(
        proposal.disposition,
        hartevo_assemblyai_transcript_result_plugin::ProposalDisposition::DecisionPending
    );
    assert!(proposal.eligible_for_next_decision());
    assert!(proposal.is_review_only());
    assert!(!proposal.can_be_adopted());
    assert!(!consumer.can_adopt_work_product());
    assert!(!consumer.can_adopt_outcome());

    let first = service
        .record_work_product_proposal(&mut consumer, &proposal, "idempotency-1")
        .expect("recording");
    assert!(!first.replayed);
    assert!(!first.durable_provider_receipt);
    let replay = service
        .record_work_product_proposal(&mut consumer, &proposal, "idempotency-1")
        .expect("replay");
    assert!(replay.replayed);

    let second = service
        .compile_work_product_proposal(&consumer, &projection, "proposal-2")
        .expect("second proposal");
    assert_eq!(
        service
            .record_work_product_proposal(&mut consumer, &second, "idempotency-1")
            .unwrap_err(),
        AssemblyAiResultError::ReplayConflict
    );
    assert_eq!(
        service
            .compile_work_product_proposal(&consumer, &projection, "proposal-1")
            .unwrap_err(),
        AssemblyAiResultError::DuplicateProposal
    );
}

#[test]
fn stale_mission_and_registration_revocation_fail_closed() {
    let expected = scope();
    let registered = registration(&expected);
    let service = AssemblyAiTranscriptResultService::new(registered.clone()).expect("service");
    let projection = service
        .read_transcript(&mut provider(&expected, fixture(&expected, "completed")))
        .expect("projection");

    let mut stale = expected.clone();
    stale.mission = hartevo_assemblyai_transcript_result_plugin::MissionReference::new(
        MissionId::new("mission-1").expect("mission"),
        2,
    )
    .expect("stale Mission");
    let stale_consumer = MissionTranscriptResultConsumer::new(stale).expect("stale consumer");
    assert_eq!(
        stale_consumer
            .compile_proposal(&projection, "stale")
            .unwrap_err(),
        AssemblyAiResultError::ScopeMismatch
    );

    let revoked = registered.clone();
    revoked.revoke().expect("revoke");
    assert_eq!(revoked.state(), RegistrationState::Revoked);
    assert_eq!(
        AssemblyAiProvider::new(
            revoked,
            FakeTransport::new(fixture(&expected, "completed")),
            StaticApiKeyCredentialResolver::api_key("fixture-key"),
        )
        .unwrap_err(),
        AssemblyAiProviderError::RegistrationRevoked
    );

    let secret_revoked = registration(&expected);
    secret_revoked.revoke_secret_reference();
    let mut provider = AssemblyAiProvider::new(
        secret_revoked,
        FakeTransport::new(fixture(&expected, "completed")),
        StaticApiKeyCredentialResolver::api_key("fixture-key"),
    )
    .expect("provider with revoked secret");
    assert_eq!(
        provider.read_transcript().unwrap_err(),
        AssemblyAiProviderError::SecretRevoked
    );
}

#[test]
fn registration_registry_is_duplicate_safe_and_reversible() {
    let expected = scope();
    let original = registration(&expected);
    let mut registry = AssemblyAiRegistrationRegistry::default();
    registry.register(original.clone()).expect("register");
    assert_eq!(
        registry.register(original.clone()).unwrap_err(),
        AssemblyAiResultError::RegistrationAlreadyExists
    );
    let id = original.id().clone();
    registry.revoke(&id).expect("revoke");
    assert_eq!(
        registry.get(&id).expect("registration").state(),
        RegistrationState::Revoked
    );
    registry.restore(&id).expect("restore");
    registry.reverse(&id).expect("reverse");
    assert_eq!(
        registry.get(&id).expect("registration").state(),
        RegistrationState::Reversed
    );
}

#[test]
fn malformed_page_payload_is_rejected_before_projection() {
    let expected = scope();
    let mut page = RawTranscriptPage::new(
        RawTranscriptSnapshot::for_scope(&expected, "completed").expect("snapshot"),
        vec![utterances(&expected)[0].clone()],
        None,
    )
    .expect("page");
    page.payload_digest = Digest::from_text("tampered");
    let fixture = TranscriptFixture::from_pages_unchecked(vec![page]).expect("tampered fixture");
    let mut provider = provider(&expected, fixture);
    assert_eq!(
        provider.read_transcript().unwrap_err(),
        AssemblyAiProviderError::MalformedResponse
    );
}

#[test]
fn operation_recording_is_bounded_and_has_no_opaque_token() {
    let expected = scope();
    let mut provider = provider(&expected, fixture(&expected, "completed"));
    provider.read_transcript().expect("projection");
    let operations: Vec<AssemblyAiTransportOperation> = provider.operations();
    let json = serde_json::to_string(&operations).expect("operations JSON");
    assert!(!json.contains("assemblyai-fixture-page-1"));
    assert!(json.contains("pageTokenDigest"));
}
