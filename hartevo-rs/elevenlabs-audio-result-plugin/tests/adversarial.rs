use std::fmt::Debug;

use hartevo_elevenlabs_audio_result_plugin::{
    AdoptionDecision, ApiHost, AudioConfig, AudioContentEvidence, AudioCreationObjective,
    AudioStatus, BlockedEnvTransport, Digest, ElevenLabsAudioResultRegistration,
    ElevenLabsAudioResultService, ElevenLabsProvider, HttpsRequest, HttpsResponse, HttpsTransport,
    LanguageCode, LoopbackHttpsTransport, MAX_RECORDED_USAGE_CHARACTERS, MAX_TEXT_CHARACTERS,
    MissionAudioResultConsumer, MissionId, MissionScope, ModelId, ModelSelection, ObjectiveId,
    OperationId, OutputFormat, PluginVersion, ProjectId, ProjectScope, ProviderError,
    ProviderErrorKind, RecordingHttpsTransport, RedactionState, ScriptText, SecretReference,
    SynthesisBinding, SynthesisResponse, SynthesisStatus, TransportError, TransportFailure,
    UsageEvidence, VoiceId, VoiceSelection, WorkProductId, WorkProductScope, WorkspaceId,
};

fn digest(label: &str) -> Digest {
    Digest::from_text(label)
}

fn scope_with_revision(mission_revision: u64) -> MissionScope {
    let project = ProjectScope::new(
        WorkspaceId::new("workspace-1").expect("workspace"),
        ProjectId::new("project-1").expect("project"),
        3,
    )
    .expect("project scope");
    MissionScope::new(
        project,
        MissionId::new("mission-1").expect("mission"),
        mission_revision,
        WorkProductScope::new(
            WorkProductId::new("work-product-1").expect("work product"),
            2,
        )
        .expect("work product scope"),
        ApiHost::official(),
        VoiceSelection::new(
            VoiceId::new("voice-1").expect("voice"),
            4,
            digest("voice-v4"),
        )
        .expect("voice selection"),
        ModelSelection::new(
            ModelId::new("eleven_multilingual_v2").expect("model"),
            7,
            digest("model-v7"),
        )
        .expect("model selection"),
        LanguageCode::new("en-US").expect("language"),
        AudioConfig::new(
            9,
            OutputFormat::new("mp3_44100_128").expect("format"),
            1_000,
            60_000,
        )
        .expect("config"),
    )
    .expect("mission scope")
}

fn objective(scope: MissionScope, text: &str) -> AudioCreationObjective {
    AudioCreationObjective::new(
        scope,
        ObjectiveId::new("objective-1").expect("objective"),
        6,
        ScriptText::new(text).expect("bounded text"),
    )
    .expect("objective")
}

fn registration(scope: MissionScope) -> ElevenLabsAudioResultRegistration {
    ElevenLabsAudioResultRegistration::register(scope, digest("implementation-v1"))
        .expect("registration")
}

fn usage(
    proposal: &hartevo_elevenlabs_audio_result_plugin::AudioGenerationProposal,
) -> UsageEvidence {
    UsageEvidence::new(
        proposal.text_character_count(),
        Some(proposal.text_character_count()),
        Some(1_000),
        proposal.scope().output_format().clone(),
        RedactionState::Redacted,
    )
    .expect("usage")
}

fn content(
    proposal: &hartevo_elevenlabs_audio_result_plugin::AudioGenerationProposal,
) -> AudioContentEvidence {
    AudioContentEvidence::new(
        digest("audio-content-v1"),
        proposal.scope().output_format().clone(),
        1_000,
        Some(512),
        RedactionState::Redacted,
    )
    .expect("content")
}

fn provider_with_recording(
    registration: &ElevenLabsAudioResultRegistration,
    response: Result<HttpsResponse, TransportError>,
) -> ElevenLabsProvider<RecordingHttpsTransport> {
    ElevenLabsProvider::new(
        registration.clone(),
        SecretReference::new(registration.scope(), "secret-ref-do-not-store")
            .expect("opaque secret reference"),
        RecordingHttpsTransport::recording([response]),
    )
    .expect("provider")
}

#[test]
fn loopback_compiles_exact_proposal_and_work_product_boundary() {
    let scope = scope_with_revision(5);
    let objective = objective(scope.clone(), "Hello, bounded world.");
    let registration = registration(scope);
    assert!(registration.verify_digest());
    assert!(registration.receipt().verify_digest());
    let secret = SecretReference::new(registration.scope(), "opaque-api-key-reference")
        .expect("secret reference");
    let provider = ElevenLabsProvider::new(
        registration.clone(),
        secret.clone(),
        LoopbackHttpsTransport::new(),
    )
    .expect("provider");
    let mut service = ElevenLabsAudioResultService::new(registration.clone()).expect("service");
    let mut consumer = MissionAudioResultConsumer::new(registration).expect("consumer");

    let proposal = service
        .propose_audio(&provider, &objective)
        .expect("proposal");
    assert!(proposal.verify_digest());
    assert_eq!(proposal.binding().text_digest(), &objective.text_digest());
    assert_eq!(proposal.scope().host().as_str(), ApiHost::OFFICIAL);
    assert_eq!(proposal.scope().output_format().as_str(), "mp3_44100_128");

    let request = HttpsRequest::for_proposal(&proposal);
    assert_eq!(request.path(), "/v1/text-to-speech/voice-1");
    let serialized_request = serde_json::to_string(&request).expect("request JSON");
    assert!(!serialized_request.contains("Hello, bounded world."));
    let serialized_proposal = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!serialized_proposal.contains("Hello, bounded world."));
    let secret_json = serde_json::to_string(&secret).expect("secret JSON");
    assert!(!secret_json.contains("opaque-api-key-reference"));

    let mut provider = ElevenLabsProvider::new(
        proposal_registration(&proposal),
        secret,
        LoopbackHttpsTransport::new(),
    )
    .expect("loopback provider");
    let receipt = service
        .record_synthesis(&mut provider, &proposal)
        .expect("recorded loopback response");
    assert_eq!(receipt.status(), AudioStatus::Completed);
    assert!(!receipt.evidence().connected());
    assert!(!receipt.evidence().native());
    assert_eq!(receipt.usage().expect("usage").input_character_count(), 21);
    assert!(!receipt.content().expect("content").bytes_retained());
    assert!(receipt.verify_digest());

    let projection = service
        .project_status(&mut consumer, &receipt)
        .expect("projection");
    assert_eq!(projection.status(), SynthesisStatus::Completed);
    let work_product = service
        .propose_work_product(&mut consumer, &proposal, &receipt)
        .expect("work product proposal");
    assert_eq!(
        work_product.decision(),
        AdoptionDecision::ReadyForWorkProductProposal
    );
    assert_eq!(
        work_product.audio_content_digest(),
        receipt.content().expect("content").audio_content_digest()
    );
    assert!(work_product.verify_fingerprint());
}

fn proposal_registration(
    proposal: &hartevo_elevenlabs_audio_result_plugin::AudioGenerationProposal,
) -> ElevenLabsAudioResultRegistration {
    ElevenLabsAudioResultRegistration::register(
        proposal.scope().clone(),
        digest("implementation-v1"),
    )
    .expect("proposal registration")
}

#[test]
fn status_projection_preserves_pending_completed_failed_expired_and_unknown() {
    let scope = scope_with_revision(5);
    let objective = objective(scope.clone(), "status matrix");
    let registration = registration(scope);
    let provider = provider_with_recording(&registration, Err(TransportError::BlockedEnv));
    let proposal = provider.propose_audio(&objective).expect("proposal");

    let responses = [
        SynthesisResponse::pending(&proposal, 1).expect("pending"),
        SynthesisResponse::completed(&proposal, usage(&proposal), content(&proposal), 2)
            .expect("completed"),
        SynthesisResponse::failed(&proposal, TransportFailure::http(500), 3).expect("failed"),
        SynthesisResponse::expired(&proposal, 4).expect("expired"),
        SynthesisResponse::provider_unknown(&proposal, TransportFailure::Timeout, 5)
            .expect("unknown"),
    ];
    assert_eq!(responses[0].status(), SynthesisStatus::Pending);
    assert_eq!(responses[1].status(), SynthesisStatus::Completed);
    assert_eq!(responses[2].status(), SynthesisStatus::Failed);
    assert_eq!(responses[3].status(), SynthesisStatus::Expired);
    assert_eq!(responses[4].status(), SynthesisStatus::ProviderUnknown);

    for (response, expected) in responses.into_iter().zip([
        SynthesisStatus::Pending,
        SynthesisStatus::Completed,
        SynthesisStatus::Failed,
        SynthesisStatus::Expired,
        SynthesisStatus::ProviderUnknown,
    ]) {
        let provider = provider_with_recording(&registration, Err(TransportError::BlockedEnv));
        let receipt = provider
            .record_response(&proposal, response)
            .expect("typed status receipt");
        assert_eq!(receipt.status(), expected);
    }
}

#[test]
fn duplicate_proposals_and_work_product_replays_are_fenced() {
    let scope = scope_with_revision(5);
    let objective = objective(scope.clone(), "duplicate boundary");
    let registration = registration(scope);
    let secret = SecretReference::new(registration.scope(), "secret-ref").expect("secret");
    let provider =
        ElevenLabsProvider::new(registration.clone(), secret, LoopbackHttpsTransport::new())
            .expect("provider");
    let mut service = ElevenLabsAudioResultService::new(registration.clone()).expect("service");
    let mut consumer = MissionAudioResultConsumer::new(registration).expect("consumer");
    let proposal = service
        .propose_audio(&provider, &objective)
        .expect("proposal");
    assert!(matches!(
        service.propose_audio(&provider, &objective),
        Err(hartevo_elevenlabs_audio_result_plugin::ServiceError::DuplicateProposal)
    ));
    let mut provider = ElevenLabsProvider::new(
        proposal_registration(&proposal),
        SecretReference::new(proposal.scope(), "secret-ref").expect("secret"),
        LoopbackHttpsTransport::new(),
    )
    .expect("provider");
    let receipt = service
        .record_synthesis(&mut provider, &proposal)
        .expect("receipt");
    assert!(consumer.project_status(&receipt).is_ok());
    assert!(consumer.project_status(&receipt).is_ok());
    assert!(consumer.propose_work_product(&proposal, &receipt).is_ok());
    assert!(matches!(
        consumer.propose_work_product(&proposal, &receipt),
        Err(hartevo_elevenlabs_audio_result_plugin::ConsumerError::DuplicateFingerprint)
    ));
}

#[test]
fn voice_model_text_and_config_drift_is_rejected() {
    let scope = scope_with_revision(5);
    let objective = objective(scope.clone(), "binding drift");
    let registration = registration(scope.clone());
    let provider = provider_with_recording(&registration, Err(TransportError::BlockedEnv));
    let proposal = provider.propose_audio(&objective).expect("proposal");

    let drift_scope = scope_with_revision(5);
    let drift_binding = SynthesisBinding::for_scope(
        &MissionScope::new(
            drift_scope.project().clone(),
            drift_scope.mission_id().clone(),
            drift_scope.mission_revision(),
            drift_scope.work_product().clone(),
            drift_scope.host().clone(),
            VoiceSelection::new(
                VoiceId::new("voice-drift").expect("voice"),
                99,
                digest("voice-drift"),
            )
            .expect("voice"),
            ModelSelection::new(
                ModelId::new("model-drift").expect("model"),
                99,
                digest("model-drift"),
            )
            .expect("model"),
            drift_scope.language().clone(),
            AudioConfig::new(
                99,
                OutputFormat::new("pcm_44100").expect("format"),
                1_000,
                60_000,
            )
            .expect("config"),
        )
        .expect("drift scope"),
        objective.text_revision(),
        objective.text_digest(),
    );
    let response = SynthesisResponse::recorded(
        proposal.fence().operation_id().clone(),
        proposal.fence().fingerprint().clone(),
        drift_binding,
        SynthesisStatus::Pending,
        None,
        None,
        None,
        1,
    )
    .expect("response");
    assert!(matches!(
        provider.record_response(&proposal, response),
        Err(ProviderError::Evidence(
            ProviderErrorKind::VoiceDrift
                | ProviderErrorKind::ModelDrift
                | ProviderErrorKind::OutputFormatMismatch
                | ProviderErrorKind::ConfigMismatch
        ))
    ));

    let text_binding = SynthesisBinding::for_scope(
        &scope_with_revision(5),
        objective.text_revision(),
        digest("different-text"),
    );
    let response = SynthesisResponse::recorded(
        proposal.fence().operation_id().clone(),
        proposal.fence().fingerprint().clone(),
        text_binding,
        SynthesisStatus::Pending,
        None,
        None,
        None,
        2,
    )
    .expect("response");
    assert!(matches!(
        provider.record_response(&proposal, response),
        Err(ProviderError::Evidence(ProviderErrorKind::TextMismatch))
    ));
}

#[test]
fn provider_failures_are_preserved_without_connected_claims() {
    let scope = scope_with_revision(5);
    let objective = objective(scope.clone(), "failure matrix");
    let registration = registration(scope);
    let failures = [
        TransportFailure::unauthorized(),
        TransportFailure::forbidden(),
        TransportFailure::not_found(),
        TransportFailure::conflict(),
        TransportFailure::rate_limited(30),
        TransportFailure::Timeout,
        TransportFailure::http(500),
        TransportFailure::MalformedResponse,
        TransportFailure::PartialResponse,
        TransportFailure::ByteDigestMismatch,
        TransportFailure::AccessRevoked,
    ];
    for failure in failures {
        let mut provider =
            provider_with_recording(&registration, Err(TransportError::Failure(failure.clone())));
        let proposal = provider.propose_audio(&objective).expect("proposal");
        assert!(matches!(
            provider.record_synthesis(&proposal),
            Err(ProviderError::Transport(TransportError::Failure(actual))) if actual == failure
        ));
    }
    let mut blocked = ElevenLabsProvider::new(
        registration,
        SecretReference::new(&scope_with_revision(5), "secret-ref").expect("secret"),
        BlockedEnvTransport,
    )
    .expect("blocked provider");
    let proposal = blocked.propose_audio(&objective).expect("proposal");
    assert!(matches!(
        blocked.record_synthesis(&proposal),
        Err(ProviderError::Transport(TransportError::BlockedEnv))
    ));
}

#[test]
fn malformed_partial_and_digest_mismatch_evidence_is_rejected() {
    let scope = scope_with_revision(5);
    let objective = objective(scope.clone(), "integrity boundary");
    let registration = registration(scope);
    let provider = provider_with_recording(&registration, Err(TransportError::BlockedEnv));
    let proposal = provider.propose_audio(&objective).expect("proposal");

    let incomplete = SynthesisResponse::recorded(
        proposal.fence().operation_id().clone(),
        proposal.fence().fingerprint().clone(),
        proposal.binding().clone(),
        SynthesisStatus::Completed,
        Some(usage(&proposal)),
        None,
        None,
        1,
    )
    .expect("partial response fixture");
    assert!(matches!(
        provider.record_response(&proposal, incomplete),
        Err(ProviderError::Evidence(
            ProviderErrorKind::MissingContentDigest
        ))
    ));

    let mismatched_content =
        content(&proposal).with_independent_content_digest(digest("independent-different"));
    let mismatched =
        SynthesisResponse::completed(&proposal, usage(&proposal), mismatched_content, 2)
            .expect("mismatch fixture");
    assert!(matches!(
        provider.record_response(&proposal, mismatched),
        Err(ProviderError::Evidence(
            ProviderErrorKind::ContentDigestMismatch
        ))
    ));

    let truncated_usage = UsageEvidence::new(
        proposal.text_character_count(),
        Some(proposal.text_character_count()),
        Some(1_000),
        proposal.scope().output_format().clone(),
        RedactionState::Truncated,
    )
    .expect("truncated usage");
    let receipt = provider
        .record_response(
            &proposal,
            SynthesisResponse::completed(&proposal, truncated_usage, content(&proposal), 3)
                .expect("truncated response"),
        )
        .expect("recorded truncated receipt");
    let mut consumer =
        MissionAudioResultConsumer::new(proposal_registration(&proposal)).expect("consumer");
    assert!(matches!(
        consumer.propose_work_product(&proposal, &receipt),
        Err(hartevo_elevenlabs_audio_result_plugin::ConsumerError::RedactedEvidence)
    ));
}

#[test]
fn text_character_and_duration_bounds_are_enforced() {
    let long_text = "x".repeat(MAX_TEXT_CHARACTERS + 1);
    assert!(matches!(
        ScriptText::new(long_text),
        Err(hartevo_elevenlabs_audio_result_plugin::TypeError::TextTooLong)
    ));
    assert!(matches!(
        UsageEvidence::new(
            MAX_RECORDED_USAGE_CHARACTERS + 1,
            None,
            None,
            OutputFormat::new("mp3_44100_128").expect("format"),
            RedactionState::Redacted,
        ),
        Err(ProviderError::Operation(
            ProviderErrorKind::UsageLimitExceeded
        ))
    ));

    let base = scope_with_revision(5);
    let small_config = AudioConfig::new(
        10,
        OutputFormat::new("mp3_44100_128").expect("format"),
        10,
        60_000,
    )
    .expect("small config");
    let small_scope = MissionScope::new(
        base.project().clone(),
        base.mission_id().clone(),
        base.mission_revision(),
        base.work_product().clone(),
        base.host().clone(),
        base.voice().clone(),
        base.model().clone(),
        base.language().clone(),
        small_config,
    )
    .expect("small scope");
    assert!(matches!(
        AudioCreationObjective::new(
            small_scope,
            ObjectiveId::new("objective-1").expect("objective"),
            1,
            ScriptText::new("01234567890").expect("global text bound"),
        ),
        Err(hartevo_elevenlabs_audio_result_plugin::TypeError::TextTooLong)
    ));
}

#[test]
fn status_regression_after_terminal_evidence_is_rejected() {
    let scope = scope_with_revision(5);
    let objective = objective(scope.clone(), "status regression");
    let registration = registration(scope);
    let provider = provider_with_recording(&registration, Err(TransportError::BlockedEnv));
    let proposal = provider.propose_audio(&objective).expect("proposal");
    let pending = provider
        .record_response(
            &proposal,
            SynthesisResponse::pending(&proposal, 1).expect("pending"),
        )
        .expect("pending receipt");
    let completed = provider
        .record_response(
            &proposal,
            SynthesisResponse::completed(&proposal, usage(&proposal), content(&proposal), 2)
                .expect("completed"),
        )
        .expect("completed receipt");
    let replayed_pending = provider
        .record_response(
            &proposal,
            SynthesisResponse::pending(&proposal, 3).expect("pending replay"),
        )
        .expect("pending receipt");
    let mut consumer =
        MissionAudioResultConsumer::new(proposal_registration(&proposal)).expect("consumer");
    consumer
        .project_status(&pending)
        .expect("pending projection");
    consumer
        .project_status(&completed)
        .expect("completed projection");
    assert!(matches!(
        consumer.project_status(&replayed_pending),
        Err(hartevo_elevenlabs_audio_result_plugin::ConsumerError::StaleStatus)
    ));
}

#[test]
fn stale_scope_and_revocation_fail_closed() {
    let scope = scope_with_revision(5);
    let mission_objective = objective(scope.clone(), "revision boundary");
    let registration = registration(scope.clone());
    let secret = SecretReference::new(&scope, "secret-ref").expect("secret");
    let provider =
        ElevenLabsProvider::new(registration.clone(), secret, LoopbackHttpsTransport::new())
            .expect("provider");
    let stale_objective = objective(scope_with_revision(6), "revision boundary");
    assert!(matches!(
        provider.propose_audio(&stale_objective),
        Err(ProviderError::Registration(
            hartevo_elevenlabs_audio_result_plugin::RegistrationError::ScopeMismatch
        ))
    ));

    registration.revoke().expect("revoke");
    assert!(matches!(
        ElevenLabsAudioResultService::new(registration.clone()),
        Err(
            hartevo_elevenlabs_audio_result_plugin::ServiceError::Registration(
                hartevo_elevenlabs_audio_result_plugin::RegistrationError::Revoked
            )
        )
    ));
    assert!(matches!(
        provider.propose_audio(&mission_objective),
        Err(ProviderError::Registration(
            hartevo_elevenlabs_audio_result_plugin::RegistrationError::Revoked
        ))
    ));
}

#[test]
fn official_host_and_secret_scope_are_exact() {
    assert!(ApiHost::new("https://example.invalid").is_err());
    let scope = scope_with_revision(5);
    let secret = SecretReference::for_provider(&scope, "other.provider", "opaque-ref")
        .expect("foreign opaque reference can be represented");
    assert!(matches!(
        ElevenLabsProvider::new(registration(scope), secret, LoopbackHttpsTransport::new(),),
        Err(ProviderError::Registration(
            hartevo_elevenlabs_audio_result_plugin::RegistrationError::ScopeMismatch
        ))
    ));
}

#[allow(dead_code)]
fn _assert_public_types_are_debug<T: Debug>() {}

#[allow(dead_code)]
fn _assert_transport_is_typed<T: HttpsTransport>() {}

#[allow(dead_code)]
fn _operation_id_is_constructible() -> OperationId {
    OperationId::new("op-test").expect("operation")
}

#[allow(dead_code)]
fn _version_is_constructible() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}
