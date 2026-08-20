use hartevo_heygen_video_result_plugin::{
    AdoptionDecision, ArtifactId, ArtifactMetadata, ArtifactReceipt, AssetId, AsyncVideoStatus,
    AvatarId, AvatarSelection, BlockedEnvTransport, CONSUMER_ID, CONTRACT_VERSION, Capability,
    CaptionExpectation, ConsentReference, CredentialScope, Digest, DurationExpectation,
    EVIDENCE_LEVEL, FixtureHttpsTransport, GenerationStatusProjection, HeyGenVideoProvider,
    HeyGenVideoResultRegistration, HeyGenVideoResultService, HttpsResponse, IdentityKind,
    InputAsset, Locale, LoopbackHttpsTransport, MediaType, MediaUrl, MissionId, MissionScope,
    MissionVideoResultConsumer, MissionVideoSource, OperationReceipt, PLUGIN_ID, PROVIDER_ID,
    PluginVersion, ProjectId, ProviderError, ProviderProvenance, ProviderStatus,
    RecordingHttpsTransport, RenderExpectations, SERVICE_ID, Scene, ScriptText, SecretReference,
    TemplateId, TemplateVariable, TransportError, TransportFailure, VariableName, VariableValue,
    VideoDimensions, VideoId, VoiceId, VoiceSelection, WorkspaceId,
};

fn scope() -> MissionScope {
    MissionScope::new(
        WorkspaceId::new("workspace-acme").expect("workspace"),
        ProjectId::new("project-launch").expect("project"),
        MissionId::new("mission-42").expect("mission"),
        TemplateId::new("template-news").expect("template"),
        AvatarSelection::provider_default(AvatarId::new("avatar-1").expect("avatar")),
        VoiceSelection::provider_default(VoiceId::new("voice-1").expect("voice")),
        Locale::new("en-US").expect("locale"),
    )
    .expect("scope")
}

fn source(scope: MissionScope, variable_order: &[(&str, &str)]) -> MissionVideoSource {
    let scenes = vec![
        Scene::new(
            1,
            "scene-1",
            ScriptText::new("Opening scene").expect("scene script"),
        )
        .expect("scene 1"),
        Scene::new(
            2,
            "scene-2",
            ScriptText::new("Closing scene").expect("scene script"),
        )
        .expect("scene 2"),
    ];
    let variables = variable_order
        .iter()
        .map(|(name, value)| {
            TemplateVariable::new(
                VariableName::new(*name).expect("variable name"),
                VariableValue::new(*value).expect("variable value"),
            )
            .expect("variable")
        })
        .collect();
    MissionVideoSource::new(
        scope,
        7,
        3,
        ScriptText::new("Mission script that must never be logged").expect("script"),
        scenes,
        variables,
        vec![
            InputAsset::new(
                AssetId::new("asset-1").expect("asset"),
                Digest::from_text("input-image-bytes"),
                512,
                MediaType::new("image/png").expect("media type"),
            )
            .expect("asset input"),
        ],
        RenderExpectations::new(
            VideoDimensions::new(1280, 720).expect("dimensions"),
            DurationExpectation::new(20, 40).expect("duration"),
            CaptionExpectation::Required,
        ),
    )
    .expect("source")
}

fn registration(scope: MissionScope) -> HeyGenVideoResultRegistration {
    HeyGenVideoResultRegistration::register(scope, Digest::from_text("implementation-v1"))
        .expect("registration")
}

fn secret(scope: &MissionScope) -> SecretReference {
    SecretReference::new(
        "secret-ref-live-key",
        CredentialScope::new(
            scope.workspace_id().clone(),
            scope.project_id().clone(),
            scope.mission_id().clone(),
            PROVIDER_ID,
        )
        .expect("credential scope"),
        1,
    )
    .expect("secret reference")
}

fn provider<T>(
    registration: HeyGenVideoResultRegistration,
    scope: &MissionScope,
    transport: T,
) -> HeyGenVideoProvider<T>
where
    T: hartevo_heygen_video_result_plugin::HttpsTransport,
{
    HeyGenVideoProvider::new(registration, secret(scope), transport).expect("provider")
}

fn completed_status(
    proposal: &hartevo_heygen_video_result_plugin::GenerationProposal,
) -> OperationReceipt {
    OperationReceipt::recorded(
        proposal,
        Some(VideoId::new("video-99").expect("video")),
        AsyncVideoStatus::Completed,
        20,
        ProviderProvenance::Recording,
    )
    .expect("completed status")
}

fn artifact(status: &OperationReceipt, artifact_id: &str, expires_at: u64) -> ArtifactReceipt {
    ArtifactReceipt::builder(
        ArtifactId::new(artifact_id).expect("artifact id"),
        status,
        MediaUrl::new("https://cdn.example.test/video.mp4?sig=private-signature").expect("URL"),
        expires_at,
        ArtifactMetadata::new(
            MediaType::new("video/mp4").expect("media type"),
            1024,
            VideoDimensions::new(1280, 720).expect("dimensions"),
            30,
            CaptionExpectation::Required,
        )
        .expect("metadata"),
        30,
        ProviderProvenance::Recording,
    )
    .build()
    .expect("artifact")
}

#[test]
fn exact_scene_variable_and_revision_digests_drive_idempotency() {
    let left = source(scope(), &[("headline", "Launch"), ("cta", "Learn")]);
    let right = source(scope(), &[("cta", "Learn"), ("headline", "Launch")]);
    assert_ne!(
        left.digests().variable_digest(),
        right.digests().variable_digest()
    );
    assert_ne!(
        left.digests().source_digest(),
        right.digests().source_digest()
    );

    let registration = registration(left.scope().clone());
    let provider = provider(
        registration.clone(),
        left.scope(),
        LoopbackHttpsTransport::new(),
    );
    let left_proposal = provider.propose_generation(&left).expect("left proposal");
    let right_proposal = provider.propose_generation(&right).expect("right proposal");
    assert_ne!(
        left_proposal.fence().fingerprint(),
        right_proposal.fence().fingerprint()
    );
    assert_eq!(
        left_proposal.scope().template_id().as_str(),
        "template-news"
    );
    assert_eq!(left_proposal.scope().locale().as_str(), "en-US");
}

#[test]
fn custom_identity_and_secret_scope_fail_closed_without_material_leaks() {
    let wrong_consent = ConsentReference::new(
        "consent-avatar-1",
        WorkspaceId::new("workspace-other").expect("workspace"),
        ProjectId::new("project-launch").expect("project"),
        MissionId::new("mission-42").expect("mission"),
        IdentityKind::Avatar,
        "avatar-custom",
        1,
    )
    .expect("consent reference");
    assert!(
        MissionScope::new(
            WorkspaceId::new("workspace-acme").expect("workspace"),
            ProjectId::new("project-launch").expect("project"),
            MissionId::new("mission-42").expect("mission"),
            TemplateId::new("template-news").expect("template"),
            AvatarSelection::custom(
                AvatarId::new("avatar-custom").expect("avatar"),
                wrong_consent,
            ),
            VoiceSelection::provider_default(VoiceId::new("voice-1").expect("voice")),
            Locale::new("en-US").expect("locale"),
        )
        .is_err()
    );

    let good_consent = ConsentReference::new(
        "consent-avatar-1",
        WorkspaceId::new("workspace-acme").expect("workspace"),
        ProjectId::new("project-launch").expect("project"),
        MissionId::new("mission-42").expect("mission"),
        IdentityKind::Avatar,
        "avatar-custom",
        1,
    )
    .expect("consent reference");
    let custom_scope = MissionScope::new(
        WorkspaceId::new("workspace-acme").expect("workspace"),
        ProjectId::new("project-launch").expect("project"),
        MissionId::new("mission-42").expect("mission"),
        TemplateId::new("template-news").expect("template"),
        AvatarSelection::custom(
            AvatarId::new("avatar-custom").expect("avatar"),
            good_consent,
        ),
        VoiceSelection::provider_default(VoiceId::new("voice-1").expect("voice")),
        Locale::new("en-US").expect("locale"),
    )
    .expect("custom scope");
    let opaque_secret = secret(&custom_scope);
    let debug = format!("{opaque_secret:?}");
    assert!(!debug.contains("secret-ref-live-key"));
    assert!(
        !serde_json::to_string(&opaque_secret)
            .expect("redacted secret serialization")
            .contains("live-key")
    );
}

#[test]
fn all_async_states_project_and_terminal_regression_is_rejected() {
    let scope = scope();
    let registration = registration(scope.clone());
    let source = source(scope.clone(), &[("headline", "Launch")]);
    let provider = provider(registration.clone(), &scope, LoopbackHttpsTransport::new());
    let proposal = provider.propose_generation(&source).expect("proposal");
    let mut consumer = MissionVideoResultConsumer::new(registration).expect("consumer");

    let statuses = [
        (
            AsyncVideoStatus::Pending,
            GenerationStatusProjection::Pending,
        ),
        (
            AsyncVideoStatus::Waiting,
            GenerationStatusProjection::Waiting,
        ),
        (
            AsyncVideoStatus::Processing,
            GenerationStatusProjection::Processing,
        ),
        (
            AsyncVideoStatus::Completed,
            GenerationStatusProjection::Completed,
        ),
    ];
    for (status, expected) in statuses {
        let receipt = OperationReceipt::recorded(
            &proposal,
            Some(VideoId::new("video-99").expect("video")),
            status,
            10,
            ProviderProvenance::Recording,
        )
        .expect("status");
        assert_eq!(
            consumer.project_status(&receipt).expect("projection"),
            expected
        );
    }
    let failed_after_completed = OperationReceipt::recorded(
        &proposal,
        Some(VideoId::new("video-99").expect("video")),
        AsyncVideoStatus::Failed {
            code: "provider_failed".to_owned(),
        },
        11,
        ProviderProvenance::Recording,
    )
    .expect("failed receipt");
    assert!(matches!(
        consumer.project_status(&failed_after_completed),
        Err(hartevo_heygen_video_result_plugin::ConsumerError::StaleStatus)
    ));
    let cross_operation = OperationReceipt::recorded(
        &proposal,
        Some(VideoId::new("video-other").expect("video")),
        AsyncVideoStatus::Completed,
        12,
        ProviderProvenance::Recording,
    )
    .expect("cross operation receipt");
    assert!(matches!(
        consumer.project_status(&cross_operation),
        Err(hartevo_heygen_video_result_plugin::ConsumerError::StaleStatus)
    ));
}

#[test]
fn completed_expiring_url_is_blocked_until_independent_bytes_are_digested() {
    let scope = scope();
    let registration = registration(scope.clone());
    let source = source(scope.clone(), &[("headline", "Launch")]);
    let provider = provider(registration.clone(), &scope, LoopbackHttpsTransport::new());
    let proposal = provider.propose_generation(&source).expect("proposal");
    let status = completed_status(&proposal);
    let mut consumer = MissionVideoResultConsumer::new(registration).expect("consumer");

    let expiring = artifact(&status, "artifact-expiring", 100);
    let expiry_receipt = expiring.url_expiry_receipt();
    assert_eq!(expiry_receipt.expires_at(), 100);
    assert_eq!(
        expiry_receipt.artifact_receipt_digest(),
        expiring.receipt_digest()
    );
    let blocked = consumer
        .propose_adoption(&proposal, &status, &expiring, 90)
        .expect("blocked proposal");
    assert_eq!(
        blocked.decision(),
        AdoptionDecision::BlockedPendingIndependentByteDigest
    );
    assert!(matches!(
        consumer.propose_adoption(&proposal, &status, &expiring, 100),
        Err(hartevo_heygen_video_result_plugin::ConsumerError::ExpiredUrl)
    ));

    let independent = ArtifactReceipt::builder(
        ArtifactId::new("artifact-independent").expect("artifact"),
        &status,
        MediaUrl::new("https://cdn.example.test/video.mp4?sig=another-private-signature")
            .expect("URL"),
        100,
        expiring.metadata().clone(),
        30,
        ProviderProvenance::Recording,
    )
    .independent_content_digest(Digest::from_text("downloaded-video-bytes"))
    .build()
    .expect("independent artifact");
    let ready = consumer
        .propose_adoption(&proposal, &status, &independent, 90)
        .expect("layer 2 review proposal");
    assert_eq!(
        ready.decision(),
        AdoptionDecision::ReadyForLayer2Verification
    );
    assert!(matches!(
        consumer.propose_adoption(&proposal, &status, &independent, 90),
        Err(hartevo_heygen_video_result_plugin::ConsumerError::DuplicateFingerprint)
    ));
}

#[test]
fn metadata_and_content_digest_mismatches_are_rejected() {
    let scope = scope();
    let registration = registration(scope.clone());
    let source = source(scope.clone(), &[("headline", "Launch")]);
    let provider = provider(registration.clone(), &scope, LoopbackHttpsTransport::new());
    let proposal = provider.propose_generation(&source).expect("proposal");
    let status = completed_status(&proposal);
    let mut consumer = MissionVideoResultConsumer::new(registration).expect("consumer");

    let mismatched_metadata = ArtifactReceipt::builder(
        ArtifactId::new("artifact-wrong-metadata").expect("artifact"),
        &status,
        MediaUrl::new("https://cdn.example.test/video.mp4?sig=metadata").expect("URL"),
        100,
        ArtifactMetadata::new(
            MediaType::new("video/mp4").expect("media type"),
            1024,
            VideoDimensions::new(1920, 1080).expect("dimensions"),
            30,
            CaptionExpectation::Required,
        )
        .expect("metadata"),
        30,
        ProviderProvenance::Recording,
    )
    .build()
    .expect("artifact");
    assert!(matches!(
        consumer.propose_adoption(&proposal, &status, &mismatched_metadata, 40),
        Err(hartevo_heygen_video_result_plugin::ConsumerError::ArtifactMetadataMismatch)
    ));

    let mismatched_content = ArtifactReceipt::builder(
        ArtifactId::new("artifact-wrong-content").expect("artifact"),
        &status,
        MediaUrl::new("https://cdn.example.test/video.mp4?sig=content").expect("URL"),
        100,
        artifact(&status, "reference", 100).metadata().clone(),
        30,
        ProviderProvenance::Recording,
    )
    .provider_artifact_digest(Digest::from_text("provider-bytes"))
    .independent_content_digest(Digest::from_text("different-bytes"))
    .build()
    .expect("artifact");
    assert!(matches!(
        consumer.propose_adoption(&proposal, &status, &mismatched_content, 40),
        Err(hartevo_heygen_video_result_plugin::ConsumerError::ContentDigestMismatch)
    ));
}

#[test]
fn proposal_service_fence_is_duplicate_safe_and_registration_is_reversible() {
    let scope = scope();
    let registration = registration(scope.clone());
    let source = source(scope.clone(), &[("headline", "Launch")]);
    let provider = provider(registration.clone(), &scope, LoopbackHttpsTransport::new());
    let mut service = HeyGenVideoResultService::new(registration.clone()).expect("service");
    assert_eq!(
        registration.receipt().state(),
        hartevo_heygen_video_result_plugin::RegistrationState::Active
    );
    let first = service
        .propose_generation(&provider, &source)
        .expect("first proposal");
    assert!(matches!(
        service.propose_generation(&provider, &source),
        Err(hartevo_heygen_video_result_plugin::ServiceError::DuplicateProposal)
    ));
    assert_eq!(first.provider_id(), PROVIDER_ID);
    assert_eq!(first.provider_version(), PluginVersion::new(1, 0, 0));

    let revocation = registration.revoke().expect("revoke");
    assert_eq!(revocation.revocation_epoch(), 1);
    assert_eq!(
        registration.receipt().state(),
        hartevo_heygen_video_result_plugin::RegistrationState::Revoked
    );
    assert!(matches!(
        service.propose_generation(&provider, &source),
        Err(
            hartevo_heygen_video_result_plugin::ServiceError::Registration(
                hartevo_heygen_video_result_plugin::RegistrationError::Revoked
            )
        )
    ));
}

#[test]
fn fixture_recording_loopback_and_blocked_env_are_never_connected() {
    let scope = scope();
    let registration = registration(scope.clone());
    let responses = vec![
        Ok(HttpsResponse::Capability {
            capability: Capability::TemplateProbe,
            supported: true,
        }),
        Ok(HttpsResponse::Template {
            template_id: scope.template_id().clone(),
            supported: true,
            template_digest: Some(Digest::from_text("template")),
        }),
        Ok(HttpsResponse::Identity {
            identity_kind: IdentityKind::Avatar,
            identity_id: scope.avatar().avatar_id().as_str().to_owned(),
            supported: true,
            identity_digest: Some(Digest::from_text("avatar")),
        }),
        Ok(HttpsResponse::Identity {
            identity_kind: IdentityKind::Voice,
            identity_id: scope.voice().voice_id().as_str().to_owned(),
            supported: true,
            identity_digest: Some(Digest::from_text("voice")),
        }),
    ];
    let mut fixture_provider = provider(
        registration.clone(),
        &scope,
        FixtureHttpsTransport::new(responses),
    );
    let capability = fixture_provider
        .probe_capability(Capability::TemplateProbe, 1)
        .expect("capability");
    let template = fixture_provider
        .probe_template(scope.template_id().clone(), 2)
        .expect("template");
    let avatar = fixture_provider
        .probe_avatar(scope.avatar().avatar_id().clone(), None, 3)
        .expect("avatar");
    let voice = fixture_provider
        .probe_voice(scope.voice().voice_id().clone(), None, 4)
        .expect("voice");
    for evidence in [
        capability.evidence(),
        template.evidence(),
        avatar.evidence(),
        voice.evidence(),
    ] {
        assert!(!evidence.connected());
        assert!(!evidence.native());
    }

    let mut blocked = provider(registration.clone(), &scope, BlockedEnvTransport);
    assert!(matches!(
        blocked.probe_capability(Capability::TemplateProbe, 5),
        Err(ProviderError::Transport(TransportError::BlockedEnv))
    ));

    let mut rate_limited = provider(
        registration.clone(),
        &scope,
        RecordingHttpsTransport::recording(vec![Err(TransportError::Failure(
            TransportFailure::RateLimited {
                retry_after_seconds: 17,
            },
        ))]),
    );
    assert!(matches!(
        rate_limited.probe_capability(Capability::TemplateProbe, 6),
        Err(ProviderError::Transport(TransportError::Failure(
            TransportFailure::RateLimited {
                retry_after_seconds: 17
            }
        )))
    ));
    assert_eq!(EVIDENCE_LEVEL, "L1");
    assert_eq!(PLUGIN_ID, "heygen.video.result");
    assert_eq!(SERVICE_ID, "video.result.heygen");
    assert_eq!(PROVIDER_ID, "provider.heygen.video-result");
    assert_eq!(CONSUMER_ID, "mission.video-result.heygen");
    assert_eq!(CONTRACT_VERSION, "heygen-video-result-layer1/v1");
    assert_eq!(ProviderStatus::BlockedEnv, ProviderStatus::BlockedEnv);
}

#[test]
fn debug_and_safe_serialization_redact_scripts_urls_and_secret_references() {
    let scope = scope();
    let source = source(scope.clone(), &[("customer_name", "Ada Lovelace")]);
    let debug = format!("{source:?}");
    assert!(!debug.contains("customer_name"));
    assert!(!debug.contains("Ada Lovelace"));
    assert!(!debug.contains("Mission script that must never be logged"));
    let source_json = serde_json::to_string(&source).expect("safe source JSON");
    assert!(!source_json.contains("customer_name"));
    assert!(!source_json.contains("Ada Lovelace"));

    let registration = registration(scope.clone());
    let provider = provider(registration, &scope, LoopbackHttpsTransport::new());
    let proposal = provider.propose_generation(&source).expect("proposal");
    let status = completed_status(&proposal);
    let receipt = artifact(&status, "artifact-redaction", 100);
    let encoded = serde_json::to_string(&receipt).expect("safe receipt JSON");
    assert!(!encoded.contains("private-signature"));
    assert!(encoded.contains("redacted-media-url"));
}
