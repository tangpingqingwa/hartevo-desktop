use hartevo_crowdin_localization_result_plugin::{
    ApprovalState, BlockedEnvCrowdinTransport, BoundedCounts, BuildState, CROWDIN_API_ORIGIN,
    CROWDIN_PROVIDER_REVISION, CrowdinBranchId, CrowdinBundleId, CrowdinFileId,
    CrowdinLocalizationResultContract, CrowdinLocalizationResultService, CrowdinLocalizationScope,
    CrowdinLocalizationScopeInput, CrowdinProjectId, CrowdinProvider, CrowdinReadResponse,
    CrowdinTransportError, LanguageCode, LocalizationRevision, LocalizationState,
    MAX_RESPONSE_BYTES, MissionCrowdinLocalizationConsumer, ObservationWindow, PAGE_SIZE,
    RecordingCrowdinTransport, RevisionKind, SecretReference, SourceFileMetadata,
    TranslationBuildStatus, TranslationProgress, TransportProvenance,
};

fn digest(label: &str) -> hartevo_crowdin_localization_result_plugin::Digest {
    hartevo_crowdin_localization_result_plugin::sha256_digest(label.as_bytes())
}

fn scope() -> CrowdinLocalizationScope {
    CrowdinLocalizationScope::new(CrowdinLocalizationScopeInput {
        organization: "org-acme".to_owned(),
        crowdin_project_id: 42,
        crowdin_project_revision: 12,
        source_branch_id: 7,
        source_branch_name: "main".to_owned(),
        source_branch_revision: 3,
        source_file_id: 99,
        source_file_revision: 4,
        source_file_path_digest: digest("src/i18n.json"),
        target_language: "de".to_owned(),
        hartevo_project_id: "project-1".to_owned(),
        hartevo_project_revision: 8,
        mission_id: "mission-1".to_owned(),
        mission_revision: 5,
        work_product_id: "work-product-1".to_owned(),
        work_product_revision: 2,
        consent_scope: "localization.read.proposal".to_owned(),
        consent_revision: 6,
        consent_digest: digest("consent-v6"),
    })
    .expect("scope")
}

fn fixture_responses(
    scope: &CrowdinLocalizationScope,
) -> Vec<Result<CrowdinReadResponse, CrowdinTransportError>> {
    let project = CrowdinProjectId::new(42).expect("project");
    let branch = CrowdinBranchId::new(7).expect("branch");
    let file = CrowdinFileId::new(99).expect("file");
    let source_revision = LocalizationRevision::new(RevisionKind::File, 4, digest("source-v4"))
        .expect("source revision");
    let translation_revision =
        LocalizationRevision::new(RevisionKind::String, 9, digest("translation-v9"))
            .expect("translation revision");
    let counts = BoundedCounts::new(10, 7, 2, 4).expect("counts");
    let metadata = hartevo_crowdin_localization_result_plugin::ProjectMetadata::new(
        project,
        &scope.organization,
        12,
        "en",
        vec![LanguageCode::parse("de").expect("language")],
    )
    .expect("metadata");
    let coverage = hartevo_crowdin_localization_result_plugin::LanguageCoverage::new(
        project,
        branch,
        "de",
        counts,
        LocalizationState::Partial,
    )
    .expect("coverage");
    let source_file = SourceFileMetadata::new(
        project,
        branch,
        file,
        4,
        scope.source_file.path_digest.clone(),
        10,
        source_revision.clone(),
    )
    .expect("source file");
    let progress = TranslationProgress::new(
        project,
        branch,
        file,
        "de",
        source_revision.clone(),
        Some(translation_revision),
        counts,
        ApprovalState::NeedsReview,
        LocalizationState::Partial,
    )
    .expect("progress");
    let build = TranslationBuildStatus::new(
        project,
        branch,
        file,
        "de",
        CrowdinBundleId::new(17).expect("bundle"),
        source_revision.content_digest.clone(),
        BuildState::Ready,
        Some(100),
        digest("build-v4-de"),
    )
    .expect("build");
    vec![
        Ok(CrowdinReadResponse::project(metadata, 256)),
        Ok(CrowdinReadResponse::language_coverage(vec![coverage], 512)),
        Ok(CrowdinReadResponse::source_file(source_file, 384)),
        Ok(CrowdinReadResponse::translation_progress(
            vec![progress],
            768,
        )),
        Ok(CrowdinReadResponse::build_status(vec![build], 256)),
    ]
}

#[test]
fn contract_service_and_scope_are_versioned_and_fenced() {
    CrowdinLocalizationResultContract::baseline().expect("contract");
    let service = CrowdinLocalizationResultService::new();
    service.validate().expect("service");
    assert!(service.read_only());
    assert!(!service.native_connected());
    assert_eq!(service.allowed_read_operations().len(), 5);
    assert_eq!(CROWDIN_API_ORIGIN, "https://api.crowdin.com/api/v2");
    assert_eq!(CROWDIN_PROVIDER_REVISION, "crowdin-api-v2-read-r1");
    assert_eq!(MAX_RESPONSE_BYTES, 1_048_576);
    assert_eq!(PAGE_SIZE, 50);

    let scope = scope();
    assert_ne!(scope.digest(), digest("different-scope"));
    let secret = SecretReference::crowdin("crowdin-token-value", 4).expect("secret reference");
    let serialized = serde_json::to_string(&secret).expect("secret serialization");
    assert!(!serialized.contains("crowdin-token-value"));
    assert!(!format!("{secret:?}").contains("crowdin-token-value"));
    assert!(serialized.contains("referenceDigest"));
}

#[test]
fn fixture_reads_compile_redacted_observation_record_and_mission_proposal() {
    let scope = scope();
    let secret = SecretReference::crowdin("opaque-crowdin-handle", 4).expect("secret reference");
    let transport = RecordingCrowdinTransport::fixture(fixture_responses(&scope));
    let mut provider = CrowdinProvider::new(transport, scope.clone(), secret).expect("provider");
    let window = ObservationWindow::new(1_000, 1_600).expect("window");
    let proposal = provider.propose(window).expect("proposal");
    assert_eq!(proposal.bounds.max_response_bytes, MAX_RESPONSE_BYTES);
    assert!(!proposal.native);
    assert!(!proposal.connected);
    assert_eq!(proposal.operations.len(), 5);

    let observation = provider.read(&proposal).expect("observation");
    observation.validate().expect("observation validation");
    assert_eq!(observation.provenance, TransportProvenance::Fixture);
    assert!(!observation.native);
    assert!(!observation.connected);
    assert!(observation.states.contains(&LocalizationState::Partial));
    assert!(observation.states.contains(&LocalizationState::NeedsReview));
    assert!(observation.states.contains(&LocalizationState::Approved));
    assert!(observation.states.contains(&LocalizationState::Ready));
    assert_eq!(provider.transport().requests().len(), 5);
    assert!(
        provider
            .transport()
            .requests()
            .iter()
            .all(|request| request.method
                == hartevo_crowdin_localization_result_plugin::CrowdinHttpMethod::Get)
    );

    let receipt = provider
        .record(observation.clone(), 1_600)
        .expect("receipt");
    receipt.validate().expect("receipt validation");
    assert!(!receipt.durable);
    assert!(!receipt.publication_claim);
    assert!(!receipt.native);

    let consumer = MissionCrowdinLocalizationConsumer::new(scope);
    let result = consumer
        .consume_recorded(&receipt, &observation)
        .expect("Mission result proposal");
    result
        .validate(&consumer)
        .expect("Mission result validation");
    assert!(!result.adoptable);
    assert!(!result.outcome_authority);
    assert!(!result.publication_claim);
    assert!(!result.native);
    assert!(!result.connected);

    assert_eq!(
        provider.read(&proposal),
        Err(hartevo_crowdin_localization_result_plugin::CrowdinError::DuplicateEvidence)
    );
    provider.revoke_registration().expect("revoke");
    assert!(matches!(
        provider.propose(window),
        Err(hartevo_crowdin_localization_result_plugin::CrowdinError::RegistrationRevoked)
    ));
}

#[test]
fn rate_limit_retry_is_bounded_and_blocked_env_never_looks_native() {
    let scope = scope();
    let secret = SecretReference::new("opaque-handle", 1).expect("secret");
    let mut responses = fixture_responses(&scope);
    responses.insert(
        0,
        Err(CrowdinTransportError::RateLimited { retry_after_ms: 20 }),
    );
    let mut provider = CrowdinProvider::new(
        RecordingCrowdinTransport::new(responses),
        scope.clone(),
        secret.clone(),
    )
    .expect("provider");
    let proposal = provider
        .propose(ObservationWindow::new(1, 2).expect("window"))
        .expect("proposal");
    let observation = provider.read(&proposal).expect("bounded retry");
    assert_eq!(observation.receipts[0].retry_count, 1);
    assert!(!provider.native());
    assert!(!provider.connected());

    let mut blocked =
        CrowdinProvider::new(BlockedEnvCrowdinTransport, scope, secret).expect("blocked provider");
    let blocked_proposal = blocked
        .propose(ObservationWindow::new(3, 4).expect("window"))
        .expect("blocked proposal remains compilable");
    assert_eq!(blocked.provenance(), TransportProvenance::BlockedEnv);
    assert!(!blocked.native());
    assert!(!blocked.connected());
    assert!(matches!(
        blocked.read(&blocked_proposal),
        Err(
            hartevo_crowdin_localization_result_plugin::CrowdinError::Transport(
                CrowdinTransportError::BlockedEnv
            )
        )
    ));
}
