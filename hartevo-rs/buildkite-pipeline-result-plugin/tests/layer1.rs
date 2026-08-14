use hartevo_buildkite_pipeline_result_plugin::{
    AnnotationPage, ArtifactMetadataPage, BlockedEnvTransport, BuildPage, BuildState,
    BuildkitePipelineResultError, BuildkitePipelineResultRecordingLog,
    BuildkitePipelineResultService, BuildkiteProvider, BuildkiteProviderError,
    BuildkiteRegistration, BuildkiteRegistrationRegistry, BuildkiteScope, BuildkiteTransport,
    BuildkiteTransportError, CONTRACT_DIGEST, CONTRACT_JSON, CONTRACT_VERSION, FakeTransport,
    JobPage, JobState, LoopbackTransport, MAX_PAGE_SIZE, PermissionSnapshot, ProviderIdentity,
    RecordingTransport, RegistrationId, RegistrationStatus, RetryState, SecretReference,
    TransportProvenance, contract_digest,
};

const OBSERVED_AT: u64 = 1_744_550_401;
const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn scope() -> BuildkiteScope {
    BuildkiteScope::from_ids(
        "https://api.buildkite.com",
        1,
        "hartevo",
        2,
        "desktop",
        3,
        "build-42",
        42,
        4,
        "job-7",
        5,
        "attempt-2",
        2,
        6,
        COMMIT,
        7,
        "artifact-1",
        8,
        "annotation-1",
        9,
        "mission-buildkite-1",
        10,
        "project-buildkite-1",
        11,
        "work-product-buildkite-1",
        12,
    )
    .expect("scope")
}

fn registration(scope: BuildkiteScope) -> BuildkiteRegistration {
    BuildkiteRegistration::new(
        RegistrationId::new("registration-buildkite-1").expect("registration id"),
        scope,
        SecretReference::api_token("opaque-buildkite-api-token", 1).expect("secret"),
        PermissionSnapshot::read_only(1).expect("permissions"),
        ProviderIdentity::new(1, "buildkite-release-1").expect("provider"),
        1,
    )
    .expect("registration")
}

fn provider<T: BuildkiteTransport>(scope: &BuildkiteScope, transport: T) -> BuildkiteProvider<T> {
    BuildkiteProvider::new(registration(scope.clone()), transport).expect("provider")
}

fn fixture_transport(scope: &BuildkiteScope) -> FakeTransport {
    FakeTransport::from_scope(scope)
}

#[test]
fn contract_is_exact_layer_one_and_non_native() {
    assert_eq!(contract_digest(), CONTRACT_DIGEST);
    assert!(CONTRACT_JSON.contains("buildkite.pipeline-result"));
    assert!(CONTRACT_JSON.contains("blocked_env"));
    assert!(CONTRACT_JSON.contains("annotationBody"));
    assert_eq!(CONTRACT_VERSION, "buildkite-pipeline-result-01-layer-1/v1");

    let scope = scope();
    let mut service =
        BuildkitePipelineResultService::new(registration(scope.clone()), fixture_transport(&scope))
            .expect("service");
    let capabilities = service.describe_capabilities();
    assert!(capabilities.read_only);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.can_create_build);
    assert!(!capabilities.can_rebuild_build);
    assert!(!capabilities.can_retry_job);
    assert!(!capabilities.can_cancel_build);
    assert!(!capabilities.can_mutate_annotation);
    assert!(!capabilities.can_read_raw_logs);
    assert!(!capabilities.can_read_raw_artifacts);
    assert!(!capabilities.can_adopt_outcome);

    let evidence = service
        .read_pipeline_result(MAX_PAGE_SIZE, "service-read")
        .expect("evidence");
    assert!(evidence.is_complete());
    assert!(evidence.is_review_only());
    assert!(!evidence.can_be_adopted());
    assert!(!evidence.connected);
    assert!(!evidence.native);
}

#[test]
fn all_four_provenances_are_explicitly_non_native_and_non_connected() {
    let scope = scope();
    let recording = provider(&scope, RecordingTransport::from_scope(&scope));
    assert_eq!(recording.provenance(), TransportProvenance::Recording);
    assert!(!recording.connected());
    assert!(!recording.native());

    let fake = provider(&scope, FakeTransport::from_scope(&scope));
    assert_eq!(fake.provenance(), TransportProvenance::Fake);
    assert!(!fake.provenance().is_native());
    assert!(!fake.provenance().claims_connected());

    let loopback = provider(&scope, LoopbackTransport::from_scope(&scope));
    assert_eq!(loopback.provenance(), TransportProvenance::Loopback);
    assert!(!loopback.provenance().is_native());
    assert!(!loopback.provenance().claims_connected());

    let blocked = BlockedEnvTransport;
    assert_eq!(blocked.provenance(), TransportProvenance::BlockedEnv);
    assert!(!blocked.provenance().is_native());
    assert!(!blocked.provenance().claims_connected());
    let mut blocked_provider = provider(&scope, blocked);
    assert_eq!(
        blocked_provider
            .read_builds(MAX_PAGE_SIZE)
            .expect_err("blocked native read accepted"),
        BuildkiteProviderError::Transport(BuildkiteTransportError::BlockedEnv)
    );
}

#[test]
fn bounded_build_job_annotation_and_artifact_metadata_keep_retry_and_redaction_evidence() {
    let scope = scope();
    let builds = BuildPage::new(
        1,
        vec![
            hartevo_buildkite_pipeline_result_plugin::BuildRecord::from_values(
                &scope,
                BuildState::Passed,
                RetryState::Failed,
                OBSERVED_AT,
                512,
            ),
        ],
        None,
        512,
    )
    .expect("build page");
    let jobs = JobPage::new(
        1,
        vec![
            hartevo_buildkite_pipeline_result_plugin::JobRecord::from_values(
                &scope,
                JobState::Passed,
                RetryState::Running,
                1,
                1,
                OBSERVED_AT,
                512,
            ),
        ],
        None,
        512,
    )
    .expect("job page");

    // Mutating a sealed retry record without resealing it must fail closed.
    let mut tampered_retry = BuildPage::for_scope(&scope);
    tampered_retry.builds[0].retry_identity.state = RetryState::Passed;
    assert_eq!(
        provider(
            &scope,
            FakeTransport::new(
                [Ok(tampered_retry)],
                [Ok(JobPage::for_scope(&scope))],
                [Ok(AnnotationPage::for_scope(&scope))],
                [Ok(ArtifactMetadataPage::for_scope(&scope))],
            ),
        )
        .read_builds(MAX_PAGE_SIZE)
        .expect_err("retry tamper accepted"),
        BuildkiteProviderError::BuildTampered
    );

    let mut service = BuildkitePipelineResultService::new(
        registration(scope.clone()),
        FakeTransport::new(
            [Ok(builds)],
            [Ok(jobs)],
            [Ok(AnnotationPage::for_scope(&scope))],
            [Ok(ArtifactMetadataPage::for_scope(&scope))],
        ),
    )
    .expect("service");
    let evidence = service
        .read_pipeline_result(MAX_PAGE_SIZE, "retry-state")
        .expect("bounded evidence");
    assert_eq!(evidence.retry_evidence.len(), 2);
    assert!(
        !evidence.annotations.annotations[0]
            .redaction
            .raw_annotation_body_retained
    );
    assert!(
        !evidence.artifacts.artifacts[0]
            .redaction
            .raw_artifact_content_retained
    );
    assert!(evidence.artifacts.artifacts[0].content_digest.is_none());
    assert!(
        evidence.artifacts.artifacts[0]
            .download_url_digest
            .is_none()
    );
    let encoded = serde_json::to_string(&evidence).expect("evidence JSON");
    assert!(!encoded.contains("artifact bytes"));
    assert!(!encoded.contains("annotation body"));
}

#[test]
fn exact_scope_drift_is_rejected_for_every_identity_boundary() {
    let expected = scope();
    let drifted = BuildkiteScope::from_ids(
        "https://drift.example",
        1,
        "hartevo",
        2,
        "desktop",
        3,
        "build-42",
        42,
        4,
        "job-7",
        5,
        "attempt-2",
        2,
        6,
        COMMIT,
        7,
        "artifact-1",
        8,
        "annotation-1",
        9,
        "mission-buildkite-1",
        10,
        "project-buildkite-1",
        11,
        "work-product-buildkite-1",
        12,
    )
    .expect("drifted scope");
    assert_eq!(
        provider(
            &expected,
            FakeTransport::new(
                [Ok(BuildPage::for_scope(&drifted))],
                [Ok(JobPage::for_scope(&expected))],
                [Ok(AnnotationPage::for_scope(&expected))],
                [Ok(ArtifactMetadataPage::for_scope(&expected))],
            )
        )
        .read_builds(MAX_PAGE_SIZE)
        .expect_err("host drift accepted"),
        BuildkiteProviderError::HostDrift
    );
}

#[test]
fn pagination_and_response_bounds_fail_closed() {
    let scope = scope();
    let mut page_one = BuildPage::for_scope(&scope);
    page_one.next_page_token = Some("page-1".to_owned());
    // The page is intentionally resealed after setting the cursor.
    page_one = BuildPage::new(
        page_one.page_number,
        page_one.builds,
        page_one.next_page_token,
        page_one.response_bytes,
    )
    .expect("page one");
    let mut page_two = BuildPage::for_scope(&scope);
    page_two.next_page_token = Some("page-1".to_owned());
    page_two = BuildPage::new(
        2,
        page_two.builds,
        page_two.next_page_token,
        page_two.response_bytes,
    )
    .expect("page two");
    assert_eq!(
        provider(
            &scope,
            FakeTransport::new(
                [Ok(page_one), Ok(page_two)],
                [Ok(JobPage::for_scope(&scope))],
                [Ok(AnnotationPage::for_scope(&scope))],
                [Ok(ArtifactMetadataPage::for_scope(&scope))],
            ),
        )
        .read_builds(MAX_PAGE_SIZE)
        .expect_err("repeated page token accepted"),
        BuildkiteProviderError::PaginationLoop
    );

    let oversized = BuildPage::new(
        1,
        vec![
            hartevo_buildkite_pipeline_result_plugin::BuildRecord::for_scope(
                &scope,
                BuildState::Passed,
                OBSERVED_AT,
            ),
        ],
        None,
        hartevo_buildkite_pipeline_result_plugin::MAX_RESPONSE_BYTES + 1,
    );
    assert_eq!(
        oversized.expect_err("oversized page accepted"),
        BuildkiteProviderError::PageTampered
    );

    assert_eq!(
        provider(&scope, fixture_transport(&scope))
            .read_builds(hartevo_buildkite_pipeline_result_plugin::MAX_PAGE_SIZE + 1)
            .expect_err("oversized request accepted"),
        BuildkiteProviderError::PaginationLimit
    );
}

#[test]
fn registration_is_reversible_and_secret_material_stays_opaque() {
    let scope = scope();
    let registration = registration(scope);
    assert!(
        !format!("{:?}", registration.secret_reference()).contains("opaque-buildkite-api-token")
    );
    let serialized = serde_json::to_string(&registration).expect("safe registration JSON");
    assert!(!serialized.contains("opaque-buildkite-api-token"));
    assert!(serialized.contains("api_token"));

    let id = registration.id().clone();
    let mut registry = BuildkiteRegistrationRegistry::default();
    let receipt = registry.register(registration).expect("register");
    assert_eq!(receipt.status, RegistrationStatus::Active);
    let revoked = registry.revoke(&id).expect("revoke");
    assert_eq!(revoked.status, RegistrationStatus::Revoked);
    assert!(!registry.get(&id).expect("registration").is_active());
    registry.restore(&id).expect("restore");
    assert!(registry.get(&id).expect("registration").is_active());
    registry.reverse(&id).expect("reverse");
    assert_eq!(
        registry.get(&id).expect("registration").status(),
        RegistrationStatus::Reversed
    );
    assert!(
        registry
            .get(&id)
            .expect("registration")
            .revocation_evidence()
            .validate()
            .is_ok()
    );
}

#[test]
fn secret_and_registration_revocation_block_reads() {
    let scope = scope();
    let mut revoked_secret = SecretReference::oidc("opaque-oidc-handle", 2).expect("secret");
    revoked_secret.revoke();
    let revoked_secret_registration = BuildkiteRegistration::new(
        RegistrationId::new("registration-revoked-secret").expect("id"),
        scope.clone(),
        revoked_secret,
        PermissionSnapshot::read_only(1).expect("permissions"),
        ProviderIdentity::new(1, "release").expect("provider"),
        1,
    )
    .expect("registration");
    assert_eq!(
        BuildkiteProvider::new(
            revoked_secret_registration,
            FakeTransport::from_scope(&scope),
        )
        .expect("provider")
        .read_builds(MAX_PAGE_SIZE)
        .expect_err("revoked secret accepted"),
        BuildkiteProviderError::SecretRevoked
    );

    let mut provider = provider(&scope, FakeTransport::from_scope(&scope));
    provider.registration_mut().revoke().expect("revoke");
    assert_eq!(
        provider
            .read_builds(MAX_PAGE_SIZE)
            .expect_err("revoked registration accepted"),
        BuildkiteProviderError::RegistrationRevoked
    );
}

#[test]
fn proposal_and_recording_are_scope_bound_and_idempotent() {
    let scope = scope();
    let mut service = BuildkitePipelineResultService::new(
        registration(scope.clone()),
        FakeTransport::from_scope(&scope),
    )
    .expect("service");
    let evidence = service
        .read_pipeline_result(MAX_PAGE_SIZE, "proposal-read")
        .expect("evidence");
    let proposal = service
        .compile_pipeline_result_proposal(&evidence, "proposal-key")
        .expect("proposal");
    assert!(proposal.is_review_only());
    assert!(!proposal.can_be_adopted());
    let mut log = BuildkitePipelineResultRecordingLog::default();
    let first = service
        .record_pipeline_result(&mut log, &proposal)
        .expect("record");
    let replay = service
        .record_pipeline_result(&mut log, &proposal)
        .expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(log.len(), 1);

    let mut tampered = proposal.clone();
    tampered.response_truncated = !tampered.response_truncated;
    assert_eq!(
        service
            .record_pipeline_result(&mut log, &tampered)
            .expect_err("proposal tamper accepted"),
        BuildkitePipelineResultError::InvalidProposal
    );
}

#[test]
fn redaction_tamper_is_detected_before_consume() {
    let scope = scope();
    let mut evidence = provider(&scope, FakeTransport::from_scope(&scope))
        .read_pipeline_result(MAX_PAGE_SIZE, "redaction")
        .expect("evidence");
    evidence.annotations.annotations[0]
        .redaction
        .raw_annotation_body_retained = true;
    assert_eq!(
        evidence
            .validate_integrity()
            .expect_err("raw annotation accepted"),
        BuildkitePipelineResultError::RedactionViolation
    );
}
