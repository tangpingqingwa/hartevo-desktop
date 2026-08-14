use hartevo_jfrog_artifactory_result_plugin::{
    AqlMetadataRecord, AqlRange, ArtifactChecksums, ArtifactMetadata, ArtifactPathIdentity,
    ArtifactStatus, BuildIdentity, BuildInfoEvidence, Digest, FakeTransport, HostIdentity,
    JfrogArtifactRecordingLog, JfrogArtifactoryProvider, JfrogArtifactoryResponse,
    JfrogArtifactoryResultError, JfrogArtifactoryResultService, JfrogProviderError,
    JfrogRegistration, JfrogRegistrationRegistry, JfrogScope, JfrogTransportError, MissionIdentity,
    MissionJfrogArtifactConsumer, ModuleIdentity, OrganizationIdentity, PermissionSnapshot,
    ProjectIdentity, PromotionEvidence, PromotionState, ProviderIdentity, RecordingTransport,
    RegistrationId, ReleaseDecision, RepositoryIdentity, SecretReference, TransportProvenance,
    WorkProductIdentity,
};

fn scope() -> JfrogScope {
    JfrogScope::new(
        HostIdentity::new("https://artifactory.example.com", 1).expect("host"),
        OrganizationIdentity::new("acme", 1).expect("organization"),
        RepositoryIdentity::new("release-local", 1).expect("repository"),
        ArtifactPathIdentity::new("com/acme/app/1.0.0/app.tgz", 1).expect("path"),
        BuildIdentity::new("release", "42", 3).expect("build"),
        ModuleIdentity::new("app", 1).expect("module"),
        hartevo_jfrog_artifactory_result_plugin::ArtifactIdentity::new("app.tgz", 1)
            .expect("artifact"),
        hartevo_jfrog_artifactory_result_plugin::CommitIdentity::new(
            "0123456789abcdef0123456789abcdef01234567",
            7,
        )
        .expect("commit"),
        MissionIdentity::new("mission-1", 9).expect("mission"),
        ProjectIdentity::new("project-1", 4).expect("project"),
        WorkProductIdentity::new("wp-1", 2).expect("work product"),
    )
    .expect("scope")
}

fn checksums(seed: &str) -> ArtifactChecksums {
    ArtifactChecksums::from_sha256_digest(Digest::from_text(seed)).expect("checksum")
}

fn registration(scope: &JfrogScope) -> JfrogRegistration {
    JfrogRegistration::new(
        RegistrationId::new("registration-1").expect("registration id"),
        scope.clone(),
        SecretReference::api_token("opaque-api-token-handle", 1).expect("secret"),
        PermissionSnapshot::read_only(),
        ProviderIdentity::new(1, "recording-fixture").expect("provider"),
        1,
    )
    .expect("registration")
}

fn evidence(scope: &JfrogScope) -> (ArtifactMetadata, BuildInfoEvidence, PromotionEvidence) {
    let artifact = ArtifactMetadata::for_scope(scope, checksums("artifact-bytes"), Vec::new())
        .expect("artifact metadata");
    let build_info =
        BuildInfoEvidence::for_scope(scope, artifact.clone(), Vec::new()).expect("build-info");
    let promotion = PromotionEvidence::new(scope, PromotionState::Promoted, None, Vec::new(), 1)
        .expect("promotion");
    (artifact, build_info, promotion)
}

fn promoted_response(scope: &JfrogScope) -> JfrogArtifactoryResponse {
    let (artifact, build_info, promotion) = evidence(scope);
    JfrogArtifactoryResponse::present(
        scope,
        artifact,
        Some(build_info),
        Some(promotion),
        TransportProvenance::Recording,
    )
    .expect("response")
}

#[test]
fn contract_capabilities_and_four_provenances_are_honest() {
    let scope = scope();
    let registration = registration(&scope);
    let service = JfrogArtifactoryResultService::new(
        registration,
        RecordingTransport::new(JfrogArtifactoryResponse::missing(
            &scope,
            TransportProvenance::Recording,
        )),
    )
    .expect("service");
    let capabilities = service.describe_capabilities();
    assert!(capabilities.read_only);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.can_upload);
    assert!(!capabilities.can_download_bytes);
    assert!(!capabilities.can_delete);
    assert!(!capabilities.can_overwrite);
    assert!(!capabilities.can_promote);
    assert!(!capabilities.can_demote);
    assert!(!capabilities.can_configure_repository);
    assert!(!capabilities.can_mutate_xray);
    assert!(!capabilities.can_adopt_outcome);

    for provenance in [
        TransportProvenance::Recording,
        TransportProvenance::Fake,
        TransportProvenance::Loopback,
        TransportProvenance::BlockedEnv,
    ] {
        assert!(!provenance.is_native());
        assert!(!provenance.claims_connected());
    }
}

#[test]
fn promoted_artifact_build_and_provenance_digests_fence_a_release_proposal() {
    let scope = scope();
    let registration = registration(&scope);
    let mut service = JfrogArtifactoryResultService::new(
        registration,
        RecordingTransport::new(promoted_response(&scope)),
    )
    .expect("service");
    let projection = service
        .read_artifact_metadata(10_usize)
        .expect("bounded metadata read");
    assert_eq!(projection.status, ArtifactStatus::Promoted);
    assert!(projection.is_complete());
    assert!(!projection.is_adoptable());
    assert!(!projection.connected);
    assert!(!projection.native);
    assert!(projection.artifact_metadata_digest().is_some());
    assert!(projection.build_info_digest().is_some());
    assert!(projection.checksum_digest().is_some());
    projection.validate_integrity().expect("projection digest");

    let proposal = service
        .compile_release_decision_proposal(&projection, "release-idempotency-1")
        .expect("proposal");
    assert_eq!(proposal.release_decision, ReleaseDecision::RecommendRelease);
    assert!(!proposal.can_be_adopted());
    proposal.validate_integrity().expect("proposal digest");

    let mut log = JfrogArtifactRecordingLog::default();
    let first = service
        .record_release_decision(&mut log, &proposal)
        .expect("record");
    assert!(!first.replayed);
    let replay = service
        .record_release_decision(&mut log, &proposal)
        .expect("idempotent replay");
    assert!(replay.replayed);
    assert_eq!(log.len(), 1);
}

#[test]
fn all_projection_states_remain_descriptive_and_non_adoptable() {
    let scope = scope();
    for status in [
        ArtifactStatus::Missing,
        ArtifactStatus::Rejected,
        ArtifactStatus::Partial,
        ArtifactStatus::AccessLost,
        ArtifactStatus::ProviderUnknown,
    ] {
        let response = JfrogArtifactoryResponse::for_scope(&scope, TransportProvenance::Fake)
            .with_status(status);
        let mut provider =
            JfrogArtifactoryProvider::new(registration(&scope), FakeTransport::new(response))
                .expect("provider");
        let projection = provider
            .read_artifact_metadata("state-request")
            .expect("state projection");
        assert_eq!(projection.status, status);
        assert!(!projection.is_adoptable());
        assert!(!projection.connected);
        assert!(!projection.native);
    }
}

#[test]
fn exact_scope_drift_is_rejected_at_each_identity_boundary() {
    let original = scope();
    let cases = [
        ("host", {
            let mut value = original.clone();
            value.host = HostIdentity::new("https://other.example.com", 1).expect("host");
            value
        }),
        ("organization", {
            let mut value = original.clone();
            value.organization = OrganizationIdentity::new("other", 1).expect("organization");
            value
        }),
        ("repository", {
            let mut value = original.clone();
            value.repository = RepositoryIdentity::new("other-local", 1).expect("repository");
            value
        }),
        ("path", {
            let mut value = original.clone();
            value.artifact_path = ArtifactPathIdentity::new("other/app.tgz", 1).expect("path");
            value
        }),
        ("build", {
            let mut value = original.clone();
            value.build = BuildIdentity::new("release", "43", 3).expect("build");
            value
        }),
        ("module", {
            let mut value = original.clone();
            value.module = ModuleIdentity::new("other", 1).expect("module");
            value
        }),
        ("artifact", {
            let mut value = original.clone();
            value.artifact =
                hartevo_jfrog_artifactory_result_plugin::ArtifactIdentity::new("other.tgz", 1)
                    .expect("artifact");
            value
        }),
        ("commit", {
            let mut value = original.clone();
            value.commit = hartevo_jfrog_artifactory_result_plugin::CommitIdentity::new(
                "fedcba9876543210fedcba9876543210fedcba98",
                7,
            )
            .expect("commit");
            value
        }),
        ("mission", {
            let mut value = original.clone();
            value.mission = MissionIdentity::new("other-mission", 9).expect("mission");
            value
        }),
        ("project", {
            let mut value = original.clone();
            value.project = ProjectIdentity::new("other-project", 4).expect("project");
            value
        }),
        ("work product", {
            let mut value = original.clone();
            value.work_product = WorkProductIdentity::new("other-wp", 2).expect("work product");
            value
        }),
    ];

    for (label, drifted_scope) in cases {
        let response =
            JfrogArtifactoryResponse::for_scope(&drifted_scope, TransportProvenance::Recording);
        let mut provider = JfrogArtifactoryProvider::new(
            registration(&original),
            RecordingTransport::new(response),
        )
        .expect("provider");
        let error = provider
            .read_artifact_metadata("scope-drift")
            .expect_err(label);
        assert!(matches!(
            error,
            JfrogProviderError::HostDrift
                | JfrogProviderError::OrganizationDrift
                | JfrogProviderError::RepositoryDrift
                | JfrogProviderError::ArtifactPathDrift
                | JfrogProviderError::BuildDrift
                | JfrogProviderError::ModuleDrift
                | JfrogProviderError::ArtifactDrift
                | JfrogProviderError::CommitDrift
                | JfrogProviderError::MissionDrift
                | JfrogProviderError::ProjectDrift
                | JfrogProviderError::WorkProductDrift
        ));
    }
}

#[test]
fn checksum_metadata_and_build_revision_mismatches_fail_closed() {
    let scope = scope();
    let (artifact, build_info, _) = evidence(&scope);

    let mut checksum_provider = JfrogArtifactoryProvider::new(
        registration(&scope),
        RecordingTransport::new(promoted_response(&scope)),
    )
    .expect("provider");
    let error = checksum_provider
        .read_artifact_with_expected_checksums("checksum-request", checksums("different"))
        .expect_err("checksum mismatch");
    assert_eq!(error, JfrogProviderError::ChecksumMismatch);

    let mut tampered_artifact = artifact.clone();
    tampered_artifact.metadata_digest = Digest::from_text("wrong-metadata-digest");
    let tampered_response =
        JfrogArtifactoryResponse::for_scope(&scope, TransportProvenance::Recording)
            .with_artifact_metadata(tampered_artifact);
    let mut metadata_provider = JfrogArtifactoryProvider::new(
        registration(&scope),
        RecordingTransport::new(tampered_response),
    )
    .expect("provider");
    assert_eq!(
        metadata_provider
            .read_artifact_metadata("metadata-request")
            .expect_err("metadata mismatch"),
        JfrogProviderError::MetadataMismatch
    );

    let wrong_commit = hartevo_jfrog_artifactory_result_plugin::CommitIdentity::new(
        "fedcba9876543210fedcba9876543210fedcba98",
        7,
    )
    .expect("wrong commit");
    let mismatched_build_info =
        BuildInfoEvidence::new(scope.build.clone(), wrong_commit, Vec::new(), Vec::new())
            .expect("mismatched but internally sealed build-info");
    let response = JfrogArtifactoryResponse::for_scope(&scope, TransportProvenance::Recording)
        .with_artifact_metadata(artifact)
        .with_build_info(mismatched_build_info);
    let mut build_provider =
        JfrogArtifactoryProvider::new(registration(&scope), RecordingTransport::new(response))
            .expect("provider");
    assert_eq!(
        build_provider
            .read_artifact_metadata("build-revision-request")
            .expect_err("build revision mismatch"),
        JfrogProviderError::BuildInfoRevisionMismatch
    );
    assert_ne!(build_info.build_info_digest, Digest::from_text("missing"));
}

#[test]
fn bounded_aql_pagination_duplicate_and_replay_are_rejected() {
    let scope = scope();
    let first_record =
        AqlMetadataRecord::for_scope(&scope, checksums("aql-one"), Vec::new(), Some(123))
            .expect("first record");
    let page_two = JfrogArtifactoryResponse::for_scope(&scope, TransportProvenance::Recording)
        .with_aql_results(
            Vec::new(),
            Some(AqlRange::new(1, 1, 1).expect("second range")),
        )
        .with_status(ArtifactStatus::Missing);
    let first_page = JfrogArtifactoryResponse::for_scope(&scope, TransportProvenance::Recording)
        .with_aql_results(
            vec![first_record.clone()],
            Some(AqlRange::new(0, 1, 1).expect("first range")),
        )
        .with_next_page_token("page-two");
    let mut provider = JfrogArtifactoryProvider::new(
        registration(&scope),
        RecordingTransport::new(first_page.clone()).with_pages(vec![first_page, page_two]),
    )
    .expect("provider");
    let projection = provider
        .read_aql_metadata("aql-request", 1)
        .expect("bounded AQL pagination");
    assert_eq!(projection.aql_results.len(), 1);
    assert_eq!(projection.status, ArtifactStatus::Missing);

    let repeated = JfrogArtifactoryResponse::for_scope(&scope, TransportProvenance::Fake)
        .with_aql_results(Vec::new(), Some(AqlRange::new(0, 0, 0).unwrap()))
        .with_next_page_token("same-page");
    let mut loop_provider =
        JfrogArtifactoryProvider::new(registration(&scope), FakeTransport::new(repeated))
            .expect("provider");
    assert_eq!(
        loop_provider
            .read_aql_metadata("loop-request", 1)
            .expect_err("pagination loop"),
        JfrogProviderError::PaginationLoop
    );

    let duplicate_page_one =
        JfrogArtifactoryResponse::for_scope(&scope, TransportProvenance::Loopback)
            .with_aql_results(
                vec![first_record.clone()],
                Some(AqlRange::new(0, 1, 2).unwrap()),
            )
            .with_next_page_token("duplicate-page");
    let duplicate_page_two =
        JfrogArtifactoryResponse::for_scope(&scope, TransportProvenance::Loopback)
            .with_aql_results(vec![first_record], Some(AqlRange::new(1, 2, 2).unwrap()));
    let mut duplicate_provider = JfrogArtifactoryProvider::new(
        registration(&scope),
        hartevo_jfrog_artifactory_result_plugin::LoopbackTransport::new(duplicate_page_one)
            .with_pages(vec![
                JfrogArtifactoryResponse::for_scope(&scope, TransportProvenance::Loopback)
                    .with_aql_results(
                        vec![duplicate_page_two.aql_results[0].clone()],
                        Some(AqlRange::new(0, 1, 2).unwrap()),
                    )
                    .with_next_page_token("duplicate-page"),
                duplicate_page_two,
            ]),
    )
    .expect("provider");
    assert_eq!(
        duplicate_provider
            .read_aql_metadata("duplicate-request", 1)
            .expect_err("duplicate AQL record"),
        JfrogProviderError::DuplicateEvidence
    );
}

#[test]
fn pagination_limit_and_response_bounds_fail_closed() {
    let scope = scope();
    let mut pages = Vec::new();
    for index in 0..9 {
        let mut response =
            JfrogArtifactoryResponse::for_scope(&scope, TransportProvenance::Recording)
                .with_status(ArtifactStatus::Missing);
        if index < 8 {
            response = response.with_next_page_token(format!("page-{index}"));
        }
        pages.push(response);
    }
    let mut provider = JfrogArtifactoryProvider::new(
        registration(&scope),
        RecordingTransport::new(pages[0].clone()).with_pages(pages),
    )
    .expect("provider");
    assert_eq!(
        provider
            .read_artifact_metadata("pagination-limit")
            .expect_err("pagination limit"),
        JfrogProviderError::PaginationLimit
    );

    let oversized = JfrogArtifactoryResponse::for_scope(&scope, TransportProvenance::Fake)
        .with_response_bytes(1_048_577);
    let mut response_provider =
        JfrogArtifactoryProvider::new(registration(&scope), FakeTransport::new(oversized))
            .expect("provider");
    assert_eq!(
        response_provider
            .read_artifact_metadata("response-bound")
            .expect_err("response bound"),
        JfrogProviderError::ResponseTooLarge
    );
}

#[test]
fn transport_fault_classes_and_blocked_environment_are_finite() {
    let scope = scope();
    let faults = [
        JfrogTransportError::Unauthorized401,
        JfrogTransportError::Forbidden403,
        JfrogTransportError::NotFound404,
        JfrogTransportError::Conflict409,
        JfrogTransportError::RateLimited429,
        JfrogTransportError::Timeout,
        JfrogTransportError::Server5xx { status: 503 },
        JfrogTransportError::AccessLost,
        JfrogTransportError::ProviderUnknown,
        JfrogTransportError::MalformedResponse,
        JfrogTransportError::PartialResponse,
    ];
    for fault in faults {
        let mut provider = JfrogArtifactoryProvider::new(
            registration(&scope),
            FakeTransport::new(JfrogArtifactoryResponse::missing(
                &scope,
                TransportProvenance::Fake,
            ))
            .with_error(fault.clone()),
        )
        .expect("provider");
        let error = provider
            .read_artifact_metadata("fault-request")
            .expect_err("transport fault");
        assert_eq!(error, JfrogProviderError::Transport(fault));
    }

    let mut blocked = JfrogArtifactoryProvider::new(
        registration(&scope),
        hartevo_jfrog_artifactory_result_plugin::BlockedEnvTransport::new(),
    )
    .expect("blocked provider");
    assert_eq!(
        blocked
            .read_artifact_metadata("blocked-request")
            .expect_err("blocked env"),
        JfrogProviderError::Transport(JfrogTransportError::EnvironmentBlocked)
    );
}

#[test]
fn registration_is_reversible_duplicate_safe_and_revocation_fenced() {
    let scope = scope();
    let initial_registration = registration(&scope);
    let id = initial_registration.id().clone();
    let mut registry = JfrogRegistrationRegistry::default();
    let receipt = registry
        .register(initial_registration.clone())
        .expect("register");
    assert_eq!(receipt.registration_id, id);
    assert!(registry.register(initial_registration).is_err());

    registry.revoke(&id).expect("revoke");
    assert_eq!(
        registry.get(&id).expect("registration").status(),
        hartevo_jfrog_artifactory_result_plugin::RegistrationStatus::Revoked
    );
    registry.restore(&id).expect("restore");
    registry.reverse(&id).expect("reverse");
    assert!(registry.restore(&id).is_err());

    let mut revoked_secret = registration(&scope);
    revoked_secret.revoke_secret_reference();
    assert!(matches!(
        JfrogArtifactoryProvider::new(
            revoked_secret,
            RecordingTransport::new(JfrogArtifactoryResponse::missing(
                &scope,
                TransportProvenance::Recording,
            )),
        ),
        Err(JfrogProviderError::SecretRevoked)
    ));

    let secret = SecretReference::oidc("opaque-oidc-handle", 2).expect("oidc");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("opaque-oidc-handle"));
}

#[test]
fn stale_mission_and_tampered_proposal_or_projection_do_not_record() {
    let scope = scope();
    let mut service = JfrogArtifactoryResultService::new(
        registration(&scope),
        RecordingTransport::new(promoted_response(&scope)),
    )
    .expect("service");
    let projection = service
        .read_release_evidence("proposal-request")
        .expect("projection");
    let consumer = MissionJfrogArtifactConsumer::new({
        let mut stale = scope.clone();
        stale.mission = MissionIdentity::new("mission-1", 10).expect("stale mission");
        stale
    });
    assert_eq!(
        consumer
            .compile_proposal(service.registration(), &projection, "stale")
            .expect_err("stale mission"),
        JfrogArtifactoryResultError::ScopeMismatch
    );

    let mut tampered_projection = projection.clone();
    tampered_projection.status = ArtifactStatus::Missing;
    let mut log = JfrogArtifactRecordingLog::default();
    assert!(
        consumer
            .record(&mut log, &{
                let mut invalid = service
                    .compile_release_decision_proposal(&projection, "tampered")
                    .expect("proposal");
                invalid.proposal_digest = Digest::from_text("tampered");
                invalid
            })
            .is_err()
    );
    assert!(tampered_projection.validate_integrity().is_err());
}
