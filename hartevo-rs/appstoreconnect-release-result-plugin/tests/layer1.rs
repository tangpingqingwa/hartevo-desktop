use hartevo_appstoreconnect_release_result_plugin::{
    AppPayload, AppScope, AppStoreConnectEndpoint, AppStoreConnectHttpRequest,
    AppStoreConnectProvider, AppStoreConnectProviderState, AppStoreConnectReleaseResultError,
    AppStoreConnectReleaseService, AppStoreConnectResponseBody, AppStoreConnectScope,
    AppStoreConnectTransportError, AppStoreState, AppStoreVersionPayload, AppStoreVersionScope,
    ArtifactScope, BetaAppReviewSubmissionPayload, BetaGroupPayload, BetaGroupScope,
    BetaReviewState, BuildPayload, BuildProcessingState, BuildScope, Digest,
    FixtureAppStoreConnectTransport, JwtRedaction, LinkagePayload,
    LoopbackAppStoreConnectTransport, MissionMobileReleaseConsumer, MissionScope, Page, PageToken,
    PermissionSnapshot, Platform, PreReleaseVersionPayload, PreReleaseVersionScope, ProjectScope,
    ProjectionStatus, RecordingAppStoreConnectTransport, ReleaseScope, ReleaseState, ReviewScope,
    ReviewState, ReviewSubmissionPayload, SecretReference, TeamScope, TransportProvenance,
    WorkProductScope, validate_contract_document,
};

const ORIGIN: &str = "https://api.appstoreconnect.apple.com";
const APP_ID: &str = "app-1";
const BUNDLE_ID: &str = "com.example.mobile";
const PRE_RELEASE_ID: &str = "pre-release-1";
const BUILD_ID: &str = "build-1";
const VERSION_ID: &str = "version-1";
const BETA_GROUP_ID: &str = "beta-group-1";
const REVIEW_ID: &str = "review-1";
const RELEASE_ID: &str = "release-1";

fn artifact() -> Digest {
    Digest::from_text("artifact-bytes-1").expect("artifact digest")
}

fn scope() -> AppStoreConnectScope {
    let artifact = artifact();
    AppStoreConnectScope::new(
        hartevo_appstoreconnect_release_result_plugin::ApiOriginScope::new(ORIGIN, 1)
            .expect("origin"),
        TeamScope::new("team-1", 2).expect("team"),
        AppScope::new(APP_ID, BUNDLE_ID, 3).expect("app"),
        Platform::Ios,
        PreReleaseVersionScope::new(PRE_RELEASE_ID, 4).expect("pre-release"),
        BuildScope::new(BUILD_ID, "1.2.3", "42", artifact.clone(), 5).expect("build"),
        AppStoreVersionScope::new(VERSION_ID, "1.2.3", Platform::Ios, 6)
            .expect("app store version"),
        BetaGroupScope::with_id(BETA_GROUP_ID, 7).expect("beta group"),
        ReviewScope::with_id(REVIEW_ID, 8).expect("review"),
        ReleaseScope::new(RELEASE_ID, 6).expect("release"),
        ProjectScope::new("project-1", 9).expect("Project"),
        MissionScope::new("mission-1", 10).expect("Mission"),
        WorkProductScope::new("work-product-1", 11).expect("Work Product"),
        ArtifactScope::new(artifact, 12).expect("artifact"),
    )
    .expect("scope")
}

fn permissions() -> PermissionSnapshot {
    PermissionSnapshot::read_only()
}

fn registration() -> hartevo_appstoreconnect_release_result_plugin::AppStoreConnectRegistration {
    let current_scope = scope();
    let permissions = permissions();
    let secret = SecretReference::from_apple_team_key_material(
        "keychain://apple/team-key-1",
        "TEAMKEY1",
        "issuer-1",
        b"-----BEGIN PRIVATE KEY-----super-sensitive-----END PRIVATE KEY-----",
    )
    .expect("opaque Apple team key reference")
    .bind_to(&current_scope, &permissions)
    .expect("bound secret reference");
    let mut service = AppStoreConnectReleaseService::new();
    let receipt = service
        .register(
            hartevo_appstoreconnect_release_result_plugin::AppStoreConnectRegistrationRequest::new(
                current_scope,
                secret,
                permissions,
                1,
            )
            .expect("registration request"),
        )
        .expect("registration");
    service
        .get(&receipt.registration_digest)
        .expect("registration lookup")
        .clone()
}

fn build(
    scope: &AppStoreConnectScope,
    processing_state: BuildProcessingState,
    beta_state: BetaReviewState,
) -> BuildPayload {
    BuildPayload {
        id: BUILD_ID.to_owned(),
        app_id: APP_ID.to_owned(),
        pre_release_version_id: PRE_RELEASE_ID.to_owned(),
        app_store_version_id: Some(VERSION_ID.to_owned()),
        version: scope.build.version.as_str().to_owned(),
        build_number: scope.build.build_number.as_str().to_owned(),
        processing_state,
        beta_review_state: beta_state,
        artifact_digest: artifact(),
        revision: scope.build.revision,
        expired: false,
        removed: false,
    }
}

fn version(
    scope: &AppStoreConnectScope,
    app_state: AppStoreState,
    review_state: ReviewState,
    release_state: ReleaseState,
) -> AppStoreVersionPayload {
    AppStoreVersionPayload {
        id: VERSION_ID.to_owned(),
        app_id: APP_ID.to_owned(),
        pre_release_version_id: PRE_RELEASE_ID.to_owned(),
        version: scope.app_store_version.version.as_str().to_owned(),
        release_id: RELEASE_ID.to_owned(),
        platform: Platform::Ios,
        app_store_state: app_state,
        review_state,
        release_state,
        build_id: Some(BUILD_ID.to_owned()),
        revision: scope.app_store_version.revision,
        expired: false,
        removed: false,
    }
}

fn entries(
    scope: &AppStoreConnectScope,
    processing_state: BuildProcessingState,
    beta_state: BetaReviewState,
    app_state: AppStoreState,
    review_state: ReviewState,
    release_state: ReleaseState,
) -> Vec<(AppStoreConnectEndpoint, AppStoreConnectResponseBody)> {
    let build = build(scope, processing_state, beta_state);
    let version = version(scope, app_state, review_state, release_state);
    let app = AppPayload {
        id: APP_ID.to_owned(),
        team_id: "team-1".to_owned(),
        bundle_id: BUNDLE_ID.to_owned(),
        revision: scope.app.revision,
        removed: false,
    };
    let pre_release = PreReleaseVersionPayload {
        id: PRE_RELEASE_ID.to_owned(),
        app_id: APP_ID.to_owned(),
        version: scope.app_store_version.version.as_str().to_owned(),
        platform: Platform::Ios,
        revision: scope.pre_release_version.revision,
        expired: false,
        removed: false,
    };
    let beta_group = BetaGroupPayload {
        id: BETA_GROUP_ID.to_owned(),
        app_id: APP_ID.to_owned(),
        build_ids: vec![BUILD_ID.to_owned()],
        revision: scope.beta_group.revision,
        removed: false,
    };
    let beta_review = BetaAppReviewSubmissionPayload {
        id: "beta-review-1".to_owned(),
        build_id: BUILD_ID.to_owned(),
        app_id: APP_ID.to_owned(),
        state: beta_state,
        revision: 13,
        expired: false,
        removed: false,
    };
    let review = ReviewSubmissionPayload {
        id: REVIEW_ID.to_owned(),
        app_id: APP_ID.to_owned(),
        app_store_version_id: Some(VERSION_ID.to_owned()),
        platform: Platform::Ios,
        state: review_state,
        revision: scope.review.revision,
        expired: false,
        removed: false,
    };
    let origin = ORIGIN.to_owned();
    vec![
        (
            AppStoreConnectEndpoint::Apps {
                origin: origin.clone(),
                bundle_id: BUNDLE_ID.to_owned(),
            },
            AppStoreConnectResponseBody::Apps(
                Page::new(vec![app.clone()], None).expect("apps page"),
            ),
        ),
        (
            AppStoreConnectEndpoint::App {
                origin: origin.clone(),
                app_id: APP_ID.to_owned(),
            },
            AppStoreConnectResponseBody::App(app),
        ),
        (
            AppStoreConnectEndpoint::PreReleaseVersion {
                origin: origin.clone(),
                pre_release_version_id: PRE_RELEASE_ID.to_owned(),
            },
            AppStoreConnectResponseBody::PreReleaseVersion(pre_release),
        ),
        (
            AppStoreConnectEndpoint::PreReleaseVersionBuilds {
                origin: origin.clone(),
                pre_release_version_id: PRE_RELEASE_ID.to_owned(),
            },
            AppStoreConnectResponseBody::Builds(
                Page::new(vec![build.clone()], None).expect("pre-release builds"),
            ),
        ),
        (
            AppStoreConnectEndpoint::Build {
                origin: origin.clone(),
                build_id: BUILD_ID.to_owned(),
            },
            AppStoreConnectResponseBody::Build(build.clone()),
        ),
        (
            AppStoreConnectEndpoint::BuildPreReleaseVersion {
                origin: origin.clone(),
                build_id: BUILD_ID.to_owned(),
            },
            AppStoreConnectResponseBody::Linkage(LinkagePayload {
                source_type: "builds".to_owned(),
                source_id: BUILD_ID.to_owned(),
                relationship: "preReleaseVersion".to_owned(),
                target_type: "preReleaseVersions".to_owned(),
                target_id: Some(PRE_RELEASE_ID.to_owned()),
                revision: scope.pre_release_version.revision,
            }),
        ),
        (
            AppStoreConnectEndpoint::BuildAppStoreVersion {
                origin: origin.clone(),
                build_id: BUILD_ID.to_owned(),
            },
            AppStoreConnectResponseBody::Linkage(LinkagePayload {
                source_type: "builds".to_owned(),
                source_id: BUILD_ID.to_owned(),
                relationship: "appStoreVersion".to_owned(),
                target_type: "appStoreVersions".to_owned(),
                target_id: Some(VERSION_ID.to_owned()),
                revision: scope.app_store_version.revision,
            }),
        ),
        (
            AppStoreConnectEndpoint::AppStoreVersions {
                origin: origin.clone(),
                app_id: APP_ID.to_owned(),
            },
            AppStoreConnectResponseBody::AppStoreVersions(
                Page::new(vec![version.clone()], None).expect("versions page"),
            ),
        ),
        (
            AppStoreConnectEndpoint::AppStoreVersion {
                origin: origin.clone(),
                app_store_version_id: VERSION_ID.to_owned(),
            },
            AppStoreConnectResponseBody::AppStoreVersion(version),
        ),
        (
            AppStoreConnectEndpoint::AppStoreVersionBuild {
                origin: origin.clone(),
                app_store_version_id: VERSION_ID.to_owned(),
            },
            AppStoreConnectResponseBody::Build(build.clone()),
        ),
        (
            AppStoreConnectEndpoint::AppStoreVersionBuildRelationship {
                origin: origin.clone(),
                app_store_version_id: VERSION_ID.to_owned(),
            },
            AppStoreConnectResponseBody::Linkage(LinkagePayload {
                source_type: "appStoreVersions".to_owned(),
                source_id: VERSION_ID.to_owned(),
                relationship: "build".to_owned(),
                target_type: "builds".to_owned(),
                target_id: Some(BUILD_ID.to_owned()),
                revision: scope.build.revision,
            }),
        ),
        (
            AppStoreConnectEndpoint::BetaGroups {
                origin: origin.clone(),
                app_id: APP_ID.to_owned(),
            },
            AppStoreConnectResponseBody::BetaGroups(
                Page::new(vec![beta_group.clone()], None).expect("beta groups page"),
            ),
        ),
        (
            AppStoreConnectEndpoint::BetaGroup {
                origin: origin.clone(),
                beta_group_id: BETA_GROUP_ID.to_owned(),
            },
            AppStoreConnectResponseBody::BetaGroup(beta_group),
        ),
        (
            AppStoreConnectEndpoint::BetaGroupBuilds {
                origin: origin.clone(),
                beta_group_id: BETA_GROUP_ID.to_owned(),
            },
            AppStoreConnectResponseBody::Builds(
                Page::new(vec![build.clone()], None).expect("beta builds page"),
            ),
        ),
        (
            AppStoreConnectEndpoint::BuildBetaAppReviewSubmission {
                origin: origin.clone(),
                build_id: BUILD_ID.to_owned(),
            },
            AppStoreConnectResponseBody::BetaReviewSubmission(beta_review),
        ),
        (
            AppStoreConnectEndpoint::ReviewSubmissions {
                origin: origin.clone(),
                app_id: APP_ID.to_owned(),
            },
            AppStoreConnectResponseBody::ReviewSubmissions(
                Page::new(vec![review.clone()], None).expect("reviews page"),
            ),
        ),
        (
            AppStoreConnectEndpoint::ReviewSubmission {
                origin,
                review_submission_id: REVIEW_ID.to_owned(),
            },
            AppStoreConnectResponseBody::ReviewSubmission(review),
        ),
    ]
}

fn recording_provider() -> AppStoreConnectProvider<RecordingAppStoreConnectTransport> {
    let registration = registration();
    let transport = RecordingAppStoreConnectTransport::new(entries(
        &registration.scope,
        BuildProcessingState::Complete,
        BetaReviewState::Approved,
        AppStoreState::PendingDeveloperRelease,
        ReviewState::Accepted,
        ReleaseState::PendingDeveloperRelease,
    ))
    .expect("recording transport");
    AppStoreConnectProvider::new(registration, transport).expect("provider")
}

#[test]
fn contract_capabilities_and_scope_digests_are_exact() {
    validate_contract_document().expect("contract");
    let service = AppStoreConnectReleaseService::new();
    let capabilities = service.describe_capabilities();
    assert!(capabilities.read_only);
    assert!(capabilities.proposal_only);
    assert!(!capabilities.external_writes);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.kernel_authority);
    assert!(!capabilities.jwt_serialized);
    assert!(!capabilities.private_key_material);
    assert_eq!(
        capabilities.transport_provenance,
        ["recording", "fixture", "loopback", "blocked_env"]
    );
    assert_ne!(
        scope().digest(),
        Digest::from_text("other-scope").expect("digest")
    );
}

#[test]
fn secret_and_jwt_material_are_digest_only_and_es256_is_explicit() {
    let secret = SecretReference::from_apple_team_key_material(
        "opaque-handle-sensitive",
        "TEAMKEY-SENSITIVE",
        "ISSUER-SENSITIVE",
        b"PRIVATE-KEY-SENSITIVE",
    )
    .expect("secret reference");
    let serialized = serde_json::to_string(&secret).expect("secret serialization");
    let debug = format!("{secret:?}");
    for forbidden in [
        "opaque-handle-sensitive",
        "TEAMKEY-SENSITIVE",
        "ISSUER-SENSITIVE",
        "PRIVATE-KEY-SENSITIVE",
    ] {
        assert!(!serialized.contains(forbidden));
        assert!(!debug.contains(forbidden));
    }
    let redaction = JwtRedaction::from_es256_material(
        "TEAMKEY-SENSITIVE",
        "ISSUER-SENSITIVE",
        "jwt.header.payload.signature",
        b"PRIVATE-KEY-SENSITIVE",
    )
    .expect("JWT redaction");
    assert_eq!(redaction.algorithm.as_str(), "ES256");
    assert!(!redaction.raw_jwt);
    assert!(!redaction.private_key_material);
    let json = serde_json::to_string(&redaction).expect("JWT metadata serialization");
    for forbidden in [
        "TEAMKEY-SENSITIVE",
        "ISSUER-SENSITIVE",
        "jwt.header.payload.signature",
        "PRIVATE-KEY-SENSITIVE",
    ] {
        assert!(!json.contains(forbidden));
    }
}

#[test]
fn recording_read_projects_linkage_and_records_below_kernel_evidence() {
    let mut provider = recording_provider();
    let projection = provider.read_result().expect("release projection");
    assert_eq!(projection.status, ProjectionStatus::BetaApproved);
    assert_eq!(projection.provenance, TransportProvenance::Recording);
    assert_eq!(projection.receipts.len(), 17);
    assert!(projection.receipts.iter().all(|receipt| {
        receipt.method == "GET"
            && !receipt.raw_provider_payload
            && !receipt.credential_material
            && !receipt.provider_receipt
            && !receipt.connected
            && !receipt.native
    }));
    projection
        .validate_integrity()
        .expect("projection integrity");
    assert!(
        provider
            .transport()
            .requests()
            .iter()
            .all(|request| request.method.as_str() == "GET")
    );
    assert!(
        provider.transport().requests().iter().all(|request| request
            .authorization
            .algorithm
            .as_str()
            == "ES256")
    );

    let consumer = MissionMobileReleaseConsumer::new(provider.registration()).expect("consumer");
    let proposal = consumer
        .compile_proposal(&projection, "mobile-release-result-1")
        .expect("proposal");
    assert!(proposal.is_review_only());
    assert!(!proposal.can_be_adopted());
    assert_eq!(proposal.project_id, "project-1");
    assert_eq!(proposal.mission_id, "mission-1");
    assert_eq!(proposal.work_product_id, "work-product-1");
    let mut log =
        hartevo_appstoreconnect_release_result_plugin::MobileReleaseRecordingLog::default();
    let recorded = consumer.record(&proposal, &mut log).expect("recording");
    assert!(!recorded.replayed);
    recorded.validate().expect("recorded evidence");
    let replay = consumer.record(&proposal, &mut log).expect("replay");
    assert!(replay.replayed);
    assert_eq!(log.len(), 1);
    assert!(consumer.verify(&projection, &proposal).expect("verify"));
}

#[test]
fn loopback_fixture_and_blocked_env_never_claim_native_or_connected() {
    let registered = registration();
    let loopback = LoopbackAppStoreConnectTransport::new(entries(
        &registered.scope,
        BuildProcessingState::Complete,
        BetaReviewState::None,
        AppStoreState::PrepareForSubmission,
        ReviewState::None,
        ReleaseState::PendingDeveloperRelease,
    ))
    .expect("loopback");
    let mut provider =
        AppStoreConnectProvider::new(registered.clone(), loopback).expect("provider");
    let projection = provider.read_result().expect("loopback projection");
    assert_eq!(projection.provenance, TransportProvenance::Loopback);
    assert_eq!(projection.status, ProjectionStatus::Ready);
    assert!(!projection.connected);
    assert!(!projection.native);

    let mut blocked = AppStoreConnectProvider::new(
        registered,
        hartevo_appstoreconnect_release_result_plugin::BlockedEnvAppStoreConnectTransport,
    )
    .expect("blocked provider");
    let blocked_projection = blocked.read_result().expect("blocked projection");
    assert_eq!(blocked_projection.status, ProjectionStatus::ProviderUnknown);
    assert_eq!(
        blocked_projection.provenance,
        TransportProvenance::BlockedEnv
    );
    assert_eq!(blocked.state(), AppStoreConnectProviderState::BlockedEnv);
    assert!(!blocked_projection.connected);
    assert!(!blocked_projection.native);
}

#[test]
fn status_projection_covers_processing_review_beta_release_and_partial() {
    let cases = [
        (
            BuildProcessingState::Processing,
            BetaReviewState::None,
            AppStoreState::PrepareForSubmission,
            ReviewState::None,
            ReleaseState::PendingDeveloperRelease,
            ProjectionStatus::Processing,
        ),
        (
            BuildProcessingState::Complete,
            BetaReviewState::None,
            AppStoreState::InReview,
            ReviewState::InReview,
            ReleaseState::PendingDeveloperRelease,
            ProjectionStatus::InReview,
        ),
        (
            BuildProcessingState::Complete,
            BetaReviewState::WaitingForReview,
            AppStoreState::PrepareForSubmission,
            ReviewState::None,
            ReleaseState::PendingDeveloperRelease,
            ProjectionStatus::BetaPending,
        ),
        (
            BuildProcessingState::Complete,
            BetaReviewState::Rejected,
            AppStoreState::PrepareForSubmission,
            ReviewState::None,
            ReleaseState::PendingDeveloperRelease,
            ProjectionStatus::BetaRejected,
        ),
        (
            BuildProcessingState::Complete,
            BetaReviewState::None,
            AppStoreState::ReadyForSale,
            ReviewState::Accepted,
            ReleaseState::Released,
            ProjectionStatus::Released,
        ),
    ];
    for (processing, beta, app, review, release, expected) in cases {
        let registered = registration();
        let transport = RecordingAppStoreConnectTransport::new(entries(
            &registered.scope,
            processing,
            beta,
            app,
            review,
            release,
        ))
        .expect("transport");
        let mut provider = AppStoreConnectProvider::new(registered, transport).expect("provider");
        assert_eq!(provider.read_result().expect("projection").status, expected);
    }

    let registered = registration();
    let mut fixture = FixtureAppStoreConnectTransport::new(entries(
        &registered.scope,
        BuildProcessingState::Complete,
        BetaReviewState::Approved,
        AppStoreState::PendingDeveloperRelease,
        ReviewState::Accepted,
        ReleaseState::PendingDeveloperRelease,
    ))
    .expect("fixture");
    fixture
        .insert(
            AppStoreConnectEndpoint::BetaGroupBuilds {
                origin: ORIGIN.to_owned(),
                beta_group_id: BETA_GROUP_ID.to_owned(),
            },
            AppStoreConnectResponseBody::Builds(
                Page::new(Vec::new(), None).expect("empty beta builds"),
            ),
        )
        .expect("partial fixture");
    let mut provider = AppStoreConnectProvider::new(registered, fixture).expect("provider");
    let projection = provider.read_result().expect("partial projection");
    assert_eq!(projection.status, ProjectionStatus::Partial);
    assert_eq!(
        projection.completeness,
        hartevo_appstoreconnect_release_result_plugin::ProjectionCompleteness::Partial
    );
}

#[test]
fn scope_revision_and_artifact_drift_fail_closed() {
    let registered = registration();
    let mut provider = recording_provider();
    let mut different_scope = scope();
    different_scope.app = AppScope::new(APP_ID, "com.other.bundle", 3).expect("other scope");
    let request = hartevo_appstoreconnect_release_result_plugin::AppStoreConnectReadRequest::new(
        different_scope,
    )
    .expect("request");
    assert_eq!(
        provider
            .read_release_result(&request)
            .expect_err("scope drift"),
        AppStoreConnectReleaseResultError::ScopeMismatch
    );

    let wrong_revision_entries = entries(
        &registered.scope,
        BuildProcessingState::Complete,
        BetaReviewState::Approved,
        AppStoreState::PendingDeveloperRelease,
        ReviewState::Accepted,
        ReleaseState::PendingDeveloperRelease,
    );
    let mut wrong_revision_fixture =
        FixtureAppStoreConnectTransport::new(wrong_revision_entries).expect("revision fixture");
    wrong_revision_fixture
        .insert(
            AppStoreConnectEndpoint::App {
                origin: ORIGIN.to_owned(),
                app_id: APP_ID.to_owned(),
            },
            AppStoreConnectResponseBody::App(AppPayload {
                id: APP_ID.to_owned(),
                team_id: "team-1".to_owned(),
                bundle_id: BUNDLE_ID.to_owned(),
                revision: 999,
                removed: false,
            }),
        )
        .expect("wrong revision");
    let mut revision_provider =
        AppStoreConnectProvider::new(registered.clone(), wrong_revision_fixture).expect("provider");
    assert_eq!(
        revision_provider.read_result().expect_err("revision drift"),
        AppStoreConnectReleaseResultError::RevisionMismatch
    );

    let mut wrong_artifact_fixture = FixtureAppStoreConnectTransport::new(entries(
        &registered.scope,
        BuildProcessingState::Complete,
        BetaReviewState::Approved,
        AppStoreState::PendingDeveloperRelease,
        ReviewState::Accepted,
        ReleaseState::PendingDeveloperRelease,
    ))
    .expect("artifact fixture");
    let mut wrong_build = build(
        &registered.scope,
        BuildProcessingState::Complete,
        BetaReviewState::Approved,
    );
    wrong_build.artifact_digest = Digest::from_text("different-artifact").expect("digest");
    wrong_artifact_fixture
        .insert(
            AppStoreConnectEndpoint::Build {
                origin: ORIGIN.to_owned(),
                build_id: BUILD_ID.to_owned(),
            },
            AppStoreConnectResponseBody::Build(wrong_build),
        )
        .expect("wrong artifact");
    let mut artifact_provider =
        AppStoreConnectProvider::new(registered, wrong_artifact_fixture).expect("provider");
    assert_eq!(
        artifact_provider.read_result().expect_err("artifact drift"),
        AppStoreConnectReleaseResultError::ArtifactMismatch
    );
}

#[test]
fn pagination_and_relationship_loops_fail_closed() {
    let registered = registration();
    let token = PageToken::new("same-page-token").expect("token");
    let endpoint = AppStoreConnectEndpoint::Apps {
        origin: ORIGIN.to_owned(),
        bundle_id: BUNDLE_ID.to_owned(),
    };
    let mut fixture = FixtureAppStoreConnectTransport::empty();
    fixture
        .insert_page(
            endpoint.clone(),
            0,
            None,
            AppStoreConnectResponseBody::Apps(
                Page::new(Vec::new(), Some(token.clone())).expect("first page"),
            ),
        )
        .expect("first page fixture");
    fixture
        .insert_page(
            endpoint,
            1,
            Some(token.clone()),
            AppStoreConnectResponseBody::Apps(
                Page::new(Vec::new(), Some(token)).expect("loop page"),
            ),
        )
        .expect("loop page fixture");
    let mut provider = AppStoreConnectProvider::new(registered.clone(), fixture).expect("provider");
    assert_eq!(
        provider.read_result().expect_err("pagination loop"),
        AppStoreConnectReleaseResultError::RelationshipLoop
    );

    let mut relationship_fixture = FixtureAppStoreConnectTransport::new(entries(
        &registered.scope,
        BuildProcessingState::Complete,
        BetaReviewState::Approved,
        AppStoreState::PendingDeveloperRelease,
        ReviewState::Accepted,
        ReleaseState::PendingDeveloperRelease,
    ))
    .expect("relationship fixture");
    relationship_fixture
        .insert(
            AppStoreConnectEndpoint::BuildPreReleaseVersion {
                origin: ORIGIN.to_owned(),
                build_id: BUILD_ID.to_owned(),
            },
            AppStoreConnectResponseBody::Relationships(
                hartevo_appstoreconnect_release_result_plugin::RelationshipPayload {
                    source_type: "builds".to_owned(),
                    source_id: BUILD_ID.to_owned(),
                    relationship: "preReleaseVersion".to_owned(),
                    links: vec![
                        hartevo_appstoreconnect_release_result_plugin::RelationshipLink {
                            resource_type: "builds".to_owned(),
                            resource_id: BUILD_ID.to_owned(),
                        },
                    ],
                    next: None,
                },
            ),
        )
        .expect("relationship loop");
    let mut provider =
        AppStoreConnectProvider::new(registered, relationship_fixture).expect("provider");
    assert_eq!(
        provider.read_result().expect_err("relationship loop"),
        AppStoreConnectReleaseResultError::RelationshipLoop
    );
}

#[test]
fn provider_statuses_cover_http_errors_timeouts_expiry_removal_and_tamper() {
    for (http_status, expected) in [
        (401, ProjectionStatus::AccessLost),
        (403, ProjectionStatus::AccessLost),
        (404, ProjectionStatus::Removed),
        (409, ProjectionStatus::Partial),
        (422, ProjectionStatus::Partial),
        (429, ProjectionStatus::ProviderUnknown),
        (500, ProjectionStatus::ProviderUnknown),
        (503, ProjectionStatus::ProviderUnknown),
    ] {
        let registered = registration();
        let mut fixture = FixtureAppStoreConnectTransport::empty();
        fixture
            .insert_status(
                AppStoreConnectEndpoint::Apps {
                    origin: ORIGIN.to_owned(),
                    bundle_id: BUNDLE_ID.to_owned(),
                },
                http_status,
            )
            .expect("status fixture");
        let mut provider = AppStoreConnectProvider::new(registered, fixture).expect("provider");
        let projection = provider.read_result().expect("status projection");
        assert_eq!(projection.status, expected);
    }

    let registered = registration();
    let mut timeout_fixture = FixtureAppStoreConnectTransport::empty();
    timeout_fixture
        .insert_error(
            AppStoreConnectEndpoint::Apps {
                origin: ORIGIN.to_owned(),
                bundle_id: BUNDLE_ID.to_owned(),
            },
            AppStoreConnectTransportError::Timeout,
        )
        .expect("timeout fixture");
    let mut timeout_provider = AppStoreConnectProvider::new(registered.clone(), timeout_fixture)
        .expect("timeout provider");
    assert_eq!(
        timeout_provider
            .read_result()
            .expect("timeout projection")
            .status,
        ProjectionStatus::ProviderUnknown
    );

    let mut removed_entries = entries(
        &registered.scope,
        BuildProcessingState::Complete,
        BetaReviewState::Approved,
        AppStoreState::PendingDeveloperRelease,
        ReviewState::Accepted,
        ReleaseState::PendingDeveloperRelease,
    );
    if let Some((_, AppStoreConnectResponseBody::Apps(page))) = removed_entries.first_mut()
        && let Some(app) = page.items.first_mut()
    {
        app.removed = true;
    }
    let removed_fixture =
        FixtureAppStoreConnectTransport::new(removed_entries).expect("removed fixture");
    let mut removed_provider = AppStoreConnectProvider::new(registered.clone(), removed_fixture)
        .expect("removed provider");
    assert_eq!(
        removed_provider
            .read_result()
            .expect("removed projection")
            .status,
        ProjectionStatus::Removed
    );

    let mut expired_entries = entries(
        &registered.scope,
        BuildProcessingState::Complete,
        BetaReviewState::Approved,
        AppStoreState::PendingDeveloperRelease,
        ReviewState::Accepted,
        ReleaseState::PendingDeveloperRelease,
    );
    for (_, body) in &mut expired_entries {
        if let AppStoreConnectResponseBody::PreReleaseVersion(value) = body {
            value.expired = true;
        }
    }
    let expired_fixture =
        FixtureAppStoreConnectTransport::new(expired_entries).expect("expired fixture");
    let mut expired_provider = AppStoreConnectProvider::new(registered.clone(), expired_fixture)
        .expect("expired provider");
    assert_eq!(
        expired_provider
            .read_result()
            .expect("expired projection")
            .status,
        ProjectionStatus::Expired
    );

    let mut provider = recording_provider();
    let mut projection = provider.read_result().expect("projection");
    projection.connected = true;
    assert_eq!(
        projection.validate_integrity().expect_err("tamper"),
        AppStoreConnectReleaseResultError::TamperedEvidence
    );
}

#[test]
fn registration_is_reversible_and_revocable() {
    let current_scope = scope();
    let permission_snapshot = permissions();
    let secret = SecretReference::new("opaque-registration-handle")
        .expect("secret")
        .bind_to(&current_scope, &permission_snapshot)
        .expect("bound secret");
    let mut service = AppStoreConnectReleaseService::new();
    let registered = service
        .register(
            hartevo_appstoreconnect_release_result_plugin::AppStoreConnectRegistrationRequest::new(
                current_scope.clone(),
                secret,
                permission_snapshot.clone(),
                7,
            )
            .expect("request"),
        )
        .expect("registered");
    assert!(registered.reversible);
    assert!(registered.revocable);
    let reversed = service
        .reverse_registration(&registered.registration_digest)
        .expect("reversed");
    assert_eq!(
        reversed.status,
        hartevo_appstoreconnect_release_result_plugin::AppStoreConnectRegistrationStatus::Reversed
    );
    assert!(
        service
            .reverse_registration(&registered.registration_digest)
            .is_err()
    );

    let secret = SecretReference::new("opaque-revocable-handle")
        .expect("secret")
        .bind_to(&current_scope, &permission_snapshot)
        .expect("bound secret");
    let registered = service
        .register(
            hartevo_appstoreconnect_release_result_plugin::AppStoreConnectRegistrationRequest::new(
                current_scope,
                secret,
                permission_snapshot,
                8,
            )
            .expect("request"),
        )
        .expect("registered");
    let revoked = service
        .revoke_registration(&registered.registration_digest)
        .expect("revoked");
    assert_eq!(
        revoked.status,
        hartevo_appstoreconnect_release_result_plugin::AppStoreConnectRegistrationStatus::Revoked
    );
}

#[test]
fn request_is_get_only_and_endpoint_paths_are_official_shapes() {
    let registration = registration();
    let request = AppStoreConnectHttpRequest::new(
        AppStoreConnectEndpoint::AppStoreVersionBuildRelationship {
            origin: ORIGIN.to_owned(),
            app_store_version_id: VERSION_ID.to_owned(),
        },
        1_048_576,
        JwtRedaction::for_secret_reference(&registration.secret_reference),
    )
    .expect("GET request");
    assert_eq!(request.method.as_str(), "GET");
    assert_eq!(
        request.path_and_query().expect("path"),
        "https://api.appstoreconnect.apple.com/v1/appStoreVersions/version-1/relationships/build"
    );
    assert!(
        !serde_json::to_string(&request)
            .expect("request serialization")
            .contains("PRIVATE")
    );
}
