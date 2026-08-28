use std::fmt::Debug;

use hartevo_googleplay_release_result_plugin::{
    AccessTokenLease, ArtifactBinding, ArtifactId, BlockedEnvCredentialResolver,
    BlockedEnvGooglePlayTransport, CredentialKind, DeveloperAccountId, EvidenceCompleteness,
    FixtureGooglePlayTransport, FormFactor, GoogleCredentialResolver, GooglePlayEndpoint,
    GooglePlayHttpRequest, GooglePlayHttpResponse, GooglePlayProvider, GooglePlayProviderState,
    GooglePlayReadRequest, GooglePlayReleasePayload, GooglePlayReleaseResultError,
    GooglePlayReleaseScope, GooglePlayReleaseService, GooglePlayResponseBody,
    GooglePlayTrackPayload, LoopbackGooglePlayTransport, MissionAndroidReleaseConsumer,
    PackageName, PermissionSnapshot, ProjectScope, RecordingGooglePlayTransport, ReleaseId,
    ReleaseLifecycleState, ReleaseResultStatus, ReleaseSelector, RolloutBucket, SecretReference,
    TrackName, TransportProvenance, WorkProductScope,
};

const ARTIFACT_DIGEST_TEXT: &str = "android-bundle-for-mission-7";
const HANDLE: &str = "opaque://googleplay/credential/7";

fn scope() -> GooglePlayReleaseScope {
    GooglePlayReleaseScope::new(
        DeveloperAccountId::parse("developer-7").expect("developer"),
        PackageName::parse("com.hartevo.demo").expect("package"),
        TrackName::parse("production").expect("track"),
        FormFactor::Phone,
        ReleaseSelector::Exact(ReleaseId::parse("release-42").expect("release")),
        ArtifactBinding::new(
            ArtifactId::parse("artifact-aab-42").expect("artifact"),
            42,
            hartevo_googleplay_release_result_plugin::Digest::from_text(ARTIFACT_DIGEST_TEXT),
        )
        .expect("artifact binding"),
        ProjectScope::new("project-7", 3).expect("project"),
        hartevo_googleplay_release_result_plugin::MissionScope::new("mission-7", 5)
            .expect("mission"),
        WorkProductScope::new("work-product-7", 9).expect("work product"),
        Some(
            hartevo_googleplay_release_result_plugin::DeploymentIdentity::parse("deploy-42")
                .expect("deployment"),
        ),
    )
    .expect("scope")
}

fn registration_for_scope(
    current_scope: GooglePlayReleaseScope,
) -> hartevo_googleplay_release_result_plugin::GooglePlayRegistration {
    let permissions = PermissionSnapshot::read_only();
    let secret = SecretReference::new(HANDLE, CredentialKind::OAuth, 7)
        .expect("secret")
        .bind_to(&current_scope, &permissions)
        .expect("bound secret");
    let mut service = GooglePlayReleaseService::new();
    let receipt = service
        .register(
            hartevo_googleplay_release_result_plugin::GooglePlayRegistrationRequest::new(
                current_scope,
                secret,
                permissions,
                11,
            )
            .expect("registration request"),
        )
        .expect("registration");
    service
        .get(&receipt.registration_digest)
        .expect("registered item")
        .clone()
}

fn registration() -> hartevo_googleplay_release_result_plugin::GooglePlayRegistration {
    registration_for_scope(scope())
}

fn endpoint() -> GooglePlayEndpoint {
    GooglePlayEndpoint::TrackReleases {
        package_name: PackageName::parse("com.hartevo.demo").expect("package"),
        track: TrackName::parse("production").expect("track"),
    }
}

fn payload(state: ReleaseLifecycleState, version_codes: Vec<u64>) -> GooglePlayTrackPayload {
    let release = GooglePlayReleasePayload::new(
        ReleaseId::parse("release-42").expect("release"),
        state,
        version_codes,
    )
    .expect("release");
    GooglePlayTrackPayload::new(
        TrackName::parse("production").expect("track"),
        vec![release],
    )
    .expect("track")
    .with_package_name(PackageName::parse("com.hartevo.demo").expect("package"))
}

fn recording_provider(
    body: GooglePlayResponseBody,
) -> GooglePlayProvider<RecordingGooglePlayTransport, BlockedEnvCredentialResolver> {
    let transport = RecordingGooglePlayTransport::new([(endpoint(), body)]).expect("transport");
    GooglePlayProvider::new(registration(), transport, BlockedEnvCredentialResolver)
        .expect("provider")
}

fn read_request() -> GooglePlayReadRequest {
    GooglePlayReadRequest::with_bounds(20, 1_048_576, 100).expect("request")
}

#[test]
fn contract_capability_and_endpoint_are_exactly_read_only() {
    hartevo_googleplay_release_result_plugin::validate_contract_document().expect("contract");
    assert_eq!(
        hartevo_googleplay_release_result_plugin::contract_digest().as_str(),
        "4f22ab5de14af6781fd4312dd8f3063aba87d9cb13ab06732e13df153d1f4d99"
    );
    let service = GooglePlayReleaseService::new();
    let capabilities = service.describe_capabilities();
    assert!(capabilities.read_only);
    assert!(capabilities.proposal_only);
    assert!(!capabilities.external_writes);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.kernel_authority);
    assert!(!capabilities.raw_release_notes);
    assert!(!capabilities.tester_pii);
    assert!(!capabilities.artifact_bytes);

    let request = GooglePlayHttpRequest::new(endpoint(), 1_048_576, 100).expect("request");
    assert_eq!(
        request.path_and_query().expect("path"),
        "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/com.hartevo.demo/tracks/production/releases"
    );
    assert_eq!(request.method.as_str(), "GET");
    assert!(request.request_digest.is_sha256());
}

#[test]
fn opaque_credentials_and_borrowed_tokens_never_print_material() {
    let secret = SecretReference::new(HANDLE, CredentialKind::ServiceAccount, 1).expect("secret");
    let debug = format!("{secret:?}");
    let json = serde_json::to_string(&secret).expect("secret JSON");
    assert!(!debug.contains(HANDLE));
    assert!(!json.contains(HANDLE));
    assert!(json.contains("referenceDigest"));

    let token = AccessTokenLease::new("access-token-must-not-print", 1000).expect("token");
    assert!(!format!("{token:?}").contains("access-token-must-not-print"));
    assert_eq!(token.as_str(), "access-token-must-not-print");
}

#[test]
fn registration_binds_scope_permission_provider_and_is_reversible_revocable() {
    let current_scope = scope();
    let permissions = PermissionSnapshot::read_only();
    let secret = SecretReference::for_service_account(HANDLE, 7)
        .expect("secret")
        .bind_to(&current_scope, &permissions)
        .expect("bound");
    let mut service = GooglePlayReleaseService::new();
    let receipt = service
        .register(
            hartevo_googleplay_release_result_plugin::GooglePlayRegistrationRequest::new(
                current_scope,
                secret,
                permissions,
                12,
            )
            .expect("request"),
        )
        .expect("register");
    assert!(receipt.reversible);
    assert!(receipt.revocable);
    assert!(!receipt.connected);
    assert!(!receipt.native);
    assert!(!receipt.credential_material);

    let reversed = service
        .reverse_registration(&receipt.registration_digest)
        .expect("reverse");
    assert_eq!(
        reversed.status,
        hartevo_googleplay_release_result_plugin::GooglePlayRegistrationStatus::Reversed
    );
    assert_eq!(
        service
            .reverse_registration(&receipt.registration_digest)
            .expect_err("one-way terminal transition"),
        GooglePlayReleaseResultError::RegistrationReversed
    );
}

#[test]
fn all_allowlisted_lifecycle_states_and_rollout_buckets_project_without_native_claims() {
    for (state, expected) in [
        (ReleaseLifecycleState::Draft, ReleaseResultStatus::Draft),
        (
            ReleaseLifecycleState::NotSentForReview,
            ReleaseResultStatus::NotSentForReview,
        ),
        (
            ReleaseLifecycleState::InReview,
            ReleaseResultStatus::InReview,
        ),
        (
            ReleaseLifecycleState::ApprovedNotPublished,
            ReleaseResultStatus::ApprovedNotPublished,
        ),
        (
            ReleaseLifecycleState::NotApproved,
            ReleaseResultStatus::NotApproved,
        ),
        (
            ReleaseLifecycleState::Published,
            ReleaseResultStatus::Published,
        ),
    ] {
        let body = GooglePlayResponseBody::TrackReleases(
            payload(state, vec![42])
                .with_user_fraction(250_000)
                .expect("rollout"),
        );
        let mut provider = recording_provider(body);
        let evidence = provider.read(&read_request()).expect("evidence");
        assert_eq!(evidence.status, expected);
        assert_eq!(evidence.completeness, EvidenceCompleteness::Complete);
        assert_eq!(evidence.releases.len(), 1);
        assert_eq!(
            evidence.releases[0].rollout_bucket,
            RolloutBucket::UserFraction {
                millionths: 250_000
            }
        );
        assert!(evidence.releases[0].artifact_binding_matches);
        assert!(!evidence.connected);
        assert!(!evidence.native);
        assert!(evidence.receipts.iter().all(|receipt| {
            receipt.method == "GET"
                && !receipt.raw_provider_payload
                && !receipt.credential_material
                && !receipt.provider_receipt
                && !receipt.connected
                && !receipt.native
        }));
    }

    let halted = GooglePlayResponseBody::TrackReleases(
        payload(ReleaseLifecycleState::Published, vec![42])
            .with_country_targeting_digest(
                hartevo_googleplay_release_result_plugin::Digest::from_text("countries"),
            )
            .expect("country digest"),
    );
    let mut provider = recording_provider(halted);
    let evidence = provider.read(&read_request()).expect("evidence");
    assert_eq!(
        evidence.releases[0].rollout_bucket,
        RolloutBucket::CountryTargeted {
            targeting_digest: hartevo_googleplay_release_result_plugin::Digest::from_text(
                "countries",
            )
        }
    );

    let release = GooglePlayReleasePayload::new(
        ReleaseId::parse("release-42").expect("release"),
        ReleaseLifecycleState::Published,
        vec![42],
    )
    .expect("release")
    .halted();
    let track = GooglePlayTrackPayload::new(
        TrackName::parse("production").expect("track"),
        vec![release],
    )
    .expect("track")
    .with_package_name(PackageName::parse("com.hartevo.demo").expect("package"));
    let mut provider = recording_provider(GooglePlayResponseBody::TrackReleases(track));
    assert_eq!(
        provider.read(&read_request()).expect("halted").status,
        ReleaseResultStatus::Halted
    );
}

#[test]
fn raw_notes_and_tester_fields_are_dropped_before_the_typed_body() {
    let request = GooglePlayHttpRequest::new(endpoint(), 1_048_576, 1).expect("request");
    let response = GooglePlayHttpResponse::from_json(
        &request,
        200,
        r#"{
          "track":"production",
          "packageName":"com.hartevo.demo",
          "releases":[{
            "name":"release-42",
            "status":"PUBLISHED",
            "versionCodes":["42"],
            "releaseNotes":[{"language":"en-US","text":"private release note"}],
            "testers":["alice@example.test"],
            "userFraction":0.5,
            "countryTargeting":{"countries":["US"]}
          }]
        }"#,
        TransportProvenance::Loopback,
    )
    .expect("normalized response");
    let body = serde_json::to_string(response.body().expect("body")).expect("safe body JSON");
    assert!(!body.contains("private release note"));
    assert!(!body.contains("alice@example.test"));
    assert!(!body.contains("releaseNotes"));
    assert!(!body.contains("testers"));
}

#[test]
fn package_and_track_scope_drift_fail_closed() {
    let wrong_track = GooglePlayTrackPayload::new(
        TrackName::parse("beta").expect("track"),
        vec![
            GooglePlayReleasePayload::new(
                ReleaseId::parse("release-42").expect("release"),
                ReleaseLifecycleState::Published,
                vec![42],
            )
            .expect("release"),
        ],
    )
    .expect("track")
    .with_package_name(PackageName::parse("com.hartevo.demo").expect("package"));
    let mut wrong_track_provider =
        recording_provider(GooglePlayResponseBody::TrackReleases(wrong_track));
    assert_eq!(
        wrong_track_provider
            .read(&read_request())
            .expect_err("track drift"),
        GooglePlayReleaseResultError::ScopeMismatch
    );

    let wrong_package = GooglePlayTrackPayload::new(
        TrackName::parse("production").expect("track"),
        vec![
            GooglePlayReleasePayload::new(
                ReleaseId::parse("release-42").expect("release"),
                ReleaseLifecycleState::Published,
                vec![42],
            )
            .expect("release"),
        ],
    )
    .expect("track")
    .with_package_name(PackageName::parse("com.other.demo").expect("package"));
    let mut wrong_package_provider =
        recording_provider(GooglePlayResponseBody::TrackReleases(wrong_package));
    assert_eq!(
        wrong_package_provider
            .read(&read_request())
            .expect_err("package drift"),
        GooglePlayReleaseResultError::ScopeMismatch
    );
}

#[test]
fn max_twenty_releases_is_a_hard_bound() {
    let mut track = payload(ReleaseLifecycleState::Published, vec![42]);
    for version_code in 43..=63 {
        track.releases.push(
            GooglePlayReleasePayload::new(
                ReleaseId::parse(format!("release-{version_code}")).expect("release"),
                ReleaseLifecycleState::Published,
                vec![version_code],
            )
            .expect("release"),
        );
    }
    let mut provider = recording_provider(GooglePlayResponseBody::TrackReleases(track));
    assert_eq!(
        provider.read(&read_request()).expect_err("bounded result"),
        GooglePlayReleaseResultError::BoundExceeded {
            field: "release summaries"
        }
    );
}

#[test]
fn stale_obsolete_and_version_code_artifact_mismatch_are_not_success() {
    let old_release = GooglePlayReleasePayload::new(
        ReleaseId::parse("release-41").expect("release"),
        ReleaseLifecycleState::Published,
        vec![41],
    )
    .expect("release");
    let track = GooglePlayTrackPayload::new(
        TrackName::parse("production").expect("track"),
        vec![old_release],
    )
    .expect("track")
    .with_package_name(PackageName::parse("com.hartevo.demo").expect("package"));
    let mut provider = recording_provider(GooglePlayResponseBody::TrackReleases(track));
    let evidence = provider.read(&read_request()).expect("stale evidence");
    assert_eq!(evidence.status, ReleaseResultStatus::Stale);
    assert_eq!(evidence.completeness, EvidenceCompleteness::Unavailable);

    let mismatched = payload(ReleaseLifecycleState::Published, vec![42])
        .with_artifact_digest(
            42,
            hartevo_googleplay_release_result_plugin::Digest::from_text("different-artifact"),
        )
        .expect("mismatched digest");
    let mut provider = recording_provider(GooglePlayResponseBody::TrackReleases(mismatched));
    assert_eq!(
        provider
            .read(&read_request())
            .expect_err("artifact mismatch"),
        GooglePlayReleaseResultError::VersionCodeArtifactMismatch
    );
}

#[test]
fn rollout_policy_is_part_of_scope_and_mismatch_fails_closed() {
    let scoped = scope()
        .with_rollout(
            hartevo_googleplay_release_result_plugin::RolloutSelector::Exact(
                RolloutBucket::UserFraction {
                    millionths: 250_000,
                },
            ),
        )
        .expect("rollout scope");
    assert_ne!(scoped.digest(), scope().digest());
    let transport = RecordingGooglePlayTransport::new([(
        endpoint(),
        GooglePlayResponseBody::TrackReleases(
            payload(ReleaseLifecycleState::Published, vec![42])
                .with_user_fraction(500_000)
                .expect("rollout"),
        ),
    )])
    .expect("transport");
    let mut provider = GooglePlayProvider::new(
        registration_for_scope(scoped),
        transport,
        BlockedEnvCredentialResolver,
    )
    .expect("provider");
    assert_eq!(
        provider.read(&read_request()).expect_err("rollout drift"),
        GooglePlayReleaseResultError::ScopeMismatch
    );
}

#[test]
fn status_and_timeout_classification_is_bounded_and_fail_closed() {
    for (http_status, expected) in [
        (401, ReleaseResultStatus::AccessLost),
        (403, ReleaseResultStatus::AccessLost),
        (404, ReleaseResultStatus::Stale),
        (409, ReleaseResultStatus::Partial),
        (429, ReleaseResultStatus::ProviderUnknown),
        (500, ReleaseResultStatus::ProviderUnknown),
        (503, ReleaseResultStatus::ProviderUnknown),
    ] {
        let mut fixture = FixtureGooglePlayTransport::empty();
        fixture
            .insert_status(endpoint(), http_status)
            .expect("status");
        let mut provider =
            GooglePlayProvider::new(registration(), fixture, BlockedEnvCredentialResolver)
                .expect("provider");
        let evidence = provider.read(&read_request()).expect("classified status");
        assert_eq!(evidence.status, expected);
        assert!(!evidence.connected);
        assert!(!evidence.native);
    }

    let mut fixture = FixtureGooglePlayTransport::empty();
    fixture.insert_timeout(endpoint()).expect("timeout");
    let mut provider =
        GooglePlayProvider::new(registration(), fixture, BlockedEnvCredentialResolver)
            .expect("provider");
    assert_eq!(
        provider
            .read(&read_request())
            .expect("timeout evidence")
            .status,
        ReleaseResultStatus::ProviderUnknown
    );
}

#[test]
fn tamper_partial_and_provider_unknown_evidence_never_compile_for_adoption() {
    let mut provider = recording_provider(GooglePlayResponseBody::TrackReleases(payload(
        ReleaseLifecycleState::Published,
        vec![42],
    )));
    let mut evidence = provider.read(&read_request()).expect("evidence");
    evidence.status = ReleaseResultStatus::Stale;
    assert_eq!(
        evidence.validate().expect_err("tampered status"),
        GooglePlayReleaseResultError::TamperedEvidence
    );

    let mut partial_provider = recording_provider(GooglePlayResponseBody::TrackReleases(
        payload(ReleaseLifecycleState::Published, vec![42]).partial(),
    ));
    let partial = partial_provider.read(&read_request()).expect("partial");
    assert_eq!(partial.status, ReleaseResultStatus::Partial);
    let consumer = MissionAndroidReleaseConsumer::new(&registration()).expect("consumer");
    assert_eq!(
        consumer
            .compile_proposal(&partial, "partial")
            .expect_err("partial cannot adopt"),
        GooglePlayReleaseResultError::NonAdoptableProposal
    );

    let mut blocked = GooglePlayProvider::new(
        registration(),
        BlockedEnvGooglePlayTransport,
        BlockedEnvCredentialResolver,
    )
    .expect("blocked provider");
    let unknown = blocked.read(&read_request()).expect("blocked evidence");
    assert_eq!(unknown.status, ReleaseResultStatus::ProviderUnknown);
    assert_eq!(blocked.state(), GooglePlayProviderState::BlockedEnv);
    assert_eq!(unknown.provenance, TransportProvenance::BlockedEnv);
    assert!(!unknown.connected);
    assert!(!unknown.native);
}

#[test]
fn fixture_recording_loopback_and_blocked_provenance_never_become_connected() {
    let body =
        GooglePlayResponseBody::TrackReleases(payload(ReleaseLifecycleState::Published, vec![42]));
    let fixture = FixtureGooglePlayTransport::new([(endpoint(), body.clone())]).expect("fixture");
    let mut fixture_provider =
        GooglePlayProvider::new(registration(), fixture, BlockedEnvCredentialResolver)
            .expect("fixture provider");
    assert_eq!(
        fixture_provider
            .read(&read_request())
            .expect("fixture")
            .provenance,
        TransportProvenance::Fixture
    );

    let mut recording = GooglePlayProvider::new(
        registration(),
        RecordingGooglePlayTransport::new([(endpoint(), body.clone())]).expect("recording"),
        BlockedEnvCredentialResolver,
    )
    .expect("recording provider");
    assert_eq!(
        recording
            .read(&read_request())
            .expect("recording")
            .provenance,
        TransportProvenance::Recording
    );

    let mut loopback = GooglePlayProvider::new(
        registration(),
        LoopbackGooglePlayTransport::new([(endpoint(), body)]).expect("loopback"),
        BlockedEnvCredentialResolver,
    )
    .expect("loopback provider");
    assert_eq!(
        loopback.read(&read_request()).expect("loopback").provenance,
        TransportProvenance::Loopback
    );
    assert!(!fixture_provider.is_connected());
    assert!(!recording.is_native());
    assert!(!loopback.is_connected());
}

#[test]
fn mission_consumer_binds_revisions_and_records_idempotently_below_kernel() {
    let mut provider = recording_provider(GooglePlayResponseBody::TrackReleases(payload(
        ReleaseLifecycleState::Published,
        vec![42],
    )));
    let evidence = provider.read(&read_request()).expect("evidence");
    let registration = registration();
    let consumer = MissionAndroidReleaseConsumer::new(&registration).expect("consumer");
    let proposal = consumer
        .compile_release_proposal(&evidence, "mission-decision-1")
        .expect("proposal");
    assert_eq!(proposal.project_id, "project-7");
    assert_eq!(proposal.project_revision, 3);
    assert_eq!(proposal.mission_id, "mission-7");
    assert_eq!(proposal.mission_revision, 5);
    assert_eq!(proposal.work_product_id, "work-product-7");
    assert_eq!(proposal.work_product_revision, 9);
    assert!(proposal.is_review_only());
    assert!(!proposal.can_be_adopted());
    assert!(!proposal.connected);
    assert!(!proposal.native);

    let mut log =
        hartevo_googleplay_release_result_plugin::GooglePlayReleaseRecordingLog::default();
    let recorded = consumer.record(&proposal, &mut log).expect("record");
    assert!(!recorded.replayed);
    recorded.validate().expect("record integrity");
    let replay = consumer.record(&proposal, &mut log).expect("replay");
    assert!(replay.replayed);
    assert_eq!(log.len(), 1);
    assert!(consumer.verify(&evidence, &proposal).expect("verify"));
}

#[test]
fn official_transport_without_layer2_credentials_stays_provider_unknown() {
    let official =
        hartevo_googleplay_release_result_plugin::UreqGooglePlayTransport::android_publisher()
            .expect("official transport");
    let mut provider =
        GooglePlayProvider::new(registration(), official, BlockedEnvCredentialResolver)
            .expect("provider");
    let evidence = provider
        .read(&read_request())
        .expect("blocked official read");
    assert_eq!(evidence.status, ReleaseResultStatus::ProviderUnknown);
    assert_eq!(evidence.provenance, TransportProvenance::OfficialHttpsRead);
    assert_eq!(provider.state(), GooglePlayProviderState::BlockedEnv);
}

#[derive(Debug)]
struct Resolver;

impl GoogleCredentialResolver for Resolver {
    fn resolve(
        &mut self,
        _reference: &SecretReference,
        _at_epoch_seconds: u64,
    ) -> Result<AccessTokenLease, hartevo_googleplay_release_result_plugin::CredentialError> {
        AccessTokenLease::new("temporary-token", 1000)
            .map_err(|_| hartevo_googleplay_release_result_plugin::CredentialError::Invalid)
    }
}

#[test]
fn official_provider_seam_accepts_only_a_transient_lease_without_retaining_it() {
    let _resolver: Box<dyn Debug> = Box::new(Resolver);
    assert!(!format!("{Resolver:?}").contains("temporary-token"));
}
