use hartevo_dockerhub_image_result_plugin as dockerhub;
use serde_json::json;

fn platform(os: &str, architecture: &str) -> dockerhub::PlatformTuple {
    dockerhub::PlatformTuple::new(os, architecture, None::<String>).expect("platform")
}

fn scope_with(platforms: Vec<dockerhub::PlatformTuple>) -> dockerhub::DockerHubImageResultScope {
    dockerhub::DockerHubImageResultScope::exact(
        "library",
        "sample",
        "stable",
        dockerhub::MissionBinding::new("mission-1", 4).expect("mission"),
        dockerhub::ProjectBinding::new("project-1", 5).expect("project"),
        dockerhub::WorkProductBinding::new("work-product-1", 6).expect("work product"),
        platforms,
    )
    .expect("scope")
}

fn payload(two_platforms: bool) -> serde_json::Value {
    let mut images = vec![json!({
        "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "os": "linux",
        "architecture": "amd64",
        "size": 1024,
        "layers": [
            {
                "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "size": 512,
                "instruction": "FROM private/base:latest"
            }
        ]
    })];
    if two_platforms {
        images.push(json!({
            "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "os": "linux",
            "architecture": "arm64",
            "size": 768,
            "layers": [
                {
                    "digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    "size": 256,
                    "instruction": "RUN private instruction"
                }
            ]
        }));
    }
    json!({
        "name": "stable",
        "status": "active",
        "last_updated": "2026-08-15T00:00:00Z",
        "full_size": 1792,
        "description": "private description must be discarded",
        "creator": 42,
        "last_updater_username": "private-user",
        "images": images
    })
}

fn service(
    response: dockerhub::DockerHubTagResponse,
) -> dockerhub::DockerHubImageResultService<dockerhub::FixtureDockerHubTransport> {
    let scope = scope_with(vec![platform("linux", "amd64")]);
    let provider = dockerhub::DockerHubProvider::new(
        scope,
        dockerhub::SecretReference::new("opaque-keyring-handle", 9).expect("secret"),
        dockerhub::FixtureDockerHubTransport::new(response),
    )
    .expect("provider");
    dockerhub::DockerHubImageResultService::new(provider).expect("service")
}

fn service_for_status(
    status: u16,
) -> dockerhub::DockerHubImageResultService<dockerhub::FixtureDockerHubTransport> {
    service(
        dockerhub::DockerHubTagResponse::json(
            status,
            &json!({
                "detail": "provider body must not become evidence"
            }),
        )
        .expect("response"),
    )
}

#[test]
fn exact_tag_projection_is_bounded_redacted_and_deterministic() {
    let first = dockerhub::DockerHubTagResponse::json(200, &payload(false)).expect("response");
    let mut first_service = service(first);
    let proposal = first_service.compile_proposal().expect("proposal");
    assert_eq!(
        proposal.evidence.state,
        dockerhub::DockerHubEvidenceState::Ready
    );
    let projection = proposal.evidence.projection.as_ref().expect("projection");
    assert_eq!(projection.tag_status, dockerhub::DockerHubTagStatus::Active);
    assert_eq!(projection.image_count, 1);
    assert_eq!(projection.platform_count, 1);
    assert_eq!(projection.total_layer_count, 1);
    assert_eq!(projection.full_size_bytes, Some(1792));
    assert_eq!(projection.images[0].image_size_bytes, 1024);
    assert_eq!(projection.images[0].layer_size_bytes, 512);
    assert!(!proposal.native);
    assert!(!proposal.connected);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.adopts_outcome);
    assert!(!proposal.adopts_work_product);

    let serialized = serde_json::to_string(&proposal).expect("proposal serializes");
    assert!(!serialized.contains("opaque-keyring-handle"));
    assert!(!serialized.contains("private description"));
    assert!(!serialized.contains("private-user"));
    assert!(!serialized.contains("private/base"));
    assert!(!serialized.contains("private instruction"));
    assert!(!serialized.contains("creator"));

    let reordered = json!({
        "images": payload(false)["images"].clone(),
        "last_updated": "2026-08-15T00:00:00Z",
        "full_size": 1792,
        "status": "active",
        "name": "stable",
        "creator": 42,
        "last_updater_username": "private-user",
        "description": "private description must be discarded"
    });
    let reordered_response =
        dockerhub::DockerHubTagResponse::json(200, &reordered).expect("reordered response");
    let mut reordered_service = service(reordered_response);
    let reordered_proposal = reordered_service.compile_proposal().expect("proposal");
    assert_eq!(
        proposal
            .evidence
            .projection
            .as_ref()
            .expect("projection")
            .projection_digest,
        reordered_proposal
            .evidence
            .projection
            .as_ref()
            .expect("projection")
            .projection_digest
    );
    assert_eq!(
        proposal.evidence.digest(),
        reordered_proposal.evidence.digest()
    );
    assert_eq!(proposal.digest(), reordered_proposal.digest());
}

#[test]
fn two_platforms_are_retained_only_as_bounded_tuples_and_path_is_redacted() {
    let response = dockerhub::DockerHubTagResponse::json(200, &payload(true)).expect("response");
    let scope = scope_with(Vec::new());
    let provider = dockerhub::DockerHubProvider::new(
        scope,
        dockerhub::SecretReference::new("opaque-keyring-handle", 1).expect("secret"),
        dockerhub::RecordingDockerHubTransport::new(response),
    )
    .expect("provider");
    let mut service = dockerhub::DockerHubImageResultService::new(provider).expect("service");
    let proposal = service.compile_proposal().expect("proposal");
    let projection = proposal.evidence.projection.as_ref().expect("projection");
    assert_eq!(projection.platform_count, 2);
    assert_eq!(projection.total_layer_count, 2);
    assert_eq!(projection.images[0].platform.architecture(), "amd64");
    assert_eq!(projection.images[1].platform.architecture(), "arm64");

    let request = dockerhub::DockerHubTagRequest::new(service.scope(), 1_048_576).expect("request");
    assert_eq!(
        request.path_template(),
        "/v2/namespaces/{namespace}/repositories/{repository}/tags/{tag}"
    );
    assert!(!request.path_and_query().contains("library"));
    assert!(!request.path_and_query().contains("sample"));
    assert!(!request.path_and_query().contains("stable"));
    assert_eq!(
        service.provider().transport().requests()[0].operation,
        dockerhub::DockerHubOperation::ReadRepositoryTag
    );
}

#[test]
fn status_matrix_and_blocked_env_never_claim_connection() {
    let cases = [
        (401, dockerhub::DockerHubEvidenceState::Unauthorized),
        (403, dockerhub::DockerHubEvidenceState::Forbidden),
        (404, dockerhub::DockerHubEvidenceState::NotFound),
        (429, dockerhub::DockerHubEvidenceState::Throttled),
        (500, dockerhub::DockerHubEvidenceState::ProviderUnknown),
    ];
    for (status, expected) in cases {
        let mut service = service_for_status(status);
        let proposal = service.compile_proposal().expect("proposal");
        assert_eq!(proposal.evidence.state, expected);
        assert!(!proposal.evidence.connected);
        assert!(!proposal.evidence.native);
        assert!(!proposal.evidence.first_party);
    }

    let scope = scope_with(vec![platform("linux", "amd64")]);
    let provider = dockerhub::DockerHubProvider::new(
        scope,
        dockerhub::SecretReference::new("opaque-keyring-handle", 1).expect("secret"),
        dockerhub::BlockedEnvDockerHubTransport,
    )
    .expect("provider");
    let mut service = dockerhub::DockerHubImageResultService::new(provider).expect("service");
    let evidence = service.read().expect("blocked evidence");
    assert_eq!(
        evidence.state,
        dockerhub::DockerHubEvidenceState::ProviderUnknown
    );
    assert_eq!(
        evidence.provenance,
        dockerhub::TransportProvenance::BlockedEnv
    );
    assert!(!evidence.connected && !evidence.native && !evidence.first_party);
}

#[test]
fn registration_is_reversible_revocable_and_drift_fails_closed() {
    let response = dockerhub::DockerHubTagResponse::json(200, &payload(false)).expect("response");
    let mut service = service(response);
    let original_digest = service.registration().registration_digest().clone();
    let proposal = service.compile_proposal().expect("proposal");

    let revoked = service.revoke().expect("revoke");
    assert_eq!(revoked.previous_registration_digest, original_digest);
    assert_ne!(revoked.registration_digest, original_digest);
    assert!(matches!(
        service.read(),
        Err(dockerhub::DockerHubImageResultError::RegistrationInactive)
    ));

    service.restore_registration().expect("restore");
    assert_ne!(
        service.registration().registration_digest(),
        &original_digest
    );
    assert!(service.verify_proposal(&proposal).is_err());
    let restored = service.compile_proposal().expect("restored proposal");
    assert_ne!(restored.digest(), proposal.digest());

    let mut tampered = restored.clone();
    tampered.connected = true;
    assert!(service.verify_proposal(&tampered).is_err());
}

#[test]
fn mission_consumer_rejects_replay_and_keeps_outcome_authority_false() {
    let response = dockerhub::DockerHubTagResponse::json(200, &payload(false)).expect("response");
    let scope = scope_with(vec![platform("linux", "amd64")]);
    let provider = dockerhub::DockerHubProvider::new(
        scope,
        dockerhub::SecretReference::new("opaque-keyring-handle", 2).expect("secret"),
        dockerhub::FixtureDockerHubTransport::new(response),
    )
    .expect("provider");
    let mut consumer = dockerhub::MissionDockerHubImageConsumer::new(provider).expect("consumer");
    let proposal = consumer.compile_proposal().expect("proposal");
    let result = consumer.consume(&proposal).expect("consume");
    assert_eq!(
        result.state,
        dockerhub::MissionDockerHubImageResultState::DecisionReady
    );
    assert!(!result.native);
    assert!(!result.connected);
    assert!(!result.first_party);
    assert!(!result.provider_receipt);
    assert!(!result.adopts_outcome);
    assert!(!result.adopts_work_product);
    assert!(matches!(
        consumer.consume(&proposal),
        Err(dockerhub::MissionDockerHubImageConsumerError::ReplayDetected)
    ));
}

#[test]
fn declared_response_digest_tampering_is_not_adoptable() {
    let response = dockerhub::DockerHubTagResponse::json(200, &payload(false))
        .expect("response")
        .with_declared_digest(dockerhub::Digest::from_text("tampered"));
    let mut service = service(response);
    let proposal = service.compile_proposal().expect("proposal");
    assert_eq!(
        proposal.evidence.state,
        dockerhub::DockerHubEvidenceState::Tampered
    );
    assert!(
        service
            .verify(&proposal)
            .failures
            .contains(&dockerhub::DockerHubVerificationFailure::TamperedEvidence)
    );
}
