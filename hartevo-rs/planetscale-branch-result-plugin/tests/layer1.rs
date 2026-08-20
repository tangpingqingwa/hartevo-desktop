use hartevo_planetscale_branch_result_plugin as planetscale;
use serde_json::json;

fn scope() -> planetscale::PlanetScaleScope {
    planetscale::PlanetScaleScope::new(
        planetscale::OrganizationId::new("org-1").expect("organization"),
        planetscale::DatabaseId::new("db-1").expect("database"),
        planetscale::BranchId::new("branch-1").expect("branch"),
        planetscale::DeployRequestId::new("deploy-1").expect("deploy request"),
        planetscale::SchemaId::new("schema-1").expect("schema"),
        planetscale::ProjectBinding::new("project-1", 7).expect("project"),
        planetscale::MissionBinding::new("mission-1", 8).expect("mission"),
        planetscale::WorkProductBinding::new("work-product-1", 9).expect("work product"),
        planetscale::ConsentBinding::new(
            planetscale::ConsentId::new("consent-1").expect("consent"),
            4,
            planetscale::ConsentAction::InspectBranchDeployPosture,
        )
        .expect("consent binding"),
    )
    .expect("scope")
}

fn secret(scope: &planetscale::PlanetScaleScope) -> planetscale::SecretReference {
    planetscale::SecretReference::for_scope(scope, "pscale-service-token-handle", 11)
        .expect("secret reference")
}

fn service_with_fixture(
    read: planetscale::PostureRead,
) -> planetscale::PlanetScaleBranchResultService<planetscale::FixturePlanetScaleTransport> {
    let scope = scope();
    let observation =
        planetscale::PostureObservation::fixture(scope.clone(), read).expect("fixture observation");
    let provider = planetscale::PlanetScaleProvider::new(
        scope.clone(),
        secret(&scope),
        planetscale::FixturePlanetScaleTransport::new(
            planetscale::PostureResponse::from_observation(observation),
        ),
    )
    .expect("provider");
    planetscale::PlanetScaleBranchResultService::new(provider).expect("service")
}

fn key(value: &str) -> planetscale::IdempotencyKey {
    planetscale::IdempotencyKey::new(value).expect("idempotency key")
}

#[test]
fn exact_scope_revision_consent_and_secret_are_digest_fenced() {
    let scope = scope();
    assert_eq!(scope.revision_fence().project_revision.get(), 7);
    assert_eq!(scope.revision_fence().mission_revision.get(), 8);
    assert_eq!(scope.revision_fence().work_product_revision.get(), 9);
    assert_eq!(scope.consent.revision.get(), 4);

    let secret = secret(&scope);
    let debug = format!("{secret:?}");
    assert!(!debug.contains("pscale-service-token-handle"));
    assert!(debug.contains("reference_digest"));

    let wrong_scope = planetscale::PlanetScaleScope::new(
        scope.organization_id.clone(),
        scope.database_id.clone(),
        planetscale::BranchId::new("other-branch").expect("other branch"),
        scope.deploy_request_id.clone(),
        scope.schema_id.clone(),
        scope.project.clone(),
        scope.mission.clone(),
        scope.work_product.clone(),
        scope.consent.clone(),
    )
    .expect("wrong scope");
    assert!(matches!(
        secret.validate_for(&wrong_scope),
        Err(planetscale::PlanetScaleBranchResultError::ScopeMismatch { .. })
    ));
}

#[test]
fn bounded_fixture_proposal_record_verify_and_mission_projection_are_non_native() {
    let mut service = service_with_fixture(planetscale::PostureRead::BranchDeploySchema);
    let proposal = service
        .propose_posture(
            planetscale::PostureRead::BranchDeploySchema,
            25,
            &key("read-1"),
        )
        .expect("proposal");
    assert!(proposal.proposal_only);
    assert!(!proposal.connected && !proposal.native);
    assert_eq!(proposal.request.page_size, 25);

    let evidence = service.read(&proposal).expect("fixture evidence");
    assert_eq!(evidence.state, planetscale::EvidenceState::Complete);
    assert_eq!(
        evidence.branch_status,
        Some(planetscale::BranchStatus::Ready)
    );
    assert_eq!(
        evidence.deploy_status,
        Some(planetscale::DeployStatus::Succeeded)
    );
    assert_eq!(
        evidence.schema_status,
        Some(planetscale::SchemaStatus::Available)
    );
    assert!(!evidence.connected && !evidence.native);

    let receipt = service.record(&proposal, &evidence).expect("record");
    assert!(receipt.independent_record);
    let verification = service
        .verify(&proposal, &evidence, &receipt)
        .expect("verify");
    assert!(verification.is_verified());

    let consumer =
        planetscale::MissionPlanetScaleBranchConsumer::new(service).expect("Mission consumer");
    let result = consumer
        .consume(&proposal, &evidence, &receipt)
        .expect("Mission projection");
    assert_eq!(
        result.state,
        planetscale::MissionResultState::PendingDecision
    );
    assert!(!result.connected && !result.native && !result.adopts_work_product);
}

#[test]
fn serialized_proposal_evidence_and_receipt_are_redacted_and_deterministic() {
    let mut service = service_with_fixture(planetscale::PostureRead::Branch);
    let proposal = service
        .propose_posture(planetscale::PostureRead::Branch, 10, &key("redaction-1"))
        .expect("proposal");
    let evidence = service.read(&proposal).expect("evidence");
    let receipt = service.record(&proposal, &evidence).expect("receipt");

    let serialized = serde_json::to_string(&json!({
        "proposal": &proposal,
        "evidence": &evidence,
        "receipt": &receipt,
    }))
    .expect("safe JSON");
    assert!(!serialized.contains("pscale-service-token-handle"));
    assert!(!serialized.contains("read-1"));
    assert!(!serialized.contains("private-api-body"));
    assert!(!serialized.contains("rawSql"));

    let second_proposal = service
        .propose_posture(planetscale::PostureRead::Branch, 10, &key("redaction-1"))
        .expect("same deterministic proposal");
    assert_eq!(proposal.proposal_digest, second_proposal.proposal_digest);
    let second_evidence = service.read(&second_proposal).expect("second evidence");
    assert_eq!(evidence.evidence_digest, second_evidence.evidence_digest);
    let second_receipt = service
        .record(&second_proposal, &second_evidence)
        .expect("idempotent record");
    assert_eq!(receipt, second_receipt);
}

#[test]
fn cursor_and_idempotency_fences_reject_conflicting_replays() {
    let scope = scope();
    let observation =
        planetscale::PostureObservation::fixture(scope.clone(), planetscale::PostureRead::Deploy)
            .expect("observation");
    let provider = planetscale::PlanetScaleProvider::new(
        scope.clone(),
        secret(&scope),
        planetscale::RecordingPlanetScaleTransport::new(
            planetscale::PostureResponse::from_observation(observation),
        ),
    )
    .expect("provider");
    let mut service = planetscale::PlanetScaleBranchResultService::new(provider).expect("service");
    let cursor = planetscale::PageCursor::new("opaque-next-page-token").expect("cursor");
    let proposal = service
        .compile_proposal(
            planetscale::PostureRead::Deploy,
            100,
            Some(&cursor),
            &key("replay-key"),
            planetscale::ProposalIntent::InspectBranchDeployPosture,
        )
        .expect("cursor proposal");
    assert!(proposal.request.cursor_digest.is_some());
    assert!(
        !serde_json::to_string(&proposal)
            .expect("proposal JSON")
            .contains("opaque-next-page-token")
    );
    let evidence = service.read(&proposal).expect("evidence");
    service.record(&proposal, &evidence).expect("first record");

    let conflicting = service
        .propose_posture(planetscale::PostureRead::Schema, 100, &key("replay-key"))
        .expect("conflicting proposal compiles");
    let conflicting_evidence = service.read(&conflicting).expect("conflicting evidence");
    assert!(matches!(
        service.record(&conflicting, &conflicting_evidence),
        Err(planetscale::PlanetScaleBranchResultError::Provider(
            planetscale::PlanetScaleProviderError::DuplicateIdempotency
        ))
    ));
}

#[test]
fn provider_statuses_fail_closed_into_typed_evidence() {
    let cases = [
        (
            403,
            planetscale::EvidenceState::Denied,
            planetscale::FailureKind::PermissionDenied,
        ),
        (
            404,
            planetscale::EvidenceState::AccessLost,
            planetscale::FailureKind::NotFound,
        ),
        (
            409,
            planetscale::EvidenceState::Stale,
            planetscale::FailureKind::Conflict,
        ),
        (
            429,
            planetscale::EvidenceState::RateLimited,
            planetscale::FailureKind::RateLimited,
        ),
        (
            500,
            planetscale::EvidenceState::ProviderUnknown,
            planetscale::FailureKind::ProviderUnknown,
        ),
    ];
    for (status, expected_state, expected_failure) in cases {
        let scope = scope();
        let provider = planetscale::PlanetScaleProvider::new(
            scope.clone(),
            secret(&scope),
            planetscale::RecordingPlanetScaleTransport::new(planetscale::PostureResponse::status(
                status,
                planetscale::EvidenceSource::Recording,
            )),
        )
        .expect("provider");
        let mut service =
            planetscale::PlanetScaleBranchResultService::new(provider).expect("service");
        let proposal = service
            .propose_posture(planetscale::PostureRead::Branch, 1, &key("status-key"))
            .expect("proposal");
        let evidence = service.read(&proposal).expect("typed evidence");
        assert_eq!(evidence.state, expected_state);
        assert_eq!(evidence.failure, Some(expected_failure));
        assert!(!evidence.connected && !evidence.native);
    }
}

#[test]
fn all_fixture_modes_and_blocked_env_never_claim_connected_or_native() {
    let scope = scope();
    for mode in [
        planetscale::TransportMode::Fixture,
        planetscale::TransportMode::Recording,
        planetscale::TransportMode::Fake,
        planetscale::TransportMode::Loopback,
        planetscale::TransportMode::BlockedEnv,
    ] {
        assert!(!mode.is_native());
        assert!(!mode.evidence_source().is_native());
    }

    let provider = planetscale::PlanetScaleProvider::new(
        scope.clone(),
        secret(&scope),
        planetscale::BlockedEnvPlanetScaleTransport,
    )
    .expect("blocked provider");
    let mut service =
        planetscale::PlanetScaleBranchResultService::new(provider).expect("blocked service");
    let proposal = service
        .propose_posture(planetscale::PostureRead::Schema, 1, &key("blocked-key"))
        .expect("blocked proposal");
    let evidence = service.read(&proposal).expect("blocked evidence");
    assert_eq!(evidence.state, planetscale::EvidenceState::AccessLost);
    assert_eq!(evidence.failure, Some(planetscale::FailureKind::BlockedEnv));
    assert_eq!(evidence.source, planetscale::EvidenceSource::BlockedEnv);
    assert!(!evidence.connected && !evidence.native);
}

#[test]
fn tamper_and_revision_drift_are_rejected_before_verification() {
    let mut service = service_with_fixture(planetscale::PostureRead::Deploy);
    let mut proposal = service
        .propose_posture(planetscale::PostureRead::Deploy, 5, &key("tamper-key"))
        .expect("proposal");
    let original_digest = proposal.proposal_digest.clone();
    proposal.proposal_digest = planetscale::sha256_digest(b"tampered-proposal");
    assert!(matches!(
        service.read(&proposal),
        Err(planetscale::PlanetScaleBranchResultError::DigestMismatch { .. })
    ));
    proposal.proposal_digest = original_digest;
    let evidence = service.read(&proposal).expect("evidence");
    let mut tampered = evidence.clone();
    tampered.response_bytes = planetscale::MAX_RESPONSE_BYTES;
    assert!(matches!(
        service.record(&proposal, &tampered),
        Err(
            planetscale::PlanetScaleBranchResultError::DigestMismatch { .. }
                | planetscale::PlanetScaleBranchResultError::ReceiptMismatch { .. },
        )
    ));

    let mut drifted_scope = scope();
    drifted_scope.project = planetscale::ProjectBinding::new("project-1", 8).expect("drift");
    assert_ne!(drifted_scope.digest(), service.scope().digest());
    let drifted_secret =
        planetscale::SecretReference::for_scope(&drifted_scope, "pscale-service-token-handle", 11)
            .expect("drifted secret");
    assert!(drifted_secret.validate_for(service.scope()).is_err());
}

#[test]
fn registration_is_reversible_and_revocation_blocks_new_proposals() {
    let mut service = service_with_fixture(planetscale::PostureRead::Branch);
    let receipt = service
        .registration_receipt()
        .expect("registration receipt");
    assert!(receipt.active);
    let proposal = service
        .propose_posture(planetscale::PostureRead::Branch, 1, &key("revoke-key"))
        .expect("proposal");
    service.revoke().expect("revoke");
    assert!(matches!(
        service.propose_posture(planetscale::PostureRead::Branch, 1, &key("new-key")),
        Err(planetscale::PlanetScaleBranchResultError::RegistrationRevoked)
    ));
    let revoked_evidence = service.read(&proposal).expect("revoked evidence");
    assert_eq!(revoked_evidence.state, planetscale::EvidenceState::Revoked);
    service.restore().expect("restore");
    let restored = service
        .propose_posture(planetscale::PostureRead::Branch, 1, &key("restored-key"))
        .expect("restored proposal");
    assert_ne!(restored.proposal_digest, proposal.proposal_digest);
}
