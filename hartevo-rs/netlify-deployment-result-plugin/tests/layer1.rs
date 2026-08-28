use std::fmt::Debug;

use hartevo_netlify_deployment_result_plugin as netlify;
use netlify::{
    BlockedEnvTransport, ConsentScope, Digest, FixtureTransport, MissionNetlifyDeploymentConsumer,
    NetlifyDeployFixture, NetlifyDeployPageFixture, NetlifyDeploymentError,
    NetlifyDeploymentEvidenceState, NetlifyDeploymentScope, NetlifyProvider, NetlifyResponse,
    NetlifyTransport, OpaqueCursor, PermissionSnapshot, Project, RecordingTransport,
    SecretReference, TransportProvenance, WorkProduct,
};

fn scope() -> NetlifyDeploymentScope {
    NetlifyDeploymentScope::new(
        "team-1",
        "site-1",
        "deploy-1",
        "main",
        "commit-1",
        "deploy-preview",
        Project::new("project-1", 2).expect("project"),
        netlify::Mission::new("mission-1", 3).expect("mission"),
        WorkProduct::new("work-product-1", 4).expect("work product"),
    )
    .expect("scope")
}

fn manifest_digest() -> Digest {
    Digest::from_text("bounded-file-manifest")
}

fn fixture(state: &str, commit: &str) -> NetlifyDeployFixture {
    let mut fixture = NetlifyDeployFixture::ready(
        "site-1",
        "deploy-1",
        "main",
        commit,
        "deploy-preview",
        &manifest_digest(),
    );
    state.clone_into(&mut fixture.state);
    fixture
}

fn page(fixture: NetlifyDeployFixture) -> NetlifyResponse {
    NetlifyResponse::json(
        200,
        &NetlifyDeployPageFixture {
            site_id: "site-1".to_owned(),
            deploys: vec![fixture],
        },
        None,
    )
    .expect("page response")
}

fn detail(fixture: &NetlifyDeployFixture) -> NetlifyResponse {
    NetlifyResponse::json(200, &fixture, None).expect("detail response")
}

fn service_from_responses(
    responses: impl IntoIterator<Item = NetlifyResponse>,
) -> netlify::NetlifyDeploymentService<RecordingTransport> {
    let scope = scope();
    let secret = SecretReference::personal_token("opaque-netlify-token", &scope, 7)
        .expect("opaque secret reference");
    let provider =
        NetlifyProvider::new(RecordingTransport::new(responses), scope, secret).expect("provider");
    netlify::NetlifyDeploymentService::register(
        provider,
        "registration-1",
        PermissionSnapshot::for_layer_one(2).expect("permissions"),
        ConsentScope::for_layer_one("consent-1", 1, 1_000).expect("consent"),
        1,
    )
    .expect("service")
}

fn ready_service() -> netlify::NetlifyDeploymentService<RecordingTransport> {
    let deployment = fixture("ready", "commit-1");
    service_from_responses([page(deployment.clone()), detail(&deployment)])
}

fn response_with_status(status: u16) -> NetlifyResponse {
    NetlifyResponse::new(status, b"{}".to_vec(), None)
}

#[test]
fn contract_and_layer_one_authority_are_machine_checked() {
    let document: serde_json::Value =
        serde_json::from_str(netlify::CONTRACT_JSON).expect("contract JSON");
    assert_eq!(document["schemaVersion"], netlify::CONTRACT_SCHEMA);
    assert_eq!(document["contractVersion"], netlify::CONTRACT_VERSION);
    assert_eq!(document["contractDigest"], netlify::CONTRACT_DIGEST);
    assert_eq!(netlify::contract_digest(), netlify::CONTRACT_DIGEST);
    assert_eq!(document["service"]["type"], "NetlifyDeploymentService");
    assert_eq!(document["provider"]["type"], "NetlifyProvider");
    assert_eq!(
        document["consumer"]["type"],
        "MissionNetlifyDeploymentConsumer"
    );
    assert_eq!(
        document["projection"]["deployUrl"],
        "non_verified_metadata_digest_only"
    );
    assert_eq!(
        document["allowlist"]["writes"].as_array().map(Vec::len),
        Some(0)
    );
    assert!(!netlify::Layer1Authority::connected());
    assert!(!netlify::Layer1Authority::native_provider());
    assert!(!netlify::Layer1Authority::first_party_provider());
    assert!(!netlify::Layer1Authority::outcome_authority());
}

#[test]
fn secret_reference_is_opaque_non_serializing_and_scope_bound() {
    let scope = scope();
    let secret = SecretReference::oauth("oauth-token-material", &scope, 1).expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("oauth-token-material"));
    assert_eq!(secret.scope_digest(), &scope.digest());
    assert_eq!(secret.kind(), netlify::SecretKind::OAuth2);
    assert!(secret.reference_digest().as_str().len() == 64);

    let permission = PermissionSnapshot::for_layer_one(1).expect("permission");
    let consent = ConsentScope::for_layer_one("consent", 1, 100).expect("consent");
    let provider = netlify::NetlifyProviderDefinition::default();
    let registration = netlify::NetlifyDeploymentRegistration::new(
        "registration",
        scope,
        secret,
        permission,
        consent,
        &provider,
        1,
    )
    .expect("registration");
    let serialized = serde_json::to_string(&registration).expect("redacted registration");
    assert!(!serialized.contains("oauth-token-material"));
    assert!(serialized.contains("secretReferenceDigest"));
}

#[test]
fn ready_state_is_a_bounded_preview_proposal_not_hosted_content_verification() {
    let mut service = ready_service();
    let evidence = service.read(100).expect("evidence");
    assert_eq!(evidence.state, NetlifyDeploymentEvidenceState::Ready);
    assert_eq!(
        evidence.preview_decision,
        netlify::NetlifyPreviewDecision::ReadyForReview
    );
    assert!(evidence.listing_complete);
    assert_eq!(evidence.list_pages, 1);
    assert_eq!(evidence.poll_attempts, 1);
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert!(!evidence.first_party);
    assert!(!evidence.content_verified);
    assert!(evidence.deployment.as_ref().is_some_and(|deployment| {
        deployment.deploy_url_digest.is_some() && !deployment.deploy_url_is_verified
    }));
    evidence.validate_integrity().expect("evidence integrity");

    let proposal = service
        .compile_proposal_from_evidence(evidence)
        .expect("proposal");
    let report = service
        .verify_proposal(&proposal)
        .expect("verification report");
    assert!(report.verified());
    assert!(report.ready_preview);
    assert!(!report.content_verified);
    assert!(!report.adoptable);

    let mut consumer = service.consumer().expect("Mission consumer");
    let result = consumer.consume(&proposal).expect("Mission projection");
    assert_eq!(result.disposition, netlify::ProposalDisposition::Ready);
    assert!(result.review_only);
    assert!(!result.content_verified);
    assert!(!result.can_be_adopted());
    let first = consumer.record(&proposal, "idempotency-1").expect("record");
    assert!(!first.replayed);
    let replay = consumer.record(&proposal, "idempotency-1").expect("replay");
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn requests_are_get_only_and_never_contain_the_opaque_secret_or_raw_cursor() {
    let mut service = ready_service();
    let _ = service.read(100).expect("read");
    let requests = service.provider().transport().requests();
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(netlify::NetlifyRequest::is_allowlisted));
    assert!(requests.iter().all(|request| request.method == "GET"));
    assert!(
        requests
            .iter()
            .all(|request| request.host == "https://api.netlify.com")
    );
    assert!(requests.iter().all(|request| {
        let encoded = serde_json::to_string(request).expect("request serializes");
        !encoded.contains("opaque-netlify-token")
    }));
}

#[test]
fn link_pagination_is_bounded_opaque_and_scope_fenced() {
    let mut first = fixture("ready", "commit-1");
    first.id = "other-deploy".to_owned();
    let first_response = NetlifyResponse::json(
        200,
        &NetlifyDeployPageFixture {
            site_id: "site-1".to_owned(),
            deploys: vec![first],
        },
        Some(
            "<https://api.netlify.com/api/v1/sites/site-1/deploys?cursor=page-2>; rel=\"next\""
                .to_owned(),
        ),
    )
    .expect("first page");
    let target = fixture("ready", "commit-1");
    let second_response = page(target.clone());
    let mut service = service_from_responses([first_response, second_response, detail(&target)]);
    let evidence = service.read(100).expect("paginated read");
    assert_eq!(evidence.state, NetlifyDeploymentEvidenceState::Ready);
    assert_eq!(evidence.list_pages, 2);
    let requests = service.provider().transport().requests();
    assert_eq!(
        requests[1].cursor_digest,
        Some(
            OpaqueCursor::from_token("page-2")
                .expect("cursor")
                .digest()
                .clone()
        )
    );
}

#[test]
fn pagination_loop_and_bound_are_partial_and_non_adoptable() {
    let target = fixture("ready", "commit-1");
    let loop_response = NetlifyResponse::json(
        200,
        &NetlifyDeployPageFixture {
            site_id: "site-1".to_owned(),
            deploys: vec![target.clone()],
        },
        Some(
            "<https://api.netlify.com/api/v1/sites/site-1/deploys?cursor=same>; rel=\"next\""
                .to_owned(),
        ),
    )
    .expect("loop response");
    let mut service = service_from_responses([loop_response.clone(), loop_response]);
    let evidence = service.read(100).expect("loop evidence");
    assert_eq!(evidence.state, NetlifyDeploymentEvidenceState::Partial);
    assert_eq!(
        evidence.preview_decision,
        netlify::NetlifyPreviewDecision::Blocked
    );
    assert!(!evidence.listing_complete);
    assert!(
        evidence
            .failure
            .as_ref()
            .is_some_and(|failure| { failure.category == "pagination_loop" })
    );
}

#[test]
fn scope_revision_and_commit_drift_fail_closed() {
    assert!(Project::new("project-1", 0).is_err());
    assert!(netlify::Mission::new("mission-1", 0).is_err());
    assert!(WorkProduct::new("work-product-1", 0).is_err());

    let mut stale = fixture("ready", "old-commit");
    stale.file_count = 4;
    let mut service = service_from_responses([page(stale.clone()), detail(&stale)]);
    let evidence = service.read(100).expect("stale evidence");
    assert_eq!(evidence.state, NetlifyDeploymentEvidenceState::StaleCommit);
    assert!(
        !evidence
            .preview_decision
            .eq(&netlify::NetlifyPreviewDecision::ReadyForReview)
    );
}

#[test]
fn site_and_deploy_mismatch_are_tampered_not_adopted() {
    let mut wrong_site = fixture("ready", "commit-1");
    let wrong_page = NetlifyResponse::json(
        200,
        &NetlifyDeployPageFixture {
            site_id: "site-other".to_owned(),
            deploys: vec![wrong_site.clone()],
        },
        None,
    )
    .expect("wrong site page");
    let mut service = service_from_responses([wrong_page]);
    let evidence = service.read(100).expect("mismatch evidence");
    assert_eq!(evidence.state, NetlifyDeploymentEvidenceState::Tampered);
    assert!(
        !evidence
            .preview_decision
            .eq(&netlify::NetlifyPreviewDecision::ReadyForReview)
    );

    wrong_site.site_id = "site-1".to_owned();
    wrong_site.id = "deploy-other".to_owned();
    let target = fixture("ready", "commit-1");
    let mut service = service_from_responses([page(target), detail(&wrong_site)]);
    let evidence = service.read(100).expect("wrong deploy detail evidence");
    assert_eq!(evidence.state, NetlifyDeploymentEvidenceState::Tampered);
}

#[test]
fn tampered_response_and_proposal_are_rejected() {
    let deployment = fixture("ready", "commit-1");
    let tampered_response =
        page(deployment.clone()).with_declared_response_digest(Digest::from_text("wrong"));
    let mut service = service_from_responses([tampered_response]);
    let evidence = service.read(100).expect("tampered response evidence");
    assert_eq!(evidence.state, NetlifyDeploymentEvidenceState::Tampered);

    let mut service = service_from_responses([page(deployment.clone()), detail(&deployment)]);
    let evidence = service.read(100).expect("ready evidence");
    let mut proposal = service
        .compile_proposal_from_evidence(evidence)
        .expect("proposal");
    proposal.connected = true;
    assert_eq!(
        service.verify_proposal(&proposal),
        Err(NetlifyDeploymentError::TamperedEvidence)
    );
}

#[test]
fn pending_poll_timeout_and_partial_state_are_bounded() {
    let pending = fixture("uploading", "commit-1");
    let responses = [
        page(pending.clone()),
        detail(&pending),
        page(pending.clone()),
        detail(&pending),
        page(pending.clone()),
        detail(&pending),
    ];
    let mut service = service_from_responses(responses);
    let evidence = service.read(100).expect("bounded polling evidence");
    assert_eq!(evidence.state, NetlifyDeploymentEvidenceState::Partial);
    assert_eq!(evidence.poll_attempts, 3);
    assert_eq!(
        evidence
            .failure
            .as_ref()
            .map(|failure| failure.category.as_str()),
        Some("poll_bound")
    );
}

#[test]
fn expiry_manifest_and_response_bounds_fail_closed() {
    let mut expired = fixture("ready", "commit-1");
    expired.expires_at = Some(100);
    let mut service = service_from_responses([page(expired.clone()), detail(&expired)]);
    assert_eq!(
        service.read(100).expect("expiry evidence").state,
        NetlifyDeploymentEvidenceState::Expired
    );

    let mut oversized_manifest = fixture("ready", "commit-1");
    oversized_manifest.file_count = netlify::MAX_MANIFEST_FILES + 1;
    let mut service = service_from_responses([page(oversized_manifest)]);
    assert_eq!(
        service.read(100).expect("manifest evidence").state,
        NetlifyDeploymentEvidenceState::Tampered
    );

    let oversized = NetlifyResponse::new(200, vec![b'x'; netlify::MAX_RESPONSE_BYTES + 1], None);
    let mut service = service_from_responses([oversized]);
    assert_eq!(
        service.read(100).expect("response evidence").state,
        NetlifyDeploymentEvidenceState::Tampered
    );
}

#[test]
fn access_loss_throttle_timeout_and_blocked_env_never_claim_native() {
    for (status, expected) in [
        (401, NetlifyDeploymentEvidenceState::AccessLoss),
        (403, NetlifyDeploymentEvidenceState::AccessLoss),
        (404, NetlifyDeploymentEvidenceState::NotFound),
        (409, NetlifyDeploymentEvidenceState::Conflict),
        (429, NetlifyDeploymentEvidenceState::Throttled),
        (500, NetlifyDeploymentEvidenceState::ProviderUnknown),
    ] {
        let mut service = service_from_responses([response_with_status(status)]);
        let evidence = service.read(100).expect("status evidence");
        assert_eq!(evidence.state, expected);
        assert!(!evidence.connected);
        assert!(!evidence.native);
        assert!(!evidence.first_party);
        assert_eq!(evidence.provenance, TransportProvenance::Recording);
    }

    let mut timed_out = service_from_responses(Vec::<NetlifyResponse>::new());
    let evidence = timed_out.read(100).expect("timeout evidence");
    assert_eq!(evidence.state, NetlifyDeploymentEvidenceState::Timeout);
    assert_eq!(
        evidence
            .failure
            .as_ref()
            .map(|failure| failure.category.as_str()),
        Some("timeout")
    );
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert!(!evidence.first_party);

    let scope = scope();
    let secret = SecretReference::new("opaque", &scope, 1).expect("secret");
    let provider = NetlifyProvider::new(BlockedEnvTransport, scope, secret).expect("provider");
    let mut service = netlify::NetlifyDeploymentService::register(
        provider,
        "blocked-registration",
        PermissionSnapshot::for_layer_one(1).expect("permissions"),
        ConsentScope::for_layer_one("consent", 1, 1_000).expect("consent"),
        1,
    )
    .expect("service");
    let evidence = service.read(100).expect("blocked env evidence");
    assert_eq!(
        evidence.state,
        NetlifyDeploymentEvidenceState::ProviderUnknown
    );
    assert_eq!(evidence.provenance, TransportProvenance::BlockedEnv);
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert!(!evidence.first_party);
}

#[test]
fn registration_revision_digest_and_revocation_are_reversible_but_fail_closed() {
    let mut service = ready_service();
    let before = service.registration().registration_digest().clone();
    let revoked = service.revoke().expect("revoke");
    assert_eq!(revoked.previous_status, netlify::RegistrationStatus::Active);
    assert_eq!(revoked.new_status, netlify::RegistrationStatus::Revoked);
    assert_eq!(service.registration().registration_revision(), 2);
    assert_ne!(before, *service.registration().registration_digest());
    assert_eq!(
        service.read(100),
        Err(NetlifyDeploymentError::RegistrationInactive)
    );
    assert_eq!(
        service.revoke(),
        Err(NetlifyDeploymentError::AlreadyRevoked)
    );

    let restored = service.restore_registration().expect("restore");
    assert_eq!(restored.new_status, netlify::RegistrationStatus::Active);
    assert_eq!(service.registration().registration_revision(), 3);
    let reversed = service.reverse().expect("reverse");
    assert_eq!(reversed.new_status, netlify::RegistrationStatus::Reversed);
    assert_eq!(
        service.read(100),
        Err(NetlifyDeploymentError::RegistrationInactive)
    );
    assert_eq!(
        service.restore_registration(),
        Err(NetlifyDeploymentError::RegistrationReversed)
    );
}

#[test]
fn deterministic_fixture_and_loopback_provenance_are_always_non_native() {
    let response = response_with_status(200);
    let transports: Vec<Box<dyn NetlifyTransport>> = vec![
        Box::new(FixtureTransport::new(response.clone())),
        Box::new(netlify::LoopbackTransport::new(response)),
    ];
    for transport in transports {
        let provenance = transport.provenance();
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
    }
}

#[test]
fn mission_consumer_rejects_scope_drift_and_replay_conflicts() {
    let mut service = ready_service();
    let evidence = service.read(100).expect("evidence");
    let proposal = service
        .compile_proposal_from_evidence(evidence)
        .expect("proposal");
    let mut consumer =
        MissionNetlifyDeploymentConsumer::new(scope(), service.registration().clone())
            .expect("consumer");
    let mut drifted = proposal.clone();
    drifted.scope_digest = Digest::from_text("drifted-scope");
    assert_eq!(
        consumer.consume(&drifted),
        Err(NetlifyDeploymentError::TamperedEvidence)
    );

    let first = consumer
        .record(&proposal, "same-key")
        .expect("first record");
    assert!(!first.replayed);
    let second_evidence = service.read(100).expect("second evidence");
    let conflicting = service
        .compile_proposal_from_evidence(second_evidence)
        .expect("second proposal");
    assert_eq!(
        consumer.record(&conflicting, "same-key"),
        Err(NetlifyDeploymentError::RecordingConflict)
    );
}

#[allow(dead_code)]
fn _assert_debug<T: Debug>() {}
