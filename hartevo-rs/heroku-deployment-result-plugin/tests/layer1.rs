use hartevo_heroku_deployment_result_plugin as heroku;
use heroku::{
    ConsentScope, HerokuAppFixture, HerokuBuildFixture, HerokuDeploymentError,
    HerokuDeploymentResultService, HerokuDeploymentScope, HerokuDeploymentState, HerokuDynoFixture,
    HerokuProvider, HerokuReleaseFixture, HerokuReleasePageFixture, HerokuResponse,
    HerokuSlugFixture, HerokuTransport, Layer1Authority, Mission, MissionHerokuDeploymentConsumer,
    PermissionSnapshot, Project, RecordingTransport, SecretKind, SecretReference, WorkProduct,
};

fn make_scope() -> HerokuDeploymentScope {
    HerokuDeploymentScope::new(
        "account-1",
        "team-1",
        "app-1",
        "build-1",
        "release-1",
        "slug-1",
        "dyno-1",
        "us",
        "commit-1",
        Project::new("project-1", 1).expect("project"),
        Mission::new("mission-1", 1).expect("mission"),
        WorkProduct::new("work-product-1", 1).expect("work product"),
    )
    .expect("scope")
}

fn ready_responses(scope: &HerokuDeploymentScope) -> Vec<HerokuResponse> {
    vec![
        HerokuResponse::json(200, &HerokuAppFixture::released(scope)).expect("app response"),
        HerokuResponse::json(200, &HerokuBuildFixture::succeeded(scope)).expect("build response"),
        HerokuResponse::json(200, &HerokuReleasePageFixture::released(scope))
            .expect("release response"),
        HerokuResponse::json(200, &HerokuSlugFixture::ready(scope)).expect("slug response"),
        HerokuResponse::json(200, &HerokuDynoFixture::up(scope)).expect("dyno response"),
    ]
}

fn ready_service(
    scope: &HerokuDeploymentScope,
) -> HerokuDeploymentResultService<RecordingTransport> {
    let secret = SecretReference::new("opaque-heroku-oauth-reference", scope, 1, SecretKind::OAuth)
        .expect("secret reference");
    let provider = HerokuProvider::new(
        RecordingTransport::new(ready_responses(scope)),
        scope.clone(),
        secret,
    )
    .expect("provider");
    HerokuDeploymentResultService::register(
        provider,
        "registration-1",
        PermissionSnapshot::for_layer_one(1).expect("permissions"),
        ConsentScope::for_layer_one("consent-1", 1, 100).expect("consent"),
        1,
    )
    .expect("service")
}

#[test]
fn contract_and_layer_one_authority_are_machine_checked() {
    let contract: serde_json::Value =
        serde_json::from_str(heroku::CONTRACT_JSON).expect("contract");
    assert_eq!(contract["contractDigest"], heroku::CONTRACT_DIGEST);
    assert_eq!(heroku::contract_digest(), heroku::CONTRACT_DIGEST);
    assert_eq!(contract["service"]["type"], "HerokuDeploymentResultService");
    assert_eq!(contract["provider"]["type"], "HerokuProvider");
    assert_eq!(
        contract["consumer"]["type"],
        "MissionHerokuDeploymentConsumer"
    );
    assert_eq!(
        contract["allowlist"]["writes"].as_array().map(Vec::len),
        Some(0)
    );
    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native_provider());
    assert!(!Layer1Authority::first_party_provider());
    assert!(!Layer1Authority::external_writes());
}

#[test]
fn scope_revision_permissions_and_secret_reference_are_fenced_and_redacted() {
    assert!(Project::new("project", 0).is_err());
    assert!(Mission::new("mission", 0).is_err());
    assert!(WorkProduct::new("work-product", 0).is_err());
    assert!(PermissionSnapshot::new(0, ["heroku:apps.read"]).is_err());

    let scope = make_scope();
    let secret = SecretReference::new(
        "do-not-leak-heroku-oauth-token",
        &scope,
        1,
        SecretKind::Token,
    )
    .expect("secret");
    let debug = format!("{secret:?}");
    let encoded = serde_json::to_string(&secret).expect("redacted secret");
    assert!(!debug.contains("do-not-leak-heroku-oauth-token"));
    assert!(!encoded.contains("do-not-leak-heroku-oauth-token"));
    assert!(encoded.contains("referenceDigest"));
    assert_eq!(secret.scope_digest(), &scope.digest());
    assert_eq!(secret.kind(), SecretKind::Token);

    let other_app = heroku::Identifier::new("other-app").expect("other app");
    assert!(
        scope
            .clone()
            .with_allowlists(
                [other_app],
                scope.build_allowlist().clone(),
                scope.release_allowlist().clone(),
                scope.slug_allowlist().clone(),
                scope.dyno_allowlist().clone(),
            )
            .is_err()
    );
}

#[test]
fn released_flow_is_bounded_digest_bound_and_mission_review_only() {
    let scope = make_scope();
    let mut service = ready_service(&scope);
    let evidence = service.read(10).expect("evidence");
    assert_eq!(evidence.state, HerokuDeploymentState::Released);
    assert_eq!(evidence.page_count, 1);
    assert!(evidence.listing_complete);
    assert!(evidence.app.is_some());
    assert!(evidence.build.is_some());
    assert!(evidence.release.is_some());
    assert!(evidence.slug.is_some());
    assert!(evidence.dyno.is_some());
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert!(!evidence.first_party);
    evidence.validate_integrity().expect("evidence integrity");

    let proposal = service
        .compile_proposal_from_evidence(evidence)
        .expect("proposal");
    let verification = service.verify_proposal(&proposal).expect("verification");
    assert!(verification.verified());
    assert!(!verification.can_be_adopted());
    let receipt = service
        .record_observation(&proposal, "observation-1", 10)
        .expect("receipt");
    assert!(!receipt.replayed);
    receipt.validate_integrity().expect("receipt integrity");
    let replay = service
        .record_observation(&proposal, "observation-1", 11)
        .expect("replay");
    assert!(replay.replayed);
    assert!(!replay.durable_provider_receipt);

    let consumer =
        MissionHerokuDeploymentConsumer::new(scope.clone(), service.registration().clone())
            .expect("consumer");
    let result = consumer.consume(&proposal).expect("Mission result");
    assert!(result.review_only);
    assert!(!result.can_be_adopted);
    result.validate_integrity().expect("Mission integrity");
}

#[test]
fn fixture_fake_loopback_and_blocked_env_never_claim_connected_or_native() {
    let scope = make_scope();
    let response = HerokuResponse::new(200, b"{}".to_vec());
    let transports: Vec<Box<dyn HerokuTransport>> = vec![
        Box::new(heroku::FixtureTransport::new(response.clone())),
        Box::new(heroku::FakeTransport::new(response.clone())),
        Box::new(heroku::LoopbackTransport::new(response)),
        Box::new(heroku::BlockedEnvTransport),
    ];
    for transport in transports {
        let provenance = transport.provenance();
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
        assert!(!provenance.provider_receipt());
    }

    let secret = SecretReference::oauth("blocked-oauth-ref", &scope, 1).expect("secret");
    let provider = HerokuProvider::new(heroku::BlockedEnvTransport, scope.clone(), secret)
        .expect("blocked provider");
    let mut service = HerokuDeploymentResultService::register(
        provider,
        "blocked-registration",
        PermissionSnapshot::for_layer_one(1).expect("permissions"),
        ConsentScope::for_layer_one("consent-1", 1, 100).expect("consent"),
        1,
    )
    .expect("service");
    let evidence = service.read(10).expect("blocked evidence");
    assert_eq!(evidence.state, HerokuDeploymentState::ProviderUnknown);
    assert_eq!(evidence.provenance, heroku::ProviderProvenance::BlockedEnv);
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert!(!evidence.first_party);
}

#[test]
fn typed_building_released_failed_and_unknown_states_are_projected() {
    for (build_status, release_status, expected) in [
        ("building", "released", HerokuDeploymentState::Building),
        ("succeeded", "failed", HerokuDeploymentState::Failed),
        ("mystery", "released", HerokuDeploymentState::Unknown),
    ] {
        let scope = make_scope();
        let mut build = HerokuBuildFixture::succeeded(&scope);
        build.status = build_status.to_owned();
        let mut release = HerokuReleaseFixture::released(&scope);
        release.status = release_status.to_owned();
        let release_page = HerokuReleasePageFixture {
            app_id: scope.app_id().as_str().to_owned(),
            releases: vec![release],
            next_cursor: None,
        };
        let responses = vec![
            HerokuResponse::json(200, &HerokuAppFixture::released(&scope)).expect("app"),
            HerokuResponse::json(200, &build).expect("build"),
            HerokuResponse::json(200, &release_page).expect("release"),
            HerokuResponse::json(200, &HerokuSlugFixture::ready(&scope)).expect("slug"),
            HerokuResponse::json(200, &HerokuDynoFixture::up(&scope)).expect("dyno"),
        ];
        let secret = SecretReference::token("status-token", &scope, 1).expect("secret");
        let provider =
            HerokuProvider::new(RecordingTransport::new(responses), scope.clone(), secret)
                .expect("provider");
        let mut service = HerokuDeploymentResultService::register(
            provider,
            "status-registration",
            PermissionSnapshot::for_layer_one(1).expect("permissions"),
            ConsentScope::for_layer_one("consent-1", 1, 100).expect("consent"),
            1,
        )
        .expect("service");
        assert_eq!(service.read(10).expect("state").state, expected);
    }
}

#[test]
fn pagination_rate_limit_partial_and_fail_closed_paths_are_typed() {
    let scope = make_scope();
    let mut first_release = HerokuReleaseFixture::released(&scope);
    first_release.id = "other-release".to_owned();
    let first_page = HerokuReleasePageFixture {
        app_id: scope.app_id().as_str().to_owned(),
        releases: vec![first_release],
        next_cursor: Some("opaque-page-2".to_owned()),
    };
    let second_page = HerokuReleasePageFixture::released(&scope);
    let responses = vec![
        HerokuResponse::json(200, &HerokuAppFixture::released(&scope)).expect("app"),
        HerokuResponse::json(200, &HerokuBuildFixture::succeeded(&scope)).expect("build"),
        HerokuResponse::json(200, &first_page).expect("page one"),
        HerokuResponse::json(200, &second_page).expect("page two"),
        HerokuResponse::json(200, &HerokuSlugFixture::ready(&scope)).expect("slug"),
        HerokuResponse::json(200, &HerokuDynoFixture::up(&scope)).expect("dyno"),
    ];
    let secret = SecretReference::oauth("pagination-oauth", &scope, 1).expect("secret");
    let provider = HerokuProvider::new(RecordingTransport::new(responses), scope.clone(), secret)
        .expect("provider");
    let mut service = HerokuDeploymentResultService::register(
        provider,
        "pagination-registration",
        PermissionSnapshot::for_layer_one(1).expect("permissions"),
        ConsentScope::for_layer_one("consent-1", 1, 100).expect("consent"),
        1,
    )
    .expect("service");
    let evidence = service.read(10).expect("paginated evidence");
    assert_eq!(evidence.state, HerokuDeploymentState::Released);
    assert_eq!(evidence.page_count, 2);
    assert_eq!(evidence.cursor_digests.len(), 1);

    let rate_scope = make_scope();
    let rate_limited = vec![
        HerokuResponse::json(200, &HerokuAppFixture::released(&rate_scope)).expect("app"),
        HerokuResponse::json(200, &HerokuBuildFixture::succeeded(&rate_scope)).expect("build"),
        HerokuResponse::new(429, b"rate limit body is not evidence".to_vec()).with_retry_after(120),
        HerokuResponse::json(200, &HerokuReleasePageFixture::released(&rate_scope))
            .expect("release"),
        HerokuResponse::json(200, &HerokuSlugFixture::ready(&rate_scope)).expect("slug"),
        HerokuResponse::json(200, &HerokuDynoFixture::up(&rate_scope)).expect("dyno"),
    ];
    let secret = SecretReference::oauth("rate-limit-oauth", &rate_scope, 1).expect("secret");
    let provider = HerokuProvider::new(
        RecordingTransport::new(rate_limited),
        rate_scope.clone(),
        secret,
    )
    .expect("provider");
    let mut service = HerokuDeploymentResultService::register(
        provider,
        "rate-registration",
        PermissionSnapshot::for_layer_one(1).expect("permissions"),
        ConsentScope::for_layer_one("consent-1", 1, 100).expect("consent"),
        1,
    )
    .expect("service");
    let evidence = service.read(10).expect("rate-limited retry");
    assert_eq!(evidence.state, HerokuDeploymentState::Released);
    assert_eq!(evidence.backoff.expect("backoff").retry_after_seconds, 60);
    assert_eq!(service.provider().transport().requests().len(), 6);

    let scope = make_scope();
    let secret = SecretReference::token("partial-token", &scope, 1).expect("secret");
    let provider = HerokuProvider::new(
        RecordingTransport::new(vec![HerokuResponse::new(206, b"partial".to_vec())]),
        scope.clone(),
        secret,
    )
    .expect("provider");
    let mut service = HerokuDeploymentResultService::register(
        provider,
        "partial-registration",
        PermissionSnapshot::for_layer_one(1).expect("permissions"),
        ConsentScope::for_layer_one("consent-1", 1, 100).expect("consent"),
        1,
    )
    .expect("service");
    assert_eq!(
        service.read(10).expect("partial evidence").state,
        HerokuDeploymentState::Partial
    );
}

#[test]
fn tamper_revision_replay_and_registration_revocation_fail_closed() {
    let scope = make_scope();
    let mut service = ready_service(&scope);
    let evidence = service.read(10).expect("evidence");
    let mut tampered = evidence.clone();
    tampered.state = HerokuDeploymentState::Failed;
    assert_eq!(
        tampered.validate_integrity().expect_err("tamper"),
        HerokuDeploymentError::TamperedEvidence
    );

    let proposal = service
        .compile_proposal_from_evidence(evidence)
        .expect("proposal");
    let mut request = heroku::HerokuReadRequest::new(
        &scope,
        service.registration().registration_digest().clone(),
        service.registration().permission_digest().clone(),
        service.registration().consent_digest().clone(),
    );
    request.project_revision = heroku::Revision::new(2).expect("revision");
    assert_eq!(
        service
            .read_with_fence(&request, 10)
            .expect_err("stale revision"),
        HerokuDeploymentError::StaleRevision
    );

    let conflict = service.record_observation(&proposal, "same-key", 10);
    assert!(conflict.is_ok());
    let mut next_app = HerokuAppFixture::released(&scope);
    next_app.updated_at = "fixture-app-updated-again".to_owned();
    let next_responses = vec![
        HerokuResponse::json(200, &next_app).expect("next app"),
        HerokuResponse::json(200, &HerokuBuildFixture::succeeded(&scope)).expect("next build"),
        HerokuResponse::json(200, &HerokuReleasePageFixture::released(&scope))
            .expect("next release"),
        HerokuResponse::json(200, &HerokuSlugFixture::ready(&scope)).expect("next slug"),
        HerokuResponse::json(200, &HerokuDynoFixture::up(&scope)).expect("next dyno"),
    ];
    for response in next_responses {
        service.provider().transport().push_response(response);
    }
    let second_proposal = service.compile_proposal(10).expect("second proposal");
    assert_eq!(
        service
            .record_observation(&second_proposal, "same-key", 10)
            .expect_err("idempotency conflict"),
        HerokuDeploymentError::RecordingConflict
    );

    let transition = service.revoke_registration().expect("revoke");
    assert_eq!(transition.to, heroku::RegistrationStatus::Revoked);
    assert_eq!(
        service.read(10).expect_err("revoked read"),
        HerokuDeploymentError::RegistrationInactive
    );
    service.restore_registration().expect("restore");
    service.reverse_registration().expect("reverse");
    assert_eq!(
        service
            .restore_registration()
            .expect_err("terminal reverse"),
        HerokuDeploymentError::RegistrationReversed
    );
    assert_eq!(
        service
            .provider()
            .reject_write("release_promote")
            .expect_err("write boundary"),
        HerokuDeploymentError::MutationForbidden {
            operation: "release_promote"
        }
    );
}

#[test]
fn response_digest_tamper_and_request_redaction_are_enforced() {
    let scope = make_scope();
    let tampered_response = HerokuResponse::new(200, b"{}".to_vec())
        .with_declared_response_digest(heroku::Digest::from_text("different-body"));
    let secret = SecretReference::oauth("tamper-oauth", &scope, 1).expect("secret");
    let provider = HerokuProvider::new(
        RecordingTransport::new(vec![tampered_response]),
        scope.clone(),
        secret,
    )
    .expect("provider");
    let mut service = HerokuDeploymentResultService::register(
        provider,
        "tamper-registration",
        PermissionSnapshot::for_layer_one(1).expect("permissions"),
        ConsentScope::for_layer_one("consent-1", 1, 100).expect("consent"),
        1,
    )
    .expect("service");
    let evidence = service.read(10).expect("typed response tamper");
    assert_eq!(evidence.state, HerokuDeploymentState::Tampered);

    let request_scope = make_scope();
    let mut first_page = HerokuReleasePageFixture::released(&request_scope);
    first_page.releases[0].id = "other-release".to_owned();
    first_page.next_cursor = Some("secret-cursor".to_owned());
    let responses = vec![
        HerokuResponse::json(200, &HerokuAppFixture::released(&request_scope)).expect("app"),
        HerokuResponse::json(200, &HerokuBuildFixture::succeeded(&request_scope)).expect("build"),
        HerokuResponse::json(200, &first_page).expect("first release page"),
        HerokuResponse::json(200, &HerokuReleasePageFixture::released(&request_scope))
            .expect("second release page"),
        HerokuResponse::json(200, &HerokuSlugFixture::ready(&request_scope)).expect("slug"),
        HerokuResponse::json(200, &HerokuDynoFixture::up(&request_scope)).expect("dyno"),
    ];
    let secret = SecretReference::token("request-token", &request_scope, 1).expect("secret");
    let provider = HerokuProvider::new(
        RecordingTransport::new(responses),
        request_scope.clone(),
        secret,
    )
    .expect("provider");
    let mut service = HerokuDeploymentResultService::register(
        provider,
        "request-registration",
        PermissionSnapshot::for_layer_one(1).expect("permissions"),
        ConsentScope::for_layer_one("consent-1", 1, 100).expect("consent"),
        1,
    )
    .expect("service");
    service.read(10).expect("request evidence");
    let requests = service.provider().transport().requests();
    let debug = format!("{requests:?}");
    let encoded = serde_json::to_string(&requests).expect("request receipt");
    assert!(!debug.contains("secret-cursor"));
    assert!(!encoded.contains("secret-cursor"));
    assert!(requests.iter().all(heroku::HerokuRequest::is_get));
    assert!(requests.iter().all(heroku::HerokuRequest::is_allowlisted));
}
