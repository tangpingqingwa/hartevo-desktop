use hartevo_render_deployment_result_plugin as render;
use render::{
    BlockedEnvTransport, ConsentScope, Digest, FakeTransport, FixtureTransport, Layer1Authority,
    LoopbackTransport, MissionRenderDeploymentConsumer, PermissionSnapshot, ProviderProvenance,
    RecordingTransport, RenderDeployFixture, RenderDeployPageFixture, RenderDeploymentError,
    RenderDeploymentResultService, RenderDeploymentScope, RenderHealthFixture, RenderReadRequest,
    RenderResponse, RenderResultState, RenderServiceFixture, RenderTransport, SecretKind,
    SecretReference, WorkProduct,
};

fn scope() -> RenderDeploymentScope {
    RenderDeploymentScope::new(
        "owner-1",
        "workspace-1",
        "service-1",
        "environment-1",
        "deploy-1",
        "commit-1",
        "oregon",
        render::Project::new("project-1", 2).expect("project"),
        render::Mission::new("mission-1", 3).expect("mission"),
        WorkProduct::new("work-product-1", 4).expect("work product"),
    )
    .expect("scope")
}

fn service_fixture(scope: &RenderDeploymentScope) -> RenderServiceFixture {
    RenderServiceFixture::ready(scope)
}

fn deploy_fixture(scope: &RenderDeploymentScope) -> RenderDeployFixture {
    RenderDeployFixture::live(scope)
}

fn service_from_responses(
    scope: &RenderDeploymentScope,
    responses: impl IntoIterator<Item = RenderResponse>,
) -> RenderDeploymentResultService<RecordingTransport> {
    let secret = SecretReference::new(
        "opaque-render-credential-reference",
        scope,
        7,
        SecretKind::ApiKey,
    )
    .expect("secret reference");
    let provider =
        render::RenderProvider::new(RecordingTransport::new(responses), scope.clone(), secret)
            .expect("provider");
    RenderDeploymentResultService::register(
        provider,
        "registration-1",
        PermissionSnapshot::for_layer_one(2).expect("permissions"),
        ConsentScope::for_layer_one("consent-1", 1, 100).expect("consent"),
        1,
    )
    .expect("service")
}

fn ready_service(
    scope: &RenderDeploymentScope,
) -> RenderDeploymentResultService<RecordingTransport> {
    let service = service_fixture(scope);
    let deploy = deploy_fixture(scope);
    service_from_responses(
        scope,
        [
            RenderResponse::json(200, &service).expect("service response"),
            RenderResponse::json(
                200,
                &RenderDeployPageFixture {
                    service_id: scope.service_id().as_str().to_owned(),
                    environment_id: scope.environment_id().as_str().to_owned(),
                    deploys: vec![deploy.clone()],
                    next_cursor: None,
                },
            )
            .expect("deploy page"),
            RenderResponse::json(200, &deploy).expect("deploy response"),
        ],
    )
}

#[test]
fn contract_and_authority_are_machine_checked() {
    let document: serde_json::Value =
        serde_json::from_str(render::CONTRACT_JSON).expect("contract");
    assert_eq!(document["schemaVersion"], render::CONTRACT_SCHEMA);
    assert_eq!(document["contractVersion"], render::CONTRACT_VERSION);
    assert_eq!(document["contractDigest"], render::CONTRACT_DIGEST);
    assert_eq!(render::contract_digest(), render::CONTRACT_DIGEST);
    assert_eq!(document["service"]["type"], "RenderDeploymentResultService");
    assert_eq!(document["provider"]["type"], "RenderProvider");
    assert_eq!(
        document["consumer"]["type"],
        "MissionRenderDeploymentConsumer"
    );
    assert_eq!(
        document["allowlist"]["writes"].as_array().map(Vec::len),
        Some(0)
    );
    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native_provider());
    assert!(!Layer1Authority::external_writes());
    assert!(!Layer1Authority::outcome_authority());
    assert!(!Layer1Authority::work_product_adoption());
}

#[test]
fn scope_revisions_permissions_and_secret_reference_are_fenced_and_redacted() {
    assert!(render::Project::new("project", 0).is_err());
    assert!(render::Mission::new("mission", 0).is_err());
    assert!(WorkProduct::new("work-product", 0).is_err());
    assert!(PermissionSnapshot::new(1, ["render:services.read"]).is_err());

    let scope = scope();
    let secret = SecretReference::new(
        "do-not-leak-this-render-token",
        &scope,
        1,
        SecretKind::OAuth2,
    )
    .expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("do-not-leak-this-render-token"));
    assert_eq!(secret.scope_digest(), &scope.digest());
    assert_eq!(secret.kind(), SecretKind::OAuth2);

    let provider = render::RenderProvider::new(
        FixtureTransport::new(RenderResponse::new(200, b"{}".to_vec())),
        scope.clone(),
        secret,
    )
    .expect("provider");
    let registration = render::RenderDeploymentRegistration::new(
        "registration",
        &provider,
        PermissionSnapshot::for_layer_one(1).expect("permissions"),
        ConsentScope::for_layer_one("consent", 1, 100).expect("consent"),
        1,
    )
    .expect("registration");
    let encoded = serde_json::to_string(&registration).expect("redacted registration");
    assert!(!encoded.contains("do-not-leak-this-render-token"));
    assert!(encoded.contains("secretReferenceDigest"));
    assert_eq!(registration.scope().digest(), scope.digest());
}

#[test]
fn ready_flow_is_bounded_redacted_and_mission_scoped() {
    let scope = scope();
    let mut service = ready_service(&scope);
    let read_request = RenderReadRequest::new(
        &scope,
        scope.mission().revision().get(),
        scope.work_product().revision().get(),
        service.registration().permission_digest().clone(),
        service.registration().consent_digest().clone(),
    )
    .expect("read fence");
    let evidence = service
        .read_with_fence(&read_request, 10)
        .expect("evidence");
    assert_eq!(evidence.state, RenderResultState::Ready);
    assert_eq!(evidence.page_count, 1);
    assert_eq!(evidence.deploy_count, 1);
    assert!(evidence.listing_complete);
    assert!(evidence.service.is_some());
    assert!(evidence.deployment.is_some());
    assert!(evidence.health.is_some());
    assert!(!evidence.connected);
    assert!(!evidence.native);
    evidence.validate_integrity().expect("evidence integrity");

    let proposal = service
        .compile_proposal_from_evidence(evidence)
        .expect("proposal");
    let report = service.verify_proposal(&proposal).expect("verification");
    assert!(report.verified());
    assert!(!report.can_be_adopted());
    let receipt = service
        .record_observation(&proposal, 10)
        .expect("redacted receipt");
    receipt.validate_integrity().expect("receipt integrity");
    assert!(!receipt.durable_provider_receipt);

    let mut consumer =
        MissionRenderDeploymentConsumer::new(scope.clone(), service.registration().clone())
            .expect("consumer");
    let mission = consumer.consume(&proposal).expect("Mission projection");
    assert_eq!(mission.project.revision, scope.project().revision());
    assert_eq!(mission.mission.revision, scope.mission().revision());
    assert_eq!(
        mission.work_product.revision,
        scope.work_product().revision()
    );
    assert!(mission.review_only);
    assert!(!mission.can_be_adopted());
    mission.validate_integrity().expect("Mission integrity");

    let first = consumer.record(&proposal, "idempotency-1").expect("record");
    assert!(!first.replayed);
    let replay = consumer.record(&proposal, "idempotency-1").expect("replay");
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn fixture_fake_loopback_and_blocked_env_never_claim_connected_or_native() {
    let scope = scope();
    let response = RenderResponse::new(200, b"{}".to_vec());
    let transports: Vec<Box<dyn RenderTransport>> = vec![
        Box::new(FixtureTransport::new(response.clone())),
        Box::new(FakeTransport::new(response.clone())),
        Box::new(LoopbackTransport::new(response)),
        Box::new(BlockedEnvTransport),
    ];
    for transport in transports {
        let provenance = transport.provenance();
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
        assert!(!provenance.provider_receipt());
    }

    let secret = SecretReference::api_key("opaque", &scope, 1).expect("secret");
    let provider = render::RenderProvider::new(BlockedEnvTransport, scope.clone(), secret)
        .expect("blocked provider");
    let mut service = RenderDeploymentResultService::register(
        provider,
        "blocked-registration",
        PermissionSnapshot::for_layer_one(1).expect("permissions"),
        ConsentScope::for_layer_one("consent", 1, 100).expect("consent"),
        1,
    )
    .expect("service");
    let evidence = service.read(10).expect("blocked evidence");
    assert_eq!(evidence.state, RenderResultState::ProviderUnknown);
    assert_eq!(evidence.provenance, ProviderProvenance::BlockedEnv);
    assert!(!evidence.connected);
    assert!(!evidence.native);
}

#[test]
fn service_deploy_and_health_states_are_typed() {
    let scope = scope();
    for (deploy_status, expected) in [
        ("building", RenderResultState::InProgress),
        ("failed", RenderResultState::Failed),
        ("canceled", RenderResultState::Canceled),
    ] {
        let service_fixture = service_fixture(&scope);
        let mut deploy = deploy_fixture(&scope);
        deploy.status = deploy_status.to_owned();
        let mut service = service_from_responses(
            &scope,
            [
                RenderResponse::json(200, &service_fixture).expect("service"),
                RenderResponse::json(
                    200,
                    &RenderDeployPageFixture {
                        service_id: scope.service_id().as_str().to_owned(),
                        environment_id: scope.environment_id().as_str().to_owned(),
                        deploys: vec![deploy.clone()],
                        next_cursor: None,
                    },
                )
                .expect("page"),
                RenderResponse::json(200, &deploy).expect("deploy"),
            ],
        );
        let evidence = service.read(10).expect("typed state");
        assert_eq!(evidence.state, expected);
        assert!(!evidence.state.is_adoptable());
    }

    let mut degraded = service_fixture(&scope);
    degraded.health = RenderHealthFixture::degraded();
    let deploy = deploy_fixture(&scope);
    let mut service = service_from_responses(
        &scope,
        [
            RenderResponse::json(200, &degraded).expect("service"),
            RenderResponse::json(
                200,
                &RenderDeployPageFixture {
                    service_id: scope.service_id().as_str().to_owned(),
                    environment_id: scope.environment_id().as_str().to_owned(),
                    deploys: vec![deploy.clone()],
                    next_cursor: None,
                },
            )
            .expect("page"),
            RenderResponse::json(200, &deploy).expect("deploy"),
        ],
    );
    assert_eq!(
        service.read(10).expect("health state").state,
        RenderResultState::HealthUnknown
    );
}

#[test]
fn pagination_rate_limit_and_backoff_are_bounded() {
    let scope = scope();
    let service_fixture = service_fixture(&scope);
    let deploy = deploy_fixture(&scope);
    let mut other = deploy.clone();
    other.deploy_id = "other-deploy".to_owned();
    let first_page = RenderDeployPageFixture {
        service_id: scope.service_id().as_str().to_owned(),
        environment_id: scope.environment_id().as_str().to_owned(),
        deploys: vec![other],
        next_cursor: Some("opaque-page-2".to_owned()),
    };
    let second_page = RenderDeployPageFixture {
        service_id: scope.service_id().as_str().to_owned(),
        environment_id: scope.environment_id().as_str().to_owned(),
        deploys: vec![deploy.clone()],
        next_cursor: None,
    };
    let mut service = service_from_responses(
        &scope,
        [
            RenderResponse::json(200, &service_fixture).expect("service"),
            RenderResponse::new(429, b"{}".to_vec()),
            RenderResponse::json(200, &first_page).expect("first page"),
            RenderResponse::json(200, &second_page).expect("second page"),
            RenderResponse::json(200, &deploy).expect("deploy"),
        ],
    );
    let evidence = service.read(10).expect("bounded paginated evidence");
    assert_eq!(evidence.state, RenderResultState::Ready);
    assert_eq!(evidence.page_count, 2);
    assert_eq!(evidence.cursor_digests.len(), 1);
    assert!(evidence.backoff.is_some());
    assert!(
        evidence
            .backoff
            .as_ref()
            .is_some_and(|backoff| { backoff.retry_after_seconds <= render::MAX_BACKOFF_SECONDS })
    );
    let requests = service.provider().transport().requests();
    assert_eq!(requests.len(), 5);
    assert!(requests.iter().all(render::RenderRequest::is_get));
    assert!(requests.iter().all(render::RenderRequest::is_allowlisted));
    let serialized = serde_json::to_string(&requests).expect("redacted requests");
    assert!(!serialized.contains("opaque-render-credential-reference"));
}

#[test]
fn pagination_loop_bound_and_access_loss_fail_closed() {
    let scope = scope();
    let service_fixture = service_fixture(&scope);
    let deploy = deploy_fixture(&scope);
    let loop_page = RenderDeployPageFixture {
        service_id: scope.service_id().as_str().to_owned(),
        environment_id: scope.environment_id().as_str().to_owned(),
        deploys: vec![deploy],
        next_cursor: Some("same-cursor".to_owned()),
    };
    let mut service = service_from_responses(
        &scope,
        [
            RenderResponse::json(200, &service_fixture).expect("service"),
            RenderResponse::json(200, &loop_page).expect("page"),
            RenderResponse::json(200, &loop_page).expect("loop page"),
        ],
    );
    let evidence = service.read(10).expect("loop evidence");
    assert_eq!(evidence.state, RenderResultState::PaginationLoop);
    assert!(!evidence.listing_complete);
    assert!(
        service
            .compile_proposal_from_evidence(evidence)
            .and_then(|proposal| service.verify_proposal(&proposal))
            .is_ok()
    );

    let mut pages = vec![RenderResponse::json(200, &service_fixture).expect("service")];
    for index in 0..render::MAX_PAGES {
        pages.push(
            RenderResponse::json(
                200,
                &RenderDeployPageFixture {
                    service_id: scope.service_id().as_str().to_owned(),
                    environment_id: scope.environment_id().as_str().to_owned(),
                    deploys: Vec::new(),
                    next_cursor: Some(format!("page-{index}")),
                },
            )
            .expect("page"),
        );
    }
    let mut bounded = service_from_responses(&scope, pages);
    let evidence = bounded.read(10).expect("bound evidence");
    assert_eq!(evidence.state, RenderResultState::PaginationBound);
    assert!(!evidence.state.is_adoptable());

    let mut access_loss =
        service_from_responses(&scope, [RenderResponse::new(403, b"{}".to_vec())]);
    let evidence = access_loss.read(10).expect("access-loss evidence");
    assert_eq!(evidence.state, RenderResultState::AccessLoss);
    assert!(!evidence.connected);
    assert!(!evidence.native);
}

#[test]
fn commit_scope_mismatch_response_tamper_and_verification_fail_closed() {
    let scope = scope();
    let service_fixture = service_fixture(&scope);
    let mut stale_deploy = deploy_fixture(&scope);
    stale_deploy.commit = "different-commit".to_owned();
    let mut stale = service_from_responses(
        &scope,
        [
            RenderResponse::json(200, &service_fixture).expect("service"),
            RenderResponse::json(
                200,
                &RenderDeployPageFixture {
                    service_id: scope.service_id().as_str().to_owned(),
                    environment_id: scope.environment_id().as_str().to_owned(),
                    deploys: vec![stale_deploy.clone()],
                    next_cursor: None,
                },
            )
            .expect("page"),
            RenderResponse::json(200, &stale_deploy).expect("deploy"),
        ],
    );
    assert_eq!(
        stale.read(10).expect("stale evidence").state,
        RenderResultState::StaleRevision
    );

    let mut wrong_service = service_fixture.clone();
    wrong_service.service_id = "service-other".to_owned();
    let mut tampered = service_from_responses(
        &scope,
        [RenderResponse::json(200, &wrong_service).expect("wrong service")],
    );
    assert_eq!(
        tampered.read(10).expect("tampered evidence").state,
        RenderResultState::Tampered
    );

    let mut service = ready_service(&scope);
    let evidence = service.read(10).expect("evidence");
    let mut proposal = service
        .compile_proposal_from_evidence(evidence)
        .expect("proposal");
    proposal.connected = true;
    assert_eq!(
        service.verify_proposal(&proposal),
        Err(RenderDeploymentError::TamperedEvidence)
    );
}

#[test]
fn registration_revoke_restore_and_mutation_forbidden_are_digest_bound() {
    let scope = scope();
    let mut service = ready_service(&scope);
    let before = service.registration().registration_digest().clone();
    let revoked = service.revoke().expect("revoke");
    assert_eq!(revoked.previous_status, render::RegistrationStatus::Active);
    assert_eq!(revoked.new_status, render::RegistrationStatus::Revoked);
    assert_eq!(service.registration().registration_revision().get(), 2);
    assert_ne!(before, *service.registration().registration_digest());
    assert_eq!(
        service.read(10),
        Err(RenderDeploymentError::RegistrationInactive)
    );
    let restored = service.restore_registration().expect("restore");
    assert_eq!(restored.new_status, render::RegistrationStatus::Active);
    assert_eq!(service.registration().registration_revision().get(), 3);
    let reversed = service.reverse_registration().expect("reverse");
    assert_eq!(reversed.new_status, render::RegistrationStatus::Reversed);
    assert_eq!(
        service.read(10),
        Err(RenderDeploymentError::RegistrationInactive)
    );

    for operation in [
        "deploy create",
        "deploy restart",
        "deploy rollback",
        "deploy cancel",
        "environment variable mutation",
        "secret export",
        "raw logs",
    ] {
        assert_eq!(
            service.provider().reject_write(operation),
            Err(RenderDeploymentError::MutationForbidden { operation })
        );
    }
}

#[test]
fn recording_conflict_is_distinct_from_idempotent_replay() {
    let scope = scope();
    let mut service = ready_service(&scope);
    let first_evidence = service.read(10).expect("first evidence");
    let first = service
        .compile_proposal_from_evidence(first_evidence)
        .expect("first proposal");

    let mut failed_deploy = deploy_fixture(&scope);
    failed_deploy.status = "failed".to_owned();
    service
        .provider()
        .transport()
        .push_response(RenderResponse::json(200, &service_fixture(&scope)).expect("service"));
    service.provider().transport().push_response(
        RenderResponse::json(
            200,
            &RenderDeployPageFixture {
                service_id: scope.service_id().as_str().to_owned(),
                environment_id: scope.environment_id().as_str().to_owned(),
                deploys: vec![failed_deploy.clone()],
                next_cursor: None,
            },
        )
        .expect("page"),
    );
    service
        .provider()
        .transport()
        .push_response(RenderResponse::json(200, &failed_deploy).expect("deploy"));
    let second = service.compile_proposal(10).expect("second proposal");

    let mut consumer = MissionRenderDeploymentConsumer::new(scope, service.registration().clone())
        .expect("consumer");
    consumer.record(&first, "same-key").expect("first record");
    let replay = consumer.record(&first, "same-key").expect("replay");
    assert!(replay.replayed);
    assert_eq!(
        consumer.record(&second, "same-key"),
        Err(RenderDeploymentError::RecordingConflict)
    );
}

#[test]
fn cursor_and_response_redaction_are_deterministic() {
    let cursor = render::OpaqueCursor::from_token("raw-cursor-must-not-escape").expect("cursor");
    let encoded = serde_json::to_string(&cursor).expect("cursor digest");
    assert!(!encoded.contains("raw-cursor-must-not-escape"));
    assert_eq!(cursor.digest().as_str().len(), 64);

    let response = RenderResponse::new(200, b"raw response body".to_vec());
    let debug = format!("{response:?}");
    let encoded = serde_json::to_string(&response).expect("response envelope");
    assert!(!debug.contains("raw response body"));
    assert!(!encoded.contains("raw response body"));
    assert_eq!(response.response_bytes(), 17);
    assert_eq!(
        response.response_digest(),
        Digest::from_text("raw response body")
    );
}
