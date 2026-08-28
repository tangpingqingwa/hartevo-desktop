use chrono::{DateTime, TimeZone, Utc};
use hartevo_aws_api_gateway_result_plugin::*;

fn at(day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 2, day, 0, 0, 0)
        .single()
        .expect("test timestamp")
}

fn scope_and_secret() -> (AwsApiGatewayScope, SecretReference) {
    let secret = SecretReference::new("sigv4-keyring-ref").expect("secret");
    let permissions = PermissionFence::read_only(
        PermissionId::new("api-gateway-read").expect("permission id"),
        Revision::new(3).expect("permission revision"),
    )
    .expect("permissions");
    let scope = AwsApiGatewayScope::new(
        AccountId::new("123456789012").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        ApiBinding::new(
            ApiKind::Rest,
            ApiGatewayApiId::new("abc123").expect("api"),
            Revision::new(7).expect("api revision"),
        ),
        StageBinding::new(
            StageName::new("prod").expect("stage"),
            Revision::new(4).expect("stage revision"),
        ),
        ApiDeploymentBinding::new(
            ApiGatewayDeploymentId::new("dep-001").expect("API deployment"),
            Revision::new(9).expect("deployment revision"),
            Digest::from_text("configuration-v1"),
            None,
        )
        .expect("API deployment"),
        MissionBinding::new(
            MissionId::new("mission-1").expect("Mission"),
            Revision::new(11).expect("Mission revision"),
        ),
        ProjectBinding::new(
            ProjectId::new("project-1").expect("Project"),
            Revision::new(12).expect("Project revision"),
        ),
        WorkProductBinding::new(
            WorkProductId::new("work-product-1").expect("Work Product"),
            Revision::new(13).expect("Work Product revision"),
        ),
        DeploymentBinding::new(
            DeploymentId::new("hartevo-deployment-1").expect("Hartevo deployment"),
            Revision::new(14).expect("Hartevo deployment revision"),
        ),
        permissions,
        secret.reference_digest().clone(),
    )
    .expect("scope");
    (scope, secret)
}

fn fixture_service() -> (
    AwsApiGatewayScope,
    AwsApiGatewayService<FixtureAwsApiGatewayTransport>,
) {
    let (scope, secret) = scope_and_secret();
    let provider = AwsApiGatewayProvider::new(FixtureAwsApiGatewayTransport::default())
        .expect("fixture provider");
    let service = AwsApiGatewayService::new(scope.clone(), secret, provider).expect("service");
    (scope, service)
}

fn recording_service() -> (
    AwsApiGatewayScope,
    AwsApiGatewayService<RecordingAwsApiGatewayTransport>,
) {
    let (scope, secret) = scope_and_secret();
    let provider = AwsApiGatewayProvider::new(RecordingAwsApiGatewayTransport::default())
        .expect("recording provider");
    let service = AwsApiGatewayService::new(scope.clone(), secret, provider).expect("service");
    (scope, service)
}

fn provider_revision() -> ProviderRevision {
    ProviderRevision::new(AWS_API_GATEWAY_API_REVISION).expect("provider revision")
}

fn stage_for(
    scope: &AwsApiGatewayScope,
    deployment_id: &str,
    stage_revision: Revision,
) -> StageMetadata {
    StageMetadata::new(
        scope.api.id.clone(),
        scope.stage.name.clone(),
        ApiGatewayDeploymentId::new(deployment_id).expect("deployment id"),
        scope.api.revision,
        stage_revision,
        at(2),
        Some(15),
        Digest::from_text("route-auth-summary"),
    )
    .expect("stage metadata")
}

fn deployment_for(
    scope: &AwsApiGatewayScope,
    deployment_id: &str,
    revision: Revision,
) -> DeploymentMetadata {
    DeploymentMetadata::new(
        scope.api.id.clone(),
        ApiGatewayDeploymentId::new(deployment_id).expect("deployment id"),
        revision,
        at(1),
        scope.deployment.configuration_digest.clone(),
        scope.deployment.commit_digest.clone(),
        Digest::from_text("route-auth-summary"),
    )
    .expect("deployment metadata")
}

#[test]
fn contract_is_versioned_and_layer_one_honest() {
    let contract = AwsApiGatewayContract::baseline().expect("contract");
    assert_eq!(contract.digest(), contract_digest());
    assert_eq!(plugin_version(), (1, 0, 0));
    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native());
    assert!(!Layer1Authority::first_party());
    assert!(!Layer1Authority::truth_authority());
    assert!(!Layer1Authority::consent_authority());
    assert!(!Layer1Authority::effect_authority());
    assert!(!Layer1Authority::outcome_adoption());
}

#[test]
fn scope_contains_exact_project_mission_work_product_and_api_target() {
    let (scope, service) = fixture_service();
    assert_eq!(scope.account_id.as_str(), "123456789012");
    assert_eq!(scope.region.as_str(), "us-east-1");
    assert_eq!(scope.api.id.as_str(), "abc123");
    assert_eq!(scope.stage.name.as_str(), "prod");
    assert_eq!(scope.deployment.id.as_str(), "dep-001");
    assert_eq!(scope.mission.id.as_str(), "mission-1");
    assert_eq!(scope.project.id.as_str(), "project-1");
    assert_eq!(scope.work_product.id.as_str(), "work-product-1");
    assert_eq!(scope.hartevo_deployment.id.as_str(), "hartevo-deployment-1");
    assert!(service.is_active());
    assert!(
        service.registration().recomputed_digest() == service.registration().registration_digest
    );
}

#[test]
fn secret_and_page_tokens_are_opaque_and_non_serializing() {
    let (_, secret) = scope_and_secret();
    let encoded = serde_json::to_string(&secret).expect("secret JSON");
    assert_eq!(encoded, r#"{"opaque":true}"#);
    assert!(!encoded.contains("sigv4-keyring-ref"));
    assert!(!format!("{secret:?}").contains("sigv4-keyring-ref"));

    let token = OpaquePageToken::new("provider-next-token-secret").expect("token");
    let encoded = serde_json::to_string(&token).expect("token JSON");
    assert_eq!(encoded, r#"{"opaque":true}"#);
    assert!(!encoded.contains("provider-next-token-secret"));
    assert!(!format!("{token:?}").contains("provider-next-token-secret"));
}

#[test]
fn fixture_recording_and_loopback_provenance_never_claim_native_access() {
    let (scope, mut service) = fixture_service();
    let stage = service
        .read(AwsApiGatewayReadRequest::get_stage(&scope).expect("stage request"))
        .expect("fixture stage");
    assert_eq!(stage.evidence.status, EvidenceStatus::Complete);
    assert_eq!(stage.evidence.provenance, TransportProvenance::Fixture);
    assert!(!stage.evidence.connected);
    assert!(!stage.evidence.native);
    assert!(!stage.evidence.first_party);

    let deployment = service
        .read(AwsApiGatewayReadRequest::get_deployment(&scope).expect("deployment request"))
        .expect("fixture deployment");
    assert_eq!(deployment.evidence.status, EvidenceStatus::Complete);

    let deployments = service
        .read(AwsApiGatewayReadRequest::get_deployments(&scope).expect("list request"))
        .expect("fixture deployments");
    assert_eq!(deployments.evidence.status, EvidenceStatus::Complete);
    assert_eq!(deployments.evidence.deployments.len(), 1);

    let (_, secret) = scope_and_secret();
    let loopback_provider = AwsApiGatewayProvider::new(LoopbackAwsApiGatewayTransport::default())
        .expect("loopback provider");
    let loopback = AwsApiGatewayService::new(scope, secret, loopback_provider).expect("loopback");
    assert!(!loopback.provider().provenance().native());
    assert!(!loopback.provider().provenance().connected());
}

#[test]
fn proposal_record_verify_and_mission_consume_remain_below_authority() {
    let (scope, mut service) = fixture_service();
    let proposal = service
        .propose(
            AwsApiGatewayReadRequest::get_stage(&scope).expect("stage request"),
            at(3),
        )
        .expect("proposal");
    assert_eq!(proposal.evidence.status, EvidenceStatus::Complete);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.adopts_outcome);
    assert!(!proposal.truth_authority);

    let consumer = MissionAwsApiGatewayConsumer::new(scope.clone(), service.registration().clone())
        .expect("consumer");
    let result = consumer.consume(proposal.clone()).expect("Mission result");
    assert_eq!(result.consumer_id, AWS_API_GATEWAY_CONSUMER_ID);
    assert_eq!(
        result.decision_state,
        MissionAwsApiGatewayDecisionState::ReviewRequired
    );
    assert!(result.requires_human_review);
    assert!(!result.safe_to_promote);
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.first_party);
    assert!(!result.certification_claim);
    assert!(!result.adopted_outcome);
    assert!(!result.truth_authority);

    let receipt = service.record_at(&proposal, at(4)).expect("record receipt");
    assert!(!receipt.durable_receipt);
    let verified = service.verify(&receipt).expect("verified record");
    assert!(verified.verified);
    assert!(!verified.connected);
    assert!(!verified.native);
    assert!(!verified.first_party);
    assert!(!verified.adopted_outcome);
    assert!(!verified.truth_authority);
}

#[test]
fn json_parsers_retain_bounded_metadata_and_drop_raw_provider_fields() {
    let (scope, _) = scope_and_secret();
    let stage_request = GetStageRequest::from_scope(&scope);
    let stage_body = br#"{
      "deploymentId":"dep-001",
      "lastUpdatedDate":"2026-02-02T00:00:00Z",
      "canarySettings":{"percentTraffic":12.5,"stageVariableOverrides":{"token":"secret"}},
      "methodSettings":{"*/*":{"loggingLevel":"INFO"}},
      "stageVariables":{"password":"do-not-retain"},
      "authorizerSecret":"do-not-retain"
    }"#;
    let stage = AwsApiGatewayProvider::<RecordingAwsApiGatewayTransport>::parse_stage_json(
        &stage_request,
        stage_body.len(),
        stage_body,
        provider_revision(),
    )
    .expect("stage parser");
    let encoded = serde_json::to_string(&stage).expect("stage JSON");
    assert!(!encoded.contains("do-not-retain"));
    assert!(!encoded.contains("password"));
    assert_eq!(stage.stage.canary_traffic_percent, Some(13));

    let deployment_request = GetDeploymentRequest::from_scope(&scope);
    let deployment_body = br#"{
      "id":"dep-001",
      "createdDate":"2026-02-01T00:00:00Z",
      "description":"private deployment note",
      "apiSummary":{"/private":{"GET":"lambda-secret"}},
      "variables":{"secret":"drop"},
      "openapi":"drop"
    }"#;
    let deployment =
        AwsApiGatewayProvider::<RecordingAwsApiGatewayTransport>::parse_deployment_json(
            &deployment_request,
            deployment_body.len(),
            deployment_body,
            provider_revision(),
        )
        .expect("deployment parser");
    let encoded = serde_json::to_string(&deployment).expect("deployment JSON");
    assert!(!encoded.contains("private deployment note"));
    assert!(!encoded.contains("lambda-secret"));
    assert!(!encoded.contains("openapi"));

    let list_request = GetDeploymentsRequest::from_scope(&scope).expect("list request");
    let list_body = br#"{
      "items":[{"id":"dep-001","createdDate":"2026-02-01T00:00:00Z","description":"drop","apiSummary":{}}],
      "position":"raw-next-token-secret"
    }"#;
    let page = AwsApiGatewayProvider::<RecordingAwsApiGatewayTransport>::parse_deployments_json(
        &list_request,
        1,
        list_body.len(),
        list_body,
        provider_revision(),
    )
    .expect("list parser");
    let encoded = serde_json::to_string(&page).expect("page JSON");
    assert!(!encoded.contains("raw-next-token-secret"));
    assert_eq!(page.deployments.len(), 1);
}

#[test]
fn stage_and_deployment_drift_is_partial_and_fail_closed() {
    let (scope, mut service) = recording_service();
    let stage = stage_for(&scope, "other-deployment", scope.stage.revision);
    service
        .provider_mut()
        .transport_mut()
        .push_stage_response(Ok(AwsApiGatewayStageResponse::new(
            stage,
            512,
            provider_revision(),
        )));
    let result = service
        .read(AwsApiGatewayReadRequest::get_stage(&scope).expect("request"))
        .expect("bounded drift evidence");
    assert_eq!(result.evidence.status, EvidenceStatus::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(PartialReason::StageDrift)
    );

    let (scope, mut service) = recording_service();
    let deployment = deployment_for(&scope, "dep-001", Revision::new(99).expect("revision"));
    service
        .provider_mut()
        .transport_mut()
        .push_deployment_response(Ok(AwsApiGatewayDeploymentResponse::new(
            deployment,
            640,
            provider_revision(),
        )));
    let result = service
        .read(AwsApiGatewayReadRequest::get_deployment(&scope).expect("request"))
        .expect("revision evidence");
    assert_eq!(result.evidence.status, EvidenceStatus::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(PartialReason::RevisionDrift)
    );
}

#[test]
fn digest_tamper_and_scope_replay_are_rejected() {
    let (scope, mut service) = fixture_service();
    let proposal = service
        .propose(
            AwsApiGatewayReadRequest::get_stage(&scope).expect("request"),
            at(3),
        )
        .expect("proposal");
    let mut tampered = proposal.clone();
    tampered.evidence.status = EvidenceStatus::ProviderUnknown;
    assert!(service.verify_proposal(&tampered).is_err());

    let mut replay_scope = scope.clone();
    replay_scope.stage.name = StageName::new("staging").expect("stage");
    let replay_request = AwsApiGatewayReadRequest::stage(&replay_scope);
    assert!(matches!(
        service.read(replay_request),
        Err(AwsApiGatewayServiceError::ScopeMismatch)
    ));

    let mut tampered_registration = service.registration().clone();
    tampered_registration.scope_digest = Digest::zero();
    assert!(MissionAwsApiGatewayConsumer::new(scope, tampered_registration).is_err());
}

#[test]
fn pagination_loops_budgets_and_out_of_scope_items_are_partial() {
    let (scope, mut service) = recording_service();
    let request = GetDeploymentsRequest::from_scope(&scope).expect("request");
    let target = DeploymentSummary::from_metadata(&deployment_for(
        &scope,
        "dep-001",
        scope.deployment.revision,
    ));
    let cursor = OpaquePageToken::new("cursor-a").expect("cursor");
    let first = AwsApiGatewayDeploymentsPage::new(
        &request,
        1,
        vec![target.clone()],
        Some(cursor.clone()),
        768,
        provider_revision(),
    )
    .expect("first page");
    let second = AwsApiGatewayDeploymentsPage::new(
        &request,
        2,
        vec![target],
        Some(cursor),
        768,
        provider_revision(),
    )
    .expect("second page");
    service
        .provider_mut()
        .transport_mut()
        .push_deployments_page(Ok(first));
    service
        .provider_mut()
        .transport_mut()
        .push_deployments_page(Ok(second));
    let result = service
        .read(AwsApiGatewayReadRequest::GetDeployments(request))
        .expect("loop evidence");
    assert_eq!(result.evidence.status, EvidenceStatus::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(PartialReason::PaginationLoop)
    );
    assert!(result.evidence.truncated);

    let (scope, mut service) = recording_service();
    let budget_request =
        GetDeploymentsRequest::with_bounds(&scope, 50, 1, MAX_RESPONSE_BYTES, 0, None)
            .expect("budget request");
    let next = OpaquePageToken::new("page-two").expect("next cursor");
    let page = AwsApiGatewayDeploymentsPage::new(
        &budget_request,
        1,
        vec![DeploymentSummary::from_metadata(&deployment_for(
            &scope,
            "dep-001",
            scope.deployment.revision,
        ))],
        Some(next),
        768,
        provider_revision(),
    )
    .expect("budget page");
    service
        .provider_mut()
        .transport_mut()
        .push_deployments_page(Ok(page));
    let result = service
        .read(AwsApiGatewayReadRequest::GetDeployments(budget_request))
        .expect("budget evidence");
    assert_eq!(result.evidence.status, EvidenceStatus::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(PartialReason::PageBudget)
    );

    let (scope, mut service) = recording_service();
    let wrong = DeploymentSummary::from_metadata(&deployment_for(
        &scope,
        "other-deployment",
        scope.deployment.revision,
    ));
    let request = GetDeploymentsRequest::from_scope(&scope).expect("request");
    let page =
        AwsApiGatewayDeploymentsPage::new(&request, 1, vec![wrong], None, 768, provider_revision())
            .expect("out-of-scope page");
    service
        .provider_mut()
        .transport_mut()
        .push_deployments_page(Ok(page));
    let result = service
        .read(AwsApiGatewayReadRequest::GetDeployments(request))
        .expect("out-of-scope evidence");
    assert_eq!(result.evidence.status, EvidenceStatus::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(PartialReason::DeploymentDrift)
    );
    assert!(result.evidence.deployments.is_empty());
}

#[test]
fn access_loss_throttle_timeout_conflict_and_blocked_env_are_typed() {
    let cases = [
        (TransportError::Unauthorized, EvidenceStatus::AccessLoss),
        (TransportError::AccessDenied, EvidenceStatus::AccessLoss),
        (TransportError::NotFound, EvidenceStatus::AccessLoss),
        (TransportError::Conflict, EvidenceStatus::Partial),
        (
            TransportError::Throttled {
                retry_after_seconds: Some(2),
            },
            EvidenceStatus::ProviderUnknown,
        ),
        (
            TransportError::ServerFailure {
                status_code: Some(503),
            },
            EvidenceStatus::ProviderUnknown,
        ),
        (TransportError::Timeout, EvidenceStatus::ProviderUnknown),
    ];
    for (error, expected_status) in cases {
        let (scope, mut service) = recording_service();
        for _ in 0..=MAX_RETRIES {
            service
                .provider_mut()
                .transport_mut()
                .push_stage_response(Err(error.clone()));
        }
        let result = service
            .read(AwsApiGatewayReadRequest::get_stage(&scope).expect("request"))
            .expect("typed failure evidence");
        assert_eq!(result.evidence.status, expected_status);
        assert!(!result.evidence.provider_errors.is_empty());
        assert!(result.evidence.request_count <= 3);
    }

    let (scope, secret) = scope_and_secret();
    let provider = AwsApiGatewayProvider::new(BlockedEnvAwsApiGatewayTransport).expect("blocked");
    let mut service = AwsApiGatewayService::new(scope.clone(), secret, provider).expect("service");
    let result = service
        .read(AwsApiGatewayReadRequest::get_stage(&scope).expect("request"))
        .expect("blocked evidence");
    assert_eq!(result.evidence.status, EvidenceStatus::ProviderUnknown);
    assert_eq!(
        result.evidence.partial_reason,
        Some(PartialReason::BlockedEnvironment)
    );
    assert_eq!(result.evidence.provenance, TransportProvenance::BlockedEnv);
    assert!(!result.evidence.connected);
    assert!(!result.evidence.native);
    assert!(!result.evidence.first_party);
}

#[test]
fn response_digest_tamper_and_registration_revocation_fail_closed() {
    let (scope, mut service) = recording_service();
    let stage = stage_for(&scope, "dep-001", scope.stage.revision);
    let mut response = AwsApiGatewayStageResponse::new(stage, 512, provider_revision());
    response.response_digest = Digest::from_text("tampered-response");
    service
        .provider_mut()
        .transport_mut()
        .push_stage_response(Ok(response));
    let result = service
        .read(AwsApiGatewayReadRequest::get_stage(&scope).expect("request"))
        .expect("digest evidence");
    assert_eq!(result.evidence.status, EvidenceStatus::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(PartialReason::DigestDrift)
    );

    let (scope, mut service) = fixture_service();
    let proposal = service
        .propose(
            AwsApiGatewayReadRequest::get_stage(&scope).expect("request"),
            at(3),
        )
        .expect("proposal");
    let receipt = service.record_at(&proposal, at(4)).expect("receipt");
    service.revoke_registration().expect("revoke");
    assert!(!service.is_active());
    assert!(service.record_at(&proposal, at(5)).is_err());
    assert!(service.verify(&receipt).is_err());
    assert!(service.revoke_registration().is_err());
}

#[test]
fn insufficient_permission_and_secret_scope_mismatch_are_rejected() {
    let (scope, secret) = scope_and_secret();
    let restricted_permissions = PermissionFence::new(
        PermissionId::new("stage-only").expect("permission"),
        Revision::new(1).expect("permission revision"),
        [PermissionAction::GetStage],
    )
    .expect("restricted permissions");
    let restricted_scope = AwsApiGatewayScope::new(
        scope.account_id.clone(),
        scope.region.clone(),
        scope.api.clone(),
        scope.stage.clone(),
        scope.deployment.clone(),
        scope.mission.clone(),
        scope.project.clone(),
        scope.work_product.clone(),
        scope.hartevo_deployment.clone(),
        restricted_permissions,
        secret.reference_digest().clone(),
    )
    .expect("restricted scope");
    let provider =
        AwsApiGatewayProvider::new(FixtureAwsApiGatewayTransport::default()).expect("provider");
    assert!(matches!(
        AwsApiGatewayService::new(restricted_scope, secret.clone(), provider),
        Err(AwsApiGatewayServiceError::PermissionLoss)
    ));

    let wrong_secret = SecretReference::new("different-sigv4-ref").expect("wrong secret");
    let provider =
        AwsApiGatewayProvider::new(FixtureAwsApiGatewayTransport::default()).expect("provider");
    assert!(matches!(
        AwsApiGatewayService::new(scope, wrong_secret, provider),
        Err(AwsApiGatewayServiceError::ScopeMismatch)
    ));
}
