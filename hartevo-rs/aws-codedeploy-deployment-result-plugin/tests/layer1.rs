use hartevo_aws_codedeploy_deployment_result_plugin::*;

fn scope() -> CodeDeployScope {
    let permissions = PermissionSnapshot::read_only_default(1).expect("permissions");
    let revision = CodeDeployRevision::new(
        RevisionId::new("revision-1").expect("revision id"),
        RevisionKind::S3,
        Digest::from_text("source-revision-1"),
    )
    .expect("revision");
    CodeDeployScope::from_strings(
        "123456789012",
        "us-east-1",
        "payments",
        "production",
        "d-ABC123",
        revision.revision_id.as_str(),
        revision.kind,
        revision.source_digest.clone(),
        "project-1",
        "mission-1",
        "work-product-1",
        7,
        3,
        permissions,
    )
    .expect("scope")
}

fn secret(scope: &CodeDeployScope) -> SecretReference {
    SecretReference::new("opaque-reference-1", scope, 1).expect("secret reference")
}

fn deployment(
    scope: &CodeDeployScope,
    status: CodeDeployDeploymentStatus,
) -> CodeDeployDeploymentRecord {
    CodeDeployDeploymentRecord {
        account: scope.account.clone(),
        region: scope.region.clone(),
        application: scope.application.clone(),
        deployment_group: scope.deployment_group.clone(),
        deployment: scope.deployment.clone(),
        revision: scope.revision.clone(),
        status,
        created_at: Some(100),
        completed_at: status.is_terminal().then_some(200),
        lifecycle_revision: 2,
        error_digest: (status == CodeDeployDeploymentStatus::Failed)
            .then(|| Digest::from_text("redacted-error")),
        provider_request_digest: Digest::from_text("request-deployment-1"),
    }
}

fn target(scope: &CodeDeployScope, status: CodeDeployTargetStatus) -> CodeDeployTargetRecord {
    CodeDeployTargetRecord {
        account: scope.account.clone(),
        region: scope.region.clone(),
        application: scope.application.clone(),
        deployment_group: scope.deployment_group.clone(),
        deployment: scope.deployment.clone(),
        target: TargetId::new("i-target-1").expect("target id"),
        kind: CodeDeployTargetKind::Instance,
        status,
        lifecycle_events: vec![
            CodeDeployLifecycleEvent::new(
                "ApplicationStop",
                if status == CodeDeployTargetStatus::Succeeded {
                    CodeDeployLifecycleEventStatus::Succeeded
                } else {
                    CodeDeployLifecycleEventStatus::InProgress
                },
                Some(110),
                (status == CodeDeployTargetStatus::Succeeded).then_some(190),
                Some(Digest::from_text("redacted-diagnostic")),
            )
            .expect("lifecycle event"),
        ],
        lifecycle_revision: 4,
        last_updated_at: Some(190),
        provider_target_revision: 1,
    }
}

fn service_with_status(
    status: CodeDeployDeploymentStatus,
    target_status: CodeDeployTargetStatus,
    provenance: ProviderProvenance,
) -> CodeDeployDeploymentResultService<RecordingCodeDeployTransport> {
    let scope = scope();
    let registration =
        CodeDeployRegistration::new(scope.clone(), secret(&scope), 1).expect("registration");
    let deployment = deployment(&scope, status);
    let target = target(&scope, target_status);
    let filter = DeploymentListFilter::exact(MAX_PAGE_SIZE).expect("filter");
    let deployment_page = CodeDeployDeploymentPage::new(
        scope.digest(),
        filter.filter_digest.clone(),
        vec![scope.deployment.clone()],
        None,
        512,
        false,
    )
    .expect("deployment page");
    let target_page = CodeDeployTargetPage::new(
        scope.digest(),
        deployment.digest(),
        vec![target],
        None,
        1024,
        false,
    )
    .expect("target page");
    let mut transport = RecordingCodeDeployTransport::new(provenance);
    transport.push_deployment_page(Ok(deployment_page));
    transport.set_deployment(deployment);
    transport.push_target_page(Ok(target_page));
    let provider = CodeDeployProvider::new(registration, transport).expect("provider");
    CodeDeployDeploymentResultService::new(provider).expect("service")
}

#[test]
fn contract_definition_and_secret_debug_are_layer_one_honest() {
    validate_contract().expect("contract");
    let definition = CodeDeployServiceDefinition::layer1();
    definition.validate().expect("definition");
    assert_eq!(definition.operations.len(), 8);
    assert!(definition.read_only);
    assert!(definition.proposal_only);
    assert!(definition.recording_only);
    assert!(!definition.external_writes);
    assert!(!definition.kernel_authority);
    assert!(!definition.outcome_adoption);

    let scope = scope();
    let secret = secret(&scope);
    let debug = format!("{secret:?}");
    assert!(!debug.contains("opaque-reference-1"));
    assert!(!ReadOnlyAuthority::deployment_effect());
    assert!(!ReadOnlyAuthority::raw_logs());
    assert!(!ReadOnlyAuthority::raw_scripts());
    assert!(!ReadOnlyAuthority::artifact_bytes());
}

#[test]
fn recording_flow_seals_scope_digests_and_mission_proposal() {
    let mut service = service_with_status(
        CodeDeployDeploymentStatus::Succeeded,
        CodeDeployTargetStatus::Succeeded,
        ProviderProvenance::Recording,
    );
    let evidence = service.read_evidence().expect("evidence");
    evidence.validate().expect("evidence validates");
    assert_eq!(evidence.state, CodeDeployResultState::Succeeded);
    assert_eq!(evidence.deployment_page_count, 1);
    assert_eq!(evidence.target_page_count, 1);
    assert!(!evidence.native_transport);
    assert!(!evidence.native_connected);

    let proposal = service.propose(&evidence).expect("proposal");
    assert_eq!(
        proposal.verification_status,
        ResultVerificationStatus::Verified
    );
    assert!(!proposal.external_effect_performed);
    assert!(!proposal.durable_adoption);
    assert!(!proposal.kernel_authority);

    let receipt = service.record(&evidence).expect("recording receipt");
    let verified = service
        .verify_deployment_result(&proposal, &evidence, &receipt)
        .expect("verification");
    let consumer = MissionAwsCodeDeployDeploymentConsumer::from_registration(
        service.provider().registration(),
    )
    .expect("consumer");
    let result = consumer.consume(&verified).expect("Mission proposal");
    result.validate().expect("Mission result");
    assert!(!result.outcome_adoption);
    assert!(!result.kernel_authority);
    assert_eq!(result.consumer_id, CONSUMER_ID);

    let requests = service.provider().transport().requests();
    assert!(requests.iter().any(|request| {
        matches!(
            request,
            CodeDeployTransportOperation::ListDeployments { .. }
        )
    }));
    assert!(
        requests.iter().any(|request| {
            matches!(request, CodeDeployTransportOperation::GetDeployment { .. })
        })
    );
    assert!(requests.iter().any(|request| {
        matches!(
            request,
            CodeDeployTransportOperation::ListDeploymentTargets { .. }
        )
    }));
}

#[test]
fn fixture_and_loopback_never_claim_connected_or_native_and_blocked_env_fails_closed() {
    for provenance in [ProviderProvenance::Fixture, ProviderProvenance::Loopback] {
        let mut service = service_with_status(
            CodeDeployDeploymentStatus::Succeeded,
            CodeDeployTargetStatus::Succeeded,
            provenance,
        );
        let evidence = service.read_evidence().expect("fixture evidence");
        assert_eq!(evidence.provenance, provenance);
        assert!(!evidence.provenance.is_native());
        assert!(!evidence.provenance.is_connected());
        let proposal = service.propose(&evidence).expect("proposal");
        assert!(!proposal.native_transport);
        assert!(!proposal.native_connected);
    }

    let scope = scope();
    let secret_reference = secret(&scope);
    let registration = CodeDeployRegistration::new(scope, secret_reference, 1);
    let registration = registration.expect("registration");
    let provider = CodeDeployProvider::new(registration, BlockedEnvCodeDeployTransport)
        .expect("blocked provider");
    let mut service = CodeDeployDeploymentResultService::new(provider).expect("service");
    assert!(matches!(
        service.read_evidence(),
        Err(AwsCodeDeployDeploymentResultError::Transport(
            AwsCodeDeployTransportError::BlockedEnv
        ))
    ));
}

#[test]
fn scope_and_revision_fences_reject_drift() {
    let mut service = service_with_status(
        CodeDeployDeploymentStatus::Succeeded,
        CodeDeployTargetStatus::Succeeded,
        ProviderProvenance::Recording,
    );
    let mut changed_scope = scope();
    changed_scope.application = ApplicationName::new("other-application").expect("application");
    let request = CodeDeployReadRequest::new(changed_scope).expect("request");
    assert!(matches!(
        service.read_deployment_evidence(&request),
        Err(AwsCodeDeployDeploymentResultError::ScopeMismatch)
    ));

    let scope = service.scope().clone();
    let changed_revision = CodeDeployRevision::new(
        RevisionId::new("revision-2").expect("revision id"),
        RevisionKind::S3,
        Digest::from_text("source-revision-2"),
    )
    .expect("changed revision");
    let mut changed_deployment = deployment(&scope, CodeDeployDeploymentStatus::Succeeded);
    changed_deployment.revision = changed_revision;
    service
        .provider_mut()
        .transport_mut()
        .set_deployment(changed_deployment);
    assert!(matches!(
        service.read_evidence(),
        Err(AwsCodeDeployDeploymentResultError::RevisionMismatch)
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn pagination_filter_and_response_bounds_fail_closed() {
    let mut service = service_with_status(
        CodeDeployDeploymentStatus::Succeeded,
        CodeDeployTargetStatus::Succeeded,
        ProviderProvenance::Recording,
    );
    let current_scope = service.scope().clone();
    let filter = DeploymentListFilter::exact(MAX_PAGE_SIZE).expect("filter");
    let cursor = OpaqueCursor::new("cursor-1").expect("cursor");
    let first = CodeDeployDeploymentPage::new(
        current_scope.digest(),
        filter.filter_digest.clone(),
        vec![current_scope.deployment.clone()],
        Some(cursor.clone()),
        100,
        false,
    )
    .expect("page");
    let second = CodeDeployDeploymentPage::new(
        current_scope.digest(),
        filter.filter_digest.clone(),
        Vec::new(),
        Some(cursor),
        100,
        false,
    )
    .expect("page");
    service
        .provider_mut()
        .transport_mut()
        .clear_queued_deployment_pages();
    service
        .provider_mut()
        .transport_mut()
        .push_deployment_page(Ok(first));
    service
        .provider_mut()
        .transport_mut()
        .push_deployment_page(Ok(second));
    assert!(matches!(
        service.read_evidence(),
        Err(AwsCodeDeployDeploymentResultError::PaginationLoop)
    ));

    let mut bounded = service_with_status(
        CodeDeployDeploymentStatus::Succeeded,
        CodeDeployTargetStatus::Succeeded,
        ProviderProvenance::Recording,
    );
    let scope = bounded.scope().clone();
    let page = CodeDeployDeploymentPage::new(
        scope.digest(),
        filter.filter_digest.clone(),
        vec![scope.deployment.clone()],
        Some(OpaqueCursor::new("cursor-bound").expect("cursor")),
        100,
        false,
    )
    .expect("page");
    bounded
        .provider_mut()
        .transport_mut()
        .clear_queued_deployment_pages();
    bounded
        .provider_mut()
        .transport_mut()
        .push_deployment_page(Ok(page));
    let request = CodeDeployReadRequest::with_bounds(scope, 1, MAX_DEPLOYMENTS, MAX_TARGETS)
        .expect("bounded request");
    assert!(matches!(
        bounded.read_deployment_evidence(&request),
        Err(AwsCodeDeployDeploymentResultError::PageLimitExceeded)
    ));

    let mut drifted = service_with_status(
        CodeDeployDeploymentStatus::Succeeded,
        CodeDeployTargetStatus::Succeeded,
        ProviderProvenance::Recording,
    );
    let scope = drifted.scope().clone();
    let wrong_filter = DeploymentListFilter::new(
        std::collections::BTreeSet::from([CodeDeployDeploymentStatus::Failed]),
        MAX_PAGE_SIZE,
    )
    .expect("wrong filter");
    let wrong_page = CodeDeployDeploymentPage::new(
        scope.digest(),
        wrong_filter.filter_digest,
        vec![scope.deployment.clone()],
        None,
        100,
        false,
    )
    .expect("wrong page");
    drifted
        .provider_mut()
        .transport_mut()
        .clear_queued_deployment_pages();
    drifted
        .provider_mut()
        .transport_mut()
        .push_deployment_page(Ok(wrong_page));
    assert!(matches!(
        drifted.read_evidence(),
        Err(AwsCodeDeployDeploymentResultError::EvidenceTampered)
    ));
}

#[test]
fn access_errors_target_scope_and_terminal_states_are_typed() {
    let mut denied = service_with_status(
        CodeDeployDeploymentStatus::Succeeded,
        CodeDeployTargetStatus::Succeeded,
        ProviderProvenance::Recording,
    );
    denied
        .provider_mut()
        .transport_mut()
        .set_fault(AwsCodeDeployTransportError::AccessLoss);
    assert!(matches!(
        denied.read_evidence(),
        Err(AwsCodeDeployDeploymentResultError::Transport(
            AwsCodeDeployTransportError::AccessLoss
        ))
    ));
    assert_eq!(
        denied.provider().state(),
        CodeDeployProviderState::AccessLoss
    );

    let mut wrong_target = service_with_status(
        CodeDeployDeploymentStatus::Succeeded,
        CodeDeployTargetStatus::Succeeded,
        ProviderProvenance::Recording,
    );
    let scope = wrong_target.scope().clone();
    let deployment = deployment(&scope, CodeDeployDeploymentStatus::Succeeded);
    let mut target = target(&scope, CodeDeployTargetStatus::Succeeded);
    target.deployment_group = DeploymentGroupName::new("wrong-group").expect("group");
    let page = CodeDeployTargetPage::new(
        scope.digest(),
        deployment.digest(),
        vec![target],
        None,
        100,
        false,
    )
    .expect("page");
    wrong_target
        .provider_mut()
        .transport_mut()
        .set_deployment(deployment);
    wrong_target
        .provider_mut()
        .transport_mut()
        .clear_queued_target_pages();
    wrong_target
        .provider_mut()
        .transport_mut()
        .set_target_page(page);
    assert!(matches!(
        wrong_target.read_evidence(),
        Err(AwsCodeDeployDeploymentResultError::TargetScopeMismatch)
    ));

    for (status, target_status, expected) in [
        (
            CodeDeployDeploymentStatus::InProgress,
            CodeDeployTargetStatus::InProgress,
            CodeDeployResultState::InProgress,
        ),
        (
            CodeDeployDeploymentStatus::Failed,
            CodeDeployTargetStatus::Failed,
            CodeDeployResultState::Failed,
        ),
        (
            CodeDeployDeploymentStatus::Stopped,
            CodeDeployTargetStatus::Skipped,
            CodeDeployResultState::Stopped,
        ),
    ] {
        let mut service = service_with_status(status, target_status, ProviderProvenance::Fixture);
        let evidence = service.read_evidence().expect("state evidence");
        assert_eq!(evidence.state, expected);
        assert_eq!(
            status.is_terminal(),
            !matches!(status, CodeDeployDeploymentStatus::InProgress)
        );
        assert_eq!(
            target_status.is_terminal(),
            !matches!(target_status, CodeDeployTargetStatus::InProgress)
        );
    }
}

#[test]
fn tamper_replay_recording_and_revocation_are_rejected() {
    let mut service = service_with_status(
        CodeDeployDeploymentStatus::Succeeded,
        CodeDeployTargetStatus::Succeeded,
        ProviderProvenance::Recording,
    );
    let evidence = service.read_evidence().expect("evidence");
    let receipt = service.record(&evidence).expect("receipt");
    let replay = service.record(&evidence).expect("idempotent replay");
    assert_eq!(replay, receipt);

    let mut tampered = evidence.clone();
    tampered.observed_sequence += 1;
    assert!(matches!(
        tampered.validate(),
        Err(AwsCodeDeployDeploymentResultError::EvidenceTampered)
    ));

    let mut conflicting = evidence.clone();
    conflicting.observed_sequence += 1;
    conflicting.evidence_digest = conflicting.computed_digest();
    assert!(matches!(
        service.record(&conflicting),
        Err(AwsCodeDeployDeploymentResultError::DuplicateEvidence)
    ));

    let mut proposal = service.propose(&evidence).expect("proposal");
    proposal.result_id.push_str("-tampered");
    assert!(matches!(
        service.verify_deployment_result(&proposal, &evidence, &receipt),
        Err(AwsCodeDeployDeploymentResultError::EvidenceTampered)
    ));

    service.revoke().expect("revocation");
    assert!(matches!(
        service.read_evidence(),
        Err(AwsCodeDeployDeploymentResultError::RegistrationRevoked)
    ));
    assert!(matches!(
        service.record(&evidence),
        Err(AwsCodeDeployDeploymentResultError::RegistrationRevoked)
    ));
}
