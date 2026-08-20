use super::*;

#[derive(Clone)]
struct Fixtures {
    scope: EcsDeploymentScope,
    secret: SigV4SecretReference,
    service_observation: ServiceObservation,
    task_observation: TaskObservation,
    task_definition_observation: TaskDefinitionObservation,
}

impl Fixtures {
    fn new() -> Self {
        let account = AccountBinding::new(
            AccountId::new("123456789012").expect("account"),
            Revision::new(1).expect("account revision"),
        );
        let region = RegionBinding::new(
            AwsRegion::new("us-east-1").expect("region"),
            Revision::new(1).expect("region revision"),
        );
        let cluster = ClusterBinding::new(
            ClusterName::new("cluster-a").expect("cluster"),
            Revision::new(2).expect("cluster revision"),
        );
        let service = ServiceBinding::new(
            ServiceName::new("service-a").expect("service"),
            Revision::new(3).expect("service revision"),
        );
        let deployment = DeploymentBinding::with_generation(
            DeploymentId::new("ecs-svc/123").expect("deployment"),
            Revision::new(4).expect("deployment revision"),
            17,
        )
        .expect("deployment generation");
        let task_definition = TaskDefinitionBinding::new(
            TaskDefinitionFamily::new("hartevo-api").expect("task family"),
            Revision::new(9).expect("task definition revision"),
        );
        let task = TaskBinding::new(
            TaskId::new("task-a").expect("task"),
            Revision::new(1).expect("task revision"),
        );
        let mission = MissionBinding::new(
            MissionId::new("mission-a").expect("Mission"),
            Revision::new(8).expect("Mission revision"),
        );
        let project = ProjectBinding::new(
            ProjectId::new("project-a").expect("Project"),
            Revision::new(5).expect("Project revision"),
        );
        let work_product = WorkProductBinding::new(
            WorkProductId::new("work-product-a").expect("Work Product"),
            Revision::new(6).expect("Work Product revision"),
        );
        let consent = ConsentScope::all("consent-a", Revision::new(1).expect("consent revision"))
            .expect("consent");
        let permission = PermissionScope::readonly(
            account.clone(),
            Revision::new(2).expect("permission revision"),
            &consent,
        )
        .expect("permission");
        let scope = EcsDeploymentScope::new(
            account,
            region,
            cluster,
            service,
            deployment,
            task_definition,
            [task],
            mission,
            project,
            work_product,
            permission,
            consent,
        )
        .expect("scope");
        let secret =
            SigV4SecretReference::for_scope("vault/ecs/a", &scope, Revision::new(1).unwrap())
                .expect("secret reference");
        let service_observation = ServiceObservation::new(
            scope.service.clone(),
            ServiceStatus::Active,
            DeploymentRolloutState::Completed,
            3,
            2,
            1,
            scope.task_definition.clone(),
            scope.deployment.generation,
            [ServiceDeploymentObservation::new(
                scope.deployment.clone(),
                ServiceStatus::Active,
                DeploymentRolloutState::Completed,
                3,
                2,
                1,
                scope.task_definition.clone(),
            )],
        )
        .expect("service observation");
        let task_observation = TaskObservation::new(
            scope.tasks[0].clone(),
            scope.task_definition.clone(),
            TaskHealth::Healthy,
            TaskLastStatus::Running,
            None,
        )
        .expect("task observation");
        let task_definition_observation =
            TaskDefinitionObservation::new(scope.task_definition.clone(), ServiceStatus::Active);
        Self {
            scope,
            secret,
            service_observation,
            task_observation,
            task_definition_observation,
        }
    }

    fn provider_revision() -> ProviderRevision {
        ProviderRevision::new(AWS_ECS_API_REVISION).expect("provider revision")
    }

    fn bounds() -> ReadBounds {
        ReadBounds::default()
    }

    fn service_with(
        &self,
        transport: RecordingEcsTransport,
    ) -> EcsDeploymentResultService<RecordingEcsTransport> {
        EcsDeploymentResultService::new(
            self.scope.clone(),
            self.secret.clone(),
            EcsProvider::new(transport).expect("provider"),
        )
        .expect("service")
    }
}

fn queue_service_page(
    transport: &mut RecordingEcsTransport,
    fixtures: &Fixtures,
    response_bytes: usize,
) {
    let request = DescribeServicesRequest::for_scope(&fixtures.scope, Fixtures::bounds())
        .expect("DescribeServices request");
    transport.queue_describe_services(Ok(DescribeServicesPage::new(
        &request,
        1,
        vec![fixtures.service_observation.clone()],
        None,
        response_bytes,
        Fixtures::provider_revision(),
    )
    .expect("DescribeServices page")));
}

#[test]
fn contract_is_versioned_and_layer_one_only() {
    let contract = EcsDeploymentContract::baseline().expect("contract");
    assert_eq!(contract.digest(), contract_digest());
    assert_eq!(AWS_ECS_API_VERSION, "2014-11-13");
    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native());
    assert!(!Layer1Authority::kernel_authority());
    assert!(!Layer1Authority::adopted_outcome());
}

#[test]
fn describe_services_normalizes_counts_generation_and_deployment_state() {
    let fixtures = Fixtures::new();
    let mut transport = RecordingEcsTransport::fixture();
    queue_service_page(&mut transport, &fixtures, 128);
    let mut service = fixtures.service_with(transport);
    let result = service.read_describe_services().expect("read");
    let observation = &result.evidence.services[0];
    assert_eq!(observation.desired_count, 3);
    assert_eq!(observation.running_count, 2);
    assert_eq!(observation.pending_count, 1);
    assert_eq!(observation.deployment_generation, 17);
    assert_eq!(
        observation.deployment_status,
        DeploymentRolloutState::Completed
    );
    assert!(result.evidence.pagination.complete);
    assert!(!result.evidence.pagination.truncated);
    assert!(!result.evidence.authority.connected);
    assert!(!result.evidence.authority.native);
}

#[test]
fn describe_tasks_normalizes_health_last_status_and_redacts_stopped_reason() {
    let fixtures = Fixtures::new();
    let request = DescribeTasksRequest::for_scope(&fixtures.scope, Fixtures::bounds()).unwrap();
    let stopped = TaskObservation::from_api(
        fixtures.scope.tasks[0].clone(),
        fixtures.scope.task_definition.clone(),
        Some("UNHEALTHY"),
        "STOPPED",
        Some("private stopped reason with secret-like material"),
    )
    .unwrap();
    let mut transport = RecordingEcsTransport::fixture();
    transport.queue_describe_tasks(Ok(DescribeTasksPage::new(
        &request,
        1,
        vec![stopped.clone()],
        128,
        Fixtures::provider_revision(),
    )
    .unwrap()));
    let mut service = fixtures.service_with(transport);
    let result = service.read_describe_tasks().unwrap();
    assert_eq!(result.evidence.tasks[0].health, TaskHealth::Unhealthy);
    assert_eq!(
        result.evidence.tasks[0].last_status,
        TaskLastStatus::Stopped
    );
    let digest = result.evidence.tasks[0]
        .stopped_reason_digest
        .as_ref()
        .expect("redacted stopped reason digest");
    assert_ne!(
        digest,
        &Digest::from_text("private stopped reason with secret-like material")
    );
    let encoded = serde_json::to_string(&result.evidence).unwrap();
    assert!(!encoded.contains("private stopped reason"));
}

#[test]
fn describe_task_definition_is_family_and_revision_fenced() {
    let fixtures = Fixtures::new();
    let request =
        DescribeTaskDefinitionRequest::for_scope(&fixtures.scope, Fixtures::bounds()).unwrap();
    let mut transport = RecordingEcsTransport::fixture();
    transport.queue_describe_task_definition(Ok(DescribeTaskDefinitionPage::new(
        &request,
        1,
        fixtures.task_definition_observation.clone(),
        64,
        Fixtures::provider_revision(),
    )
    .unwrap()));
    let mut service = fixtures.service_with(transport);
    let result = service.read_describe_task_definition().unwrap();
    assert_eq!(
        result
            .evidence
            .task_definition
            .unwrap()
            .task_definition
            .revision
            .get(),
        9
    );
}

#[test]
fn list_tasks_cursor_and_filter_are_bound_without_retaining_token() {
    let fixtures = Fixtures::new();
    let first_request = ListTasksRequest::for_scope(
        &fixtures.scope,
        TaskFilter::all().with_desired_status(TaskLastStatus::Running),
        Fixtures::bounds(),
    )
    .unwrap();
    let opaque = OpaqueCursor::new("provider-next-token-secret").unwrap();
    let second_request = first_request.with_cursor(Some(opaque.clone())).unwrap();
    let mut transport = RecordingEcsTransport::fixture();
    transport.queue_list_tasks(Ok(ListTasksPage::new(
        &first_request,
        1,
        vec![fixtures.task_observation.clone()],
        Some(opaque.clone()),
        128,
        Fixtures::provider_revision(),
    )
    .unwrap()));
    transport.queue_list_tasks(Ok(ListTasksPage::new(
        &second_request,
        2,
        vec![],
        None,
        64,
        Fixtures::provider_revision(),
    )
    .unwrap()));
    let mut service = fixtures.service_with(transport);
    let result = service.read(first_request.clone()).unwrap();
    assert!(result.evidence.pagination.complete);
    assert_eq!(result.evidence.pagination.pages_observed, 2);
    assert_ne!(
        first_request.request_digest(),
        second_request.request_digest()
    );
    assert_eq!(first_request.query_digest(), second_request.query_digest());
    assert!(!format!("{opaque:?}").contains("provider-next-token-secret"));
    assert!(
        !serde_json::to_string(&result.evidence)
            .unwrap()
            .contains("provider-next-token-secret")
    );
}

#[test]
fn cursor_filter_binding_drift_is_rejected() {
    let fixtures = Fixtures::new();
    let request =
        ListTasksRequest::for_scope(&fixtures.scope, TaskFilter::all(), Fixtures::bounds())
            .unwrap();
    let cursor = OpaqueCursor::new("cursor")
        .unwrap()
        .bind(&Digest::from_text("wrong-filter"), 1);
    let mut tampered = request.clone();
    tampered.cursor = Some(cursor);
    assert!(tampered.validate_against(&fixtures.scope).is_err());
    let other_filter = TaskFilter::all().with_task_definition(TaskDefinitionBinding::new(
        TaskDefinitionFamily::new("different-family").unwrap(),
        Revision::new(1).unwrap(),
    ));
    assert!(
        ListTasksRequest::for_scope(&fixtures.scope, other_filter, Fixtures::bounds()).is_err()
    );
}

#[test]
fn scope_and_revision_drift_fail_closed() {
    let fixtures = Fixtures::new();
    let mut request =
        DescribeServicesRequest::for_scope(&fixtures.scope, Fixtures::bounds()).unwrap();
    request.scope_digest = Digest::from_text("scope-drift");
    let mut transport = RecordingEcsTransport::fixture();
    queue_service_page(&mut transport, &fixtures, 128);
    let mut service = fixtures.service_with(transport);
    assert!(matches!(
        service.read(request),
        Err(EcsDeploymentServiceError::Model(
            ModelError::ScopeMismatch { .. }
        ))
    ));

    let stale_service = ServiceObservation::new(
        fixtures.scope.service.clone(),
        ServiceStatus::Active,
        DeploymentRolloutState::Completed,
        3,
        2,
        1,
        fixtures.scope.task_definition.clone(),
        18,
        [],
    )
    .unwrap();
    let page_request =
        DescribeServicesRequest::for_scope(&fixtures.scope, Fixtures::bounds()).unwrap();
    let mut transport = RecordingEcsTransport::fixture();
    transport.queue_describe_services(Ok(DescribeServicesPage::new(
        &page_request,
        1,
        vec![stale_service],
        None,
        128,
        Fixtures::provider_revision(),
    )
    .unwrap()));
    let mut service = fixtures.service_with(transport);
    assert!(matches!(
        service.read_describe_services(),
        Err(EcsDeploymentServiceError::StaleDeploymentGeneration)
    ));
}

#[test]
fn stale_task_definition_revision_is_rejected() {
    let fixtures = Fixtures::new();
    let stale_definition = TaskDefinitionBinding::new(
        fixtures.scope.task_definition.family.clone(),
        Revision::new(10).unwrap(),
    );
    let stale_task = TaskObservation::new(
        fixtures.scope.tasks[0].clone(),
        stale_definition,
        TaskHealth::Healthy,
        TaskLastStatus::Running,
        None,
    )
    .unwrap();
    let request = DescribeTasksRequest::for_scope(&fixtures.scope, Fixtures::bounds()).unwrap();
    let mut transport = RecordingEcsTransport::fixture();
    transport.queue_describe_tasks(Ok(DescribeTasksPage::new(
        &request,
        1,
        vec![stale_task],
        64,
        Fixtures::provider_revision(),
    )
    .unwrap()));
    let mut service = fixtures.service_with(transport);
    assert!(matches!(
        service.read_describe_tasks(),
        Err(EcsDeploymentServiceError::StaleTaskDefinitionRevision)
    ));
}

#[test]
fn lifecycle_and_health_unknown_states_are_partial_not_connected() {
    let fixtures = Fixtures::new();
    let unknown_service = ServiceObservation::from_api(
        fixtures.scope.service.clone(),
        "NEW_FUTURE_STATE",
        "NEW_ROLLOUT_STATE",
        1,
        0,
        1,
        fixtures.scope.task_definition.clone(),
        fixtures.scope.deployment.generation,
        [],
    )
    .unwrap();
    let request = DescribeServicesRequest::for_scope(&fixtures.scope, Fixtures::bounds()).unwrap();
    let mut transport = RecordingEcsTransport::fixture();
    transport.queue_describe_services(Ok(DescribeServicesPage::new(
        &request,
        1,
        vec![unknown_service],
        None,
        64,
        Fixtures::provider_revision(),
    )
    .unwrap()));
    let mut service = fixtures.service_with(transport);
    let result = service.read_describe_services().unwrap();
    assert_eq!(result.evidence.state, EvidenceState::Partial);
    assert!(result.evidence.pagination.truncated);
    assert!(!result.evidence.authority.connected);
}

#[test]
fn partial_pagination_is_truncated_and_non_adoptable() {
    let fixtures = Fixtures::new();
    let bounds = ReadBounds::new(1, 256, 100, MAX_RESPONSE_BYTES, 6, 2).unwrap();
    let request = ListTasksRequest::for_scope(&fixtures.scope, TaskFilter::all(), bounds).unwrap();
    let cursor = OpaqueCursor::new("still-more").unwrap();
    let mut transport = RecordingEcsTransport::fixture();
    transport.queue_list_tasks(Ok(ListTasksPage::new(
        &request,
        1,
        vec![fixtures.task_observation.clone()],
        Some(cursor),
        64,
        Fixtures::provider_revision(),
    )
    .unwrap()));
    let mut service = fixtures.service_with(transport);
    let result = service.read(request).unwrap();
    assert_eq!(result.evidence.state, EvidenceState::Partial);
    assert!(result.evidence.pagination.truncated);
    assert!(!result.evidence.state.is_complete());
}

#[test]
fn retries_cover_throttled_and_server_then_success() {
    let fixtures = Fixtures::new();
    let request = DescribeServicesRequest::for_scope(&fixtures.scope, Fixtures::bounds()).unwrap();
    let page = DescribeServicesPage::new(
        &request,
        1,
        vec![fixtures.service_observation.clone()],
        None,
        64,
        Fixtures::provider_revision(),
    )
    .unwrap();
    let mut transport = RecordingEcsTransport::fixture();
    transport.queue_describe_services(Err(TransportError::from_status(429)));
    transport.queue_describe_services(Err(TransportError::from_status(503)));
    transport.queue_describe_services(Ok(page));
    let mut service = fixtures.service_with(transport);
    let result = service.read_describe_services().unwrap();
    assert_eq!(result.evidence.state, EvidenceState::Complete);
    assert_eq!(service.provider().transport().calls().len(), 3);
}

#[test]
fn typed_transport_failures_are_classified_and_non_native() {
    let fixtures = Fixtures::new();
    for (error, expected) in [
        (TransportError::from_status(403), EvidenceState::AccessLoss),
        (TransportError::from_status(404), EvidenceState::NotFound),
        (TransportError::from_status(429), EvidenceState::Throttled),
        (
            TransportError::from_status(500),
            EvidenceState::ProviderUnknown,
        ),
        (TransportError::timeout(), EvidenceState::ProviderUnknown),
    ] {
        let mut transport = RecordingEcsTransport::fixture();
        let request =
            DescribeServicesRequest::for_scope(&fixtures.scope, Fixtures::bounds()).unwrap();
        if error.failure.retryable() {
            transport.queue_describe_services(Err(error.clone()));
            transport.queue_describe_services(Err(error.clone()));
            transport.queue_describe_services(Err(error.clone()));
        } else {
            transport.queue_describe_services(Err(error));
        }
        let mut service = fixtures.service_with(transport);
        let result = service.read(request).unwrap();
        assert_eq!(result.evidence.state, expected);
        assert!(!result.evidence.authority.connected);
        assert!(!result.evidence.authority.native);
    }
}

#[test]
fn non_retryable_4xx_is_not_retried() {
    let fixtures = Fixtures::new();
    let mut transport = RecordingEcsTransport::fixture();
    let request = DescribeServicesRequest::for_scope(&fixtures.scope, Fixtures::bounds()).unwrap();
    transport.queue_describe_services(Err(TransportError::from_status(400)));
    let mut service = fixtures.service_with(transport);
    let _ = service.read(request).unwrap();
    assert_eq!(service.provider().transport().calls().len(), 1);
}

#[test]
fn registration_and_secret_revocation_are_operation_fences() {
    let fixtures = Fixtures::new();
    let mut transport = RecordingEcsTransport::fixture();
    queue_service_page(&mut transport, &fixtures, 64);
    let mut service = fixtures.service_with(transport);
    service.revoke_registration().unwrap();
    assert!(matches!(
        service.read_describe_services(),
        Err(EcsDeploymentServiceError::RegistrationRevoked)
    ));

    let mut transport = RecordingEcsTransport::fixture();
    queue_service_page(&mut transport, &fixtures, 64);
    let mut service = fixtures.service_with(transport);
    service.revoke_secret_reference().unwrap();
    assert!(matches!(
        service.read_describe_services(),
        Err(EcsDeploymentServiceError::Model(ModelError::Revoked))
    ));
}

#[test]
fn registration_reverse_and_restore_are_reversible_until_reverse() {
    let fixtures = Fixtures::new();
    let service = fixtures.service_with(RecordingEcsTransport::fixture());
    let mut registration = service.registration().clone();
    registration.revoke().unwrap();
    assert!(registration.restore().is_ok());
    registration.reverse().unwrap();
    assert!(registration.restore().is_err());
}

#[test]
fn stale_mission_and_consumer_revocation_block_consumption() {
    let fixtures = Fixtures::new();
    let request = DescribeServicesRequest::for_scope(&fixtures.scope, Fixtures::bounds()).unwrap();
    let mut transport = RecordingEcsTransport::fixture();
    transport.queue_describe_services(Ok(DescribeServicesPage::new(
        &request,
        1,
        vec![fixtures.service_observation.clone()],
        None,
        64,
        Fixtures::provider_revision(),
    )
    .unwrap()));
    let mut service = fixtures.service_with(transport);
    let proposal = service.propose(request).unwrap();
    let mut consumer =
        MissionEcsDeploymentConsumer::new(fixtures.scope.clone(), service.registration().clone())
            .unwrap();
    consumer.replace_mission(MissionBinding::new(
        MissionId::new("mission-a").unwrap(),
        Revision::new(99).unwrap(),
    ));
    assert!(matches!(
        consumer.consume(&proposal),
        Err(ConsumerError::StaleMission)
    ));
    consumer.replace_mission(fixtures.scope.mission.clone());
    consumer.revoke();
    assert!(matches!(
        consumer.consume(&proposal),
        Err(ConsumerError::Revoked)
    ));
}

#[test]
fn consumer_recording_is_redacted_idempotent_and_conflict_checked() {
    let fixtures = Fixtures::new();
    let request = DescribeServicesRequest::for_scope(&fixtures.scope, Fixtures::bounds()).unwrap();
    let mut transport = RecordingEcsTransport::fixture();
    transport.queue_describe_services(Ok(DescribeServicesPage::new(
        &request,
        1,
        vec![fixtures.service_observation.clone()],
        None,
        64,
        Fixtures::provider_revision(),
    )
    .unwrap()));
    let mut service = fixtures.service_with(transport);
    let proposal = service.propose(request).unwrap();
    let mut consumer =
        MissionEcsDeploymentConsumer::new(fixtures.scope.clone(), service.registration().clone())
            .unwrap();
    let first = consumer.record(&proposal, "idempotency-a").unwrap();
    assert!(!first.replayed);
    let replay = consumer.record(&proposal, "idempotency-a").unwrap();
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    let mut changed = proposal.clone();
    changed.proposal_digest = Digest::from_text("tampered-proposal");
    assert!(matches!(
        consumer.record(&changed, "idempotency-a"),
        Err(ConsumerError::ProposalTampered)
    ));
}

#[test]
fn tampered_evidence_proposal_and_record_are_rejected() {
    let fixtures = Fixtures::new();
    let request = DescribeServicesRequest::for_scope(&fixtures.scope, Fixtures::bounds()).unwrap();
    let mut transport = RecordingEcsTransport::fixture();
    queue_service_page(&mut transport, &fixtures, 64);
    let mut service = fixtures.service_with(transport);
    let mut proposal = service.propose(request).unwrap();
    proposal.evidence.digests.evidence_digest = Digest::from_text("tampered-evidence");
    assert!(matches!(
        proposal.validate(),
        Err(EcsDeploymentServiceError::EvidenceTampered)
    ));

    let mut transport = RecordingEcsTransport::fixture();
    queue_service_page(&mut transport, &fixtures, 64);
    let mut service = fixtures.service_with(transport);
    let proposal = service
        .propose(DescribeServicesRequest::for_scope(&fixtures.scope, Fixtures::bounds()).unwrap())
        .unwrap();
    let mut record = service.record(&proposal, "record-a").unwrap();
    record.recording_digest = Digest::from_text("tampered-record");
    assert!(matches!(
        service.verify(&proposal, &record),
        Err(EcsDeploymentServiceError::RecordTampered)
    ));
}

#[test]
fn duplicate_items_and_oversized_pages_fail_closed() {
    let fixtures = Fixtures::new();
    let request = DescribeTasksRequest::for_scope(&fixtures.scope, Fixtures::bounds()).unwrap();
    let mut transport = RecordingEcsTransport::fixture();
    transport.queue_describe_tasks(Ok(DescribeTasksPage::new(
        &request,
        1,
        vec![
            fixtures.task_observation.clone(),
            fixtures.task_observation.clone(),
        ],
        64,
        Fixtures::provider_revision(),
    )
    .unwrap()));
    let mut service = fixtures.service_with(transport);
    assert!(matches!(
        service.read_describe_tasks(),
        Err(EcsDeploymentServiceError::Provider(
            EcsProviderError::DuplicateItem
        ))
    ));

    let mut transport = RecordingEcsTransport::fixture();
    let request = DescribeServicesRequest::for_scope(
        &fixtures.scope,
        ReadBounds::new(1, 256, 100, 32, 6, 2).unwrap(),
    )
    .unwrap();
    transport.queue_describe_services(Ok(DescribeServicesPage::new(
        &request,
        1,
        vec![fixtures.service_observation.clone()],
        None,
        128,
        Fixtures::provider_revision(),
    )
    .unwrap()));
    let mut service = fixtures.service_with(transport);
    assert!(matches!(
        service.read(request),
        Err(EcsDeploymentServiceError::Provider(
            EcsProviderError::PageBinding
        ))
    ));
}

#[test]
fn blocked_env_fixture_recording_and_loopback_never_claim_native_or_connected() {
    let fixtures = Fixtures::new();
    for provenance in [
        ProviderProvenance::Fixture,
        ProviderProvenance::Recording,
        ProviderProvenance::Loopback,
        ProviderProvenance::BlockedEnv,
    ] {
        assert!(!provenance.native());
        assert!(!provenance.connected());
        assert!(!provenance.first_party());
    }
    let provider = EcsProvider::<BlockedEnvTransport>::default();
    assert!(!provider.identity().native);
    assert!(!provider.identity().connected);
    let mut service =
        EcsDeploymentResultService::new(fixtures.scope, fixtures.secret, provider).unwrap();
    let result = service.read_describe_services().unwrap();
    assert_eq!(result.evidence.state, EvidenceState::ProviderUnknown);
    assert_eq!(
        result.evidence.provider_errors[0].kind,
        ProviderErrorKind::BlockedEnv
    );
    assert!(!result.evidence.authority.connected);
    assert!(!result.evidence.authority.native);
}

#[test]
fn opaque_secret_reference_never_leaks_debug_or_registration_payload() {
    let fixtures = Fixtures::new();
    let debug = format!("{:?}", fixtures.secret);
    assert!(!debug.contains("vault/ecs/a"));
    let service = fixtures.service_with(RecordingEcsTransport::fixture());
    let encoded = serde_json::to_string(service.registration()).unwrap();
    assert!(!encoded.contains("vault/ecs/a"));
    assert!(!encoded.contains("secretMaterial"));
}

#[test]
fn permission_and_consent_digest_fences_reject_drift() {
    let fixtures = Fixtures::new();
    let mut scope = fixtures.scope.clone();
    scope.permission.permission_digest = Digest::from_text("permission-drift");
    let secret =
        SigV4SecretReference::for_scope("vault/ecs/a", &scope, Revision::new(1).unwrap()).unwrap();
    assert!(
        EcsDeploymentResultService::new(
            scope,
            secret,
            EcsProvider::new(RecordingEcsTransport::fixture()).unwrap(),
        )
        .is_err()
    );
}
