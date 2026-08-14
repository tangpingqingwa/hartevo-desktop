use std::{collections::VecDeque, fmt::Debug};

use hartevo_confluent_stream_result_plugin::{
    ApiKeyResourceScope, BlockedEnvTransport, ConfluentProvider, ConfluentProviderError,
    ConfluentRegistration, ConfluentScope, ConfluentStreamResultError,
    ConfluentStreamResultService, ConfluentTransport, ConfluentTransportError, ConnectorStatus,
    ConnectorStatusResponse, ConsumerGroupStatus, FakeTransport, LagPage, LagRecord, MetricKind,
    MetricPoint, MetricWindow, MetricsResponse, MissionConfluentStreamConsumer, PermissionSnapshot,
    ProjectionCompleteness, ProviderIdentity, RegistrationId, SecretReference,
    StreamResultRecordingLog, TaskStatus, TaskStatusRecord, TransportProvenance,
};

fn scope() -> ConfluentScope {
    ConfluentScope::from_ids(
        "org-confluent-1",
        "env-confluent-1",
        "lkc-confluent-1",
        "orders.events",
        "connector-orders-1",
        "orders-consumer-group",
        2,
        "project-confluent-1",
        "mission-confluent-1",
        "work-product-confluent-1",
        MetricWindow::new(1_744_550_400, 1_744_550_460).expect("window"),
        1,
    )
    .expect("scope")
}

fn registration(scope: ConfluentScope) -> ConfluentRegistration {
    ConfluentRegistration::new(
        RegistrationId::new("registration-confluent-1").expect("registration id"),
        scope,
        SecretReference::resource_scoped_api_key(
            "opaque-resource-scoped-api-key",
            ApiKeyResourceScope::CloudResourceManagement,
            1,
        )
        .expect("secret reference"),
        PermissionSnapshot::read_only(1).expect("permissions"),
        ProviderIdentity::new(1, "confluent-cloud-release-1").expect("provider"),
        1,
    )
    .expect("registration")
}

fn provider(scope: &ConfluentScope) -> ConfluentProvider<FakeTransport> {
    ConfluentProvider::new(
        registration(scope.clone()),
        FakeTransport::from_scope(scope),
    )
    .expect("provider")
}

fn response_set(
    connector: ConnectorStatusResponse,
    lag: LagPage,
    metrics: MetricsResponse,
) -> FakeTransport {
    FakeTransport::new(connector, vec![lag], metrics)
}

#[test]
fn connector_and_task_status_taxonomy_is_bounded_and_non_native() {
    for status in [
        ConnectorStatus::Provisioning,
        ConnectorStatus::Running,
        ConnectorStatus::Failed,
        ConnectorStatus::Degraded,
        ConnectorStatus::Paused,
        ConnectorStatus::Restarting,
        ConnectorStatus::ProviderUnknown,
    ] {
        let connector = ConnectorStatusResponse::new(
            &scope(),
            1,
            status,
            vec![TaskStatusRecord::new("task-1", 1, TaskStatus::Running, None).expect("task")],
            1_744_550_401,
            ProjectionCompleteness::Complete,
            512,
            TransportProvenance::Fixture,
        )
        .expect("connector response");
        let mut provider = provider_with_transport(
            &scope(),
            response_set(
                connector,
                LagPage::for_scope(&scope(), TransportProvenance::Fixture),
                MetricsResponse::for_scope(&scope(), TransportProvenance::Fixture),
            ),
        );
        let projection = provider.read_connector_status().expect("status projection");
        assert_eq!(projection.status, status);
        assert!(!projection.connected);
        assert!(!projection.native);
    }

    for status in [
        TaskStatus::Running,
        TaskStatus::Stopped,
        TaskStatus::Unassigned,
        TaskStatus::Restarting,
        TaskStatus::SystemError,
        TaskStatus::UserActionableError,
    ] {
        let current_scope = scope();
        let connector = ConnectorStatusResponse::new(
            &current_scope,
            1,
            ConnectorStatus::Running,
            vec![TaskStatusRecord::new("task-1", 1, status, None).expect("task")],
            1_744_550_401,
            ProjectionCompleteness::Complete,
            512,
            TransportProvenance::Fixture,
        )
        .expect("connector response");
        let mut provider = provider_with_transport(
            &current_scope,
            response_set(
                connector,
                LagPage::for_scope(&current_scope, TransportProvenance::Fixture),
                MetricsResponse::for_scope(&current_scope, TransportProvenance::Fixture),
            ),
        );
        assert_eq!(
            provider
                .read_connector_status()
                .expect("task projection")
                .tasks[0]
                .status,
            status
        );
    }
}

#[test]
fn consumer_group_taxonomy_and_digest_only_lag_projection_are_bounded() {
    for status in [
        ConsumerGroupStatus::Stable,
        ConsumerGroupStatus::Empty,
        ConsumerGroupStatus::Dead,
        ConsumerGroupStatus::Unknown,
    ] {
        let current_scope = scope();
        let lag = LagPage::new(
            &current_scope,
            1,
            status,
            1,
            vec![LagRecord::for_scope(&current_scope, 1_744_550_401)],
            None,
            1_744_550_401,
            ProjectionCompleteness::Complete,
            512,
            TransportProvenance::Fixture,
        )
        .expect("lag page");
        let mut provider = provider_with_transport(
            &current_scope,
            response_set(
                ConnectorStatusResponse::for_scope(&current_scope, TransportProvenance::Fixture),
                lag,
                MetricsResponse::for_scope(&current_scope, TransportProvenance::Fixture),
            ),
        );
        let projection = provider
            .read_consumer_group_lag(100)
            .expect("lag projection");
        assert_eq!(projection.status, status);
        assert_eq!(projection.partition_count, 1);
        assert!(!projection.connected);
        assert!(!projection.native);
        assert!(
            !serde_json::to_string(&projection)
                .expect("projection JSON")
                .contains("current_offset")
        );
    }
}

#[test]
fn every_exact_scope_component_has_a_specific_drift_fence() {
    let expected = scope();
    let cases = [
        ("organization", ConfluentProviderError::OrganizationDrift),
        ("environment", ConfluentProviderError::EnvironmentDrift),
        ("cluster", ConfluentProviderError::ClusterDrift),
        ("topic", ConfluentProviderError::TopicDrift),
        ("connector", ConfluentProviderError::ConnectorDrift),
        ("consumer_group", ConfluentProviderError::ConsumerGroupDrift),
        ("partition", ConfluentProviderError::PartitionDrift),
        ("project", ConfluentProviderError::ProjectDrift),
        ("mission", ConfluentProviderError::MissionDrift),
        ("work_product", ConfluentProviderError::WorkProductDrift),
    ];
    for (field, expected_error) in cases {
        let mut drifted = expected.clone();
        match field {
            "organization" => drifted.organization.id = "org-drift".to_owned(),
            "environment" => drifted.environment.id = "env-drift".to_owned(),
            "cluster" => drifted.cluster.id = "lkc-drift".to_owned(),
            "topic" => drifted.topic.name = "topic-drift".to_owned(),
            "connector" => drifted.connector.id = "connector-drift".to_owned(),
            "consumer_group" => drifted.consumer_group.id = "group-drift".to_owned(),
            "partition" => drifted.partition.id = 99,
            "project" => drifted.project.id = "project-drift".to_owned(),
            "mission" => drifted.mission.id = "mission-drift".to_owned(),
            "work_product" => drifted.work_product.id = "work-product-drift".to_owned(),
            _ => unreachable!("case is explicit"),
        }
        let connector = ConnectorStatusResponse::for_scope(&drifted, TransportProvenance::Fixture);
        let mut provider = provider_with_transport(
            &expected,
            response_set(
                connector,
                LagPage::for_scope(&expected, TransportProvenance::Fixture),
                MetricsResponse::for_scope(&expected, TransportProvenance::Fixture),
            ),
        );
        assert_eq!(
            provider
                .read_connector_status()
                .expect_err("drift accepted"),
            expected_error
        );
    }
}

#[test]
fn connector_and_group_observation_revisions_cannot_regress() {
    let current_scope = scope();
    let connector_one = ConnectorStatusResponse::new(
        &current_scope,
        2,
        ConnectorStatus::Running,
        vec![TaskStatusRecord::new("task-1", 2, TaskStatus::Running, None).expect("task")],
        1_744_550_401,
        ProjectionCompleteness::Complete,
        512,
        TransportProvenance::Fixture,
    )
    .expect("connector response");
    let connector_two = ConnectorStatusResponse::new(
        &current_scope,
        1,
        ConnectorStatus::Running,
        vec![TaskStatusRecord::new("task-1", 1, TaskStatus::Running, None).expect("task")],
        1_744_550_402,
        ProjectionCompleteness::Complete,
        512,
        TransportProvenance::Fixture,
    )
    .expect("connector response");
    let transport = SequenceConnectorTransport {
        connector_responses: VecDeque::from([connector_one, connector_two]),
        scope: current_scope.clone(),
    };
    let mut provider =
        ConfluentProvider::new(registration(current_scope.clone()), transport).expect("provider");
    provider.read_connector_status().expect("first status");
    assert_eq!(
        provider
            .read_connector_status()
            .expect_err("regression accepted"),
        ConfluentProviderError::ConnectorTaskMonotonicity
    );

    let page_one = LagPage::new(
        &current_scope,
        2,
        ConsumerGroupStatus::Stable,
        1,
        vec![LagRecord::for_scope(&current_scope, 1_744_550_401)],
        None,
        1_744_550_401,
        ProjectionCompleteness::Complete,
        512,
        TransportProvenance::Fixture,
    )
    .expect("first lag page");
    let page_two = LagPage::new(
        &current_scope,
        1,
        ConsumerGroupStatus::Stable,
        1,
        vec![LagRecord::for_scope(&current_scope, 1_744_550_402)],
        None,
        1_744_550_402,
        ProjectionCompleteness::Complete,
        512,
        TransportProvenance::Fixture,
    )
    .expect("second lag page");
    let transport = FakeTransport::new(
        ConnectorStatusResponse::for_scope(&current_scope, TransportProvenance::Fixture),
        vec![page_one, page_two],
        MetricsResponse::for_scope(&current_scope, TransportProvenance::Fixture),
    );
    let mut provider = provider_with_transport(&current_scope, transport);
    provider.read_consumer_group_lag(100).expect("first lag");
    assert_eq!(
        provider
            .read_consumer_group_lag(100)
            .expect_err("group regression accepted"),
        ConfluentProviderError::ConsumerGroupMonotonicity
    );
}

#[test]
fn metric_window_completeness_is_explicit_and_window_is_exact() {
    let current_scope = scope();
    let partial = MetricsResponse::new(
        &current_scope,
        vec![
            MetricPoint::new(
                MetricKind::Throughput,
                hartevo_confluent_stream_result_plugin::Digest::from_text("partial-throughput"),
                1_744_550_401,
            )
            .expect("point"),
        ],
        ProjectionCompleteness::Partial,
        512,
        TransportProvenance::Fixture,
    )
    .expect("partial response");
    let mut metric_provider = provider_with_transport(
        &current_scope,
        response_set(
            ConnectorStatusResponse::for_scope(&current_scope, TransportProvenance::Fixture),
            LagPage::for_scope(&current_scope, TransportProvenance::Fixture),
            partial,
        ),
    );
    let projection = metric_provider
        .read_metric_window()
        .expect("partial metrics");
    assert_eq!(projection.completeness, ProjectionCompleteness::Partial);
    assert!(projection.throughput_digest.is_some());
    assert!(projection.lag_digest.is_none());

    let mut out_of_window =
        MetricsResponse::for_scope(&current_scope, TransportProvenance::Fixture);
    out_of_window.points[0].observed_at_epoch_seconds = 1_744_550_399;
    let mut provider = provider_with_transport(
        &current_scope,
        response_set(
            ConnectorStatusResponse::for_scope(&current_scope, TransportProvenance::Fixture),
            LagPage::for_scope(&current_scope, TransportProvenance::Fixture),
            out_of_window,
        ),
    );
    assert_eq!(
        provider
            .read_metric_window()
            .expect_err("out-of-window metric accepted"),
        ConfluentProviderError::ResponseTampered
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn pagination_rate_limits_and_http_failures_are_bounded_and_surface_typed_errors() {
    let current_scope = scope();
    let page_one = LagPage::new(
        &current_scope,
        1,
        ConsumerGroupStatus::Stable,
        1,
        Vec::new(),
        Some("repeat-me".to_owned()),
        1_744_550_401,
        ProjectionCompleteness::Complete,
        512,
        TransportProvenance::Fixture,
    )
    .expect("page one");
    let page_two = LagPage::new(
        &current_scope,
        1,
        ConsumerGroupStatus::Stable,
        2,
        Vec::new(),
        Some("repeat-me".to_owned()),
        1_744_550_402,
        ProjectionCompleteness::Complete,
        512,
        TransportProvenance::Fixture,
    )
    .expect("page two");
    let mut provider = provider_with_transport(
        &current_scope,
        FakeTransport::new(
            ConnectorStatusResponse::for_scope(&current_scope, TransportProvenance::Fixture),
            vec![page_one, page_two],
            MetricsResponse::for_scope(&current_scope, TransportProvenance::Fixture),
        ),
    );
    assert_eq!(
        provider
            .read_consumer_group_lag(100)
            .expect_err("repeated token accepted"),
        ConfluentProviderError::PaginationLoop
    );

    let pages = (1..=16)
        .map(|page_number| {
            LagPage::new(
                &current_scope,
                1,
                ConsumerGroupStatus::Stable,
                page_number,
                Vec::new(),
                Some(format!("page-token-{page_number}")),
                1_744_550_400 + i64::try_from(page_number).expect("page number fits timestamp"),
                ProjectionCompleteness::Complete,
                512,
                TransportProvenance::Fixture,
            )
            .expect("bounded page")
        })
        .collect::<Vec<_>>();
    let mut provider = provider_with_transport(
        &current_scope,
        FakeTransport::new(
            ConnectorStatusResponse::for_scope(&current_scope, TransportProvenance::Fixture),
            pages,
            MetricsResponse::for_scope(&current_scope, TransportProvenance::Fixture),
        ),
    );
    assert_eq!(
        provider
            .read_consumer_group_lag(100)
            .expect_err("pagination limit accepted"),
        ConfluentProviderError::PaginationLimit
    );

    for error in [
        ConfluentTransportError::BadRequest,
        ConfluentTransportError::Unauthorized,
        ConfluentTransportError::Forbidden,
        ConfluentTransportError::NotFound,
        ConfluentTransportError::Conflict,
        ConfluentTransportError::RateLimited {
            retry_after_seconds: 3,
        },
        ConfluentTransportError::Timeout,
        ConfluentTransportError::ServerError { status: 503 },
        ConfluentTransportError::BackoffRequired,
        ConfluentTransportError::MalformedResponse,
        ConfluentTransportError::PartialResponse,
    ] {
        let mut failing = ConfluentProvider::new(
            registration(current_scope.clone()),
            FakeTransport::from_scope(&current_scope).fail_connector_with(error.clone()),
        )
        .expect("provider");
        assert_eq!(
            failing
                .read_connector_status()
                .expect_err("transport error hidden"),
            ConfluentProviderError::Transport(error)
        );
        assert!(!failing.connected());
        assert!(!failing.native());
    }
}

#[test]
fn response_tamper_request_tamper_and_replay_conflict_fail_closed() {
    let current_scope = scope();
    let mut tampered =
        ConnectorStatusResponse::for_scope(&current_scope, TransportProvenance::Fixture);
    tampered.status = ConnectorStatus::Failed;
    let mut tamper_provider = provider_with_transport(
        &current_scope,
        response_set(
            tampered,
            LagPage::for_scope(&current_scope, TransportProvenance::Fixture),
            MetricsResponse::for_scope(&current_scope, TransportProvenance::Fixture),
        ),
    );
    assert_eq!(
        tamper_provider
            .read_connector_status()
            .expect_err("response tamper accepted"),
        ConfluentProviderError::ResponseTampered
    );

    let wrong_request = WrongRequestTransport {
        response: ConnectorStatusResponse::for_scope(&current_scope, TransportProvenance::Loopback),
        scope: current_scope.clone(),
    };
    let mut wrong_provider =
        ConfluentProvider::new(registration(current_scope.clone()), wrong_request)
            .expect("provider");
    assert_eq!(
        wrong_provider
            .read_connector_status()
            .expect_err("request tamper accepted"),
        ConfluentProviderError::RequestTampered
    );

    let mut current_provider = provider(&current_scope);
    let connector = current_provider.read_connector_status().expect("connector");
    let group = current_provider
        .read_consumer_group_lag(100)
        .expect("group");
    let metrics = current_provider.read_metric_window().expect("metrics");
    let registration_digest = current_provider.registration().binding_digest().clone();
    let consumer = MissionConfluentStreamConsumer::new(current_scope.clone());
    let proposal = consumer
        .compile_proposal(
            registration_digest,
            &connector,
            &group,
            &metrics,
            "replay-key",
        )
        .expect("proposal");
    let mut log = StreamResultRecordingLog::default();
    let first = consumer.record(&mut log, &proposal).expect("recording");
    let replay = consumer.record(&mut log, &proposal).expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(log.len(), 1);

    let mut changed = proposal.clone();
    changed.connector_status = ConnectorStatus::Failed;
    changed.proposal_digest = changed.computed_digest();
    assert_eq!(
        consumer
            .record(&mut log, &changed)
            .expect_err("replay conflict accepted"),
        ConfluentStreamResultError::ReplayConflict
    );
}

#[test]
fn mission_revision_registration_revocation_and_secret_redaction_are_honest() {
    let current_scope = scope();
    assert_eq!(
        PermissionSnapshot::new(vec!["connector.write".to_owned()], 1)
            .expect_err("write permission accepted"),
        ConfluentStreamResultError::InvalidPermissionSnapshot
    );
    let mut secret = SecretReference::resource_scoped_api_key(
        "opaque-api-key-handle",
        ApiKeyResourceScope::Organization("org-confluent-1".to_owned()),
        1,
    )
    .expect("secret");
    assert!(!format!("{secret:?}").contains("opaque-api-key-handle"));
    let reg = registration(current_scope.clone());
    assert!(!format!("{reg:?}").contains("opaque-resource-scoped-api-key"));
    assert!(
        !serde_json::to_string(&reg)
            .expect("safe registration JSON")
            .contains("opaque-resource-scoped-api-key")
    );

    let mut current_provider = provider(&current_scope);
    let connector = current_provider.read_connector_status().expect("connector");
    let group = current_provider
        .read_consumer_group_lag(100)
        .expect("group");
    let metrics = current_provider.read_metric_window().expect("metrics");
    let consumer = MissionConfluentStreamConsumer::new(current_scope.clone());
    let proposal = consumer
        .compile_proposal_for_mission_revision(
            current_provider.registration().binding_digest().clone(),
            &connector,
            &group,
            &metrics,
            "mission-revision",
            current_scope.mission.revision + 1,
        )
        .expect_err("stale Mission accepted");
    assert_eq!(proposal, ConfluentStreamResultError::StaleMissionRevision);

    secret.revoke();
    let revoked = ConfluentRegistration::new(
        RegistrationId::new("registration-revoked-secret").expect("id"),
        current_scope.clone(),
        secret,
        PermissionSnapshot::read_only(1).expect("permissions"),
        ProviderIdentity::new(1, "confluent-cloud-release-1").expect("provider"),
        1,
    )
    .expect("registration");
    let mut revoked_provider =
        ConfluentProvider::new(revoked, FakeTransport::from_scope(&current_scope))
            .expect("provider");
    assert_eq!(
        revoked_provider
            .read_connector_status()
            .expect_err("revoked secret accepted"),
        ConfluentProviderError::SecretRevoked
    );

    let mut service =
        ConfluentStreamResultService::new(reg, FakeTransport::from_scope(&current_scope))
            .expect("service");
    let capabilities = service.describe_capabilities();
    assert!(capabilities.read_only);
    assert!(capabilities.proposal_only);
    assert!(capabilities.recording_only);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.can_produce);
    assert!(!capabilities.can_consume);
    assert!(!capabilities.can_register_generic_events);
    service.revoke_registration().expect("revoke");
    assert_eq!(
        service
            .read_connector_status()
            .expect_err("revoked registration accepted"),
        ConfluentProviderError::RegistrationRevoked
    );
}

#[test]
fn fixture_recording_loopback_and_blocked_env_never_claim_native_or_connected() {
    let current_scope = scope();
    for (transport, provenance) in [
        (
            Box::new(FakeTransport::from_scope(&current_scope)) as Box<dyn ConfluentTransport>,
            TransportProvenance::Fixture,
        ),
        (
            Box::new(
                hartevo_confluent_stream_result_plugin::RecordingTransport::from_scope(
                    &current_scope,
                ),
            ) as Box<dyn ConfluentTransport>,
            TransportProvenance::Recording,
        ),
        (
            Box::new(
                hartevo_confluent_stream_result_plugin::LoopbackTransport::from_scope(
                    &current_scope,
                ),
            ) as Box<dyn ConfluentTransport>,
            TransportProvenance::Loopback,
        ),
    ] {
        assert_eq!(transport.provenance(), provenance);
        assert!(!transport.provenance().is_native());
        assert!(!transport.provenance().claims_connected());
    }
    let blocked = BlockedEnvTransport;
    assert_eq!(blocked.provenance(), TransportProvenance::BlockedEnv);
    assert!(!blocked.provenance().is_native());
    assert!(!blocked.provenance().claims_connected());
}

fn provider_with_transport(
    current_scope: &ConfluentScope,
    transport: FakeTransport,
) -> ConfluentProvider<FakeTransport> {
    ConfluentProvider::new(registration(current_scope.clone()), transport).expect("provider")
}

#[derive(Debug)]
struct WrongRequestTransport {
    response: ConnectorStatusResponse,
    scope: ConfluentScope,
}

impl ConfluentTransport for WrongRequestTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn read_connector_status(
        &mut self,
        _request: &hartevo_confluent_stream_result_plugin::ConnectorStatusReadRequest,
    ) -> Result<ConnectorStatusResponse, ConfluentTransportError> {
        Ok(self.response.clone())
    }

    fn read_consumer_group_lag(
        &mut self,
        _request: &hartevo_confluent_stream_result_plugin::LagReadRequest,
    ) -> Result<LagPage, ConfluentTransportError> {
        Ok(LagPage::for_scope(
            &self.scope,
            TransportProvenance::Loopback,
        ))
    }

    fn read_metrics(
        &mut self,
        _request: &hartevo_confluent_stream_result_plugin::MetricsReadRequest,
    ) -> Result<MetricsResponse, ConfluentTransportError> {
        Ok(MetricsResponse::for_scope(
            &self.scope,
            TransportProvenance::Loopback,
        ))
    }
}

#[derive(Debug)]
struct SequenceConnectorTransport {
    connector_responses: VecDeque<ConnectorStatusResponse>,
    scope: ConfluentScope,
}

impl ConfluentTransport for SequenceConnectorTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn read_connector_status(
        &mut self,
        request: &hartevo_confluent_stream_result_plugin::ConnectorStatusReadRequest,
    ) -> Result<ConnectorStatusResponse, ConfluentTransportError> {
        let mut response = self
            .connector_responses
            .pop_front()
            .ok_or(ConfluentTransportError::NotFound)?;
        response.request_digest = request.request_digest.clone();
        Ok(response)
    }

    fn read_consumer_group_lag(
        &mut self,
        _request: &hartevo_confluent_stream_result_plugin::LagReadRequest,
    ) -> Result<LagPage, ConfluentTransportError> {
        Ok(LagPage::for_scope(
            &self.scope,
            TransportProvenance::Fixture,
        ))
    }

    fn read_metrics(
        &mut self,
        _request: &hartevo_confluent_stream_result_plugin::MetricsReadRequest,
    ) -> Result<MetricsResponse, ConfluentTransportError> {
        Ok(MetricsResponse::for_scope(
            &self.scope,
            TransportProvenance::Fixture,
        ))
    }
}
