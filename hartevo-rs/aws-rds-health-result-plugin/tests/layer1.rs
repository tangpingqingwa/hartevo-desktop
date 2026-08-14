use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_rds_health_result_plugin::{
    AwsRdsHealthScope, AwsRdsHealthService, AwsRdsHealthState, AwsRdsProvider, AwsRdsReadOperation,
    AwsRdsReadPage, AwsRdsTarget, AwsRdsTransportError, BlockedEnvAwsRdsTransport,
    DeploymentBinding, DeploymentId, Digest, EndpointPresence, EngineFamily, EngineVersionFamily,
    FixtureAwsRdsTransport, MissionAwsRdsConsumer, MissionBinding, MissionId, OpaqueCursor,
    PermissionFence, PermissionId, ProjectBinding, ProjectId, RdsDatabaseObservation,
    RdsEngineScope, RdsEventCategory, RdsEventSeverity, RdsEventSummary, RdsMaintenanceCategory,
    RdsMaintenanceStatus, RdsMaintenanceSummary, RdsTimeWindow, Revision, SecretReference,
    WorkProductBinding, WorkProductId, contract_digest,
};
use serde_json::json;

const NOW_SECONDS: i64 = 1_800_000_000;

fn at() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid test timestamp")
}

fn permission() -> PermissionFence {
    PermissionFence::readonly(
        PermissionId::new("rds-health-read").expect("permission id"),
        Revision::new(4).expect("permission revision"),
    )
    .expect("permission fence")
}

fn scope() -> AwsRdsHealthScope {
    let permission = permission();
    AwsRdsHealthScope::new(
        DeploymentBinding::new(
            DeploymentId::new("deployment-1").expect("deployment id"),
            Revision::new(8).expect("deployment revision"),
        ),
        MissionBinding::new(
            MissionId::new("mission-1").expect("mission id"),
            Revision::new(9).expect("mission revision"),
        ),
        ProjectBinding::new(
            ProjectId::new("project-1").expect("project id"),
            Revision::new(10).expect("project revision"),
        ),
        WorkProductBinding::new(
            WorkProductId::new("work-product-1").expect("work product id"),
            Revision::new(11).expect("work product revision"),
        ),
        hartevo_aws_rds_health_result_plugin::AccountId::aws("123456789012").expect("account id"),
        hartevo_aws_rds_health_result_plugin::AwsRegion::aws("us-east-1").expect("region"),
        AwsRdsTarget::instance(
            hartevo_aws_rds_health_result_plugin::DbIdentifier::aws("orders")
                .expect("database identifier"),
            hartevo_aws_rds_health_result_plugin::RdsArn::aws(
                "arn:aws:rds:us-east-1:123456789012:db:orders",
            )
            .expect("database ARN"),
        )
        .expect("instance target"),
        RdsEngineScope::new(
            EngineFamily::aws("postgres").expect("engine"),
            EngineVersionFamily::aws("15").expect("engine version"),
        )
        .expect("engine scope"),
        Revision::new(12).expect("database revision"),
        RdsTimeWindow::recent(at(), Duration::hours(24)).expect("time window"),
        permission.digest(),
    )
    .expect("scope")
}

fn secret(scope: &AwsRdsHealthScope) -> SecretReference {
    SecretReference::for_rds("host-owned-opaque-sigv4-reference", scope.region().clone())
        .expect("secret reference")
}

fn request(
    scope: &AwsRdsHealthScope,
    operation: AwsRdsReadOperation,
) -> hartevo_aws_rds_health_result_plugin::AwsRdsReadRequest {
    hartevo_aws_rds_health_result_plugin::AwsRdsReadRequest::for_scope(
        scope, operation, 50, 4, None,
    )
    .expect("bounded request")
}

fn database_page(
    scope: &AwsRdsHealthScope,
    request: &hartevo_aws_rds_health_result_plugin::AwsRdsReadRequest,
    next: Option<&str>,
) -> AwsRdsReadPage {
    AwsRdsReadPage::database(
        request,
        RdsDatabaseObservation::for_scope(
            scope,
            hartevo_aws_rds_health_result_plugin::RdsDbStatus::Available,
            EndpointPresence::Present,
            scope.db_revision(),
        ),
        next,
        512,
    )
    .expect("database page")
}

fn events_page(
    scope: &AwsRdsHealthScope,
    request: &hartevo_aws_rds_health_result_plugin::AwsRdsReadRequest,
) -> AwsRdsReadPage {
    let event = RdsEventSummary::new(
        "event-1",
        scope.target().identifier().as_str(),
        RdsEventCategory::Availability,
        RdsEventSeverity::Informational,
        at() - Duration::minutes(10),
        "raw event message must not be retained",
    )
    .expect("event");
    AwsRdsReadPage::events(request, vec![event], None::<&str>, 512).expect("events page")
}

fn maintenance_page(
    request: &hartevo_aws_rds_health_result_plugin::AwsRdsReadRequest,
) -> AwsRdsReadPage {
    let maintenance = RdsMaintenanceSummary::new(
        "system-update",
        RdsMaintenanceCategory::SystemUpdate,
        RdsMaintenanceStatus::Complete,
        None,
        "raw maintenance detail must not be retained",
    )
    .expect("maintenance");
    AwsRdsReadPage::maintenance(request, vec![maintenance], None::<&str>, 512)
        .expect("maintenance page")
}

fn healthy_service() -> AwsRdsHealthService<FixtureAwsRdsTransport> {
    let scope = scope();
    let database_request = request(&scope, AwsRdsReadOperation::DescribeDbInstances);
    let events_request = request(&scope, AwsRdsReadOperation::DescribeEvents);
    let maintenance_request = request(
        &scope,
        AwsRdsReadOperation::DescribePendingMaintenanceActions,
    );
    let transport = FixtureAwsRdsTransport::new([
        Ok(database_page(&scope, &database_request, None)),
        Ok(events_page(&scope, &events_request)),
        Ok(maintenance_page(&maintenance_request)),
    ]);
    let secret_reference = secret(&scope);
    AwsRdsHealthService::new(
        scope,
        secret_reference,
        permission(),
        AwsRdsProvider::new(transport).expect("provider"),
    )
    .expect("service")
}

#[test]
fn contract_secret_and_scope_are_digest_fenced() {
    assert_eq!(
        contract_digest().as_str(),
        hartevo_aws_rds_health_result_plugin::CONTRACT_DIGEST
    );
    let scope = scope();
    let secret = secret(&scope);
    let encoded = serde_json::to_string(&secret).expect("opaque secret JSON");
    let debug = format!("{secret:?}");
    assert_eq!(encoded, r#"{"opaque":true}"#);
    assert!(!encoded.contains("host-owned-opaque-sigv4-reference"));
    assert!(!debug.contains("host-owned-opaque-sigv4-reference"));
    assert!(secret.is_opaque());

    let mut tampered = scope.clone();
    tampered.scope_digest = Digest::from_text("tampered-scope");
    assert!(tampered.validate().is_err());

    let mismatched = hartevo_aws_rds_health_result_plugin::AwsRdsReadRequest::for_scope(
        &scope,
        AwsRdsReadOperation::DescribeDbClusters,
        50,
        4,
        None,
    );
    assert!(mismatched.is_err());
}

#[test]
fn happy_path_proposes_records_verifies_and_consumes_mission_decision() {
    let mut service = healthy_service();
    let read = service.read().expect("bounded read");
    assert_eq!(read.evidence.state, AwsRdsHealthState::Healthy);
    assert!(read.evidence.complete);
    assert_eq!(
        read.evidence.provenance,
        hartevo_aws_rds_health_result_plugin::TransportProvenance::Fixture
    );
    assert!(!read.evidence.connected);
    assert!(!read.evidence.native);
    assert!(!read.evidence.first_party);
    assert!(read.evidence.validate(service.scope()).is_ok());

    let mut service = healthy_service();
    let proposal = service.propose(at()).expect("proposal");
    assert!(service.verify_proposal(&proposal).is_ok());
    assert!(service.verify_proposal_report(&proposal).is_valid());
    let receipt = service.record_at(&proposal, at()).expect("record");
    let verified = service.verify(&receipt).expect("verified record");
    assert!(verified.verified);
    assert!(!verified.outcome_adopted);

    let mut consumer =
        MissionAwsRdsConsumer::new(service.scope().clone(), service.registration().clone())
            .expect("Mission consumer");
    let result = consumer.consume(&proposal).expect("Mission result");
    assert_eq!(
        result.decision,
        hartevo_aws_rds_health_result_plugin::MissionAwsRdsDecision::Proceed
    );
    assert!(result.review_only);
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.first_party);
    assert_eq!(result.project.revision, service.scope().project.revision);
    assert_eq!(result.mission.revision, service.scope().mission.revision);
    assert_eq!(
        result.work_product.revision,
        service.scope().work_product.revision
    );
    assert!(!result.can_be_adopted());
    let first = consumer
        .record(&proposal, "mission-record-1")
        .expect("first record");
    let replay = consumer
        .record(&proposal, "mission-record-1")
        .expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert!(consumer.verify_record(&replay).is_ok());
}

#[test]
fn registration_revoke_and_restore_fail_closed() {
    let mut service = healthy_service();
    let revoked = service.revoke_registration().expect("revoke registration");
    assert_eq!(
        revoked.to,
        hartevo_aws_rds_health_result_plugin::RegistrationState::Revoked
    );
    assert!(!service.is_active());
    assert!(matches!(
        service.read(),
        Err(hartevo_aws_rds_health_result_plugin::AwsRdsServiceError::RegistrationRevoked)
    ));
    let restored = service
        .restore_registration()
        .expect("restore registration");
    assert_eq!(
        restored.to,
        hartevo_aws_rds_health_result_plugin::RegistrationState::Active
    );
    assert!(service.is_active());
}

#[test]
fn cursor_replay_and_page_budget_are_partial_not_success() {
    let scope = scope();
    let first_request = request(&scope, AwsRdsReadOperation::DescribeDbInstances);
    let second_request = first_request
        .with_cursor(Some(
            OpaqueCursor::new("same-cursor")
                .expect("cursor")
                .bind(&first_request.query_digest(), 2)
                .expect("page-two cursor"),
        ))
        .expect("bound cursor");
    let events_request = request(&scope, AwsRdsReadOperation::DescribeEvents);
    let maintenance_request = request(
        &scope,
        AwsRdsReadOperation::DescribePendingMaintenanceActions,
    );
    let transport = FixtureAwsRdsTransport::new([
        Ok(database_page(&scope, &first_request, Some("same-cursor"))),
        Ok(database_page(&scope, &second_request, Some("same-cursor"))),
        Ok(events_page(&scope, &events_request)),
        Ok(maintenance_page(&maintenance_request)),
    ]);
    let mut service = AwsRdsHealthService::new(
        scope.clone(),
        secret(&scope),
        permission(),
        AwsRdsProvider::new(transport).expect("provider"),
    )
    .expect("service");
    let replay = service.read().expect("replay evidence");
    assert_eq!(replay.evidence.state, AwsRdsHealthState::Partial);
    assert_eq!(
        replay.evidence.partial_reason,
        Some(hartevo_aws_rds_health_result_plugin::PartialReason::CursorReplay)
    );

    let db_request = hartevo_aws_rds_health_result_plugin::AwsRdsReadRequest::for_scope(
        &scope,
        AwsRdsReadOperation::DescribeDbInstances,
        50,
        1,
        None,
    )
    .expect("limited database request");
    let limited_events_request =
        hartevo_aws_rds_health_result_plugin::AwsRdsReadRequest::for_scope(
            &scope,
            AwsRdsReadOperation::DescribeEvents,
            50,
            1,
            None,
        )
        .expect("limited events request");
    let limited_maintenance_request =
        hartevo_aws_rds_health_result_plugin::AwsRdsReadRequest::for_scope(
            &scope,
            AwsRdsReadOperation::DescribePendingMaintenanceActions,
            50,
            1,
            None,
        )
        .expect("limited maintenance request");
    let transport = FixtureAwsRdsTransport::new([
        Ok(database_page(&scope, &db_request, Some("next-page"))),
        Ok(events_page(&scope, &limited_events_request)),
        Ok(maintenance_page(&limited_maintenance_request)),
    ]);
    let mut service = AwsRdsHealthService::new(
        scope.clone(),
        secret(&scope),
        permission(),
        AwsRdsProvider::new(transport).expect("provider"),
    )
    .expect("service");
    let limited = service.read_bounded(1).expect("bounded partial evidence");
    assert_eq!(limited.evidence.state, AwsRdsHealthState::Partial);
    assert_eq!(
        limited.evidence.partial_reason,
        Some(hartevo_aws_rds_health_result_plugin::PartialReason::PageBudget)
    );
}

#[test]
fn access_loss_throttle_timeout_and_blocked_env_never_claim_native() {
    let scope = scope();
    let requests = [
        request(&scope, AwsRdsReadOperation::DescribeDbInstances),
        request(&scope, AwsRdsReadOperation::DescribeEvents),
        request(
            &scope,
            AwsRdsReadOperation::DescribePendingMaintenanceActions,
        ),
    ];
    for (error, expected) in [
        (
            AwsRdsTransportError::Forbidden,
            AwsRdsHealthState::AccessLoss,
        ),
        (
            AwsRdsTransportError::RateLimited {
                retry_after_seconds: Some(30),
            },
            AwsRdsHealthState::Throttled,
        ),
        (AwsRdsTransportError::Timeout, AwsRdsHealthState::TimedOut),
    ] {
        let transport = FixtureAwsRdsTransport::new([
            Err(error.clone()),
            Ok(events_page(&scope, &requests[1])),
            Ok(maintenance_page(&requests[2])),
        ]);
        let mut service = AwsRdsHealthService::new(
            scope.clone(),
            secret(&scope),
            permission(),
            AwsRdsProvider::new(transport).expect("provider"),
        )
        .expect("service");
        let evidence = service.read().expect("failure evidence").evidence;
        assert_eq!(evidence.state, expected);
        assert!(!evidence.connected);
        assert!(!evidence.native);
        assert!(!evidence.first_party);
    }

    let mut blocked = AwsRdsHealthService::new(
        scope.clone(),
        secret(&scope),
        permission(),
        AwsRdsProvider::new(BlockedEnvAwsRdsTransport).expect("blocked provider"),
    )
    .expect("blocked service");
    let evidence = blocked.read().expect("blocked evidence").evidence;
    assert_eq!(
        evidence.provenance,
        hartevo_aws_rds_health_result_plugin::TransportProvenance::BlockedEnv
    );
    assert_eq!(evidence.state, AwsRdsHealthState::ProviderUnknown);
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert!(!evidence.first_party);
}

#[test]
fn revision_drift_and_event_retention_gap_fail_closed() {
    let scope = scope();
    let database_request = request(&scope, AwsRdsReadOperation::DescribeDbInstances);
    let events_request = request(&scope, AwsRdsReadOperation::DescribeEvents);
    let maintenance_request = request(
        &scope,
        AwsRdsReadOperation::DescribePendingMaintenanceActions,
    );
    let drifted = RdsDatabaseObservation::for_scope(
        &scope,
        hartevo_aws_rds_health_result_plugin::RdsDbStatus::Available,
        EndpointPresence::Present,
        Revision::new(scope.db_revision().get() + 1).expect("drifted revision"),
    );
    let drift_page = AwsRdsReadPage::database(&database_request, drifted, None::<&str>, 512)
        .expect("drift page");
    let transport = FixtureAwsRdsTransport::new([
        Ok(drift_page),
        Ok(events_page(&scope, &events_request)),
        Ok(maintenance_page(&maintenance_request)),
    ]);
    let mut service = AwsRdsHealthService::new(
        scope.clone(),
        secret(&scope),
        permission(),
        AwsRdsProvider::new(transport).expect("provider"),
    )
    .expect("service");
    let evidence = service.read().expect("revision evidence").evidence;
    assert_eq!(evidence.state, AwsRdsHealthState::Partial);
    assert_eq!(
        evidence.partial_reason,
        Some(hartevo_aws_rds_health_result_plugin::PartialReason::RevisionDrift)
    );

    let database_request = request(&scope, AwsRdsReadOperation::DescribeDbInstances);
    let events_request = request(&scope, AwsRdsReadOperation::DescribeEvents);
    let maintenance_request = request(
        &scope,
        AwsRdsReadOperation::DescribePendingMaintenanceActions,
    );
    let event = RdsEventSummary::new(
        "event-gap",
        scope.target().identifier().as_str(),
        RdsEventCategory::Failure,
        RdsEventSeverity::Critical,
        at() - Duration::minutes(5),
        "bounded event text",
    )
    .expect("event");
    let events = vec![event; hartevo_aws_rds_health_result_plugin::MAX_EVENTS + 1];
    let oversized_events =
        AwsRdsReadPage::events(&events_request, events, None::<&str>, 512).expect("events");
    let transport = FixtureAwsRdsTransport::new([
        Ok(database_page(&scope, &database_request, None)),
        Ok(oversized_events),
        Ok(maintenance_page(&maintenance_request)),
    ]);
    let mut service = AwsRdsHealthService::new(
        scope.clone(),
        secret(&scope),
        permission(),
        AwsRdsProvider::new(transport).expect("provider"),
    )
    .expect("service");
    let evidence = service.read().expect("event evidence").evidence;
    assert_eq!(evidence.state, AwsRdsHealthState::Partial);
    assert_eq!(
        evidence.partial_reason,
        Some(hartevo_aws_rds_health_result_plugin::PartialReason::EventRetentionGap)
    );
}

#[test]
fn provider_json_is_bounded_redacted_and_rejects_target_arn_mismatch() {
    let scope = scope();
    let request = request(&scope, AwsRdsReadOperation::DescribeDbInstances);
    let raw = serde_json::to_vec(&json!({
        "DBInstances": [{
            "DBInstanceIdentifier": "orders",
            "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:orders",
            "Engine": "postgres",
            "EngineVersion": "15.4",
            "DBInstanceStatus": "available",
            "Endpoint": {"Address": "orders.example.invalid", "Port": 5432},
            "MasterUsername": "do-not-retain"
        }]
    }))
    .expect("JSON");
    let page = AwsRdsProvider::<FixtureAwsRdsTransport>::parse_json_page(&request, 200, &raw)
        .expect("normalized page");
    let serialized = serde_json::to_string(&page).expect("page JSON");
    assert!(!serialized.contains("orders.example.invalid"));
    assert!(!serialized.contains("do-not-retain"));
    assert!(serialized.contains("endpointPresence"));

    let mismatched = serde_json::to_vec(&json!({
        "DBInstances": [{
            "DBInstanceIdentifier": "orders",
            "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:other",
            "Engine": "postgres",
            "EngineVersion": "15.4",
            "DBInstanceStatus": "available",
            "Endpoint": {"Address": "orders.example.invalid"}
        }]
    }))
    .expect("JSON");
    assert!(matches!(
        AwsRdsProvider::<FixtureAwsRdsTransport>::parse_json_page(&request, 200, &mismatched),
        Err(AwsRdsTransportError::RequestMismatch)
    ));
}

#[test]
fn tamper_and_replay_are_rejected_without_claiming_receipts() {
    let mut service = healthy_service();
    let mut proposal = service.propose(at()).expect("proposal");
    proposal.connected = true;
    assert!(matches!(
        service.verify_proposal(&proposal),
        Err(hartevo_aws_rds_health_result_plugin::AwsRdsServiceError::ProposalTampered)
    ));

    let mut service = healthy_service();
    let proposal = service.propose(at()).expect("proposal");
    let mut receipt = service.record_at(&proposal, at()).expect("receipt");
    receipt.native = true;
    assert!(matches!(
        service.verify(&receipt),
        Err(hartevo_aws_rds_health_result_plugin::AwsRdsServiceError::RecordTampered)
    ));

    let mut consumer =
        MissionAwsRdsConsumer::new(service.scope().clone(), service.registration().clone())
            .expect("consumer");
    let first = consumer.record(&proposal, "same-key").expect("record");
    assert!(consumer.record(&proposal, "same-key").is_ok());
    assert_eq!(first.recording_digest, first.recomputed_digest());
}

#[test]
fn provider_errors_have_no_raw_diagnostics_and_missing_fixture_is_bounded() {
    let scope = scope();
    let request = request(&scope, AwsRdsReadOperation::DescribeDbInstances);
    let provider = AwsRdsProvider::new(FixtureAwsRdsTransport::new([Err(
        AwsRdsTransportError::ServerFailure {
            status_code: Some(503),
            response_digest: Some(Digest::from_text("raw response")),
        },
    )]))
    .expect("provider");
    let mut provider = provider;
    let error = provider.read(&request).expect_err("provider error");
    let encoded = format!("{error:?}");
    assert!(!encoded.contains("raw response"));
    let unused_provider = AwsRdsProvider::new(FixtureAwsRdsTransport::default()).expect("provider");
    assert!(unused_provider.transport().requests().is_empty());
}
