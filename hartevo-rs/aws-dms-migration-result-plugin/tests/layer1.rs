use chrono::{Duration, TimeZone, Utc};
use hartevo_aws_dms_migration_result_plugin::{
    AssessmentResultMetadata, AssessmentStatus, AwsAccountId, AwsDmsMigrationError,
    AwsDmsMigrationReadRequest, AwsDmsMigrationService, AwsDmsProvider, AwsDmsScope,
    AwsDmsTransportError, AwsRegion, BlockedEnvTransport, ConsentScope, DatabaseEngine,
    DescribeReplicationTasksResponse, Digest, DmsOperation, EndpointArn, EndpointIdentity,
    EvidenceState, FixtureTransport, FullLoadProgress, MigrationType, MigrationWindow,
    MigrationWindowId, MissionAwsDmsConsumer, MissionIdentity, OpaqueMarker, PermissionSnapshot,
    ProjectIdentity, RecordingTransport, ReplicationIdentityValue, ReplicationInstanceArn,
    ReplicationInstanceId, ReplicationInstanceIdentity, ReplicationMetadata, ReplicationState,
    ReplicationTaskArn, ReplicationTaskIdentity, ReplicationTaskMetadata, ReplicationTaskState,
    Revision, SecretReference, ServerlessReplicationArn, ServerlessReplicationId,
    ServerlessReplicationIdentity, TaskId, TransportProvenance, WorkProductIdentity,
};

const NOW_SECONDS: i64 = 1_786_924_800;
const TASK_ARN: &str = "arn:aws:dms:us-east-1:123456789012:task:fixture-task";
const SERVERLESS_ARN: &str =
    "arn:aws:dms:us-east-1:123456789012:serverless-replication:fixture-replication";
const INSTANCE_ARN: &str = "arn:aws:dms:us-east-1:123456789012:rep:fixture-instance";
const SOURCE_ARN: &str = "arn:aws:dms:us-east-1:123456789012:endpoint:source";
const TARGET_ARN: &str = "arn:aws:dms:us-east-1:123456789012:endpoint:target";

fn now() -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn task_scope() -> AwsDmsScope {
    let task = ReplicationTaskIdentity::new(
        ReplicationTaskArn::new(TASK_ARN).expect("task ARN"),
        TaskId::new("fixture-task").expect("task id"),
    )
    .expect("task identity");
    AwsDmsScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        ReplicationIdentityValue::task(task),
        EndpointIdentity::new(
            EndpointArn::new(SOURCE_ARN).expect("source ARN"),
            DatabaseEngine::new("postgres").expect("source engine"),
        )
        .expect("source endpoint"),
        EndpointIdentity::new(
            EndpointArn::new(TARGET_ARN).expect("target ARN"),
            DatabaseEngine::new("aurora-postgresql").expect("target engine"),
        )
        .expect("target endpoint"),
        Some(
            ReplicationInstanceIdentity::new(
                ReplicationInstanceArn::new(INSTANCE_ARN).expect("instance ARN"),
                ReplicationInstanceId::new("fixture-instance").expect("instance id"),
            )
            .expect("instance"),
        ),
        Revision::new(7).expect("task revision"),
        MigrationWindow::new(
            MigrationWindowId::new("window-1").expect("window id"),
            now() - Duration::hours(1),
            now() + Duration::hours(24),
        )
        .expect("window"),
        MissionIdentity::new("mission-1", Revision::new(3).expect("mission revision"))
            .expect("Mission"),
        ProjectIdentity::new("project-1", Revision::new(5).expect("Project revision"))
            .expect("Project"),
        WorkProductIdentity::new(
            "work-product-1",
            Revision::new(9).expect("Work Product revision"),
        )
        .expect("Work Product"),
    )
    .expect("DMS task scope")
}

fn serverless_scope() -> AwsDmsScope {
    let replication = ServerlessReplicationIdentity::new(
        ServerlessReplicationArn::new(SERVERLESS_ARN).expect("serverless ARN"),
        ServerlessReplicationId::new("fixture-replication").expect("serverless id"),
    )
    .expect("serverless identity");
    let scope = task_scope();
    AwsDmsScope::new(
        scope.account().clone(),
        scope.region().clone(),
        ReplicationIdentityValue::serverless(replication),
        scope.source_endpoint().clone(),
        scope.target_endpoint().clone(),
        None,
        scope.task_revision(),
        scope.migration_window().clone(),
        scope.mission().clone(),
        scope.project().clone(),
        scope.work_product().clone(),
    )
    .expect("serverless scope")
}

fn consent() -> ConsentScope {
    ConsentScope::for_layer_one(
        "consent-1",
        Revision::new(2).expect("consent revision"),
        now() + Duration::days(3),
    )
    .expect("consent")
}

fn service_with<T: hartevo_aws_dms_migration_result_plugin::AwsDmsTransport>(
    scope: AwsDmsScope,
    transport: T,
) -> AwsDmsMigrationService<T> {
    let provider = AwsDmsProvider::new(transport).expect("provider");
    let secret = SecretReference::sigv4(
        "opaque-sigv4-handle",
        &scope,
        Revision::new(1).expect("secret revision"),
    )
    .expect("secret reference");
    AwsDmsMigrationService::new(scope, secret, consent(), provider, now()).expect("service")
}

fn fixture_service() -> AwsDmsMigrationService<FixtureTransport> {
    let scope = task_scope();
    let transport = FixtureTransport::for_scope(&scope, now()).expect("fixture transport");
    service_with(scope, transport)
}

fn task_metadata(scope: &AwsDmsScope, state: ReplicationTaskState) -> ReplicationTaskMetadata {
    ReplicationTaskMetadata::new(
        scope,
        state,
        MigrationType::FullLoadAndCdc,
        FullLoadProgress::new(10, 1, 2, 0, 2_048).expect("progress"),
        Some("provider-private stop reason".to_owned()),
        now(),
        None,
    )
    .expect("task metadata")
}

fn empty_task_response(
    request: &hartevo_aws_dms_migration_result_plugin::DescribeReplicationTasksRequest,
    scope: &AwsDmsScope,
    next_marker: Option<OpaqueMarker>,
    provenance: TransportProvenance,
) -> DescribeReplicationTasksResponse {
    DescribeReplicationTasksResponse::new(request, scope, Vec::new(), next_marker, 256, provenance)
        .expect("task response")
}

#[test]
fn exact_scope_fixture_and_metadata_projection_are_bounded() {
    let scope = task_scope();
    let secret = SecretReference::sigv4(
        "opaque-sigv4-handle",
        &scope,
        Revision::new(1).expect("revision"),
    )
    .expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("opaque-sigv4-handle"));
    let task = task_metadata(&scope, ReplicationTaskState::Running);
    let encoded = serde_json::to_string(&task).expect("metadata JSON");
    assert!(!encoded.contains("provider-private stop reason"));
    assert!(encoded.contains("stopReasonDigest"));
    assert_eq!(
        task.source_endpoint_digest,
        scope.source_endpoint().digest()
    );
    assert_eq!(
        task.target_endpoint_digest,
        scope.target_endpoint().digest()
    );
    assert_eq!(task.task_revision, scope.task_revision());
    assert_eq!(
        scope.mission().revision,
        Revision::new(3).expect("revision")
    );
    assert_eq!(
        scope.project().revision,
        Revision::new(5).expect("revision")
    );
    assert_eq!(
        scope.work_product().revision,
        Revision::new(9).expect("revision")
    );
}

#[test]
fn fixture_proposal_reads_all_three_apis_and_never_claims_native() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, EvidenceState::InProgress);
    assert!(proposal.evidence.task_complete);
    assert!(proposal.evidence.replication_complete);
    assert!(proposal.evidence.assessment_complete);
    assert_eq!(proposal.provenance, TransportProvenance::Fixture);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.can_be_adopted());
    let requests = service.provider().transport().requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[0].operation,
        DmsOperation::DescribeReplicationTasks
    );
    assert_eq!(requests[1].operation, DmsOperation::DescribeReplications);
    assert_eq!(
        requests[2].operation,
        DmsOperation::DescribeReplicationTaskAssessmentResults
    );
}

#[test]
fn serverless_scope_is_typed_and_fixture_remains_non_native() {
    let scope = serverless_scope();
    assert_eq!(
        scope.replication().kind(),
        hartevo_aws_dms_migration_result_plugin::ReplicationKind::Serverless
    );
    let transport = FixtureTransport::for_scope(&scope, now()).expect("serverless fixture");
    let mut service = service_with(scope, transport);
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("proposal");
    assert_eq!(proposal.provenance, TransportProvenance::Fixture);
    assert!(!proposal.native);
}

#[test]
fn registration_is_version_digest_scope_permission_bound_and_reversible() {
    let service = fixture_service();
    let registration = service.registration();
    registration.validate().expect("registration");
    assert!(registration.is_active());
    assert_eq!(
        registration.permission_digest(),
        &service.registration().permission_digest
    );
    let encoded = serde_json::to_string(registration).expect("registration JSON");
    assert!(encoded.contains("secretReferenceDigest"));
    assert!(!encoded.contains("opaque-sigv4-handle"));

    let mut revoked = registration.clone();
    revoked.revoke().expect("revoke");
    assert!(!revoked.is_active());
    revoked
        .validate()
        .expect("revoked registration remains integrity-valid");
    revoked.restore().expect("restore");
    assert!(revoked.is_active());
    revoked.reverse().expect("reverse");
    assert!(!revoked.is_active());
}

#[test]
fn proposal_tamper_scope_revision_and_registration_revocation_fail_closed() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("proposal");
    let mut tampered = proposal.clone();
    tampered.evidence.state = EvidenceState::Failed;
    assert!(tampered.validate_integrity().is_err());
    assert!(!service.verify(&tampered).valid);

    let mut registration = service.registration().clone();
    registration.scope_digest = hartevo_aws_dms_migration_result_plugin::Digest::zero();
    assert!(registration.validate().is_err());

    let wrong_scope = {
        let base = task_scope();
        AwsDmsScope::new(
            base.account().clone(),
            base.region().clone(),
            base.replication().clone(),
            base.source_endpoint().clone(),
            base.target_endpoint().clone(),
            base.replication_instance().cloned(),
            Revision::new(8).expect("new revision"),
            base.migration_window().clone(),
            base.mission().clone(),
            base.project().clone(),
            base.work_product().clone(),
        )
        .expect("scope with a new revision")
    };
    assert!(MissionAwsDmsConsumer::new(wrong_scope, service.registration().clone()).is_err());

    service.revoke().expect("service revoke");
    assert!(
        service
            .propose(service.default_request().expect("request"))
            .is_err()
    );
}

#[test]
fn recording_replay_is_idempotent_and_conflicts_are_rejected() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("proposal");
    let first = service
        .record_at(&proposal, "migration-result-1", now())
        .expect("record");
    let replay = service
        .record_at(
            &proposal,
            "migration-result-1",
            now() + Duration::seconds(1),
        )
        .expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(service.record_count(), 1);
    first.validate_integrity().expect("receipt integrity");

    let mut different = proposal.clone();
    different.proposal_digest =
        hartevo_aws_dms_migration_result_plugin::Digest::from_text("different");
    assert_eq!(
        service.record_at(&different, "migration-result-1", now()),
        Err(AwsDmsMigrationError::VerificationFailed)
    );
}

#[test]
fn page_budget_and_marker_replay_are_partial() {
    let scope = task_scope();
    let base = AwsDmsMigrationReadRequest::for_scope(&scope, 25, 2).expect("request");
    let request1 = base
        .tasks_request(&scope, None, 1)
        .expect("page one request");
    let marker1 = OpaqueMarker::new(
        "loop-token",
        &scope,
        DmsOperation::DescribeReplicationTasks,
        25,
        1,
    )
    .expect("marker one");
    let response1 = empty_task_response(
        &request1,
        &scope,
        Some(marker1.clone()),
        TransportProvenance::Recording,
    );
    let request2 = base
        .tasks_request(&scope, Some(marker1), 2)
        .expect("page two request");
    let marker2 = OpaqueMarker::new(
        "loop-token",
        &scope,
        DmsOperation::DescribeReplicationTasks,
        25,
        2,
    )
    .expect("marker two");
    let response2 = empty_task_response(
        &request2,
        &scope,
        Some(marker2),
        TransportProvenance::Recording,
    );
    let mut transport = hartevo_aws_dms_migration_result_plugin::RecordingTransport::default();
    transport.push_task_response(Ok(response1));
    transport.push_task_response(Ok(response2));
    let mut service = service_with(scope.clone(), transport);
    let proposal = service.propose(base).expect("partial proposal");
    assert_eq!(proposal.state, EvidenceState::Partial);
    assert_eq!(
        proposal
            .evidence
            .failure
            .as_ref()
            .expect("failure")
            .category,
        "pagination_loop"
    );

    let scope = task_scope();
    let base = AwsDmsMigrationReadRequest::for_scope(&scope, 25, 1).expect("one-page request");
    let request = base.tasks_request(&scope, None, 1).expect("request");
    let marker = OpaqueMarker::new(
        "page-budget",
        &scope,
        DmsOperation::DescribeReplicationTasks,
        25,
        1,
    )
    .expect("marker");
    let response = empty_task_response(
        &request,
        &scope,
        Some(marker),
        TransportProvenance::Recording,
    );
    let mut transport = hartevo_aws_dms_migration_result_plugin::RecordingTransport::default();
    transport.push_task_response(Ok(response));
    let mut service = service_with(scope, transport);
    let proposal = service.propose(base).expect("page-budget proposal");
    assert_eq!(proposal.state, EvidenceState::Partial);
    assert_eq!(
        proposal
            .evidence
            .failure
            .as_ref()
            .expect("failure")
            .category,
        "page_budget"
    );
}

#[test]
fn transport_error_families_fail_closed_with_bounded_evidence() {
    for (error, expected) in [
        (AwsDmsTransportError::AccessLost, EvidenceState::AccessLoss),
        (
            AwsDmsTransportError::RateLimited {
                retry_after_seconds: Some(3),
            },
            EvidenceState::Throttled,
        ),
        (
            AwsDmsTransportError::Timeout,
            EvidenceState::ProviderUnknown,
        ),
        (AwsDmsTransportError::Partial, EvidenceState::Partial),
    ] {
        let scope = task_scope();
        let mut transport = hartevo_aws_dms_migration_result_plugin::RecordingTransport::default();
        transport.push_task_response(Err(error));
        let mut service = service_with(scope, transport);
        let proposal = service
            .propose(service.default_request().expect("request"))
            .expect("typed provider failure proposal");
        assert_eq!(proposal.state, expected);
        assert!(proposal.state.is_fail_closed());
    }

    let scope = task_scope();
    let mut service = service_with(scope, BlockedEnvTransport);
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("blocked environment proposal");
    assert_eq!(proposal.state, EvidenceState::ProviderUnknown);
    assert_eq!(proposal.provenance, TransportProvenance::BlockedEnv);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
}

#[test]
fn provider_page_digest_tamper_is_rejected_before_proposal_evidence() {
    let scope = task_scope();
    let request = AwsDmsMigrationReadRequest::for_scope(&scope, 25, 1).expect("request");
    let task_request = request
        .tasks_request(&scope, None, 1)
        .expect("task request");
    let mut response = DescribeReplicationTasksResponse::new(
        &task_request,
        &scope,
        vec![task_metadata(&scope, ReplicationTaskState::Running)],
        None,
        256,
        TransportProvenance::Recording,
    )
    .expect("task response");
    response.page_digest = Digest::zero();
    let mut transport = RecordingTransport::default();
    transport.push_task_response(Ok(response));
    let mut service = service_with(scope, transport);
    let proposal = service
        .propose(request)
        .expect("invalid provider response becomes bounded evidence");
    assert_eq!(proposal.state, EvidenceState::ProviderUnknown);
    assert!(!service.verify(&proposal).valid);
}

#[test]
fn secret_reference_revocation_stops_reads() {
    let mut service = fixture_service();
    service.revoke_secret_reference();
    assert_eq!(
        service.propose(service.default_request().expect("request")),
        Err(AwsDmsMigrationError::InvalidSecretReference)
    );
}

#[test]
fn assessment_report_body_and_markers_never_cross_the_boundary() {
    let scope = task_scope();
    let assessment = AssessmentResultMetadata::new(
        &scope,
        AssessmentStatus::Passed,
        now(),
        Some(b"s3 assessment body that must not be retained"),
    )
    .expect("assessment");
    let encoded = serde_json::to_string(&assessment).expect("assessment JSON");
    assert!(!encoded.contains("s3 assessment body"));
    assert!(encoded.contains("reportDigest"));

    let marker = OpaqueMarker::new(
        "raw-provider-next-marker",
        &scope,
        DmsOperation::DescribeReplicationTasks,
        25,
        1,
    )
    .expect("marker");
    let encoded = serde_json::to_string(&marker).expect("marker JSON");
    assert!(!encoded.contains("raw-provider-next-marker"));
    assert!(encoded.contains("tokenDigest"));
}

#[test]
fn request_scope_and_marker_binding_reject_drift() {
    let scope = task_scope();
    let request = AwsDmsMigrationReadRequest::for_scope(&scope, 25, 1).expect("request");
    let mut tampered = request.clone();
    tampered.max_records = 26;
    assert!(tampered.validate_against(&scope).is_err());

    let other_scope = serverless_scope();
    let marker = OpaqueMarker::new(
        "foreign-marker",
        &other_scope,
        DmsOperation::DescribeReplicationTasks,
        25,
        1,
    )
    .expect("foreign marker");
    assert!(request.tasks_request(&scope, Some(marker), 2).is_err());

    let permission = PermissionSnapshot::new(
        Revision::new(1).expect("revision"),
        ["dms:StartReplicationTask"],
    );
    assert!(permission.is_err());
}

#[test]
fn provider_receipts_and_consumption_remain_below_kernel_authority() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("proposal");
    let mut consumer = service.consumer().expect("consumer");
    let result = consumer.consume(&proposal).expect("Mission result");
    assert!(result.review_only);
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.first_party);
    assert!(!result.provider_receipt);
    assert!(!result.outcome_adopted);
    assert!(!result.work_product_adopted);
    consumer
        .record_at(&proposal, "consumer-record-1", now())
        .expect("consumer record");
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn serverless_constructor_keeps_source_target_and_revision_fences() {
    let scope = serverless_scope();
    let assessment = AssessmentResultMetadata::from_digest(
        &scope,
        AssessmentStatus::Warning,
        now(),
        Some(hartevo_aws_dms_migration_result_plugin::Digest::from_text(
            "report",
        )),
    )
    .expect("assessment digest");
    let metadata = ReplicationMetadata::new(
        &scope,
        ReplicationState::Running,
        MigrationType::Serverless,
        now(),
    )
    .expect("replication metadata");
    assert_eq!(metadata.replication_digest, scope.replication().digest());
    assert_eq!(assessment.task_revision, scope.task_revision());
}
