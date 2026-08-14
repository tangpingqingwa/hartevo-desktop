use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_datasync_transfer_result_plugin::{
    AwsDataSyncProvider, AwsDataSyncScope, AwsDataSyncScopeInput, AwsDataSyncTransferContract,
    AwsDataSyncTransferError, AwsDataSyncTransferService, AwsDataSyncTransportError,
    BoundedCounter, ConsentScope, Cursor, CursorBinding, DataSyncTaskStatus, Digest,
    ExecutionListFilter, ExecutionMetadataInput, ExecutionProjection, FixtureTransport,
    ListTaskExecutionsRequest, ListTaskExecutionsResponse, ListTasksRequest, ListTasksResponse,
    LocationKind, MAX_COUNTER_VALUE, MAX_PAGE_SIZE, MAX_PAGES, MissionAwsDataSyncConsumer,
    PermissionSnapshot, ProposalDisposition, RecordingTransport, SecretReference, TaskListFilter,
    TaskMetadataInput, TaskProjection, TransferCounters, TransferCountersInput,
    TransferEvidenceState, TransferExecutionState, TransferReportMetadataInput,
    TransportProvenance, contract_digest, plugin_definition,
};
use hartevo_plugin_runtime::{
    MissionId as RuntimeMissionId, PluginRuntime, PluginScope, ProjectId as RuntimeProjectId,
};
use serde_json::Value;

const NOW_SECONDS: i64 = 1_787_000_000;
const TASK_ARN: &str = "arn:aws:datasync:us-east-1:123456789012:task/task-1";
const SOURCE_ARN: &str = "arn:aws:datasync:us-east-1:123456789012:location/source-1";
const DESTINATION_ARN: &str = "arn:aws:datasync:us-east-1:123456789012:location/destination-1";
const EXECUTION_ARN: &str =
    "arn:aws:datasync:us-east-1:123456789012:task/task-1/execution/execution-1";
const RAW_REPORT: &str = "report/path/object-name-and-sensitive-dataset";
const RAW_ERROR: &str = "CloudWatch raw log with person@example.com";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture time")
}

fn scope() -> AwsDataSyncScope {
    AwsDataSyncScope::new(AwsDataSyncScopeInput {
        account: "123456789012".to_owned(),
        region: "us-east-1".to_owned(),
        task_arn: TASK_ARN.to_owned(),
        source_location_arn: SOURCE_ARN.to_owned(),
        source_location_kind: LocationKind::S3,
        destination_location_arn: DESTINATION_ARN.to_owned(),
        destination_location_kind: LocationKind::S3,
        mission_id: "mission-1".to_owned(),
        mission_revision: 7,
        project_id: "project-1".to_owned(),
        project_revision: 11,
        work_product_id: "work-product-1".to_owned(),
        work_product_revision: 13,
    })
    .expect("scope")
}

fn secret(scope: &AwsDataSyncScope) -> SecretReference {
    SecretReference::sigv4("host-owned-sigv4-handle", scope, 1).expect("secret")
}

fn consent() -> ConsentScope {
    ConsentScope::for_layer_one("consent-1", 2, now() + Duration::days(1)).expect("consent")
}

fn counters(bytes: u64) -> TransferCountersInput {
    TransferCountersInput {
        bytes_to_transfer: bytes,
        bytes_transferred: bytes,
        bytes_verified: bytes,
        bytes_deleted: 0,
        files_to_transfer: 2,
        files_transferred: 2,
        files_verified: 2,
        files_deleted: 0,
        errors: 0,
    }
}

fn execution(
    scope: &AwsDataSyncScope,
    status: TransferExecutionState,
    counter_input: TransferCountersInput,
) -> ExecutionProjection {
    ExecutionProjection::from_input(
        scope,
        ExecutionMetadataInput {
            execution_arn: EXECUTION_ARN.to_owned(),
            task_arn: TASK_ARN.to_owned(),
            status,
            started_at: Some(now() - Duration::minutes(2)),
            ended_at: Some(now()),
            counters: counter_input,
            transfer_report: TransferReportMetadataInput {
                report_identifier: Some(RAW_REPORT.to_owned()),
                report_format: Some("json".to_owned()),
                report_size_bytes: Some(2_048),
            },
            error_message: Some(RAW_ERROR.to_owned()),
        },
    )
    .expect("execution projection")
}

fn recording_service(
    status: TransferExecutionState,
    counter_input: TransferCountersInput,
) -> AwsDataSyncTransferService<RecordingTransport> {
    let scope = scope();
    let task_request =
        hartevo_aws_datasync_transfer_result_plugin::DescribeTaskRequest::new(&scope)
            .expect("describe task request");
    let task = TaskProjection::from_input(
        &scope,
        TaskMetadataInput {
            task_arn: TASK_ARN.to_owned(),
            status: DataSyncTaskStatus::Available,
            source_location_arn: SOURCE_ARN.to_owned(),
            source_location_kind: LocationKind::S3,
            destination_location_arn: DESTINATION_ARN.to_owned(),
            destination_location_kind: LocationKind::S3,
        },
    )
    .expect("task projection");
    let task_list_request =
        ListTasksRequest::new(&scope, MAX_PAGE_SIZE, None).expect("task list request");
    let task_list = ListTasksResponse::new(
        &task_list_request,
        vec![task.clone()],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("task list response");
    let execution = execution(&scope, status, counter_input);
    let execution_list_request = ListTaskExecutionsRequest::new(&scope, MAX_PAGE_SIZE, None)
        .expect("execution list request");
    let execution_list = ListTaskExecutionsResponse::new(
        &execution_list_request,
        vec![execution.clone()],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("execution list response");
    let execution_request =
        hartevo_aws_datasync_transfer_result_plugin::DescribeTaskExecutionRequest::from_digest(
            &scope,
            execution.execution_digest.clone(),
        )
        .expect("describe execution request");
    let execution_response =
        hartevo_aws_datasync_transfer_result_plugin::DescribeTaskExecutionResponse::new(
            &execution_request,
            execution,
            512,
            TransportProvenance::Recording,
        )
        .expect("execution response");
    let task_response = hartevo_aws_datasync_transfer_result_plugin::DescribeTaskResponse::new(
        &task_request,
        task,
        512,
        TransportProvenance::Recording,
    )
    .expect("task response");
    let mut transport = RecordingTransport::default();
    transport.push_describe_task_response(Ok(task_response));
    transport.push_list_tasks_response(Ok(task_list));
    transport.push_list_task_executions_response(Ok(execution_list));
    transport.push_describe_task_execution_response(Ok(execution_response));
    let provider = AwsDataSyncProvider::new(transport).expect("provider");
    AwsDataSyncTransferService::new(scope.clone(), secret(&scope), consent(), provider, now())
        .expect("service")
}

fn fixture_service(status: TransferExecutionState) -> AwsDataSyncTransferService<FixtureTransport> {
    let scope = scope();
    let provider = AwsDataSyncProvider::new(FixtureTransport::with_execution_state(
        &scope,
        now(),
        status,
    ))
    .expect("fixture provider");
    AwsDataSyncTransferService::new(scope.clone(), secret(&scope), consent(), provider, now())
        .expect("fixture service")
}

#[test]
fn contract_plugin_definition_and_native_boundary_are_exact() {
    let contract = AwsDataSyncTransferContract::baseline().expect("contract");
    assert_eq!(contract.contract_digest, contract_digest());
    assert_eq!(contract.evidence.states.len(), 8);
    assert!(contract.service.read_only);
    assert!(!contract.service.external_writes);
    assert!(!contract.provider.connected_evidence);
    assert!(!contract.native_claims.blocked_environment_is_native);

    let runtime_scope = PluginScope::new(
        RuntimeProjectId::new("project-1").expect("runtime project"),
        RuntimeMissionId::new("mission-1").expect("runtime mission"),
        1,
    )
    .expect("runtime scope");
    let definition = plugin_definition(runtime_scope.clone()).expect("definition");
    let mut runtime = PluginRuntime::new();
    let handle = runtime.define(definition).expect("define");
    let receipt = runtime.mount(&handle).expect("mount");
    assert_eq!(receipt.generation(), 1);
    runtime.revoke(&handle).expect("revoke");
}

#[test]
fn fixture_proposal_is_bounded_redacted_and_review_only() {
    let mut service = fixture_service(TransferExecutionState::Success);
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    proposal
        .validate(service.scope())
        .expect("proposal validation");
    assert_eq!(proposal.state, TransferEvidenceState::Complete);
    assert_eq!(proposal.task_pages_observed, 1);
    assert_eq!(proposal.execution_pages_observed, 1);
    assert_eq!(
        proposal.execution.as_ref().expect("execution").status,
        TransferExecutionState::Success
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.adoptable);
    assert!(proposal.is_review_only());
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for raw in [
        "host-owned-sigv4-handle",
        TASK_ARN,
        SOURCE_ARN,
        DESTINATION_ARN,
        RAW_REPORT,
        RAW_ERROR,
    ] {
        assert!(!serialized.contains(raw), "raw value leaked: {raw}");
    }
    let debug = format!("{:?}", service.registration());
    assert!(!debug.contains("host-owned-sigv4-handle"));
    assert!(
        !serde_json::to_string(service.registration())
            .expect("registration JSON")
            .contains("host-owned-sigv4-handle")
    );
}

#[test]
fn all_execution_states_project_without_mutation_authority() {
    for state in TransferExecutionState::ALL {
        let mut service = fixture_service(state);
        let proposal = service
            .propose(service.default_request(now()).expect("request"))
            .expect("proposal");
        assert_eq!(
            proposal.execution.as_ref().expect("execution").status,
            state
        );
        assert!(!proposal.adoptable);
        assert!(!proposal.outcome_authority);
        assert!(!proposal.work_product_adoption);
    }
    TransferExecutionState::validate_sequence(&[
        TransferExecutionState::Queued,
        TransferExecutionState::Launching,
        TransferExecutionState::Preparing,
        TransferExecutionState::Transferring,
        TransferExecutionState::Verifying,
        TransferExecutionState::Success,
    ])
    .expect("valid state sequence");
    assert!(
        TransferExecutionState::validate_sequence(&[
            TransferExecutionState::Success,
            TransferExecutionState::Transferring,
        ])
        .is_err()
    );
}

#[test]
fn bounded_counters_truncate_and_make_evidence_partial() {
    let mut service = recording_service(
        TransferExecutionState::Success,
        TransferCountersInput {
            bytes_to_transfer: u64::MAX,
            bytes_transferred: u64::MAX,
            bytes_verified: u64::MAX,
            ..counters(u64::MAX)
        },
    );
    let proposal = service
        .propose(
            service
                .request(None, MAX_PAGES, MAX_PAGE_SIZE, now())
                .expect("request"),
        )
        .expect("proposal");
    let counters = &proposal.execution.as_ref().expect("execution").counters;
    assert_eq!(counters.bytes_transferred.value, MAX_COUNTER_VALUE);
    assert!(counters.is_truncated());
    assert_eq!(
        proposal.state,
        TransferEvidenceState::Partial(
            hartevo_aws_datasync_transfer_result_plugin::PartialReason::CounterTruncated
        )
    );
}

#[test]
fn cursor_is_opaque_and_bound_to_scope_and_operation_filter() {
    let scope = scope();
    let task_filter = TaskListFilter::for_scope(&scope, 10).expect("filter");
    let cursor = Cursor::new("opaque-provider-token", &scope, &task_filter, 2).expect("cursor");
    let request = ListTasksRequest::new(&scope, 10, Some(cursor.clone())).expect("request");
    assert!(
        !serde_json::to_string(&cursor)
            .expect("cursor JSON")
            .contains("opaque-provider-token")
    );
    assert!(!request.path_and_query().contains("opaque-provider-token"));
    assert!(ListTasksRequest::new(&scope, 11, Some(cursor.clone())).is_err());
    let other_scope = AwsDataSyncScope::new(AwsDataSyncScopeInput {
        account: "123456789012".to_owned(),
        region: "us-west-2".to_owned(),
        task_arn: TASK_ARN.to_owned(),
        source_location_arn: SOURCE_ARN.to_owned(),
        source_location_kind: LocationKind::S3,
        destination_location_arn: DESTINATION_ARN.to_owned(),
        destination_location_kind: LocationKind::S3,
        mission_id: "mission-1".to_owned(),
        mission_revision: 7,
        project_id: "project-1".to_owned(),
        project_revision: 11,
        work_product_id: "work-product-1".to_owned(),
        work_product_revision: 13,
    })
    .expect("other scope");
    assert!(ListTasksRequest::new(&other_scope, 10, Some(cursor)).is_err());
    let execution_filter = ExecutionListFilter::for_scope(&scope, 10).expect("execution filter");
    assert!(
        Cursor::new("token", &scope, &execution_filter, 2)
            .expect("execution cursor")
            .binding_digest()
            != &task_filter.binding_digest()
    );
    let _ = request;
}

#[test]
fn transport_failures_map_to_explicit_non_adoptable_states() {
    let cases = [
        (
            AwsDataSyncTransportError::BadRequest,
            TransferEvidenceState::InvalidRequest,
        ),
        (
            AwsDataSyncTransportError::Unauthorized,
            TransferEvidenceState::AccessLoss,
        ),
        (
            AwsDataSyncTransportError::Forbidden,
            TransferEvidenceState::AccessLoss,
        ),
        (
            AwsDataSyncTransportError::NotFound,
            TransferEvidenceState::NotFound,
        ),
        (
            AwsDataSyncTransportError::Conflict,
            TransferEvidenceState::Conflict,
        ),
        (
            AwsDataSyncTransportError::RateLimited {
                retry_after_seconds: Some(5),
            },
            TransferEvidenceState::Throttled,
        ),
        (
            AwsDataSyncTransportError::ServerError { status: 500 },
            TransferEvidenceState::ProviderUnknown,
        ),
        (
            AwsDataSyncTransportError::ServerError { status: 503 },
            TransferEvidenceState::ProviderUnknown,
        ),
        (
            AwsDataSyncTransportError::Timeout,
            TransferEvidenceState::Timeout,
        ),
    ];
    for (error, expected) in cases {
        let scope = scope();
        let mut transport = RecordingTransport::default();
        let task_request =
            hartevo_aws_datasync_transfer_result_plugin::DescribeTaskRequest::new(&scope)
                .expect("request");
        transport.push_describe_task_response(Err(error.clone()));
        let provider = AwsDataSyncProvider::new(transport).expect("provider");
        let mut service = AwsDataSyncTransferService::new(
            scope.clone(),
            secret(&scope),
            consent(),
            provider,
            now(),
        )
        .expect("service");
        let proposal = service
            .propose(service.default_request(now()).expect("evidence request"))
            .expect("failure proposal");
        assert_eq!(proposal.state, expected);
        assert!(!proposal.adoptable);
        assert_eq!(proposal.failures[0].status_code, error.status_code());
        assert_eq!(
            service.provider().transport().requests()[0].request_digest,
            *task_request.request_digest()
        );
    }
}

#[test]
fn partial_unknown_access_loss_and_blocked_env_never_claim_native() {
    let mut service = fixture_service(TransferExecutionState::Transferring);
    let proposal = service
        .propose(
            service
                .request(None, 1, MAX_PAGE_SIZE, now())
                .expect("request"),
        )
        .expect("proposal");
    assert_eq!(
        proposal.state,
        TransferEvidenceState::Partial(
            hartevo_aws_datasync_transfer_result_plugin::PartialReason::ExecutionInProgress
        )
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);

    let scope = scope();
    let mut blocked = AwsDataSyncTransferService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        AwsDataSyncProvider::default(),
        now(),
    )
    .expect("blocked service");
    let blocked_proposal = blocked
        .propose(blocked.default_request(now()).expect("request"))
        .expect("blocked proposal");
    assert_eq!(
        blocked_proposal.state,
        TransferEvidenceState::ProviderUnknown
    );
    assert_eq!(blocked_proposal.provenance, TransportProvenance::BlockedEnv);
    assert!(!blocked_proposal.connected);
    assert!(!blocked_proposal.native);
}

#[test]
fn tamper_and_reversible_registration_revocation_fail_closed() {
    let scope = scope();
    let task_request =
        hartevo_aws_datasync_transfer_result_plugin::DescribeTaskRequest::new(&scope)
            .expect("request");
    let tampered = hartevo_aws_datasync_transfer_result_plugin::DescribeTaskResponse::new(
        &task_request,
        TaskProjection::for_scope(&scope, DataSyncTaskStatus::Available),
        512,
        TransportProvenance::Recording,
    )
    .expect("response")
    .with_declared_digest(Digest::from_text("tampered"));
    let mut transport = RecordingTransport::default();
    transport.push_describe_task_response(Ok(tampered));
    let provider = AwsDataSyncProvider::new(transport).expect("provider");
    let mut service =
        AwsDataSyncTransferService::new(scope.clone(), secret(&scope), consent(), provider, now())
            .expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("tamper proposal");
    assert_eq!(proposal.state, TransferEvidenceState::ProviderUnknown);
    assert!(service.revoke_registration().is_ok());
    assert_eq!(
        service
            .propose(service.default_request(now()).expect("request"))
            .expect_err("revoked registration"),
        AwsDataSyncTransferError::RegistrationRevoked
    );
    let mut fixture = fixture_service(TransferExecutionState::Success);
    fixture.revoke_secret().expect("revoke secret");
    assert_eq!(
        fixture
            .propose(fixture.default_request(now()).expect("request"))
            .expect_err("revoked secret"),
        AwsDataSyncTransferError::SecretRevoked
    );
}

#[test]
fn mission_consumer_records_idempotently_without_adoption() {
    let mut service = fixture_service(TransferExecutionState::Success);
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    let mut consumer = MissionAwsDataSyncConsumer::new(scope());
    let result = consumer.consume(&proposal).expect("consume");
    assert_eq!(result.disposition, ProposalDisposition::ReviewOnly);
    assert!(!result.adoptable);
    let first = consumer
        .record(&proposal, "mission-record-1")
        .expect("record");
    let replay = consumer
        .record(&proposal, "mission-record-1")
        .expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    first
        .validate_integrity(consumer.scope())
        .expect("record integrity");
}

#[test]
fn provider_definition_and_permission_digest_are_reversible_and_bound() {
    let scope = scope();
    let provider =
        AwsDataSyncProvider::new(FixtureTransport::for_scope(&scope, now())).expect("provider");
    assert!(provider.definition().validate().is_ok());
    assert_eq!(
        provider.definition().api_revision,
        hartevo_aws_datasync_transfer_result_plugin::PROVIDER_API_REVISION
    );
    let snapshot = PermissionSnapshot::for_layer_one(1);
    assert!(snapshot.validate().is_ok());
    assert!(PermissionSnapshot::new(1, ["datasync:StartTaskExecution"]).is_err());
    let mut service =
        AwsDataSyncTransferService::new(scope.clone(), secret(&scope), consent(), provider, now())
            .expect("service");
    let registration = service.registration().clone();
    assert!(registration.validate().is_ok());
    assert_eq!(registration.scope_digest(), &scope.digest());
    assert_eq!(registration.task_digest(), scope.task().digest());
    let serialized = serde_json::to_string(&registration).expect("registration JSON");
    let value: Value = serde_json::from_str(&serialized).expect("JSON");
    assert!(value.get("secretReferenceDigest").is_some());
    assert!(value.get("secretReference").is_none());
    service.reverse_registration().expect("reverse");
    assert_eq!(
        service
            .restore_registration()
            .expect_err("reversed registration"),
        AwsDataSyncTransferError::RegistrationReversed
    );
}

#[test]
fn bounded_counter_is_a_digest_safe_numeric_summary() {
    let counter = BoundedCounter::from_raw(u64::MAX);
    assert_eq!(counter.value, MAX_COUNTER_VALUE);
    assert!(counter.truncated);
    let counters: TransferCounters = counters(u64::MAX).into();
    let json = serde_json::to_string(&counters).expect("counter JSON");
    assert!(json.contains(&MAX_COUNTER_VALUE.to_string()));
    assert!(!json.contains(&u64::MAX.to_string()));
}
