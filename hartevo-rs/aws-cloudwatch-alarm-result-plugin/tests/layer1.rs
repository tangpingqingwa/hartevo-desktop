use chrono::{TimeZone, Utc};

use hartevo_aws_cloudwatch_alarm_result_plugin::{
    AlarmIdentity, AlarmName, AlarmSnapshot, AlarmState, AwsAccountId, AwsCloudWatchAlarmScope,
    AwsCloudWatchAlarmService, AwsCloudWatchAlarmServiceError, AwsCloudWatchOperation,
    AwsCloudWatchProvider, AwsCloudWatchReadRequest, AwsCloudWatchTransportError, AwsRegion,
    ComparisonOperator, DeploymentBinding, DescribeAlarmsRequest, DescribeAlarmsResponse, Digest,
    EvidenceStatus, FixtureTransport, GetMetricDataRequest, GetMetricDataResponse,
    MetricDataAggregate, MetricIdentity, MetricName, MetricNamespace, MetricWindow,
    MissionAwsCloudWatchConsumer, MissionBinding, OpaqueCursor, PermissionAction, PermissionId,
    PermissionSnapshot, ProjectBinding, RecordingTransport, Revision, SecretReference,
    TransportProvenance, TreatMissingData, WorkProductBinding,
};

fn scope(discover_metrics: bool) -> AwsCloudWatchAlarmScope {
    let permissions = PermissionSnapshot::readonly(
        PermissionId::new("cloudwatch-read").expect("permission"),
        Revision::new(1).expect("revision"),
    )
    .expect("permissions");
    let metric = MetricIdentity::from_dimensions(
        MetricNamespace::new("AWS/Lambda").expect("namespace"),
        MetricName::new("Errors").expect("metric"),
        "Sum",
        60,
        [("FunctionName", "fixture")],
    )
    .expect("metric");
    AwsCloudWatchAlarmScope::new(
        DeploymentBinding::new(
            hartevo_aws_cloudwatch_alarm_result_plugin::DeploymentId::new("deployment")
                .expect("deployment"),
            Revision::new(1).expect("revision"),
        ),
        MissionBinding::new(
            hartevo_aws_cloudwatch_alarm_result_plugin::MissionId::new("mission").expect("mission"),
            Revision::new(1).expect("revision"),
        ),
        ProjectBinding::new(
            hartevo_aws_cloudwatch_alarm_result_plugin::ProjectId::new("project").expect("project"),
            Revision::new(1).expect("revision"),
        ),
        WorkProductBinding::new(
            hartevo_aws_cloudwatch_alarm_result_plugin::WorkProductId::new("work-product")
                .expect("work product"),
            Revision::new(1).expect("revision"),
        ),
        AwsAccountId::new("123456789012").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        AlarmIdentity::new(
            AlarmName::new("fixture-alarm").expect("alarm"),
            Revision::new(1).expect("revision"),
        )
        .expect("alarm identity"),
        metric,
        MetricWindow::new(
            Utc.with_ymd_and_hms(2026, 8, 15, 0, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 8, 15, 1, 0, 0).unwrap(),
        )
        .expect("window"),
        permissions.digest(),
        discover_metrics,
    )
    .expect("scope")
}

fn permissions() -> PermissionSnapshot {
    PermissionSnapshot::readonly(
        PermissionId::new("cloudwatch-read").expect("permission"),
        Revision::new(1).expect("revision"),
    )
    .expect("permissions")
}

fn alarm(scope: &AwsCloudWatchAlarmScope) -> AlarmSnapshot {
    AlarmSnapshot::new(
        scope.alarm.clone(),
        AlarmState::Ok,
        Utc.with_ymd_and_hms(2026, 8, 15, 0, 59, 0).unwrap(),
        Utc.with_ymd_and_hms(2026, 8, 15, 0, 58, 0).unwrap(),
        hartevo_aws_cloudwatch_alarm_result_plugin::EvaluationSummary::new(
            1.0,
            ComparisonOperator::GreaterThanThreshold,
            3,
            Some(2),
            60,
            TreatMissingData::NotBreaching,
        )
        .expect("evaluation"),
        scope.metric.clone(),
    )
    .expect("alarm")
}

fn aggregate(scope: &AwsCloudWatchAlarmScope, marker: &str) -> MetricDataAggregate {
    MetricDataAggregate::new(
        scope.metric.clone(),
        scope.window.clone(),
        1,
        1.0,
        1.0,
        1.0,
        1.0,
        Digest::from_text(marker),
    )
    .expect("metric aggregate")
}

fn service_with_transport<T: hartevo_aws_cloudwatch_alarm_result_plugin::AwsCloudWatchTransport>(
    scope: AwsCloudWatchAlarmScope,
    transport: T,
) -> AwsCloudWatchAlarmService<T> {
    let provider = AwsCloudWatchProvider::new(transport).expect("provider");
    let secret = SecretReference::new("opaque-test-handle", &scope, 1).expect("secret");
    AwsCloudWatchAlarmService::new(scope, secret, permissions(), provider).expect("service")
}

fn queued_success_responses(
    scope: &AwsCloudWatchAlarmScope,
) -> (DescribeAlarmsResponse, GetMetricDataResponse) {
    let describe_request = DescribeAlarmsRequest::for_scope(scope).expect("describe request");
    let describe = DescribeAlarmsResponse::new(
        &describe_request,
        vec![alarm(scope)],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("describe response");
    let metric_request = GetMetricDataRequest::for_scope(scope).expect("metric request");
    let metric = GetMetricDataResponse::new(
        &metric_request,
        vec![aggregate(scope, "success")],
        None,
        768,
        TransportProvenance::Recording,
    )
    .expect("metric response");
    (describe, metric)
}

#[test]
fn optional_list_metrics_is_exactly_scoped_and_recorded_as_redacted_receipts() {
    let scope = scope(true);
    let (describe, metric) = queued_success_responses(&scope);
    let list_request =
        hartevo_aws_cloudwatch_alarm_result_plugin::ListMetricsRequest::for_scope(&scope)
            .expect("list request");
    let list = hartevo_aws_cloudwatch_alarm_result_plugin::ListMetricsResponse::new(
        &list_request,
        vec![scope.metric.clone()],
        None,
        384,
        TransportProvenance::Recording,
    )
    .expect("list response");
    let mut transport = RecordingTransport::default();
    transport.push_describe_response(Ok(describe));
    transport.push_list_response(Ok(list));
    transport.push_metric_response(Ok(metric));
    let mut service = service_with_transport(scope.clone(), transport);
    let result = service.read_bounded().expect("read");
    assert_eq!(result.evidence.status, EvidenceStatus::Complete);
    assert!(result.evidence.discovery_used);
    assert_eq!(result.evidence.request_receipts.len(), 3);
    assert!(
        result
            .evidence
            .request_receipts
            .iter()
            .all(|receipt| receipt.receipt_digest == receipt.recomputed_digest())
    );
    let serialized = serde_json::to_string(&result.evidence).expect("evidence JSON");
    assert!(!serialized.contains("FunctionName"));
    assert!(!serialized.contains("opaque-test-handle"));
}

#[test]
fn empty_and_partial_evidence_are_not_adoptable() {
    let empty_scope = scope(false);
    let describe_request = DescribeAlarmsRequest::for_scope(&empty_scope).expect("request");
    let empty = DescribeAlarmsResponse::new(
        &describe_request,
        Vec::new(),
        None,
        256,
        TransportProvenance::Recording,
    )
    .expect("empty response");
    let mut empty_transport = RecordingTransport::default();
    empty_transport.push_describe_response(Ok(empty));
    let mut empty_service = service_with_transport(empty_scope, empty_transport);
    let empty_result = empty_service.read_bounded().expect("empty evidence");
    assert_eq!(empty_result.evidence.status, EvidenceStatus::Empty);
    assert!(!empty_result.evidence.is_adoptable());

    let partial_scope = scope(false);
    let describe_request = DescribeAlarmsRequest::for_scope(&partial_scope).expect("request");
    let cursor = OpaqueCursor::new("page-two").expect("cursor");
    let partial = DescribeAlarmsResponse::new(
        &describe_request,
        vec![alarm(&partial_scope)],
        Some(cursor),
        256,
        TransportProvenance::Recording,
    )
    .expect("partial response");
    let mut partial_transport = RecordingTransport::default();
    partial_transport.push_describe_response(Ok(partial));
    let mut partial_service = service_with_transport(partial_scope.clone(), partial_transport);
    let partial_request = AwsCloudWatchReadRequest::bounded(&partial_scope, false, 1, 1024, 0)
        .expect("one-page request");
    let partial_result = partial_service
        .read(partial_request)
        .expect("partial evidence");
    assert_eq!(partial_result.evidence.status, EvidenceStatus::Partial);
    assert!(!partial_result.evidence.is_adoptable());
}

#[test]
fn cursor_replay_is_bounded_and_fail_closed() {
    let scope = scope(false);
    let describe_request = DescribeAlarmsRequest::for_scope(&scope).expect("describe request");
    let describe = DescribeAlarmsResponse::new(
        &describe_request,
        vec![alarm(&scope)],
        None,
        256,
        TransportProvenance::Recording,
    )
    .expect("describe response");
    let metric_request = GetMetricDataRequest::for_scope(&scope).expect("metric request");
    let cursor_one = OpaqueCursor::new("replayed-token").expect("cursor");
    let metric_page_one = GetMetricDataResponse::new(
        &metric_request,
        vec![aggregate(&scope, "page-one")],
        Some(cursor_one),
        256,
        TransportProvenance::Recording,
    )
    .expect("metric page one");
    let metric_request_two = metric_request
        .with_cursor(metric_page_one.next_cursor.clone().expect("next cursor"))
        .expect("page two request");
    let cursor_two = OpaqueCursor::with_page("replayed-token", 3).expect("replayed cursor");
    let metric_page_two = GetMetricDataResponse::new(
        &metric_request_two,
        vec![aggregate(&scope, "page-two")],
        Some(cursor_two),
        256,
        TransportProvenance::Recording,
    )
    .expect("metric page two");
    let mut transport = RecordingTransport::default();
    transport.push_describe_response(Ok(describe));
    transport.push_metric_response(Ok(metric_page_one));
    transport.push_metric_response(Ok(metric_page_two));
    let mut service = service_with_transport(scope, transport);
    let result = service.read_bounded().expect("replay evidence");
    assert_eq!(result.evidence.status, EvidenceStatus::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_cloudwatch_alarm_result_plugin::PartialReason::ScanLoop)
    );
    assert!(!result.evidence.is_adoptable());
}

#[test]
fn drift_and_response_tamper_are_rejected_by_provider_before_evidence() {
    let scope = scope(false);
    let describe_request = DescribeAlarmsRequest::for_scope(&scope).expect("describe request");
    let mut drifted = DescribeAlarmsResponse::new(
        &describe_request,
        vec![alarm(&scope)],
        None,
        256,
        TransportProvenance::Recording,
    )
    .expect("describe response");
    drifted.alarms[0].identity.revision = Revision::new(2).expect("drift revision");
    let mut transport = RecordingTransport::default();
    transport.push_describe_response(Ok(drifted));
    let mut service = service_with_transport(scope.clone(), transport);
    assert!(matches!(
        service.read_bounded(),
        Err(AwsCloudWatchAlarmServiceError::Provider(_))
    ));

    let metric_request = GetMetricDataRequest::for_scope(&scope).expect("metric request");
    let mut tampered = GetMetricDataResponse::new(
        &metric_request,
        vec![aggregate(&scope, "tamper")],
        None,
        256,
        TransportProvenance::Recording,
    )
    .expect("metric response");
    tampered.response_digest = Digest::from_text("tampered-response");
    let (describe, _) = queued_success_responses(&scope);
    let mut transport = RecordingTransport::default();
    transport.push_describe_response(Ok(describe));
    transport.push_metric_response(Ok(tampered));
    let mut service = service_with_transport(scope, transport);
    assert!(matches!(
        service.read_bounded(),
        Err(AwsCloudWatchAlarmServiceError::Provider(_))
    ));
}

#[test]
fn access_loss_and_retry_classes_fail_closed_without_native_claims() {
    let cases = [
        (
            AwsCloudWatchTransportError::BadRequest,
            EvidenceStatus::ProviderUnknown,
        ),
        (
            AwsCloudWatchTransportError::Unauthenticated,
            EvidenceStatus::AccessLoss,
        ),
        (
            AwsCloudWatchTransportError::AccessDenied,
            EvidenceStatus::AccessLoss,
        ),
        (
            AwsCloudWatchTransportError::NotFound,
            EvidenceStatus::AccessLoss,
        ),
    ];
    for (error, expected_status) in cases {
        let scope = scope(false);
        let mut transport = RecordingTransport::default();
        transport.push_describe_response(Err(error));
        let mut service = service_with_transport(scope, transport);
        let result = service.read_bounded().expect("failure evidence");
        assert_eq!(result.evidence.status, expected_status);
        assert!(!result.evidence.connected);
        assert!(!result.evidence.native);
        assert!(!result.evidence.first_party);
        assert!(!result.evidence.is_adoptable());
    }

    for error in [
        AwsCloudWatchTransportError::RateLimited {
            retry_after_seconds: Some(1),
        },
        AwsCloudWatchTransportError::ServerFailure { status_code: 500 },
        AwsCloudWatchTransportError::Timeout,
    ] {
        let scope = scope(false);
        let mut transport = RecordingTransport::default();
        transport.push_describe_response(Err(error.clone()));
        transport.push_describe_response(Err(error.clone()));
        transport.push_describe_response(Err(error));
        let mut service = service_with_transport(scope, transport);
        let result = service.read_bounded().expect("retry failure evidence");
        assert_eq!(result.evidence.status, EvidenceStatus::ProviderUnknown);
        assert!(result.evidence.retry_count > 0);
        assert!(!result.evidence.is_adoptable());
    }
}

#[test]
fn secret_and_registration_revocation_replay_are_rejected() {
    let scope = scope(false);
    let (describe, metric) = queued_success_responses(&scope);
    let mut transport = RecordingTransport::default();
    transport.push_describe_response(Ok(describe));
    transport.push_metric_response(Ok(metric));
    let mut service = service_with_transport(scope.clone(), transport);
    let registration = service.registration().clone();
    let mut consumer = MissionAwsCloudWatchConsumer::new(&scope);
    consumer
        .bind_registration(&registration)
        .expect("registration");
    let result = service.read_bounded().expect("read");
    consumer.consume(&result).expect("consume");

    let mut tampered_registration = registration;
    tampered_registration.scope_digest = Digest::from_text("replayed-scope");
    assert!(consumer.bind_registration(&tampered_registration).is_err());

    service.revoke_secret_reference();
    assert!(matches!(
        service.read_bounded(),
        Err(AwsCloudWatchAlarmServiceError::SecretRevoked)
    ));
}

#[test]
fn capabilities_and_contract_exclude_writes_and_certification() {
    let capabilities = AwsCloudWatchAlarmService::<FixtureTransport>::describe_capabilities();
    assert!(capabilities.read_only);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.first_party);
    assert!(!capabilities.production_slo_certification);
    assert!(!capabilities.outcome_authority);
    assert_eq!(
        capabilities.allowlisted_api_operations,
        ["DescribeAlarms", "GetMetricData", "ListMetrics"]
    );
    let contract =
        hartevo_aws_cloudwatch_alarm_result_plugin::AwsCloudWatchAlarmContract::baseline()
            .expect("contract");
    let forbidden = contract.value()["forbidden"].as_array().expect("forbidden");
    assert!(forbidden.iter().any(|value| value == "PutMetricData"));
    assert!(forbidden.iter().any(|value| value == "dashboard_mutation"));
    assert!(
        forbidden
            .iter()
            .any(|value| value == "claim_production_slo")
    );
    assert!(!forbidden.iter().any(|value| value == "DescribeAlarms"));
    assert!(AwsCloudWatchOperation::GetMetricData.permission() == PermissionAction::GetMetricData);
}
