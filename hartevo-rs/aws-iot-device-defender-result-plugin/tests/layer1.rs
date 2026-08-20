#![allow(clippy::too_many_lines)]

use chrono::{DateTime, Utc};
use hartevo_aws_iot_device_defender_result_plugin::{
    API_REVISION, AuditCheckSummary, AuditEvidenceState, AuditFinding, AuditTaskBinding,
    AuditTaskMetadata, AuditTaskStatus, AwsIotDeviceDefenderContract, AwsIotDeviceDefenderError,
    AwsIotDeviceDefenderProvider, AwsIotDeviceDefenderScope, AwsIotDeviceDefenderService,
    AwsIotDeviceDefenderTransportError, AwsRegion, CheckBinding, CheckName, CheckState, Digest,
    FixtureTransport, ListAuditFindingsRequest, ListAuditFindingsResponse, ListAuditTasksRequest,
    ListAuditTasksResponse, LoopbackTransport, MissionBinding, PermissionFence, PermissionId,
    ProjectBinding, ProjectId, RecordingTransport, ResourceBinding, ResourceId, ResourceType,
    Revision, SecretReference, Severity, TransportProvenance, WorkProductBinding, WorkProductId,
};

type Service<T> = AwsIotDeviceDefenderService<T>;

const ACCOUNT: &str = "123456789012";
const REGION: &str = "us-east-1";
const TASK_ID: &str = "audit-task-1";
const CHECK_NAME: &str = "AUTHENTICATED_COGNITO_ROLE_OVERLY_PERMISSIVE_CHECK";
const RESOURCE_TYPE: &str = "AWS::IoT::Thing";
const RESOURCE_ID: &str = "thing-secret-device-1";
const RAW_SECRET_HANDLE: &str = "sigv4-secret-handle";

fn at(hour: i64) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&format!("2026-08-15T{hour:02}:00:00Z"))
        .expect("timestamp")
        .with_timezone(&Utc)
}

fn scope(retention_hour: i64) -> (AwsIotDeviceDefenderScope, PermissionFence) {
    let task = AuditTaskBinding::new(
        hartevo_aws_iot_device_defender_result_plugin::AuditTaskId::new(TASK_ID).expect("task"),
        Revision::new(7).expect("task revision"),
    );
    let check = CheckBinding::new(
        CheckName::new(CHECK_NAME).expect("check"),
        Revision::new(3).expect("check revision"),
    );
    let resource = ResourceBinding::new(
        ResourceType::new(RESOURCE_TYPE).expect("resource type"),
        ResourceId::new(RESOURCE_ID).expect("resource"),
        Revision::new(4).expect("resource revision"),
    );
    let permission = PermissionFence::readonly(
        PermissionId::new("iot-device-defender-read").expect("permission"),
        Revision::new(2).expect("permission revision"),
    )
    .expect("permission fence");
    let scope = AwsIotDeviceDefenderScope::new(
        hartevo_aws_iot_device_defender_result_plugin::AccountId::new(ACCOUNT).expect("account"),
        AwsRegion::new(REGION).expect("region"),
        task,
        [check],
        [resource],
        MissionBinding::new(
            hartevo_aws_iot_device_defender_result_plugin::MissionId::new("mission-1")
                .expect("mission"),
            Revision::new(8).expect("mission revision"),
        ),
        ProjectBinding::new(
            ProjectId::new("project-1").expect("project"),
            Revision::new(5).expect("project revision"),
        ),
        WorkProductBinding::new(
            WorkProductId::new("work-product-1").expect("work product"),
            Revision::new(6).expect("work product revision"),
        ),
        at(retention_hour),
    )
    .expect("scope");
    (scope, permission)
}

fn task(scope: &AwsIotDeviceDefenderScope) -> AuditTaskMetadata {
    AuditTaskMetadata::new(scope.audit_task.clone(), AuditTaskStatus::Complete, at(2))
}

fn check(scope: &AwsIotDeviceDefenderScope) -> AuditCheckSummary {
    AuditCheckSummary::new(
        scope.checks[0].clone(),
        CheckState::Compliant,
        Severity::High,
        1,
        0,
    )
    .expect("check summary")
}

fn finding(scope: &AwsIotDeviceDefenderScope) -> AuditFinding {
    AuditFinding::new(
        scope.checks[0].clone(),
        scope.resources[0].clone(),
        Severity::High,
        false,
        at(2),
    )
}

fn recording_service() -> (Service<RecordingTransport>, AwsIotDeviceDefenderScope) {
    let (scope, permission) = scope(12);
    let list_request = ListAuditTasksRequest::new(&scope, 100, 4, None).expect("list request");
    let describe_request =
        hartevo_aws_iot_device_defender_result_plugin::DescribeAuditTaskRequest::for_scope(&scope);
    let findings_request =
        ListAuditFindingsRequest::for_scope(&scope, 100, 4, None).expect("findings request");
    let mut transport = RecordingTransport::default();
    transport.push_list_audit_tasks(Ok(ListAuditTasksResponse::new(
        &list_request,
        1,
        vec![task(&scope)],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("tasks response")));
    transport.push_describe_audit_task(Ok(
        hartevo_aws_iot_device_defender_result_plugin::DescribeAuditTaskResponse::new(
            &describe_request,
            task(&scope),
            vec![check(&scope)],
            512,
            TransportProvenance::Recording,
        )
        .expect("describe response"),
    ));
    transport.push_list_audit_findings(Ok(ListAuditFindingsResponse::new(
        &findings_request,
        1,
        vec![finding(&scope)],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("findings response")));
    let provider = AwsIotDeviceDefenderProvider::new(transport).expect("provider");
    let secret = SecretReference::for_sigv4(RAW_SECRET_HANDLE, &scope).expect("secret");
    let service =
        Service::new(scope.clone(), secret, permission, provider, at(1)).expect("service");
    (service, scope)
}

#[test]
fn contract_scope_registration_and_capabilities_are_digest_bound() {
    AwsIotDeviceDefenderContract::baseline().expect("contract");
    let (service, scope) = recording_service();
    assert!(service.registration().validate().is_ok());
    assert_eq!(service.registration().scope_digest, scope.digest());
    assert_eq!(service.registration().provider_revision, API_REVISION);
    assert_eq!(service.describe_capabilities().operations.len(), 3);
    assert!(service.describe_capabilities().read_only);
    assert!(service.describe_capabilities().proposal_only);
    assert!(!service.describe_capabilities().connected);
    assert!(!service.describe_capabilities().native);
    assert!(!service.describe_capabilities().external_writes);
}

#[test]
fn secret_cursor_scope_and_finding_identity_are_opaque_and_redacted() {
    let (service, scope) = recording_service();
    let secret_json = serde_json::to_string(service.secret_reference()).expect("secret JSON");
    assert_eq!(secret_json, r#"{"opaque":true}"#);
    assert!(!format!("{:?}", service.secret_reference()).contains(RAW_SECRET_HANDLE));
    let cursor = hartevo_aws_iot_device_defender_result_plugin::OpaqueCursor::new(
        "provider-next-token-secret",
    )
    .expect("cursor");
    assert_eq!(
        serde_json::to_string(&cursor).expect("cursor JSON"),
        r#"{"opaque":true}"#
    );
    assert!(!format!("{cursor:?}").contains("provider-next-token-secret"));
    let request =
        ListAuditFindingsRequest::for_scope(&scope, 50, 4, Some(cursor)).expect("bound request");
    let serialized = serde_json::to_string(&request).expect("request JSON");
    assert!(!serialized.contains("provider-next-token-secret"));
    let proposal = {
        let mut service = recording_service().0;
        let request = service.default_request(at(1)).expect("request");
        service.propose(&request).expect("proposal")
    };
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!serialized.contains(RESOURCE_ID));
    assert!(!serialized.contains(RAW_SECRET_HANDLE));
    assert!(!serialized.contains("certificateArn"));
    assert!(!serialized.contains("additionalInfo"));
}

#[test]
fn complete_read_propose_verify_consume_and_record_are_review_only() {
    let (mut service, _) = recording_service();
    let request = service.default_request(at(1)).expect("request");
    let proposal = service.propose(&request).expect("proposal");
    assert_eq!(proposal.state, AuditEvidenceState::Complete);
    assert_eq!(proposal.evidence.checks.len(), 1);
    assert_eq!(proposal.evidence.findings.len(), 1);
    assert_eq!(proposal.evidence.findings[0].severity, Severity::High);
    assert!(!proposal.evidence.findings[0].suppressed);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(service.verify_at(&proposal, at(3)).valid);
    let mut consumer = service.consumer().expect("consumer");
    let result = consumer.consume(proposal.clone()).expect("mission result");
    assert_eq!(
        result.consumer_id,
        "mission.aws-iot-device-defender.consumer"
    );
    assert!(result.requires_human_review);
    assert!(!result.safe_to_promote);
    assert!(!result.adopted_outcome);
    assert!(!result.adopted_work_product);
    assert!(!result.truth_authority);
    let first = consumer
        .record_at(&proposal, "mission-record-1", at(3))
        .expect("record");
    let replay = consumer
        .record_at(&proposal, "mission-record-1", at(4))
        .expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    assert!(service.record_at(&proposal, at(3)).is_ok());
}

#[test]
fn fixture_loopback_and_blocked_env_never_claim_connected_or_native() {
    let (scope, permission) = scope(12);
    let fixture_provider =
        AwsIotDeviceDefenderProvider::new(FixtureTransport::default()).expect("fixture provider");
    assert!(!fixture_provider.definition().connected);
    assert!(!fixture_provider.definition().native);
    assert!(!fixture_provider.definition().first_party);
    let loopback_provider =
        AwsIotDeviceDefenderProvider::new(LoopbackTransport::default()).expect("loopback provider");
    assert!(!loopback_provider.definition().connected);
    assert!(!loopback_provider.definition().native);
    assert!(!loopback_provider.definition().first_party);
    let blocked_provider = AwsIotDeviceDefenderProvider::new(
        hartevo_aws_iot_device_defender_result_plugin::BlockedEnvAwsIotDeviceDefenderTransport,
    )
    .expect("blocked provider");
    let secret = SecretReference::for_sigv4(RAW_SECRET_HANDLE, &scope).expect("secret");
    let mut service = Service::new(scope.clone(), secret, permission, blocked_provider, at(1))
        .expect("blocked service");
    let request = service.default_request(at(1)).expect("request");
    let proposal = service.propose(&request).expect("blocked proposal");
    assert_eq!(proposal.state, AuditEvidenceState::ProviderUnknown);
    assert_eq!(
        proposal.evidence.provenance,
        TransportProvenance::BlockedEnv
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
}

#[test]
fn transport_statuses_fail_closed_without_connected_evidence() {
    let cases = [
        (
            AwsIotDeviceDefenderTransportError::BadRequest,
            AuditEvidenceState::ProviderUnknown,
        ),
        (
            AwsIotDeviceDefenderTransportError::Unauthorized,
            AuditEvidenceState::AccessLoss,
        ),
        (
            AwsIotDeviceDefenderTransportError::Forbidden,
            AuditEvidenceState::AccessLoss,
        ),
        (
            AwsIotDeviceDefenderTransportError::NotFound,
            AuditEvidenceState::NotFound,
        ),
        (
            AwsIotDeviceDefenderTransportError::RateLimited {
                retry_after_seconds: Some(10),
            },
            AuditEvidenceState::Throttled,
        ),
        (
            AwsIotDeviceDefenderTransportError::ServerFailure {
                status_code: Some(500),
            },
            AuditEvidenceState::ProviderUnknown,
        ),
        (
            AwsIotDeviceDefenderTransportError::Timeout,
            AuditEvidenceState::ProviderUnknown,
        ),
    ];
    for (error, expected) in cases {
        let (scope, permission) = scope(12);
        let list_request = ListAuditTasksRequest::new(&scope, 50, 4, None).expect("request");
        let mut transport = RecordingTransport::default();
        transport.push_list_audit_tasks(Err(error));
        let provider = AwsIotDeviceDefenderProvider::new(transport).expect("provider");
        let secret = SecretReference::for_sigv4(RAW_SECRET_HANDLE, &scope).expect("secret");
        let mut service =
            Service::new(scope, secret, permission, provider, at(1)).expect("service");
        let request = service.default_request(at(1)).expect("request");
        let proposal = service.propose(&request).expect("failure proposal");
        assert_eq!(proposal.state, expected);
        assert_eq!(proposal.evidence.list_pages, 1);
        assert!(!proposal.connected);
        assert!(!proposal.native);
        assert!(list_request.page_size > 0);
    }
}

#[test]
fn retention_expiry_task_check_resource_drift_and_pagination_fail_closed() {
    let (mut service, _expired_scope) = recording_service();
    let expired_request = service.request(50, 4, at(13)).expect("expired request");
    let expired = service.propose(&expired_request).expect("expired proposal");
    assert_eq!(expired.state, AuditEvidenceState::RetentionExpired);
    assert!(!service.verify_at(&expired, at(13)).valid);

    let (drift_scope, permission) = scope(12);
    let list_request =
        ListAuditTasksRequest::new(&drift_scope, 100, 4, None).expect("list request");
    let describe_request =
        hartevo_aws_iot_device_defender_result_plugin::DescribeAuditTaskRequest::for_scope(
            &drift_scope,
        );
    let findings_request =
        ListAuditFindingsRequest::for_scope(&drift_scope, 100, 4, None).expect("findings request");
    let mut transport = RecordingTransport::default();
    transport.push_list_audit_tasks(Ok(ListAuditTasksResponse::new(
        &list_request,
        1,
        vec![task(&drift_scope)],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("tasks")));
    let drift_check = CheckBinding::new(
        CheckName::new("DRIFTED_CHECK").expect("drift check"),
        Revision::new(99).expect("drift revision"),
    );
    transport.push_describe_audit_task(Ok(
        hartevo_aws_iot_device_defender_result_plugin::DescribeAuditTaskResponse::new(
            &describe_request,
            task(&drift_scope),
            vec![
                AuditCheckSummary::new(drift_check, CheckState::Unknown, Severity::Unknown, 0, 0)
                    .expect("drift summary"),
            ],
            512,
            TransportProvenance::Recording,
        )
        .expect("describe"),
    ));
    transport.push_list_audit_findings(Ok(ListAuditFindingsResponse::new(
        &findings_request,
        1,
        vec![],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("findings")));
    let provider = AwsIotDeviceDefenderProvider::new(transport).expect("provider");
    let secret = SecretReference::for_sigv4(RAW_SECRET_HANDLE, &drift_scope).expect("secret");
    let mut drift_service =
        Service::new(drift_scope.clone(), secret, permission, provider, at(1)).expect("service");
    let request = drift_service.default_request(at(1)).expect("request");
    let drift = drift_service.propose(&request).expect("drift proposal");
    assert_eq!(drift.state, AuditEvidenceState::CheckDrift);
    assert!(!drift_service.verify_at(&drift, at(3)).valid);

    let (loop_scope, permission) = scope(12);
    let first_request =
        ListAuditTasksRequest::new(&loop_scope, 50, 2, None).expect("bounded request");
    let loop_cursor =
        hartevo_aws_iot_device_defender_result_plugin::OpaqueCursor::new("same-token")
            .expect("cursor");
    let first_page = ListAuditTasksResponse::new(
        &first_request,
        1,
        vec![task(&loop_scope)],
        Some(loop_cursor),
        512,
        TransportProvenance::Recording,
    )
    .expect("first page");
    let second_request =
        ListAuditTasksRequest::new(&loop_scope, 50, 2, first_page.next_cursor.clone())
            .expect("second request");
    let second_page = ListAuditTasksResponse::new(
        &second_request,
        2,
        vec![task(&loop_scope)],
        Some(
            hartevo_aws_iot_device_defender_result_plugin::OpaqueCursor::new("same-token")
                .expect("cursor"),
        ),
        512,
        TransportProvenance::Recording,
    )
    .expect("second page");
    let mut transport = RecordingTransport::default();
    transport.push_list_audit_tasks(Ok(first_page));
    transport.push_list_audit_tasks(Ok(second_page));
    let provider = AwsIotDeviceDefenderProvider::new(transport).expect("provider");
    let secret = SecretReference::for_sigv4(RAW_SECRET_HANDLE, &loop_scope).expect("secret");
    let mut loop_service =
        Service::new(loop_scope, secret, permission, provider, at(1)).expect("service");
    let request = loop_service.request(50, 2, at(1)).expect("request");
    let looped = loop_service.propose(&request).expect("loop proposal");
    assert_eq!(looped.state, AuditEvidenceState::PaginationLoop);
    assert!(!loop_service.verify_at(&looped, at(3)).valid);
}

#[test]
fn tamper_replay_and_registration_revocation_are_fenced() {
    let (_service, scope) = recording_service();
    let list_request = ListAuditTasksRequest::new(&scope, 100, 4, None).expect("request");
    let tampered = ListAuditTasksResponse::new(
        &list_request,
        1,
        vec![task(&scope)],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("response")
    .with_declared_digest(Digest::from_text("tampered-page"));
    let mut transport = RecordingTransport::default();
    transport.push_list_audit_tasks(Ok(tampered));
    let provider = AwsIotDeviceDefenderProvider::new(transport).expect("provider");
    let secret = SecretReference::for_sigv4(RAW_SECRET_HANDLE, &scope).expect("secret");
    let permission = PermissionFence::readonly(
        PermissionId::new("iot-device-defender-read").expect("permission"),
        Revision::new(2).expect("revision"),
    )
    .expect("permission");
    let mut tamper_service =
        Service::new(scope.clone(), secret, permission, provider, at(1)).expect("service");
    let request = tamper_service.default_request(at(1)).expect("request");
    let error = tamper_service
        .propose(&request)
        .expect_err("tamper must reject");
    assert_eq!(error, AwsIotDeviceDefenderError::EvidenceTampered);

    let (mut service, _) = recording_service();
    let request = service.default_request(at(1)).expect("request");
    let proposal = service.propose(&request).expect("proposal");
    let mut consumer = service.consumer().expect("consumer");
    assert!(consumer.record_at(&proposal, "same-key", at(3)).is_ok());
    let conflict = consumer
        .record_at(&proposal, "same-key", at(3))
        .expect("exact replay");
    assert!(conflict.replayed);
    service.revoke_registration().expect("revoke");
    assert!(service.propose(&request).is_err());
    assert!(!service.verify_at(&proposal, at(3)).valid);
    service.restore_registration().expect("restore");
    assert!(service.default_request(at(1)).is_ok());
    service.reverse_registration().expect("reverse");
    assert!(service.restore_registration().is_err());
}

#[test]
fn identifier_allowlist_rejects_raw_effects_and_only_read_permissions_exist() {
    let (scope, permission) = scope(12);
    assert!(scope.allows_check(&scope.checks[0]));
    assert!(scope.allows_resource(&scope.resources[0]));
    assert_eq!(permission.actions.len(), 4);
    let json = serde_json::to_string(&scope).expect("scope JSON");
    assert!(!json.contains(RESOURCE_ID));
    assert!(!json.contains("StartAuditTask"));
    assert!(!json.contains("CancelAuditTask"));
    assert!(!json.contains("certificate"));
    assert!(!json.contains("roleArn"));
}
