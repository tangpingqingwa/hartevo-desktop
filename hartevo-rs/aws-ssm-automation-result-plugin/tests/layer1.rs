use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_ssm_automation_result_plugin::{
    AutomationDocumentName, AutomationDocumentVersion, AutomationEvidenceState,
    AutomationExecutionId, AutomationExecutionMetadata, AutomationExecutionStatus,
    AutomationStepMetadata, AutomationStepName, AwsAccountId, AwsRegion, AwsSsmAutomationProvider,
    AwsSsmAutomationReadRequest, AwsSsmAutomationScope, AwsSsmAutomationService,
    AwsSsmAutomationTransportError, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_JSON,
    CONTRACT_SCHEMA_VERSION, CONTRACT_VERSION, DescribeAutomationExecutionsResponse,
    DescribeAutomationStepExecutionsResponse, FixtureTransport, GetAutomationExecutionResponse,
    Layer1Authority, MAX_RESPONSE_BYTES, MissionIdentity, PROVIDER_ID, PermissionSnapshot,
    ProjectIdentity, RecordingTransport, SERVICE_ID, SecretReference, TargetSelector,
    TransportProvenance, WorkProductIdentity,
};

const NOW_SECONDS: i64 = 1_787_000_000;
const RAW_OUTPUT: &str = "fixture-secret-output-that-must-not-be-retained";
const RAW_ERROR: &str = "provider-private-error-that-must-not-be-retained";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn scope_with(step: Option<&str>, target: Option<&str>) -> AwsSsmAutomationScope {
    let permission = PermissionSnapshot::readonly("ssm-read-only", 1).expect("permission");
    AwsSsmAutomationScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        AutomationDocumentName::new("AWS-RunShellScript").expect("document"),
        AutomationDocumentVersion::new("3").expect("document version"),
        AutomationExecutionId::new("11111111-1111-1111-1111-111111111111").expect("execution"),
        step.map(|value| AutomationStepName::new(value).expect("step")),
        target.map(|value| TargetSelector::new("InstanceIds", value).expect("target")),
        MissionIdentity::new("mission-1", 7).expect("mission"),
        ProjectIdentity::new("project-1", 11).expect("project"),
        WorkProductIdentity::new("work-product-1", 13).expect("work product"),
        permission.digest(),
    )
    .expect("scope")
}

fn scope() -> AwsSsmAutomationScope {
    scope_with(Some("RunScript"), Some("i-0123456789abcdef0"))
}

fn secret(scope: &AwsSsmAutomationScope) -> SecretReference {
    SecretReference::for_ssm("opaque-sigv4-handle", scope).expect("secret reference")
}

fn execution(
    scope: &AwsSsmAutomationScope,
    status: AutomationExecutionStatus,
    revision: u64,
    created_at: DateTime<Utc>,
) -> AutomationExecutionMetadata {
    AutomationExecutionMetadata::new(
        scope.execution_id.clone(),
        scope.document_name.clone(),
        scope.document_version.clone(),
        revision,
        scope.target.clone(),
        status,
        created_at,
        now(),
        Some(RAW_OUTPUT),
        Some(RAW_ERROR),
    )
    .expect("execution")
}

fn step(
    scope: &AwsSsmAutomationScope,
    status: AutomationExecutionStatus,
) -> AutomationStepMetadata {
    AutomationStepMetadata::new(
        scope.step_name.clone().expect("scoped step"),
        1,
        status,
        scope.target.clone(),
        now() - Duration::minutes(1),
        now(),
        Some(RAW_OUTPUT),
        Some(RAW_ERROR),
    )
    .expect("step")
}

fn recording_service(
    scope: &AwsSsmAutomationScope,
    transport: RecordingTransport,
) -> AwsSsmAutomationService<RecordingTransport> {
    let permission = PermissionSnapshot::readonly("ssm-read-only", 1).expect("permission");
    let provider = AwsSsmAutomationProvider::new(transport).expect("provider");
    AwsSsmAutomationService::new(scope.clone(), secret(scope), permission, provider, now())
        .expect("service")
}

fn queue_read(
    transport: &mut RecordingTransport,
    scope: &AwsSsmAutomationScope,
    status: AutomationExecutionStatus,
    revision: u64,
    provenance: TransportProvenance,
) {
    let request = AwsSsmAutomationReadRequest::for_scope(scope).expect("request");
    let listed = execution(scope, status, revision, now() - Duration::minutes(2));
    let list = DescribeAutomationExecutionsResponse::new(
        &request.describe_request(),
        [listed.clone()],
        None,
        true,
        512,
        provenance,
    )
    .expect("list response");
    let detail =
        GetAutomationExecutionResponse::new(&request.get_request(), listed, 512, provenance);
    let steps = DescribeAutomationStepExecutionsResponse::new(
        &request.steps_request(),
        [step(scope, status)],
        None,
        true,
        512,
        provenance,
    )
    .expect("step response");
    transport.push_describe_automation_executions(Ok(list));
    transport.push_get_automation_execution(Ok(detail));
    transport.push_describe_automation_step_executions(Ok(steps));
}

#[test]
fn contract_scope_and_opaque_redaction_are_explicit() {
    let contract = hartevo_aws_ssm_automation_result_plugin::AwsSsmAutomationContract::baseline()
        .expect("contract");
    assert_eq!(contract.value()["schemaVersion"], CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.value()["contractVersion"], CONTRACT_VERSION);
    assert_eq!(contract.value()["contractDigest"], CONTRACT_DIGEST);
    assert_eq!(contract.value()["consumer"]["id"], CONSUMER_ID);
    assert_eq!(contract.value()["service"]["id"], SERVICE_ID);
    assert_eq!(contract.value()["provider"]["id"], PROVIDER_ID);
    assert!(CONTRACT_JSON.contains("DescribeAutomationStepExecutions"));
    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native());
    assert!(!Layer1Authority::adopted_outcome());

    let scope = scope();
    let reference = secret(&scope);
    let serialized = serde_json::to_string(&reference).expect("opaque secret JSON");
    assert_eq!(serialized, r#"{"opaque":true}"#);
    assert!(!format!("{reference:?}").contains("opaque-sigv4-handle"));
    let request = AwsSsmAutomationReadRequest::for_scope(&scope)
        .expect("request")
        .with_cursor(Some(
            hartevo_aws_ssm_automation_result_plugin::OpaqueCursor::new("raw-next-token")
                .expect("cursor"),
        ))
        .expect("bound cursor");
    let path = request.describe_request().path_and_query();
    assert!(!path.contains("raw-next-token"));
    assert!(
        path.contains(
            request
                .filter
                .cursor
                .as_ref()
                .expect("cursor")
                .token_digest()
                .as_str()
        )
    );

    let serialized_scope = serde_json::to_string(&scope).expect("scope JSON");
    assert!(!serialized_scope.contains("i-0123456789abcdef0"));
}

#[test]
fn fixture_proposal_record_verify_and_consume_are_below_kernel_authority() {
    let scope = scope();
    let provider = AwsSsmAutomationProvider::new(FixtureTransport::for_scope(&scope, now()))
        .expect("fixture provider");
    let permission = PermissionSnapshot::readonly("ssm-read-only", 1).expect("permission");
    let mut service =
        AwsSsmAutomationService::new(scope.clone(), secret(&scope), permission, provider, now())
            .expect("service");
    assert_eq!(
        service.provider().provenance(),
        TransportProvenance::Fixture
    );
    assert!(!service.describe_capabilities().connected);
    assert!(!service.describe_capabilities().native);
    let request = service.default_request().expect("request");
    let proposal = service.propose(&request).expect("proposal");
    assert_eq!(proposal.evidence.state, AutomationEvidenceState::Success);
    assert!(proposal.evidence.review_only());
    assert!(!proposal.can_be_adopted());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!serialized.contains("fixture-output-not-retained"));
    assert!(!serialized.contains("fixture-step-output-not-retained"));
    assert!(!serialized.contains(RAW_OUTPUT));
    assert!(!serialized.contains(RAW_ERROR));
    let report = service.verify(&proposal).expect("verification");
    assert!(report.valid);
    assert!(report.review_eligible);
    assert!(!report.adopted_outcome);
    let record = service.record(&proposal, "recording-key").expect("record");
    let replay = service.record(&proposal, "recording-key").expect("replay");
    assert!(!record.replayed);
    assert!(replay.replayed);
    assert_eq!(service.record_count(), 1);
    let mut consumer = service.consumer().expect("consumer");
    let mission_result = consumer.consume(&proposal).expect("mission result");
    assert_eq!(mission_result.consumer_id, CONSUMER_ID);
    assert!(!mission_result.outcome_adopted);
    assert!(!mission_result.work_product_adopted);
    let consumer_record = consumer
        .record(&proposal, "mission-recording-key")
        .expect("mission record");
    assert!(!consumer_record.replayed);
}

#[test]
fn execution_replacement_and_status_regression_fail_closed() {
    let scope = scope();
    let mut transport = RecordingTransport::default();
    queue_read(
        &mut transport,
        &scope,
        AutomationExecutionStatus::Pending,
        1,
        TransportProvenance::Recording,
    );
    queue_read(
        &mut transport,
        &scope,
        AutomationExecutionStatus::InProgress,
        1,
        TransportProvenance::Recording,
    );
    queue_read(
        &mut transport,
        &scope,
        AutomationExecutionStatus::Success,
        1,
        TransportProvenance::Recording,
    );
    queue_read(
        &mut transport,
        &scope,
        AutomationExecutionStatus::Pending,
        1,
        TransportProvenance::Recording,
    );
    let mut service = recording_service(&scope, transport);
    let request = service.default_request().expect("request");
    assert_eq!(
        service.propose(&request).expect("pending").evidence.state,
        AutomationEvidenceState::Pending
    );
    assert_eq!(
        service
            .propose(&request)
            .expect("in progress")
            .evidence
            .state,
        AutomationEvidenceState::InProgress
    );
    assert_eq!(
        service.propose(&request).expect("success").evidence.state,
        AutomationEvidenceState::Success
    );
    assert_eq!(
        service
            .propose(&request)
            .expect("regression proposal")
            .evidence
            .state,
        AutomationEvidenceState::ProviderUnknown
    );

    let mut replacement_transport = RecordingTransport::default();
    queue_read(
        &mut replacement_transport,
        &scope,
        AutomationExecutionStatus::InProgress,
        1,
        TransportProvenance::Recording,
    );
    queue_read(
        &mut replacement_transport,
        &scope,
        AutomationExecutionStatus::InProgress,
        2,
        TransportProvenance::Recording,
    );
    let mut replacement_service = recording_service(&scope, replacement_transport);
    let request = replacement_service.default_request().expect("request");
    let _ = replacement_service
        .propose(&request)
        .expect("initial execution");
    assert_eq!(
        replacement_service
            .propose(&request)
            .expect("replacement proposal")
            .evidence
            .state,
        AutomationEvidenceState::ExecutionReplaced
    );
}

#[test]
fn step_and_target_scope_mismatches_are_not_downgraded_to_warnings() {
    let scope = scope();
    let request = AwsSsmAutomationReadRequest::for_scope(&scope).expect("request");
    let wrong_target = TargetSelector::new("InstanceIds", "i-0wrongtarget").expect("target");
    let wrong_execution = execution(
        &AwsSsmAutomationScope::new(
            scope.account_id.clone(),
            scope.region.clone(),
            scope.document_name.clone(),
            scope.document_version.clone(),
            scope.execution_id.clone(),
            scope.step_name.clone(),
            Some(wrong_target),
            scope.mission.clone(),
            scope.project.clone(),
            scope.work_product.clone(),
            scope.permission_digest.clone(),
        )
        .expect("wrong target scope"),
        AutomationExecutionStatus::Success,
        1,
        now(),
    );
    let mut target_transport = RecordingTransport::default();
    target_transport.push_describe_automation_executions(Ok(
        DescribeAutomationExecutionsResponse::new(
            &request.describe_request(),
            [wrong_execution],
            None,
            true,
            512,
            TransportProvenance::Recording,
        )
        .expect("list"),
    ));
    let mut target_service = recording_service(&scope, target_transport);
    assert!(target_service.propose(&request).is_err());

    let wrong_step = AutomationStepMetadata::new(
        AutomationStepName::new("DifferentStep").expect("step"),
        1,
        AutomationExecutionStatus::Success,
        scope.target.clone(),
        now() - Duration::minutes(1),
        now(),
        None,
        None,
    )
    .expect("step");
    let listed = execution(&scope, AutomationExecutionStatus::Success, 1, now());
    let mut step_transport = RecordingTransport::default();
    step_transport.push_describe_automation_executions(Ok(
        DescribeAutomationExecutionsResponse::new(
            &request.describe_request(),
            [listed.clone()],
            None,
            true,
            512,
            TransportProvenance::Recording,
        )
        .expect("list"),
    ));
    step_transport.push_get_automation_execution(Ok(GetAutomationExecutionResponse::new(
        &request.get_request(),
        listed,
        512,
        TransportProvenance::Recording,
    )));
    step_transport.push_describe_automation_step_executions(Ok(
        DescribeAutomationStepExecutionsResponse::new(
            &request.steps_request(),
            [wrong_step],
            None,
            true,
            512,
            TransportProvenance::Recording,
        )
        .expect("steps"),
    ));
    let mut step_service = recording_service(&scope, step_transport);
    assert!(step_service.propose(&request).is_err());
}

#[test]
fn partial_unknown_access_loss_invalid_filter_and_next_token_are_typed() {
    let scope = scope();
    for (error, expected) in [
        (
            AwsSsmAutomationTransportError::Partial,
            AutomationEvidenceState::Partial,
        ),
        (
            AwsSsmAutomationTransportError::Unknown,
            AutomationEvidenceState::ProviderUnknown,
        ),
        (
            AwsSsmAutomationTransportError::AccessLoss,
            AutomationEvidenceState::AccessLoss,
        ),
        (
            AwsSsmAutomationTransportError::InvalidFilter,
            AutomationEvidenceState::InvalidFilter,
        ),
        (
            AwsSsmAutomationTransportError::InvalidNextToken,
            AutomationEvidenceState::InvalidNextToken,
        ),
    ] {
        let mut transport = RecordingTransport::default();
        transport.push_execution_error(error);
        let mut service = recording_service(&scope, transport);
        let request = service.default_request().expect("request");
        let proposal = service.propose(&request).expect("typed error proposal");
        assert_eq!(proposal.evidence.state, expected);
        assert!(!proposal.evidence.can_be_adopted());
    }
}

#[test]
fn throttling_truncation_and_typed_http_timeout_failures_are_redacted() {
    let scope = scope();
    let typed = [
        (AwsSsmAutomationTransportError::BadRequest, Some(400)),
        (AwsSsmAutomationTransportError::Unauthorized, Some(401)),
        (AwsSsmAutomationTransportError::Forbidden, Some(403)),
        (AwsSsmAutomationTransportError::NotFound, Some(404)),
        (AwsSsmAutomationTransportError::Conflict, Some(409)),
        (
            AwsSsmAutomationTransportError::Throttled {
                retry_after_seconds: Some(3),
            },
            Some(429),
        ),
        (
            AwsSsmAutomationTransportError::ServerError { status: 503 },
            Some(503),
        ),
        (AwsSsmAutomationTransportError::Timeout, None),
    ];
    for (error, status) in typed {
        assert_eq!(error.status_code(), status);
        let mut transport = RecordingTransport::default();
        transport.push_execution_error(error);
        let mut service = recording_service(&scope, transport);
        let request = service.default_request().expect("request");
        let proposal = service.propose(&request).expect("typed transport proposal");
        assert!(proposal.evidence.provider_error.is_some());
        assert!(
            !serde_json::to_string(&proposal)
                .expect("proposal JSON")
                .contains("retry_after")
        );
    }

    let request = AwsSsmAutomationReadRequest::for_scope(&scope).expect("request");
    let listed = execution(&scope, AutomationExecutionStatus::Success, 1, now());
    let oversized = DescribeAutomationExecutionsResponse::new(
        &request.describe_request(),
        [listed],
        None,
        true,
        MAX_RESPONSE_BYTES + 1,
        TransportProvenance::Recording,
    )
    .expect("oversized response");
    let mut transport = RecordingTransport::default();
    transport.push_describe_automation_executions(Ok(oversized));
    let mut service = recording_service(&scope, transport);
    let proposal = service.propose(&request).expect("truncation proposal");
    assert_eq!(proposal.evidence.state, AutomationEvidenceState::Truncated);
}

#[test]
fn tamper_revocation_and_reversible_registration_are_fenced() {
    let scope = scope();
    let mut transport = RecordingTransport::default();
    queue_read(
        &mut transport,
        &scope,
        AutomationExecutionStatus::Success,
        1,
        TransportProvenance::Recording,
    );
    let mut service = recording_service(&scope, transport);
    let request = service.default_request().expect("request");
    let mut proposal = service.propose(&request).expect("proposal");
    proposal.evidence.state = AutomationEvidenceState::Failed;
    assert!(service.verify(&proposal).is_err());

    let reverse = service.reverse_registration().expect("reverse");
    assert_eq!(
        reverse.to,
        hartevo_aws_ssm_automation_result_plugin::RegistrationStatus::Reversed
    );
    assert!(service.propose(&request).is_err());
    let restore = service.restore_registration().expect("restore");
    assert_eq!(
        restore.to,
        hartevo_aws_ssm_automation_result_plugin::RegistrationStatus::Active
    );

    let revoke = service.revoke_registration().expect("revoke");
    assert_eq!(
        revoke.to,
        hartevo_aws_ssm_automation_result_plugin::RegistrationStatus::Revoked
    );
    assert!(service.propose(&request).is_err());
    assert!(service.restore_registration().is_err());
}

#[test]
fn blocked_env_is_honest_and_never_connected() {
    let scope = scope();
    let provider = AwsSsmAutomationProvider::new(
        hartevo_aws_ssm_automation_result_plugin::BlockedEnvTransport::default(),
    )
    .expect("blocked provider");
    assert_eq!(provider.provenance(), TransportProvenance::BlockedEnv);
    assert!(!provider.provenance().connected());
    assert!(!provider.provenance().native());
    let permission = PermissionSnapshot::readonly("ssm-read-only", 1).expect("permission");
    let mut service =
        AwsSsmAutomationService::new(scope.clone(), secret(&scope), permission, provider, now())
            .expect("service");
    let request = service.default_request().expect("request");
    let proposal = service.propose(&request).expect("blocked proposal");
    assert_eq!(
        proposal.evidence.state,
        AutomationEvidenceState::ProviderUnknown
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
}
