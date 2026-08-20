use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_audit_manager_result_plugin::{
    AssessmentId, AssessmentReportInput, AssessmentReportSummary, AssessmentStatus,
    AssessmentStatusFilter, AssessmentSummary, AssessmentSummaryInput, AuditManagerEvidenceState,
    AwsAccountId, AwsAuditManagerContract, AwsAuditManagerError, AwsAuditManagerEvidenceRequest,
    AwsAuditManagerProvider, AwsAuditManagerScope, AwsAuditManagerService,
    AwsAuditManagerTransportError, AwsRegion, CONTRACT_DIGEST, CONTRACT_VERSION, ConsentScope,
    ControlSetId, ControlSetIdentity, ControlSetSummary, EvidencePeriod, FixtureTransport,
    FrameworkId, FrameworkIdentity, LAYER1_PERMISSIONS, ListAssessmentReportsResponse,
    ListAssessmentsRequest, ListAssessmentsResponse, LoopbackTransport,
    MissionAwsAuditManagerDecisionState, OpaqueCursor, PermissionSnapshot, ProjectIdentity,
    ProviderProvenance, RecordingTransport, ReportId, ReportIdentity, ReportStatus,
    SecretReference, TenantStatus, WorkProductIdentity,
};

const NOW_SECONDS: i64 = 1_787_000_000;
const RAW_ACCOUNT: &str = "123456789012";
const RAW_ASSESSMENT: &str = "assessment-668";
const RAW_FRAMEWORK: &str = "framework-668";
const RAW_CONTROL_SET: &str = "control-set-668";
const RAW_REPORT: &str = "report-668";
const RAW_SECRET: &str = "keyring://opaque-audit-manager-668";
const RAW_EMAIL: &str = "audit-owner@example.invalid";
const RAW_ROLE_ARN: &str = "arn:aws:iam::123456789012:role/AuditManagerReadOnly";
const RAW_REPORT_BYTES: &[u8] = b"raw-report-bytes-must-not-survive";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("fixture timestamp")
}

fn scope_with_status(status: TenantStatus) -> AwsAuditManagerScope {
    AwsAuditManagerScope::with_tenant_status(
        AwsAccountId::new(RAW_ACCOUNT).expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        hartevo_aws_audit_manager_result_plugin::AssessmentIdentity::new(
            AssessmentId::new(RAW_ASSESSMENT).expect("assessment id"),
            7,
        )
        .expect("assessment"),
        FrameworkIdentity::new(FrameworkId::new(RAW_FRAMEWORK).expect("framework id"), 11)
            .expect("framework"),
        ControlSetIdentity::new(
            ControlSetId::new(RAW_CONTROL_SET).expect("control set id"),
            13,
        )
        .expect("control set"),
        ReportIdentity::new(ReportId::new(RAW_REPORT).expect("report id"), 17).expect("report"),
        hartevo_aws_audit_manager_result_plugin::MissionIdentity::new("mission-668", 19)
            .expect("mission"),
        ProjectIdentity::new("project-668", 23).expect("project"),
        WorkProductIdentity::new("work-product-668", 29).expect("work product"),
        status,
    )
    .expect("scope")
}

fn scope() -> AwsAuditManagerScope {
    scope_with_status(TenantStatus::Existing)
}

fn secret(scope: &AwsAuditManagerScope) -> SecretReference {
    SecretReference::sigv4(RAW_SECRET, scope, 1).expect("secret")
}

fn consent(expires_at: DateTime<Utc>) -> ConsentScope {
    ConsentScope::for_layer_one("consent-668", 1, expires_at).expect("consent")
}

fn fixture_service() -> AwsAuditManagerService<FixtureTransport> {
    let scope = scope();
    AwsAuditManagerService::new(
        scope.clone(),
        secret(&scope),
        consent(now() + Duration::days(30)),
        AwsAuditManagerProvider::new(FixtureTransport::for_scope(&scope, now()))
            .expect("fixture provider"),
        now(),
    )
    .expect("fixture service")
}

fn period(expires_at: DateTime<Utc>) -> EvidencePeriod {
    EvidencePeriod::new(
        now() - Duration::days(30),
        now() - Duration::days(10),
        expires_at,
    )
    .expect("period")
}

fn queued_expired_service() -> AwsAuditManagerService<RecordingTransport> {
    let scope = scope();
    let request = AwsAuditManagerEvidenceRequest::for_scope(&scope, now()).expect("request");
    let expired_period = period(now() - Duration::days(1));
    let summary = AssessmentSummary::new(
        &scope,
        AssessmentSummaryInput::new(
            scope.assessment().clone(),
            AssessmentStatus::Active,
            scope.framework().clone(),
            scope.control_set().clone(),
            expired_period.clone(),
            hartevo_aws_audit_manager_result_plugin::Digest::from_text("expired-control-results"),
            now(),
        )
        .expect("summary input")
        .with_provider_metadata(
            Some("raw assessment name".to_owned()),
            Some(RAW_EMAIL.to_owned()),
            Some(RAW_ROLE_ARN.to_owned()),
        ),
    )
    .expect("summary");
    let detail = hartevo_aws_audit_manager_result_plugin::AssessmentDetail::new(
        &scope,
        summary.clone(),
        vec![
            ControlSetSummary::new(
                &scope,
                scope.control_set().clone(),
                2,
                hartevo_aws_audit_manager_result_plugin::Digest::from_text(
                    "expired-control-results",
                ),
            )
            .expect("control set summary"),
        ],
    )
    .expect("detail");
    let report = AssessmentReportSummary::new(
        &scope,
        AssessmentReportInput::from_report_bytes(
            scope.report().clone(),
            ReportStatus::Complete,
            scope.assessment().clone(),
            expired_period,
            RAW_REPORT_BYTES,
            now(),
        )
        .expect("report input")
        .with_provider_metadata(
            Some("raw report name".to_owned()),
            Some(RAW_EMAIL.to_owned()),
            Some(RAW_ROLE_ARN.to_owned()),
        ),
    )
    .expect("report");
    let mut transport = RecordingTransport::default();
    transport.push_list_assessments_response(Ok(ListAssessmentsResponse::new(
        &request.list_assessments,
        vec![summary],
        None,
        512,
        ProviderProvenance::Recording,
    )
    .expect("list response")));
    transport.push_get_assessment_response(Ok(
        hartevo_aws_audit_manager_result_plugin::GetAssessmentResponse::new(
            &request.get_assessment,
            detail,
            768,
            ProviderProvenance::Recording,
        )
        .expect("get response"),
    ));
    transport.push_list_assessment_reports_response(Ok(ListAssessmentReportsResponse::new(
        &request.list_assessment_reports,
        vec![report],
        None,
        512,
        ProviderProvenance::Recording,
    )
    .expect("report response")));
    AwsAuditManagerService::new(
        scope.clone(),
        secret(&scope),
        consent(now() + Duration::days(30)),
        AwsAuditManagerProvider::new(transport).expect("recording provider"),
        now(),
    )
    .expect("recording service")
}

#[test]
fn contract_and_registration_are_digest_bound_and_redacted() {
    let contract = AwsAuditManagerContract::baseline().expect("contract");
    assert_eq!(contract.value()["contractVersion"], CONTRACT_VERSION);
    assert_eq!(contract.value()["contractDigest"], CONTRACT_DIGEST);
    assert_eq!(LAYER1_PERMISSIONS.len(), 4);

    let service = fixture_service();
    let encoded = serde_json::to_string(service.registration()).expect("registration JSON");
    let debug = format!("{:?}", service.registration());
    assert!(encoded.contains("secretReferenceDigest"));
    assert!(!encoded.contains(RAW_SECRET));
    assert!(!debug.contains(RAW_SECRET));
    assert!(!encoded.contains(RAW_ACCOUNT));
    assert_eq!(
        service.registration().recomputed_digest(),
        *service.registration().registration_digest()
    );
    assert_eq!(service.describe_capabilities().operations.len(), 3);
    assert!(!service.describe_capabilities().connected);
    assert!(!service.describe_capabilities().native);
}

#[test]
fn fixture_and_loopback_proposals_are_complete_review_only_and_redacted() {
    let mut fixture = fixture_service();
    let proposal = fixture
        .propose(fixture.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.evidence.state, AuditManagerEvidenceState::Complete);
    assert_eq!(proposal.evidence.provenance, ProviderProvenance::Fixture);
    assert!(proposal.evidence.pagination_complete);
    assert!(proposal.is_review_only());
    assert!(!proposal.can_be_adopted());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.certification_claim);
    assert!(!proposal.legal_advice);
    let verification = fixture.verify(&proposal);
    assert!(verification.valid);
    assert!(verification.review_eligible);

    let encoded = serde_json::to_string(&proposal).expect("proposal JSON");
    let debug = format!("{proposal:?}");
    for forbidden in [
        RAW_ACCOUNT,
        RAW_SECRET,
        RAW_EMAIL,
        RAW_ROLE_ARN,
        "fixture-report-bytes",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "raw value leaked in JSON: {forbidden}"
        );
        assert!(
            !debug.contains(forbidden),
            "raw value leaked in Debug: {forbidden}"
        );
    }

    let mut loopback = {
        let scope = scope();
        AwsAuditManagerService::new(
            scope.clone(),
            secret(&scope),
            consent(now() + Duration::days(30)),
            AwsAuditManagerProvider::new(LoopbackTransport::for_scope(&scope, now()))
                .expect("loopback provider"),
            now(),
        )
        .expect("loopback service")
    };
    let loopback_proposal = loopback
        .propose(loopback.default_request(now()).expect("request"))
        .expect("loopback proposal");
    assert_eq!(
        loopback_proposal.evidence.provenance,
        ProviderProvenance::Loopback
    );
    assert!(!loopback_proposal.connected);
    assert!(!loopback_proposal.native);
    assert!(!loopback_proposal.first_party);
}

#[test]
fn blocked_env_is_provider_unknown_and_never_native() {
    let scope = scope();
    let mut service = AwsAuditManagerService::new(
        scope.clone(),
        secret(&scope),
        consent(now() + Duration::days(30)),
        AwsAuditManagerProvider::default(),
        now(),
    )
    .expect("blocked service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("blocked proposal");
    assert_eq!(
        proposal.evidence.state,
        AuditManagerEvidenceState::ProviderUnknown
    );
    assert_eq!(proposal.evidence.provenance, ProviderProvenance::BlockedEnv);
    assert_eq!(
        proposal
            .evidence
            .failure
            .as_ref()
            .expect("failure")
            .category,
        "blocked_env"
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
}

#[test]
fn unregistered_account_fails_closed_before_provider_read() {
    let scope = scope_with_status(TenantStatus::Unregistered);
    let result = AwsAuditManagerService::new(
        scope.clone(),
        secret(&scope),
        consent(now() + Duration::days(30)),
        AwsAuditManagerProvider::new(FixtureTransport::for_scope(&scope, now()))
            .expect("fixture provider"),
        now(),
    );
    assert!(matches!(
        result,
        Err(AwsAuditManagerError::UnregisteredAccount)
    ));
}

#[test]
fn expiry_and_provider_failures_are_non_adoptable_closed_states() {
    let mut service = queued_expired_service();
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("expired proposal");
    assert_eq!(proposal.evidence.state, AuditManagerEvidenceState::Expired);
    assert!(!proposal.can_be_adopted());
    assert!(!service.verify(&proposal).valid);

    let mut transport = RecordingTransport::default();
    let scope = scope();
    let request = AwsAuditManagerEvidenceRequest::for_scope(&scope, now()).expect("request");
    transport.push_list_assessments_response(Err(AwsAuditManagerTransportError::Forbidden));
    let mut access_loss = AwsAuditManagerService::new(
        scope.clone(),
        secret(&scope),
        consent(now() + Duration::days(30)),
        AwsAuditManagerProvider::new(transport).expect("provider"),
        now(),
    )
    .expect("service");
    let proposal = access_loss.propose(request).expect("access-loss proposal");
    assert_eq!(
        proposal.evidence.state,
        AuditManagerEvidenceState::AccessLoss
    );
    assert!(!proposal.evidence.pagination_complete);
}

#[test]
fn tamper_replay_and_revocation_fences_hold() {
    let mut service = fixture_service();
    let request = service.default_request(now()).expect("request");
    let proposal = service.propose(request).expect("proposal");
    let first = service.record(&proposal, "recording-key").expect("record");
    let replay = service.record(&proposal, "recording-key").expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(service.recording_count(), 1);

    let mut tampered = proposal.clone();
    tampered.evidence.connected = true;
    assert!(!service.verify(&tampered).valid);
    assert_eq!(
        service.record(&tampered, "tampered-key"),
        Err(AwsAuditManagerError::TamperedEvidence)
    );

    service.revoke_registration().expect("revoke");
    assert_eq!(
        service.propose(service.default_request(now()).expect("request")),
        Err(AwsAuditManagerError::RegistrationRevoked)
    );
}

#[test]
fn pagination_loop_and_digest_bound_cursor_fail_closed() {
    let scope = scope();
    let request = AwsAuditManagerEvidenceRequest::for_scope(&scope, now()).expect("request");
    let summary = AssessmentSummary::for_scope(
        &scope,
        AssessmentStatus::Active,
        period(now() + Duration::days(30)),
        hartevo_aws_audit_manager_result_plugin::Digest::from_text("loop-results"),
        now(),
    )
    .expect("summary");
    let cursor = OpaqueCursor::for_request(
        "loop-token",
        request.list_assessments.request_digest.clone(),
        2,
    )
    .expect("cursor");
    let response_one = ListAssessmentsResponse::new(
        &request.list_assessments,
        vec![summary],
        Some(cursor.clone()),
        512,
        ProviderProvenance::Recording,
    )
    .expect("first response");
    let second_request = ListAssessmentsRequest::new(
        &scope,
        AssessmentStatusFilter::All,
        request.list_assessments.page_size,
        request.list_assessments.max_pages,
        Some(cursor.clone()),
    )
    .expect("second request");
    let mut response_two = response_one.clone();
    response_two.request_digest = second_request.request_digest;
    response_two.page_digest = hartevo_aws_audit_manager_result_plugin::Digest::from_parts(
        "aws-audit-manager-list-assessments-page/v1",
        &[
            ("request", response_two.request_digest.as_str().to_owned()),
            (
                "items",
                response_two
                    .assessments
                    .iter()
                    .map(|assessment| assessment.digest().as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "next",
                response_two
                    .next_cursor
                    .as_ref()
                    .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
            ),
            ("bytes", response_two.response_bytes.to_string()),
        ],
    );
    let mut transport = RecordingTransport::default();
    transport.push_list_assessments_response(Ok(response_one));
    transport.push_list_assessments_response(Ok(response_two));
    let mut service = AwsAuditManagerService::new(
        scope.clone(),
        secret(&scope),
        consent(now() + Duration::days(30)),
        AwsAuditManagerProvider::new(transport).expect("provider"),
        now(),
    )
    .expect("service");
    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.evidence.state, AuditManagerEvidenceState::Partial);
    assert_eq!(
        proposal
            .evidence
            .failure
            .as_ref()
            .expect("failure")
            .category,
        "pagination_loop"
    );

    let other_scope = AwsAuditManagerScope::with_tenant_status(
        AwsAccountId::new(RAW_ACCOUNT).expect("account"),
        AwsRegion::new("eu-west-1").expect("region"),
        scope.assessment().clone(),
        scope.framework().clone(),
        scope.control_set().clone(),
        scope.report().clone(),
        scope.mission().clone(),
        scope.project().clone(),
        scope.work_product().clone(),
        TenantStatus::Existing,
    )
    .expect("other scope");
    assert!(
        ListAssessmentsRequest::new(
            &other_scope,
            AssessmentStatusFilter::All,
            50,
            4,
            Some(cursor)
        )
        .is_err()
    );
}

#[test]
fn mission_consumer_is_review_only_and_idempotent() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    let mut consumer = service.consumer().expect("consumer");
    let result = consumer.consume(&proposal).expect("mission result");
    assert_eq!(
        result.decision_state,
        MissionAwsAuditManagerDecisionState::Complete
    );
    assert!(!result.can_be_adopted());
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.certification_claim);
    assert!(!result.legal_advice);
    let first = consumer
        .record(&proposal, "mission-record")
        .expect("record");
    let replay = consumer
        .record(&proposal, "mission-record")
        .expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn permission_snapshot_is_least_privilege_and_secret_reference_is_opaque() {
    let permissions = PermissionSnapshot::for_existing_tenant(1).expect("permissions");
    assert!(permissions.permits("auditmanager:GetAssessment"));
    assert!(!permissions.permits("auditmanager:UpdateAssessment"));
    let scope = scope();
    let reference = secret(&scope);
    let debug = format!("{reference:?}");
    assert!(!debug.contains(RAW_SECRET));
    assert_eq!(reference.scope_digest(), &scope.digest());
}
