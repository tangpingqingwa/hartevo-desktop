use chrono::{Duration, TimeZone, Utc};
use hartevo_aws_service_quota_result_plugin::{
    AwsAccountId, AwsRegion, AwsServiceQuotaOperation, AwsServiceQuotaProvider,
    AwsServiceQuotaReadPage, AwsServiceQuotaReadRequest, AwsServiceQuotaScope,
    AwsServiceQuotaService, BlockedEnvTransport, DeploymentBinding, DeploymentId, FixtureTransport,
    GetAWSDefaultServiceQuotaRequest, GetServiceQuotaRequest, HistoryWindow,
    ListRequestedServiceQuotaChangeHistoryByQuotaRequest, ListServiceQuotasRequest, MissionBinding,
    MissionId, OpaqueCursor, PermissionFence, PermissionId, ProjectBinding, ProjectId,
    ProviderRevision, QuotaBinding, QuotaEvidenceState, QuotaPostureDigest, QuotaRevision,
    RecordingTransport, Revision, SecretReference, ServiceCode, ServiceQuotaIdentity,
    TransportError, TransportProvenance, WorkProductBinding, WorkProductId,
};

const NOW_SECONDS: i64 = 1_787_000_000;
const SECRET_REFERENCE: &str = "opaque-sigv4-handle";
const RAW_QUOTA_NAME: &str = "private quota name";
const RAW_QUOTA_ARN: &str = "arn:aws:servicequotas:us-east-1:123456789012:ec2/L-0001";
const RAW_USAGE_DIMENSION: &str = "private-usage-dimension";
const RAW_REQUESTER: &str = "arn:aws:iam::123456789012:role/private-role";
const RAW_CASE_ID: &str = "private-case-id";

fn now() -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn permission() -> PermissionFence {
    PermissionFence::readonly(
        PermissionId::new("service-quota-read").expect("permission id"),
        Revision::new(1).expect("permission revision"),
    )
    .expect("permission")
}

fn scope_with_quota_count(count: usize) -> AwsServiceQuotaScope {
    let permission = permission();
    let quotas = (1..=count)
        .map(|number| {
            let quota_code = format!("L-{number:04}");
            QuotaBinding::for_quota(
                "ec2",
                quota_code,
                QuotaRevision::new(1).expect("quota revision"),
            )
            .expect("quota binding")
        })
        .collect::<Vec<_>>();
    AwsServiceQuotaScope::new(
        DeploymentBinding::new(
            DeploymentId::new("deployment-1").expect("deployment"),
            Revision::new(3).expect("deployment revision"),
        ),
        MissionBinding::new(
            MissionId::new("mission-1").expect("mission"),
            Revision::new(4).expect("mission revision"),
        ),
        ProjectBinding::new(
            ProjectId::new("project-1").expect("project"),
            Revision::new(5).expect("project revision"),
        ),
        WorkProductBinding::new(
            WorkProductId::new("work-product-1").expect("work product"),
            Revision::new(6).expect("work product revision"),
        ),
        AwsAccountId::new("123456789012").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        ServiceCode::new("ec2").expect("service code"),
        quotas,
        permission.digest(),
    )
    .expect("scope")
}

fn scope() -> AwsServiceQuotaScope {
    scope_with_quota_count(2)
}

fn secret(scope: &AwsServiceQuotaScope) -> SecretReference {
    SecretReference::sigv4(SECRET_REFERENCE, scope, 1).expect("secret reference")
}

fn quota(scope: &AwsServiceQuotaScope, index: usize) -> ServiceQuotaIdentity {
    scope.quotas[index].identity.clone()
}

fn fixture_service(scope: &AwsServiceQuotaScope) -> AwsServiceQuotaService<FixtureTransport> {
    let provider = AwsServiceQuotaProvider::new(FixtureTransport::for_scope(scope, now()))
        .expect("fixture provider");
    AwsServiceQuotaService::new(scope.clone(), secret(scope), permission(), provider)
        .expect("fixture service")
}

fn recording_service(
    scope: &AwsServiceQuotaScope,
    responses: impl IntoIterator<Item = Result<AwsServiceQuotaReadPage, TransportError>>,
) -> AwsServiceQuotaService<RecordingTransport> {
    let mut transport = RecordingTransport::default();
    for response in responses {
        transport.push_response(response);
    }
    let provider = AwsServiceQuotaProvider::new(transport).expect("recording provider");
    AwsServiceQuotaService::new(scope.clone(), secret(scope), permission(), provider)
        .expect("recording service")
}

#[test]
fn contract_registration_secret_and_capabilities_are_digest_bound() {
    let contract = hartevo_aws_service_quota_result_plugin::AwsServiceQuotaContract::baseline()
        .expect("contract");
    assert_eq!(
        contract.digest(),
        hartevo_aws_service_quota_result_plugin::contract_digest()
    );

    let scope = scope();
    let service = fixture_service(&scope);
    let registration = service.registration();
    assert!(registration.registration_digest == registration.recomputed_digest());
    assert!(!registration.evidence_digest.is_zero());
    assert!(!registration.service_digest.is_zero());
    assert!(!registration.quota_digest.is_zero());
    assert!(!registration.scope_digest.is_zero());
    assert!(!registration.permission_digest.is_zero());
    assert!(
        service.secret_reference().digest()
            != &hartevo_aws_service_quota_result_plugin::Digest::zero()
    );

    let debug = format!("{:?}", service.secret_reference());
    assert!(!debug.contains(SECRET_REFERENCE));
    let registration_json = serde_json::to_string(registration).expect("registration JSON");
    assert!(registration_json.contains("secretReferenceDigest"));
    assert!(!registration_json.contains(SECRET_REFERENCE));

    let capabilities = AwsServiceQuotaService::<FixtureTransport>::describe_capabilities();
    assert_eq!(capabilities.operations.len(), 4);
    assert!(capabilities.read_only);
    assert!(capabilities.proposal_only);
    assert!(capabilities.recording_only);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.first_party);
    assert!(!capabilities.kernel_authority);
    assert!(!capabilities.outcome_adoption);
}

#[test]
fn fixture_list_proposes_records_verifies_and_stays_below_mission_authority() {
    let scope = scope();
    let mut service = fixture_service(&scope);
    let request = AwsServiceQuotaReadRequest::list_service_quotas_at(&scope, 50, None, now())
        .expect("list request");
    let proposal = service.propose(request, now()).expect("proposal");
    assert_eq!(
        proposal.operation,
        AwsServiceQuotaOperation::ListServiceQuotas
    );
    assert_eq!(proposal.evidence.state, QuotaEvidenceState::Complete);
    assert_eq!(proposal.evidence.observations.len(), 2);
    assert!(proposal.is_review_only());
    assert!(!proposal.can_be_adopted());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.adopted_outcome);
    assert!(!proposal.financial_guarantee);
    assert!(!proposal.infrastructure_guarantee);
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!serialized.contains("fixture-applied-value"));
    assert!(!serialized.contains("raw_usage"));
    assert!(!serialized.contains("usageSeries"));

    let receipt = service.record_at(&proposal, now()).expect("record");
    assert!(!receipt.connected);
    assert!(!receipt.native);
    assert!(!receipt.durable_provider_receipt);
    assert!(!receipt.raw_quota_values_retained);
    assert!(!receipt.raw_usage_series_retained);
    assert_eq!(receipt.receipt_digest, receipt.recomputed_digest());
    let verified = service.verify(&receipt).expect("verify");
    assert!(verified.verified);
    assert!(!verified.connected);
    assert!(!verified.native);
    assert!(!verified.adopted_outcome);
    assert!(!verified.financial_guarantee);
    assert!(!verified.infrastructure_guarantee);

    let consumer = service.consumer().expect("consumer");
    let mission_result = consumer.consume_ref(&proposal).expect("Mission result");
    assert_eq!(
        mission_result.observed_quota_state,
        QuotaEvidenceState::Complete
    );
    assert!(mission_result.requires_human_review);
    assert!(!mission_result.safe_to_promote);
    assert!(!mission_result.capacity_guarantee);
    assert!(!mission_result.infrastructure_guarantee);
    assert!(!mission_result.financial_guarantee);
    assert!(!mission_result.truth_authority);
    assert!(!mission_result.adopted_outcome);
}

#[test]
fn all_four_allowlisted_operations_have_typed_bounded_seams() {
    let scope = scope();
    let identity = quota(&scope, 0);
    let history_window = HistoryWindow::new(now() - Duration::days(1), now(), 8).expect("window");

    let list = ListServiceQuotasRequest::new(&scope, 10, None).expect("list request");
    assert_eq!(list.operation, AwsServiceQuotaOperation::ListServiceQuotas);
    let get = GetServiceQuotaRequest::new(&scope, identity.clone()).expect("get request");
    assert_eq!(get.operation, AwsServiceQuotaOperation::GetServiceQuota);
    let default =
        GetAWSDefaultServiceQuotaRequest::new(&scope, identity.clone()).expect("default request");
    assert_eq!(
        default.operation,
        AwsServiceQuotaOperation::GetAWSDefaultServiceQuota
    );
    let history = ListRequestedServiceQuotaChangeHistoryByQuotaRequest::new(
        &scope,
        identity,
        history_window,
        8,
        None,
    )
    .expect("history request");
    assert_eq!(
        history.operation,
        AwsServiceQuotaOperation::ListRequestedServiceQuotaChangeHistoryByQuota
    );

    for request in [
        list.into_inner(),
        get.into_inner(),
        default.into_inner(),
        history.into_inner(),
    ] {
        let mut service = fixture_service(&scope);
        let proposal = service.propose(request, now()).expect("operation proposal");
        assert_eq!(proposal.evidence.state, QuotaEvidenceState::Complete);
        assert_eq!(proposal.evidence.operation, proposal.operation);
        assert_eq!(proposal.evidence.page_count, 1);
        assert!(proposal.evidence.observations.iter().all(|observation| {
            observation.applied_value_digest.is_some()
                || observation.default_value_digest.is_some()
                || observation.request_history_digest.is_some()
        }));
    }
}

#[test]
fn parsed_provider_payload_is_reduced_to_digest_only_evidence() {
    let scope = scope_with_quota_count(1);
    let identity = quota(&scope, 0);
    let request = AwsServiceQuotaReadRequest::get_service_quota_at(&scope, identity, now())
        .expect("get request");
    let body = br#"{
        "Quota": {
            "ServiceCode": "ec2",
            "QuotaCode": "L-0001",
            "QuotaName": "private quota name",
            "QuotaArn": "arn:aws:servicequotas:us-east-1:123456789012:ec2/L-0001",
            "Value": 123.5,
            "Unit": "None",
            "Adjustable": true,
            "GlobalQuota": false,
            "UsageMetric": {
                "MetricNamespace": "AWS/Usage",
                "MetricName": "ResourceCount",
                "MetricDimensions": {"Private": "private-usage-dimension"}
            },
            "Requester": "arn:aws:iam::123456789012:role/private-role"
        }
    }"#;
    let page = AwsServiceQuotaProvider::<RecordingTransport>::parse_json_page(
        &request,
        1,
        200,
        body,
        ProviderRevision::new("aws-service-quotas-read-r1").expect("provider revision"),
    )
    .expect("parsed page");
    let page_json = serde_json::to_string(&page).expect("page JSON");
    for raw in [
        RAW_QUOTA_NAME,
        RAW_QUOTA_ARN,
        RAW_USAGE_DIMENSION,
        RAW_REQUESTER,
    ] {
        assert!(!page_json.contains(raw), "raw provider value leaked: {raw}");
    }
    assert!(page_json.contains("appliedValueDigest"));
    assert!(page_json.contains("usageMetricDigest"));

    let mut service = recording_service(&scope, [Ok(page)]);
    let proposal = service.propose(request, now()).expect("proposal");
    let evidence_json = serde_json::to_string(&proposal.evidence).expect("evidence JSON");
    for raw in [
        RAW_QUOTA_NAME,
        RAW_QUOTA_ARN,
        RAW_USAGE_DIMENSION,
        RAW_REQUESTER,
    ] {
        assert!(
            !evidence_json.contains(raw),
            "raw evidence value leaked: {raw}"
        );
    }
}

#[test]
fn history_parser_digests_statuses_and_drops_case_and_requester_material() {
    let scope = scope_with_quota_count(1);
    let identity = quota(&scope, 0);
    let window = HistoryWindow::new(now() - Duration::days(1), now(), 8).expect("window");
    let request =
        AwsServiceQuotaReadRequest::list_requested_service_quota_change_history_by_quota_at(
            &scope,
            identity,
            window,
            8,
            None,
            now(),
        )
        .expect("history request");
    let body = format!(
        r#"{{"RequestedQuotas":[{{"ServiceCode":"ec2","QuotaCode":"L-0001","Unit":"None","Adjustable":true,"GlobalQuota":false,"Status":"CASE_OPENED","DesiredValue":99.0,"Created":{},"LastUpdated":{},"Requester":"{}","CaseId":"{}"}}]}}"#,
        NOW_SECONDS - 100,
        NOW_SECONDS - 10,
        RAW_REQUESTER,
        RAW_CASE_ID,
    );
    let page = AwsServiceQuotaProvider::<RecordingTransport>::parse_json_page(
        &request,
        1,
        200,
        body.as_bytes(),
        ProviderRevision::new("aws-service-quotas-read-r1").expect("provider revision"),
    )
    .expect("history page");
    let serialized = serde_json::to_string(&page).expect("history page JSON");
    assert!(!serialized.contains(RAW_REQUESTER));
    assert!(!serialized.contains(RAW_CASE_ID));
    assert!(!serialized.contains("CASE_OPENED"));
    assert!(serialized.contains("requestHistoryDigest"));
}

#[test]
fn stale_usage_is_explicit_and_fail_closed() {
    let scope = scope_with_quota_count(1);
    let identity = quota(&scope, 0);
    let request = AwsServiceQuotaReadRequest::get_service_quota_at(&scope, identity.clone(), now())
        .expect("get request");
    let stale = QuotaPostureDigest::fixture(
        &identity,
        Revision::new(99).expect("stale usage revision"),
        now(),
    )
    .expect("stale posture");
    let page = AwsServiceQuotaReadPage::new(
        &request,
        vec![stale],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("page");
    let mut service = recording_service(&scope, [Ok(page)]);
    let result = service.read(request).expect("evidence result");
    assert_eq!(result.evidence.state, QuotaEvidenceState::StaleUsage);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_service_quota_result_plugin::PartialReason::StaleUsage)
    );
    assert!(!result.evidence.can_be_adopted());
}

#[test]
fn pagination_binds_filter_and_rejects_cursor_replay() {
    let scope = scope();
    let identity_one = quota(&scope, 0);
    let identity_two = quota(&scope, 1);
    let request_one = AwsServiceQuotaReadRequest::list_service_quotas_at(&scope, 1, None, now())
        .expect("page one request");
    let cursor =
        OpaqueCursor::new("opaque-page-token", &request_one.filter_digest, 2).expect("cursor");
    let page_one = AwsServiceQuotaReadPage::new(
        &request_one,
        vec![
            QuotaPostureDigest::fixture(&identity_one, Revision::new(1).expect("usage"), now())
                .expect("posture"),
        ],
        Some(cursor.clone()),
        512,
        TransportProvenance::Recording,
    )
    .expect("page one");
    let request_two = request_one
        .with_cursor(Some(cursor.clone()))
        .expect("page two request");
    let page_two = AwsServiceQuotaReadPage::new(
        &request_two,
        vec![
            QuotaPostureDigest::fixture(&identity_two, Revision::new(1).expect("usage"), now())
                .expect("posture"),
        ],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("page two");
    let mut service = recording_service(&scope, [Ok(page_one), Ok(page_two)]);
    let result = service.read(request_one.clone()).expect("two page result");
    assert_eq!(result.evidence.state, QuotaEvidenceState::Complete);
    assert_eq!(result.evidence.page_count, 2);
    assert_eq!(result.evidence.observations.len(), 2);
    let changed_filter = AwsServiceQuotaReadRequest::list_service_quotas_at(
        &scope,
        1,
        None,
        now() + Duration::seconds(1),
    )
    .expect("changed filter request");
    assert!(changed_filter.with_cursor(Some(cursor.clone())).is_err());

    let replay_cursor =
        OpaqueCursor::new("replayed-token", &request_one.filter_digest, 2).expect("replay cursor");
    let replay_page_one = AwsServiceQuotaReadPage::new(
        &request_one,
        vec![
            QuotaPostureDigest::fixture(&identity_one, Revision::new(1).expect("usage"), now())
                .expect("posture"),
        ],
        Some(replay_cursor.clone()),
        512,
        TransportProvenance::Recording,
    )
    .expect("replay page one");
    let replay_request_two = request_one
        .with_cursor(Some(replay_cursor.clone()))
        .expect("replay page two request");
    let replay_cursor_again = OpaqueCursor::new("replayed-token", &request_one.filter_digest, 3)
        .expect("replayed cursor");
    let replay_page_two = AwsServiceQuotaReadPage::new(
        &replay_request_two,
        vec![
            QuotaPostureDigest::fixture(&identity_one, Revision::new(1).expect("usage"), now())
                .expect("posture"),
        ],
        Some(replay_cursor_again),
        512,
        TransportProvenance::Recording,
    )
    .expect("replay page two");
    let mut replay_service = recording_service(&scope, [Ok(replay_page_one), Ok(replay_page_two)]);
    let replay_result = replay_service.read(request_one).expect("replay result");
    assert_eq!(
        replay_result.evidence.state,
        QuotaEvidenceState::PaginationIncomplete
    );
    assert_eq!(
        replay_result.evidence.partial_reason,
        Some(hartevo_aws_service_quota_result_plugin::PartialReason::CursorReplay)
    );
}

#[test]
fn fixture_loopback_and_blocked_env_never_claim_native_or_connected() {
    let scope = scope_with_quota_count(1);
    let request = AwsServiceQuotaReadRequest::list_service_quotas_at(&scope, 10, None, now())
        .expect("request");
    let mut fixture = fixture_service(&scope);
    let fixture_proposal = fixture
        .propose(request.clone(), now())
        .expect("fixture proposal");
    assert_eq!(
        fixture_proposal.evidence.provenance,
        TransportProvenance::Fixture
    );
    assert!(!fixture_proposal.evidence.connected);
    assert!(!fixture_proposal.evidence.native);
    assert!(!fixture_proposal.evidence.first_party);

    let loopback_provider = AwsServiceQuotaProvider::new(
        hartevo_aws_service_quota_result_plugin::LoopbackTransport::for_scope(&scope, now()),
    )
    .expect("loopback provider");
    let mut loopback = AwsServiceQuotaService::new(
        scope.clone(),
        secret(&scope),
        permission(),
        loopback_provider,
    )
    .expect("loopback service");
    let loopback_proposal = loopback
        .propose(request.clone(), now())
        .expect("loopback proposal");
    assert_eq!(
        loopback_proposal.evidence.provenance,
        TransportProvenance::Loopback
    );
    assert!(!loopback_proposal.evidence.connected);
    assert!(!loopback_proposal.evidence.native);

    let blocked_scope = scope;
    let blocked_secret =
        SecretReference::sigv4(SECRET_REFERENCE, &blocked_scope, 1).expect("blocked secret");
    let blocked_provider = AwsServiceQuotaProvider::<BlockedEnvTransport>::default();
    let mut blocked = AwsServiceQuotaService::new(
        blocked_scope,
        blocked_secret,
        permission(),
        blocked_provider,
    )
    .expect("blocked service");
    let blocked_proposal = blocked.propose(request, now()).expect("blocked proposal");
    assert_eq!(
        blocked_proposal.evidence.state,
        QuotaEvidenceState::ProviderUnknown
    );
    assert_eq!(
        blocked_proposal.evidence.provenance,
        TransportProvenance::BlockedEnv
    );
    assert!(blocked_proposal.evidence.provider_errors[0].blocked_env);
    assert!(!blocked_proposal.evidence.connected);
    assert!(!blocked_proposal.evidence.native);
}

#[test]
fn access_loss_and_retries_are_typed_without_raw_errors() {
    let scope = scope_with_quota_count(1);
    let request = AwsServiceQuotaReadRequest::list_service_quotas_at(&scope, 10, None, now())
        .expect("request");
    let mut access_loss = recording_service(&scope, [Err(TransportError::forbidden())]);
    let access_result = access_loss
        .read(request.clone())
        .expect("access-loss evidence");
    assert_eq!(access_result.evidence.state, QuotaEvidenceState::AccessLoss);
    assert!(access_result.evidence.provider_errors[0].access_loss);
    let error_json = serde_json::to_string(&access_result.evidence).expect("error evidence JSON");
    assert!(error_json.contains("errorDigest"));
    assert!(!error_json.contains("errorMessage"));

    let identity = quota(&scope, 0);
    let page = AwsServiceQuotaReadPage::new(
        &request,
        vec![
            QuotaPostureDigest::fixture(&identity, Revision::new(1).expect("usage"), now())
                .expect("posture"),
        ],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("retry page");
    let mut retry = recording_service(&scope, [Err(TransportError::rate_limited()), Ok(page)]);
    let retry_result = retry.read(request).expect("retry evidence");
    assert_eq!(retry_result.evidence.state, QuotaEvidenceState::Complete);
    assert_eq!(retry_result.evidence.retry_count, 1);
}

#[test]
fn documented_failure_classes_fail_closed_without_provider_payloads() {
    let cases = [
        (
            TransportError::bad_request(),
            QuotaEvidenceState::ProviderUnknown,
        ),
        (
            TransportError::unauthorized(),
            QuotaEvidenceState::AccessLoss,
        ),
        (TransportError::forbidden(), QuotaEvidenceState::AccessLoss),
        (TransportError::not_found(), QuotaEvidenceState::AccessLoss),
        (
            TransportError::rate_limited(),
            QuotaEvidenceState::ProviderUnknown,
        ),
        (
            TransportError::server_failure(),
            QuotaEvidenceState::ProviderUnknown,
        ),
        (
            TransportError::timeout(),
            QuotaEvidenceState::ProviderUnknown,
        ),
    ];
    for (error, expected_state) in cases {
        let scope = scope_with_quota_count(1);
        let request = AwsServiceQuotaReadRequest::list_service_quotas_at(&scope, 10, None, now())
            .expect("request");
        let mut service = recording_service(&scope, [Err(error)]);
        let result = service.read(request).expect("typed failure evidence");
        assert_eq!(result.evidence.state, expected_state);
        assert!(!result.evidence.connected);
        assert!(!result.evidence.native);
        assert!(result.evidence.provider_errors.iter().all(|item| {
            item.error_digest != hartevo_aws_service_quota_result_plugin::Digest::zero()
        }));
    }
}

#[test]
fn registration_revoke_reverse_restore_fail_closed() {
    let scope = scope_with_quota_count(1);
    let request = AwsServiceQuotaReadRequest::list_service_quotas_at(&scope, 10, None, now())
        .expect("request");
    let mut service = fixture_service(&scope);
    service.revoke_registration().expect("revoke");
    assert!(service.read(request.clone()).is_err());
    service.restore_registration().expect("restore");
    assert!(service.read(request.clone()).is_ok());
    service.reverse_registration().expect("reverse");
    assert!(service.read(request.clone()).is_err());
    assert!(service.restore_registration().is_ok());
    assert!(service.read(request).is_ok());
}
