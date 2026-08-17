use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};
use hartevo_aws_cloudwatch_logs_result_plugin::{
    AwsCloudWatchLogsProvider, AwsCloudWatchLogsScope, AwsCloudWatchLogsService,
    AwsCloudWatchLogsServiceError, BlockedEnvAwsCloudWatchLogsTransport, CloudWatchLogsQuery,
    DeploymentBinding, DeploymentId, Digest, ErrorClass, EvidenceState, FieldName,
    GetQueryResultsRequest, GetQueryResultsResponse, LogGroupName,
    MissionAwsCloudWatchLogsConsumer, MissionBinding, MissionId, OpaqueCursor, PermissionFence,
    PermissionId, ProjectBinding, ProjectId, QueryExecutionStatus, QueryId, QueryTemplate,
    RecordingTransport, ResultSummary, Revision, SecretReference, ServiceRevision,
    ServiceRevisionId, StartQueryRequest, StartQueryResponse, TimeWindow, TransportError,
    WorkProductBinding, WorkProductId,
};

fn timestamp(hour: u32, minute: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 15, hour, minute, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn fixture() -> (
    AwsCloudWatchLogsScope,
    PermissionFence,
    SecretReference,
    CloudWatchLogsQuery,
) {
    let permission = PermissionFence::readonly(
        PermissionId::new("cloudwatch-logs-read").expect("permission id"),
        Revision::new(1).expect("permission revision"),
    )
    .expect("readonly permission");
    let template = QueryTemplate::error_summary(
        hartevo_aws_cloudwatch_logs_result_plugin::QueryTemplateId::new("errors-v1")
            .expect("template id"),
    )
    .expect("template");
    let window = TimeWindow::new(timestamp(0, 0), timestamp(1, 0)).expect("window");
    let scope = AwsCloudWatchLogsScope::new(
        DeploymentBinding::new(
            DeploymentId::new("deploy-1").expect("deployment id"),
            Revision::new(7).expect("deployment revision"),
        ),
        ServiceRevision::new(
            ServiceRevisionId::new("checkout").expect("service revision id"),
            Revision::new(3).expect("service revision"),
        ),
        MissionBinding::new(
            MissionId::new("mission-1").expect("mission id"),
            Revision::new(2).expect("mission revision"),
        ),
        ProjectBinding::new(
            ProjectId::new("project-1").expect("project id"),
            Revision::new(4).expect("project revision"),
        ),
        WorkProductBinding::new(
            WorkProductId::new("work-product-1").expect("work product id"),
            Revision::new(5).expect("work product revision"),
        ),
        hartevo_aws_cloudwatch_logs_result_plugin::AccountId::new("123456789012")
            .expect("account id"),
        hartevo_aws_cloudwatch_logs_result_plugin::AwsRegion::new("us-east-1").expect("region"),
        [LogGroupName::new("/app/checkout").expect("log group")],
        [template.id.clone()],
        window.clone(),
        permission.digest(),
    )
    .expect("scope");
    let secret = SecretReference::new("sigv4-keyring-ref", &scope, 9).expect("secret reference");
    let query = CloudWatchLogsQuery::new(
        &scope,
        &permission,
        template,
        LogGroupName::new("/app/checkout").expect("log group"),
        vec![],
        window,
    )
    .expect("query");
    (scope, permission, secret, query)
}

fn complete_service() -> (
    AwsCloudWatchLogsService<RecordingTransport>,
    CloudWatchLogsQuery,
) {
    let (scope, permission, secret, query) = fixture();
    let query_id = QueryId::new("query-1").expect("query id");
    let start_request = StartQueryRequest::from_query(&scope, &permission, &secret, &query);
    let start = StartQueryResponse::new(
        &start_request,
        query_id.clone(),
        QueryExecutionStatus::Complete,
        timestamp(1, 1),
        Some(timestamp(1, 2)),
    )
    .expect("start response");
    let describe_request =
        hartevo_aws_cloudwatch_logs_result_plugin::DescribeQueriesRequest::from_query(
            &scope,
            &permission,
            &secret,
            &query,
        );
    let described =
        hartevo_aws_cloudwatch_logs_result_plugin::QueryExecutionSummary::from_start(&start);
    let describe = hartevo_aws_cloudwatch_logs_result_plugin::DescribeQueriesResponse::new(
        &describe_request,
        vec![described],
    )
    .expect("describe response");
    let get_request =
        GetQueryResultsRequest::from_query(&scope, &permission, &secret, &query, query_id, 1, None);
    let mut error_classes = BTreeMap::new();
    error_classes.insert(ErrorClass::Application, 2);
    let summary = ResultSummary::new(
        vec![
            FieldName::new("@timestamp").expect("timestamp field"),
            FieldName::new("errorClass").expect("error class field"),
            FieldName::new("count").expect("count field"),
        ],
        2,
        512,
        error_classes,
        vec![Digest::from_text("request-fingerprint-1")],
    )
    .expect("summary");
    let results = GetQueryResultsResponse::new(
        &get_request,
        QueryExecutionStatus::Complete,
        summary,
        None,
        512,
    )
    .expect("results response");
    let mut transport = RecordingTransport::default();
    transport.push_start_response(Ok(start));
    transport.push_describe_queries_response(Ok(describe));
    transport.push_get_query_results_response(Ok(results));
    let provider = AwsCloudWatchLogsProvider::new(transport).expect("provider");
    let service =
        AwsCloudWatchLogsService::new(scope, secret, permission, provider).expect("service");
    (service, query)
}

#[test]
fn complete_summary_is_digest_bound_and_mission_review_only() {
    let (mut service, query) = complete_service();
    let proposal = service.propose(query, timestamp(1, 3)).expect("proposal");
    assert_eq!(proposal.state, EvidenceState::Complete);
    assert_eq!(proposal.evidence.event_count, 2);
    assert_eq!(proposal.evidence.bytes_scanned, 512);
    assert!(!proposal.evidence.connected);
    assert!(!proposal.evidence.native);
    assert!(!proposal.evidence.first_party);
    assert!(proposal.evidence.provider_errors.is_empty());
    assert_eq!(
        proposal.evidence.evidence_digest,
        proposal.evidence.recomputed_digest()
    );
    assert_eq!(proposal.proposal_digest, proposal.recomputed_digest());
    assert!(!format!("{proposal:?}").contains("request-fingerprint-1"));

    let receipt = service
        .record_at(&proposal, timestamp(1, 4))
        .expect("record");
    assert!(!receipt.retained_raw_events);
    assert!(!receipt.durable_provider_receipt);
    let verified = service.verify(&receipt).expect("verify");
    assert!(verified.verified);
    assert!(!verified.adopted_outcome);

    let consumer = MissionAwsCloudWatchLogsConsumer::new(
        service.scope().clone(),
        service.registration().clone(),
    )
    .expect("consumer");
    let result = consumer.consume(proposal).expect("mission result");
    assert_eq!(result.observed_state, EvidenceState::Complete);
    assert!(result.requires_human_review);
    assert!(!result.safe_to_promote);
    assert!(!result.truth_authority);
    assert!(!result.adopted_work_product);
    assert!(!result.can_be_adopted());
}

#[test]
fn query_ast_rejects_raw_log_fields_and_secret_stays_opaque() {
    assert!(FieldName::new("@message").is_err());
    assert!(FieldName::new("@ptr").is_err());
    let (_, _, secret, query) = fixture();
    let debug = format!("{secret:?}");
    assert!(!debug.contains("sigv4-keyring-ref"));
    assert!(debug.contains("<opaque>"));
    assert!(!format!("{query:?}").contains("sigv4-keyring-ref"));
    assert!(!format!("{query:?}").contains("arbitrary"));
}

#[test]
fn running_and_expired_states_are_not_reported_as_complete() {
    for status in [QueryExecutionStatus::Running, QueryExecutionStatus::Timeout] {
        let (scope, permission, secret, query) = fixture();
        let query_id = QueryId::new("query-status").expect("query id");
        let start_request = StartQueryRequest::from_query(&scope, &permission, &secret, &query);
        let start = StartQueryResponse::new(
            &start_request,
            query_id,
            status,
            timestamp(2, 0),
            Some(timestamp(2, 1)),
        )
        .expect("start");
        let describe_request =
            hartevo_aws_cloudwatch_logs_result_plugin::DescribeQueriesRequest::from_query(
                &scope,
                &permission,
                &secret,
                &query,
            );
        let describe = hartevo_aws_cloudwatch_logs_result_plugin::DescribeQueriesResponse::new(
            &describe_request,
            vec![
                hartevo_aws_cloudwatch_logs_result_plugin::QueryExecutionSummary::from_start(
                    &start,
                ),
            ],
        )
        .expect("describe");
        let mut transport = RecordingTransport::default();
        transport.push_start_response(Ok(start));
        transport.push_describe_queries_response(Ok(describe));
        let provider = AwsCloudWatchLogsProvider::new(transport).expect("provider");
        let mut service =
            AwsCloudWatchLogsService::new(scope, secret, permission, provider).expect("service");
        let proposal = service.propose(query, timestamp(2, 2)).expect("proposal");
        assert_eq!(
            proposal.state,
            if status == QueryExecutionStatus::Running {
                EvidenceState::Running
            } else {
                EvidenceState::Expired
            }
        );
        assert!(!proposal.is_adoptable());
    }
}

#[test]
fn access_loss_and_blocked_environment_are_truthful_non_native_states() {
    let (scope, permission, secret, query) = fixture();
    let mut transport = RecordingTransport::default();
    transport.push_start_response(Err(TransportError::forbidden()));
    let provider = AwsCloudWatchLogsProvider::new(transport).expect("provider");
    let mut service =
        AwsCloudWatchLogsService::new(scope, secret, permission, provider).expect("service");
    let proposal = service.read(&query).expect("access-loss proposal");
    assert_eq!(proposal.evidence.state, EvidenceState::AccessLoss);
    assert!(!proposal.evidence.connected);
    assert!(!proposal.evidence.native);

    let (scope, permission, secret, query) = fixture();
    let provider = AwsCloudWatchLogsProvider::new(BlockedEnvAwsCloudWatchLogsTransport)
        .expect("blocked provider");
    assert!(!provider.identity().provenance.connected());
    assert!(!provider.identity().provenance.native());
    let mut service = AwsCloudWatchLogsService::new(scope, secret, permission, provider)
        .expect("blocked service");
    let proposal = service.read(&query).expect("blocked proposal");
    assert_eq!(proposal.evidence.state, EvidenceState::ProviderUnknown);
    assert!(
        proposal.evidence.provider_errors[0].kind
            == hartevo_aws_cloudwatch_logs_result_plugin::ProviderErrorKind::BlockedEnv
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn pagination_replay_is_non_adoptable_and_tampering_is_rejected() {
    let (scope, permission, secret, query) = fixture();
    let query_id = QueryId::new("query-replay").expect("query id");
    let start_request = StartQueryRequest::from_query(&scope, &permission, &secret, &query);
    let start = StartQueryResponse::new(
        &start_request,
        query_id.clone(),
        QueryExecutionStatus::Complete,
        timestamp(3, 0),
        Some(timestamp(3, 1)),
    )
    .expect("start");
    let describe_request =
        hartevo_aws_cloudwatch_logs_result_plugin::DescribeQueriesRequest::from_query(
            &scope,
            &permission,
            &secret,
            &query,
        );
    let describe = hartevo_aws_cloudwatch_logs_result_plugin::DescribeQueriesResponse::new(
        &describe_request,
        vec![hartevo_aws_cloudwatch_logs_result_plugin::QueryExecutionSummary::from_start(&start)],
    )
    .expect("describe");
    let first_request = GetQueryResultsRequest::from_query(
        &scope,
        &permission,
        &secret,
        &query,
        query_id.clone(),
        1,
        None,
    );
    let summary = ResultSummary::new(
        vec![FieldName::new("count").expect("count field")],
        1,
        32,
        BTreeMap::new(),
        vec![],
    )
    .expect("summary");
    let first = GetQueryResultsResponse::new(
        &first_request,
        QueryExecutionStatus::Complete,
        summary.clone(),
        Some(OpaqueCursor::new("cursor-one").expect("cursor")),
        32,
    )
    .expect("first page");
    let second_request = GetQueryResultsRequest::from_query(
        &scope,
        &permission,
        &secret,
        &query,
        query_id,
        2,
        first.next_page_token.clone(),
    );
    let second = GetQueryResultsResponse::new(
        &second_request,
        QueryExecutionStatus::Complete,
        summary,
        Some(OpaqueCursor::new("cursor-one").expect("cursor")),
        32,
    )
    .expect("second page");
    let mut transport = RecordingTransport::default();
    transport.push_start_response(Ok(start));
    transport.push_describe_queries_response(Ok(describe));
    transport.push_get_query_results_response(Ok(first));
    transport.push_get_query_results_response(Ok(second));
    let provider = AwsCloudWatchLogsProvider::new(transport).expect("provider");
    let mut service =
        AwsCloudWatchLogsService::new(scope, secret, permission, provider).expect("service");
    let proposal = service
        .propose(query.clone(), timestamp(3, 2))
        .expect("proposal");
    assert_eq!(proposal.state, EvidenceState::Replay);
    assert!(!proposal.is_adoptable());

    let (scope, permission, secret, query) = fixture();
    let query_id = QueryId::new("query-tamper").expect("query id");
    let start_request = StartQueryRequest::from_query(&scope, &permission, &secret, &query);
    let start = StartQueryResponse::new(
        &start_request,
        query_id.clone(),
        QueryExecutionStatus::Complete,
        timestamp(4, 0),
        Some(timestamp(4, 1)),
    )
    .expect("start");
    let describe_request =
        hartevo_aws_cloudwatch_logs_result_plugin::DescribeQueriesRequest::from_query(
            &scope,
            &permission,
            &secret,
            &query,
        );
    let describe = hartevo_aws_cloudwatch_logs_result_plugin::DescribeQueriesResponse::new(
        &describe_request,
        vec![hartevo_aws_cloudwatch_logs_result_plugin::QueryExecutionSummary::from_start(&start)],
    )
    .expect("describe");
    let get_request =
        GetQueryResultsRequest::from_query(&scope, &permission, &secret, &query, query_id, 1, None);
    let summary = ResultSummary::new(
        vec![FieldName::new("count").expect("count field")],
        1,
        32,
        BTreeMap::new(),
        vec![],
    )
    .expect("summary");
    let mut tampered = GetQueryResultsResponse::new(
        &get_request,
        QueryExecutionStatus::Complete,
        summary,
        None,
        32,
    )
    .expect("results");
    tampered.response_digest = Digest::from_text("tampered-response");
    let mut transport = RecordingTransport::default();
    transport.push_start_response(Ok(start));
    transport.push_describe_queries_response(Ok(describe));
    transport.push_get_query_results_response(Ok(tampered));
    let provider = AwsCloudWatchLogsProvider::new(transport).expect("provider");
    let mut service =
        AwsCloudWatchLogsService::new(scope, secret, permission, provider).expect("service");
    assert_eq!(
        service.read(&query).expect_err("tamper must fail closed"),
        AwsCloudWatchLogsServiceError::EvidenceTampered
    );
}

#[test]
fn registration_is_reversible_but_revocation_and_secret_revoke_fail_closed() {
    let (mut service, query) = complete_service();
    service.reverse_registration().expect("reverse");
    assert!(service.registration().is_reversed());
    assert_eq!(
        service.read(&query).expect_err("reversed registration"),
        AwsCloudWatchLogsServiceError::RegistrationRevoked
    );
    service.restore_registration().expect("restore");
    assert!(service.registration().is_active());
    service.revoke_secret().expect("revoke secret");
    assert_eq!(
        service.read(&query).expect_err("revoked secret"),
        AwsCloudWatchLogsServiceError::SecretRevoked
    );

    let (mut service, query) = complete_service();
    service.revoke_registration().expect("revoke registration");
    assert_eq!(
        service.read(&query).expect_err("revoked registration"),
        AwsCloudWatchLogsServiceError::RegistrationRevoked
    );
}
