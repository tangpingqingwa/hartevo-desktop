#![allow(clippy::too_many_lines)]
#![allow(clippy::unwrap_used)]

use chrono::{DateTime, Duration, Utc};
use hartevo_aws_eventbridge_pipe_result_plugin::{
    AwsAccountId, AwsEventBridgePipeContract, AwsEventBridgePipeProvider,
    AwsEventBridgePipeReadRequest, AwsEventBridgePipeScope, AwsEventBridgePipeService,
    AwsEventBridgePipeTransportError, AwsRegion, BlockedEnvTransport, CurrentPipeState,
    DesiredPipeState, Digest, ErrorClassification, FixtureTransport, ListPipesRequest,
    ListPipesResponse, LoopbackTransport, MissionAwsEventBridgePipeConsumer, PermissionSnapshot,
    PipeArn, PipeDescription, PipeEvidenceState, PipeIdentity, PipeListFilter, PipeName,
    PipeSummary, ProjectIdentity, RecordingTransport, Revision, SecretReference,
    TransportProvenance,
};

type Service = AwsEventBridgePipeService<RecordingTransport>;

fn at(hours: i64) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-02-01T00:00:00Z")
        .expect("base timestamp")
        .with_timezone(&Utc)
        + Duration::hours(hours)
}

fn scope_with_pipe(pipe_name: &str) -> AwsEventBridgePipeScope {
    AwsEventBridgePipeScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        PipeIdentity::new(
            PipeName::new(pipe_name).expect("pipe name"),
            PipeArn::new(format!(
                "arn:aws:pipes:us-east-1:123456789012:pipe/{pipe_name}"
            ))
            .expect("pipe arn"),
        )
        .expect("pipe identity"),
        PipeArn::new("arn:aws:sqs:us-east-1:123456789012:source-queue").expect("source arn"),
        PipeArn::new("arn:aws:lambda:us-east-1:123456789012:function:target").expect("target arn"),
        hartevo_aws_eventbridge_pipe_result_plugin::MissionIdentity::new(
            "mission-1",
            Revision::new(3).expect("Mission revision"),
        )
        .expect("Mission"),
        ProjectIdentity::new("project-1", Revision::new(2).expect("Project revision"))
            .expect("Project"),
    )
    .expect("scope")
}

fn scope() -> AwsEventBridgePipeScope {
    scope_with_pipe("pipe-a")
}

fn list_request(
    scope: &AwsEventBridgePipeScope,
    page_number: u16,
    cursor: Option<hartevo_aws_eventbridge_pipe_result_plugin::Cursor>,
) -> ListPipesRequest {
    ListPipesRequest::new(
        scope,
        PipeListFilter::for_scope(scope, 10).expect("filter"),
        page_number,
        cursor,
    )
    .expect("list request")
}

fn recording_service_with(
    current_state: CurrentPipeState,
    desired_state: DesiredPipeState,
    description_source: &str,
    description_target: &str,
    description_last_modified: DateTime<Utc>,
) -> Service {
    let scope = scope();
    let filter = PipeListFilter::for_scope(&scope, 100).expect("filter");
    let request = ListPipesRequest::new(&scope, filter, 1, None).expect("list request");
    let summary = PipeSummary::new(
        scope.pipe().name().as_str(),
        scope.pipe().arn().as_str(),
        current_state,
        desired_state,
        at(0),
        at(1),
        if current_state.is_failed() {
            ErrorClassification::ProviderReported
        } else {
            ErrorClassification::None
        },
    )
    .expect("summary");
    let list_response = ListPipesResponse::new(
        &request,
        vec![summary],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("list response");
    let describe_request =
        hartevo_aws_eventbridge_pipe_result_plugin::DescribePipeRequest::for_scope(&scope)
            .expect("describe request");
    let description = PipeDescription::new(
        scope.pipe().name().as_str(),
        scope.pipe().arn().as_str(),
        description_source,
        description_target,
        current_state,
        desired_state,
        at(0),
        description_last_modified,
        true,
        true,
        if current_state.is_failed() {
            ErrorClassification::ProviderReported
        } else {
            ErrorClassification::None
        },
    )
    .expect("description");
    let describe_response = hartevo_aws_eventbridge_pipe_result_plugin::DescribePipeResponse::new(
        &describe_request,
        description,
        512,
        TransportProvenance::Recording,
    )
    .expect("describe response");
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Ok(list_response));
    transport.push_describe_response(Ok(describe_response));
    let provider = AwsEventBridgePipeProvider::new(transport).expect("provider");
    AwsEventBridgePipeService::new(
        scope.clone(),
        SecretReference::for_scope("opaque-sigv4-handle", &scope).expect("secret"),
        PermissionSnapshot::for_layer_one(4).expect("permissions"),
        provider,
        at(1),
    )
    .expect("service")
}

fn recording_service() -> Service {
    let scope = scope();
    let filter = PipeListFilter::for_scope(&scope, 100).expect("filter");
    let request = ListPipesRequest::new(&scope, filter, 1, None).expect("list request");
    let summary = PipeSummary::new(
        scope.pipe().name().as_str(),
        scope.pipe().arn().as_str(),
        CurrentPipeState::Running,
        DesiredPipeState::Running,
        at(0),
        at(1),
        ErrorClassification::None,
    )
    .expect("summary");
    let list_response = ListPipesResponse::new(
        &request,
        vec![summary],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("list response");
    let describe_request =
        hartevo_aws_eventbridge_pipe_result_plugin::DescribePipeRequest::for_scope(&scope)
            .expect("describe request");
    let description = PipeDescription::for_scope(
        &scope,
        CurrentPipeState::Running,
        DesiredPipeState::Running,
        at(0),
        at(1),
        false,
        false,
        ErrorClassification::None,
    )
    .expect("description");
    let describe_response = hartevo_aws_eventbridge_pipe_result_plugin::DescribePipeResponse::new(
        &describe_request,
        description,
        512,
        TransportProvenance::Recording,
    )
    .expect("describe response");
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Ok(list_response));
    transport.push_describe_response(Ok(describe_response));
    let provider = AwsEventBridgePipeProvider::new(transport).expect("provider");
    AwsEventBridgePipeService::new(
        scope.clone(),
        SecretReference::for_scope("opaque-sigv4-handle", &scope).expect("secret"),
        PermissionSnapshot::for_layer_one(4).expect("permissions"),
        provider,
        at(1),
    )
    .expect("service")
}

fn error_service(error: AwsEventBridgePipeTransportError) -> Service {
    let scope = scope();
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Err(error));
    let provider = AwsEventBridgePipeProvider::new(transport).expect("provider");
    AwsEventBridgePipeService::new(
        scope.clone(),
        SecretReference::for_scope("opaque-sigv4-handle", &scope).expect("secret"),
        PermissionSnapshot::for_layer_one(4).expect("permissions"),
        provider,
        at(1),
    )
    .expect("service")
}

fn proposal(
    mut service: Service,
) -> hartevo_aws_eventbridge_pipe_result_plugin::AwsEventBridgePipeProposal {
    let request = service.default_request(at(2)).expect("request");
    service.propose(request).expect("proposal")
}

#[test]
fn contract_scope_registration_and_read_allowlist_are_digest_fenced() {
    AwsEventBridgePipeContract::baseline().expect("contract");
    let service = recording_service();
    assert!(service.registration().validate().is_ok());
    assert_ne!(service.registration().scope_digest(), &Digest::zero());
    assert_ne!(service.registration().permission_digest(), &Digest::zero());
    assert_ne!(service.registration().evidence_digest(), &Digest::zero());
    let capabilities = service.describe_capabilities();
    assert_eq!(
        capabilities.allowlisted_api_operations,
        ["ListPipes", "DescribePipe"]
    );
    assert!(capabilities.read_only);
    assert!(capabilities.proposal_only);
    assert!(capabilities.recording_only);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.raw_event_payloads);
    assert!(!capabilities.delivery_verification);
    let operations = capabilities.operations.join(" ").to_ascii_lowercase();
    for forbidden in ["create", "update", "delete", "start", "stop"] {
        assert!(
            !operations.contains(forbidden),
            "forbidden operation surfaced: {forbidden}"
        );
    }
}

#[test]
fn secret_and_cursor_are_opaque_and_raw_values_never_cross_evidence() {
    let scope = scope();
    let secret = SecretReference::for_scope("raw-secret-reference-that-must-not-leak", &scope)
        .expect("secret");
    assert_eq!(
        serde_json::to_string(&secret).expect("secret JSON"),
        r#"{"opaque":true}"#
    );
    assert!(!format!("{secret:?}").contains("raw-secret-reference"));
    let filter = PipeListFilter::for_scope(&scope, 10).expect("filter");
    let cursor = hartevo_aws_eventbridge_pipe_result_plugin::Cursor::new(
        "raw-provider-next-token",
        &scope,
        &filter,
        2,
    )
    .expect("cursor");
    assert_eq!(
        serde_json::to_string(&cursor).expect("cursor JSON"),
        r#"{"opaque":true}"#
    );
    let request = ListPipesRequest::new(&scope, filter, 2, Some(cursor)).expect("request");
    let encoded = serde_json::to_string(&request).expect("request JSON");
    assert!(!encoded.contains("raw-provider-next-token"));
    assert!(!request.path_and_query().contains("raw-provider-next-token"));
    assert!(encoded.contains("requestDigest"));
}

#[test]
fn complete_recording_is_stateful_but_remains_review_only() {
    let mut service = recording_service();
    let request = service.default_request(at(2)).expect("request");
    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.state, PipeEvidenceState::Running);
    assert_eq!(proposal.current_state, Some(CurrentPipeState::Running));
    assert_eq!(proposal.desired_state, Some(DesiredPipeState::Running));
    assert_eq!(
        proposal.source_arn_digest,
        Some(service.scope().source().digest().clone())
    );
    assert_eq!(
        proposal.target_arn_digest,
        Some(service.scope().target().digest().clone())
    );
    assert!(proposal.list_complete);
    assert_eq!(proposal.list_pages, 1);
    assert!(!proposal.evidence.enrichment_present);
    assert!(!proposal.evidence.filter_present);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.can_be_adopted());
    assert!(proposal.validate_integrity().is_ok());
    let report = service.verify(&proposal);
    assert!(report.valid);
    assert!(report.review_eligible);

    let mut consumer = service.consumer().expect("Mission consumer");
    let result = consumer.consume(&proposal).expect("Mission result");
    assert_eq!(result.state, PipeEvidenceState::Running);
    assert!(!result.can_be_adopted());
    assert!(!result.outcome_adopted);
    assert!(!result.work_product_adopted);
    let first = consumer.record(&proposal, "recording-key").expect("record");
    let replay = consumer.record(&proposal, "recording-key").expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    assert!(first.validate_integrity().is_ok());
}

#[test]
fn desired_and_current_lifecycle_states_are_projected_without_effects() {
    let cases = [
        (
            CurrentPipeState::Running,
            DesiredPipeState::Running,
            PipeEvidenceState::Running,
        ),
        (
            CurrentPipeState::Stopped,
            DesiredPipeState::Running,
            PipeEvidenceState::Stopped,
        ),
        (
            CurrentPipeState::Creating,
            DesiredPipeState::Running,
            PipeEvidenceState::Creating,
        ),
        (
            CurrentPipeState::Updating,
            DesiredPipeState::Stopped,
            PipeEvidenceState::Updating,
        ),
        (
            CurrentPipeState::Starting,
            DesiredPipeState::Running,
            PipeEvidenceState::Starting,
        ),
        (
            CurrentPipeState::Stopping,
            DesiredPipeState::Stopped,
            PipeEvidenceState::Stopping,
        ),
        (
            CurrentPipeState::Deleting,
            DesiredPipeState::Deleted,
            PipeEvidenceState::Deleting,
        ),
        (
            CurrentPipeState::CreateFailed,
            DesiredPipeState::Running,
            PipeEvidenceState::Failed,
        ),
    ];
    for (current, desired, expected) in cases {
        let service = recording_service_with(
            current,
            desired,
            "arn:aws:sqs:us-east-1:123456789012:source-queue",
            "arn:aws:lambda:us-east-1:123456789012:function:target",
            at(1),
        );
        let result = proposal(service);
        assert_eq!(result.state, expected, "current state {current:?}");
        assert_eq!(result.current_state, Some(current));
        assert_eq!(result.desired_state, Some(desired));
        assert!(!result.evidence.can_be_adopted());
    }
}

#[test]
fn state_drift_and_source_target_mismatch_fail_closed() {
    let mut drift = recording_service_with(
        CurrentPipeState::Running,
        DesiredPipeState::Running,
        "arn:aws:sqs:us-east-1:123456789012:source-queue",
        "arn:aws:lambda:us-east-1:123456789012:function:target",
        at(2),
    );
    let drift_proposal = drift
        .propose(drift.default_request(at(3)).expect("request"))
        .expect("drift proposal");
    assert_eq!(drift_proposal.state, PipeEvidenceState::Partial);
    assert_eq!(
        drift_proposal.evidence.error_classification,
        ErrorClassification::StateDrift
    );
    assert!(!drift.verify(&drift_proposal).review_eligible);

    let mut mismatch = recording_service_with(
        CurrentPipeState::Running,
        DesiredPipeState::Running,
        "arn:aws:sqs:us-east-1:123456789012:other-source",
        "arn:aws:lambda:us-east-1:123456789012:function:target",
        at(1),
    );
    let mismatch_proposal = mismatch
        .propose(mismatch.default_request(at(3)).expect("request"))
        .expect("mismatch proposal");
    assert_eq!(mismatch_proposal.state, PipeEvidenceState::Partial);
    assert_eq!(
        mismatch_proposal.evidence.error_classification,
        ErrorClassification::SourceTargetMismatch
    );
    assert!(!mismatch.verify(&mismatch_proposal).review_eligible);
}

#[test]
fn pagination_loops_and_truncation_are_explicitly_partial() {
    let loop_scope = scope();
    let filter = PipeListFilter::for_scope(&loop_scope, 1).expect("filter");
    let request_one =
        ListPipesRequest::new(&loop_scope, filter.clone(), 1, None).expect("page one");
    let cursor_two = hartevo_aws_eventbridge_pipe_result_plugin::Cursor::new(
        "loop-token",
        &loop_scope,
        &filter,
        2,
    )
    .expect("cursor two");
    let cursor_three = hartevo_aws_eventbridge_pipe_result_plugin::Cursor::new(
        "loop-token",
        &loop_scope,
        &filter,
        3,
    )
    .expect("cursor three");
    let other = PipeSummary::new(
        "pipe-other",
        "arn:aws:pipes:us-east-1:123456789012:pipe/pipe-other",
        CurrentPipeState::Running,
        DesiredPipeState::Running,
        at(0),
        at(1),
        ErrorClassification::None,
    )
    .expect("other summary");
    let first = ListPipesResponse::new(
        &request_one,
        vec![other.clone()],
        Some(cursor_two.clone()),
        512,
        TransportProvenance::Recording,
    )
    .expect("first page");
    let request_two =
        ListPipesRequest::new(&loop_scope, filter.clone(), 2, Some(cursor_two)).expect("page two");
    let second = ListPipesResponse::new(
        &request_two,
        vec![other],
        Some(cursor_three),
        512,
        TransportProvenance::Recording,
    )
    .expect("second page");
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Ok(first));
    transport.push_list_response(Ok(second));
    let provider = AwsEventBridgePipeProvider::new(transport).expect("provider");
    let mut service = AwsEventBridgePipeService::new(
        loop_scope.clone(),
        SecretReference::for_scope("opaque-sigv4-handle", &loop_scope).expect("secret"),
        PermissionSnapshot::for_layer_one(4).expect("permissions"),
        provider,
        at(1),
    )
    .expect("service");
    let read_request = AwsEventBridgePipeReadRequest::new(&loop_scope, filter, 4, at(2), None)
        .expect("read request");
    let looped = service.read(read_request).expect("looped evidence");
    assert_eq!(looped.state, PipeEvidenceState::Partial);
    assert_eq!(
        looped.error_classification,
        ErrorClassification::PaginationLoop
    );
    assert!(!looped.list_complete);

    let truncated_scope = scope();
    let filter = PipeListFilter::for_scope(&truncated_scope, 1).expect("filter");
    let request =
        ListPipesRequest::new(&truncated_scope, filter.clone(), 1, None).expect("request");
    let cursor = hartevo_aws_eventbridge_pipe_result_plugin::Cursor::new(
        "truncated-token",
        &truncated_scope,
        &filter,
        2,
    )
    .expect("cursor");
    let page = ListPipesResponse::new(
        &request,
        vec![],
        Some(cursor),
        512,
        TransportProvenance::Recording,
    )
    .expect("page");
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Ok(page));
    let provider = AwsEventBridgePipeProvider::new(transport).expect("provider");
    let mut service = AwsEventBridgePipeService::new(
        truncated_scope.clone(),
        SecretReference::for_scope("opaque-sigv4-handle", &truncated_scope).expect("secret"),
        PermissionSnapshot::for_layer_one(4).expect("permissions"),
        provider,
        at(1),
    )
    .expect("service");
    let read_request = AwsEventBridgePipeReadRequest::new(&truncated_scope, filter, 1, at(2), None)
        .expect("read request");
    let truncated = service.read(read_request).expect("truncated evidence");
    assert_eq!(truncated.state, PipeEvidenceState::Partial);
    assert_eq!(
        truncated.error_classification,
        ErrorClassification::Truncated
    );
    assert!(truncated.truncated);
}

#[test]
fn provider_status_families_map_to_typed_non_adoptable_evidence() {
    let cases = [
        (
            AwsEventBridgePipeTransportError::BadRequest,
            PipeEvidenceState::ProviderUnknown,
            ErrorClassification::BadRequest,
        ),
        (
            AwsEventBridgePipeTransportError::Unauthorized,
            PipeEvidenceState::AccessLoss,
            ErrorClassification::Unauthorized,
        ),
        (
            AwsEventBridgePipeTransportError::Forbidden,
            PipeEvidenceState::AccessLoss,
            ErrorClassification::Forbidden,
        ),
        (
            AwsEventBridgePipeTransportError::NotFound,
            PipeEvidenceState::NotFound,
            ErrorClassification::NotFound,
        ),
        (
            AwsEventBridgePipeTransportError::Conflict,
            PipeEvidenceState::ProviderUnknown,
            ErrorClassification::Conflict,
        ),
        (
            AwsEventBridgePipeTransportError::RateLimited {
                retry_after_seconds: Some(4),
            },
            PipeEvidenceState::Throttled,
            ErrorClassification::RateLimited,
        ),
        (
            AwsEventBridgePipeTransportError::ServerError { status: 503 },
            PipeEvidenceState::ProviderUnknown,
            ErrorClassification::ServerError,
        ),
        (
            AwsEventBridgePipeTransportError::Timeout,
            PipeEvidenceState::ProviderUnknown,
            ErrorClassification::Timeout,
        ),
    ];
    for (error, expected_state, expected_classification) in cases {
        let mut service = error_service(error);
        let proposal = service
            .propose(service.default_request(at(2)).expect("request"))
            .expect("failure proposal");
        assert_eq!(proposal.state, expected_state);
        assert_eq!(
            proposal.evidence.error_classification,
            expected_classification
        );
        assert!(proposal.failure.is_some());
        assert!(!proposal.can_be_adopted());
        assert!(!proposal.connected);
        assert!(!proposal.native);
    }
}

#[test]
fn parser_retains_only_bounded_state_and_presence_flags() {
    let scope = scope();
    let filter = PipeListFilter::for_scope(&scope, 10).expect("filter");
    let request = ListPipesRequest::new(&scope, filter, 1, None).expect("request");
    let list_body = br#"{
      "Pipes": [{
        "Name": "pipe-a",
        "Arn": "arn:aws:pipes:us-east-1:123456789012:pipe/pipe-a",
        "CurrentState": "RUNNING",
        "DesiredState": "RUNNING",
        "CreationTime": "2026-02-01T00:00:00Z",
        "LastModifiedTime": "2026-02-01T01:00:00Z",
        "StateReason": "sensitive provider explanation",
        "EventPayload": {"secret": "do not retain"}
      }],
      "NextToken": "raw-provider-token"
    }"#;
    let list =
        AwsEventBridgePipeProvider::<RecordingTransport>::parse_list_json(&request, 200, list_body)
            .expect("list parse");
    let serialized = serde_json::to_string(&list).expect("list JSON");
    assert!(!serialized.contains("raw-provider-token"));
    assert!(!serialized.contains("sensitive provider explanation"));
    assert!(!serialized.contains("do not retain"));
    assert_eq!(
        list.pipes[0].error_classification,
        ErrorClassification::ProviderReported
    );

    let describe_request =
        hartevo_aws_eventbridge_pipe_result_plugin::DescribePipeRequest::for_scope(&scope)
            .expect("describe request");
    let describe_body = br#"{
      "Name": "pipe-a",
      "Arn": "arn:aws:pipes:us-east-1:123456789012:pipe/pipe-a",
      "Source": "arn:aws:sqs:us-east-1:123456789012:source-queue",
      "Target": "arn:aws:lambda:us-east-1:123456789012:function:target",
      "CurrentState": "RUNNING",
      "DesiredState": "RUNNING",
      "CreationTime": "2026-02-01T00:00:00Z",
      "LastModifiedTime": "2026-02-01T01:00:00Z",
      "StateReason": "secret reason",
      "Enrichment": {"target": "raw data"},
      "FilterCriteria": {"FilterPattern": "raw pattern"},
      "EventPayload": {"body": "raw payload"}
    }"#;
    let describe = AwsEventBridgePipeProvider::<RecordingTransport>::parse_describe_json(
        &describe_request,
        200,
        describe_body,
    )
    .expect("describe parse");
    assert!(describe.description.enrichment_present);
    assert!(describe.description.filter_present);
    let serialized = serde_json::to_string(&describe).expect("describe JSON");
    for raw in ["secret reason", "raw data", "raw pattern", "raw payload"] {
        assert!(
            !serialized.contains(raw),
            "raw provider value leaked: {raw}"
        );
    }
}

#[test]
fn fixture_loopback_and_blocked_env_never_claim_connected_or_native() {
    let scope = scope();
    let secret = SecretReference::for_scope("opaque-sigv4-handle", &scope).expect("secret");
    let permissions = PermissionSnapshot::for_layer_one(4).expect("permissions");

    let fixture_provider =
        AwsEventBridgePipeProvider::new(FixtureTransport::for_scope(&scope, at(1)))
            .expect("fixture provider");
    let mut fixture = AwsEventBridgePipeService::new(
        scope.clone(),
        secret.clone(),
        permissions.clone(),
        fixture_provider,
        at(1),
    )
    .expect("fixture service");
    let fixture_proposal = fixture
        .propose(fixture.default_request(at(2)).expect("request"))
        .expect("fixture proposal");
    assert_eq!(fixture_proposal.provenance, TransportProvenance::Fixture);
    assert!(!fixture_proposal.connected);
    assert!(!fixture_proposal.native);

    let loopback_provider =
        AwsEventBridgePipeProvider::new(LoopbackTransport::for_scope(&scope, at(1)))
            .expect("loopback provider");
    let mut loopback = AwsEventBridgePipeService::new(
        scope.clone(),
        secret.clone(),
        permissions.clone(),
        loopback_provider,
        at(1),
    )
    .expect("loopback service");
    let loopback_proposal = loopback
        .propose(loopback.default_request(at(2)).expect("request"))
        .expect("loopback proposal");
    assert_eq!(loopback_proposal.provenance, TransportProvenance::Loopback);
    assert!(!loopback_proposal.connected);
    assert!(!loopback_proposal.native);

    let mut blocked = AwsEventBridgePipeService::new(
        scope.clone(),
        secret,
        permissions,
        AwsEventBridgePipeProvider::new(BlockedEnvTransport).expect("blocked provider"),
        at(1),
    )
    .expect("blocked service");
    let blocked_proposal = blocked
        .propose(blocked.default_request(at(2)).expect("request"))
        .expect("blocked proposal");
    assert_eq!(blocked_proposal.provenance, TransportProvenance::BlockedEnv);
    assert_eq!(blocked_proposal.state, PipeEvidenceState::ProviderUnknown);
    assert_eq!(
        blocked_proposal.evidence.error_classification,
        ErrorClassification::BlockedEnv
    );
    assert!(!blocked_proposal.connected);
    assert!(!blocked_proposal.native);
}

#[test]
fn tamper_response_proposal_and_registration_revocation_fail_closed() {
    let scope = scope();
    let filter = PipeListFilter::for_scope(&scope, 10).expect("filter");
    let request = ListPipesRequest::new(&scope, filter, 1, None).expect("request");
    let summary = PipeSummary::new(
        scope.pipe().name().as_str(),
        scope.pipe().arn().as_str(),
        CurrentPipeState::Running,
        DesiredPipeState::Running,
        at(0),
        at(1),
        ErrorClassification::None,
    )
    .expect("summary");
    let tampered = ListPipesResponse::new(
        &request,
        vec![summary],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("response")
    .with_declared_digest(Digest::from_text("tampered"));
    assert!(tampered.validate_integrity(&request).is_err());
    assert!(
        ListPipesResponse::new(
            &request,
            vec![],
            None,
            hartevo_aws_eventbridge_pipe_result_plugin::MAX_RESPONSE_BYTES + 1,
            TransportProvenance::Recording,
        )
        .is_err()
    );

    let mut service = recording_service();
    let proposal = service
        .propose(service.default_request(at(2)).expect("request"))
        .expect("proposal");
    let mut tampered_proposal = proposal.clone();
    tampered_proposal.current_state = Some(CurrentPipeState::Stopped);
    assert!(tampered_proposal.validate_integrity().is_err());
    service.revoke().expect("revoke");
    assert!(
        service
            .propose(service.default_request(at(3)).expect("request"))
            .is_err()
    );
    assert!(!service.verify(&proposal).review_eligible);
    service.restore_registration().expect("restore");
    service.reverse().expect("reverse");
    assert!(service.restore_registration().is_err());
}

#[test]
fn scope_and_permission_revision_drift_are_rejected() {
    let scope_a = scope_with_pipe("pipe-a");
    let scope_b = scope_with_pipe("pipe-b");
    let filter_a = PipeListFilter::for_scope(&scope_a, 10).expect("filter a");
    assert!(ListPipesRequest::new(&scope_b, filter_a, 1, None).is_err());
    let permission = PermissionSnapshot::for_layer_one(7).expect("permission");
    assert_ne!(permission.digest(), &Digest::zero());
    assert!(PermissionSnapshot::new(7, vec!["pipes:CreatePipe".to_owned()]).is_err());
    let secret_a = SecretReference::for_scope("handle", &scope_a).expect("secret a");
    let secret_b = SecretReference::for_scope("handle", &scope_b).expect("secret b");
    assert_ne!(secret_a.digest(), secret_b.digest());
}

#[test]
fn parser_status_mapping_covers_http_error_classes() {
    let scope = scope();
    let request = list_request(&scope, 1, None);
    for (status, expected) in [
        (400, AwsEventBridgePipeTransportError::BadRequest),
        (401, AwsEventBridgePipeTransportError::Unauthorized),
        (403, AwsEventBridgePipeTransportError::Forbidden),
        (404, AwsEventBridgePipeTransportError::NotFound),
        (409, AwsEventBridgePipeTransportError::Conflict),
        (
            429,
            AwsEventBridgePipeTransportError::RateLimited {
                retry_after_seconds: None,
            },
        ),
        (
            500,
            AwsEventBridgePipeTransportError::ServerError { status: 500 },
        ),
    ] {
        let error = AwsEventBridgePipeProvider::<RecordingTransport>::parse_list_json(
            &request, status, br"{}",
        )
        .expect_err("status must fail");
        assert_eq!(
            error,
            hartevo_aws_eventbridge_pipe_result_plugin::AwsEventBridgePipeProviderError::Transport(
                expected
            )
        );
    }
}

#[test]
fn mission_consumer_rejects_scope_tamper_and_recording_conflicts() {
    let service = recording_service();
    let consumer = service.consumer().expect("consumer");
    let mut service_for_proposal = recording_service();
    let proposal = service_for_proposal
        .propose(
            service_for_proposal
                .default_request(at(2))
                .expect("request"),
        )
        .expect("proposal");
    let mut scope_tamper = proposal.clone();
    scope_tamper.scope_digest = Digest::from_text("different-scope");
    assert!(consumer.consume(&scope_tamper).is_err());

    let mut own_service = recording_service();
    let own_proposal = own_service
        .propose(own_service.default_request(at(2)).expect("request"))
        .expect("proposal");
    let mut own_consumer = own_service.consumer().expect("consumer");
    own_consumer
        .record(&own_proposal, "same-key")
        .expect("first record");
    let mut alternate_service = recording_service_with(
        CurrentPipeState::Stopped,
        DesiredPipeState::Stopped,
        "arn:aws:sqs:us-east-1:123456789012:source-queue",
        "arn:aws:lambda:us-east-1:123456789012:function:target",
        at(1),
    );
    let alternate = alternate_service
        .propose(
            alternate_service
                .default_request(at(2))
                .expect("alternate request"),
        )
        .expect("alternate proposal");
    assert!(own_consumer.record(&alternate, "same-key").is_err());
}

#[test]
fn raw_payload_type_is_not_available_from_public_contract_models() {
    let scope = scope();
    let description = PipeDescription::for_scope(
        &scope,
        CurrentPipeState::Running,
        DesiredPipeState::Running,
        at(0),
        at(1),
        true,
        true,
        ErrorClassification::None,
    )
    .expect("description");
    let encoded = serde_json::to_string(&description).expect("description JSON");
    assert!(encoded.contains("sourceArnDigest"));
    assert!(encoded.contains("targetArnDigest"));
    assert!(!encoded.contains("Source"));
    assert!(!encoded.contains("Target"));
    assert!(!encoded.contains("payload"));
    assert!(!encoded.contains("FilterPattern"));
}

#[allow(dead_code)]
fn assert_consumer_type(_: MissionAwsEventBridgePipeConsumer) {}
