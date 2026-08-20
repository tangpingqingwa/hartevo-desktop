use std::fmt::Debug;

use hartevo_aws_glue_job_result_plugin::*;

fn scope() -> AwsGlueScope {
    AwsGlueScope::new(
        AccountId::new("123456789012").unwrap(),
        AwsRegion::new("us-east-1").unwrap(),
        CatalogId::new("123456789012").unwrap(),
        [JobName::new("transform_job").unwrap()],
        MissionId::new("mission-564").unwrap(),
        ProjectId::new("project-564").unwrap(),
        WorkProductId::new("work-product-564").unwrap(),
        Revision::new(7).unwrap(),
        Digest::from_text("glue:read,glue:get-job-runs"),
        Digest::from_text("consent:mission-564"),
    )
    .unwrap()
}

fn secret(scope: &AwsGlueScope) -> SecretReference {
    SecretReference::sigv4("keyring-reference-564", scope, 3).unwrap()
}

fn run(scope: &AwsGlueScope, state: GlueJobRunState, started: u64) -> JobRunEvidence {
    JobRunEvidence::new(
        JobRunReference::new(
            scope.account_id().clone(),
            scope.region().clone(),
            scope.catalog_id().clone(),
            JobName::new("transform_job").unwrap(),
            RunId::new(format!("jr-{started}")).unwrap(),
            Some(AttemptNumber::new(1).unwrap()),
        ),
        state,
        Some(Timestamp::new(started)),
        state.is_terminal().then_some(Timestamp::new(started + 4)),
        Some(4),
        Some(60),
        CapacitySummary::new(Some(1_000), Some(1_000), Some(4), Some(2), Some(1)).unwrap(),
        Some(Digest::from_text("raw-arguments-are-never-retained")),
        Some(Digest::from_text("artifact-location-is-never-retained")),
        Some(Digest::from_text("provider-diagnostic-is-never-retained")),
    )
    .unwrap()
}

fn service_with_run(
    state: GlueJobRunState,
    retry_policy: RetryPolicy,
) -> AwsGlueJobResultService<RecordingAwsGlueTransport> {
    let governed_scope = scope();
    let governed_secret = secret(&governed_scope);
    let job = JobName::new("transform_job").unwrap();
    let run_id = RunId::new("jr-100").unwrap();
    let request = GetJobRunRequest::new(
        &governed_scope,
        &governed_secret,
        job,
        run_id,
        Some(AttemptNumber::new(1).unwrap()),
    );
    let response = GetJobRunResponse::new(&request, run(&governed_scope, state, 100), None);
    let mut transport = RecordingAwsGlueTransport::default();
    transport.push_job_run_response(Ok(response));
    let provider =
        AwsGlueProvider::new(transport, "fixture-0.1", ProviderProvenance::Fixture).unwrap();
    AwsGlueJobResultService::new(governed_scope, governed_secret, provider, retry_policy).unwrap()
}

fn get_job_run_request(
    governed_scope: &AwsGlueScope,
    governed_secret: &SecretReference,
    run_id: &str,
) -> GetJobRunRequest {
    GetJobRunRequest::new(
        governed_scope,
        governed_secret,
        JobName::new("transform_job").unwrap(),
        RunId::new(run_id).unwrap(),
        Some(AttemptNumber::new(1).unwrap()),
    )
}

fn bounds(max_runs: u32, page_size: u32, max_pages: u8) -> ResultBounds {
    ResultBounds::new(max_runs, page_size, max_pages, 120).unwrap()
}

fn get_run_request() -> AwsGlueJobResultRequest {
    AwsGlueJobResultRequest::get_job_run(
        JobName::new("transform_job").unwrap(),
        RunId::new("jr-100").unwrap(),
        Some(AttemptNumber::new(1).unwrap()),
        bounds(8, 8, 4),
        false,
        Revision::new(7).unwrap(),
    )
}

#[test]
fn contract_and_capabilities_pin_layer_one_honesty() {
    AwsGlueJobResultContract::baseline().unwrap();
    let capabilities = ServiceCapabilities::layer_one();
    assert!(capabilities.read_only);
    assert!(capabilities.proposal_only);
    assert!(!capabilities.live_execution);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.durable_receipt);
    assert!(!capabilities.start_job_run);
    assert!(!capabilities.stop_job_run);
    assert!(!capabilities.raw_arguments);
    assert!(!capabilities.raw_logs);
    assert!(!capabilities.data_rows);
    assert!(!capabilities.transformation_authority);
    assert!(!capabilities.data_quality_authority);
    assert!(!capabilities.outcome_authority);
    assert_eq!(
        capabilities.provider_operations,
        ["GetJobRun", "GetJobRuns", "GetJob"]
    );
}

#[test]
fn secret_and_cursor_debug_are_opaque_and_non_serializing() {
    let governed_scope = scope();
    let governed_secret = secret(&governed_scope);
    let secret_debug = format!("{governed_secret:?}");
    assert!(!secret_debug.contains("keyring-reference-564"));
    assert!(secret_debug.contains("reference_digest"));

    let cursor = OpaquePageCursor::new("opaque-provider-cursor").unwrap();
    let cursor_debug = format!("{cursor:?}");
    assert!(!cursor_debug.contains("opaque-provider-cursor"));
    assert!(cursor_debug.contains("token_digest"));
}

#[test]
fn every_glue_lifecycle_state_is_typed_and_unknown_is_not_success() {
    for (raw, expected) in [
        ("STARTING", GlueJobRunState::Starting),
        ("RUNNING", GlueJobRunState::Running),
        ("STOPPING", GlueJobRunState::Stopping),
        ("STOPPED", GlueJobRunState::Stopped),
        ("SUCCEEDED", GlueJobRunState::Succeeded),
        ("FAILED", GlueJobRunState::Failed),
        ("TIMEOUT", GlueJobRunState::Timeout),
        ("future-state", GlueJobRunState::Unknown),
    ] {
        assert_eq!(GlueJobRunState::parse(raw), expected);
    }
    assert!(!GlueJobRunState::Running.is_terminal());
    assert!(GlueJobRunState::Succeeded.is_terminal());
    assert!(GlueJobRunState::Timeout.is_terminal());

    for (state, projection) in [
        (GlueJobRunState::Starting, ResultProjection::Starting),
        (GlueJobRunState::Running, ResultProjection::Running),
        (GlueJobRunState::Stopping, ResultProjection::Stopping),
        (GlueJobRunState::Stopped, ResultProjection::Stopped),
        (GlueJobRunState::Succeeded, ResultProjection::Succeeded),
        (GlueJobRunState::Failed, ResultProjection::Failed),
        (GlueJobRunState::Timeout, ResultProjection::Timeout),
    ] {
        let proposal = service_with_run(state, RetryPolicy::new(1).unwrap())
            .propose(get_run_request())
            .unwrap();
        assert_eq!(proposal.projection, projection);
        if matches!(state, GlueJobRunState::Starting | GlueJobRunState::Running) {
            assert_eq!(
                proposal.evidence.timeout_projection,
                TimeoutProjection::Bounded {
                    timeout_seconds: 120
                }
            );
        }
    }
    let unknown = service_with_run(GlueJobRunState::Unknown, RetryPolicy::new(1).unwrap())
        .propose(get_run_request())
        .unwrap();
    assert_eq!(unknown.projection, ResultProjection::ProviderUnknown);
}

#[test]
fn timeout_and_provider_statuses_project_without_leaking_diagnostics() {
    let timeout = service_with_run(GlueJobRunState::Timeout, RetryPolicy::new(1).unwrap())
        .propose(get_run_request())
        .unwrap();
    assert_eq!(timeout.projection, ResultProjection::Timeout);
    assert_eq!(
        timeout.evidence.timeout_projection,
        TimeoutProjection::RunTimeout
    );

    for (status, expected) in [
        (400, ResultProjection::FinalError),
        (401, ResultProjection::AccessLost),
        (403, ResultProjection::AccessLost),
        (404, ResultProjection::ProviderUnknown),
        (409, ResultProjection::FinalError),
        (429, ResultProjection::ProviderUnknown),
        (500, ResultProjection::ProviderUnknown),
        (504, ResultProjection::ProviderUnknown),
    ] {
        let governed_scope = scope();
        let governed_secret = secret(&governed_scope);
        let mut transport = RecordingAwsGlueTransport::default();
        transport.push_job_run_response(Err(TransportError::from_status(
            status,
            "sensitive provider diagnostic",
        )));
        let provider =
            AwsGlueProvider::new(transport, "fixture-0.1", ProviderProvenance::Fixture).unwrap();
        let mut service = AwsGlueJobResultService::new(
            governed_scope,
            governed_secret,
            provider,
            RetryPolicy::new(1).unwrap(),
        )
        .unwrap();
        let proposal = service.propose(get_run_request()).unwrap();
        assert_eq!(proposal.projection, expected, "status {status}");
        assert_eq!(proposal.evidence.provider_errors.len(), 1);
        assert!(
            !format!("{:?}", proposal.evidence.provider_errors[0])
                .contains("sensitive provider diagnostic")
        );
    }
}

#[test]
fn retries_are_bounded_and_recorded_as_digests() {
    let governed_scope = scope();
    let governed_secret = secret(&governed_scope);
    let provider_request = get_job_run_request(&governed_scope, &governed_secret, "jr-100");
    let response = GetJobRunResponse::new(
        &provider_request,
        run(&governed_scope, GlueJobRunState::Succeeded, 100),
        None,
    );
    let mut transport = RecordingAwsGlueTransport::default();
    transport.push_job_run_response(Err(TransportError::from_status(503, "temporary")));
    transport.push_job_run_response(Ok(response));
    let provider =
        AwsGlueProvider::new(transport, "recording-0.1", ProviderProvenance::Recording).unwrap();
    let mut service = AwsGlueJobResultService::new(
        governed_scope,
        governed_secret,
        provider,
        RetryPolicy::new(3).unwrap(),
    )
    .unwrap();
    let proposal = service.propose(get_run_request()).unwrap();
    assert_eq!(proposal.projection, ResultProjection::Succeeded);
    assert_eq!(proposal.evidence.retries.len(), 1);
    assert_eq!(proposal.evidence.retry_projection.provider_attempts, 2);
    assert_eq!(proposal.evidence.retry_projection.provider_retry_count, 1);
    assert!(proposal.evidence.retry_projection.retried);
    assert!(
        !proposal.evidence.retries[0]
            .error_digest
            .as_str()
            .contains("temporary")
    );
}

#[test]
fn newest_first_pagination_binds_cursor_and_retains_only_bounded_runs() {
    let governed_scope = scope();
    let governed_secret = secret(&governed_scope);
    let job = JobName::new("transform_job").unwrap();
    let read_bounds = bounds(8, 2, 4);
    let first_request = GetJobRunsRequest::new(
        &governed_scope,
        &governed_secret,
        job.clone(),
        read_bounds,
        1,
        None,
    );
    let raw_cursor = OpaquePageCursor::new("page-2-cursor").unwrap();
    let first = GetJobRunsResponse::new(
        &first_request,
        vec![run(&governed_scope, GlueJobRunState::Succeeded, 200)],
        Some(raw_cursor),
        true,
        None,
    );
    let next_cursor = first.next_cursor.clone().unwrap();
    let second_request = GetJobRunsRequest::new(
        &governed_scope,
        &governed_secret,
        job,
        read_bounds,
        2,
        Some(next_cursor.clone()),
    );
    let second = GetJobRunsResponse::new(
        &second_request,
        vec![run(&governed_scope, GlueJobRunState::Succeeded, 100)],
        None,
        true,
        None,
    );
    let mut transport = RecordingAwsGlueTransport::default();
    transport.push_job_runs_response(Ok(first));
    transport.push_job_runs_response(Ok(second));
    let provider =
        AwsGlueProvider::new(transport, "fixture-0.1", ProviderProvenance::Fixture).unwrap();
    let mut service = AwsGlueJobResultService::new(
        governed_scope,
        governed_secret,
        provider,
        RetryPolicy::new(1).unwrap(),
    )
    .unwrap();
    let request = AwsGlueJobResultRequest::get_job_runs(
        JobName::new("transform_job").unwrap(),
        None,
        read_bounds,
        false,
        Revision::new(7).unwrap(),
    );
    let proposal = service.propose(request).unwrap();
    assert_eq!(proposal.projection, ResultProjection::Succeeded);
    assert_eq!(proposal.evidence.runs.len(), 2);
    assert_eq!(proposal.evidence.pages_observed, 2);
    assert_eq!(
        proposal.evidence.page_cursor_digests,
        vec![next_cursor.token_digest().clone()]
    );
    assert!(format!("{next_cursor:?}").contains("token_digest"));
    assert!(!format!("{next_cursor:?}").contains("page-2-cursor"));
}

#[test]
fn pagination_rejects_non_newest_order_and_repeated_cursor() {
    let governed_scope = scope();
    let governed_secret = secret(&governed_scope);
    let read_bounds = bounds(8, 2, 4);
    let first_request = GetJobRunsRequest::new(
        &governed_scope,
        &governed_secret,
        JobName::new("transform_job").unwrap(),
        read_bounds,
        1,
        None,
    );
    let unordered = GetJobRunsResponse::new(
        &first_request,
        vec![run(&governed_scope, GlueJobRunState::Succeeded, 100)],
        None,
        false,
        None,
    );
    let mut transport = RecordingAwsGlueTransport::default();
    transport.push_job_runs_response(Ok(unordered));
    let provider =
        AwsGlueProvider::new(transport, "fixture-0.1", ProviderProvenance::Fixture).unwrap();
    let mut service = AwsGlueJobResultService::new(
        governed_scope.clone(),
        governed_secret.clone(),
        provider,
        RetryPolicy::new(1).unwrap(),
    )
    .unwrap();
    let request = AwsGlueJobResultRequest::get_job_runs(
        JobName::new("transform_job").unwrap(),
        None,
        read_bounds,
        false,
        Revision::new(7).unwrap(),
    );
    assert_eq!(
        service.propose(request).unwrap_err(),
        AwsGlueJobResultServiceError::PaginationOrderViolation
    );

    let first_request = GetJobRunsRequest::new(
        &governed_scope,
        &governed_secret,
        JobName::new("transform_job").unwrap(),
        read_bounds,
        1,
        None,
    );
    let cursor = OpaquePageCursor::new("loop-cursor").unwrap();
    let first = GetJobRunsResponse::new(
        &first_request,
        vec![run(&governed_scope, GlueJobRunState::Succeeded, 200)],
        Some(cursor),
        true,
        None,
    );
    let second_request = GetJobRunsRequest::new(
        &governed_scope,
        &governed_secret,
        JobName::new("transform_job").unwrap(),
        read_bounds,
        2,
        first.next_cursor.clone(),
    );
    let second = GetJobRunsResponse::new(
        &second_request,
        vec![run(&governed_scope, GlueJobRunState::Succeeded, 100)],
        second_request.cursor.clone(),
        true,
        None,
    );
    let mut transport = RecordingAwsGlueTransport::default();
    transport.push_job_runs_response(Ok(first));
    transport.push_job_runs_response(Ok(second));
    let provider =
        AwsGlueProvider::new(transport, "fixture-0.1", ProviderProvenance::Fixture).unwrap();
    let mut service = AwsGlueJobResultService::new(
        governed_scope,
        governed_secret,
        provider,
        RetryPolicy::new(1).unwrap(),
    )
    .unwrap();
    let request = AwsGlueJobResultRequest::get_job_runs(
        JobName::new("transform_job").unwrap(),
        None,
        read_bounds,
        false,
        Revision::new(7).unwrap(),
    );
    assert_eq!(
        service.propose(request).unwrap_err(),
        AwsGlueJobResultServiceError::PageLoop
    );
}

#[test]
fn scope_attempt_and_truncation_fences_fail_closed() {
    let governed_scope = scope();
    let governed_secret = secret(&governed_scope);
    let mut service = service_with_run(GlueJobRunState::Succeeded, RetryPolicy::new(1).unwrap());
    let outside_job = AwsGlueJobResultRequest::get_job_run(
        JobName::new("not_allowlisted").unwrap(),
        RunId::new("jr-100").unwrap(),
        Some(AttemptNumber::new(1).unwrap()),
        bounds(8, 8, 4),
        false,
        Revision::new(7).unwrap(),
    );
    assert_eq!(
        service.propose(outside_job).unwrap_err(),
        AwsGlueJobResultServiceError::ScopeMismatch
    );

    let wrong_attempt_request = AwsGlueJobResultRequest::get_job_run(
        JobName::new("transform_job").unwrap(),
        RunId::new("jr-100").unwrap(),
        Some(AttemptNumber::new(2).unwrap()),
        bounds(8, 8, 4),
        false,
        Revision::new(7).unwrap(),
    );
    assert_eq!(
        service.propose(wrong_attempt_request).unwrap_err(),
        AwsGlueJobResultServiceError::AttemptMismatch
    );

    let request = GetJobRunsRequest::new(
        &governed_scope,
        &governed_secret,
        JobName::new("transform_job").unwrap(),
        bounds(1, 4, 2),
        1,
        None,
    );
    let response = GetJobRunsResponse::new(
        &request,
        vec![
            run(&governed_scope, GlueJobRunState::Succeeded, 300),
            run(&governed_scope, GlueJobRunState::Succeeded, 200),
        ],
        None,
        true,
        None,
    );
    let mut transport = RecordingAwsGlueTransport::default();
    transport.push_job_runs_response(Ok(response));
    let provider =
        AwsGlueProvider::new(transport, "fixture-0.1", ProviderProvenance::Fixture).unwrap();
    let mut bounded_service = AwsGlueJobResultService::new(
        governed_scope,
        governed_secret,
        provider,
        RetryPolicy::new(1).unwrap(),
    )
    .unwrap();
    let proposal = bounded_service
        .propose(AwsGlueJobResultRequest::get_job_runs(
            JobName::new("transform_job").unwrap(),
            None,
            bounds(1, 4, 2),
            false,
            Revision::new(7).unwrap(),
        ))
        .unwrap();
    assert_eq!(
        proposal.projection,
        ResultProjection::Partial(PartialReason::RunCap)
    );
    assert_eq!(proposal.evidence.runs.len(), 1);
    assert!(proposal.evidence.truncated);
}

#[test]
fn optional_definition_metadata_is_bounded_and_digest_bound() {
    let governed_scope = scope();
    let governed_secret = secret(&governed_scope);
    let provider_request = get_job_run_request(&governed_scope, &governed_secret, "jr-100");
    let response = GetJobRunResponse::new(
        &provider_request,
        run(&governed_scope, GlueJobRunState::Succeeded, 100),
        None,
    );
    let definition_request = GetJobDefinitionRequest::new(
        &governed_scope,
        &governed_secret,
        JobName::new("transform_job").unwrap(),
    );
    let definition = JobDefinitionMetadata::new(
        JobName::new("transform_job").unwrap(),
        Some(Digest::from_text("job-arn")),
        Some(Timestamp::new(10)),
        Some(Timestamp::new(20)),
        Some("4.0".to_owned()),
        Some("G.1X".to_owned()),
        Some(2),
        Some(1_000),
        Some(60),
        Some(1),
    )
    .unwrap();
    let definition_response = GetJobDefinitionResponse::new(&definition_request, definition);
    let mut transport = RecordingAwsGlueTransport::default();
    transport.push_job_run_response(Ok(response));
    transport.push_job_definition_response(Ok(definition_response));
    let provider =
        AwsGlueProvider::new(transport, "fixture-0.1", ProviderProvenance::Fixture).unwrap();
    let mut service = AwsGlueJobResultService::new(
        governed_scope,
        governed_secret,
        provider,
        RetryPolicy::new(1).unwrap(),
    )
    .unwrap();
    let proposal = service
        .propose(AwsGlueJobResultRequest::get_job_run(
            JobName::new("transform_job").unwrap(),
            RunId::new("jr-100").unwrap(),
            Some(AttemptNumber::new(1).unwrap()),
            bounds(8, 8, 4),
            true,
            Revision::new(7).unwrap(),
        ))
        .unwrap();
    assert!(proposal.evidence.job_definition.is_some());
    let serialized = serde_json::to_string(&proposal.evidence.runs).unwrap();
    assert!(!serialized.contains("raw-arguments-are-never-retained"));
    assert!(!serialized.contains("script"));
}

#[test]
fn receipt_verification_and_revocation_are_reversible_but_not_adoption() {
    let mut service = service_with_run(GlueJobRunState::Succeeded, RetryPolicy::new(1).unwrap());
    let proposal = service.propose(get_run_request()).unwrap();
    let receipt = service.record(&proposal).unwrap();
    assert!(!receipt.durable);
    assert!(!receipt.connected);
    assert!(!receipt.native);
    assert!(service.verify(&receipt).unwrap().verified);

    let mut tampered = receipt.clone();
    tampered.status = ResultStatus::Failed;
    assert_eq!(
        service.verify(&tampered).unwrap_err(),
        AwsGlueJobResultServiceError::ProposalTampered
    );

    service.revoke_registration().unwrap();
    assert_eq!(
        service.propose(get_run_request()).unwrap_err(),
        AwsGlueJobResultServiceError::RegistrationRevoked
    );
    service.restore_registration().unwrap();
    service.revoke_secret().unwrap();
    assert_eq!(
        service.propose(get_run_request()).unwrap_err(),
        AwsGlueJobResultServiceError::SecretRevoked
    );
    service.restore_secret().unwrap();
    let mut fresh_service =
        service_with_run(GlueJobRunState::Succeeded, RetryPolicy::new(1).unwrap());
    let proposal = fresh_service.propose(get_run_request()).unwrap();
    let mission_consumer =
        MissionAwsGlueJobConsumer::new(fresh_service.scope().clone(), fresh_service.registration())
            .unwrap();
    let consumed = mission_consumer.consume(proposal).unwrap();
    assert_eq!(consumed.state, MissionResultState::PendingDecision);
    assert!(!consumed.authority.connected());
    assert!(!consumed.authority.native());
    assert!(!consumed.authority.adopted_outcome());
}

#[test]
fn independent_request_status_and_digest_mutations_fail_closed() {
    let mut service = service_with_run(GlueJobRunState::Succeeded, RetryPolicy::new(1).unwrap());
    let proposal = service.propose(get_run_request()).unwrap();

    let mut tampered_status = proposal.clone();
    tampered_status.evidence.status = ResultStatus::Failed;
    assert_eq!(
        tampered_status.validate_integrity().unwrap_err(),
        AwsGlueJobResultServiceError::ProposalTampered
    );

    let mut tampered_digest = proposal.clone();
    tampered_digest.evidence.digests.job_digest = Digest::from_text("tampered-job");
    assert_eq!(
        tampered_digest.validate_integrity().unwrap_err(),
        AwsGlueJobResultServiceError::TamperedEvidence
    );

    let mut tampered_request = proposal.clone();
    tampered_request.request.job_name = JobName::new("other_job").unwrap();
    assert_eq!(
        tampered_request.validate_integrity().unwrap_err(),
        AwsGlueJobResultServiceError::ProposalTampered
    );

    let mut tampered_retry = proposal;
    tampered_retry.evidence.retry_projection.retried = true;
    assert_eq!(
        tampered_retry.validate_integrity().unwrap_err(),
        AwsGlueJobResultServiceError::TamperedEvidence
    );
}

#[test]
fn fixture_recording_loopback_and_blocked_env_never_claim_native_or_connected() {
    let governed_scope = scope();
    let governed_secret = secret(&governed_scope);
    let governed_run = run(&governed_scope, GlueJobRunState::Succeeded, 100);
    let transports: Vec<Box<dyn Debug>> = vec![
        Box::new(RecordingAwsGlueTransport::default()),
        Box::new(LoopbackAwsGlueTransport::new(
            Some(governed_run.clone()),
            vec![governed_run],
            None,
        )),
        Box::new(BlockedEnvAwsGlueTransport),
    ];
    assert_eq!(transports.len(), 3);
    for provenance in [
        ProviderProvenance::Fixture,
        ProviderProvenance::Recording,
        ProviderProvenance::Fake,
        ProviderProvenance::Loopback,
        ProviderProvenance::BlockedEnv,
    ] {
        let provider = AwsGlueProvider::new(
            RecordingAwsGlueTransport::default(),
            "fixture-0.1",
            provenance,
        )
        .unwrap();
        assert!(!provider.definition().native);
        assert!(!provider.definition().connected);
        assert!(!provider.provenance().is_native());
        assert!(!provider.provenance().is_connected());
        assert!(!provider.provenance().is_first_party());
    }
    assert_eq!(governed_scope.account_id().as_str(), "123456789012");
    assert_eq!(governed_secret.kind(), SecretKind::SigV4);
}
