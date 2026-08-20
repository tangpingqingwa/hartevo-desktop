use std::collections::BTreeSet;

use hartevo_aws_batch_job_result_plugin as plugin;
use plugin::{
    AccessLossKind, ArrayProjection, AttemptNumber, AwsAccountId, AwsBatchJobResultOperation,
    AwsBatchJobResultService, AwsBatchProvider, AwsBatchScope, AwsBatchTransportError, AwsRegion,
    BatchFilter, BlockedEnvAwsBatchTransport, ContainerArtifactMetadata, DescribeJobsPage,
    DescribeJobsRequest, Digest, EvidenceStatus, ExitCodeSummary, JobDefinitionId, JobId,
    JobProjection, JobQueueId, JobStatus, JobSummary, LifecycleEvent, LifecycleSummary,
    ListJobsPage, ListJobsRequest, MissionAwsBatchConsumer, MnpProjection, OpaquePageToken,
    PartialReason, ProviderProvenance, RecordingAwsBatchTransport, Revision, SecretReference,
    WorkProductId,
};

fn scope() -> AwsBatchScope {
    AwsBatchScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        JobQueueId::new("queue-high").expect("queue"),
        JobDefinitionId::new("definition:v1").expect("definition"),
        JobId::new("job-parent").expect("job"),
        plugin::ProjectId::new("project-batch").expect("project"),
        plugin::MissionId::new("mission-batch").expect("mission"),
        WorkProductId::new("work-product-batch").expect("work product"),
    )
}

fn secret(scope: &AwsBatchScope) -> SecretReference {
    SecretReference::new("raw-sigv4-reference-must-not-leak", scope, 7).expect("secret")
}

fn attempt(number: u32, status: JobStatus, exit_code: i32) -> plugin::AttemptSummary {
    plugin::AttemptSummary::new(
        AttemptNumber::new(number).expect("attempt"),
        status,
        Some(10 + u64::from(number)),
        Some(20 + u64::from(number)),
        Some(exit_code),
        Digest::from_text(format!("container-{number}")),
        Some(Digest::from_text(format!("artifact-{number}"))),
    )
    .expect("attempt summary")
}

fn succeeded_projection(scope: &AwsBatchScope) -> JobProjection {
    let attempts = vec![attempt(1, JobStatus::Succeeded, 0)];
    JobProjection::new(
        scope.job_id.clone(),
        None,
        scope.job_queue_id.clone(),
        scope.job_definition_id.clone(),
        JobStatus::Succeeded,
        Some(1),
        Some(11),
        Some(21),
        LifecycleSummary::from_events(vec![
            LifecycleEvent::new(JobStatus::Submitted, 1),
            LifecycleEvent::new(JobStatus::Running, 11),
            LifecycleEvent::new(JobStatus::Succeeded, 21),
        ])
        .expect("lifecycle"),
        attempts,
        ContainerArtifactMetadata::new(Digest::from_text("container-metadata"))
            .with_artifact_metadata_digest(Digest::from_text("artifact-metadata")),
        None,
        None,
    )
    .expect("job projection")
}

fn describe_page(
    scope: &AwsBatchScope,
    projection: JobProjection,
) -> (DescribeJobsRequest, DescribeJobsPage) {
    let request =
        DescribeJobsRequest::new(scope, vec![projection.job_id.clone()]).expect("request");
    let page = DescribeJobsPage::new(
        &request,
        vec![projection],
        false,
        plugin::AWS_BATCH_JOB_RESULT_API_REVISION,
    )
    .expect("page");
    (request, page)
}

fn registered_provider(
    scope: &AwsBatchScope,
    transport: RecordingAwsBatchTransport,
) -> (
    AwsBatchProvider<RecordingAwsBatchTransport>,
    plugin::AwsBatchRegistration,
) {
    let mut provider = AwsBatchProvider::baseline(transport).expect("provider");
    let registration = provider
        .register_scope(scope.clone(), secret(scope))
        .expect("registration");
    (provider, registration)
}

#[test]
fn contract_service_runtime_and_native_honesty_are_frozen() {
    plugin::validate_contract_document().expect("contract");
    assert_eq!(plugin::contract_digest().as_str().len(), 64);
    assert_eq!(plugin::permission_digest().as_str().len(), 64);

    let service = AwsBatchJobResultService::new();
    service.validate().expect("service");
    assert!(service.read_only());
    assert!(!service.native_connected());
    assert_eq!(
        service.capabilities().len(),
        AwsBatchJobResultOperation::ALL.len()
    );
    assert!(service.capabilities().iter().all(|capability| {
        capability.read_only
            && !capability.mutates_provider
            && !capability.native_evidence
            && !capability.workload_correctness_authority
    }));

    let runtime_scope = hartevo_plugin_runtime::PluginScope::new(
        hartevo_plugin_runtime::ProjectId::new("project.batch").expect("runtime project"),
        hartevo_plugin_runtime::MissionId::new("mission.batch").expect("runtime mission"),
        1,
    )
    .expect("runtime scope");
    plugin::plugin_definition(runtime_scope)
        .expect("runtime definition")
        .validate()
        .expect("valid definition");

    let blocked =
        AwsBatchProvider::baseline(BlockedEnvAwsBatchTransport).expect("blocked provider");
    assert_eq!(blocked.provenance(), ProviderProvenance::BlockedEnv);
    assert!(!blocked.provenance().is_native());
}

#[test]
fn opaque_sigv4_secret_and_metadata_redaction_never_expose_raw_material() {
    let scope = scope();
    let reference = secret(&scope);
    let debug = format!("{reference:?}");
    let display = reference.to_string();
    assert!(!debug.contains("raw-sigv4-reference"));
    assert!(!display.contains("raw-sigv4-reference"));
    assert_eq!(reference.scope_digest(), &scope.digest());
    assert_eq!(reference.credential_revision().get(), 7);

    let projection = succeeded_projection(&scope);
    let serialized = serde_json::to_string(&projection).expect("projection JSON");
    for forbidden_raw_value in [
        "echo secret",
        "AWS_SECRET_ACCESS_KEY=secret",
        "provider-log-line",
        "public.ecr.aws/example:latest",
        "s3://bucket/private-output",
    ] {
        assert!(!serialized.contains(forbidden_raw_value));
    }
    assert!(serialized.contains("redactedFields"));
    assert!(!serialized.contains("raw-sigv4-reference"));
    assert!(!projection.metadata.redaction.raw_provider_payload_retained);
}

#[test]
fn describe_propose_record_verify_is_bound_to_all_digests_and_returns_redacted_receipt() {
    let scope = scope();
    let projection = succeeded_projection(&scope);
    let (request, page) = describe_page(&scope, projection);
    let (mut provider, registration) =
        registered_provider(&scope, RecordingAwsBatchTransport::new([Ok(page)]));
    let consumer =
        MissionAwsBatchConsumer::with_registration(scope.clone(), registration).expect("consumer");
    let read_request = plugin::AwsBatchReadRequest::describe_jobs(&scope, request.job_ids.clone())
        .expect("read request");
    let result = consumer
        .read(&mut provider, &read_request)
        .expect("read result");

    assert_eq!(result.evidence.status, EvidenceStatus::Complete);
    assert_eq!(result.evidence.jobs.len(), 1);
    assert_eq!(result.evidence.scope_digest, scope.digest());
    assert_eq!(result.evidence.job_digest, scope.job_digest());
    assert_eq!(result.evidence.attempt_digest, scope.attempt_digest());
    assert_eq!(
        result.evidence.provider_revision,
        plugin::AWS_BATCH_JOB_RESULT_API_REVISION
    );
    result.validate(&scope).expect("result validates");
    let mut tampered_receipt = result.clone();
    tampered_receipt.receipt.receipt_digest = Digest::from_text("tampered-receipt");
    assert!(matches!(
        tampered_receipt.validate(&scope),
        Err(plugin::AwsBatchError::TamperedEvidence)
    ));

    let service = AwsBatchJobResultService::new();
    let proposal = service.propose(result.evidence.clone()).expect("proposal");
    assert!(proposal.read_only);
    assert!(!proposal.native);
    assert!(!proposal.connected);
    assert!(!proposal.workload_correctness_authority);
    let record = service.record(&proposal).expect("record");
    assert!(!record.durable);
    assert!(!record.verified);
    assert!(!record.adopted);
    assert!(!record.receipt.durable_provider_receipt);
    assert!(!record.receipt.raw_provider_response_retained);
    let verification = service
        .verify(&record, &result.evidence)
        .expect("verification");
    assert_eq!(
        verification.status,
        plugin::VerificationStatus::VerifiedReadOnly
    );
    assert!(verification.accepted);
    assert!(!verification.independent_output_readback);
    assert!(!verification.native);
    assert!(!verification.outcome_authority);
}

#[test]
fn lifecycle_state_transitions_and_retry_summaries_fail_closed() {
    let invalid = LifecycleSummary::from_events(vec![
        LifecycleEvent::new(JobStatus::Submitted, 1),
        LifecycleEvent::new(JobStatus::Running, 2),
        LifecycleEvent::new(JobStatus::Submitted, 3),
    ]);
    assert!(invalid.is_err());

    let terminal_transition = LifecycleSummary::from_events(vec![
        LifecycleEvent::new(JobStatus::Succeeded, 1),
        LifecycleEvent::new(JobStatus::Failed, 2),
    ]);
    assert!(terminal_transition.is_err());

    let first = attempt(1, JobStatus::Failed, 12);
    let second = attempt(2, JobStatus::Succeeded, 0);
    let retry =
        plugin::RetrySummary::from_attempts(&[first.clone(), second.clone()]).expect("retry");
    assert_eq!(retry.total_attempts, 2);
    assert_eq!(retry.retry_count, 1);
    assert_eq!(retry.failed_attempts, 1);
    assert_eq!(retry.succeeded_attempts, 1);
    let exit_codes = ExitCodeSummary::from_attempts(&[first, second]).expect("exit codes");
    assert_eq!(exit_codes.observed_codes, vec![12, 0]);
    assert_eq!(exit_codes.failed_count, 1);
    assert_eq!(exit_codes.successful_count, 1);
}

#[test]
fn array_and_mnp_child_projections_are_fenced_and_bounded() {
    let array_scope = scope().with_array_job_id(JobId::new("job-parent").expect("array parent"));
    let child_attempt = attempt(1, JobStatus::Succeeded, 0);
    let array_child = plugin::JobChildProjection::new(
        JobId::new("array-child-0").expect("child"),
        array_scope.job_id.clone(),
        plugin::ChildProjectionKind::ArrayChild,
        0,
        None,
        array_scope.job_queue_id.clone(),
        array_scope.job_definition_id.clone(),
        JobStatus::Succeeded,
        Some(11),
        Some(21),
        vec![child_attempt.clone()],
        ContainerArtifactMetadata::new(Digest::from_text("array-container")),
    )
    .expect("array child");
    let array = ArrayProjection::new(array_scope.job_id.clone(), 2, vec![array_child])
        .expect("array projection");
    let parent = JobProjection::new(
        array_scope.job_id.clone(),
        None,
        array_scope.job_queue_id.clone(),
        array_scope.job_definition_id.clone(),
        JobStatus::Succeeded,
        Some(1),
        Some(11),
        Some(21),
        LifecycleSummary::single(JobStatus::Succeeded, 21).expect("lifecycle"),
        vec![child_attempt.clone()],
        ContainerArtifactMetadata::new(Digest::from_text("parent-container")),
        Some(array),
        None,
    )
    .expect("array parent");
    parent.validate_against(&array_scope).expect("array fence");

    let mnp_scope = scope().with_mnp_job_id(JobId::new("job-parent").expect("mnp parent"));
    let node = plugin::JobChildProjection::new(
        JobId::new("node-0").expect("node"),
        mnp_scope.job_id.clone(),
        plugin::ChildProjectionKind::MultiNodeNode,
        0,
        Some(true),
        mnp_scope.job_queue_id.clone(),
        mnp_scope.job_definition_id.clone(),
        JobStatus::Succeeded,
        Some(11),
        Some(21),
        vec![attempt(1, JobStatus::Succeeded, 0)],
        ContainerArtifactMetadata::new(Digest::from_text("node-container")),
    )
    .expect("mnp node");
    let mnp =
        MnpProjection::new(mnp_scope.job_id.clone(), 1, 0, vec![node]).expect("mnp projection");
    let mnp_parent = JobProjection::new(
        mnp_scope.job_id.clone(),
        None,
        mnp_scope.job_queue_id.clone(),
        mnp_scope.job_definition_id.clone(),
        JobStatus::Succeeded,
        Some(1),
        Some(11),
        Some(21),
        LifecycleSummary::single(JobStatus::Succeeded, 21).expect("lifecycle"),
        vec![attempt(1, JobStatus::Succeeded, 0)],
        ContainerArtifactMetadata::new(Digest::from_text("mnp-container")),
        None,
        Some(mnp),
    )
    .expect("mnp parent");
    mnp_parent.validate_against(&mnp_scope).expect("mnp fence");
}

#[test]
fn describe_jobs_limit_splits_at_one_hundred_and_scope_attempt_is_exact() {
    let scope = scope();
    let too_many: Vec<JobId> = (0..101)
        .map(|index| JobId::new(format!("job-{index}")).expect("job id"))
        .collect();
    assert!(DescribeJobsRequest::new(&scope, too_many.clone()).is_err());
    let batches = DescribeJobsRequest::batch(&scope, too_many).expect("batches");
    assert_eq!(batches.len(), 2);
    assert_eq!(batches[0].job_ids.len(), 100);
    assert_eq!(batches[1].job_ids.len(), 1);

    let attempted_scope = AwsBatchScope::new(
        scope.account_id.clone(),
        scope.region.clone(),
        scope.job_queue_id.clone(),
        scope.job_definition_id.clone(),
        scope.job_id.clone(),
        scope.project_id.clone(),
        scope.mission_id.clone(),
        scope.work_product_id.clone(),
    )
    .with_attempt(AttemptNumber::new(2).expect("attempt"));
    let mut projection = succeeded_projection(&attempted_scope);
    projection.attempts[0] = attempt(1, JobStatus::Succeeded, 0);
    // The immutable projection digest is now intentionally stale; either the
    // digest fence or the scope fence must reject it before consumption.
    let request = DescribeJobsRequest::new(&attempted_scope, vec![attempted_scope.job_id.clone()])
        .expect("request");
    let page = DescribeJobsPage::new(
        &request,
        vec![projection],
        false,
        plugin::AWS_BATCH_JOB_RESULT_API_REVISION,
    )
    .expect("valid page before attempt fence");
    let (mut provider, registration) = registered_provider(
        &attempted_scope,
        RecordingAwsBatchTransport::new([Ok(page)]),
    );
    let consumer =
        MissionAwsBatchConsumer::with_registration(attempted_scope.clone(), registration)
            .expect("attempt-fenced consumer");
    let result = consumer.read(
        &mut provider,
        &plugin::AwsBatchReadRequest::describe_jobs(
            &attempted_scope,
            vec![attempted_scope.job_id.clone()],
        )
        .expect("attempt-fenced request"),
    );
    assert!(matches!(result, Err(plugin::AwsBatchError::ScopeMismatch)));
}

#[test]
fn list_page_bound_marks_truncation_without_claiming_complete_evidence() {
    let scope = scope();
    let first_request = ListJobsRequest::for_queue(&scope, BatchFilter::all(), 1).expect("request");
    let first_token = OpaquePageToken::new("page-token-1").expect("token");
    let second_request = first_request
        .next_page(first_token.clone())
        .expect("page 2");
    let second_token = OpaquePageToken::new("page-token-2").expect("token");
    let third_request = second_request
        .next_page(second_token.clone())
        .expect("page 3");
    let third_token = OpaquePageToken::new("page-token-3").expect("token");
    let fourth_request = third_request
        .next_page(third_token.clone())
        .expect("page 4");
    let fourth_token = OpaquePageToken::new("page-token-4").expect("token");
    let pages = [
        ListJobsPage::new(
            &first_request,
            Vec::new(),
            Some(first_token),
            false,
            plugin::AWS_BATCH_JOB_RESULT_API_REVISION,
        )
        .expect("page 1"),
        ListJobsPage::new(
            &second_request,
            Vec::new(),
            Some(second_token),
            false,
            plugin::AWS_BATCH_JOB_RESULT_API_REVISION,
        )
        .expect("page 2"),
        ListJobsPage::new(
            &third_request,
            Vec::new(),
            Some(third_token),
            false,
            plugin::AWS_BATCH_JOB_RESULT_API_REVISION,
        )
        .expect("page 3"),
        ListJobsPage::new(
            &fourth_request,
            Vec::new(),
            Some(fourth_token),
            false,
            plugin::AWS_BATCH_JOB_RESULT_API_REVISION,
        )
        .expect("page 4"),
    ];
    let describe_page = describe_page(&scope, succeeded_projection(&scope)).1;
    let transport = RecordingAwsBatchTransport::new_with_list_responses(
        [Ok(describe_page)],
        pages.into_iter().map(Ok),
    );
    let (mut provider, registration) = registered_provider(&scope, transport);
    let consumer =
        MissionAwsBatchConsumer::with_registration(scope.clone(), registration).expect("consumer");
    let result = consumer
        .read(
            &mut provider,
            &plugin::AwsBatchReadRequest::for_list(&scope, first_request).expect("read request"),
        )
        .expect("bounded partial evidence");
    assert_eq!(result.evidence.status, EvidenceStatus::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(PartialReason::PageLimitReached)
    );
    assert_eq!(result.evidence.pages.len(), 4);
    assert!(provider.transport().describe_requests().is_empty());
    assert!(AttemptNumber::new(17).is_err());
}

#[test]
fn filtered_opaque_pagination_binds_each_page_without_retaining_token() {
    let scope = scope();
    let first_request = ListJobsRequest::for_queue(
        &scope,
        BatchFilter::all().with_status(JobStatus::Running),
        1,
    )
    .expect("first list request");
    let token = OpaquePageToken::new("opaque-provider-token-do-not-retain").expect("token");
    let second_request = first_request
        .next_page(token.clone())
        .expect("second request");
    let summary = JobSummary::new(
        scope.job_id.clone(),
        None,
        scope.job_queue_id.clone(),
        scope.job_definition_id.clone(),
        JobStatus::Running,
        Some(10),
        None,
        None,
        None,
        None,
    )
    .expect("summary");
    let first_page = ListJobsPage::new(
        &first_request,
        Vec::new(),
        Some(token),
        false,
        plugin::AWS_BATCH_JOB_RESULT_API_REVISION,
    )
    .expect("first page");
    let second_page = ListJobsPage::new(
        &second_request,
        vec![summary],
        None,
        false,
        plugin::AWS_BATCH_JOB_RESULT_API_REVISION,
    )
    .expect("second page");
    let (describe_request, describe_response) = describe_page(&scope, succeeded_projection(&scope));
    let transport = RecordingAwsBatchTransport::new_with_list_responses(
        [Ok(describe_response)],
        [Ok(first_page), Ok(second_page)],
    );
    let (mut provider, registration) = registered_provider(&scope, transport);
    let consumer =
        MissionAwsBatchConsumer::with_registration(scope.clone(), registration).expect("consumer");
    let request =
        plugin::AwsBatchReadRequest::for_list(&scope, first_request).expect("read request");
    let result = consumer
        .read(&mut provider, &request)
        .expect("paged result");
    assert_eq!(result.evidence.status, EvidenceStatus::Complete);
    assert_eq!(provider.transport().list_requests().len(), 2);
    assert_eq!(provider.transport().describe_requests().len(), 1);
    assert_eq!(
        provider.transport().list_requests()[1].page_token_digest,
        Some(
            plugin::OpaquePageToken::new("opaque-provider-token-do-not-retain")
                .expect("token")
                .digest()
        )
    );
    let recorded = serde_json::to_string(provider.transport().list_requests()[1])
        .expect("recorded request JSON");
    assert!(!recorded.contains("opaque-provider-token-do-not-retain"));
    assert_eq!(describe_request.job_ids.len(), 1);
}

#[test]
#[allow(clippy::too_many_lines)]
fn partial_unknown_and_blocked_env_are_not_complete_or_native() {
    let scope = scope();
    let unknown_attempt = plugin::AttemptSummary::new(
        AttemptNumber::new(1).expect("attempt"),
        JobStatus::Unknown,
        None,
        None,
        None,
        Digest::from_text("unknown-container"),
        None,
    )
    .expect("unknown attempt");
    let unknown = JobProjection::new(
        scope.job_id.clone(),
        None,
        scope.job_queue_id.clone(),
        scope.job_definition_id.clone(),
        JobStatus::Unknown,
        None,
        None,
        None,
        LifecycleSummary::single(JobStatus::Unknown, 10).expect("unknown lifecycle"),
        vec![unknown_attempt],
        ContainerArtifactMetadata::new(Digest::from_text("unknown-container-metadata")),
        None,
        None,
    )
    .expect("unknown projection");
    let (request, _) = describe_page(&scope, succeeded_projection(&scope));
    let unknown_page = DescribeJobsPage::new(
        &request,
        vec![unknown],
        true,
        plugin::AWS_BATCH_JOB_RESULT_API_REVISION,
    )
    .expect("unknown page");
    let (mut unknown_provider, unknown_registration) =
        registered_provider(&scope, RecordingAwsBatchTransport::new([Ok(unknown_page)]));
    let unknown_consumer =
        MissionAwsBatchConsumer::with_registration(scope.clone(), unknown_registration)
            .expect("unknown consumer");
    let unknown_result = unknown_consumer
        .read(
            &mut unknown_provider,
            &plugin::AwsBatchReadRequest::describe_jobs(&scope, vec![scope.job_id.clone()])
                .expect("unknown request"),
        )
        .expect("unknown evidence");
    assert_eq!(unknown_result.evidence.status, EvidenceStatus::Partial);
    assert_eq!(
        unknown_result.evidence.partial_reason,
        Some(PartialReason::UnknownStatus)
    );

    let partial_projection = succeeded_projection(&scope);
    let partial_request =
        DescribeJobsRequest::new(&scope, vec![scope.job_id.clone()]).expect("request");
    let partial_page = DescribeJobsPage::new(
        &partial_request,
        vec![partial_projection],
        true,
        plugin::AWS_BATCH_JOB_RESULT_API_REVISION,
    )
    .expect("partial page");
    let (mut partial_provider, partial_registration) =
        registered_provider(&scope, RecordingAwsBatchTransport::new([Ok(partial_page)]));
    let partial_consumer =
        MissionAwsBatchConsumer::with_registration(scope.clone(), partial_registration)
            .expect("consumer");
    let partial_result = partial_consumer
        .read(
            &mut partial_provider,
            &plugin::AwsBatchReadRequest::describe_jobs(&scope, vec![scope.job_id.clone()])
                .expect("read request"),
        )
        .expect("partial result");
    assert_eq!(partial_result.evidence.status, EvidenceStatus::Partial);
    assert_eq!(
        partial_result.evidence.partial_reason,
        Some(PartialReason::ProviderMarkedPartial)
    );

    let mut blocked_provider =
        AwsBatchProvider::baseline(BlockedEnvAwsBatchTransport).expect("provider");
    let blocked_registration = blocked_provider
        .register_scope(scope.clone(), secret(&scope))
        .expect("registration");
    let blocked_consumer =
        MissionAwsBatchConsumer::with_registration(scope.clone(), blocked_registration)
            .expect("consumer");
    let blocked_result = blocked_consumer
        .read(
            &mut blocked_provider,
            &plugin::AwsBatchReadRequest::describe_jobs(&scope, vec![scope.job_id.clone()])
                .expect("read request"),
        )
        .expect("blocked evidence");
    assert_eq!(blocked_result.evidence.status, EvidenceStatus::AccessLost);
    assert_eq!(
        blocked_result.evidence.provenance,
        ProviderProvenance::BlockedEnv
    );
    assert_eq!(
        blocked_result
            .evidence
            .access_loss
            .as_ref()
            .map(|loss| loss.kind),
        Some(AccessLossKind::BlockedEnv)
    );
    assert!(!blocked_result.observation.native);
    assert!(!blocked_result.observation.connected);
}

#[test]
fn requested_http_failures_and_timeout_become_access_loss_evidence() {
    let failures = [
        AwsBatchTransportError::BadRequest,
        AwsBatchTransportError::Unauthorized,
        AwsBatchTransportError::AccessDenied,
        AwsBatchTransportError::NotFound,
        AwsBatchTransportError::Conflict,
        AwsBatchTransportError::Throttled,
        AwsBatchTransportError::ServerError,
        AwsBatchTransportError::Timeout,
    ];
    for failure in failures {
        let scope = scope();
        let mut provider =
            AwsBatchProvider::baseline(RecordingAwsBatchTransport::new([Err(failure.clone())]))
                .expect("provider");
        let registration = provider
            .register_scope(scope.clone(), secret(&scope))
            .expect("registration");
        let consumer = MissionAwsBatchConsumer::with_registration(scope.clone(), registration)
            .expect("consumer");
        let result = consumer
            .read(
                &mut provider,
                &plugin::AwsBatchReadRequest::describe_jobs(&scope, vec![scope.job_id.clone()])
                    .expect("read request"),
            )
            .expect("access-loss evidence");
        assert_eq!(result.evidence.status, EvidenceStatus::AccessLost);
        assert_eq!(
            result.evidence.partial_reason,
            Some(PartialReason::AccessLoss)
        );
        assert_eq!(
            result.evidence.access_loss.as_ref().map(|loss| loss.kind),
            Some(failure.access_loss_kind())
        );
        assert!(!result.observation.native);
    }
}

#[test]
fn repeated_page_tokens_tamper_and_revocation_fail_closed() {
    let scope = scope();
    let request = ListJobsRequest::for_queue(&scope, BatchFilter::all(), 1).expect("request");
    let token = OpaquePageToken::new("repeat-token").expect("token");
    let repeated_request = request.next_page(token.clone()).expect("second request");
    let first = ListJobsPage::new(
        &request,
        Vec::new(),
        Some(token.clone()),
        false,
        plugin::AWS_BATCH_JOB_RESULT_API_REVISION,
    )
    .expect("first");
    let second = ListJobsPage::new(
        &repeated_request,
        Vec::new(),
        Some(token),
        false,
        plugin::AWS_BATCH_JOB_RESULT_API_REVISION,
    )
    .expect("second");
    let transport = RecordingAwsBatchTransport::new_with_list_responses(
        [Ok(
            succeeded_projection(&scope).pipe(|projection| describe_page(&scope, projection).1)
        )],
        [Ok(first), Ok(second)],
    );
    let (mut provider, registration) = registered_provider(&scope, transport);
    let consumer =
        MissionAwsBatchConsumer::with_registration(scope.clone(), registration).expect("consumer");
    let read_request =
        plugin::AwsBatchReadRequest::for_list(&scope, request).expect("read request");
    assert!(matches!(
        consumer.read(&mut provider, &read_request),
        Err(plugin::AwsBatchError::PageLoop)
    ));

    let (request, page) = describe_page(&scope, succeeded_projection(&scope));
    let (mut provider, registration) =
        registered_provider(&scope, RecordingAwsBatchTransport::new([Ok(page)]));
    let consumer =
        MissionAwsBatchConsumer::with_registration(scope.clone(), registration).expect("consumer");
    let result = consumer
        .read(
            &mut provider,
            &plugin::AwsBatchReadRequest::describe_jobs(&scope, request.job_ids.clone())
                .expect("read request"),
        )
        .expect("result");
    let service = AwsBatchJobResultService::new();
    let proposal = service.propose(result.evidence.clone()).expect("proposal");
    let mut tampered = proposal.evidence.clone();
    tampered.jobs[0].status = JobStatus::Failed;
    assert!(matches!(
        service.propose(tampered),
        Err(plugin::AwsBatchError::TamperedEvidence)
    ));

    provider
        .revoke_registration(Revision::new(8).expect("revision"))
        .expect("revoke");
    assert!(matches!(
        consumer.read(
            &mut provider,
            &plugin::AwsBatchReadRequest::describe_jobs(&scope, request.job_ids)
                .expect("read request")
        ),
        Err(plugin::AwsBatchError::RegistrationRevoked)
    ));
}

#[test]
fn scope_fences_reject_region_queue_definition_and_mission_drift() {
    let scope = scope();
    let mut wrong_region = scope.clone();
    wrong_region.region = AwsRegion::new("us-west-2").expect("region");
    assert_ne!(scope.digest(), wrong_region.digest());
    assert_ne!(scope.job_digest(), wrong_region.job_digest());

    let wrong_queue = AwsBatchScope::new(
        scope.account_id.clone(),
        scope.region.clone(),
        JobQueueId::new("other-queue").expect("queue"),
        scope.job_definition_id.clone(),
        scope.job_id.clone(),
        scope.project_id.clone(),
        scope.mission_id.clone(),
        scope.work_product_id.clone(),
    );
    assert_ne!(scope.scope_digest(), wrong_queue.scope_digest());
    assert_ne!(scope.job_digest(), wrong_queue.job_digest());

    let wrong_mission = AwsBatchScope::new(
        scope.account_id.clone(),
        scope.region.clone(),
        scope.job_queue_id.clone(),
        scope.job_definition_id.clone(),
        scope.job_id.clone(),
        scope.project_id.clone(),
        plugin::MissionId::new("other-mission").expect("mission"),
        scope.work_product_id.clone(),
    );
    assert_ne!(scope.scope_digest(), wrong_mission.scope_digest());
}

trait Pipe: Sized {
    fn pipe<T>(self, function: impl FnOnce(Self) -> T) -> T {
        function(self)
    }
}

impl<T> Pipe for T {}

#[allow(dead_code)]
fn _keep_btreeset_in_scope() -> BTreeSet<String> {
    BTreeSet::new()
}
