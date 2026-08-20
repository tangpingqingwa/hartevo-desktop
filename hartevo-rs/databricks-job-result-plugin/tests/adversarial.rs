use std::collections::VecDeque;

use hartevo_databricks_job_result_plugin::{
    AdoptionDisposition, CONTRACT_DIGEST, DatabricksError, DatabricksJobResultService,
    DatabricksJobsProvider, DatabricksJobsTransport, DatabricksProviderError, DatabricksScope,
    EvidenceStatus, JOBS_API_REVISION, JobSnapshot, MAX_OUTPUT_BYTES, MissionDatabricksJobConsumer,
    OAuthCapabilitySnapshot, OutputAccess, OutputDisposition, OutputEvidence, RecordingTransport,
    RepairRecord, RetryPolicy, RunAttempt, RunLifecycleState, RunParameter, RunProposalInput,
    RunReadRequest, RunResultState, RunTrigger, SecretReference, SourceIdentity, TaskAttempt,
    TaskSnapshot, TaskType, TransportProvenance, VerificationReason, VerificationVerdict,
};

fn digest(value: &str) -> String {
    hartevo_databricks_job_result_plugin::digest_text(value)
}

fn make_scope(task_keys: impl IntoIterator<Item = String>, run_id: u64) -> DatabricksScope {
    DatabricksScope::new(
        "acct-1",
        "https://dbc.example.test",
        "ws-1",
        42,
        7,
        task_keys,
        "mission-1",
        "project-1",
        "work-product-1",
        3,
        4,
    )
    .expect("scope")
    .with_run_ids([run_id])
    .expect("run scope")
    .with_cluster_id(Some("cluster-1".to_owned()))
    .expect("cluster scope")
}

fn oauth() -> OAuthCapabilitySnapshot {
    OAuthCapabilitySnapshot::new(
        [
            "jobs.read".to_owned(),
            "runs.read".to_owned(),
            "run-output.read".to_owned(),
        ],
        &digest("service-principal"),
        1,
    )
    .expect("oauth")
}

fn secret(scope: &DatabricksScope) -> SecretReference {
    SecretReference::oauth_m2m("client-secret-reference", &scope.digest(), 1).expect("secret")
}

fn task_snapshot(task_key: &str) -> TaskSnapshot {
    TaskSnapshot::new(
        task_key,
        Vec::new(),
        TaskType::Notebook,
        Some("cluster-1".to_owned()),
        None,
        &digest(&format!("task:{task_key}")),
    )
    .expect("task")
}

fn job(task_keys: &[String]) -> JobSnapshot {
    JobSnapshot::new(
        42,
        7,
        &digest("job-settings"),
        task_keys.iter().map(|key| task_snapshot(key)).collect(),
        Some("cluster-1".to_owned()),
        None,
        100,
    )
    .expect("job")
}

fn run_attempt(lifecycle_state: RunLifecycleState, result_state: RunResultState) -> RunAttempt {
    RunAttempt::new(
        42,
        7,
        9001,
        9001,
        0,
        lifecycle_state,
        result_state,
        Some(100),
        Some(200),
        Some(100),
        RunTrigger::Manual,
        Some(digest("recorded-source")),
    )
    .expect("run")
}

fn task_attempt(task_key: &str, task_run_id: u64, result: RunResultState) -> TaskAttempt {
    TaskAttempt::new(
        task_key,
        task_run_id,
        0,
        task_run_id,
        RunLifecycleState::Terminated,
        result,
        Some(100),
        Some(200),
        Some(100),
        None,
    )
    .expect("task attempt")
}

fn make_service(
    scope: DatabricksScope,
    transport: RecordingTransport,
) -> DatabricksJobResultService<RecordingTransport> {
    let provider = DatabricksJobsProvider::new(transport);
    let secret_reference = secret(&scope);
    DatabricksJobResultService::register(
        provider,
        "0.1.0",
        "adapter-1",
        oauth(),
        scope,
        secret_reference,
    )
    .expect("service")
}

fn proposal_and_evidence(
    service: &mut DatabricksJobResultService<RecordingTransport>,
    job: &JobSnapshot,
    task_keys: Vec<String>,
) -> (
    hartevo_databricks_job_result_plugin::RunProposal,
    hartevo_databricks_job_result_plugin::RunEvidence,
) {
    let source = SourceIdentity::new(
        Some(digest("source")),
        Some(digest("commit")),
        Some(digest("artifact")),
    )
    .expect("source");
    let input = RunProposalInput::new(
        task_keys,
        vec![RunParameter::public("environment", "prod").expect("parameter")],
        source,
        100,
    )
    .expect("input");
    let proposal = service.compile_run_proposal(job, input).expect("proposal");
    let request = RunReadRequest::new(9001, 300, 1_000).expect("read request");
    let evidence = service.read_run_evidence(&request).expect("evidence");
    (proposal, evidence)
}

#[test]
fn pagination_merges_more_than_one_hundred_tasks_and_binds_idempotency() {
    let task_keys = (0..101)
        .map(|index| format!("task-{index:03}"))
        .collect::<Vec<_>>();
    let scope = make_scope(task_keys.clone(), 9001);
    let job = job(&task_keys);
    let first_tasks = task_keys[..100]
        .iter()
        .enumerate()
        .map(|(index, key)| task_attempt(key, 10_000 + index as u64, RunResultState::Success))
        .collect::<Vec<_>>();
    let second_tasks = vec![task_attempt(
        &task_keys[100],
        10_100,
        RunResultState::Success,
    )];
    let first = hartevo_databricks_job_result_plugin::RunPage::new(
        run_attempt(RunLifecycleState::Running, RunResultState::NotAvailable),
        first_tasks,
        Vec::new(),
        Some("opaque-page-2".to_owned()),
    )
    .expect("first page");
    let second = hartevo_databricks_job_result_plugin::RunPage::new(
        run_attempt(RunLifecycleState::Running, RunResultState::NotAvailable),
        second_tasks,
        Vec::new(),
        None,
    )
    .expect("second page")
    .for_page_token(Some("opaque-page-2".to_owned()))
    .expect("second token");
    let transport = RecordingTransport::new()
        .with_job(job.clone())
        .with_page(first)
        .with_page(second);
    let mut service = make_service(scope, transport);
    let (proposal, evidence) = proposal_and_evidence(&mut service, &job, task_keys);

    assert_eq!(evidence.page_count, 2);
    assert_eq!(evidence.tasks.len(), 101);
    assert!(proposal.provider_idempotency_token.len() <= 64);
    assert!(proposal.provider_idempotency_token.starts_with("dbx2-"));
    assert_eq!(
        proposal.provider_idempotency_token,
        proposal.expected_idempotency_token()
    );
    assert!(proposal.verify_digest());
    assert_eq!(service.provider().transport().page_calls(), 2);
    assert_eq!(evidence.provenance, TransportProvenance::Recording);
    assert_eq!(evidence.evidence_status, EvidenceStatus::Recorded);
}

#[test]
fn repeated_and_missing_pages_fail_closed() {
    let task_keys = vec!["task-001".to_owned()];
    let scope = make_scope(task_keys.clone(), 9001);
    let job = job(&task_keys);
    let page = hartevo_databricks_job_result_plugin::RunPage::new(
        run_attempt(RunLifecycleState::Running, RunResultState::NotAvailable),
        vec![task_attempt(
            "task-001",
            10_001,
            RunResultState::NotAvailable,
        )],
        Vec::new(),
        Some("repeat".to_owned()),
    )
    .expect("page");
    let repeat = hartevo_databricks_job_result_plugin::RunPage::new(
        run_attempt(RunLifecycleState::Running, RunResultState::NotAvailable),
        Vec::new(),
        Vec::new(),
        Some("repeat".to_owned()),
    )
    .expect("repeat page")
    .for_page_token(Some("repeat".to_owned()))
    .expect("repeat page");
    let transport = RecordingTransport::new()
        .with_job(job.clone())
        .with_page(page)
        .with_page(repeat);
    let mut service = make_service(scope, transport);
    let err = service
        .read_run_evidence(&RunReadRequest::new(9001, 300, 1_000).expect("request"))
        .expect_err("repeated token");
    assert_eq!(
        err,
        DatabricksError::Provider(DatabricksProviderError::RepeatedPageToken)
    );

    let scope = make_scope(task_keys.clone(), 9001);
    let missing_page_transport = RecordingTransport::new().with_job(job);
    let mut missing_service = make_service(scope, missing_page_transport);
    let err = missing_service
        .read_run_evidence(&RunReadRequest::new(9001, 300, 1_000).expect("request"))
        .expect_err("missing page");
    assert_eq!(
        err,
        DatabricksError::Provider(DatabricksProviderError::NotFound)
    );
}

#[test]
fn out_of_scope_job_page_and_duplicate_attempt_are_rejected() {
    let task_keys = vec!["task-001".to_owned()];
    let scope = make_scope(task_keys.clone(), 9001);
    let job = job(&task_keys);
    let mut wrong_run = run_attempt(RunLifecycleState::Running, RunResultState::NotAvailable);
    wrong_run.job_id = 999;
    let page = hartevo_databricks_job_result_plugin::RunPage::new(
        wrong_run,
        vec![task_attempt(
            "task-001",
            10_001,
            RunResultState::NotAvailable,
        )],
        Vec::new(),
        None,
    )
    .expect("page");
    let mut service = make_service(
        scope.clone(),
        RecordingTransport::new()
            .with_job(job.clone())
            .with_page(page),
    );
    let err = service
        .read_run_evidence(&RunReadRequest::new(9001, 300, 1_000).expect("request"))
        .expect_err("out-of-scope run");
    assert_eq!(
        err,
        DatabricksError::Provider(DatabricksProviderError::OutOfScope)
    );

    let page_one = hartevo_databricks_job_result_plugin::RunPage::new(
        run_attempt(RunLifecycleState::Running, RunResultState::NotAvailable),
        vec![task_attempt(
            "task-001",
            10_001,
            RunResultState::NotAvailable,
        )],
        Vec::new(),
        Some("next".to_owned()),
    )
    .expect("page one");
    let page_two = hartevo_databricks_job_result_plugin::RunPage::new(
        run_attempt(RunLifecycleState::Running, RunResultState::NotAvailable),
        vec![task_attempt(
            "task-001",
            10_001,
            RunResultState::NotAvailable,
        )],
        Vec::new(),
        None,
    )
    .expect("page two")
    .for_page_token(Some("next".to_owned()))
    .expect("page token");
    let mut service = make_service(
        scope,
        RecordingTransport::new()
            .with_job(job)
            .with_page(page_one)
            .with_page(page_two),
    );
    let err = service
        .read_run_evidence(&RunReadRequest::new(9001, 300, 1_000).expect("request"))
        .expect_err("duplicate attempt");
    assert_eq!(
        err,
        DatabricksError::Provider(DatabricksProviderError::DuplicateAttempt)
    );
}

#[derive(Debug)]
struct RetryTransport {
    responses:
        VecDeque<Result<hartevo_databricks_job_result_plugin::RunPage, DatabricksProviderError>>,
}

impl DatabricksJobsTransport for RetryTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn describe_job(
        &mut self,
        _scope: &DatabricksScope,
        _secret_reference: &SecretReference,
    ) -> Result<JobSnapshot, DatabricksProviderError> {
        Err(DatabricksProviderError::Unavailable)
    }

    fn get_run_page(
        &mut self,
        _scope: &DatabricksScope,
        _secret_reference: &SecretReference,
        _run_id: u64,
        _page_token: Option<&str>,
    ) -> Result<hartevo_databricks_job_result_plugin::RunPage, DatabricksProviderError> {
        self.responses
            .pop_front()
            .unwrap_or(Err(DatabricksProviderError::Unavailable))
    }

    fn get_run_output(
        &mut self,
        _scope: &DatabricksScope,
        _secret_reference: &SecretReference,
        _run_id: u64,
        _task_run_id: u64,
    ) -> Result<OutputEvidence, DatabricksProviderError> {
        Err(DatabricksProviderError::Unavailable)
    }
}

#[test]
fn bounded_retry_respects_mission_deadline() {
    let task_keys = vec!["task-001".to_owned()];
    let scope = make_scope(task_keys, 9001);
    let secret = secret(&scope);
    let page = hartevo_databricks_job_result_plugin::RunPage::new(
        run_attempt(RunLifecycleState::Running, RunResultState::NotAvailable),
        Vec::new(),
        Vec::new(),
        None,
    )
    .expect("page");
    let transport = RetryTransport {
        responses: VecDeque::from([
            Err(DatabricksProviderError::RateLimited { retry_after_ms: 5 }),
            Ok(page.clone()),
        ]),
    };
    let mut provider = DatabricksJobsProvider::new(transport);
    let request = RunReadRequest::new(9001, 100, 110).expect("request");
    let evidence = provider
        .read_run_evidence(&scope, &secret, &request)
        .expect("retry within deadline");
    assert_eq!(evidence.provenance, TransportProvenance::Fixture);

    let transport = RetryTransport {
        responses: VecDeque::from([Err(DatabricksProviderError::ServerError { status: 503 })]),
    };
    let mut provider = DatabricksJobsProvider::new(transport);
    let request = RunReadRequest::new(9001, 100, 100).expect("request");
    let err = provider
        .read_run_evidence(&scope, &secret, &request)
        .expect_err("deadline");
    assert_eq!(err, DatabricksError::MissionDeadlineExceeded);
}

#[test]
fn http_status_timeout_and_server_errors_remain_typed() {
    let errors = vec![
        DatabricksProviderError::BadRequest,
        DatabricksProviderError::Unauthorized,
        DatabricksProviderError::Forbidden,
        DatabricksProviderError::NotFound,
        DatabricksProviderError::Timeout,
        DatabricksProviderError::ServerError { status: 503 },
    ];
    for provider_error in errors {
        let task_keys = vec!["task-001".to_owned()];
        let registered_scope = make_scope(task_keys, 9001);
        let secret_reference = secret(&registered_scope);
        let transport = RetryTransport {
            responses: VecDeque::from([Err(provider_error.clone())]),
        };
        let mut provider = DatabricksJobsProvider::new(transport)
            .with_retry_policy(RetryPolicy::new(1, 0).expect("one attempt"));
        let request = RunReadRequest::new(9001, 100, 100).expect("request");
        let error = provider
            .read_run_evidence(&registered_scope, &secret_reference, &request)
            .expect_err("typed provider error");
        assert_eq!(error, DatabricksError::Provider(provider_error));
    }
}

#[test]
fn lifecycle_terminal_without_success_is_not_success() {
    let task_keys = vec!["task-001".to_owned()];
    let scope = make_scope(task_keys.clone(), 9001);
    let job = job(&task_keys);
    let output =
        OutputEvidence::from_metadata(&digest("output"), 3, 3, false, 10_000).expect("output");
    let task = TaskAttempt::new(
        "task-001",
        10_001,
        0,
        10_001,
        RunLifecycleState::Terminated,
        RunResultState::NotAvailable,
        Some(100),
        Some(200),
        Some(100),
        Some(output),
    )
    .expect("task");
    let page = hartevo_databricks_job_result_plugin::RunPage::new(
        run_attempt(RunLifecycleState::Terminated, RunResultState::NotAvailable),
        vec![task],
        Vec::new(),
        None,
    )
    .expect("page");
    let mut service = make_service(
        scope,
        RecordingTransport::new()
            .with_job(job.clone())
            .with_page(page),
    );
    let (proposal, evidence) = proposal_and_evidence(&mut service, &job, task_keys);
    let result = service
        .project_result(&proposal, &evidence, 300)
        .expect("result");
    assert_eq!(
        result.disposition,
        hartevo_databricks_job_result_plugin::ResultDisposition::TerminalWithoutResult
    );
    assert_ne!(
        result.disposition,
        hartevo_databricks_job_result_plugin::ResultDisposition::Success
    );
    assert_eq!(result.adoption, AdoptionDisposition::NeverAdoptableByLayer1);
}

#[test]
fn queued_blocked_waiting_and_provider_unknown_lifecycles_stay_separate() {
    let cases = [
        (
            RunLifecycleState::Queued,
            hartevo_databricks_job_result_plugin::ResultDisposition::Pending,
        ),
        (
            RunLifecycleState::Blocked,
            hartevo_databricks_job_result_plugin::ResultDisposition::Blocked,
        ),
        (
            RunLifecycleState::WaitingForRetry,
            hartevo_databricks_job_result_plugin::ResultDisposition::WaitingForRetry,
        ),
        (
            RunLifecycleState::ProviderUnknown,
            hartevo_databricks_job_result_plugin::ResultDisposition::ProviderUnknown,
        ),
    ];
    for (lifecycle, expected) in cases {
        let task_keys = vec!["task-001".to_owned()];
        let registered_scope = make_scope(task_keys.clone(), 9001);
        let job = job(&task_keys);
        let page = hartevo_databricks_job_result_plugin::RunPage::new(
            run_attempt(lifecycle, RunResultState::NotAvailable),
            vec![task_attempt(
                "task-001",
                10_001,
                RunResultState::NotAvailable,
            )],
            Vec::new(),
            None,
        )
        .expect("page");
        let mut service = make_service(
            registered_scope,
            RecordingTransport::new()
                .with_job(job.clone())
                .with_page(page),
        );
        let (proposal, evidence) = proposal_and_evidence(&mut service, &job, task_keys);
        let result = service
            .project_result(&proposal, &evidence, 300)
            .expect("projection");
        assert_eq!(result.disposition, expected);
    }
}

#[test]
fn stale_job_revision_and_run_scope_are_rejected() {
    let task_keys = vec!["task-001".to_owned()];
    let registered_scope = make_scope(task_keys.clone(), 9001);
    let stale_job = JobSnapshot::new(
        42,
        8,
        &digest("job-settings"),
        task_keys.iter().map(|key| task_snapshot(key)).collect(),
        Some("cluster-1".to_owned()),
        None,
        100,
    )
    .expect("stale job");
    let mut service = make_service(
        registered_scope.clone(),
        RecordingTransport::new().with_job(stale_job),
    );
    assert_eq!(
        service.describe_job().expect_err("stale revision"),
        DatabricksError::JobRevisionMismatch
    );

    let job = job(&task_keys);
    let page = hartevo_databricks_job_result_plugin::RunPage::new(
        run_attempt(RunLifecycleState::Running, RunResultState::NotAvailable),
        vec![task_attempt(
            "task-001",
            10_001,
            RunResultState::NotAvailable,
        )],
        Vec::new(),
        None,
    )
    .expect("page");
    let mut service = make_service(
        registered_scope,
        RecordingTransport::new().with_job(job).with_page(page),
    );
    assert_eq!(
        service
            .read_run_evidence(&RunReadRequest::new(9002, 300, 1_000).expect("request"))
            .expect_err("stale run"),
        DatabricksError::ScopeMismatch
    );
}

#[test]
fn truncation_and_expiry_are_explicit_and_non_adoptable() {
    let task_keys = vec!["task-001".to_owned()];
    let scope = make_scope(task_keys.clone(), 9001);
    let job = job(&task_keys);
    let truncated = OutputEvidence::from_bytes(&vec![7_u8; MAX_OUTPUT_BYTES + 1], 10_000)
        .expect("truncated output");
    assert!(truncated.truncated);
    assert_eq!(truncated.captured_size_bytes, MAX_OUTPUT_BYTES as u64);
    assert_eq!(truncated.access, OutputAccess::Available);
    let task = TaskAttempt::new(
        "task-001",
        10_001,
        0,
        10_001,
        RunLifecycleState::Terminated,
        RunResultState::Success,
        Some(100),
        Some(200),
        Some(100),
        Some(truncated),
    )
    .expect("task");
    let page = hartevo_databricks_job_result_plugin::RunPage::new(
        run_attempt(RunLifecycleState::Terminated, RunResultState::Success),
        vec![task],
        Vec::new(),
        None,
    )
    .expect("page");
    let mut service = make_service(
        scope,
        RecordingTransport::new()
            .with_job(job.clone())
            .with_page(page),
    );
    let (proposal, evidence) = proposal_and_evidence(&mut service, &job, task_keys);
    let result = service
        .project_result(&proposal, &evidence, 300)
        .expect("result");
    assert_eq!(
        result.disposition,
        hartevo_databricks_job_result_plugin::ResultDisposition::OutputTruncated
    );
    let report = service
        .verify_job_result(&proposal, &evidence, 300)
        .expect("verification");
    assert_eq!(report.verdict, VerificationVerdict::PartialEvidence);
    assert!(
        report
            .reasons
            .contains(&VerificationReason::OutputTruncated)
    );
    assert!(!report.native);

    let expired = service
        .verify_job_result(&proposal, &evidence, evidence.expires_at_ms)
        .expect("expired verification");
    assert_eq!(expired.verdict, VerificationVerdict::FailedClosed);
    assert!(
        expired
            .reasons
            .contains(&VerificationReason::EvidenceExpired)
    );
}

#[test]
fn tamper_revocation_and_secret_redaction_fail_closed() {
    let task_keys = vec!["task-001".to_owned()];
    let scope = make_scope(task_keys.clone(), 9001);
    let job = job(&task_keys);
    let page = hartevo_databricks_job_result_plugin::RunPage::new(
        run_attempt(RunLifecycleState::Running, RunResultState::NotAvailable),
        vec![task_attempt(
            "task-001",
            10_001,
            RunResultState::NotAvailable,
        )],
        Vec::new(),
        None,
    )
    .expect("page");
    let mut service = make_service(
        scope.clone(),
        RecordingTransport::new()
            .with_job(job.clone())
            .with_page(page),
    );
    let (mut proposal, evidence) = proposal_and_evidence(&mut service, &job, task_keys);
    proposal.proposal_digest = digest("tampered");
    let report = service
        .verify_job_result(&proposal, &evidence, 300)
        .expect("tamper report");
    assert_eq!(report.verdict, VerificationVerdict::FailedClosed);
    assert!(
        report
            .reasons
            .contains(&VerificationReason::ProposalTampered)
    );
    assert!(
        service
            .record_run_receipt(&proposal, &evidence, 300)
            .is_err()
    );

    let debug = format!("{:?}", secret(&scope));
    assert!(!debug.contains("client-secret-reference"));
    assert!(
        !serde_json::to_string(&service.registration())
            .expect("safe registration")
            .contains("client-secret-reference")
    );

    service.revoke().expect("revoke");
    assert_eq!(
        service.registration().status,
        hartevo_databricks_job_result_plugin::RegistrationStatus::Revoked
    );
    assert!(matches!(
        service.describe_job(),
        Err(DatabricksError::RegistrationRevoked)
    ));
    service.reverse().expect("reverse");
    assert_eq!(
        service.registration().status,
        hartevo_databricks_job_result_plugin::RegistrationStatus::Reversed
    );
}

#[test]
fn blocked_env_is_not_connected_or_native() {
    let task_keys = vec!["task-001".to_owned()];
    let scope = make_scope(task_keys, 9001);
    let provider = DatabricksJobsProvider::blocked_env();
    let service = DatabricksJobResultService::register(
        provider,
        "0.1.0",
        "adapter-1",
        oauth(),
        scope.clone(),
        secret(&scope),
    )
    .expect("service");
    assert_eq!(
        service.provider().provenance(),
        TransportProvenance::BlockedEnv
    );
    assert!(!service.provider().provenance().is_native());
    assert_eq!(JOBS_API_REVISION, "jobs-api-2.2");
    assert_eq!(CONTRACT_DIGEST.len(), 64);
    let mut service = service;
    let err = service.describe_job().expect_err("blocked env");
    assert_eq!(
        err,
        DatabricksError::Provider(DatabricksProviderError::BlockedEnv)
    );
}

#[test]
fn oauth_m2m_and_scope_registration_are_digest_bound() {
    let task_keys = vec!["task-001".to_owned()];
    let scope = make_scope(task_keys, 9001);
    let registration = hartevo_databricks_job_result_plugin::DatabricksRegistration::new(
        "0.1.0",
        CONTRACT_DIGEST,
        "adapter-1",
        oauth(),
        scope.clone(),
        secret(&scope),
    )
    .expect("registration");
    assert!(registration.validate_integrity().is_ok());
    let serialized = serde_json::to_string(&registration.snapshot()).expect("snapshot");
    assert!(serialized.contains("jobs-api-2.2"));
    assert!(!serialized.contains("bearer"));
    assert!(!serialized.contains("client-secret-reference"));

    let wrong_scope = DatabricksScope::new(
        "acct-1",
        "https://other.example.test",
        "ws-1",
        42,
        7,
        ["task-001".to_owned()],
        "mission-1",
        "project-1",
        "work-product-1",
        3,
        4,
    )
    .expect("wrong scope");
    assert!(SecretReference::oauth_m2m("ref", &wrong_scope.digest(), 1).is_ok());
    assert!(
        DatabricksJobResultService::new(
            DatabricksJobsProvider::new(RecordingTransport::new()),
            registration,
        )
        .is_ok()
    );
}

#[test]
fn mission_consumer_preserves_repair_and_output_metadata_without_raw_output() {
    let task_keys = vec!["task-001".to_owned()];
    let scope = make_scope(task_keys.clone(), 9001);
    let job = job(&task_keys);
    let output = OutputEvidence::from_metadata(&digest("bounded-output"), 10, 10, false, 10_000)
        .expect("output");
    let task = TaskAttempt::new(
        "task-001",
        10_001,
        1,
        10_001,
        RunLifecycleState::Terminated,
        RunResultState::Success,
        Some(100),
        Some(200),
        Some(100),
        Some(output),
    )
    .expect("task");
    let repair = RepairRecord::new(1, 9001, 9002, vec!["task-001".to_owned()]).expect("repair");
    let page = hartevo_databricks_job_result_plugin::RunPage::new(
        run_attempt(RunLifecycleState::Terminated, RunResultState::Success),
        vec![task],
        vec![repair],
        None,
    )
    .expect("page");
    let mut service = make_service(
        scope,
        RecordingTransport::new()
            .with_job(job.clone())
            .with_page(page),
    );
    let (proposal, evidence) = proposal_and_evidence(&mut service, &job, task_keys);
    let result = MissionDatabricksJobConsumer::new()
        .consume(&service.registration(), &proposal, &evidence, 300)
        .expect("consumer");
    assert_eq!(
        result.disposition,
        hartevo_databricks_job_result_plugin::ResultDisposition::Success
    );
    assert_eq!(result.repairs.len(), 1);
    assert_eq!(
        result.tasks[0].output_disposition,
        OutputDisposition::Complete
    );
    assert_eq!(result.adoption, AdoptionDisposition::NeverAdoptableByLayer1);
    let serialized = serde_json::to_string(&result).expect("result");
    assert!(!serialized.contains("bounded-output"));
}
