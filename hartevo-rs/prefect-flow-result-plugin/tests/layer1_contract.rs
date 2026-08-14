use hartevo_prefect_flow_result_plugin::{
    Authority, BLOCKED_ENV, CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION, Digest,
    MAX_FILTER_VALUES, MAX_PAGE_ITEMS, MAX_TASK_RUNS, MissionConsumptionDisposition,
    MissionPrefectFlowConsumer, MissionScopeBinding, PrefectAccountIdentity,
    PrefectAdoptionDisposition, PrefectDeploymentIdentity, PrefectError, PrefectFlowIdentity,
    PrefectFlowResultService, PrefectFlowRunIdentity, PrefectFlowRunRecord, PrefectOperation,
    PrefectPage, PrefectPermission, PrefectProvider, PrefectReadRequest, PrefectRunProjection,
    PrefectScope, PrefectServerHostIdentity, PrefectState, PrefectStateHistoryPage,
    PrefectStateHistoryRecord, PrefectStateScope, PrefectTaskRunIdentity, PrefectTaskRunPage,
    PrefectTaskRunRecord, PrefectTransportError, PrefectWorkspaceIdentity, ReadLimits,
    ReadOnlyAuthority, RecordingPrefectTransport, SecretKind, SecretReference, TransportProvenance,
    contract_digest, flow_run_endpoint_path, flow_run_filter_endpoint_path,
    flow_run_history_endpoint_path, state_history_endpoint_path, task_run_endpoint_path,
    task_runs_endpoint_path,
};

fn scope() -> PrefectScope {
    let mission = MissionScopeBinding::new(
        "project-prefect-01",
        "mission-prefect-01",
        "work-product-prefect-01",
        3,
        4,
        5,
        Digest::from_text("policy-revision-3"),
        Digest::from_text("consent-revision-4"),
    )
    .expect("mission scope");
    PrefectScope::new(
        PrefectServerHostIdentity::new(
            "https://prefect.example",
            "prefect-prod",
            hartevo_prefect_flow_result_plugin::PREFECT_API_REVISION,
            1,
        )
        .expect("server host"),
        PrefectAccountIdentity::new("account-prefect-prod", 2).expect("account"),
        PrefectWorkspaceIdentity::new("workspace-prefect-prod", 3).expect("workspace"),
        PrefectFlowIdentity::new("daily_orders", 4).expect("flow"),
        PrefectDeploymentIdentity::new("daily_orders-prod", 5).expect("deployment"),
        PrefectFlowRunIdentity::new("flow-run-2026-08-14", 6).expect("flow run"),
        PrefectTaskRunIdentity::new("task-run-publish-orders", 7).expect("task run"),
        PrefectStateScope::new(
            [
                PrefectState::Scheduled,
                PrefectState::Pending,
                PrefectState::Running,
                PrefectState::Completed,
                PrefectState::Failed,
                PrefectState::Crashed,
                PrefectState::Cancelled,
                PrefectState::Paused,
                PrefectState::Late,
                PrefectState::ProviderUnknown,
            ],
            8,
        )
        .expect("state scope"),
        mission,
        [
            PrefectPermission::ServerHostRead,
            PrefectPermission::AccountRead,
            PrefectPermission::WorkspaceRead,
            PrefectPermission::FlowRead,
            PrefectPermission::DeploymentRead,
            PrefectPermission::FlowRunRead,
            PrefectPermission::TaskRunRead,
            PrefectPermission::StateRead,
            PrefectPermission::MissionScope,
        ],
    )
    .expect("Prefect scope")
}

fn secret(scope: &PrefectScope, revision: u64) -> SecretReference {
    SecretReference::api_key(
        format!("secret-ref-prefect-api-key-{revision}"),
        scope,
        revision,
    )
    .expect("opaque API key reference")
}

fn flow_run(scope: &PrefectScope, state: PrefectState) -> PrefectFlowRunRecord {
    PrefectFlowRunRecord::new(
        scope.flow.clone(),
        scope.deployment.clone(),
        scope.flow_run.clone(),
        state,
    )
    .expect("flow run")
}

fn task_run(scope: &PrefectScope, state: PrefectState) -> PrefectTaskRunRecord {
    PrefectTaskRunRecord::new(
        scope.flow.clone(),
        scope.deployment.clone(),
        scope.flow_run.clone(),
        scope.task_run.clone(),
        state,
    )
    .expect("task run")
}

fn task_run_with_id(
    scope: &PrefectScope,
    task_run_id: &str,
    state: PrefectState,
) -> PrefectTaskRunRecord {
    PrefectTaskRunRecord::new(
        scope.flow.clone(),
        scope.deployment.clone(),
        scope.flow_run.clone(),
        PrefectTaskRunIdentity::new(task_run_id, scope.task_run.revision).expect("task id"),
        state,
    )
    .expect("task run")
}

fn task_page(items: Vec<PrefectTaskRunRecord>, total: usize, offset: usize) -> PrefectTaskRunPage {
    PrefectPage::new(items, total, offset, 1, false)
}

fn ready_service(scope: &PrefectScope) -> PrefectFlowResultService<RecordingPrefectTransport> {
    let transport = RecordingPrefectTransport::recording(
        flow_run(scope, PrefectState::Completed),
        task_page(vec![task_run(scope, PrefectState::Completed)], 1, 0),
    );
    PrefectFlowResultService::from_transport(scope.clone(), secret(scope, 1), transport)
        .expect("service")
}

#[test]
fn contract_is_layer_one_read_only_and_honest() {
    let document: serde_json::Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
    assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
    assert_eq!(document["contractVersion"], CONTRACT_VERSION);
    assert_eq!(document["serviceId"], "PrefectFlowResultService");
    assert_eq!(document["providerId"], "PrefectProvider");
    assert_eq!(document["consumerId"], "MissionPrefectFlowConsumer");
    assert_eq!(document["layer"], 1);
    assert_eq!(document["honesty"]["connected"], false);
    assert_eq!(document["honesty"]["native"], false);
    assert_eq!(document["honesty"]["rawApiKeySerialized"], false);
    assert_eq!(document["honesty"]["rawLogsRetained"], false);
    assert_eq!(document["honesty"]["rawResultsRetained"], false);
    assert_eq!(document["honesty"]["stateMutation"], false);
    assert_eq!(document["honesty"]["workflowRegistryAuthority"], false);
    assert_eq!(document["honesty"]["kernelAuthority"], false);
    assert_eq!(document["honesty"]["workProductAdopted"], false);
    assert_eq!(
        document["provider"]["apiRevision"],
        hartevo_prefect_flow_result_plugin::PREFECT_API_REVISION
    );
    assert_eq!(
        document["properties"]["bounds"]["properties"]["maxFilterValues"]["const"],
        MAX_FILTER_VALUES
    );
    assert_eq!(contract_digest().as_str().len(), 64);
    assert!(!Authority::external_writes());
    assert!(!ReadOnlyAuthority::create_flow_run());
    assert!(!ReadOnlyAuthority::set_flow_run_state());
    assert!(!ReadOnlyAuthority::cancel_flow_run());
    assert!(!ReadOnlyAuthority::mutate_deployment());
    assert!(!ReadOnlyAuthority::mutate_worker());
    assert!(!ReadOnlyAuthority::raw_logs());
    assert!(!ReadOnlyAuthority::raw_results());
    assert!(!ReadOnlyAuthority::arbitrary_filter_dsl());
    assert!(!ReadOnlyAuthority::workflow_registry_authority());
    assert!(!ReadOnlyAuthority::kernel_authority());
    assert!(!ReadOnlyAuthority::provider_receipt());
    assert!(!ReadOnlyAuthority::work_product_adoption());
}

#[test]
fn exact_scope_reads_compile_verify_and_consume_review_only_proposal() {
    let scope = scope();
    let mut service = ready_service(&scope);
    assert_eq!(
        service.describe_server_host().expect("host").server_host,
        scope.server_host
    );
    assert_eq!(
        service.describe_account().expect("account").account,
        scope.account
    );
    assert_eq!(
        service.describe_workspace().expect("workspace").workspace,
        scope.workspace
    );
    assert_eq!(service.describe_flow().expect("flow").flow, scope.flow);
    assert_eq!(
        service
            .describe_deployment()
            .expect("deployment")
            .deployment,
        scope.deployment
    );

    let evidence = service
        .read_evidence(PrefectReadRequest::for_task_runs(0, 1).expect("request"))
        .expect("bounded evidence");
    assert_eq!(evidence.projection, PrefectRunProjection::Completed);
    assert_eq!(evidence.task_runs.len(), 1);
    assert_eq!(evidence.retry_markers.len(), 2);
    assert!(evidence.is_review_only());
    assert!(!evidence.provenance.is_connected());
    assert!(!evidence.provenance.is_native());
    assert!(!evidence.provenance.is_first_party());

    let proposal = service
        .compile_flow_result_proposal(&evidence)
        .expect("proposal");
    assert_eq!(
        proposal.adoption,
        PrefectAdoptionDisposition::Layer2Required
    );
    assert!(proposal.is_review_only());
    let verified = service
        .verify_proposal(&proposal, &evidence)
        .expect("verified proposal");
    assert!(verified.verified());
    assert!(!verified.connected);
    assert!(!verified.kernel_authority);
    assert!(!verified.work_product_adopted);

    let registration = service.registration().clone();
    let mut consumer =
        MissionPrefectFlowConsumer::from_registration(&registration, &scope).expect("consumer");
    let mission_result = consumer.consume_result(&proposal).expect("Mission result");
    assert_eq!(
        mission_result.disposition,
        MissionConsumptionDisposition::Fresh
    );
    assert!(!mission_result.adopted);
    assert!(!mission_result.kernel_authority);
    let replay = consumer.consume_result(&proposal).expect("replay");
    assert_eq!(replay.disposition, MissionConsumptionDisposition::Replay);

    let mut newer_mission = scope.mission.clone();
    newer_mission.mission_revision += 1;
    assert_eq!(
        consumer.consume_at_revision(&proposal, &newer_mission),
        Err(PrefectError::StaleMissionRevision)
    );
}

#[test]
fn api_key_reference_is_opaque_and_safe_to_serialize() {
    let scope = scope();
    let reference = secret(&scope, 9);
    assert_eq!(reference.kind(), SecretKind::ApiKey);
    let debug = format!("{reference:?}");
    assert!(!debug.contains("secret-ref-prefect-api-key-9"));
    assert!(!debug.contains("api_key_value"));
    assert!(!debug.contains("authorization"));
    let serialized = serde_json::to_string(&reference).expect("safe reference JSON");
    assert!(!serialized.contains("secret-ref-prefect-api-key-9"));
    assert!(serialized.contains("referenceDigest"));
}

#[test]
fn fixture_fake_loopback_and_blocked_env_never_claim_native_or_connected() {
    let scope = scope();
    let transports = [
        RecordingPrefectTransport::fixture(
            flow_run(&scope, PrefectState::Completed),
            task_page(vec![task_run(&scope, PrefectState::Completed)], 1, 0),
        ),
        RecordingPrefectTransport::fake(
            flow_run(&scope, PrefectState::Completed),
            task_page(vec![task_run(&scope, PrefectState::Completed)], 1, 0),
        ),
        RecordingPrefectTransport::loopback(
            flow_run(&scope, PrefectState::Completed),
            task_page(vec![task_run(&scope, PrefectState::Completed)], 1, 0),
        ),
    ];
    for transport in transports {
        let provider =
            PrefectProvider::new(scope.clone(), secret(&scope, 1), transport).expect("provider");
        assert!(!provider.connected());
        assert!(!provider.native());
        assert!(!provider.first_party());
    }

    let mut blocked = PrefectProvider::new(
        scope.clone(),
        secret(&scope, 2),
        RecordingPrefectTransport::blocked_env(),
    )
    .expect("blocked provider");
    assert_eq!(blocked.provenance(), TransportProvenance::BlockedEnv);
    let error = blocked
        .read_evidence(PrefectReadRequest::for_task_run())
        .expect_err("BLOCKED_ENV must fail closed");
    assert_eq!(error, PrefectError::BlockedEnv);
    assert_eq!(error.projection(), PrefectRunProjection::ProviderUnknown);
    assert_eq!(BLOCKED_ENV, "BLOCKED_ENV");
}

#[test]
fn pagination_offsets_states_and_history_are_bounded_and_fenced() {
    let scope = scope();
    let other = task_run_with_id(&scope, "other-task-run", PrefectState::Completed);
    let target = task_run(&scope, PrefectState::Completed);
    let transport = RecordingPrefectTransport::recording_with_pages(
        flow_run(&scope, PrefectState::Completed),
        [task_page(vec![other], 2, 0), task_page(vec![target], 2, 1)],
    );
    let mut service =
        PrefectFlowResultService::from_transport(scope.clone(), secret(&scope, 3), transport)
            .expect("service");
    let evidence = service
        .read_evidence(PrefectReadRequest::for_task_runs(0, 1).expect("request"))
        .expect("paged evidence");
    assert!(evidence.complete);
    assert_eq!(evidence.pages_read, 3);
    assert_eq!(evidence.task_runs.len(), 1);

    assert_eq!(
        PrefectReadRequest::for_task_runs(0, MAX_PAGE_ITEMS + 1),
        Err(PrefectError::PaginationLimit)
    );
    assert_eq!(
        PrefectReadRequest::for_task_runs(MAX_TASK_RUNS + 1, 1),
        Err(PrefectError::PaginationLimit)
    );
    assert_eq!(
        PrefectReadRequest::for_state_history("2026-08-15T00:00:00Z", "2026-08-14T00:00:00Z"),
        Err(PrefectError::TimeFilterOutOfScope)
    );

    let history = PrefectStateHistoryRecord::new(
        scope.flow_run.clone(),
        PrefectState::Completed,
        "2026-08-14T00:00:00Z",
        1,
        0,
        false,
    )
    .expect("history point");
    let history_page: PrefectStateHistoryPage = PrefectPage::new(vec![history], 1, 0, 1, false);
    let mut history_service = PrefectFlowResultService::from_transport(
        scope.clone(),
        secret(&scope, 4),
        RecordingPrefectTransport::recording_with_history(
            flow_run(&scope, PrefectState::Completed),
            [task_page(
                vec![task_run(&scope, PrefectState::Completed)],
                1,
                0,
            )],
            [history_page],
            [],
        ),
    )
    .expect("history service");
    let history_evidence = history_service
        .read_evidence(
            PrefectReadRequest::for_state_history("2026-08-13T00:00:00Z", "2026-08-15T00:00:00Z")
                .expect("history request"),
        )
        .expect("history evidence");
    assert_eq!(history_evidence.state_history.len(), 1);
    assert_eq!(history_evidence.projection, PrefectRunProjection::Completed);
}

#[test]
fn http_statuses_timeout_and_malformed_evidence_project_honestly() {
    let statuses = [
        (401, PrefectRunProjection::AccessLoss),
        (403, PrefectRunProjection::AccessLoss),
        (404, PrefectRunProjection::Stale),
        (409, PrefectRunProjection::Stale),
        (422, PrefectRunProjection::ProviderUnknown),
        (500, PrefectRunProjection::ProviderUnknown),
        (503, PrefectRunProjection::ProviderUnknown),
    ];
    for (status, projection) in statuses {
        let scope = scope();
        let mut provider = PrefectProvider::new(
            scope.clone(),
            secret(&scope, status.into()),
            RecordingPrefectTransport::with_http_error(TransportProvenance::Recording, status),
        )
        .expect("HTTP provider");
        let error = provider
            .read_evidence(PrefectReadRequest::for_task_run())
            .expect_err("HTTP error");
        assert_eq!(error.status(), Some(status));
        assert_eq!(error.projection(), projection);
    }

    let scope = scope();
    let mut timeout = PrefectProvider::new(
        scope.clone(),
        secret(&scope, 900),
        RecordingPrefectTransport::with_transport_error(
            TransportProvenance::Recording,
            PrefectTransportError::Timeout,
        ),
    )
    .expect("timeout provider");
    assert_eq!(
        timeout.read_evidence(PrefectReadRequest::for_task_run()),
        Err(PrefectError::Timeout)
    );
    let mut malformed = PrefectProvider::new(
        scope.clone(),
        secret(&scope, 901),
        RecordingPrefectTransport::with_transport_error(
            TransportProvenance::Recording,
            PrefectTransportError::MalformedResponse,
        ),
    )
    .expect("malformed provider");
    assert_eq!(
        malformed.read_evidence(PrefectReadRequest::for_task_run()),
        Err(PrefectError::PartialResponse)
    );
}

#[test]
fn endpoints_are_allowlisted_and_no_mutation_endpoint_is_exposed() {
    let scope = scope();
    assert_eq!(
        flow_run_endpoint_path(&scope),
        "/api/accounts/account-prefect-prod/workspaces/workspace-prefect-prod/flow_runs/flow-run-2026-08-14"
    );
    assert_eq!(
        task_runs_endpoint_path(&scope),
        "/api/accounts/account-prefect-prod/workspaces/workspace-prefect-prod/task_runs/filter"
    );
    assert_eq!(
        task_run_endpoint_path(&scope),
        "/api/accounts/account-prefect-prod/workspaces/workspace-prefect-prod/task_runs/task-run-publish-orders"
    );
    assert_eq!(
        flow_run_history_endpoint_path(&scope),
        "/api/accounts/account-prefect-prod/workspaces/workspace-prefect-prod/flow_runs/history"
    );
    assert_eq!(
        state_history_endpoint_path(&scope),
        "/api/accounts/account-prefect-prod/workspaces/workspace-prefect-prod/flow_runs/history"
    );
    assert_eq!(
        flow_run_filter_endpoint_path(&scope),
        "/api/accounts/account-prefect-prod/workspaces/workspace-prefect-prod/flow_runs/filter"
    );
    assert_eq!(PrefectOperation::GetFlowRun.method(), "GET");
    assert_eq!(PrefectOperation::GetTaskRun.method(), "GET");
    assert_eq!(PrefectOperation::ListTaskRuns.method(), "POST");
    assert_eq!(PrefectOperation::ReadStateHistory.method(), "POST");
    assert_eq!(PrefectOperation::FilterFlowRuns.method(), "POST");
    assert!(!ReadOnlyAuthority::external_writes());
}

#[test]
fn late_retry_monotonicity_tamper_and_revocation_fail_closed() {
    let scope = scope();
    let late_flow = flow_run(&scope, PrefectState::Running)
        .with_retry_late(2, true)
        .expect("late flow");
    let mut service = PrefectFlowResultService::from_transport(
        scope.clone(),
        secret(&scope, 11),
        RecordingPrefectTransport::recording(
            late_flow,
            task_page(vec![task_run(&scope, PrefectState::Running)], 1, 0),
        ),
    )
    .expect("late service");
    let late = service
        .read_evidence(PrefectReadRequest::for_task_run())
        .expect("late evidence");
    assert_eq!(late.projection, PrefectRunProjection::Late);
    assert_eq!(late.retry_markers[0].retry_count, 2);
    assert!(late.retry_markers[0].late);

    let mut running = service;
    let tampered = running
        .read_evidence(PrefectReadRequest::for_task_run())
        .expect_err("recording is exhausted after one read");
    assert_eq!(tampered, PrefectError::RecordingExhausted);

    let mut service = ready_service(&scope);
    let evidence = service
        .read_evidence(PrefectReadRequest::for_task_run())
        .expect("evidence");
    let mut changed = evidence.clone();
    changed.projection = PrefectRunProjection::Failed;
    assert_eq!(
        service.verify_run_evidence(&changed),
        Err(PrefectError::EvidenceTampered)
    );
    service.unmount().expect("unmount");
    assert_eq!(
        service.read_evidence(PrefectReadRequest::for_task_run()),
        Err(PrefectError::RegistrationInactive)
    );
    service.remount().expect("remount");
    service.revoke().expect("revoke");
    assert!(service.secret_reference().is_revoked());
    assert_eq!(
        service.read_evidence(PrefectReadRequest::for_task_run()),
        Err(PrefectError::SecretRevoked)
    );

    let mut service = ready_service(&scope);
    service.provider_mut().registration_mut().flow_run_digest = Digest::from_text("tampered");
    assert_eq!(
        service.read_evidence(PrefectReadRequest::for_task_run()),
        Err(PrefectError::RegistrationTampered)
    );
}

#[test]
fn provider_unknown_and_all_prefect_states_are_explicit() {
    let states = [
        PrefectState::Scheduled,
        PrefectState::Pending,
        PrefectState::Running,
        PrefectState::Completed,
        PrefectState::Failed,
        PrefectState::Crashed,
        PrefectState::Cancelled,
        PrefectState::Paused,
        PrefectState::Late,
        PrefectState::ProviderUnknown,
    ];
    for state in states {
        assert_eq!(state.projection().is_terminal(), state.is_terminal());
    }
    assert!(PrefectRunProjection::Scheduled.can_follow(PrefectRunProjection::Running));
    assert!(PrefectRunProjection::Late.can_follow(PrefectRunProjection::Completed));
    assert!(!PrefectRunProjection::Completed.can_follow(PrefectRunProjection::Running));
    assert!(!PrefectRunProjection::ProviderUnknown.can_follow(PrefectRunProjection::Completed));
    assert_eq!(ReadLimits::default().max_pages, 32);
    assert_eq!(MAX_FILTER_VALUES, 16);
}
