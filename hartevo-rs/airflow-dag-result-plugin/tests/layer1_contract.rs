use std::collections::BTreeSet;

use hartevo_airflow_dag_result_plugin::{
    AirflowAdoptionDisposition, AirflowCommitOrRelease, AirflowDagIdentity,
    AirflowDagResultService, AirflowDagRunRecord, AirflowError, AirflowHostIdentity,
    AirflowLogicalDate, AirflowOperation, AirflowPage, AirflowPermission, AirflowProvider,
    AirflowReadRequest, AirflowRegistration, AirflowRunIdentity, AirflowRunProjection,
    AirflowScope, AirflowState, AirflowTaskIdentity, AirflowTaskInstanceRecord,
    AirflowTenantIdentity, BLOCKED_ENV, CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION, Digest,
    EvidenceProvenance, MAX_PAGE_ITEMS, MAX_TASK_INSTANCES, MissionAirflowRunConsumer,
    MissionConsumptionDisposition, MissionScopeBinding, ReadLimits, ReadOnlyAuthority,
    ReadOnlyAuthority as Authority, RecordingAirflowTransport, RedactionEvidence,
    RegistrationStatus, SecretKind, SecretReference, TransportProvenance, contract_digest,
    dag_run_endpoint_path, task_instance_endpoint_path, task_instances_endpoint_path,
};

const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const LOGICAL_DATE: &str = "2026-08-14T00:00:00Z";

fn scope() -> AirflowScope {
    let mission = MissionScopeBinding::new(
        "project-airflow-01",
        "mission-airflow-01",
        "work-product-airflow-01",
        3,
        4,
        5,
        Digest::from_text("policy-revision-3"),
        Digest::from_text("consent-revision-4"),
    )
    .expect("mission scope");
    AirflowScope::new(
        AirflowHostIdentity::new(
            "https://airflow.example",
            "airflow-prod",
            hartevo_airflow_dag_result_plugin::AIRFLOW_API_REVISION,
            1,
        )
        .expect("host"),
        AirflowTenantIdentity::new("tenant-prod", 2).expect("tenant"),
        AirflowDagIdentity::new("daily_orders", 3).expect("DAG"),
        AirflowRunIdentity::new("scheduled__2026-08-14", 4).expect("run"),
        AirflowTaskIdentity::new("publish_orders", 5).expect("task"),
        AirflowLogicalDate::new(LOGICAL_DATE, 6).expect("logical date"),
        AirflowCommitOrRelease::commit(COMMIT, 7).expect("commit"),
        mission,
        [
            AirflowPermission::HostRead,
            AirflowPermission::TenantRead,
            AirflowPermission::DagRead,
            AirflowPermission::DagRunRead,
            AirflowPermission::TaskInstanceRead,
            AirflowPermission::LogicalDateRead,
            AirflowPermission::CommitRead,
            AirflowPermission::MissionScope,
        ],
    )
    .expect("scope")
}

fn dag_run(scope: &AirflowScope) -> AirflowDagRunRecord {
    AirflowDagRunRecord::new(
        scope.dag.clone(),
        scope.run.clone(),
        scope.logical_date.clone(),
        AirflowState::Success,
    )
    .expect("DAG run")
}

fn task(scope: &AirflowScope, state: AirflowState) -> AirflowTaskInstanceRecord {
    AirflowTaskInstanceRecord::new(
        scope.dag.clone(),
        scope.run.clone(),
        scope.task.clone(),
        scope.logical_date.clone(),
        state,
    )
    .expect("task instance")
}

fn page(
    tasks: Vec<AirflowTaskInstanceRecord>,
    total: usize,
    offset: usize,
) -> AirflowPage<AirflowTaskInstanceRecord> {
    AirflowPage::new(tasks, total, offset, 1, false)
}

fn ready_service(scope: &AirflowScope) -> AirflowDagResultService<RecordingAirflowTransport> {
    let secret = SecretReference::bearer("secret-ref-airflow-bearer", scope, 9).expect("secret");
    let transport = RecordingAirflowTransport::recording(
        dag_run(scope),
        page(vec![task(scope, AirflowState::Success)], 1, 0),
    );
    AirflowDagResultService::from_transport(scope.clone(), secret, transport).expect("service")
}

#[test]
fn contract_is_layer_one_read_only_and_honest() {
    let document: serde_json::Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
    assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
    assert_eq!(document["contractVersion"], CONTRACT_VERSION);
    assert_eq!(document["serviceId"], "AirflowDagResultService");
    assert_eq!(document["providerId"], "AirflowProvider");
    assert_eq!(document["consumerId"], "MissionAirflowRunConsumer");
    assert_eq!(document["layer"], 1);
    assert_eq!(document["honesty"]["connected"], false);
    assert_eq!(document["honesty"]["native"], false);
    assert_eq!(document["honesty"]["firstParty"], false);
    assert_eq!(document["honesty"]["rawBearerSerialized"], false);
    assert_eq!(document["honesty"]["rawOidcSerialized"], false);
    assert_eq!(document["honesty"]["schedulerAuthority"], false);
    assert_eq!(document["honesty"]["kernelAuthority"], false);
    assert_eq!(document["honesty"]["workProductAdopted"], false);
    assert_eq!(contract_digest().as_str().len(), 64);
    assert!(!Authority::external_writes());
    assert!(!ReadOnlyAuthority::trigger_dag());
    assert!(!ReadOnlyAuthority::clear_task_instance());
    assert!(!ReadOnlyAuthority::retry_task_instance());
    assert!(!ReadOnlyAuthority::read_variables());
    assert!(!ReadOnlyAuthority::read_connections());
    assert!(!ReadOnlyAuthority::raw_logs());
    assert!(!ReadOnlyAuthority::raw_xcom());
    assert!(!ReadOnlyAuthority::scheduler_authority());
    assert!(!ReadOnlyAuthority::kernel_authority());
    assert!(!ReadOnlyAuthority::provider_receipt());
    assert!(!ReadOnlyAuthority::work_product_adoption());
    assert!(!ReadOnlyAuthority::native_connected());
    assert!(!ReadOnlyAuthority::first_party());
}

#[test]
fn exact_scope_reads_compile_and_consume_review_only_proposal() {
    let scope = scope();
    let mut service = ready_service(&scope);
    let host = service.describe_host().expect("host description");
    assert_eq!(host.host, scope.host);
    assert!(!host.native_connected);
    let dag = service.describe_dag().expect("DAG description");
    assert_eq!(dag.dag, scope.dag);
    assert!(dag.stable_rest_read);
    let evidence = service
        .read_evidence(AirflowReadRequest::for_task_instances(0, 1).expect("request"))
        .expect("evidence");
    assert_eq!(evidence.projection, AirflowRunProjection::Success);
    assert_eq!(evidence.task_instances.len(), 1);
    assert_eq!(evidence.materializations.len(), 1);
    assert!(!evidence.provenance.is_connected());
    assert!(!evidence.provenance.is_native());
    assert!(!evidence.provenance.is_first_party());
    let proposal = service
        .compile_run_result_proposal(&evidence)
        .expect("proposal");
    assert_eq!(
        proposal.disposition,
        AirflowAdoptionDisposition::Layer2Required
    );
    let verified = service
        .verify_proposal(&proposal, &evidence)
        .expect("verified proposal");
    assert!(verified.verified());
    assert!(!verified.connected);
    let registration = service.registration().clone();
    let mut mission_consumer =
        MissionAirflowRunConsumer::from_registration(&registration, &scope).expect("consumer");
    let mission_result = mission_consumer
        .consume_result(&proposal)
        .expect("Mission result");
    assert_eq!(
        mission_result.disposition,
        MissionConsumptionDisposition::Fresh
    );
    assert!(!mission_result.adopted);
    assert!(!mission_result.kernel_authority);
    let replay = mission_consumer.consume_result(&proposal).expect("replay");
    assert_eq!(replay.disposition, MissionConsumptionDisposition::Replay);
    let mut newer_mission = scope.mission.clone();
    newer_mission.mission_revision += 1;
    assert_eq!(
        mission_consumer.consume_at_revision(&proposal, &newer_mission),
        Err(AirflowError::StaleMissionRevision)
    );
}

#[test]
fn opaque_bearer_and_oidc_references_never_print_credential_material() {
    let scope = scope();
    let bearer = SecretReference::new("secret-ref-airflow-bearer", SecretKind::Bearer, &scope, 1)
        .expect("bearer");
    let oidc = SecretReference::oidc("secret-ref-airflow-oidc", &scope, 2).expect("OIDC");
    assert_eq!(bearer.kind(), SecretKind::Bearer);
    assert_eq!(oidc.kind(), SecretKind::Oidc);
    let debug = format!("{bearer:?} {oidc:?}");
    assert!(!debug.contains("token"));
    assert!(!debug.contains("authorization"));
    assert!(!debug.contains("client_secret"));
    assert!(!debug.contains("secret-ref-airflow-bearer"));
    assert!(!debug.contains("secret-ref-airflow-oidc"));
}

#[test]
fn fixture_fake_loopback_and_blocked_env_never_claim_native_or_connected() {
    let scope = scope();
    let records = [
        RecordingAirflowTransport::fixture(
            dag_run(&scope),
            page(vec![task(&scope, AirflowState::Success)], 1, 0),
        ),
        RecordingAirflowTransport::fake(
            dag_run(&scope),
            page(vec![task(&scope, AirflowState::Success)], 1, 0),
        ),
        RecordingAirflowTransport::loopback(
            dag_run(&scope),
            page(vec![task(&scope, AirflowState::Success)], 1, 0),
        ),
    ];
    for transport in records {
        let secret = SecretReference::bearer("secret-ref-airflow-read", &scope, 1).expect("secret");
        let provider = AirflowProvider::new(scope.clone(), secret, transport).expect("provider");
        assert!(!provider.connected());
        assert!(!provider.native());
        assert!(!provider.first_party());
    }
    let secret = SecretReference::bearer("secret-ref-airflow-blocked", &scope, 1).expect("secret");
    let mut blocked = AirflowProvider::new(
        scope.clone(),
        secret,
        RecordingAirflowTransport::blocked_env(),
    )
    .expect("blocked provider");
    assert_eq!(blocked.provenance(), TransportProvenance::BlockedEnv);
    let error = blocked
        .read_evidence(AirflowReadRequest::for_task_instance())
        .expect_err("BLOCKED_ENV must fail closed");
    assert_eq!(error, AirflowError::BlockedEnv);
    assert_eq!(error.projection(), AirflowRunProjection::ProviderUnknown);
    let secret =
        SecretReference::bearer("secret-ref-airflow-projected", &scope, 1).expect("secret");
    let mut access_loss = AirflowProvider::new(
        scope.clone(),
        secret,
        RecordingAirflowTransport::with_http_error(TransportProvenance::Recording, 401),
    )
    .expect("access-loss provider");
    let projected = access_loss.read_evidence_projected(AirflowReadRequest::for_task_instance());
    let hartevo_airflow_dag_result_plugin::AirflowReadOutcome::Failure(failure) = projected else {
        panic!("HTTP access loss must be projected as failure evidence");
    };
    assert_eq!(failure.projection, AirflowRunProjection::AccessLoss);
    failure
        .validate(access_loss.scope(), access_loss.registration())
        .expect("failure evidence");
    assert_eq!(BLOCKED_ENV, "BLOCKED_ENV");
}

#[test]
fn pagination_ordering_and_logical_date_bounds_are_fenced() {
    let scope = scope();
    let other_task = AirflowTaskInstanceRecord::new(
        scope.dag.clone(),
        scope.run.clone(),
        AirflowTaskIdentity::new("extract_orders", 8).expect("other task"),
        scope.logical_date.clone(),
        AirflowState::Success,
    )
    .expect("other task instance");
    let transport = RecordingAirflowTransport::recording_with_pages(
        dag_run(&scope),
        [
            page(vec![other_task], 2, 0),
            page(vec![task(&scope, AirflowState::Success)], 2, 1),
        ],
    );
    let secret =
        SecretReference::bearer("secret-ref-airflow-pagination", &scope, 1).expect("secret");
    let mut provider = AirflowProvider::new(scope.clone(), secret, transport).expect("provider");
    let evidence = provider
        .read_evidence(AirflowReadRequest::for_task_instances(0, 1).expect("request"))
        .expect("paged evidence");
    assert!(evidence.complete);
    assert_eq!(evidence.pages_read, 2);
    assert_eq!(evidence.task_instances.len(), 1);
    let outside = AirflowReadRequest::for_task_instances(0, 1)
        .expect("request")
        .with_date_bounds(
            Some("2026-08-15T00:00:00Z".into()),
            Some("2026-08-16T00:00:00Z".into()),
        )
        .expect("date bounds");
    assert_eq!(
        provider.read_evidence(outside),
        Err(AirflowError::DateFilterOutOfScope)
    );
}

#[test]
fn tamper_revision_access_and_registration_fences_fail_closed() {
    let scope = scope();
    let mut service = ready_service(&scope);
    let mut evidence = service
        .read_evidence(AirflowReadRequest::for_task_instance())
        .expect("evidence");
    evidence.projection = AirflowRunProjection::Failed;
    assert_eq!(
        service.verify_run_evidence(&evidence),
        Err(AirflowError::EvidenceTampered)
    );

    let mut service = ready_service(&scope);
    service.unmount().expect("unmount");
    assert_eq!(
        service.read_evidence(AirflowReadRequest::for_task_instance()),
        Err(AirflowError::RegistrationInactive)
    );
    service.remount().expect("remount");
    service.revoke().expect("revoke");
    assert!(service.secret_reference().is_revoked());
    assert_eq!(
        service.read_evidence(AirflowReadRequest::for_task_instance()),
        Err(AirflowError::SecretRevoked)
    );

    let mut service = ready_service(&scope);
    service.provider_mut().registration_mut().run_digest = Digest::from_text("tampered");
    assert_eq!(
        service.read_evidence(AirflowReadRequest::for_task_instance()),
        Err(AirflowError::RegistrationTampered)
    );
}

#[test]
fn http_statuses_project_to_honest_fences_and_paths_are_get_only() {
    let statuses = [
        (401, AirflowRunProjection::AccessLoss),
        (403, AirflowRunProjection::AccessLoss),
        (404, AirflowRunProjection::Stale),
        (409, AirflowRunProjection::Stale),
        (429, AirflowRunProjection::ProviderUnknown),
        (503, AirflowRunProjection::ProviderUnknown),
    ];
    for (status, projection) in statuses {
        let error = AirflowError::HttpStatus { status, projection };
        assert_eq!(error.projection(), projection);
    }
    let scope = scope();
    for (status, projection) in [
        (401, AirflowRunProjection::AccessLoss),
        (403, AirflowRunProjection::AccessLoss),
        (404, AirflowRunProjection::Stale),
        (409, AirflowRunProjection::Stale),
        (429, AirflowRunProjection::ProviderUnknown),
        (503, AirflowRunProjection::ProviderUnknown),
    ] {
        let secret = SecretReference::bearer("secret-ref-airflow-http", &scope, status.into())
            .expect("secret");
        let transport =
            RecordingAirflowTransport::with_http_error(TransportProvenance::Recording, status);
        let mut provider =
            AirflowProvider::new(scope.clone(), secret, transport).expect("HTTP provider");
        let error = provider
            .read_evidence(AirflowReadRequest::for_task_instance())
            .expect_err("HTTP error");
        assert_eq!(error.status(), Some(status));
        assert_eq!(error.projection(), projection);
    }
    let secret = SecretReference::bearer("secret-ref-airflow-timeout", &scope, 10).expect("secret");
    let mut timeout = AirflowProvider::new(
        scope.clone(),
        secret,
        RecordingAirflowTransport::with_transport_error(
            TransportProvenance::Recording,
            hartevo_airflow_dag_result_plugin::AirflowTransportError::Timeout,
        ),
    )
    .expect("timeout provider");
    assert_eq!(
        timeout.read_evidence(AirflowReadRequest::for_task_instance()),
        Err(AirflowError::Timeout)
    );
    let secret =
        SecretReference::bearer("secret-ref-airflow-malformed", &scope, 11).expect("secret");
    let mut malformed = AirflowProvider::new(
        scope.clone(),
        secret,
        RecordingAirflowTransport::with_transport_error(
            TransportProvenance::Recording,
            hartevo_airflow_dag_result_plugin::AirflowTransportError::MalformedResponse,
        ),
    )
    .expect("malformed provider");
    assert_eq!(
        malformed.read_evidence(AirflowReadRequest::for_task_instance()),
        Err(AirflowError::PartialResponse)
    );
    assert_eq!(
        dag_run_endpoint_path(&scope),
        "/api/v1/dags/daily_orders/dagRuns/scheduled__2026-08-14"
    );
    assert_eq!(
        task_instances_endpoint_path(&scope),
        "/api/v1/dags/daily_orders/dagRuns/scheduled__2026-08-14/taskInstances"
    );
    assert_eq!(
        task_instance_endpoint_path(&scope),
        "/api/v1/dags/daily_orders/dagRuns/scheduled__2026-08-14/taskInstances/publish_orders"
    );
    assert_eq!(AirflowOperation::GetDagRun.method(), "GET");
    assert_eq!(AirflowOperation::ListTaskInstances.method(), "GET");
    assert_eq!(AirflowOperation::GetTaskInstance.method(), "GET");
}

#[test]
fn partial_payloads_run_id_drift_and_cursor_bounds_are_projected_or_rejected() {
    let scope = scope();
    let partial_page = AirflowPage::new(vec![task(&scope, AirflowState::Running)], 1, 0, 1, true);
    let secret = SecretReference::bearer("secret-ref-airflow-partial", &scope, 1).expect("secret");
    let mut partial = AirflowProvider::new(
        scope.clone(),
        secret,
        RecordingAirflowTransport::recording_with_pages(dag_run(&scope), [partial_page]),
    )
    .expect("partial provider");
    let evidence = partial
        .read_evidence(AirflowReadRequest::for_task_instances(0, 1).expect("request"))
        .expect("partial evidence");
    assert_eq!(evidence.projection, AirflowRunProjection::Partial);
    assert!(!evidence.complete);

    let drifted_run = AirflowDagRunRecord::new(
        scope.dag.clone(),
        AirflowRunIdentity::new("different-run", scope.run.revision).expect("drifted run"),
        scope.logical_date.clone(),
        AirflowState::Success,
    )
    .expect("drifted DAG run");
    let secret =
        SecretReference::bearer("secret-ref-airflow-run-drift", &scope, 2).expect("secret");
    let mut drifted = AirflowProvider::new(
        scope.clone(),
        secret,
        RecordingAirflowTransport::recording(
            drifted_run,
            page(vec![task(&scope, AirflowState::Success)], 1, 0),
        ),
    )
    .expect("drifted provider");
    assert_eq!(
        drifted.read_evidence(AirflowReadRequest::for_task_instance()),
        Err(AirflowError::RunMismatch)
    );

    assert_eq!(
        AirflowReadRequest::new(
            AirflowOperation::ListTaskInstances,
            0,
            MAX_PAGE_ITEMS + 1,
            None,
            None,
            [],
        ),
        Err(AirflowError::PaginationLimit)
    );
    assert_eq!(
        AirflowReadRequest::new(
            AirflowOperation::ListTaskInstances,
            MAX_TASK_INSTANCES + 1,
            1,
            None,
            None,
            [],
        ),
        Err(AirflowError::PaginationLimit)
    );
}

#[test]
fn redaction_and_registration_digests_are_deterministic_and_bounded() {
    let scope = scope();
    let first = RedactionEvidence::standard();
    let second = RedactionEvidence::standard();
    assert_eq!(first, second);
    first.validate().expect("redaction");
    let secret = SecretReference::bearer("secret-ref-airflow-digest", &scope, 4).expect("secret");
    let registration = AirflowRegistration::new(&scope, &secret).expect("registration");
    assert_eq!(
        registration.compute_digest(),
        registration.registration_digest
    );
    assert_eq!(registration.status(), RegistrationStatus::Active);
    assert!(registration.reversible);
    assert!(registration.revocable);
    assert_eq!(
        ReadLimits::default().validate().expect("limits").max_pages,
        32
    );
    assert_eq!(contract_digest(), contract_digest());
    assert!(BTreeSet::from([AirflowState::Success]).contains(&AirflowState::Success));
}

#[test]
fn blocked_environment_marker_is_not_a_connected_claim() {
    let provenance = EvidenceProvenance {
        transport: TransportProvenance::BlockedEnv,
        connected: false,
        native: false,
        first_party: false,
    };
    provenance.validate().expect("honest provenance");
}
