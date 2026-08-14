use std::collections::BTreeSet;

use hartevo_dbt_cloud_result_plugin::{
    AdoptionDisposition, ArtifactMetadata, DEFAULT_API_HOST, DbtCloudApiVersion, DbtCloudError,
    DbtCloudPage, DbtCloudPayload, DbtCloudPermission, DbtCloudProvider, DbtCloudResultService,
    DbtCloudScope, DbtCloudTransportError, Digest, EvidenceNodeKind, EvidenceNodeStatus,
    JobConfiguration, MissionDbtResultConsumer, MissionScopeBinding, RecordingDbtCloudTransport,
    RegistrationStatus, RunReadRequest, RunSnapshot, RunStatus, TransportKind,
};

const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OBSERVED_AT: u64 = 150;

fn scope() -> DbtCloudScope {
    let mission = MissionScopeBinding::new(
        "project-01",
        "mission-01",
        "work-product-01",
        3,
        4,
        5,
        Digest::from_text("policy-revision-3"),
        Digest::from_text("consent-revision-4"),
    )
    .expect("mission binding");
    DbtCloudScope::new(
        DbtCloudApiVersion::V2,
        DEFAULT_API_HOST,
        "account-01",
        "dbt-project-01",
        "environment-01",
        "job-01",
        hartevo_dbt_cloud_result_plugin::RepositoryIdentity::new(
            "github",
            "tangpingqingwa",
            "data-product",
            "https://github.com/tangpingqingwa/data-product",
        )
        .expect("repository"),
        COMMIT,
        ["model:orders".into()],
        ["test:orders".into()],
        ["run_results.json".into()],
        mission,
        [
            DbtCloudPermission::JobRead,
            DbtCloudPermission::RunRead,
            DbtCloudPermission::RunResultsRead,
            DbtCloudPermission::ArtifactMetadataRead,
        ],
    )
    .expect("scope")
}

fn run(scope: &DbtCloudScope, status: RunStatus) -> RunSnapshot {
    RunSnapshot::for_scope(scope, "run-01", status, Some(100), Some(110), Some(200)).expect("run")
}

fn model(
    scope: &DbtCloudScope,
    status: EvidenceNodeStatus,
) -> hartevo_dbt_cloud_result_plugin::ModelTestEvidence {
    hartevo_dbt_cloud_result_plugin::ModelTestEvidence::new(
        "model.data_product.orders",
        "orders",
        EvidenceNodeKind::Model,
        status,
        scope.selector_digest(),
        Some(30),
        None,
        Some("run".into()),
    )
    .expect("model evidence")
}

fn test(
    scope: &DbtCloudScope,
    status: EvidenceNodeStatus,
) -> hartevo_dbt_cloud_result_plugin::ModelTestEvidence {
    hartevo_dbt_cloud_result_plugin::ModelTestEvidence::new(
        "test.data_product.orders.not_null_id",
        "orders.not_null_id",
        EvidenceNodeKind::Test,
        status,
        scope.selector_digest(),
        Some(5),
        (status == EvidenceNodeStatus::Fail).then(|| Digest::from_text("failure")),
        Some("test".into()),
    )
    .expect("test evidence")
}

fn artifact(expiry: Option<u64>) -> ArtifactMetadata {
    ArtifactMetadata::new(
        "run_results.json",
        "run_results.json",
        512,
        Digest::from_text("run-results-body"),
        "application/json",
        Some(100),
        expiry,
    )
    .expect("artifact metadata")
}

fn transport(
    scope: &DbtCloudScope,
    status: RunStatus,
    test_status: EvidenceNodeStatus,
    artifact_expiry: Option<u64>,
) -> RecordingDbtCloudTransport {
    let mut transport = RecordingDbtCloudTransport::fixture();
    transport.push_job_response(Ok(DbtCloudPayload::new(JobConfiguration::for_scope(scope))));
    transport.push_job_response(Ok(DbtCloudPayload::new(JobConfiguration::for_scope(scope))));
    transport.push_run_response(Ok(DbtCloudPayload::new(run(scope, status))));
    transport.push_results_response(Ok(DbtCloudPage::new(
        0,
        None,
        None,
        vec![
            model(scope, EvidenceNodeStatus::Pass),
            test(scope, test_status),
        ],
    )));
    transport.push_artifacts_response(Ok(DbtCloudPage::new(
        0,
        None,
        None,
        vec![artifact(artifact_expiry)],
    )));
    transport
}

fn service(
    scope: DbtCloudScope,
    transport: RecordingDbtCloudTransport,
) -> DbtCloudResultService<RecordingDbtCloudTransport> {
    let secret =
        hartevo_dbt_cloud_result_plugin::SecretReference::new("secret-ref-dbt-fixture", &scope, 1)
            .expect("secret reference");
    DbtCloudResultService::new(DbtCloudProvider::new(transport), scope, secret).expect("service")
}

fn read_success(
    service: &mut DbtCloudResultService<RecordingDbtCloudTransport>,
) -> hartevo_dbt_cloud_result_plugin::RunEvidence {
    service.describe_job().expect("job");
    service.describe_job().expect("job replay");
    service
        .read_run_evidence(RunReadRequest::new("job-01", "run-01", OBSERVED_AT).expect("request"))
        .expect("evidence")
}

#[test]
fn service_definition_is_layer1_read_proposal_recording_only() {
    let definition = DbtCloudResultService::<RecordingDbtCloudTransport>::definition();
    assert_eq!(definition.layer, 1);
    assert!(definition.read_only);
    assert!(definition.proposal_only);
    assert!(definition.recording_only);
    assert!(!definition.connected);
    assert!(!definition.native);
    assert!(
        definition
            .forbidden_effects
            .iter()
            .any(|effect| effect == "trigger_live_job")
    );
    assert!(
        definition
            .forbidden_effects
            .iter()
            .any(|effect| effect == "adopt_kernel_outcome")
    );
}

#[test]
fn successful_recording_proposal_and_mission_consumer_are_exactly_bound() {
    let scope = scope();
    let mut service = service(
        scope.clone(),
        transport(
            &scope,
            RunStatus::Success,
            EvidenceNodeStatus::Pass,
            Some(200),
        ),
    );
    let evidence = read_success(&mut service);
    assert_eq!(evidence.status, RunStatus::Success);
    assert_eq!(evidence.test_summary.pass_count, 2);
    assert_eq!(evidence.artifact_metadata.len(), 1);
    assert!(!evidence.provenance.connected);
    assert!(!evidence.provenance.native);

    let recording = service.record_run_receipt(&evidence).expect("record");
    assert!(!recording.durable);
    assert!(!recording.connected);
    assert!(!recording.native);
    let replay = service.record_run_receipt(&evidence).expect("replay");
    assert_eq!(
        replay.disposition,
        hartevo_dbt_cloud_result_plugin::RecordingDisposition::Replay
    );

    let proposal = service
        .compile_transformation_proposal(&evidence)
        .expect("proposal");
    assert_eq!(proposal.adoption, AdoptionDisposition::Layer2Required);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    let mut consumer = MissionDbtResultConsumer::new(&scope).expect("consumer");
    let mission_result = consumer.consume(&proposal).expect("consume");
    assert_eq!(mission_result.mission_id, "mission-01");
    assert_eq!(mission_result.work_product_id, "work-product-01");
    assert!(!mission_result.adopted);
    assert!(!mission_result.connected);
    assert!(!mission_result.native);
    let mission_replay = consumer.consume(&proposal).expect("consumer replay");
    assert_eq!(
        mission_replay.disposition,
        hartevo_dbt_cloud_result_plugin::MissionConsumptionDisposition::Replay
    );

    let audits = service.provider().transport().requests();
    assert!(audits.iter().all(|audit| !audit.connected && !audit.native));
}

#[test]
fn secret_reference_and_recordings_never_serialize_raw_credentials() {
    let scope = scope();
    let secret =
        hartevo_dbt_cloud_result_plugin::SecretReference::new("secret-ref-dbt-fixture", &scope, 7)
            .expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("dbt_api_token"));
    assert!(!debug.contains("fixture-token"));
    assert!(
        serde_json::to_string(&scope)
            .expect("scope json")
            .contains("account-01")
    );

    let transport = transport(
        &scope,
        RunStatus::Success,
        EvidenceNodeStatus::Pass,
        Some(200),
    );
    let mut service = service(scope, transport);
    let evidence = read_success(&mut service);
    let recording = service.record_run_receipt(&evidence).expect("recording");
    let json = serde_json::to_string(&recording).expect("recording json");
    assert!(!json.contains("dbt_api_token"));
    assert!(!json.contains("fixture-token"));
    assert!(!json.contains("raw_logs"));
}

#[test]
fn commit_job_and_selector_drift_fail_closed() {
    let scope = scope();
    let mut job_drift = JobConfiguration::for_scope(&scope);
    job_drift.job_id = "job-other".into();
    let mut job_transport = RecordingDbtCloudTransport::fixture();
    job_transport.push_job_response(Ok(DbtCloudPayload::new(job_drift)));
    let mut job_service = service(scope.clone(), job_transport);
    assert_eq!(job_service.describe_job(), Err(DbtCloudError::JobMismatch));

    let mut commit_drift = run(&scope, RunStatus::Success);
    commit_drift.commit_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
    let mut commit_transport = RecordingDbtCloudTransport::fixture();
    commit_transport.push_run_response(Ok(DbtCloudPayload::new(commit_drift)));
    let mut commit_service = service(scope.clone(), commit_transport);
    assert_eq!(
        commit_service.read_run_evidence(
            RunReadRequest::new("job-01", "run-01", OBSERVED_AT).expect("request")
        ),
        Err(DbtCloudError::CommitMismatch)
    );

    let mut selection_drift = run(&scope, RunStatus::Success);
    selection_drift.selector_digest = Digest::from_text("selector-drift");
    let mut selection_transport = RecordingDbtCloudTransport::fixture();
    selection_transport.push_run_response(Ok(DbtCloudPayload::new(selection_drift)));
    let mut selection_service = service(scope, selection_transport);
    assert_eq!(
        selection_service.read_run_evidence(
            RunReadRequest::new("job-01", "run-01", OBSERVED_AT).expect("request")
        ),
        Err(DbtCloudError::SelectionDrift)
    );
}

#[test]
fn pagination_is_bounded_and_repeated_cursor_is_rejected() {
    let scope = scope();
    let mut transport = RecordingDbtCloudTransport::fixture();
    transport.push_job_response(Ok(DbtCloudPayload::new(JobConfiguration::for_scope(
        &scope,
    ))));
    transport.push_job_response(Ok(DbtCloudPayload::new(JobConfiguration::for_scope(
        &scope,
    ))));
    transport.push_run_response(Ok(DbtCloudPayload::new(run(&scope, RunStatus::Success))));
    transport.push_results_response(Ok(DbtCloudPage::new(
        0,
        None,
        Some("cursor-1".into()),
        vec![model(&scope, EvidenceNodeStatus::Pass)],
    )));
    transport.push_results_response(Ok(DbtCloudPage::new(
        1,
        Some("cursor-1".into()),
        None,
        vec![test(&scope, EvidenceNodeStatus::Pass)],
    )));
    transport.push_artifacts_response(Ok(DbtCloudPage::new(
        0,
        None,
        None,
        vec![artifact(Some(200))],
    )));
    let mut paged_service = service(scope.clone(), transport);
    let evidence = read_success(&mut paged_service);
    assert_eq!(evidence.results_pages_read, 2);

    let mut repeated = RecordingDbtCloudTransport::fixture();
    repeated.push_run_response(Ok(DbtCloudPayload::new(run(&scope, RunStatus::Success))));
    repeated.push_results_response(Ok(DbtCloudPage::new(
        0,
        None,
        Some("cursor-loop".into()),
        vec![model(&scope, EvidenceNodeStatus::Pass)],
    )));
    repeated.push_results_response(Ok(DbtCloudPage::new(
        1,
        Some("cursor-loop".into()),
        Some("cursor-loop".into()),
        vec![test(&scope, EvidenceNodeStatus::Pass)],
    )));
    let mut repeated_service = service(scope, repeated);
    assert_eq!(
        repeated_service.read_run_evidence(
            RunReadRequest::new("job-01", "run-01", OBSERVED_AT).expect("request")
        ),
        Err(DbtCloudError::PaginationRepeatedCursor)
    );
}

#[test]
fn expiry_partial_and_error_projections_are_explicit() {
    let scope = scope();
    let mut expired_service = service(
        scope.clone(),
        transport(
            &scope,
            RunStatus::Success,
            EvidenceNodeStatus::Pass,
            Some(120),
        ),
    );
    let expired = read_success(&mut expired_service);
    assert_eq!(expired.status, RunStatus::Expired);
    let expired_projection = expired_service
        .verify_data_product_result(&expired)
        .expect("expired projection");
    assert_eq!(expired_projection.status, RunStatus::Expired);
    assert_eq!(
        expired_projection.adoption,
        AdoptionDisposition::BlockedByProjection
    );

    let mut partial_service = service(
        scope.clone(),
        transport(
            &scope,
            RunStatus::Success,
            EvidenceNodeStatus::Fail,
            Some(200),
        ),
    );
    let partial = read_success(&mut partial_service);
    assert_eq!(partial.status, RunStatus::Partial);
    assert!(
        !partial_service
            .verify_data_product_result(&partial)
            .expect("partial projection")
            .bounded_evidence_verified
    );

    let mut error_service = service(
        scope.clone(),
        transport(
            &scope,
            RunStatus::Error,
            EvidenceNodeStatus::Pass,
            Some(200),
        ),
    );
    let error = read_success(&mut error_service);
    assert_eq!(error.status, RunStatus::Error);

    let mut cancelled_service = service(
        scope.clone(),
        transport(
            &scope,
            RunStatus::Cancelled,
            EvidenceNodeStatus::Pass,
            Some(200),
        ),
    );
    assert_eq!(
        read_success(&mut cancelled_service).status,
        RunStatus::Cancelled
    );
}

#[test]
fn http_access_loss_provider_unknown_timeout_and_blocked_env_map_to_projections() {
    let cases = [
        (401, RunStatus::AccessLoss),
        (403, RunStatus::AccessLoss),
        (404, RunStatus::Expired),
        (409, RunStatus::ProviderUnknown),
        (429, RunStatus::ProviderUnknown),
        (500, RunStatus::ProviderUnknown),
        (503, RunStatus::ProviderUnknown),
    ];
    for (status, projection) in cases {
        let current_scope = scope();
        let mut transport = RecordingDbtCloudTransport::fixture();
        transport.fail_with(DbtCloudTransportError::HttpStatus {
            status,
            retry_after_seconds: (status == 429).then_some(3),
        });
        let mut service = service(current_scope, transport);
        let error = service
            .read_run_evidence(
                RunReadRequest::new("job-01", "run-01", OBSERVED_AT).expect("request"),
            )
            .expect_err("HTTP failure");
        assert_eq!(error.status(), Some(status));
        assert_eq!(service.projection_for_error(&error), projection);
    }

    let current_scope = scope();
    let mut blocked_service = service(current_scope, RecordingDbtCloudTransport::blocked_env());
    let blocked = blocked_service
        .read_run_evidence(RunReadRequest::new("job-01", "run-01", OBSERVED_AT).expect("request"))
        .expect_err("blocked env");
    assert_eq!(blocked, DbtCloudError::BlockedEnv);
    assert_eq!(
        blocked_service.projection_for_error(&blocked),
        RunStatus::ProviderUnknown
    );

    let current_scope = scope();
    let mut timed_out_transport = RecordingDbtCloudTransport::fixture();
    timed_out_transport.fail_with(DbtCloudTransportError::Timeout);
    let mut timed_out_service = service(current_scope, timed_out_transport);
    let timed_out = timed_out_service
        .read_run_evidence(RunReadRequest::new("job-01", "run-01", OBSERVED_AT).expect("request"))
        .expect_err("timeout");
    assert_eq!(timed_out, DbtCloudError::Timeout);
    assert_eq!(
        timed_out_service.projection_for_error(&timed_out),
        RunStatus::ProviderUnknown
    );
}

#[test]
fn tamper_and_truncation_are_rejected_before_projection() {
    let scope = scope();
    let run = run(&scope, RunStatus::Success);
    let mut tampered_transport = RecordingDbtCloudTransport::fixture();
    tampered_transport.push_run_response(Ok(DbtCloudPayload::new(run.clone())
        .with_transport_metadata(128, false, Digest::from_text("tampered-response"))));
    let mut tampered_service = service(scope.clone(), tampered_transport);
    assert_eq!(
        tampered_service.read_run_evidence(
            RunReadRequest::new("job-01", "run-01", OBSERVED_AT).expect("request")
        ),
        Err(DbtCloudError::PayloadTampered)
    );

    let mut truncated_transport = RecordingDbtCloudTransport::fixture();
    let original = DbtCloudPayload::new(run);
    truncated_transport.push_run_response(Ok(original.clone().with_transport_metadata(
        128,
        true,
        original.response_digest.clone(),
    )));
    let mut truncated_service = service(scope, truncated_transport);
    assert_eq!(
        truncated_service.read_run_evidence(
            RunReadRequest::new("job-01", "run-01", OBSERVED_AT).expect("request")
        ),
        Err(DbtCloudError::PayloadTruncated)
    );
}

#[test]
fn registration_unmount_is_reversible_and_revoke_is_terminal() {
    let scope = scope();
    let mut service = service(
        scope.clone(),
        transport(
            &scope,
            RunStatus::Success,
            EvidenceNodeStatus::Pass,
            Some(200),
        ),
    );
    assert_eq!(service.registration().status, RegistrationStatus::Active);
    service.unmount().expect("unmount");
    assert_eq!(
        service.describe_job(),
        Err(DbtCloudError::RegistrationInactive)
    );
    service.remount().expect("remount");
    service.describe_job().expect("remounted read");
    let revocation = service.revoke();
    assert_eq!(revocation.status, RegistrationStatus::Revoked);
    assert_eq!(
        service.describe_job(),
        Err(DbtCloudError::RegistrationRevoked)
    );
    assert_eq!(service.remount(), Err(DbtCloudError::RegistrationRevoked));
}

#[test]
fn duplicate_run_conflict_and_consumer_scope_drift_are_rejected() {
    let scope = scope();
    let mut service = service(
        scope.clone(),
        transport(
            &scope,
            RunStatus::Success,
            EvidenceNodeStatus::Pass,
            Some(200),
        ),
    );
    let evidence = read_success(&mut service);
    service
        .record_run_receipt(&evidence)
        .expect("first recording");
    let mut conflicting = evidence.clone();
    conflicting.status = RunStatus::Partial;
    conflicting.evidence_digest = conflicting.compute_digest();
    assert_eq!(
        service.record_run_receipt(&conflicting),
        Err(DbtCloudError::DuplicateRun)
    );

    let proposal = service
        .compile_transformation_proposal(&evidence)
        .expect("proposal");
    let mut drifted_proposal = proposal.clone();
    drifted_proposal.scope.mission.mission_id = "mission-other".into();
    drifted_proposal.proposal_digest = drifted_proposal.compute_digest();
    let mut consumer = MissionDbtResultConsumer::new(&scope).expect("consumer");
    assert_eq!(
        consumer.consume(&drifted_proposal),
        Err(DbtCloudError::MissionScopeMismatch)
    );
}

#[test]
fn json_contract_and_transport_kind_keep_fixture_honesty_explicit() {
    let scope = scope();
    let transports = [
        RecordingDbtCloudTransport::fixture(),
        RecordingDbtCloudTransport::new(TransportKind::Recording).expect("recording"),
        RecordingDbtCloudTransport::fake(),
        RecordingDbtCloudTransport::loopback(),
        RecordingDbtCloudTransport::blocked_env(),
    ];
    assert_eq!(
        transports
            .iter()
            .map(hartevo_dbt_cloud_result_plugin::DbtCloudTransport::kind)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            TransportKind::Fixture,
            TransportKind::Recording,
            TransportKind::Fake,
            TransportKind::Loopback,
            TransportKind::BlockedEnv
        ])
    );
    let definition_json =
        serde_json::to_string(&DbtCloudResultService::<RecordingDbtCloudTransport>::definition())
            .expect("definition json");
    assert!(definition_json.contains("\"connected\":false"));
    assert!(definition_json.contains("\"native\":false"));
    assert!(!definition_json.contains("trigger_live_job\":true"));
    assert!(scope.scope_digest().is_valid());
}
