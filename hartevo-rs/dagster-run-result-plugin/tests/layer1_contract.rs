use std::collections::BTreeSet;

use hartevo_dagster_run_result_plugin::{
    AdoptionDisposition, DagsterAssetDescription, DagsterAssetIdentity,
    DagsterAssetMaterialization, DagsterCodeLocationDescription, DagsterCodeLocationIdentity,
    DagsterCommitReference, DagsterDeploymentDescription, DagsterDeploymentIdentity, DagsterError,
    DagsterEventKind, DagsterEventStatus, DagsterEventSummary, DagsterJobDescription,
    DagsterJobIdentity, DagsterOperation, DagsterPage, DagsterPartitionIdentity, DagsterPayload,
    DagsterPermission, DagsterProvider, DagsterRegistration, DagsterRegistrationRegistry,
    DagsterRepositoryDescription, DagsterRepositoryIdentity, DagsterRunEvidence,
    DagsterRunIdentity, DagsterRunReadRequest, DagsterRunResultProposal, DagsterRunResultService,
    DagsterRunSnapshot, DagsterRunStatus, DagsterScope, DagsterServiceDefinition,
    DagsterTransportError, MAX_PAGE_ITEMS, MissionDagsterRunConsumer, MissionScopeBinding,
    ReadLimits, RecordingDagsterTransport, RedactionEvidence, RegistrationStatus, SecretReference,
    TransportProvenance, contract_digest,
};

const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OBSERVED_AT: u64 = 1_744_550_401;

fn scope() -> DagsterScope {
    let mission = MissionScopeBinding::new(
        "project-dagster-01",
        "mission-dagster-01",
        "work-product-dagster-01",
        3,
        4,
        5,
        hartevo_dagster_run_result_plugin::Digest::from_text("policy-revision-3"),
        hartevo_dagster_run_result_plugin::Digest::from_text("consent-revision-4"),
    )
    .expect("mission scope");
    DagsterScope::new(
        DagsterDeploymentIdentity::new("https://dagster.example", "prod", 1).expect("deployment"),
        DagsterRepositoryIdentity::new("analytics", 2).expect("repository"),
        DagsterCodeLocationIdentity::new("analytics-location", 3).expect("code location"),
        DagsterJobIdentity::new("daily_assets", 4).expect("job"),
        DagsterRunIdentity::new("run-dagster-01", 5).expect("run"),
        Some(DagsterPartitionIdentity::new("2026-08-14", 6).expect("partition")),
        DagsterAssetIdentity::new(["analytics".into(), "orders".into()], 7).expect("asset"),
        DagsterCommitReference::new(COMMIT, 8).expect("commit"),
        mission,
        [
            DagsterPermission::DeploymentRead,
            DagsterPermission::RepositoryRead,
            DagsterPermission::CodeLocationRead,
            DagsterPermission::JobRead,
            DagsterPermission::RunRead,
            DagsterPermission::EventRead,
            DagsterPermission::AssetRead,
            DagsterPermission::PartitionRead,
            DagsterPermission::CommitRead,
            DagsterPermission::MissionScope,
        ],
    )
    .expect("scope")
}

fn materialization(scope: &DagsterScope) -> DagsterAssetMaterialization {
    DagsterAssetMaterialization::for_scope(
        scope,
        "materialize_orders",
        hartevo_dagster_run_result_plugin::Digest::from_text("data-version-01"),
        OBSERVED_AT,
    )
    .expect("materialization")
}

fn events(scope: &DagsterScope, include_materialization: bool) -> Vec<DagsterEventSummary> {
    let mut events = vec![
        DagsterEventSummary::new(
            "event-step-01",
            DagsterEventKind::Step,
            DagsterEventStatus::Success,
            Some("materialize_orders".into()),
            Some(42),
            hartevo_dagster_run_result_plugin::Digest::from_text("step-metadata"),
            None,
            OBSERVED_AT,
        )
        .expect("step event"),
    ];
    if include_materialization {
        events.push(
            DagsterEventSummary::materialization(
                "event-materialization-01",
                materialization(scope),
            )
            .expect("materialization event"),
        );
    }
    events
}

fn service(
    scope: DagsterScope,
    status: DagsterRunStatus,
    include_materialization: bool,
) -> DagsterRunResultService<RecordingDagsterTransport> {
    let mut transport = RecordingDagsterTransport::recording();
    transport.push_run_response(Ok(DagsterPayload::new(DagsterRunSnapshot::for_scope(
        &scope, status,
    ))));
    transport.push_events_response(Ok(DagsterPage::new(
        DagsterOperation::ReadEvents,
        0,
        None,
        None,
        events(&scope, include_materialization),
    )));
    let secret = SecretReference::deployment_token("secret-ref-dagster-fixture", &scope, 1)
        .expect("secret reference");
    DagsterRunResultService::new(DagsterProvider::new(transport), scope, secret).expect("service")
}

#[test]
fn contract_is_exact_layer_one_and_non_native() {
    let definition = DagsterServiceDefinition::layer1();
    assert_eq!(definition.layer, 1);
    assert!(definition.read_only);
    assert!(definition.proposal_only);
    assert!(definition.recording_only);
    assert!(!definition.connected);
    assert!(!definition.native);
    assert!(!definition.first_party);
    assert!(definition.forbidden_effects.contains(&"launch_run"));
    assert!(definition.forbidden_effects.contains(&"terminate_run"));
    assert!(definition.forbidden_effects.contains(&"retain_raw_logs"));
    assert!(
        definition
            .operations
            .contains(&DagsterOperation::ReadEvents)
    );
    assert!(DagsterOperation::ReadRun.is_read_only());
    assert_eq!(contract_digest().as_str().len(), 64);
    assert!(hartevo_dagster_run_result_plugin::CONTRACT_JSON.contains("provider_unknown"));
}

#[test]
fn successful_recording_proposal_consumer_and_replay_are_exactly_bound() {
    let current_scope = scope();
    let mut service = service(current_scope.clone(), DagsterRunStatus::Success, true);
    let evidence = service
        .read_run_evidence(
            DagsterRunReadRequest::new("run-dagster-01", OBSERVED_AT).expect("request"),
        )
        .expect("evidence");
    assert_eq!(evidence.status, DagsterRunStatus::Success);
    assert_eq!(evidence.pages_read, 1);
    assert_eq!(evidence.steps.len(), 1);
    assert_eq!(evidence.materializations.len(), 1);
    assert_eq!(evidence.data_version_digests.len(), 1);
    assert!(evidence.materialization_verified);
    assert!(!evidence.provenance.connected);
    assert!(!evidence.provenance.native);
    assert!(!evidence.provenance.first_party);

    let recording = service.record_run_receipt(&evidence).expect("recording");
    assert!(!recording.durable);
    assert!(!recording.connected);
    assert!(!recording.native);
    assert!(!recording.replayed);
    let replay = service
        .record_run_receipt(&evidence)
        .expect("recording replay");
    assert!(replay.replayed);

    let proposal = service
        .compile_run_result_proposal(&evidence)
        .expect("proposal");
    assert_eq!(proposal.adoption, AdoptionDisposition::Layer2Required);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    let mut consumer = MissionDagsterRunConsumer::new(&current_scope).expect("consumer");
    let result = consumer.consume(&proposal).expect("mission result");
    assert_eq!(result.project_id, "project-dagster-01");
    assert_eq!(result.mission_id, "mission-dagster-01");
    assert_eq!(result.work_product_id, "work-product-dagster-01");
    assert!(!result.adopted);
    assert!(!result.connected);
    assert!(!result.native);
    let replayed = consumer.consume(&proposal).expect("mission replay");
    assert_eq!(
        replayed.disposition,
        hartevo_dagster_run_result_plugin::MissionConsumptionDisposition::Replay
    );

    let audits = service.provider().transport().requests();
    assert_eq!(audits.len(), 2);
    assert!(
        audits
            .iter()
            .all(|audit| !audit.connected && !audit.native && !audit.first_party)
    );
    assert!(audits.iter().all(|audit| audit.page_size <= MAX_PAGE_ITEMS));
}

#[test]
fn descriptions_are_read_only_and_scope_bound() {
    let current_scope = scope();
    let mut transport = RecordingDagsterTransport::recording();
    transport.push_deployment_response(Ok(DagsterPayload::new(
        DagsterDeploymentDescription::for_scope(&current_scope),
    )));
    transport.push_repository_response(Ok(DagsterPayload::new(
        DagsterRepositoryDescription::for_scope(&current_scope),
    )));
    transport.push_code_location_response(Ok(DagsterPayload::new(
        DagsterCodeLocationDescription::for_scope(&current_scope),
    )));
    transport.push_job_response(Ok(DagsterPayload::new(DagsterJobDescription::for_scope(
        &current_scope,
    ))));
    transport.push_asset_response(Ok(DagsterPayload::new(DagsterAssetDescription::for_scope(
        &current_scope,
    ))));
    let secret = SecretReference::api_secret("secret-ref-dagster-describe", &current_scope, 1)
        .expect("secret");
    let mut service =
        DagsterRunResultService::new(DagsterProvider::new(transport), current_scope, secret)
            .expect("service");
    assert_eq!(
        service
            .describe_deployment()
            .expect("deployment")
            .repository_count,
        1
    );
    assert_eq!(
        service
            .describe_repository()
            .expect("repository")
            .job_names
            .len(),
        1
    );
    assert_eq!(
        service
            .describe_code_location()
            .expect("location")
            .load_status,
        "loaded"
    );
    assert_eq!(service.describe_job().expect("job").asset_keys.len(), 1);
    assert_eq!(service.describe_asset().expect("asset").asset.path.len(), 2);
}

#[test]
fn run_state_transitions_and_projection_are_bounded() {
    let current_scope = scope();
    let mut transport = RecordingDagsterTransport::recording();
    transport.push_run_response(Ok(DagsterPayload::new(DagsterRunSnapshot::for_scope(
        &current_scope,
        DagsterRunStatus::Started,
    ))));
    transport.push_events_response(Ok(DagsterPage::new(
        DagsterOperation::ReadEvents,
        0,
        None,
        None,
        events(&current_scope, false),
    )));
    transport.push_run_response(Ok(DagsterPayload::new(DagsterRunSnapshot::for_scope(
        &current_scope,
        DagsterRunStatus::Success,
    ))));
    transport.push_events_response(Ok(DagsterPage::new(
        DagsterOperation::ReadEvents,
        0,
        None,
        None,
        events(&current_scope, true),
    )));
    transport.push_run_response(Ok(DagsterPayload::new(DagsterRunSnapshot::for_scope(
        &current_scope,
        DagsterRunStatus::Queued,
    ))));
    let secret = SecretReference::deployment_token("secret-ref-dagster-state", &current_scope, 1)
        .expect("secret");
    let mut service = DagsterRunResultService::new(
        DagsterProvider::new(transport),
        current_scope.clone(),
        secret,
    )
    .expect("service");
    service
        .read_run_evidence(DagsterRunReadRequest::new("run-dagster-01", 1).expect("request"))
        .expect("started");
    let success = service
        .read_run_evidence(DagsterRunReadRequest::new("run-dagster-01", 2).expect("request"))
        .expect("success");
    assert_eq!(success.status, DagsterRunStatus::Success);
    assert_eq!(
        service
            .read_run_evidence(DagsterRunReadRequest::new("run-dagster-01", 3).expect("request"))
            .expect_err("terminal state regressed"),
        DagsterError::InvalidStateTransition
    );

    let mut first = DagsterRunSnapshot::for_scope(&current_scope, DagsterRunStatus::Success);
    let second = DagsterRunSnapshot::for_scope(&current_scope, DagsterRunStatus::Started);
    assert_eq!(
        first.validate_transition(&second),
        Err(DagsterError::InvalidStateTransition)
    );
    first.status = DagsterRunStatus::Queued;
    first.reseal();
    assert_eq!(first.status, DagsterRunStatus::Queued);
}

fn service_error_for_snapshot(
    snapshot: DagsterRunSnapshot,
    current_scope: &DagsterScope,
) -> DagsterError {
    let mut transport = RecordingDagsterTransport::recording();
    transport.push_run_response(Ok(DagsterPayload::new(snapshot)));
    let secret = SecretReference::deployment_token("secret-ref-dagster-drift", current_scope, 1)
        .expect("secret");
    let mut service = DagsterRunResultService::new(
        DagsterProvider::new(transport),
        current_scope.clone(),
        secret,
    )
    .expect("service");
    service
        .read_run_evidence(DagsterRunReadRequest::new("run-dagster-01", 1).expect("request"))
        .expect_err("drift accepted")
}

#[test]
fn deployment_repository_code_location_job_run_partition_asset_and_commit_drift_fail_closed() {
    let current_scope = scope();
    let mut snapshot = DagsterRunSnapshot::for_scope(&current_scope, DagsterRunStatus::Success);
    snapshot.deployment.deployment_id = "other-deployment".into();
    snapshot.reseal();
    assert_eq!(
        service_error_for_snapshot(snapshot, &current_scope),
        DagsterError::DeploymentMismatch
    );

    let mut snapshot = DagsterRunSnapshot::for_scope(&current_scope, DagsterRunStatus::Success);
    snapshot.repository.name = "other-repository".into();
    snapshot.reseal();
    assert_eq!(
        service_error_for_snapshot(snapshot, &current_scope),
        DagsterError::RepositoryMismatch
    );

    let mut snapshot = DagsterRunSnapshot::for_scope(&current_scope, DagsterRunStatus::Success);
    snapshot.code_location.name = "other-location".into();
    snapshot.reseal();
    assert_eq!(
        service_error_for_snapshot(snapshot, &current_scope),
        DagsterError::CodeLocationMismatch
    );

    let mut snapshot = DagsterRunSnapshot::for_scope(&current_scope, DagsterRunStatus::Success);
    snapshot.job.name = "other-job".into();
    snapshot.reseal();
    assert_eq!(
        service_error_for_snapshot(snapshot, &current_scope),
        DagsterError::JobMismatch
    );

    let mut snapshot = DagsterRunSnapshot::for_scope(&current_scope, DagsterRunStatus::Success);
    snapshot.run.run_id = "other-run".into();
    snapshot.reseal();
    assert_eq!(
        service_error_for_snapshot(snapshot, &current_scope),
        DagsterError::RunMismatch
    );

    let mut snapshot = DagsterRunSnapshot::for_scope(&current_scope, DagsterRunStatus::Success);
    snapshot.partition = None;
    snapshot.reseal();
    assert_eq!(
        service_error_for_snapshot(snapshot, &current_scope),
        DagsterError::PartitionMismatch
    );

    let mut snapshot = DagsterRunSnapshot::for_scope(&current_scope, DagsterRunStatus::Success);
    snapshot.asset.path = vec!["other".into(), "asset".into()];
    snapshot.reseal();
    assert_eq!(
        service_error_for_snapshot(snapshot, &current_scope),
        DagsterError::AssetMismatch
    );

    let mut snapshot = DagsterRunSnapshot::for_scope(&current_scope, DagsterRunStatus::Success);
    snapshot.commit.sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
    snapshot.reseal();
    assert_eq!(
        service_error_for_snapshot(snapshot, &current_scope),
        DagsterError::CommitMismatch
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn graphql_pagination_digests_and_redaction_bounds_fail_closed() {
    let current_scope = scope();
    let mut transport = RecordingDagsterTransport::recording();
    transport.push_run_response(Ok(DagsterPayload::new(DagsterRunSnapshot::for_scope(
        &current_scope,
        DagsterRunStatus::Success,
    ))));
    transport.push_events_response(Ok(DagsterPage::new(
        DagsterOperation::ReadEvents,
        0,
        None,
        Some("cursor-1".into()),
        vec![events(&current_scope, false).remove(0)],
    )));
    transport.push_events_response(Ok(DagsterPage::new(
        DagsterOperation::ReadEvents,
        1,
        Some("cursor-1".into()),
        None,
        vec![
            DagsterEventSummary::materialization(
                "event-materialization-01",
                materialization(&current_scope),
            )
            .expect("materialization"),
        ],
    )));
    let secret =
        SecretReference::deployment_token("secret-ref-dagster-pagination", &current_scope, 1)
            .expect("secret");
    let mut service = DagsterRunResultService::new(
        DagsterProvider::new(transport),
        current_scope.clone(),
        secret,
    )
    .expect("service");
    let evidence = service
        .read_run_evidence(DagsterRunReadRequest::new("run-dagster-01", 1).expect("request"))
        .expect("paged evidence");
    assert_eq!(evidence.pages_read, 2);
    assert_eq!(evidence.total_events, 2);

    let mut repeated = RecordingDagsterTransport::recording();
    repeated.push_run_response(Ok(DagsterPayload::new(DagsterRunSnapshot::for_scope(
        &current_scope,
        DagsterRunStatus::Success,
    ))));
    repeated.push_events_response(Ok(DagsterPage::new(
        DagsterOperation::ReadEvents,
        0,
        None,
        Some("loop".into()),
        vec![events(&current_scope, false).remove(0)],
    )));
    repeated.push_events_response(Ok(DagsterPage::new(
        DagsterOperation::ReadEvents,
        1,
        Some("loop".into()),
        Some("loop".into()),
        vec![
            DagsterEventSummary::materialization(
                "event-materialization-01",
                materialization(&current_scope),
            )
            .expect("materialization"),
        ],
    )));
    let mut repeated_service = DagsterRunResultService::new(
        DagsterProvider::new(repeated),
        current_scope.clone(),
        SecretReference::deployment_token("secret-ref-dagster-repeat", &current_scope, 1)
            .expect("secret"),
    )
    .expect("service");
    assert_eq!(
        repeated_service
            .read_run_evidence(DagsterRunReadRequest::new("run-dagster-01", 1).expect("request"))
            .expect_err("cursor loop accepted"),
        DagsterError::PaginationRepeatedCursor
    );

    let tampered = DagsterPage::new(
        DagsterOperation::ReadEvents,
        0,
        None,
        None,
        events(&current_scope, true),
    )
    .with_transport_metadata(
        64,
        false,
        hartevo_dagster_run_result_plugin::Digest::from_text("tampered"),
    );
    let mut tampered_transport = RecordingDagsterTransport::recording();
    tampered_transport.push_run_response(Ok(DagsterPayload::new(DagsterRunSnapshot::for_scope(
        &current_scope,
        DagsterRunStatus::Success,
    ))));
    tampered_transport.push_events_response(Ok(tampered));
    let mut tampered_service = DagsterRunResultService::new(
        DagsterProvider::new(tampered_transport),
        current_scope.clone(),
        SecretReference::deployment_token("secret-ref-dagster-tamper", &current_scope, 1)
            .expect("secret"),
    )
    .expect("service");
    assert_eq!(
        tampered_service
            .read_run_evidence(DagsterRunReadRequest::new("run-dagster-01", 1).expect("request"))
            .expect_err("tampered page accepted"),
        DagsterError::PayloadTampered
    );

    let partial = DagsterPage::new(
        DagsterOperation::ReadEvents,
        0,
        None,
        None,
        events(&current_scope, true),
    )
    .with_event_metadata(true, RedactionEvidence::default());
    let mut partial_transport = RecordingDagsterTransport::recording();
    partial_transport.push_run_response(Ok(DagsterPayload::new(DagsterRunSnapshot::for_scope(
        &current_scope,
        DagsterRunStatus::Success,
    ))));
    partial_transport.push_events_response(Ok(partial));
    let mut partial_service = DagsterRunResultService::new(
        DagsterProvider::new(partial_transport),
        current_scope.clone(),
        SecretReference::deployment_token("secret-ref-dagster-partial", &current_scope, 1)
            .expect("secret"),
    )
    .expect("service");
    assert_eq!(
        partial_service
            .read_run_evidence(DagsterRunReadRequest::new("run-dagster-01", 1).expect("request"))
            .expect_err("partial page accepted"),
        DagsterError::PartialResponse
    );

    let redacted = DagsterPage::new(
        DagsterOperation::ReadEvents,
        0,
        None,
        None,
        events(&current_scope, true),
    )
    .with_event_metadata(
        false,
        RedactionEvidence {
            raw_logs_retained: true,
            ..RedactionEvidence::default()
        },
    );
    let mut redacted_transport = RecordingDagsterTransport::recording();
    redacted_transport.push_run_response(Ok(DagsterPayload::new(DagsterRunSnapshot::for_scope(
        &current_scope,
        DagsterRunStatus::Success,
    ))));
    redacted_transport.push_events_response(Ok(redacted));
    let mut redacted_service = DagsterRunResultService::new(
        DagsterProvider::new(redacted_transport),
        current_scope.clone(),
        SecretReference::deployment_token("secret-ref-dagster-redaction", &current_scope, 1)
            .expect("secret"),
    )
    .expect("service");
    assert_eq!(
        redacted_service
            .read_run_evidence(DagsterRunReadRequest::new("run-dagster-01", 1).expect("request"))
            .expect_err("raw log retention accepted"),
        DagsterError::RedactionViolation
    );
}

#[test]
fn http_timeout_and_blocked_environment_projections_are_honest() {
    let cases = [
        (401, DagsterRunStatus::AccessLoss),
        (403, DagsterRunStatus::AccessLoss),
        (404, DagsterRunStatus::Invalid),
        (409, DagsterRunStatus::ProviderUnknown),
        (429, DagsterRunStatus::ProviderUnknown),
        (500, DagsterRunStatus::ProviderUnknown),
        (503, DagsterRunStatus::ProviderUnknown),
    ];
    for (http_status, projection) in cases {
        let current_scope = scope();
        let mut transport = RecordingDagsterTransport::recording();
        transport.fail_with(DagsterTransportError::HttpStatus {
            status: http_status,
            retry_after_seconds: (http_status == 429).then_some(3),
        });
        let mut service = DagsterRunResultService::new(
            DagsterProvider::new(transport),
            current_scope.clone(),
            SecretReference::deployment_token("secret-ref-dagster-http", &current_scope, 1)
                .expect("secret"),
        )
        .expect("service");
        let error = service
            .read_run_evidence(DagsterRunReadRequest::new("run-dagster-01", 1).expect("request"))
            .expect_err("HTTP error accepted");
        assert_eq!(error.status(), Some(http_status));
        assert_eq!(service.projection_for_error(&error), projection);
    }

    let current_scope = scope();
    let mut blocked_service = DagsterRunResultService::new(
        DagsterProvider::new(RecordingDagsterTransport::blocked_env()),
        current_scope.clone(),
        SecretReference::deployment_token("secret-ref-dagster-blocked", &current_scope, 1)
            .expect("secret"),
    )
    .expect("service");
    let blocked = blocked_service
        .read_run_evidence(DagsterRunReadRequest::new("run-dagster-01", 1).expect("request"))
        .expect_err("blocked environment accepted");
    assert_eq!(blocked, DagsterError::BlockedEnv);
    assert_eq!(
        blocked_service.projection_for_error(&blocked),
        DagsterRunStatus::ProviderUnknown
    );

    let current_scope = scope();
    let mut timed_out_transport = RecordingDagsterTransport::recording();
    timed_out_transport.fail_with(DagsterTransportError::Timeout);
    let mut timed_out_service = DagsterRunResultService::new(
        DagsterProvider::new(timed_out_transport),
        current_scope.clone(),
        SecretReference::deployment_token("secret-ref-dagster-timeout", &current_scope, 1)
            .expect("secret"),
    )
    .expect("service");
    let timeout = timed_out_service
        .read_run_evidence(DagsterRunReadRequest::new("run-dagster-01", 1).expect("request"))
        .expect_err("timeout accepted");
    assert_eq!(timeout, DagsterError::Timeout);
    assert_eq!(
        timed_out_service.projection_for_error(&timeout),
        DagsterRunStatus::Timeout
    );
}

#[test]
fn registration_is_reversible_revocable_and_secret_opaque() {
    let current_scope = scope();
    let mut secret =
        SecretReference::deployment_token("secret-ref-dagster-registration", &current_scope, 9)
            .expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("secret-ref-dagster-registration"));
    let serialized = serde_json::to_string(&secret).expect("secret JSON");
    assert!(!serialized.contains("secret-ref-dagster-registration"));
    assert!(serialized.contains("deployment_token"));

    let registration = DagsterRegistration::new(&current_scope, &secret).expect("registration");
    let id = registration.registration_digest.clone();
    let mut registry = DagsterRegistrationRegistry::default();
    let receipt = registry.register(registration).expect("register");
    assert_eq!(receipt.status, RegistrationStatus::Active);
    registry
        .get_mut(&id)
        .expect("registration")
        .unmount()
        .expect("unmount");
    assert_eq!(
        registry.restore(&id).expect("restore").to,
        RegistrationStatus::Active
    );
    let revoked = registry.revoke(&id, &mut secret).expect("revoke");
    assert_eq!(revoked.transition.to, RegistrationStatus::Revoked);
    assert!(secret.is_revoked());
    assert_eq!(
        registry.reverse(&id).expect("reverse").to,
        RegistrationStatus::Reversed
    );
    assert!(
        registry
            .get(&id)
            .expect("registration")
            .registration_digest
            .is_valid()
    );
}

#[test]
fn stale_mission_revision_and_revocation_block_consumption() {
    let current_scope = scope();
    let mut source_service = service(current_scope.clone(), DagsterRunStatus::Success, true);
    let evidence = source_service
        .read_run_evidence(DagsterRunReadRequest::new("run-dagster-01", 1).expect("request"))
        .expect("evidence");
    let proposal = source_service
        .compile_run_result_proposal(&evidence)
        .expect("proposal");

    let mut stale_scope = current_scope.clone();
    stale_scope.mission.mission_revision += 1;
    let mut stale_consumer = MissionDagsterRunConsumer::new(&stale_scope).expect("consumer");
    assert_eq!(
        stale_consumer
            .consume(&proposal)
            .expect_err("stale mission accepted"),
        DagsterError::StaleMissionRevision
    );

    let mut revoked_service = service(current_scope, DagsterRunStatus::Success, true);
    revoked_service.revoke().expect("revoke");
    let error = revoked_service
        .read_run_evidence(DagsterRunReadRequest::new("run-dagster-01", 1).expect("request"))
        .expect_err("revoked registration accepted");
    assert!(matches!(
        error,
        DagsterError::SecretRevoked | DagsterError::RegistrationRevoked
    ));
}

#[test]
fn partial_materialization_data_version_and_payload_size_are_not_adoptable() {
    let current_scope = scope();
    let missing_data_version = DagsterAssetMaterialization::new(
        current_scope.asset.clone(),
        current_scope.partition.clone(),
        "materialize_orders",
        hartevo_dagster_run_result_plugin::Digest::from_text("metadata"),
        None,
        OBSERVED_AT,
    )
    .expect("materialization object");
    let event = DagsterEventSummary::materialization("event-missing-version", missing_data_version)
        .expect("event");
    let mut transport = RecordingDagsterTransport::recording();
    transport.push_run_response(Ok(DagsterPayload::new(DagsterRunSnapshot::for_scope(
        &current_scope,
        DagsterRunStatus::Success,
    ))));
    transport.push_events_response(Ok(DagsterPage::new(
        DagsterOperation::ReadEvents,
        0,
        None,
        None,
        vec![event],
    )));
    let mut service = DagsterRunResultService::new(
        DagsterProvider::new(transport),
        current_scope.clone(),
        SecretReference::deployment_token("secret-ref-dagster-missing-version", &current_scope, 1)
            .expect("secret"),
    )
    .expect("service");
    assert_eq!(
        service
            .read_run_evidence(DagsterRunReadRequest::new("run-dagster-01", 1).expect("request"))
            .expect_err("missing data version accepted"),
        DagsterError::MissingDataVersionDigest
    );

    let limits = ReadLimits {
        max_response_bytes: 128,
        ..ReadLimits::default()
    };
    assert!(DagsterProvider::with_limits(RecordingDagsterTransport::recording(), limits).is_ok());
    let invalid_limits = ReadLimits {
        max_page_items: MAX_PAGE_ITEMS + 1,
        ..ReadLimits::default()
    };
    assert_eq!(
        DagsterProvider::with_limits(RecordingDagsterTransport::recording(), invalid_limits)
            .expect_err("invalid limits accepted"),
        DagsterError::InvalidLimits
    );
}

#[test]
fn permission_scope_is_canonical_and_duplicate_sets_are_stable() {
    let current_scope = scope();
    let mut permissions = BTreeSet::new();
    permissions.insert(DagsterPermission::RunRead);
    permissions.insert(DagsterPermission::RunRead);
    assert_eq!(permissions.len(), 1);
    let digest = current_scope.permission_digest();
    assert!(digest.is_valid());
    assert_eq!(
        TransportProvenance::Recording,
        TransportProvenance::Recording
    );
}

#[test]
fn evidence_serialization_contains_digests_but_no_raw_logs_or_config() {
    let current_scope = scope();
    let mut current_service = service(current_scope, DagsterRunStatus::Success, true);
    let evidence: DagsterRunEvidence = current_service
        .read_run_evidence(DagsterRunReadRequest::new("run-dagster-01", 1).expect("request"))
        .expect("evidence");
    let json = serde_json::to_string(&evidence).expect("evidence JSON");
    assert!(json.contains("eventDigest"));
    assert!(json.contains("dataVersionDigests"));
    assert!(!json.contains("rawLogs"));
    assert!(!json.contains("runConfig"));
    assert!(!json.contains("secret-ref-dagster-fixture"));

    let proposal: DagsterRunResultProposal = current_service
        .compile_run_result_proposal(&evidence)
        .expect("proposal");
    let proposal_json = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!proposal_json.contains("launchRun"));
    assert!(!proposal_json.contains("terminateRun"));
}
