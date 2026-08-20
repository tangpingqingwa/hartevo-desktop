use hartevo_temporal_worker_plugin::{
    Digest, DurableWorkerService, FakeTemporalTransport, MissionWorkerIdentity, MissionWorkerPlan,
    ProviderState, RecordingTransport, SecretReference, TemporalProviderManifest,
    TemporalProviderRegistration, TemporalTransport, TemporalWorkerError, WorkflowCommand,
    WorkflowScope,
};
use serde_json::json;

fn digest(value: &str) -> Digest {
    Digest::from_bytes(value.as_bytes())
}

fn registration() -> TemporalProviderRegistration {
    let scope = WorkflowScope::new("hartevo", "mission-workers", "workflow-1").expect("scope");
    TemporalProviderRegistration::new(
        TemporalProviderManifest::layer1(),
        scope.clone(),
        SecretReference::for_scope("secret-ref-adversarial", &scope, 1).expect("secret"),
    )
    .expect("registration")
}

fn plan() -> MissionWorkerPlan {
    MissionWorkerPlan::new(
        MissionWorkerIdentity::new(
            "project-1",
            "mission-1",
            "worker-1",
            1,
            digest("effect-fence"),
        )
        .expect("identity"),
        WorkflowScope::new("hartevo", "mission-workers", "workflow-1").expect("scope"),
        "workflow",
        "activity",
        digest("input"),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        hartevo_temporal_worker_plugin::RetryPolicy::new(2, 1, 2, 2_000).expect("retry"),
        hartevo_temporal_worker_plugin::HeartbeatPolicy::new(1, 2).expect("heartbeat"),
        None,
    )
    .expect("plan")
}

#[test]
fn provider_manifest_digest_version_and_scope_drift_fail_closed() {
    let original = registration();
    let mut value = serde_json::to_value(&original).expect("registration JSON");
    value["manifest"]["providerVersion"] = json!("temporal-provider/v2");
    let drifted: TemporalProviderRegistration = serde_json::from_value(value).expect("drifted");
    assert!(matches!(
        hartevo_temporal_worker_plugin::TemporalProvider::new(drifted, RecordingTransport::new()),
        Err(TemporalWorkerError::DigestMismatch {
            field: "manifest_digest" | "registration_digest"
        } | TemporalWorkerError::ProviderManifestMismatch { .. })
    ));

    let scope = WorkflowScope::new("hartevo", "other-queue", "workflow-1").expect("scope");
    let changed = TemporalProviderRegistration::new(
        TemporalProviderManifest::layer1(),
        scope.clone(),
        SecretReference::for_scope("secret-ref-scope", &scope, 1).expect("secret"),
    )
    .expect("changed registration");
    let service = DurableWorkerService::new(original, RecordingTransport::new()).expect("service");
    let mission_plan = plan();
    let proposal = service
        .compile_workflow_proposal(&mission_plan)
        .expect("proposal");
    let mut changed_service =
        DurableWorkerService::new(changed, RecordingTransport::new()).expect("changed service");
    assert!(matches!(
        changed_service.record_start(&proposal),
        Err(TemporalWorkerError::ScopeMismatch { .. })
    ));
}

#[test]
fn secret_reference_and_raw_payload_never_enter_receipts_or_debug() {
    let service =
        DurableWorkerService::new(registration(), RecordingTransport::new()).expect("service");
    let mission_plan = plan();
    let proposal = service
        .compile_workflow_proposal(&mission_plan)
        .expect("proposal");
    let debug = format!("{proposal:?} {:?}", service.describe_capabilities());
    let encoded = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!debug.contains("secret-ref-adversarial"));
    assert!(!encoded.contains("secret-ref-adversarial"));
    assert!(!encoded.contains("raw-temporal-payload"));
}

#[test]
fn blocked_environment_is_explicitly_non_native_and_revocation_fences_recording() {
    let blocked = DurableWorkerService::new(
        registration(),
        hartevo_temporal_worker_plugin::BlockedEnvTransport,
    )
    .expect("blocked service");
    assert_eq!(blocked.provider().state(), ProviderState::BlockedEnv);
    let capabilities = blocked.describe_capabilities();
    assert_eq!(
        capabilities.native,
        hartevo_temporal_worker_plugin::Availability::Unavailable
    );
    assert_eq!(
        capabilities.connected,
        hartevo_temporal_worker_plugin::Availability::Unavailable
    );
    assert_eq!(
        capabilities.real_grpc,
        hartevo_temporal_worker_plugin::Availability::Unavailable
    );

    let mut service = DurableWorkerService::new(registration(), RecordingTransport::new())
        .expect("recording service");
    let mission_plan = plan();
    let proposal = service
        .compile_workflow_proposal(&mission_plan)
        .expect("proposal");
    service.provider_mut().revoke();
    assert!(matches!(
        service.record_start(&proposal),
        Err(TemporalWorkerError::ProviderRevoked)
    ));
}

#[test]
fn semantic_idempotency_replays_same_command_rejects_conflicts_and_fake_retries() {
    let service =
        DurableWorkerService::new(registration(), RecordingTransport::new()).expect("service");
    let mission_plan = plan();
    let proposal = service
        .compile_workflow_proposal(&mission_plan)
        .expect("proposal");
    let start = proposal.commands[0].clone();
    let mut conflicting = start.clone();
    if let WorkflowCommand::StartWorkflow { input_digest, .. } = &mut conflicting {
        *input_digest = digest("different-input");
    } else {
        panic!("proposal starts with StartWorkflow");
    }

    let mut recording = RecordingTransport::new();
    let first = recording.record(start).expect("record start");
    assert_eq!(
        recording.record(conflicting).expect_err("conflict"),
        TemporalWorkerError::ReplayConflict
    );
    let replay = recording
        .record(proposal.commands[0].clone())
        .expect("replay");
    assert_eq!(first.sequence, replay.sequence);

    let mut fake = FakeTemporalTransport::new();
    fake.fail_next_transiently();
    assert!(matches!(
        fake.record(proposal.commands[0].clone()),
        Err(TemporalWorkerError::Transport { .. })
    ));
    let fake_record = fake
        .record(proposal.commands[0].clone())
        .expect("fake retry");
    assert_eq!(
        fake_record.provenance,
        hartevo_temporal_worker_plugin::ProviderProvenance::Fixture
    );
}
