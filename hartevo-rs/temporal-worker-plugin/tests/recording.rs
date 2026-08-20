use hartevo_temporal_worker_plugin::{
    ActivityAttempt, ActivityAttemptStatus, Digest, DurableWorkerService, HeartbeatPolicy,
    MissionWorkerIdentity, MissionWorkerPlan, OutcomeAuthority, OutcomeStatus, RecordingTransport,
    RecoveryVerificationRequest, RetryPolicy, SecretReference, SignalDefinition, SignalEnvelope,
    TemporalProviderManifest, TemporalProviderRegistration, TimerDefinition, WorkflowScope,
};

fn digest(value: &str) -> Digest {
    Digest::from_bytes(value.as_bytes())
}

fn service() -> DurableWorkerService<RecordingTransport> {
    let scope = WorkflowScope::new("hartevo", "mission-workers", "workflow-1").expect("scope");
    let secret = SecretReference::for_scope("secret-ref-temporal-test", &scope, 1).expect("secret");
    let registration =
        TemporalProviderRegistration::new(TemporalProviderManifest::layer1(), scope, secret)
            .expect("registration");
    DurableWorkerService::new(registration, RecordingTransport::new()).expect("service")
}

fn mission_plan() -> MissionWorkerPlan {
    let identity = MissionWorkerIdentity::new(
        "project-1",
        "mission-1",
        "worker-1",
        7,
        digest("effect-fence-7"),
    )
    .expect("identity");
    let scope = WorkflowScope::new("hartevo", "mission-workers", "workflow-1").expect("scope");
    MissionWorkerPlan::new(
        identity,
        scope,
        "mission.workflow",
        "mission.activity",
        digest("mission-input"),
        vec![SignalDefinition::new("resume").expect("signal")],
        vec![hartevo_temporal_worker_plugin::QueryDefinition::new("status").expect("query")],
        vec![TimerDefinition::new("wait", 1_000).expect("timer")],
        RetryPolicy::new(3, 100, 1_000, 2_000).expect("retry"),
        HeartbeatPolicy::new(50, 250).expect("heartbeat"),
        Some(10),
    )
    .expect("mission plan")
}

#[test]
#[allow(clippy::too_many_lines)]
fn deterministic_recording_covers_temporal_lifecycle_and_recovery() {
    let mut service = service();
    let proposal = service
        .compile_workflow_proposal(&mission_plan())
        .expect("proposal");
    assert!(!proposal.external_execution);
    assert!(!proposal.native);
    assert_eq!(proposal.commands.len(), 5);
    service.record_start(&proposal).expect("start");

    let first_attempt = ActivityAttempt::new(
        proposal.binding.clone(),
        "mission.activity",
        1,
        0,
        digest("mission-input"),
        ActivityAttemptStatus::Started,
    )
    .expect("attempt");
    service
        .record_activity_attempt(
            first_attempt.clone(),
            proposal.workflow_plan.retry_policy.clone(),
            proposal.workflow_plan.heartbeat_policy.clone(),
        )
        .expect("first attempt");
    service
        .record_heartbeat(
            proposal.binding.clone(),
            first_attempt.attempt_fence.clone(),
            digest("heartbeat-1"),
        )
        .expect("heartbeat");

    let retry = ActivityAttempt::new(
        proposal.binding.clone(),
        "mission.activity",
        2,
        1,
        digest("mission-input"),
        ActivityAttemptStatus::Retrying,
    )
    .expect("retry");
    service
        .record_activity_attempt(
            retry,
            proposal.workflow_plan.retry_policy.clone(),
            proposal.workflow_plan.heartbeat_policy.clone(),
        )
        .expect("retry attempt");

    let signal = SignalEnvelope::new(
        proposal.binding.clone(),
        "signal-resume-1",
        "resume",
        digest("resume-payload"),
    )
    .expect("signal");
    service.record_signal(signal).expect("signal record");
    service
        .record_query(proposal.binding.clone(), "status")
        .expect("query record");
    service
        .record_timer(proposal.binding.clone(), "wait", 1_000)
        .expect("timer record");
    service
        .record_continue_as_new(
            proposal.binding.clone(),
            proposal.workflow_plan.plan_digest.clone(),
        )
        .expect("continue as new");

    let before_recovery = service.provider().snapshot();
    let recovery = service
        .verify_recovery(
            RecoveryVerificationRequest::new(proposal.binding.clone(), 1)
                .expect("recovery request"),
        )
        .expect("recovery");
    assert!(recovery.no_uncertain_replay);
    assert_eq!(recovery.recovered_attempts, 2);
    assert_eq!(recovery.retry_count, 1);
    assert_eq!(recovery.last_sequence, before_recovery.events.len() as u64);

    let cancel = service
        .record_cancel(proposal.binding.clone(), digest("operator-cancel"))
        .expect("cancel");
    assert_eq!(
        cancel.operation,
        hartevo_temporal_worker_plugin::TemporalOperation::CancelWorkflow
    );
    let outcome = service
        .record_outcome(
            proposal.binding.clone(),
            OutcomeStatus::Cancelled,
            digest("cancelled-outcome"),
        )
        .expect("outcome");
    assert_eq!(
        outcome.authority,
        OutcomeAuthority::HartevoTruthBoundaryPending
    );
    assert_eq!(outcome.activity_attempts, 2);
    assert_eq!(outcome.retry_count, 1);
    assert_eq!(outcome.recovery_count, 1);

    let encoded = serde_json::to_string(&outcome).expect("outcome JSON");
    assert!(!encoded.contains("secret-ref-temporal-test"));
    assert!(!encoded.contains("resume-payload"));
    assert!(!encoded.contains("operator-cancel"));
}

#[test]
fn snapshot_restore_replays_same_command_without_uncertain_duplicate() {
    let mut original = service();
    let proposal = original
        .compile_workflow_proposal(&mission_plan())
        .expect("proposal");
    let first = original.record_start(&proposal).expect("first start");
    let snapshot = original.provider().snapshot();
    let restored = RecordingTransport::from_snapshot(snapshot).expect("restore");
    let mut recovered =
        DurableWorkerService::new(original.provider().registration().clone(), restored)
            .expect("recovered service");
    let replay = recovered.record_start(&proposal).expect("replayed start");
    assert_eq!(first.sequence, replay.sequence);
    assert_eq!(
        replay.disposition,
        hartevo_temporal_worker_plugin::ReplayDisposition::Replayed
    );
    assert_eq!(recovered.provider().history().len(), 1);
}
