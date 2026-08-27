use chrono::{Duration, TimeZone, Utc};
use hartevo_gcp_workflows_execution_result_plugin as workflows;
use serde_json::json;

const NOW_SECONDS: i64 = 1_787_000_000;

fn now() -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid timestamp")
}

fn scope(selector: workflows::ExecutionSelector) -> workflows::GcpWorkflowsScope {
    workflows::GcpWorkflowsScope::read_only(
        workflows::ProjectBinding::new("project-1", 2).expect("project"),
        "us-central1",
        workflows::WorkflowBinding::new("workflow-1", "revision-7").expect("workflow"),
        selector,
        workflows::MissionBinding::new("mission-1", 3).expect("mission"),
        workflows::WorkProductBinding::new("work-product-1", 4).expect("work product"),
    )
    .expect("scope")
}

fn execution(id: &str, state: workflows::ExecutionState) -> workflows::ExecutionSummary {
    let start = now() + Duration::seconds(1);
    let end = state.is_terminal().then(|| start + Duration::seconds(2));
    let step_state = match state {
        workflows::ExecutionState::Succeeded => workflows::StepState::Succeeded,
        workflows::ExecutionState::Failed => workflows::StepState::Failed,
        workflows::ExecutionState::Cancelled => workflows::StepState::Cancelled,
        workflows::ExecutionState::Active => workflows::StepState::Running,
        workflows::ExecutionState::Queued => workflows::StepState::Queued,
        workflows::ExecutionState::Unavailable | workflows::ExecutionState::StateUnspecified => {
            workflows::StepState::Unknown
        }
    };
    let step = workflows::StepMetadata::from_payloads(
        "main-step",
        step_state,
        1,
        0,
        (state == workflows::ExecutionState::Succeeded).then_some("private result"),
        (state == workflows::ExecutionState::Failed).then_some("private error"),
    )
    .expect("step");
    let termination = if state.is_terminal() {
        workflows::TerminationMetadata::new(
            match state {
                workflows::ExecutionState::Succeeded => workflows::TerminationKind::Completed,
                workflows::ExecutionState::Failed => workflows::TerminationKind::Failed,
                workflows::ExecutionState::Cancelled => workflows::TerminationKind::Cancelled,
                workflows::ExecutionState::Unavailable => workflows::TerminationKind::Unavailable,
                workflows::ExecutionState::StateUnspecified
                | workflows::ExecutionState::Queued
                | workflows::ExecutionState::Active => workflows::TerminationKind::Unknown,
            },
            1,
            0,
            None,
        )
        .expect("termination")
    } else {
        workflows::TerminationMetadata::not_terminated()
    };
    workflows::ExecutionSummary::from_payloads(
        id,
        "revision-7",
        state,
        workflows::ExecutionTiming::new(now(), Some(start), end, Some(2_000)).expect("timing"),
        vec![step],
        termination,
        (state == workflows::ExecutionState::Succeeded).then_some("private result"),
        (state == workflows::ExecutionState::Failed).then_some("private error"),
        None,
    )
    .expect("execution")
}

fn service(
    selector: workflows::ExecutionSelector,
    executions: impl IntoIterator<Item = workflows::ExecutionSummary>,
) -> workflows::GcpWorkflowsExecutionService<workflows::FixtureGcpWorkflowsTransport> {
    let scope = scope(selector);
    let secret = workflows::SecretReference::oauth(
        "oauth-token-shaped-private-value",
        &scope,
        workflows::Revision::new(1).expect("revision"),
    )
    .expect("secret reference");
    let provider = workflows::GcpWorkflowsProvider::layer1(
        workflows::FixtureGcpWorkflowsTransport::new(executions),
    )
    .expect("provider");
    workflows::GcpWorkflowsExecutionService::with_bounds(
        scope,
        secret,
        provider,
        workflows::ReadBounds::new(4, 2, 20).expect("bounds"),
    )
    .expect("service")
}

#[test]
fn contract_and_scope_are_exactly_layer_one() {
    let contract = workflows::GcpWorkflowsExecutionServiceDefinition::new();
    contract.validate().expect("service contract");
    assert!(workflows::contract_json_is_embedded());
    assert_eq!(
        workflows::provider_revision(),
        "gcp-workflows-executions-v1-r1"
    );
    assert_eq!(
        workflows::GCP_WORKFLOWS_EXECUTION_BLOCKED_ENV,
        "BLOCKED_ENV"
    );
    assert!(!workflows::Layer1Authority::connected());
    assert!(!workflows::Layer1Authority::native_provider());
    assert!(!workflows::Layer1Authority::external_writes());
    assert!(!workflows::Layer1Authority::adopted_outcome());

    let scope = scope(workflows::ExecutionSelector::exact("execution-1"));
    assert_eq!(scope.project.project_id().as_str(), "project-1");
    assert_eq!(scope.location.as_str(), "us-central1");
    assert_eq!(scope.workflow.workflow_id().as_str(), "workflow-1");
    assert_eq!(scope.mission.mission_id().as_str(), "mission-1");
    assert_eq!(
        scope.work_product.work_product_id().as_str(),
        "work-product-1"
    );
    assert!(
        scope
            .permission
            .allows(workflows::PermissionAction::WorkflowsExecutionsList)
    );
    assert!(
        scope
            .permission
            .allows(workflows::PermissionAction::WorkflowsExecutionsGet)
    );
    assert_eq!(scope.scope_digest().len(), 64);
}

#[test]
fn opaque_secret_and_cursor_never_serialize_or_print_raw_values() {
    let scope = scope(workflows::ExecutionSelector::Any);
    let secret = workflows::SecretReference::service_account(
        "service-account-private-key-shaped-value",
        &scope,
        workflows::Revision::new(3).expect("revision"),
    )
    .expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("private-key"));
    assert!(!debug.contains("service-account-private-key-shaped-value"));
    assert_eq!(
        secret.kind(),
        workflows::SecretReferenceKind::ServiceAccount
    );

    let token = workflows::OpaquePageToken::new("cursor-that-must-stay-opaque").expect("cursor");
    let debug = format!("{token:?}");
    assert!(!debug.contains("cursor-that-must-stay-opaque"));
    let request = workflows::ExecutionReadRequest::list(
        &scope,
        workflows::Digest::from_text("provider"),
        2,
        10,
        Some(token),
    )
    .expect("request");
    let json = serde_json::to_string(&request).expect("safe request");
    assert!(!json.contains("cursor-that-must-stay-opaque"));
    assert!(json.contains("pageTokenDigest"));
}

#[test]
fn bounded_list_paginates_and_retains_only_safe_execution_metadata() {
    let mut service = service(
        workflows::ExecutionSelector::Any,
        [
            execution("execution-1", workflows::ExecutionState::Succeeded),
            execution("execution-2", workflows::ExecutionState::Failed),
            execution("execution-3", workflows::ExecutionState::Active),
        ],
    );
    let evidence = service.read_bounded().expect("bounded list");
    assert_eq!(evidence.state, workflows::EvidenceState::Complete);
    assert_eq!(evidence.execution_count, 3);
    assert_eq!(evidence.page_count, 2);
    assert!(!evidence.native && !evidence.connected);
    assert!(!evidence.outcome_authority && !evidence.work_product_adoption);
    assert!(evidence.verify_digest());
    assert!(
        evidence
            .executions
            .iter()
            .all(workflows::ExecutionSummary::verify_digest)
    );
    let json = serde_json::to_string(&evidence).expect("evidence serializes");
    assert!(!json.contains("private result"));
    assert!(!json.contains("private error"));
    assert!(!json.contains("oauth-token-shaped-private-value"));
    assert!(
        service
            .provider()
            .transport()
            .requests()
            .get(1)
            .and_then(|request| request.page_token_digest.as_ref())
            .is_some()
    );
}

#[test]
fn exact_get_returns_state_step_retry_and_digest_only_presence() {
    let mut service = service(
        workflows::ExecutionSelector::exact("execution-1"),
        [execution("execution-1", workflows::ExecutionState::Failed)],
    );
    let evidence = service.read_bounded().expect("bounded get");
    assert_eq!(evidence.execution_count, 1);
    let execution = &evidence.executions[0];
    assert_eq!(execution.state, workflows::ExecutionState::Failed);
    assert_eq!(execution.steps.len(), 1);
    assert!(execution.steps[0].error_digest.is_some());
    assert!(execution.result_digest.is_none());
    assert!(execution.error_digest.is_some());
    assert!(evidence.verify_digest());
    let mut tampered = evidence.clone();
    tampered.state = workflows::EvidenceState::Partial;
    assert!(!tampered.verify_digest());
}

#[test]
fn provider_statuses_project_to_explicit_non_native_evidence_states() {
    let cases = [
        (401, workflows::EvidenceState::AccessLost),
        (403, workflows::EvidenceState::AccessLost),
        (404, workflows::EvidenceState::NotFound),
        (409, workflows::EvidenceState::Conflict),
        (429, workflows::EvidenceState::RateLimited),
        (500, workflows::EvidenceState::ProviderUnknown),
    ];
    for (status, expected) in cases {
        let error = workflows::GcpWorkflowsProviderError::failure(
            match status {
                401 => workflows::ProviderFailureClass::Unauthorized,
                403 => workflows::ProviderFailureClass::Forbidden,
                404 => workflows::ProviderFailureClass::NotFound,
                409 => workflows::ProviderFailureClass::Conflict,
                429 => workflows::ProviderFailureClass::RateLimited,
                _ => workflows::ProviderFailureClass::Server,
            },
            Some(status),
        );
        assert_eq!(error.evidence_state(), expected);
        assert_eq!(error.status_code(), Some(status));
    }
    assert_eq!(
        workflows::provider_failure_projection(&workflows::GcpWorkflowsProviderError::failure(
            workflows::ProviderFailureClass::Timeout,
            None,
        )),
        workflows::EvidenceState::Timeout
    );
}

#[test]
fn blocked_env_recording_and_loopback_never_claim_connected_or_native() {
    let any_scope = scope(workflows::ExecutionSelector::Any);
    let secret = workflows::SecretReference::oauth(
        "opaque-reference",
        &any_scope,
        workflows::Revision::new(1).expect("revision"),
    )
    .expect("secret");
    let blocked =
        workflows::GcpWorkflowsProvider::layer1(workflows::BlockedEnvGcpWorkflowsTransport)
            .expect("blocked provider");
    assert_eq!(
        blocked.provenance(),
        workflows::ProviderProvenance::BlockedEnv
    );
    assert!(!blocked.is_native() && !blocked.is_connected());
    let mut blocked_service =
        workflows::GcpWorkflowsExecutionService::new(any_scope, secret, blocked)
            .expect("blocked service");
    let blocked_evidence = blocked_service.read_bounded().expect("blocked evidence");
    assert_eq!(
        blocked_evidence.state,
        workflows::EvidenceState::ProviderUnknown
    );
    assert!(!blocked_evidence.native && !blocked_evidence.connected);

    let recording =
        workflows::GcpWorkflowsProvider::layer1(workflows::RecordingGcpWorkflowsTransport::empty())
            .expect("recording provider");
    assert_eq!(
        recording.provenance(),
        workflows::ProviderProvenance::Recording
    );
    assert!(!recording.definition().first_party);
    let loopback =
        workflows::GcpWorkflowsProvider::layer1(workflows::LoopbackGcpWorkflowsTransport::new([]))
            .expect("loopback provider");
    assert_eq!(
        loopback.provenance(),
        workflows::ProviderProvenance::Loopback
    );
    assert!(!loopback.is_native() && !loopback.is_connected());
}

#[test]
fn registration_is_reversible_and_old_proposals_fail_closed() {
    let mut service = service(
        workflows::ExecutionSelector::Any,
        [execution("execution-1", workflows::ExecutionState::Active)],
    );
    let original = service.registration().registration_digest.clone();
    let proposal = service.propose_list_executions(1, None).expect("proposal");
    service.revoke_registration().expect("revoke");
    assert!(!service.is_registered());
    assert!(matches!(
        service.read_list_executions(&proposal),
        Err(workflows::GcpWorkflowsExecutionServiceError::RegistrationRevoked)
    ));
    service.register().expect("restore");
    assert!(service.is_registered());
    assert_ne!(service.registration().registration_digest, original);
    let restored = service
        .propose_list_executions(1, None)
        .expect("new proposal");
    assert_ne!(restored.proposal_digest(), proposal.proposal_digest());
}

#[test]
fn mission_consumer_rejects_replay_and_never_adopts_outcome() {
    let service = service(
        workflows::ExecutionSelector::Any,
        [execution(
            "execution-1",
            workflows::ExecutionState::Succeeded,
        )],
    );
    let mut consumer = workflows::MissionGcpWorkflowConsumer::new(service).expect("consumer");
    let evidence = consumer.read().expect("evidence");
    let result = consumer.consume(evidence.clone()).expect("consume");
    assert!(result.proposal_only);
    assert!(!result.native && !result.connected);
    assert!(!result.adopts_outcome && !result.work_product_adoption);
    assert_eq!(
        result.state,
        workflows::MissionGcpWorkflowState::EvidenceReady
    );
    assert!(matches!(
        consumer.consume(evidence),
        Err(workflows::ConsumerError::ReplayDetected)
    ));
}

#[test]
fn malformed_bounds_and_state_metadata_fail_closed() {
    assert!(workflows::ReadBounds::new(0, 1, 1).is_err());
    assert!(workflows::OpaquePageToken::new(" ").is_err());
    assert!(
        workflows::ExecutionTiming::new(now(), Some(now() - Duration::seconds(1)), None, None,)
            .is_err()
    );
    assert!(
        workflows::StepMetadata::from_payloads(
            "step",
            workflows::StepState::Succeeded,
            1,
            1,
            None,
            None,
        )
        .is_err()
    );
    let input = json!({
        "argument": "private argument",
        "result": "private result",
        "error": {"context": "private stack trace"}
    });
    let digest = workflows::Digest::from_serializable(&input);
    assert_eq!(digest.len(), 64);
    assert_ne!(digest.as_str(), "private result");
}
