use std::cell::Cell;

use hartevo_connector_sdk::{ConnectorScope, SecretReference};
use hartevo_step_functions_worker_plugin::{
    BLOCKED_ENV_STATUS, BlockedEnvStepFunctionsProvider, BlockedEnvironmentReason,
    ConnectionEvidence, ConsumerError, DescribeExecutionFixture, Digest, ExecutionMode,
    ExecutionName, ExecutionStatus, FailureEvidence, HttpsSigV4Transport, MissionExecutionEvidence,
    MissionExecutionResultConsumer, NativeStepFunctionsProvider, ObservationConsistency,
    OutputEvidence, PollPolicy, PollingEvidence, ProviderAvailability, ProviderError,
    ProviderProvenance, RecordingMissionExecutionResultConsumer, RecordingStepFunctionsProvider,
    RegistrationBinding, SigV4HttpResponse, StartExecutionOutcome, StateMachineArn,
    StepFunctionsAction, StepFunctionsMissionScope, StepFunctionsProvider,
    StepFunctionsWorkerService, TaskToken, TaskTokenCallback, TaskTokenCallbackKind,
    TransportError,
};

const ACCOUNT: &str = "123456789012";
const REGION: &str = "us-east-1";
const STATE_MACHINE: &str = "arn:aws:states:us-east-1:123456789012:stateMachine:mission-worker";

fn scope() -> StepFunctionsMissionScope {
    StepFunctionsMissionScope::new(ACCOUNT, REGION, STATE_MACHINE, "mission-305")
        .expect("fixture scope")
}

fn secret(scope: &StepFunctionsMissionScope) -> SecretReference {
    let connector_scope = ConnectorScope::new(
        "tenant-fixture",
        "project-fixture",
        "aws.step-functions.worker",
        scope.account_id().as_str(),
        [
            "states:StartExecution".to_owned(),
            "states:DescribeExecution".to_owned(),
            "states:SendTaskSuccess".to_owned(),
            "states:SendTaskFailure".to_owned(),
        ],
    )
    .expect("connector scope");
    SecretReference::new("secret-ref-step-functions-fixture", connector_scope, 1)
        .expect("opaque SecretReference")
}

fn registration() -> RegistrationBinding {
    RegistrationBinding::new(scope(), 1, Digest::from_text("fixture-provider-v1"))
        .expect("registration")
}

fn service() -> StepFunctionsWorkerService<
    RecordingStepFunctionsProvider,
    RecordingMissionExecutionResultConsumer,
> {
    let registration = registration();
    let secret = secret(registration.scope());
    let provider = RecordingStepFunctionsProvider::new(registration.clone(), &secret)
        .expect("fixture provider");
    let consumer =
        RecordingMissionExecutionResultConsumer::new(registration).expect("result consumer");
    StepFunctionsWorkerService::new(provider, consumer).expect("worker service")
}

fn standard_proposal(
    service: &StepFunctionsWorkerService<
        RecordingStepFunctionsProvider,
        RecordingMissionExecutionResultConsumer,
    >,
    input: &str,
) -> hartevo_step_functions_worker_plugin::StartExecutionProposal {
    service
        .propose_execution(
            hartevo_step_functions_worker_plugin::StartExecutionIdentity::new(
                ExecutionMode::Standard,
                ExecutionName::new("mission-305-run-1").expect("execution name"),
                Digest::from_text(input),
            ),
        )
        .expect("execution proposal")
}

fn fixture(
    execution: &hartevo_step_functions_worker_plugin::ExecutionReceipt,
    status: ExecutionStatus,
    output: OutputEvidence,
    failure: FailureEvidence,
    consistency: ObservationConsistency,
) -> DescribeExecutionFixture {
    DescribeExecutionFixture::new(
        execution.execution_arn().clone(),
        execution.scope().state_machine_arn().clone(),
        status,
        output,
        failure,
        consistency,
    )
}

#[test]
fn standard_start_execution_is_idempotent_on_same_name_and_input() {
    let mut service = service();
    let proposal = standard_proposal(&service, "mission-input-v1");
    let request = service
        .prepare_start_execution(&proposal)
        .expect("typed SigV4 request");
    assert_eq!(request.action(), StepFunctionsAction::StartExecution);
    assert_eq!(request.region().as_str(), REGION);
    assert_ne!(request.body_digest(), proposal.identity().input_digest());

    let first = service
        .start_execution(&proposal)
        .expect("first fixture start");
    assert_eq!(first.outcome(), StartExecutionOutcome::Started);
    let duplicate = service
        .start_execution(&proposal)
        .expect("idempotent duplicate");
    assert_eq!(
        duplicate.outcome(),
        StartExecutionOutcome::DuplicateSameInput
    );
    assert_eq!(
        duplicate.execution().execution_arn(),
        first.execution().execution_arn()
    );

    let changed_input = standard_proposal(&service, "mission-input-v2");
    assert_eq!(
        service.start_execution(&changed_input),
        Err(
            hartevo_step_functions_worker_plugin::ServiceError::Provider(
                ProviderError::ExecutionAlreadyExistsDifferentInput,
            )
        )
    );
}

#[test]
fn standard_closed_execution_name_is_not_reused_before_the_provider_window() {
    let mut service = service();
    let proposal = standard_proposal(&service, "closed-input");
    let first = service.start_execution(&proposal).expect("start");
    service
        .provider_mut()
        .mark_execution_closed(first.execution())
        .expect("close fixture execution");
    assert_eq!(
        service.start_execution(&proposal),
        Err(
            hartevo_step_functions_worker_plugin::ServiceError::Provider(
                ProviderError::ExecutionAlreadyExistsClosed,
            )
        )
    );
}

#[test]
fn express_is_explicitly_non_idempotent_and_has_no_describe_projection() {
    let mut service = service();
    let proposal = service
        .propose_execution(
            hartevo_step_functions_worker_plugin::StartExecutionIdentity::new(
                ExecutionMode::Express,
                ExecutionName::new("express-run").expect("execution name"),
                Digest::from_text("express-input"),
            ),
        )
        .expect("express proposal");
    let first = service
        .start_execution(&proposal)
        .expect("express start fixture");
    let second = service
        .start_execution(&proposal)
        .expect("express replay fixture");
    assert_eq!(first.outcome(), StartExecutionOutcome::ExpressNonIdempotent);
    assert_eq!(
        second.outcome(),
        StartExecutionOutcome::ExpressNonIdempotent
    );
    assert_ne!(
        first.execution().execution_arn(),
        second.execution().execution_arn()
    );
    assert_eq!(
        service.describe_execution(first.execution()),
        Err(
            hartevo_step_functions_worker_plugin::ServiceError::Provider(
                ProviderError::ExpressDescribeUnsupported,
            )
        )
    );
}

#[test]
fn describe_states_are_exact_and_eventual_consistency_is_bounded_evidence() {
    for (wire, expected) in [
        ("RUNNING", ExecutionStatus::Running),
        ("SUCCEEDED", ExecutionStatus::Succeeded),
        ("FAILED", ExecutionStatus::Failed),
        ("TIMED_OUT", ExecutionStatus::TimedOut),
        ("ABORTED", ExecutionStatus::Aborted),
        ("PENDING_REDRIVE", ExecutionStatus::PendingRedrive),
    ] {
        assert_eq!(ExecutionStatus::from_wire(wire), expected);
    }
    assert!(matches!(
        ExecutionStatus::from_wire("NEW_AWS_STATE"),
        ExecutionStatus::ProviderUnknown(_)
    ));

    let mut service = service();
    let proposal = standard_proposal(&service, "eventual-input");
    let start = service.start_execution(&proposal).expect("start");
    let execution = start.execution().clone();
    service
        .provider_mut()
        .push_describe_fixture(&execution, Err(ProviderError::EventuallyConsistent));
    service.provider_mut().push_describe_fixture(
        &execution,
        Ok(fixture(
            &execution,
            ExecutionStatus::Running,
            OutputEvidence::missing(),
            FailureEvidence::missing(),
            ObservationConsistency::Fresh,
        )),
    );
    service.provider_mut().push_describe_fixture(
        &execution,
        Ok(fixture(
            &execution,
            ExecutionStatus::Succeeded,
            OutputEvidence::present(Digest::from_text("output-v1")),
            FailureEvidence::missing(),
            ObservationConsistency::Fresh,
        )),
    );

    let reconciliation = service
        .reconcile_execution(&execution, PollPolicy::new(3, 10, 20).expect("policy"))
        .expect("bounded reconciliation");
    assert!(reconciliation.is_terminal());
    assert_eq!(reconciliation.polling().attempts(), 3);
    assert_eq!(reconciliation.polling().delays_ms(), &[10, 20]);
    assert!(reconciliation.polling().eventual_consistency_observed());
    let adoption = service
        .propose_result_adoption(&execution, &reconciliation, Vec::new())
        .expect("Mission adoption proposal");
    assert_eq!(
        adoption.outcome(),
        hartevo_step_functions_worker_plugin::MissionExecutionOutcome::Succeeded
    );
    assert_eq!(
        adoption.output().digest(),
        Some(&Digest::from_text("output-v1"))
    );
}

#[test]
fn missing_output_is_not_success_and_tampered_output_digest_is_rejected() {
    let mut service = service();
    let proposal = standard_proposal(&service, "missing-output-input");
    let start = service.start_execution(&proposal).expect("start");
    let execution = start.execution().clone();
    service.provider_mut().push_describe_fixture(
        &execution,
        Ok(fixture(
            &execution,
            ExecutionStatus::Succeeded,
            OutputEvidence::missing(),
            FailureEvidence::missing(),
            ObservationConsistency::Fresh,
        )),
    );
    let reconciliation = service
        .reconcile_execution(&execution, PollPolicy::new(1, 1, 1).expect("policy"))
        .expect("projection");
    assert_eq!(
        service.propose_result_adoption(&execution, &reconciliation, Vec::new()),
        Err(
            hartevo_step_functions_worker_plugin::ServiceError::Consumer(
                ConsumerError::MissingOutput,
            )
        )
    );

    let projection = fixture(
        &execution,
        ExecutionStatus::Succeeded,
        OutputEvidence::present(Digest::from_text("output-real")),
        FailureEvidence::missing(),
        ObservationConsistency::Fresh,
    );
    service
        .provider_mut()
        .push_describe_fixture(&execution, Ok(projection));
    let projection = service.describe_execution(&execution).expect("projection");
    let evidence = MissionExecutionEvidence::new(
        service.registration(),
        execution,
        projection,
        Vec::new(),
        PollingEvidence::new(1, Vec::new(), false, true).expect("polling evidence"),
    )
    .expect("evidence");
    let mut tampered = serde_json::to_value(&evidence).expect("serialize evidence");
    tampered["projection"]["output"]["digest"] =
        serde_json::json!(Digest::from_text("output-tampered").as_str());
    let tampered: MissionExecutionEvidence =
        serde_json::from_value(tampered).expect("deserialize tampered evidence");
    assert_eq!(
        service.consumer_mut().propose_result_adoption(&tampered),
        Err(ConsumerError::DigestBindingMismatch)
    );
}

#[test]
fn task_token_receipts_are_scope_bound_tamper_resistant_and_replay_safe() {
    let mut service = service();
    let proposal = standard_proposal(&service, "task-token-input");
    let start = service.start_execution(&proposal).expect("start");
    let execution = start.execution().clone();
    let token = TaskToken::new("raw-task-token-never-logged").expect("task token");
    service
        .provider_mut()
        .register_task_token(&execution, &token)
        .expect("register fixture token");
    let tampered = TaskTokenCallback::new(
        execution.scope().clone(),
        execution.execution_arn().clone(),
        TaskToken::new("different-token").expect("tampered token"),
        TaskTokenCallbackKind::Success,
        Some(Digest::from_text("callback-output")),
    )
    .expect("tampered callback shape");
    assert!(!format!("{tampered:?}").contains("different-token"));
    assert_eq!(
        service.project_task_token_callback(tampered),
        Err(
            hartevo_step_functions_worker_plugin::ServiceError::Provider(
                ProviderError::TaskTokenTampered,
            )
        )
    );

    let valid = TaskTokenCallback::new(
        execution.scope().clone(),
        execution.execution_arn().clone(),
        token,
        TaskTokenCallbackKind::Success,
        Some(Digest::from_text("callback-output")),
    )
    .expect("valid callback");
    let replay = valid.clone();
    let receipt = service
        .project_task_token_callback(valid)
        .expect("task-token receipt projection");
    assert!(receipt.is_projected_only());
    assert_eq!(
        service.project_task_token_callback(replay),
        Err(
            hartevo_step_functions_worker_plugin::ServiceError::Provider(
                ProviderError::TaskTokenReplay,
            )
        )
    );
}

#[test]
fn fixture_loopback_and_blocked_env_never_claim_connected_or_native() {
    let registration = registration();
    let secret = secret(registration.scope());
    let fixture = RecordingStepFunctionsProvider::new(registration.clone(), &secret)
        .expect("fixture provider");
    let loopback = RecordingStepFunctionsProvider::loopback(registration.clone(), &secret)
        .expect("loopback provider");
    let blocked = BlockedEnvStepFunctionsProvider::new(
        registration.clone(),
        BlockedEnvironmentReason::MissingAwsCredentials,
    );
    for evidence in [
        fixture.connection_evidence(),
        loopback.connection_evidence(),
        blocked.connection_evidence(),
    ] {
        assert!(!evidence.is_connected());
        assert!(!evidence.is_native());
    }
    assert_eq!(fixture.availability(), ProviderAvailability::Fixture);
    assert_eq!(loopback.availability(), ProviderAvailability::Loopback);
    assert_eq!(blocked.availability(), ProviderAvailability::BlockedEnv);
    assert_eq!(blocked.provenance(), ProviderProvenance::BlockedEnv);
}

#[derive(Debug, Default)]
struct CountingTransport {
    sends: Cell<u32>,
}

impl HttpsSigV4Transport for CountingTransport {
    fn send(
        &mut self,
        _request: hartevo_step_functions_worker_plugin::SigV4HttpRequest,
    ) -> Result<SigV4HttpResponse, TransportError> {
        self.sends.set(self.sends.get().saturating_add(1));
        Ok(SigV4HttpResponse::new(200, Digest::from_text("transport")))
    }
}

#[test]
fn native_provider_keeps_transport_as_an_uninvoked_layer_two_seam() {
    let mut native = NativeStepFunctionsProvider::without_credentials(
        registration(),
        CountingTransport::default(),
    );
    let evidence: ConnectionEvidence = native.connection_evidence();
    assert_eq!(evidence.availability(), ProviderAvailability::BlockedEnv);
    assert!(!evidence.is_connected());
    assert!(!evidence.is_native());
    assert_eq!(native.transport_mut().sends.get(), 0);
    assert_eq!(BLOCKED_ENV_STATUS, "BLOCKED_ENV");
}

#[test]
fn registration_is_version_digest_scope_bound_and_reversible() {
    let service = service();
    assert!(service.registration().is_active());
    service.revoke_registration().expect("revoke registration");
    assert!(!service.registration().is_active());
    let proposal = service.propose_execution(
        hartevo_step_functions_worker_plugin::StartExecutionIdentity::new(
            ExecutionMode::Standard,
            ExecutionName::new("revoked-run").expect("name"),
            Digest::from_text("input"),
        ),
    );
    assert_eq!(
        proposal,
        Err(hartevo_step_functions_worker_plugin::ServiceError::RegistrationRevoked)
    );
}

#[test]
fn scope_rejects_cross_account_state_machines() {
    assert!(
        StepFunctionsMissionScope::new(
            ACCOUNT,
            REGION,
            "arn:aws:states:us-west-2:123456789012:stateMachine:mission-worker",
            "mission-305",
        )
        .is_err()
    );
    assert!(
        StateMachineArn::new("arn:aws:states:us-east-1:999999999999:stateMachine:other").is_ok()
    );
}
