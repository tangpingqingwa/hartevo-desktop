//! Layer-1 AWS Step Functions provider portability for Hartevo Missions.
//!
//! This crate intentionally models proposals, receipts, projections, and
//! adoption evidence without starting an AWS execution or sending a task
//! callback.  The provider has a typed HTTPS/SigV4 seam, but native transport
//! work is an explicit Layer-2 gap.  Fixture, loopback, and `BLOCKED_ENV`
//! evidence can never become `Connected` or native authority.

pub const STEP_FUNCTIONS_WORKER_SCHEMA_VERSION: &str = "hartevo-step-functions-worker-contract/v1";
pub const STEP_FUNCTIONS_WORKER_CONTRACT_VERSION: &str = "aws-step-functions-worker/v1";
pub const STEP_FUNCTIONS_WORKER_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/step-functions-worker/step-functions-worker.v1.json");
pub const STEP_FUNCTIONS_PROVIDER_ID: &str = "aws.step-functions.worker";
pub const STEP_FUNCTIONS_SERVICE_ID: &str = "aws.step-functions.worker.service";
pub const STEP_FUNCTIONS_CONSUMER_ID: &str = "aws.step-functions.mission-result";
pub const BLOCKED_ENV_STATUS: &str = "BLOCKED_ENV";

mod consumer;
mod provider;
mod service;
mod types;

pub use consumer::{
    ConsumerError, DefaultMissionExecutionResultConsumer, MissionExecutionEvidence,
    MissionExecutionOutcome, MissionExecutionResultConsumer, MissionResultAdoptionProposal,
    RecordingMissionExecutionResultConsumer,
};
pub use provider::{
    BlockedEnvStepFunctionsProvider, BlockedEnvironmentReason, FixtureStepFunctionsProvider,
    HttpsSigV4Transport, Layer2Operation, LoopbackStepFunctionsProvider,
    NativeStepFunctionsProvider, ProviderError, RecordedProviderCall,
    RecordingStepFunctionsProvider, SigV4HttpRequest, SigV4HttpResponse, StepFunctionsAction,
    StepFunctionsProvider, TransportError,
};
pub use service::{ReconciliationResult, ServiceError, StepFunctionsWorkerService};
pub use types::{
    AwsAccountId, AwsRegion, ConnectionEvidence, ContractVersion, DescribeExecutionFixture,
    DescribeExecutionRequest, Digest, ExecutionArn, ExecutionMode, ExecutionName, ExecutionReceipt,
    ExecutionStatus, ExecutionStatusProjection, FailureEvidence, MissionId, ObservationConsistency,
    OutputEvidence, PollPolicy, PollingEvidence, ProviderAvailability, ProviderIdentity,
    ProviderProvenance, RegistrationBinding, RegistrationError, SecretReferenceBinding,
    StartExecutionIdentity, StartExecutionOutcome, StartExecutionProposal, StartExecutionReceipt,
    StateMachineArn, StepFunctionsMissionScope, TaskToken, TaskTokenCallback,
    TaskTokenCallbackKind, TaskTokenReceipt, UnknownStateCode, ValidationError,
};

/// The checked-in contract is digested into every registration binding.
pub fn contract_digest() -> Digest {
    Digest::from_text(STEP_FUNCTIONS_WORKER_CONTRACT_JSON)
}

#[cfg(test)]
mod contract_tests {
    use serde::Deserialize;

    use super::{
        BLOCKED_ENV_STATUS, STEP_FUNCTIONS_PROVIDER_ID, STEP_FUNCTIONS_WORKER_CONTRACT_JSON,
        STEP_FUNCTIONS_WORKER_CONTRACT_VERSION, STEP_FUNCTIONS_WORKER_SCHEMA_VERSION,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        evidence_level: String,
        provider_id: String,
        describe_execution_states: Vec<String>,
        authority: ContractAuthority,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractAuthority {
        connected: bool,
        native_execution: bool,
        native_task_callbacks: bool,
        blocked_env_status: String,
    }

    #[test]
    fn checked_contract_matches_layer_one_authority() {
        let document =
            serde_json::from_str::<ContractDocument>(STEP_FUNCTIONS_WORKER_CONTRACT_JSON)
                .expect("Step Functions worker contract JSON");
        assert_eq!(
            document.schema_version,
            STEP_FUNCTIONS_WORKER_SCHEMA_VERSION
        );
        assert_eq!(
            document.contract_version,
            STEP_FUNCTIONS_WORKER_CONTRACT_VERSION
        );
        assert_eq!(document.evidence_level, "E1");
        assert_eq!(document.provider_id, STEP_FUNCTIONS_PROVIDER_ID);
        assert!(!document.authority.connected);
        assert!(!document.authority.native_execution);
        assert!(!document.authority.native_task_callbacks);
        assert_eq!(document.authority.blocked_env_status, BLOCKED_ENV_STATUS);
        assert_eq!(
            document.describe_execution_states,
            vec![
                "RUNNING",
                "SUCCEEDED",
                "FAILED",
                "TIMED_OUT",
                "ABORTED",
                "PENDING_REDRIVE",
                "PROVIDER_UNKNOWN",
            ]
        );
    }
}
