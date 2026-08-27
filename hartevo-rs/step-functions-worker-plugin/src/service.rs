use thiserror::Error;

use crate::{
    ConsumerError, ExecutionReceipt, ExecutionStatusProjection, MissionExecutionEvidence,
    MissionExecutionResultConsumer, MissionResultAdoptionProposal, ProviderError,
    StepFunctionsProvider,
    types::{
        ConnectionEvidence, Digest, PollPolicy, PollingEvidence, RegistrationBinding,
        RegistrationError, StartExecutionIdentity, StartExecutionProposal, StartExecutionReceipt,
        TaskTokenCallback, TaskTokenReceipt, ValidationError,
    },
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ServiceError {
    #[error("service registration is revoked")]
    RegistrationRevoked,
    #[error("provider and Mission consumer registrations do not match")]
    RegistrationMismatch,
    #[error("service request is invalid: {0}")]
    InvalidRequest(ValidationError),
    #[error("provider operation failed: {0}")]
    Provider(ProviderError),
    #[error("Mission result consumer rejected evidence: {0}")]
    Consumer(ConsumerError),
    #[error("bounded reconciliation produced no status projection")]
    NoProjection,
    #[error("registration could not be revoked: {0}")]
    Registration(RegistrationError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationResult {
    projection: Option<ExecutionStatusProjection>,
    polling: PollingEvidence,
}

impl ReconciliationResult {
    fn new(projection: Option<ExecutionStatusProjection>, polling: PollingEvidence) -> Self {
        Self {
            projection,
            polling,
        }
    }

    pub fn projection(&self) -> Option<&ExecutionStatusProjection> {
        self.projection.as_ref()
    }

    pub fn polling(&self) -> &PollingEvidence {
        &self.polling
    }

    pub fn is_terminal(&self) -> bool {
        self.projection
            .as_ref()
            .is_some_and(|projection| projection.status().is_terminal())
    }
}

#[derive(Debug)]
pub struct StepFunctionsWorkerService<P, C>
where
    P: StepFunctionsProvider,
    C: MissionExecutionResultConsumer,
{
    registration: RegistrationBinding,
    provider: P,
    consumer: C,
}

impl<P, C> StepFunctionsWorkerService<P, C>
where
    P: StepFunctionsProvider,
    C: MissionExecutionResultConsumer,
{
    pub fn new(provider: P, consumer: C) -> Result<Self, ServiceError> {
        let provider_registration = provider.registration();
        let consumer_registration = consumer.registration();
        if provider_registration.registration_digest()
            != consumer_registration.registration_digest()
            || provider_registration.scope() != consumer_registration.scope()
            || provider_registration.provider() != consumer_registration.provider()
        {
            return Err(ServiceError::RegistrationMismatch);
        }
        provider_registration
            .require_active()
            .map_err(|_| ServiceError::RegistrationRevoked)?;
        Ok(Self {
            registration: provider_registration.clone(),
            provider,
            consumer,
        })
    }

    pub fn registration(&self) -> &RegistrationBinding {
        &self.registration
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn consumer(&self) -> &C {
        &self.consumer
    }

    pub fn consumer_mut(&mut self) -> &mut C {
        &mut self.consumer
    }

    pub fn connection_evidence(&self) -> ConnectionEvidence {
        self.provider.connection_evidence()
    }

    pub fn revoke_registration(&self) -> Result<(), ServiceError> {
        self.registration
            .revoke()
            .map_err(ServiceError::Registration)
    }

    pub fn propose_execution(
        &self,
        identity: StartExecutionIdentity,
    ) -> Result<StartExecutionProposal, ServiceError> {
        self.registration
            .require_active()
            .map_err(|_| ServiceError::RegistrationRevoked)?;
        StartExecutionProposal::new(&self.registration, identity)
            .map_err(ServiceError::InvalidRequest)
    }

    pub fn prepare_start_execution(
        &self,
        proposal: &StartExecutionProposal,
    ) -> Result<crate::SigV4HttpRequest, ServiceError> {
        self.registration
            .require_active()
            .map_err(|_| ServiceError::RegistrationRevoked)?;
        self.provider
            .prepare_start_execution(proposal)
            .map_err(ServiceError::Provider)
    }

    pub fn start_execution(
        &mut self,
        proposal: &StartExecutionProposal,
    ) -> Result<StartExecutionReceipt, ServiceError> {
        self.registration
            .require_active()
            .map_err(|_| ServiceError::RegistrationRevoked)?;
        self.provider
            .start_execution(proposal)
            .map_err(ServiceError::Provider)
    }

    pub fn prepare_describe_execution(
        &self,
        execution: &ExecutionReceipt,
    ) -> Result<crate::SigV4HttpRequest, ServiceError> {
        self.registration
            .require_active()
            .map_err(|_| ServiceError::RegistrationRevoked)?;
        let request = crate::DescribeExecutionRequest::new(execution.clone());
        self.provider
            .prepare_describe_execution(&request)
            .map_err(ServiceError::Provider)
    }

    pub fn describe_execution(
        &mut self,
        execution: &ExecutionReceipt,
    ) -> Result<ExecutionStatusProjection, ServiceError> {
        self.registration
            .require_active()
            .map_err(|_| ServiceError::RegistrationRevoked)?;
        let request = crate::DescribeExecutionRequest::new(execution.clone());
        self.provider
            .describe_execution(&request)
            .map_err(ServiceError::Provider)
    }

    pub fn project_task_token_callback(
        &mut self,
        callback: TaskTokenCallback,
    ) -> Result<TaskTokenReceipt, ServiceError> {
        self.registration
            .require_active()
            .map_err(|_| ServiceError::RegistrationRevoked)?;
        self.provider
            .project_task_token_callback(callback)
            .map_err(ServiceError::Provider)
    }

    /// Reconcile a STANDARD execution without sleeping or making an unbounded
    /// request loop.  The returned delay schedule is evidence; Layer 2 may
    /// later use it to schedule real DescribeExecution calls.
    pub fn reconcile_execution(
        &mut self,
        execution: &ExecutionReceipt,
        policy: PollPolicy,
    ) -> Result<ReconciliationResult, ServiceError> {
        self.registration
            .require_active()
            .map_err(|_| ServiceError::RegistrationRevoked)?;
        let mut attempts = 0_u16;
        let mut delays = Vec::new();
        let mut eventual_consistency_observed = false;
        let mut projection = None;

        while attempts < policy.max_attempts() {
            attempts = attempts.saturating_add(1);
            match self.describe_execution(execution) {
                Ok(observation) => {
                    let terminal = observation.status().is_terminal();
                    projection = Some(observation);
                    if terminal {
                        break;
                    }
                }
                Err(ServiceError::Provider(ProviderError::EventuallyConsistent)) => {
                    eventual_consistency_observed = true;
                }
                Err(error) => return Err(error),
            }
            if attempts < policy.max_attempts() {
                delays.push(policy.delay_before_retry(attempts));
            }
        }

        let polling = PollingEvidence::new(attempts, delays, eventual_consistency_observed, true)
            .map_err(ServiceError::InvalidRequest)?;
        Ok(ReconciliationResult::new(projection, polling))
    }

    pub fn propose_result_adoption(
        &mut self,
        execution: &ExecutionReceipt,
        reconciliation: &ReconciliationResult,
        task_token_receipts: Vec<TaskTokenReceipt>,
    ) -> Result<MissionResultAdoptionProposal, ServiceError> {
        let projection = reconciliation
            .projection()
            .cloned()
            .ok_or(ServiceError::NoProjection)?;
        let evidence = MissionExecutionEvidence::new(
            &self.registration,
            execution.clone(),
            projection,
            task_token_receipts,
            reconciliation.polling().clone(),
        )
        .map_err(ServiceError::Consumer)?;
        self.consumer
            .propose_result_adoption(&evidence)
            .map_err(ServiceError::Consumer)
    }
}

// Keep the digest import in this module's public API boundary explicit: result
// callers bind input/output/failure evidence to a digest, never raw payloads.
#[allow(dead_code)]
fn _typed_digest_boundary(digest: Digest) -> Digest {
    digest
}
