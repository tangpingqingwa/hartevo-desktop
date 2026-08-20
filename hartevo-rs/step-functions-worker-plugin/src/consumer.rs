use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::{
    Digest, ExecutionReceipt, ExecutionStatus, ExecutionStatusProjection, FailureEvidence,
    MissionId, OutputEvidence, PollingEvidence, ProviderIdentity, ProviderProvenance,
    RegistrationBinding, TaskTokenReceipt, ValidationError,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("Mission result consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission result evidence is not bound to the consumer registration")]
    RegistrationMismatch,
    #[error("Mission result evidence is not bound to the exact execution and scope")]
    ScopeMismatch,
    #[error("Mission result evidence digest does not match its immutable contents")]
    DigestBindingMismatch,
    #[error("execution status is not terminal")]
    NonTerminal,
    #[error("execution status is provider-unknown and cannot be adopted")]
    ProviderUnknown,
    #[error("successful execution is missing output evidence")]
    MissingOutput,
    #[error("failed execution is missing failure evidence")]
    MissingFailure,
    #[error("Mission result evidence is structurally invalid: {0}")]
    InvalidEvidence(ValidationError),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionExecutionOutcome {
    Succeeded,
    Failed,
    TimedOut,
    Aborted,
}

impl MissionExecutionOutcome {
    fn from_status(status: &ExecutionStatus) -> Result<Self, ConsumerError> {
        match status {
            ExecutionStatus::Succeeded => Ok(Self::Succeeded),
            ExecutionStatus::Failed => Ok(Self::Failed),
            ExecutionStatus::TimedOut => Ok(Self::TimedOut),
            ExecutionStatus::Aborted => Ok(Self::Aborted),
            ExecutionStatus::Running | ExecutionStatus::PendingRedrive => {
                Err(ConsumerError::NonTerminal)
            }
            ExecutionStatus::ProviderUnknown(_) => Err(ConsumerError::ProviderUnknown),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionExecutionEvidence {
    execution: ExecutionReceipt,
    projection: ExecutionStatusProjection,
    task_token_receipts: Vec<TaskTokenReceipt>,
    polling: PollingEvidence,
    registration_digest: Digest,
    evidence_digest: Digest,
}

impl MissionExecutionEvidence {
    pub fn new(
        registration: &RegistrationBinding,
        execution: ExecutionReceipt,
        projection: ExecutionStatusProjection,
        task_token_receipts: Vec<TaskTokenReceipt>,
        polling: PollingEvidence,
    ) -> Result<Self, ConsumerError> {
        registration
            .require_active()
            .map_err(|_| ConsumerError::RegistrationRevoked)?;
        let evidence = Self {
            execution,
            projection,
            task_token_receipts,
            polling,
            registration_digest: registration.registration_digest().clone(),
            evidence_digest: Digest::from_text("pending-step-functions-evidence"),
        };
        evidence.validate_shape(registration)?;
        let mut evidence = evidence;
        evidence.evidence_digest = evidence.calculate_digest();
        Ok(evidence)
    }

    pub fn validate(&self, registration: &RegistrationBinding) -> Result<(), ConsumerError> {
        registration
            .require_active()
            .map_err(|_| ConsumerError::RegistrationRevoked)?;
        self.validate_shape(registration)?;
        if self.evidence_digest != self.calculate_digest() {
            return Err(ConsumerError::DigestBindingMismatch);
        }
        Ok(())
    }

    fn validate_shape(&self, registration: &RegistrationBinding) -> Result<(), ConsumerError> {
        if self.registration_digest != *registration.registration_digest()
            || self.execution.registration_digest() != registration.registration_digest()
            || self.projection.registration_digest() != registration.registration_digest()
            || self.execution.scope() != registration.scope()
            || self.projection.scope() != registration.scope()
            || self.execution.execution_arn() != self.projection.execution_arn()
            || self.execution.identity() != self.projection.identity()
            || self.execution.provider() != self.projection.provider()
            || self.execution.provider() != registration.provider()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if !self.polling.is_bounded() || self.polling.attempts() == 0 {
            return Err(ConsumerError::InvalidEvidence(
                ValidationError::InvalidPollingEvidence,
            ));
        }
        for receipt in &self.task_token_receipts {
            if receipt.registration_digest() != registration.registration_digest()
                || receipt.scope() != registration.scope()
                || receipt.execution_arn() != self.execution.execution_arn()
                || receipt.provider() != registration.provider()
            {
                return Err(ConsumerError::ScopeMismatch);
            }
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        let output = self
            .projection
            .output()
            .digest()
            .map_or("missing", Digest::as_str);
        let failure = self
            .projection
            .failure()
            .digest()
            .map_or("missing", Digest::as_str);
        let task_token_digest = self
            .task_token_receipts
            .iter()
            .map(|receipt| receipt.token_digest().as_str())
            .collect::<Vec<_>>()
            .join(",");
        let delays = self
            .polling
            .delays_ms()
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        Digest::from_parts(&[
            self.registration_digest.as_str(),
            self.execution.scope().binding_digest().as_str(),
            self.execution.execution_arn().as_str(),
            self.execution.identity().input_digest().as_str(),
            self.projection.status().as_wire(),
            output,
            failure,
            self.projection.consistency().as_str(),
            &self.polling.attempts().to_string(),
            &delays,
            if self.polling.eventual_consistency_observed() {
                "eventual-consistency"
            } else {
                "fresh"
            },
            if self.polling.is_bounded() {
                "bounded"
            } else {
                "unbounded"
            },
            &task_token_digest,
        ])
    }

    pub fn execution(&self) -> &ExecutionReceipt {
        &self.execution
    }

    pub fn projection(&self) -> &ExecutionStatusProjection {
        &self.projection
    }

    pub fn task_token_receipts(&self) -> &[TaskTokenReceipt] {
        &self.task_token_receipts
    }

    pub fn polling(&self) -> &PollingEvidence {
        &self.polling
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionResultAdoptionProposal {
    mission_id: MissionId,
    execution_arn: crate::ExecutionArn,
    input_digest: Digest,
    outcome: MissionExecutionOutcome,
    output: OutputEvidence,
    failure: FailureEvidence,
    scope: crate::StepFunctionsMissionScope,
    provider: ProviderIdentity,
    provenance: ProviderProvenance,
    registration_digest: Digest,
    evidence_digest: Digest,
    proposal_digest: Digest,
}

impl MissionResultAdoptionProposal {
    fn new(
        registration: &RegistrationBinding,
        evidence: &MissionExecutionEvidence,
        outcome: MissionExecutionOutcome,
    ) -> Self {
        let mut proposal = Self {
            mission_id: evidence.execution.scope().mission_id().clone(),
            execution_arn: evidence.execution.execution_arn().clone(),
            input_digest: evidence.execution.identity().input_digest().clone(),
            outcome,
            output: evidence.projection.output().clone(),
            failure: evidence.projection.failure().clone(),
            scope: evidence.execution.scope().clone(),
            provider: evidence.execution.provider().clone(),
            provenance: evidence.execution.provenance(),
            registration_digest: registration.registration_digest().clone(),
            evidence_digest: evidence.evidence_digest().clone(),
            proposal_digest: Digest::from_text("pending-step-functions-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }

    pub fn validate(&self, registration: &RegistrationBinding) -> Result<(), ConsumerError> {
        registration
            .require_active()
            .map_err(|_| ConsumerError::RegistrationRevoked)?;
        if self.registration_digest != *registration.registration_digest()
            || self.scope != *registration.scope()
            || self.provider != *registration.provider()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if self.proposal_digest != self.calculate_digest() {
            return Err(ConsumerError::DigestBindingMismatch);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        let output = self.output.digest().map_or("missing", Digest::as_str);
        let failure = self.failure.digest().map_or("missing", Digest::as_str);
        Digest::from_parts(&[
            self.registration_digest.as_str(),
            self.scope.binding_digest().as_str(),
            self.mission_id.as_str(),
            self.execution_arn.as_str(),
            self.input_digest.as_str(),
            self.outcome.as_str(),
            output,
            failure,
            self.provider.provider_id(),
            &self.provider.provider_version().to_string(),
            self.provider.implementation_digest().as_str(),
            self.provenance.as_str(),
            self.evidence_digest.as_str(),
        ])
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn execution_arn(&self) -> &crate::ExecutionArn {
        &self.execution_arn
    }

    pub fn input_digest(&self) -> &Digest {
        &self.input_digest
    }

    pub fn outcome(&self) -> MissionExecutionOutcome {
        self.outcome
    }

    pub fn output(&self) -> &OutputEvidence {
        &self.output
    }

    pub fn failure(&self) -> &FailureEvidence {
        &self.failure
    }

    pub fn scope(&self) -> &crate::StepFunctionsMissionScope {
        &self.scope
    }

    pub fn provider(&self) -> &ProviderIdentity {
        &self.provider
    }

    pub const fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }
}

#[derive(Debug)]
pub struct DefaultMissionExecutionResultConsumer {
    registration: RegistrationBinding,
    adoptions: Vec<MissionResultAdoptionProposal>,
}

impl DefaultMissionExecutionResultConsumer {
    pub fn new(registration: RegistrationBinding) -> Result<Self, ConsumerError> {
        registration
            .require_active()
            .map_err(|_| ConsumerError::RegistrationRevoked)?;
        Ok(Self {
            registration,
            adoptions: Vec::new(),
        })
    }

    pub fn adoptions(&self) -> &[MissionResultAdoptionProposal] {
        &self.adoptions
    }
}

pub trait MissionExecutionResultConsumer: fmt::Debug {
    fn registration(&self) -> &RegistrationBinding;

    fn propose_result_adoption(
        &mut self,
        evidence: &MissionExecutionEvidence,
    ) -> Result<MissionResultAdoptionProposal, ConsumerError>;
}

impl MissionExecutionResultConsumer for DefaultMissionExecutionResultConsumer {
    fn registration(&self) -> &RegistrationBinding {
        &self.registration
    }

    fn propose_result_adoption(
        &mut self,
        evidence: &MissionExecutionEvidence,
    ) -> Result<MissionResultAdoptionProposal, ConsumerError> {
        evidence.validate(&self.registration)?;
        let status = evidence.projection.status();
        let outcome = MissionExecutionOutcome::from_status(&status)?;
        match outcome {
            MissionExecutionOutcome::Succeeded => {
                if !matches!(evidence.projection.output(), OutputEvidence::Present(_)) {
                    return Err(ConsumerError::MissingOutput);
                }
                if !matches!(evidence.projection.failure(), FailureEvidence::Missing) {
                    return Err(ConsumerError::InvalidEvidence(
                        ValidationError::InvalidExecutionProjection,
                    ));
                }
            }
            MissionExecutionOutcome::Failed
            | MissionExecutionOutcome::TimedOut
            | MissionExecutionOutcome::Aborted => {
                if !matches!(evidence.projection.failure(), FailureEvidence::Present(_)) {
                    return Err(ConsumerError::MissingFailure);
                }
                if !matches!(evidence.projection.output(), OutputEvidence::Missing) {
                    return Err(ConsumerError::InvalidEvidence(
                        ValidationError::InvalidExecutionProjection,
                    ));
                }
            }
        }
        let proposal = MissionResultAdoptionProposal::new(&self.registration, evidence, outcome);
        proposal.validate(&self.registration)?;
        self.adoptions.push(proposal.clone());
        Ok(proposal)
    }
}

pub type RecordingMissionExecutionResultConsumer = DefaultMissionExecutionResultConsumer;

impl MissionExecutionOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::Aborted => "aborted",
        }
    }
}

impl crate::types::ObservationConsistency {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::EventuallyConsistent => "eventually_consistent",
        }
    }
}

impl ProviderProvenance {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
            Self::NativeLayer2Gap => "native_layer2_gap",
        }
    }
}
