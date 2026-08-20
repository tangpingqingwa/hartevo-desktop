use std::collections::BTreeMap;

use serde::Serialize;
use thiserror::Error;

use crate::model::{AutomationEvidenceState, AwsSsmAutomationScope, Digest};
use crate::service::{AwsSsmAutomationProposal, AwsSsmAutomationRegistration, RegistrationStatus};
use crate::{CONSUMER_ID, MAX_IDENTIFIER_BYTES};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission AWS SSM Automation consumer scope does not match")]
    ScopeMismatch,
    #[error("Mission AWS SSM Automation consumer registration is inactive")]
    RegistrationInactive,
    #[error("Mission AWS SSM Automation proposal was tampered")]
    ProposalTampered,
    #[error("Mission AWS SSM Automation recording conflicts with an existing key")]
    RecordingConflict,
    #[error("Mission AWS SSM Automation idempotency key is invalid")]
    InvalidIdempotencyKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Review,
    Success,
    Failed,
    InProgress,
    Partial,
    AccessLoss,
    ProviderUnknown,
    Rejected,
}

impl From<AutomationEvidenceState> for ProposalDisposition {
    fn from(state: AutomationEvidenceState) -> Self {
        match state {
            AutomationEvidenceState::Success => Self::Success,
            AutomationEvidenceState::Failed | AutomationEvidenceState::TimedOut => Self::Failed,
            AutomationEvidenceState::InProgress
            | AutomationEvidenceState::Pending
            | AutomationEvidenceState::Waiting
            | AutomationEvidenceState::Cancelling
            | AutomationEvidenceState::Cancelled => Self::InProgress,
            AutomationEvidenceState::Partial | AutomationEvidenceState::Truncated => Self::Partial,
            AutomationEvidenceState::AccessLoss => Self::AccessLoss,
            AutomationEvidenceState::ProviderUnknown
            | AutomationEvidenceState::InvalidFilter
            | AutomationEvidenceState::InvalidNextToken
            | AutomationEvidenceState::Throttled
            | AutomationEvidenceState::ExecutionReplaced => Self::ProviderUnknown,
            AutomationEvidenceState::RegistrationRevoked => Self::Rejected,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsSsmAutomationResult {
    pub consumer_id: &'static str,
    pub state: AutomationEvidenceState,
    pub disposition: ProposalDisposition,
    pub mission: crate::model::MissionIdentity,
    pub project: crate::model::ProjectIdentity,
    pub work_product: crate::model::WorkProductIdentity,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub decision_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsSsmAutomationResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub state: AutomationEvidenceState,
    pub replayed: bool,
    pub recording_digest: Digest,
}

#[derive(Clone, Debug)]
pub struct MissionAwsSsmAutomationConsumer {
    scope: AwsSsmAutomationScope,
    registration: AwsSsmAutomationRegistration,
    records: BTreeMap<Digest, RecordedAwsSsmAutomationResult>,
}

impl MissionAwsSsmAutomationConsumer {
    pub fn new(
        scope: AwsSsmAutomationScope,
        registration: AwsSsmAutomationRegistration,
    ) -> Result<Self, ConsumerError> {
        if registration.status != RegistrationStatus::Active
            || registration.scope_digest != scope.digest()
            || registration.registration_digest != registration.recomputed_digest()
        {
            return Err(ConsumerError::RegistrationInactive);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsSsmAutomationScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsSsmAutomationRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsSsmAutomationProposal,
    ) -> Result<MissionAwsSsmAutomationResult, ConsumerError> {
        proposal
            .validate_integrity()
            .map_err(|_| ConsumerError::ProposalTampered)?;
        if self.registration.status != RegistrationStatus::Active {
            return Err(ConsumerError::RegistrationInactive);
        }
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != self.registration.permission_digest
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        let decision_digest = Digest::from_parts(
            "hartevo-mission-aws-ssm-automation-decision/v1",
            &[
                ("scope", self.scope.digest().to_string()),
                (
                    "registration",
                    self.registration.registration_digest.to_string(),
                ),
                ("evidence", proposal.evidence.evidence_digest.to_string()),
                ("proposal", proposal.proposal_digest.to_string()),
                ("state", format!("{:?}", proposal.evidence.state)),
            ],
        );
        Ok(MissionAwsSsmAutomationResult {
            consumer_id: CONSUMER_ID,
            state: proposal.evidence.state,
            disposition: proposal.evidence.state.into(),
            mission: self.scope.mission.clone(),
            project: self.scope.project.clone(),
            work_product: self.scope.work_product.clone(),
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            decision_digest,
        })
    }

    pub fn record(
        &mut self,
        proposal: &AwsSsmAutomationProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsSsmAutomationResult, ConsumerError> {
        let result = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > MAX_IDENTIFIER_BYTES || key.chars().any(char::is_control) {
            return Err(ConsumerError::InvalidIdempotencyKey);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(ConsumerError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = Digest::from_parts(
                "hartevo-aws-ssm-automation-recording/v1",
                &[
                    ("idempotency", replay.idempotency_key_digest.to_string()),
                    ("proposal", replay.proposal_digest.to_string()),
                    ("state", format!("{:?}", replay.state)),
                ],
            );
            return Ok(replay);
        }
        let recording_digest = Digest::from_parts(
            "hartevo-aws-ssm-automation-recording/v1",
            &[
                ("idempotency", key_digest.to_string()),
                ("proposal", proposal.proposal_digest.to_string()),
                ("state", format!("{:?}", result.state)),
            ],
        );
        let recorded = RecordedAwsSsmAutomationResult {
            idempotency_key_digest: key_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            state: result.state,
            replayed: false,
            recording_digest,
        };
        self.records.insert(key_digest, recorded.clone());
        Ok(recorded)
    }
}
