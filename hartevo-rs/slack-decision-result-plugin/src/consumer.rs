//! Mission-scoped, non-authoritative Slack decision evidence consumer.

use serde::Serialize;
use thiserror::Error;

use crate::{
    SLACK_DECISION_CONSUMER_ID,
    model::{Digest, SlackDecisionScope},
    service::{
        RegistrationState, SlackDecisionEvidence, SlackDecisionProposal, SlackDecisionServiceError,
        SlackEvidenceState, SlackRegistration,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission Slack decision consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission Slack decision consumer registration or scope does not match")]
    ScopeMismatch,
    #[error("Mission Slack decision consumer proposal is stale or tampered")]
    ProposalTampered,
    #[error("Mission Slack decision consumer could not validate service evidence: {0}")]
    Service(#[from] SlackDecisionServiceError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlackDecisionState {
    DecisionObserved,
    NoDecisionMarker,
    Partial,
    RetentionUnavailable,
    AccessLoss,
    RateLimited,
    Timeout,
    ProviderUnknown,
    CursorLoop,
    RedactionLoss,
    ScopeDrift,
    ReplayDetected,
    Revoked,
}

impl SlackDecisionState {
    fn from_evidence(evidence: &SlackDecisionEvidence) -> Self {
        match evidence.state {
            SlackEvidenceState::Complete => {
                if evidence.decision_marker_digest.is_zero() {
                    Self::NoDecisionMarker
                } else {
                    Self::DecisionObserved
                }
            }
            SlackEvidenceState::Empty => Self::NoDecisionMarker,
            SlackEvidenceState::Partial => Self::Partial,
            SlackEvidenceState::RetentionUnavailable => Self::RetentionUnavailable,
            SlackEvidenceState::AccessLoss => Self::AccessLoss,
            SlackEvidenceState::RateLimited => Self::RateLimited,
            SlackEvidenceState::Timeout => Self::Timeout,
            SlackEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            SlackEvidenceState::CursorLoop => Self::CursorLoop,
            SlackEvidenceState::RedactionLoss => Self::RedactionLoss,
            SlackEvidenceState::ScopeDrift => Self::ScopeDrift,
            SlackEvidenceState::ReplayDetected => Self::ReplayDetected,
            SlackEvidenceState::Revoked => Self::Revoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionSlackDecisionResult {
    pub consumer_id: &'static str,
    pub decision_state: SlackDecisionState,
    pub evidence_state: SlackEvidenceState,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub decision_fingerprint_digest: Digest,
    pub requires_human_review: bool,
    pub safe_to_promote: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
    pub decision_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionSlackDecisionConsumer {
    scope: SlackDecisionScope,
    registration: SlackRegistration,
}

impl MissionSlackDecisionConsumer {
    pub fn new(
        scope: SlackDecisionScope,
        registration: SlackRegistration,
    ) -> Result<Self, ConsumerError> {
        if registration.state != RegistrationState::Active
            || registration.scope_digest != scope.digest()
            || registration.token_scope_digest != scope.token_scope.digest()
            || registration.registration_digest != registration.recomputed_digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
        })
    }

    pub fn scope(&self) -> &SlackDecisionScope {
        &self.scope
    }

    pub fn registration(&self) -> &SlackRegistration {
        &self.registration
    }

    pub fn consume(
        &self,
        proposal: SlackDecisionProposal,
    ) -> Result<MissionSlackDecisionResult, ConsumerError> {
        if self.registration.state != RegistrationState::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        proposal
            .validate()
            .map_err(|_| ConsumerError::ProposalTampered)?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.token_scope_digest != self.scope.token_scope.digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        let decision_state = SlackDecisionState::from_evidence(&proposal.evidence);
        let decision_digest = Digest::from_parts(
            "hartevo-mission-slack-decision/v1",
            &[
                self.scope.digest().to_string(),
                self.scope.decision_fingerprint.digest().to_string(),
                self.registration.registration_digest.to_string(),
                proposal.evidence.evidence_digest.to_string(),
                proposal.proposal_digest.to_string(),
                format!("{decision_state:?}"),
            ],
        );
        Ok(MissionSlackDecisionResult {
            consumer_id: SLACK_DECISION_CONSUMER_ID,
            decision_state,
            evidence_state: proposal.evidence.state,
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest,
            decision_fingerprint_digest: self.scope.decision_fingerprint.digest().clone(),
            requires_human_review: true,
            safe_to_promote: false,
            connected: false,
            native: false,
            first_party: false,
            adopted_outcome: false,
            truth_authority: false,
            decision_digest,
        })
    }

    pub fn verify_evidence(&self, evidence: &SlackDecisionEvidence) -> Result<(), ConsumerError> {
        if evidence.scope_digest != self.scope.digest()
            || evidence.token_scope_digest != self.scope.token_scope.digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        evidence.validate().map_err(ConsumerError::Service)
    }
}
