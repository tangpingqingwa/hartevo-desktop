use std::fmt;

use serde::Serialize;
use thiserror::Error;

use crate::{
    model::{
        Digest, EvidenceStatus, RegistrationState, Revision, SegmentRegistration, SegmentScope,
    },
    service::SegmentEventEvidenceProposal,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("the Mission Segment consumer is revoked")]
    Revoked,
    #[error("the consumer registration does not match the evidence proposal")]
    RegistrationMismatch,
    #[error("the evidence scope does not match the Project/Mission/Work Product binding")]
    ScopeMismatch,
    #[error("the evidence proposal digest is invalid")]
    ProposalDigestMismatch,
    #[error(
        "partial, stale, empty, unavailable, tampered, or provider-unknown evidence cannot be adopted"
    )]
    EvidenceNotAdoptable,
    #[error("fixture, recording, loopback, or BLOCKED_ENV evidence cannot be native")]
    NativeClassificationMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionAction {
    ReviewForMissionDecision,
    RepairInstrumentation,
    RepairDeliveryOrRerun,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CanonicalAdoptionProposal {
    pub action: AdoptionAction,
    pub mutates_external_state: bool,
    pub adopts_kernel_outcome: bool,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MissionSegmentOutcome {
    pub project_id: crate::ProjectId,
    pub project_revision: Revision,
    pub mission_id: crate::MissionId,
    pub mission_revision: Revision,
    pub work_product_id: crate::WorkProductId,
    pub work_product_revision: Revision,
    pub evidence_status: EvidenceStatus,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub adoption: CanonicalAdoptionProposal,
    pub native: bool,
    pub authority: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MissionConsumerRegistration {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revision: Revision,
    pub state: RegistrationState,
}

pub struct MissionSegmentOutcomeConsumer {
    scope: SegmentScope,
    registration: MissionConsumerRegistration,
    active: bool,
}

impl fmt::Debug for MissionSegmentOutcomeConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionSegmentOutcomeConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("active", &self.active)
            .finish()
    }
}

impl MissionSegmentOutcomeConsumer {
    pub fn new(
        scope: SegmentScope,
        registration: &SegmentRegistration,
    ) -> Result<Self, ConsumerError> {
        if registration.state != RegistrationState::Active
            || registration.scope_digest != *scope.scope_digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: MissionConsumerRegistration {
                registration_digest: registration.registration_digest.clone(),
                scope_digest: registration.scope_digest.clone(),
                revision: registration.revision,
                state: registration.state,
            },
            active: true,
        })
    }

    #[must_use]
    pub fn registration(&self) -> &MissionConsumerRegistration {
        &self.registration
    }

    #[must_use]
    pub fn scope(&self) -> &SegmentScope {
        &self.scope
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if !self.active {
            Err(ConsumerError::Revoked)
        } else {
            self.active = false;
            self.registration.state = RegistrationState::Revoked;
            Ok(())
        }
    }

    pub fn consume(
        &self,
        proposal: &SegmentEventEvidenceProposal,
    ) -> Result<MissionSegmentOutcome, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.revision
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if proposal.evidence.scope_digest != *self.scope.scope_digest()
            || proposal.evidence.digests.scope_digest != *self.scope.scope_digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if proposal.evidence.provenance.is_native() {
            return Err(ConsumerError::NativeClassificationMismatch);
        }
        let expected_proposal_digest = Digest::from_fields(
            "segment-event-evidence-proposal/v1",
            [
                self.registration.registration_digest.as_str().to_owned(),
                self.registration.revision.get().to_string(),
                proposal.evidence.evidence_digest().as_str().to_owned(),
            ],
        );
        if expected_proposal_digest != proposal.proposal_digest {
            return Err(ConsumerError::ProposalDigestMismatch);
        }
        if !proposal.evidence.is_adoptable_candidate() {
            return Err(ConsumerError::EvidenceNotAdoptable);
        }
        let action = match proposal.evidence.status {
            EvidenceStatus::Conforming => AdoptionAction::ReviewForMissionDecision,
            EvidenceStatus::Violation => AdoptionAction::RepairInstrumentation,
            EvidenceStatus::DeliveryDegraded => AdoptionAction::RepairDeliveryOrRerun,
            EvidenceStatus::Stale
            | EvidenceStatus::Partial
            | EvidenceStatus::Empty
            | EvidenceStatus::Unavailable
            | EvidenceStatus::ProviderUnknown
            | EvidenceStatus::Tampered => return Err(ConsumerError::EvidenceNotAdoptable),
        };
        let adoption_proposal = CanonicalAdoptionProposal {
            action,
            mutates_external_state: false,
            adopts_kernel_outcome: false,
            evidence_digest: proposal.evidence.evidence_digest().clone(),
            proposal_digest: proposal.proposal_digest.clone(),
        };
        Ok(MissionSegmentOutcome {
            project_id: self.scope.project_id().clone(),
            project_revision: self.scope.project_revision(),
            mission_id: self.scope.mission_id().clone(),
            mission_revision: self.scope.mission_revision(),
            work_product_id: self.scope.work_product_id().clone(),
            work_product_revision: self.scope.work_product_revision(),
            evidence_status: proposal.evidence.status,
            evidence_digest: proposal.evidence.evidence_digest().clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            adoption: adoption_proposal,
            native: false,
            authority: "mission_decision_input_only",
        })
    }

    pub fn consume_proposal(
        &self,
        proposal: &SegmentEventEvidenceProposal,
    ) -> Result<MissionSegmentOutcome, ConsumerError> {
        self.consume(proposal)
    }
}

#[cfg(test)]
mod tests {
    use crate::ProviderProvenance;

    #[test]
    fn provenance_never_claims_native() {
        assert!(!ProviderProvenance::Fixture.is_native());
        assert!(!ProviderProvenance::Recording.is_native());
        assert!(!ProviderProvenance::Loopback.is_native());
        assert!(!ProviderProvenance::BlockedEnv.is_native());
    }
}
