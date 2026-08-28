//! Mission consumer for revision-fenced Workday result proposals.

use thiserror::Error;

use crate::WorkdayError;
use crate::model::{
    Digest, MissionResultState, RegistrationState, Revision, WorkdayBusinessProcessResultEvidence,
    WorkdayScope,
};
use crate::provider::WorkdayRegistration;
use crate::service::{
    Layer1AuthorityView, ReadBackAvailability, ReceiptAvailability,
    WorkdayBusinessProcessResultProposal, WorkdayDecisionProposal, WorkdayEffectProposal,
    WorkdayReadBackProposal,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission Workday consumer is revoked")]
    Revoked,
    #[error("consumer registration does not match the proposal")]
    RegistrationMismatch,
    #[error("proposal scope does not match the Mission/Project scope")]
    ScopeMismatch,
    #[error("proposal revision or consent fence is stale")]
    FenceMismatch,
    #[error("proposal digest or Layer-1 authority is invalid")]
    InvalidProposal,
}

impl From<ConsumerError> for WorkdayError {
    fn from(error: ConsumerError) -> Self {
        WorkdayError::Consumer(error.to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerRegistration {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub mission_revision: Revision,
    pub project_revision: Revision,
    pub consent_revision: Revision,
    pub state: RegistrationState,
}

#[derive(Debug)]
pub struct MissionWorkdayBusinessProcessConsumer {
    scope: WorkdayScope,
    registration: ConsumerRegistration,
    active: bool,
}

impl MissionWorkdayBusinessProcessConsumer {
    pub fn new(
        scope: WorkdayScope,
        registration: &WorkdayRegistration,
    ) -> Result<Self, ConsumerError> {
        if registration.state != RegistrationState::Active
            || registration.scope_digest != *scope.scope_digest()
            || registration.tenant_id != *scope.tenant_id()
            || registration.tenant_revision != scope.tenant_revision()
            || registration.consent_digest != *scope.consent().consent_digest()
            || registration.consent_revision != scope.consent().consent_revision()
            || registration.mission_id != *scope.mission_id()
            || registration.mission_revision != scope.mission_revision()
            || registration.project_id != *scope.project_id()
            || registration.project_revision != scope.project_revision()
            || registration.work_product_id != *scope.work_product_id()
            || registration.work_product_revision != scope.work_product_revision()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: ConsumerRegistration {
                registration_digest: registration.registration_digest.clone(),
                scope_digest: registration.scope_digest.clone(),
                mission_revision: registration.mission_revision,
                project_revision: registration.project_revision,
                consent_revision: registration.consent_revision,
                state: RegistrationState::Active,
            },
            active: true,
        })
    }

    pub fn registration(&self) -> &ConsumerRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &WorkdayScope {
        &self.scope
    }

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
        proposal: WorkdayBusinessProcessResultProposal,
    ) -> Result<MissionWorkdayBusinessProcessResult, ConsumerError> {
        if !self.active || self.registration.state != RegistrationState::Active {
            return Err(ConsumerError::Revoked);
        }
        proposal
            .validate()
            .map_err(|_| ConsumerError::InvalidProposal)?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.registration_digest != self.registration.registration_digest
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if proposal.evidence.scope_digest != *self.scope.scope_digest()
            || proposal.evidence.consent_digest != *self.scope.consent().consent_digest()
            || proposal.evidence.consent_revision != self.scope.consent().consent_revision()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if proposal.evidence.tenant_revision != self.scope.tenant_revision()
            || proposal.evidence.process_revision != self.scope.process_revision()
            || proposal.evidence.mission_revision != self.scope.mission_revision()
            || proposal.evidence.project_revision != self.scope.project_revision()
            || proposal.evidence.work_product_revision != self.scope.work_product_revision()
        {
            return Err(ConsumerError::FenceMismatch);
        }
        if proposal.evidence.event.as_ref().is_some_and(|event| {
            event.event_id != *self.scope.event_id()
                || event.business_process_id != *self.scope.business_process_id()
                || event.business_object != *self.scope.business_object()
                || event.worker_reference.reference_digest()
                    != self.scope.worker_reference().reference_digest()
        }) {
            return Err(ConsumerError::FenceMismatch);
        }
        let state = proposal.evidence.mission_state();
        let process_status = proposal.evidence.process_status;
        let quality = proposal.evidence.quality;
        let evidence = proposal.evidence;
        Ok(MissionWorkdayBusinessProcessResult {
            mission_id: self.scope.mission_id().clone(),
            project_id: self.scope.project_id().clone(),
            work_product_id: self.scope.work_product_id().clone(),
            mission_revision: self.scope.mission_revision(),
            project_revision: self.scope.project_revision(),
            work_product_revision: self.scope.work_product_revision(),
            state,
            process_status,
            quality,
            evidence_digest: evidence.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            decision: proposal.decision,
            effect: proposal.effect,
            receipt: proposal.receipt,
            read_back: proposal.read_back,
            adoption: AdoptionAvailability::NotAdoptedLayer2,
            authority: proposal.authority,
            evidence,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptionAvailability {
    NotAdoptedLayer2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionWorkdayBusinessProcessResult {
    pub mission_id: crate::model::MissionId,
    pub project_id: crate::model::ProjectId,
    pub work_product_id: crate::model::WorkProductId,
    pub mission_revision: Revision,
    pub project_revision: Revision,
    pub work_product_revision: Revision,
    pub state: MissionResultState,
    pub process_status: crate::model::BusinessProcessStatus,
    pub quality: crate::model::EvidenceQuality,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence: WorkdayBusinessProcessResultEvidence,
    pub decision: WorkdayDecisionProposal,
    pub effect: WorkdayEffectProposal,
    pub receipt: ReceiptAvailability,
    pub read_back: WorkdayReadBackProposal,
    pub adoption: AdoptionAvailability,
    pub authority: Layer1AuthorityView,
}

impl MissionWorkdayBusinessProcessResult {
    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native_provider(&self) -> bool {
        false
    }

    pub const fn truth_authority(&self) -> bool {
        false
    }

    pub const fn adopted_outcome(&self) -> bool {
        false
    }

    pub fn evidence(&self) -> &WorkdayBusinessProcessResultEvidence {
        &self.evidence
    }

    pub const fn read_back_deferred(&self) -> bool {
        matches!(
            self.read_back.availability,
            ReadBackAvailability::DeferredLayer2
        )
    }
}
