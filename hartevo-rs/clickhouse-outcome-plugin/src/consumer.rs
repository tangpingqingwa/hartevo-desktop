use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::{
    AdoptionAvailability, AnalyticalResultAuthority, ClickHouseRegistration,
    ClickHouseResultProposal, ClickHouseScope, Digest, MissionId, ProjectId, RegistrationState,
    ResultEvidence, ResultProjection, Revision, WorkProductId,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission ClickHouse consumer is revoked")]
    Revoked,
    #[error("consumer registration does not match the proposal")]
    RegistrationMismatch,
    #[error("proposal scope does not match the Mission, Project, or Work Product scope")]
    ScopeMismatch,
    #[error("proposal evidence fence is stale")]
    FenceMismatch,
    #[error("proposal was not produced by the governed ClickHouse service")]
    InvalidProposal,
    #[error("proposal was already consumed or replayed")]
    DuplicateReplay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerRegistration {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub revision: Revision,
    pub state: RegistrationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionResultState {
    PendingDecision,
    Layer2AdoptionRequired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionClickHouseOutcome {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub projection: ResultProjection,
    pub state: MissionResultState,
    pub evidence: ResultEvidence,
    pub proposal_digest: Digest,
    pub authority: AnalyticalResultAuthority,
    pub adoption: AdoptionAvailability,
}

pub type MissionClickHouseResult = MissionClickHouseOutcome;

pub struct MissionClickHouseOutcomeConsumer {
    scope: ClickHouseScope,
    registration: ConsumerRegistration,
    active: bool,
    consumed_proposals: BTreeSet<Digest>,
}

pub type MissionClickHouseResultConsumer = MissionClickHouseOutcomeConsumer;

impl fmt::Debug for MissionClickHouseOutcomeConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionClickHouseOutcomeConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("active", &self.active)
            .field("consumed_count", &self.consumed_proposals.len())
            .finish()
    }
}

impl MissionClickHouseOutcomeConsumer {
    pub fn new(
        scope: ClickHouseScope,
        registration: &ClickHouseRegistration,
    ) -> Result<Self, ConsumerError> {
        registration
            .validate_digest()
            .map_err(|_| ConsumerError::RegistrationMismatch)?;
        if registration.state != RegistrationState::Active
            || registration.scope_digest != scope.scope_digest()
            || registration.permission_digest != *scope.permission_digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: ConsumerRegistration {
                registration_digest: registration.registration_digest.clone(),
                scope_digest: registration.scope_digest.clone(),
                permission_digest: registration.permission_digest.clone(),
                revision: registration.revision,
                state: registration.state,
            },
            active: true,
            consumed_proposals: BTreeSet::new(),
        })
    }

    pub fn registration(&self) -> &ConsumerRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &ClickHouseScope {
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

    /// Validates and projects evidence for a decision. This read-only method
    /// does not mutate Mission state or claim adoption authority.
    pub fn consume(
        &self,
        proposal: ClickHouseResultProposal,
    ) -> Result<MissionClickHouseOutcome, ConsumerError> {
        self.validate_context(
            &proposal,
            self.scope.mission_id(),
            self.scope.project_id(),
            self.scope.work_product_revision(),
        )?;
        Ok(self.project(proposal))
    }

    /// Same projection with a local replay fence for callers that require
    /// one-time proposal delivery in this in-memory Layer-1 consumer.
    pub fn consume_once(
        &mut self,
        proposal: ClickHouseResultProposal,
    ) -> Result<MissionClickHouseOutcome, ConsumerError> {
        let digest = proposal.proposal_digest.clone();
        self.validate_context(
            &proposal,
            self.scope.mission_id(),
            self.scope.project_id(),
            self.scope.work_product_revision(),
        )?;
        if !self.consumed_proposals.insert(digest) {
            return Err(ConsumerError::DuplicateReplay);
        }
        Ok(self.project(proposal))
    }

    pub fn consume_for(
        &self,
        mission_id: &MissionId,
        project_id: &ProjectId,
        work_product_revision: Revision,
        proposal: ClickHouseResultProposal,
    ) -> Result<MissionClickHouseOutcome, ConsumerError> {
        self.validate_context(&proposal, mission_id, project_id, work_product_revision)?;
        Ok(self.project(proposal))
    }

    fn validate_context(
        &self,
        proposal: &ClickHouseResultProposal,
        mission_id: &MissionId,
        project_id: &ProjectId,
        work_product_revision: Revision,
    ) -> Result<(), ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.revision
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if proposal.evidence.status != proposal.projection.status() {
            return Err(ConsumerError::InvalidProposal);
        }
        if proposal.query.scope_digest() != &self.registration.scope_digest
            || proposal.evidence.scope_digest != self.scope.scope_digest()
            || proposal.evidence.permission_digest != self.registration.permission_digest
            || proposal.evidence.consent_digest != *self.scope.consent_digest()
            || proposal.evidence.work_product_revision != work_product_revision
            || proposal.query.work_product_revision() != self.scope.work_product_revision()
            || self.scope.mission_id() != mission_id
            || self.scope.project_id() != project_id
        {
            return Err(ConsumerError::FenceMismatch);
        }
        proposal
            .validate_digests()
            .map_err(|_| ConsumerError::InvalidProposal)
    }

    fn project(&self, proposal: ClickHouseResultProposal) -> MissionClickHouseOutcome {
        let state = match proposal.projection {
            ResultProjection::Complete => MissionResultState::PendingDecision,
            ResultProjection::Partial(_)
            | ResultProjection::Truncated
            | ResultProjection::Cancelled
            | ResultProjection::AccessLost
            | ResultProjection::ProviderUnknown
            | ResultProjection::FinalError => MissionResultState::Layer2AdoptionRequired,
        };
        MissionClickHouseOutcome {
            project_id: self.scope.project_id().clone(),
            mission_id: self.scope.mission_id().clone(),
            work_product_id: self.scope.work_product_id().clone(),
            work_product_revision: self.scope.work_product_revision(),
            projection: proposal.projection,
            state,
            evidence: proposal.evidence,
            proposal_digest: proposal.proposal_digest,
            authority: AnalyticalResultAuthority,
            adoption: AdoptionAvailability::NotAdoptedLayer2,
        }
    }
}
