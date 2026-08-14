use std::fmt;

use thiserror::Error;

use crate::{
    Digest, Layer1Authority, RegistrationState, ResearchResultStatus, Revision,
    SemanticScholarRegistration, SemanticScholarResearchResultEvidence,
    SemanticScholarResearchResultProposal, SemanticScholarScope, ServiceError,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("Mission Semantic Scholar consumer is revoked")]
    Revoked,
    #[error("the registration is invalid or revoked")]
    RegistrationMismatch,
    #[error("the proposal was not produced by the registered Semantic Scholar service")]
    ProposalMismatch,
    #[error("the proposal scope does not match the Mission/Project/Work Product scope")]
    ScopeMismatch,
    #[error("the proposal consent or permission fence is stale")]
    ConsentOrPermissionMismatch,
    #[error("the proposal evidence is tampered")]
    EvidenceTampered,
    #[error("service validation failed: {0}")]
    Service(#[from] ServiceError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionResearchResultState {
    PendingDecision,
    Layer2AdoptionRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScholarlyMetadataAuthority;

impl ScholarlyMetadataAuthority {
    #[must_use]
    pub const fn connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn truth(self) -> bool {
        false
    }

    #[must_use]
    pub const fn adopts_outcome(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptionAvailability {
    NotAdoptedLayer2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionSemanticScholarResearchResult {
    pub project_id: crate::ProjectId,
    pub project_revision: Revision,
    pub mission_id: crate::MissionId,
    pub mission_revision: Revision,
    pub work_product_id: crate::WorkProductId,
    pub work_product_revision: Revision,
    pub status: ResearchResultStatus,
    pub state: MissionResearchResultState,
    pub evidence: SemanticScholarResearchResultEvidence,
    pub proposal_digest: Digest,
    pub authority: ScholarlyMetadataAuthority,
    pub adoption: AdoptionAvailability,
}

pub struct MissionSemanticScholarResearchConsumer {
    scope: SemanticScholarScope,
    registration: SemanticScholarRegistration,
    active: bool,
}

impl fmt::Debug for MissionSemanticScholarResearchConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionSemanticScholarResearchConsumer")
            .field("scope_digest", self.scope.scope_digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("registration_revision", &self.registration.revision)
            .field("active", &self.active)
            .finish()
    }
}

impl MissionSemanticScholarResearchConsumer {
    pub fn new(
        scope: SemanticScholarScope,
        registration: &SemanticScholarRegistration,
    ) -> Result<Self, ConsumerError> {
        registration.validate()?;
        if registration.state != RegistrationState::Active
            || registration.scope_digest != *scope.scope_digest()
            || registration.project_id != *scope.project_id()
            || registration.project_revision != scope.project_revision()
            || registration.mission_id != *scope.mission_id()
            || registration.mission_revision != scope.mission_revision()
            || registration.work_product_id != *scope.work_product_id()
            || registration.work_product_revision != scope.work_product_revision()
            || registration.permission_digest != *scope.permission_digest()
            || registration.consent_digest != *scope.consent().consent_digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: registration.clone(),
            active: true,
        })
    }

    #[must_use]
    pub fn registration(&self) -> &SemanticScholarRegistration {
        &self.registration
    }

    #[must_use]
    pub fn scope(&self) -> &SemanticScholarScope {
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
            Ok(())
        }
    }

    pub fn consume(
        &self,
        proposal: SemanticScholarResearchResultProposal,
    ) -> Result<MissionSemanticScholarResearchResult, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        proposal
            .validate()
            .map_err(|_| ConsumerError::EvidenceTampered)?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.revision
        {
            return Err(ConsumerError::ProposalMismatch);
        }
        let evidence = &proposal.evidence;
        if evidence.scope_digest != self.scope.scope_digest().clone()
            || evidence.permission_digest != *self.scope.permission_digest()
            || evidence.consent_digest != *self.scope.consent().consent_digest()
            || evidence.registration_digest != self.registration.registration_digest
            || evidence.provider_digest != self.registration.provider_digest
            || evidence.query_digest != self.registration.query_digest
            || evidence.query_revision != self.registration.query_revision
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        for receipt in &evidence.request_receipts {
            if receipt.scope_digest != *self.scope.scope_digest()
                || receipt.registration_digest != self.registration.registration_digest
                || receipt.credential_revision != self.registration.credential_revision
            {
                return Err(ConsumerError::ConsentOrPermissionMismatch);
            }
        }
        let state = match evidence.status {
            ResearchResultStatus::Indexed | ResearchResultStatus::Empty => {
                MissionResearchResultState::PendingDecision
            }
            ResearchResultStatus::Partial
            | ResearchResultStatus::NoAbstract
            | ResearchResultStatus::RetractedOrUnknown
            | ResearchResultStatus::AccessLost
            | ResearchResultStatus::RateLimited
            | ResearchResultStatus::ProviderUnknown => {
                MissionResearchResultState::Layer2AdoptionRequired
            }
        };
        Ok(MissionSemanticScholarResearchResult {
            project_id: self.scope.project_id().clone(),
            project_revision: self.scope.project_revision(),
            mission_id: self.scope.mission_id().clone(),
            mission_revision: self.scope.mission_revision(),
            work_product_id: self.scope.work_product_id().clone(),
            work_product_revision: self.scope.work_product_revision(),
            status: evidence.status,
            state,
            evidence: proposal.evidence,
            proposal_digest: proposal.proposal_digest,
            authority: ScholarlyMetadataAuthority,
            adoption: AdoptionAvailability::NotAdoptedLayer2,
        })
    }

    #[must_use]
    pub fn authority(&self) -> Layer1Authority {
        Layer1Authority
    }
}
