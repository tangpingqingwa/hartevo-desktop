use std::fmt;

use thiserror::Error;

use crate::{
    model::{
        EvidenceAuthority, GcpCloudLoggingScope, MissionId, ProjectId, RegistrationState, Revision,
        WorkProductId,
    },
    service::{
        GcpCloudLoggingProjection, GcpCloudLoggingRegistration, GcpCloudLoggingResultEvidence,
        GcpCloudLoggingResultProposal,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission GCP Cloud Logging consumer registration is inactive or mismatched")]
    RegistrationMismatch,
    #[error("Mission GCP Cloud Logging consumer is revoked")]
    Revoked,
    #[error("proposal scope, Project/Mission/Work Product fence, or registration is stale")]
    FenceMismatch,
    #[error("proposal evidence or digest is tampered")]
    InvalidProposal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerRegistration {
    pub registration_digest: crate::Digest,
    pub scope_digest: crate::Digest,
    pub evidence_digest: crate::Digest,
    pub revision: Revision,
    pub state: RegistrationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionResultState {
    PendingDecision,
    Layer2AdoptionRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptionAvailability {
    NotAdoptedLayer2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionGcpCloudLoggingResult {
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub projection: GcpCloudLoggingProjection,
    pub state: MissionResultState,
    pub evidence: GcpCloudLoggingResultEvidence,
    pub proposal_digest: crate::Digest,
    pub adoption: AdoptionAvailability,
    pub authority: EvidenceAuthority,
}

pub struct MissionGcpCloudLoggingConsumer {
    scope: GcpCloudLoggingScope,
    registration: ConsumerRegistration,
    active: bool,
}

impl fmt::Debug for MissionGcpCloudLoggingConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionGcpCloudLoggingConsumer")
            .field("scope_digest", &self.scope.digest())
            .field("registration", &self.registration)
            .field("active", &self.active)
            .finish()
    }
}

impl MissionGcpCloudLoggingConsumer {
    pub fn new(
        scope: GcpCloudLoggingScope,
        registration: &GcpCloudLoggingRegistration,
    ) -> Result<Self, ConsumerError> {
        if !registration.is_active()
            || registration.scope_digest != scope.digest()
            || registration.registration_digest != registration.recomputed_digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: ConsumerRegistration {
                registration_digest: registration.registration_digest.clone(),
                scope_digest: registration.scope_digest.clone(),
                evidence_digest: registration.evidence_digest.clone(),
                revision: registration.registration_revision,
                state: registration.state,
            },
            active: true,
        })
    }

    pub fn registration(&self) -> &ConsumerRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &GcpCloudLoggingScope {
        &self.scope
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if self.active {
            self.active = false;
            self.registration.state = RegistrationState::Revoked;
            Ok(())
        } else {
            Err(ConsumerError::Revoked)
        }
    }

    pub fn consume(
        &self,
        proposal: GcpCloudLoggingResultProposal,
    ) -> Result<MissionGcpCloudLoggingResult, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.revision
            || proposal.evidence.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.project_digest != self.scope.project.digest
            || proposal.evidence.mission_digest != self.scope.mission.digest
            || proposal.evidence.work_product_digest != self.scope.work_product.digest
            || proposal.evidence.provider_resource_digest != *self.scope.provider_resource_digest()
            || proposal.evidence.filter_digest != *self.scope.filter_digest()
            || proposal.evidence.time_window_digest != *self.scope.time_window_digest()
            || proposal.evidence.permission_digest != *self.scope.permission_digest()
            || proposal.evidence.evidence_policy_digest != self.registration.evidence_digest
        {
            return Err(ConsumerError::FenceMismatch);
        }
        proposal
            .evidence
            .validate(&self.scope)
            .map_err(|_| ConsumerError::InvalidProposal)?;
        proposal
            .validate_digest()
            .map_err(|_| ConsumerError::InvalidProposal)?;
        let state = match proposal.projection {
            GcpCloudLoggingProjection::Present
            | GcpCloudLoggingProjection::Empty
            | GcpCloudLoggingProjection::Partial => MissionResultState::PendingDecision,
            GcpCloudLoggingProjection::Timeout
            | GcpCloudLoggingProjection::AccessLost
            | GcpCloudLoggingProjection::ProviderUnknown
            | GcpCloudLoggingProjection::Tampered
            | GcpCloudLoggingProjection::Revoked => MissionResultState::Layer2AdoptionRequired,
        };
        Ok(MissionGcpCloudLoggingResult {
            project_id: self.scope.project.id.clone(),
            project_revision: self.scope.project.revision,
            mission_id: self.scope.mission.id.clone(),
            mission_revision: self.scope.mission.revision,
            work_product_id: self.scope.work_product.id.clone(),
            work_product_revision: self.scope.work_product.revision,
            projection: proposal.projection,
            state,
            evidence: proposal.evidence,
            proposal_digest: proposal.proposal_digest,
            adoption: AdoptionAvailability::NotAdoptedLayer2,
            authority: EvidenceAuthority,
        })
    }
}

pub type MissionCloudLoggingConsumer = MissionGcpCloudLoggingConsumer;
pub type MissionCloudLoggingResult = MissionGcpCloudLoggingResult;
