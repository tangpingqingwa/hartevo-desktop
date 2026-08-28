use std::fmt;

use serde::Serialize;
use thiserror::Error;

use crate::{
    model::{
        AdoptionAvailability, DecisionResultAuthority, Digest, MiroDecisionRegistration,
        MiroDecisionScope, RegistrationState, Revision,
    },
    provider::MiroBoardProvider,
    service::{
        MiroDecisionProjection, MiroDecisionProposalRequest, MiroDecisionResultProposal,
        MiroDecisionResultRecording, MiroDecisionResultService, MiroDecisionResultServiceError,
        MiroDecisionResultStatus,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission Miro decision consumer is revoked")]
    Revoked,
    #[error("consumer registration does not match the proposal")]
    RegistrationMismatch,
    #[error("proposal scope does not match the Mission/Project/Work Product scope")]
    ScopeMismatch,
    #[error("proposal evidence fence is stale")]
    FenceMismatch,
    #[error("proposal was not produced by the governed Miro decision service")]
    InvalidProposal,
    #[error("proposal claims native, Connected, durable, or adopted authority")]
    NativeClaim,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConsumerRegistration {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub revision: Revision,
    pub state: RegistrationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum MissionMiroDecisionState {
    PendingDecision,
    Layer2AdoptionRequired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MissionMiroDecision {
    pub mission_id: crate::MissionId,
    pub mission_revision: Revision,
    pub project_id: crate::ProjectId,
    pub project_revision: Revision,
    pub work_product_id: crate::WorkProductId,
    pub work_product_revision: Revision,
    pub projection: MiroDecisionProjection,
    pub status: MiroDecisionResultStatus,
    pub state: MissionMiroDecisionState,
    pub evidence: crate::service::MiroDecisionEvidence,
    pub proposal_digest: Digest,
    pub recording_digest: Option<Digest>,
    pub authority: DecisionResultAuthority,
    pub adoption: AdoptionAvailability,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub durable: bool,
    pub verified_adoption: bool,
    pub adopted_outcome: bool,
}

impl MissionMiroDecision {
    pub fn validate(&self) -> Result<(), ConsumerError> {
        if self.status != self.evidence.status
            || self.native
            || self.connected
            || self.first_party
            || self.durable
            || self.verified_adoption
            || self.adopted_outcome
            || self.adoption != AdoptionAvailability::NotAvailable
        {
            return Err(ConsumerError::NativeClaim);
        }
        if self.projection.status() != self.status {
            return Err(ConsumerError::InvalidProposal);
        }
        Ok(())
    }
}

pub struct MissionMiroDecisionConsumer {
    scope: MiroDecisionScope,
    registration: ConsumerRegistration,
    active: bool,
}

impl fmt::Debug for MissionMiroDecisionConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionMiroDecisionConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("active", &self.active)
            .finish()
    }
}

impl MissionMiroDecisionConsumer {
    pub fn new(
        scope: MiroDecisionScope,
        registration: &MiroDecisionRegistration,
    ) -> Result<Self, ConsumerError> {
        if registration.state() != RegistrationState::Active
            || registration.scope_digest() != &scope.scope_digest()
            || registration.permission_digest() != scope.permission_digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: ConsumerRegistration {
                registration_digest: registration.registration_digest().clone(),
                scope_digest: registration.scope_digest().clone(),
                permission_digest: registration.permission_digest().clone(),
                revision: registration.revision(),
                state: registration.state(),
            },
            active: true,
        })
    }

    pub fn registration(&self) -> &ConsumerRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &MiroDecisionScope {
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
        proposal: MiroDecisionResultProposal,
    ) -> Result<MissionMiroDecision, ConsumerError> {
        self.consume_ref(&proposal)
    }

    pub fn consume_ref(
        &self,
        proposal: &MiroDecisionResultProposal,
    ) -> Result<MissionMiroDecision, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.revision
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        proposal
            .evidence
            .validate(&self.scope)
            .map_err(|error| match error {
                MiroDecisionResultServiceError::FenceViolation
                | MiroDecisionResultServiceError::BoardMismatch => ConsumerError::FenceMismatch,
                _ => ConsumerError::InvalidProposal,
            })?;
        if proposal.evidence.scope_digest != self.registration.scope_digest
            || proposal.evidence.permission_digest != self.registration.permission_digest
            || proposal.provider_definition_digest != proposal.evidence.provider_digest
            || proposal.evidence.mission_revision != self.scope.mission_revision()
            || proposal.evidence.project_revision != self.scope.project_revision()
            || proposal.evidence.work_product_revision != self.scope.work_product_revision()
        {
            return Err(ConsumerError::FenceMismatch);
        }
        let expected_proposal_digest = Digest::from_fields(
            "miro-decision-result-proposal/v1",
            &[
                proposal.registration_digest.as_str().to_owned(),
                proposal.registration_revision.get().to_string(),
                proposal.provider_definition_digest.as_str().to_owned(),
                self.scope.scope_digest().as_str().to_owned(),
                format!("{:?}", proposal.projection),
                proposal.evidence.digests.result_digest.as_str().to_owned(),
            ],
        );
        if expected_proposal_digest != proposal.proposal_digest {
            return Err(ConsumerError::InvalidProposal);
        }
        let state = match proposal.projection {
            MiroDecisionProjection::Complete | MiroDecisionProjection::Empty => {
                MissionMiroDecisionState::PendingDecision
            }
            MiroDecisionProjection::Unsupported
            | MiroDecisionProjection::Deleted
            | MiroDecisionProjection::AccessLost
            | MiroDecisionProjection::Partial(_)
            | MiroDecisionProjection::RateLimited
            | MiroDecisionProjection::ServerFailure
            | MiroDecisionProjection::Timeout
            | MiroDecisionProjection::BlockedEnv
            | MiroDecisionProjection::ScopeDrift
            | MiroDecisionProjection::ProviderUnknown => {
                MissionMiroDecisionState::Layer2AdoptionRequired
            }
        };
        let result = MissionMiroDecision {
            mission_id: self.scope.mission_id().clone(),
            mission_revision: self.scope.mission_revision(),
            project_id: self.scope.project_id().clone(),
            project_revision: self.scope.project_revision(),
            work_product_id: self.scope.work_product_id().clone(),
            work_product_revision: self.scope.work_product_revision(),
            projection: proposal.projection,
            status: proposal.status(),
            state,
            evidence: proposal.evidence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            recording_digest: None,
            authority: DecisionResultAuthority,
            adoption: AdoptionAvailability::NotAvailable,
            native: false,
            connected: false,
            first_party: false,
            durable: false,
            verified_adoption: false,
            adopted_outcome: false,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn consume_recording(
        &self,
        recording: &MiroDecisionResultRecording,
    ) -> Result<MissionMiroDecision, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        recording
            .validate(&self.scope)
            .map_err(|_| ConsumerError::InvalidProposal)?;
        if recording.registration_digest != self.registration.registration_digest
            || recording.registration_revision != self.registration.revision
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        let proposal = MiroDecisionResultProposal {
            projection: recording.evidence.projection,
            evidence: recording.evidence.clone(),
            registration_digest: recording.registration_digest.clone(),
            registration_revision: recording.registration_revision,
            provider_definition_digest: recording.provider_definition_digest.clone(),
            proposal_digest: recording.proposal_digest.clone(),
        };
        let result = self.consume_ref(&proposal)?;
        Ok(MissionMiroDecision {
            recording_digest: Some(recording.recording_digest.clone()),
            ..result
        })
    }

    pub fn read<P: MiroBoardProvider>(
        &self,
        service: &mut MiroDecisionResultService<P>,
        request: MiroDecisionProposalRequest,
    ) -> Result<MissionMiroDecision, ConsumerError> {
        if service.scope() != &self.scope {
            return Err(ConsumerError::ScopeMismatch);
        }
        let proposal = service
            .propose(request)
            .map_err(|_| ConsumerError::InvalidProposal)?;
        self.consume_ref(&proposal)
    }
}
