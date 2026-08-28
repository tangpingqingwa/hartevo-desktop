use std::fmt;

use thiserror::Error;

use crate::model::{
    AdoptionAvailability, Digest, MissionId, MongoDbAtlasRegistration, MongoDbAtlasScope,
    ReadinessState, RegistrationState, RestoreVerification, Revision,
};
use crate::service::{Layer1Authority, RecoveryReadinessProposal};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MissionConsumerError {
    #[error("Mission MongoDB Atlas consumer is revoked")]
    Revoked,
    #[error("consumer registration does not match the proposal")]
    RegistrationMismatch,
    #[error("proposal scope does not match the Mission and Project scope")]
    ScopeMismatch,
    #[error("proposal provider or capability fence is stale")]
    ProviderFenceMismatch,
    #[error("proposal evidence is stale or tampered")]
    EvidenceFenceMismatch,
    #[error("proposal was not produced by the governed MongoDB Atlas service")]
    InvalidProposal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerRegistration {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub provider_digest: Digest,
    pub registration_revision: Revision,
    pub mission_revision: Revision,
    pub project_revision: Revision,
    pub state: RegistrationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionResultState {
    PendingDecision,
    EvidenceIncomplete,
    Layer2AdoptionRequired,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MissionMongoDbAtlasResult {
    pub mission_id: MissionId,
    pub project_id: crate::model::ProjectId,
    pub cluster_name: crate::model::ClusterName,
    pub mission_revision: Revision,
    pub project_revision: Revision,
    pub readiness: ReadinessState,
    pub state: MissionResultState,
    pub evidence: crate::service::RecoveryReadinessEvidence,
    pub proposal_digest: Digest,
    pub restore_verification: RestoreVerification,
    pub adoption: AdoptionAvailability,
    pub authority: Layer1Authority,
}

pub struct MissionMongoDbAtlasConsumer {
    scope: MongoDbAtlasScope,
    registration: ConsumerRegistration,
    active: bool,
}

impl fmt::Debug for MissionMongoDbAtlasConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionMongoDbAtlasConsumer")
            .field("scope_digest", self.scope.digest())
            .field("registration", &self.registration)
            .field("active", &self.active)
            .finish()
    }
}

impl MissionMongoDbAtlasConsumer {
    pub fn new(
        scope: MongoDbAtlasScope,
        registration: &MongoDbAtlasRegistration,
    ) -> Result<Self, MissionConsumerError> {
        if registration.state != RegistrationState::Active
            || registration.scope_digest != *scope.digest()
            || registration.consent_digest != *scope.consent().digest()
        {
            return Err(MissionConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: ConsumerRegistration {
                registration_digest: registration.registration_digest.clone(),
                scope_digest: registration.scope_digest.clone(),
                consent_digest: registration.consent_digest.clone(),
                provider_digest: registration.provider_digest.clone(),
                registration_revision: registration.registration_revision,
                mission_revision: registration.mission_revision,
                project_revision: registration.project_revision,
                state: registration.state,
            },
            active: true,
        })
    }

    pub fn registration(&self) -> &ConsumerRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &MongoDbAtlasScope {
        &self.scope
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), MissionConsumerError> {
        if !self.active {
            Err(MissionConsumerError::Revoked)
        } else {
            self.active = false;
            self.registration.state = RegistrationState::Revoked;
            Ok(())
        }
    }

    pub fn consume(
        &self,
        proposal: RecoveryReadinessProposal,
    ) -> Result<MissionMongoDbAtlasResult, MissionConsumerError> {
        if !self.active {
            return Err(MissionConsumerError::Revoked);
        }
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.registration_revision
            || proposal.mission_revision != self.registration.mission_revision
            || proposal.project_revision != self.registration.project_revision
        {
            return Err(MissionConsumerError::RegistrationMismatch);
        }
        if proposal.evidence.digests.scope_digest != self.registration.scope_digest
            || proposal.evidence.digests.consent_digest != self.registration.consent_digest
        {
            return Err(MissionConsumerError::ScopeMismatch);
        }
        if proposal.provider.provider_digest != self.registration.provider_digest
            || proposal.evidence.digests.provider_digest != self.registration.provider_digest
        {
            return Err(MissionConsumerError::ProviderFenceMismatch);
        }
        if proposal.evidence.digests.capability_digest != self.scope.capability_digest()
            || proposal.evidence.digests.measurement_digest != proposal.evidence.measurements.digest
            || proposal.evidence.digests.cluster_metadata_digest != proposal.evidence.cluster.digest
        {
            return Err(MissionConsumerError::EvidenceFenceMismatch);
        }
        if proposal.authority.connected()
            || proposal.authority.native_provider()
            || proposal.authority.restore_authority()
            || proposal.authority.truth_authority()
            || proposal.is_restore_success
            || proposal.adoption != AdoptionAvailability::NotAdoptedLayer1
        {
            return Err(MissionConsumerError::InvalidProposal);
        }
        let state = match proposal.state {
            ReadinessState::Completed => MissionResultState::PendingDecision,
            ReadinessState::Queued | ReadinessState::InProgress => {
                MissionResultState::EvidenceIncomplete
            }
            ReadinessState::Expired
            | ReadinessState::Failed
            | ReadinessState::Partial
            | ReadinessState::RetentionGap
            | ReadinessState::AccessLoss
            | ReadinessState::ProviderUnknown => MissionResultState::Layer2AdoptionRequired,
        };
        Ok(MissionMongoDbAtlasResult {
            mission_id: self.scope.mission_id().clone(),
            project_id: self.scope.project_id().clone(),
            cluster_name: self.scope.cluster_name().clone(),
            mission_revision: self.scope.mission_revision(),
            project_revision: self.scope.project_revision(),
            readiness: proposal.state,
            state,
            evidence: proposal.evidence,
            proposal_digest: proposal.proposal_digest,
            restore_verification: proposal.restore_verification,
            adoption: proposal.adoption,
            authority: proposal.authority,
        })
    }
}
