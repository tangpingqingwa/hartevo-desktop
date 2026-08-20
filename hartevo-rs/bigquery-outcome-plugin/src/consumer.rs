use std::fmt;

use thiserror::Error;

use crate::{
    AdoptionAvailability, AnalyticalResultAuthority, BigQueryRegistration, BigQueryResultProposal,
    BigQueryScope, Digest, MissionId, RegistrationState, ResultEvidence, ResultProjection,
    Revision, WorkProductId,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission BigQuery consumer is revoked")]
    Revoked,
    #[error("consumer registration does not match the proposal")]
    RegistrationMismatch,
    #[error("proposal scope does not match the Mission/Work Product scope")]
    ScopeMismatch,
    #[error("proposal evidence fence is stale")]
    FenceMismatch,
    #[error("proposal was not produced by the governed BigQuery service")]
    InvalidProposal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerRegistration {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revision: Revision,
    pub state: RegistrationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionResultState {
    PendingDecision,
    Layer2AdoptionRequired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionBigQueryResult {
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

pub struct MissionBigQueryResultConsumer {
    scope: BigQueryScope,
    registration: ConsumerRegistration,
    active: bool,
}

impl fmt::Debug for MissionBigQueryResultConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionBigQueryResultConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("active", &self.active)
            .finish()
    }
}

impl MissionBigQueryResultConsumer {
    pub fn new(
        scope: BigQueryScope,
        registration: &BigQueryRegistration,
    ) -> Result<Self, ConsumerError> {
        if registration.state != RegistrationState::Active
            || registration.scope_digest != scope.scope_digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: ConsumerRegistration {
                registration_digest: registration.registration_digest.clone(),
                scope_digest: registration.scope_digest.clone(),
                revision: registration.revision,
                state: registration.state,
            },
            active: true,
        })
    }

    pub fn registration(&self) -> &ConsumerRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &BigQueryScope {
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
        proposal: BigQueryResultProposal,
    ) -> Result<MissionBigQueryResult, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.revision
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if proposal.query.scope_digest() != &self.registration.scope_digest
            || proposal.evidence.scope_digest != self.scope.scope_digest()
            || proposal.evidence.permission_digest != *self.scope.permission_digest()
            || proposal.evidence.consent_digest != *self.scope.consent_digest()
            || proposal.evidence.work_product_revision != self.scope.work_product_revision()
            || proposal.query.work_product_revision() != self.scope.work_product_revision()
        {
            return Err(ConsumerError::FenceMismatch);
        }
        if proposal.evidence.digests.query_digest != *proposal.query.query_digest()
            || proposal.evidence.digests.config_digest != *proposal.query.config_digest()
        {
            return Err(ConsumerError::InvalidProposal);
        }
        let state = match proposal.projection {
            ResultProjection::Complete => MissionResultState::PendingDecision,
            ResultProjection::Partial(_)
            | ResultProjection::Expired
            | ResultProjection::AccessLost
            | ResultProjection::ProviderUnknown
            | ResultProjection::FinalError => MissionResultState::Layer2AdoptionRequired,
        };
        Ok(MissionBigQueryResult {
            mission_id: self.scope.mission_id().clone(),
            work_product_id: self.scope.work_product_id().clone(),
            work_product_revision: self.scope.work_product_revision(),
            projection: proposal.projection,
            state,
            evidence: proposal.evidence,
            proposal_digest: proposal.proposal_digest,
            authority: AnalyticalResultAuthority,
            adoption: AdoptionAvailability::NotAdoptedLayer2,
        })
    }
}
