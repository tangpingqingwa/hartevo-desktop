use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ComplianceSummary, Digest, EvidenceStatus, IntuneComplianceProposal,
    IntuneDeviceComplianceService, IntuneDeviceComplianceServiceError, IntuneGraphTransport,
    IntuneObservationReceipt, IntuneProvider, Layer1Authority, MissionBinding,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MissionIntuneComplianceResultState {
    EvidenceReady,
    Partial,
    AccessLoss,
    ProviderUnknown,
    Tampered,
    Revoked,
}

pub type MissionResultState = MissionIntuneComplianceResultState;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MissionIntuneComplianceConsumerError {
    #[error("the Mission consumer rejected a service projection: {0}")]
    Service(#[from] IntuneDeviceComplianceServiceError),
    #[error("the proposal has already been consumed")]
    Replay,
    #[error("the proposal is not bound to this Mission scope")]
    ScopeMismatch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MissionIntuneComplianceResult {
    pub state: MissionIntuneComplianceResultState,
    pub status: EvidenceStatus,
    pub summary: ComplianceSummary,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub mission_id_digest: Digest,
    pub proposal_only: bool,
    pub adopts_outcome: bool,
    pub certification: bool,
    pub authority: Layer1Authority,
}

#[derive(Debug)]
pub struct MissionIntuneComplianceConsumer<T: IntuneGraphTransport> {
    service: IntuneDeviceComplianceService<T>,
    mission: MissionBinding,
    consumed: BTreeSet<Digest>,
}

impl<T: IntuneGraphTransport> MissionIntuneComplianceConsumer<T> {
    pub fn new(provider: IntuneProvider<T>) -> Result<Self, MissionIntuneComplianceConsumerError> {
        let mission = provider.scope().mission.clone();
        Ok(Self {
            service: IntuneDeviceComplianceService::new(provider)?,
            mission,
            consumed: BTreeSet::new(),
        })
    }

    pub fn propose(
        &mut self,
        request: &crate::IntuneReadRequest,
    ) -> Result<IntuneComplianceProposal, MissionIntuneComplianceConsumerError> {
        Ok(self.service.propose(request)?)
    }

    pub fn consume(
        &mut self,
        proposal: &IntuneComplianceProposal,
    ) -> Result<MissionIntuneComplianceResult, MissionIntuneComplianceConsumerError> {
        self.service.verify(proposal)?;
        if proposal.evidence.scope_digest != self.service.provider().scope().scope_digest()
            || proposal.registration.binding.scope_digest
                != self.service.provider().scope().scope_digest()
            || proposal.registration.binding.scope_digest != proposal.evidence.scope_digest
            || self.service.provider().scope().mission != self.mission
        {
            return Err(MissionIntuneComplianceConsumerError::ScopeMismatch);
        }
        if !self.consumed.insert(proposal.proposal_digest.clone()) {
            return Err(MissionIntuneComplianceConsumerError::Replay);
        }
        Ok(MissionIntuneComplianceResult {
            state: result_state(proposal.evidence.status),
            status: proposal.evidence.status,
            summary: proposal.evidence.summary,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.digest(),
            scope_digest: proposal.evidence.scope_digest.clone(),
            mission_id_digest: self.mission.id.digest(),
            proposal_only: true,
            adopts_outcome: false,
            certification: false,
            authority: Layer1Authority::layer1(),
        })
    }

    pub fn record(
        &mut self,
        proposal: &IntuneComplianceProposal,
    ) -> Result<IntuneObservationReceipt, MissionIntuneComplianceConsumerError> {
        Ok(self.service.record(proposal)?)
    }

    pub fn revoke(&mut self) -> Result<(), MissionIntuneComplianceConsumerError> {
        Ok(self
            .service
            .revoke_registration("mission-consumer-revocation")?)
    }

    #[must_use]
    pub fn service(&self) -> &IntuneDeviceComplianceService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut IntuneDeviceComplianceService<T> {
        &mut self.service
    }
}

const fn result_state(status: EvidenceStatus) -> MissionIntuneComplianceResultState {
    match status {
        EvidenceStatus::Complete => MissionIntuneComplianceResultState::EvidenceReady,
        EvidenceStatus::Partial => MissionIntuneComplianceResultState::Partial,
        EvidenceStatus::AccessLoss => MissionIntuneComplianceResultState::AccessLoss,
        EvidenceStatus::ProviderUnknown => MissionIntuneComplianceResultState::ProviderUnknown,
        EvidenceStatus::Tampered => MissionIntuneComplianceResultState::Tampered,
        EvidenceStatus::Revoked => MissionIntuneComplianceResultState::Revoked,
    }
}
