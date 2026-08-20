use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::{
    AzurePolicyComplianceProposal, AzurePolicyComplianceService, AzurePolicyComplianceServiceError,
    AzurePolicyEvidence, AzurePolicyReadRequest, AzurePolicyScope, AzurePolicyTransport,
    ComplianceSummary, Digest, EvidenceStatus,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionAzurePolicyConsumerError {
    #[error("Mission Azure Policy consumer is revoked")]
    Revoked,
    #[error("Mission Azure Policy proposal replay was rejected")]
    ReplayDetected,
    #[error("Mission Azure Policy proposal is invalid")]
    InvalidProposal,
    #[error(transparent)]
    Service(#[from] AzurePolicyComplianceServiceError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionAzurePolicyResultState {
    EvidenceReady,
    NonCompliantEvidence,
    ExemptEvidence,
    UnknownEvidence,
    AccessLost,
    ProviderUnknown,
    FinalError,
}

pub type MissionResultState = MissionAzurePolicyResultState;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionAzurePolicyResult {
    pub project: crate::ProjectBinding,
    pub mission: crate::MissionBinding,
    pub work_product: crate::WorkProductBinding,
    pub evidence: AzurePolicyEvidence,
    pub proposal_digest: Digest,
    pub state: MissionAzurePolicyResultState,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub certification: bool,
    pub outcome_authority: bool,
}

pub struct MissionAzurePolicyConsumer<T> {
    service: AzurePolicyComplianceService<T>,
    registration_digest: Digest,
    active: bool,
    consumed_proposals: BTreeSet<Digest>,
}

impl<T: AzurePolicyTransport> fmt::Debug for MissionAzurePolicyConsumer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAzurePolicyConsumer")
            .field("scope_digest", &self.service.scope().scope_digest())
            .field("registration_digest", &self.registration_digest)
            .field("active", &self.active)
            .field("consumed_proposals", &self.consumed_proposals.len())
            .finish()
    }
}

impl<T: AzurePolicyTransport> MissionAzurePolicyConsumer<T> {
    pub fn new(
        provider: crate::AzurePolicyInsightsProvider<T>,
    ) -> Result<Self, MissionAzurePolicyConsumerError> {
        let service = AzurePolicyComplianceService::new(provider)?;
        Ok(Self::from_service(service))
    }

    #[must_use]
    pub fn from_service(service: AzurePolicyComplianceService<T>) -> Self {
        let registration_digest = service.registration().registration_digest.clone();
        Self {
            service,
            registration_digest,
            active: true,
            consumed_proposals: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn service(&self) -> &AzurePolicyComplianceService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut AzurePolicyComplianceService<T> {
        &mut self.service
    }

    #[must_use]
    pub fn scope(&self) -> &AzurePolicyScope {
        self.service.scope()
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn read(
        &mut self,
        request: &AzurePolicyReadRequest,
    ) -> Result<AzurePolicyEvidence, MissionAzurePolicyConsumerError> {
        self.ensure_active()?;
        let evidence = self.service.read(request)?;
        self.registration_digest = self.service.registration().registration_digest.clone();
        Ok(evidence)
    }

    pub fn propose(
        &mut self,
        request: &AzurePolicyReadRequest,
    ) -> Result<AzurePolicyComplianceProposal, MissionAzurePolicyConsumerError> {
        self.ensure_active()?;
        let proposal = self.service.propose(request)?;
        self.registration_digest = self.service.registration().registration_digest.clone();
        Ok(proposal)
    }

    pub fn consume(
        &mut self,
        proposal: &AzurePolicyComplianceProposal,
    ) -> Result<MissionAzurePolicyResult, MissionAzurePolicyConsumerError> {
        self.ensure_active()?;
        if self.service.registration().registration_digest != self.registration_digest {
            return Err(MissionAzurePolicyConsumerError::InvalidProposal);
        }
        self.service.verify(proposal)?;
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(MissionAzurePolicyConsumerError::ReplayDetected);
        }
        Ok(MissionAzurePolicyResult {
            project: self.scope().project().clone(),
            mission: self.scope().mission().clone(),
            work_product: self.scope().work_product().clone(),
            evidence: proposal.evidence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            state: result_state(proposal.status(), proposal.summary()),
            proposal_only: true,
            native: false,
            connected: false,
            certification: false,
            outcome_authority: false,
        })
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &AzurePolicyComplianceProposal,
    ) -> Result<MissionAzurePolicyResult, MissionAzurePolicyConsumerError> {
        self.consume(proposal)
    }

    pub fn record(
        &self,
        proposal: &AzurePolicyComplianceProposal,
    ) -> Result<crate::AzurePolicyObservationReceipt, MissionAzurePolicyConsumerError> {
        Ok(self.service.record(proposal)?)
    }

    pub fn revoke(&mut self) -> Result<(), MissionAzurePolicyConsumerError> {
        self.ensure_active()?;
        self.active = false;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), MissionAzurePolicyConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionAzurePolicyConsumerError::Revoked)
        }
    }
}

fn result_state(
    status: EvidenceStatus,
    summary: &ComplianceSummary,
) -> MissionAzurePolicyResultState {
    match status {
        EvidenceStatus::AccessLost => MissionAzurePolicyResultState::AccessLost,
        EvidenceStatus::ProviderUnknown => MissionAzurePolicyResultState::ProviderUnknown,
        EvidenceStatus::FinalError => MissionAzurePolicyResultState::FinalError,
        EvidenceStatus::Complete => match summary {
            ComplianceSummary::Compliant => MissionAzurePolicyResultState::EvidenceReady,
            ComplianceSummary::NonCompliant => MissionAzurePolicyResultState::NonCompliantEvidence,
            ComplianceSummary::Exempt => MissionAzurePolicyResultState::ExemptEvidence,
            ComplianceSummary::Unknown => MissionAzurePolicyResultState::UnknownEvidence,
        },
    }
}
