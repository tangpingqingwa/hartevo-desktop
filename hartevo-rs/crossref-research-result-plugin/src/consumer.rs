use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CrossrefEvidenceState, CrossrefResearchProposal, CrossrefResearchScope, Digest, IdentityBinding,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionResultState {
    Complete,
    Partial,
    Empty,
    RateLimited,
    AccessLost,
    ProviderUnknown,
    BlockedEnv,
    MalformedResponse,
    ResponseTooLarge,
}

impl From<&CrossrefEvidenceState> for MissionResultState {
    fn from(state: &CrossrefEvidenceState) -> Self {
        match state {
            CrossrefEvidenceState::Complete => Self::Complete,
            CrossrefEvidenceState::Partial => Self::Partial,
            CrossrefEvidenceState::Empty => Self::Empty,
            CrossrefEvidenceState::RateLimited => Self::RateLimited,
            CrossrefEvidenceState::AccessLost => Self::AccessLost,
            CrossrefEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            CrossrefEvidenceState::BlockedEnv => Self::BlockedEnv,
            CrossrefEvidenceState::MalformedResponse => Self::MalformedResponse,
            CrossrefEvidenceState::ResponseTooLarge => Self::ResponseTooLarge,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionCrossrefResearchConsumerError {
    #[error("Crossref proposal is not proposal-only")]
    NotProposalOnly,
    #[error("Crossref proposal has a native or connected claim")]
    NativeOrConnectedClaim,
    #[error("Crossref proposal does not match the Mission scope")]
    ScopeMismatch,
    #[error("Crossref proposal digest is stale or tampered")]
    ProposalTampered,
    #[error("Crossref evidence digest is stale or tampered")]
    EvidenceTampered,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionCrossrefResearchConsumer {
    project: IdentityBinding,
    mission: IdentityBinding,
    work_product: IdentityBinding,
    scope_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionCrossrefResearchResult {
    pub state: MissionResultState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub work_digests: Vec<Digest>,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
}

impl MissionCrossrefResearchConsumer {
    #[must_use]
    pub fn new(scope: &CrossrefResearchScope) -> Self {
        Self::from_scope(scope)
    }

    #[must_use]
    pub fn from_scope(scope: &CrossrefResearchScope) -> Self {
        Self {
            project: scope.project().clone(),
            mission: scope.mission().clone(),
            work_product: scope.work_product().clone(),
            scope_digest: scope.digest(),
        }
    }

    #[must_use]
    pub fn project(&self) -> &IdentityBinding {
        &self.project
    }

    #[must_use]
    pub fn mission(&self) -> &IdentityBinding {
        &self.mission
    }

    #[must_use]
    pub fn work_product(&self) -> &IdentityBinding {
        &self.work_product
    }

    #[must_use]
    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub fn consume(
        &self,
        proposal: &CrossrefResearchProposal,
    ) -> Result<MissionCrossrefResearchResult, MissionCrossrefResearchConsumerError> {
        if !proposal.proposal_only {
            return Err(MissionCrossrefResearchConsumerError::NotProposalOnly);
        }
        if proposal.native
            || proposal.connected
            || proposal.first_party
            || proposal.adopts_outcome
            || proposal.adopts_work_product
            || proposal.evidence.read_receipt.native
            || proposal.evidence.read_receipt.connected
            || proposal.evidence.read_receipt.first_party
        {
            return Err(MissionCrossrefResearchConsumerError::NativeOrConnectedClaim);
        }
        if proposal.scope.digest() != self.scope_digest
            || proposal.scope.project() != &self.project
            || proposal.scope.mission() != &self.mission
            || proposal.scope.work_product() != &self.work_product
        {
            return Err(MissionCrossrefResearchConsumerError::ScopeMismatch);
        }
        if proposal.proposal_digest != proposal.digest() {
            return Err(MissionCrossrefResearchConsumerError::ProposalTampered);
        }
        if proposal.source_evidence_digest != proposal.evidence.digest()
            || proposal.evidence.evidence_digest != proposal.evidence.digest()
        {
            return Err(MissionCrossrefResearchConsumerError::EvidenceTampered);
        }
        Ok(MissionCrossrefResearchResult {
            state: MissionResultState::from(&proposal.evidence.state),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.source_evidence_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            work_digests: proposal
                .evidence
                .works
                .iter()
                .map(crate::CrossrefWorkProjection::digest)
                .collect(),
            connected: false,
            native: false,
            first_party: false,
            adopts_outcome: false,
            adopts_work_product: false,
        })
    }

    pub fn project_proposal(
        &self,
        proposal: &CrossrefResearchProposal,
    ) -> Result<MissionCrossrefResearchResult, MissionCrossrefResearchConsumerError> {
        self.consume(proposal)
    }
}

pub type MissionCrossrefResearchResultState = MissionResultState;
pub type ConsumerError = MissionCrossrefResearchConsumerError;
