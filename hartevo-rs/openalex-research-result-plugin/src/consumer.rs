use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Digest, IdentityBinding, OpenAlexEvidenceState, OpenAlexResearchProposal, OpenAlexResearchScope,
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

impl From<OpenAlexEvidenceState> for MissionResultState {
    fn from(state: OpenAlexEvidenceState) -> Self {
        match state {
            OpenAlexEvidenceState::Complete => Self::Complete,
            OpenAlexEvidenceState::Partial => Self::Partial,
            OpenAlexEvidenceState::Empty => Self::Empty,
            OpenAlexEvidenceState::RateLimited => Self::RateLimited,
            OpenAlexEvidenceState::AccessLost => Self::AccessLost,
            OpenAlexEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            OpenAlexEvidenceState::BlockedEnv => Self::BlockedEnv,
            OpenAlexEvidenceState::MalformedResponse => Self::MalformedResponse,
            OpenAlexEvidenceState::ResponseTooLarge => Self::ResponseTooLarge,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionOpenAlexResearchConsumerError {
    #[error("OpenAlex proposal is not proposal-only")]
    NotProposalOnly,
    #[error(
        "OpenAlex proposal has a native, connected, ranking, full-text, identity, citation-truth, or research-Truth claim"
    )]
    AuthorityClaim,
    #[error("OpenAlex proposal does not match the Mission scope")]
    ScopeMismatch,
    #[error("OpenAlex proposal digest is stale or tampered")]
    ProposalTampered,
    #[error("OpenAlex evidence digest is stale or tampered")]
    EvidenceTampered,
    #[error("OpenAlex proposal idempotency fence detected a replay")]
    ReplayDetected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionOpenAlexResearchConsumer {
    project: IdentityBinding,
    mission: IdentityBinding,
    work_product: IdentityBinding,
    scope_digest: Digest,
    consumed_idempotency: BTreeSet<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionOpenAlexResearchResult {
    pub state: MissionResultState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub idempotency_digest: Digest,
    pub scope_digest: Digest,
    pub work_digests: Vec<Digest>,
    pub author_digests: Vec<Digest>,
    pub institution_digests: Vec<Digest>,
    pub concept_digests: Vec<Digest>,
    pub citation_digests: Vec<Digest>,
    pub connected: bool,
    pub native: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
    pub ranking_claim: bool,
    pub full_text: bool,
    pub author_identity_claim: bool,
    pub citation_truth_claim: bool,
    pub research_truth_claim: bool,
}

impl MissionOpenAlexResearchConsumer {
    #[must_use]
    pub fn new(scope: &OpenAlexResearchScope) -> Self {
        Self::from_scope(scope)
    }

    #[must_use]
    pub fn from_scope(scope: &OpenAlexResearchScope) -> Self {
        Self {
            project: scope.project().clone(),
            mission: scope.mission().clone(),
            work_product: scope.work_product().clone(),
            scope_digest: scope.digest(),
            consumed_idempotency: BTreeSet::new(),
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
        &mut self,
        proposal: &OpenAlexResearchProposal,
    ) -> Result<MissionOpenAlexResearchResult, MissionOpenAlexResearchConsumerError> {
        if !proposal.proposal_only {
            return Err(MissionOpenAlexResearchConsumerError::NotProposalOnly);
        }
        if proposal.native
            || proposal.connected
            || proposal.adopts_outcome
            || proposal.adopts_work_product
            || proposal.ranking_claim
            || proposal.full_text
            || proposal.author_identity_claim
            || proposal.citation_truth_claim
            || proposal.research_truth_claim
            || proposal.evidence.read_receipt.native
            || proposal.evidence.read_receipt.connected
        {
            return Err(MissionOpenAlexResearchConsumerError::AuthorityClaim);
        }
        if proposal.scope.digest() != self.scope_digest
            || proposal.scope.project() != &self.project
            || proposal.scope.mission() != &self.mission
            || proposal.scope.work_product() != &self.work_product
        {
            return Err(MissionOpenAlexResearchConsumerError::ScopeMismatch);
        }
        if proposal.proposal_digest != proposal.digest() {
            return Err(MissionOpenAlexResearchConsumerError::ProposalTampered);
        }
        if proposal.source_evidence_digest != proposal.evidence.digest()
            || proposal.evidence.evidence_digest != proposal.evidence.digest()
            || proposal.idempotency_digest != proposal.evidence.idempotency_digest
            || proposal.evidence.idempotency_digest
                != proposal.evidence.read_receipt.idempotency_digest
        {
            return Err(MissionOpenAlexResearchConsumerError::EvidenceTampered);
        }
        if !self
            .consumed_idempotency
            .insert(proposal.idempotency_digest.clone())
        {
            return Err(MissionOpenAlexResearchConsumerError::ReplayDetected);
        }
        Ok(MissionOpenAlexResearchResult {
            state: MissionResultState::from(proposal.evidence.state),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.source_evidence_digest.clone(),
            idempotency_digest: proposal.idempotency_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            work_digests: proposal
                .evidence
                .works
                .iter()
                .map(crate::OpenAlexWorkProjection::digest)
                .collect(),
            author_digests: proposal
                .evidence
                .authors
                .iter()
                .map(crate::OpenAlexAuthorProjection::digest)
                .collect(),
            institution_digests: proposal
                .evidence
                .institutions
                .iter()
                .map(crate::OpenAlexInstitutionProjection::digest)
                .collect(),
            concept_digests: proposal
                .evidence
                .concepts
                .iter()
                .map(crate::OpenAlexConceptProjection::digest)
                .collect(),
            citation_digests: proposal
                .evidence
                .citations
                .iter()
                .map(crate::OpenAlexCitationProjection::digest)
                .collect(),
            connected: false,
            native: false,
            adopts_outcome: false,
            adopts_work_product: false,
            ranking_claim: false,
            full_text: false,
            author_identity_claim: false,
            citation_truth_claim: false,
            research_truth_claim: false,
        })
    }

    pub fn project_proposal(
        &mut self,
        proposal: &OpenAlexResearchProposal,
    ) -> Result<MissionOpenAlexResearchResult, MissionOpenAlexResearchConsumerError> {
        self.consume(proposal)
    }
}

pub type MissionOpenAlexResearchResultState = MissionResultState;
pub type ConsumerError = MissionOpenAlexResearchConsumerError;
