use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Digest, IdentityBinding, PubMedEvidenceState, PubMedResearchProposal, PubMedResearchScope,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionResultState {
    Complete,
    Partial,
    Empty,
    Denied,
    RateLimited,
    ProviderUnknown,
    BlockedEnv,
    MalformedResponse,
    ResponseTooLarge,
    Tamper,
}

#[allow(non_upper_case_globals)]
impl MissionResultState {
    pub const AccessLost: Self = Self::Denied;
}

impl From<&PubMedEvidenceState> for MissionResultState {
    fn from(state: &PubMedEvidenceState) -> Self {
        match state {
            PubMedEvidenceState::Complete => Self::Complete,
            PubMedEvidenceState::Partial => Self::Partial,
            PubMedEvidenceState::Empty => Self::Empty,
            PubMedEvidenceState::Denied => Self::Denied,
            PubMedEvidenceState::RateLimited => Self::RateLimited,
            PubMedEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            PubMedEvidenceState::BlockedEnv => Self::BlockedEnv,
            PubMedEvidenceState::MalformedResponse => Self::MalformedResponse,
            PubMedEvidenceState::ResponseTooLarge => Self::ResponseTooLarge,
            PubMedEvidenceState::Tamper => Self::Tamper,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionPubMedResearchConsumerError {
    #[error("PubMed proposal is not proposal-only")]
    NotProposalOnly,
    #[error("PubMed proposal has a native or connected claim")]
    NativeOrConnectedClaim,
    #[error("PubMed proposal does not match the Mission scope")]
    ScopeMismatch,
    #[error("PubMed proposal registration does not match the bound consumer")]
    RegistrationMismatch,
    #[error("PubMed proposal digest is stale or tampered")]
    ProposalTampered,
    #[error("PubMed evidence digest is stale or tampered")]
    EvidenceTampered,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionPubMedResearchConsumer {
    project: IdentityBinding,
    mission: IdentityBinding,
    work_product: IdentityBinding,
    scope_digest: Digest,
    registration_digest: Option<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionPubMedResearchResult {
    pub state: MissionResultState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub pmid_digest: Option<Digest>,
    pub pmcid_digest: Option<Digest>,
    pub mesh_digest: Option<Digest>,
    pub article_digests: Vec<Digest>,
    pub link_digests: Vec<Digest>,
    pub result_digests: Vec<Digest>,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
}

impl MissionPubMedResearchConsumer {
    #[must_use]
    pub fn new(scope: &PubMedResearchScope) -> Self {
        Self::from_scope(scope)
    }

    #[must_use]
    pub fn from_scope(scope: &PubMedResearchScope) -> Self {
        Self {
            project: scope.project().clone(),
            mission: scope.mission().clone(),
            work_product: scope.work_product().clone(),
            scope_digest: scope.digest(),
            registration_digest: None,
        }
    }

    #[must_use]
    pub fn new_bound(scope: &PubMedResearchScope, registration_digest: Digest) -> Self {
        let mut consumer = Self::from_scope(scope);
        consumer.registration_digest = Some(registration_digest);
        consumer
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

    #[must_use]
    pub fn registration_digest(&self) -> Option<&str> {
        self.registration_digest.as_deref()
    }

    pub fn consume(
        &self,
        proposal: &PubMedResearchProposal,
    ) -> Result<MissionPubMedResearchResult, MissionPubMedResearchConsumerError> {
        if !proposal.proposal_only {
            return Err(MissionPubMedResearchConsumerError::NotProposalOnly);
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
            return Err(MissionPubMedResearchConsumerError::NativeOrConnectedClaim);
        }
        if proposal.scope.digest() != self.scope_digest
            || proposal.scope.project() != &self.project
            || proposal.scope.mission() != &self.mission
            || proposal.scope.work_product() != &self.work_product
        {
            return Err(MissionPubMedResearchConsumerError::ScopeMismatch);
        }
        if self
            .registration_digest
            .as_deref()
            .is_some_and(|digest| digest != proposal.registration_digest)
        {
            return Err(MissionPubMedResearchConsumerError::RegistrationMismatch);
        }
        if proposal.proposal_digest != proposal.digest() {
            return Err(MissionPubMedResearchConsumerError::ProposalTampered);
        }
        if proposal.source_evidence_digest != proposal.evidence.digest()
            || proposal.evidence.evidence_digest != proposal.evidence.digest()
        {
            return Err(MissionPubMedResearchConsumerError::EvidenceTampered);
        }
        let article_digests = proposal
            .evidence
            .articles
            .iter()
            .map(crate::PubMedArticleProjection::digest)
            .collect::<Vec<_>>();
        let link_digests = proposal
            .evidence
            .links
            .iter()
            .map(crate::PubMedLinkProjection::digest)
            .collect::<Vec<_>>();
        let result_digests = article_digests
            .iter()
            .chain(&link_digests)
            .cloned()
            .collect();
        Ok(MissionPubMedResearchResult {
            state: MissionResultState::from(&proposal.evidence.state),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.source_evidence_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            query_digest: proposal.evidence.query_digest.clone(),
            pmid_digest: proposal.evidence.pmid_digest.clone(),
            pmcid_digest: proposal.evidence.pmcid_digest.clone(),
            mesh_digest: proposal.evidence.mesh_digest.clone(),
            article_digests,
            link_digests,
            result_digests,
            connected: false,
            native: false,
            first_party: false,
            adopts_outcome: false,
            adopts_work_product: false,
        })
    }

    pub fn project_proposal(
        &self,
        proposal: &PubMedResearchProposal,
    ) -> Result<MissionPubMedResearchResult, MissionPubMedResearchConsumerError> {
        self.consume(proposal)
    }
}

pub type MissionPubMedResearchResultState = MissionResultState;
pub type ConsumerError = MissionPubMedResearchConsumerError;
