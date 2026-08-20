//! Mission-scoped, non-authoritative Amazon Detective evidence consumer.

use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_DETECTIVE_CONSUMER_ID, AwsDetectiveEvidence, AwsDetectiveProposal,
    AwsDetectiveRegistration, AwsDetectiveScope, Digest, EvidenceStatus, RegistrationState,
    ServiceError, digest_serializable,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("Mission AWS Detective consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission AWS Detective consumer registration or scope does not match")]
    ScopeMismatch,
    #[error("Mission AWS Detective consumer proposal is stale or tampered")]
    ProposalTampered,
    #[error("Mission AWS Detective consumer evidence is outside its Mission scope")]
    EvidenceOutOfScope,
    #[error("Mission AWS Detective consumer service validation failed: {0}")]
    Service(#[from] ServiceError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAwsDetectiveDecisionState {
    ReviewRequired,
    ProviderUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAwsDetectiveResult {
    pub consumer_id: &'static str,
    pub decision_state: MissionAwsDetectiveDecisionState,
    pub operation: crate::DetectiveOperation,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub requires_human_review: bool,
    pub safe_to_promote: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub certification_claim: bool,
    pub adopted_outcome: bool,
    pub adopted_work_product: bool,
    pub truth_authority: bool,
    pub decision_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAwsDetectiveConsumer {
    scope: AwsDetectiveScope,
    registration: AwsDetectiveRegistration,
}

impl MissionAwsDetectiveConsumer {
    pub fn new(
        scope: AwsDetectiveScope,
        registration: AwsDetectiveRegistration,
    ) -> Result<Self, ConsumerError> {
        if registration.state != RegistrationState::Active
            || !registration.reversible
            || registration.scope_digest != scope.digest()
            || registration.registration_digest != registration.recomputed_digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
        })
    }

    pub fn scope(&self) -> &AwsDetectiveScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsDetectiveRegistration {
        &self.registration
    }

    pub fn consume(
        &self,
        proposal: AwsDetectiveProposal,
    ) -> Result<MissionAwsDetectiveResult, ConsumerError> {
        if self.registration.state != RegistrationState::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        proposal
            .validate()
            .map_err(|_| ConsumerError::ProposalTampered)?;
        self.verify_evidence(&proposal.evidence)?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.mission != self.scope.mission
            || proposal.evidence.digests.scope_digest != self.scope.digest()
        {
            return Err(ConsumerError::EvidenceOutOfScope);
        }
        let decision_state = match proposal.evidence.status {
            EvidenceStatus::Complete => MissionAwsDetectiveDecisionState::ReviewRequired,
        };
        let decision_digest = digest_serializable(&(
            AWS_DETECTIVE_CONSUMER_ID,
            proposal.operation,
            &self.scope.mission,
            self.scope.digest(),
            &self.registration.registration_digest,
            proposal.evidence.evidence_digest(),
            &proposal.proposal_digest,
            decision_state,
        ))
        .unwrap_or_else(|_| Digest::zero());
        Ok(MissionAwsDetectiveResult {
            consumer_id: AWS_DETECTIVE_CONSUMER_ID,
            decision_state,
            operation: proposal.operation,
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest().clone(),
            proposal_digest: proposal.proposal_digest,
            requires_human_review: true,
            safe_to_promote: false,
            connected: false,
            native: false,
            first_party: false,
            certification_claim: false,
            adopted_outcome: false,
            adopted_work_product: false,
            truth_authority: false,
            decision_digest,
        })
    }

    pub fn verify_evidence(&self, evidence: &AwsDetectiveEvidence) -> Result<(), ConsumerError> {
        evidence.verify()?;
        if evidence.registration_digest != self.registration.registration_digest
            || evidence.digests.scope_digest != self.scope.digest()
            || evidence.digests.permission_digest != self.registration.permission_digest
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(())
    }
}

pub type MissionAwsDetectiveConsumerError = ConsumerError;
pub type MissionAwsDetectiveResultEvidence = MissionAwsDetectiveResult;
