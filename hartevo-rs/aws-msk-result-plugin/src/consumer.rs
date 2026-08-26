//! Mission-scoped, non-authoritative AWS MSK evidence consumer.

use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_MSK_CONSUMER_ID,
    model::{AwsMskEvidence, AwsMskScope, Digest, ReadinessState},
    service::{AwsMskProposal, AwsMskRegistration, AwsMskServiceError, RegistrationState},
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission AWS MSK consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission AWS MSK consumer registration or scope does not match")]
    ScopeMismatch,
    #[error("Mission AWS MSK consumer proposal is stale or tampered")]
    ProposalTampered,
    #[error("Mission AWS MSK consumer could not validate service evidence: {0}")]
    Service(#[from] AwsMskServiceError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAwsMskDecisionState {
    ReadyForReview,
    NotReady,
    Partial,
    InsufficientData,
    AccessLoss,
    ProviderUnknown,
}

impl MissionAwsMskDecisionState {
    const fn from_evidence(state: ReadinessState) -> Self {
        match state {
            ReadinessState::Ready => Self::ReadyForReview,
            ReadinessState::NotReady => Self::NotReady,
            ReadinessState::Partial => Self::Partial,
            ReadinessState::InsufficientData => Self::InsufficientData,
            ReadinessState::AccessLoss => Self::AccessLoss,
            ReadinessState::ProviderUnknown => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsMskResult {
    pub consumer_id: &'static str,
    pub decision_state: MissionAwsMskDecisionState,
    pub observed_state: ReadinessState,
    pub cluster_readiness: ReadinessState,
    pub configuration_readiness: ReadinessState,
    pub operation_readiness: ReadinessState,
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
    pub truth_authority: bool,
    pub work_product_adoption: bool,
    pub decision_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsMskConsumer {
    scope: AwsMskScope,
    registration: AwsMskRegistration,
}

impl MissionAwsMskConsumer {
    pub fn new(
        scope: AwsMskScope,
        registration: AwsMskRegistration,
    ) -> Result<Self, ConsumerError> {
        if registration.state != RegistrationState::Active
            || registration.scope_digest != scope.digest()
            || registration.permission_digest != scope.permission_digest
            || registration.cluster_revision != scope.cluster.revision
            || registration.configuration_revision != scope.configuration.revision
            || registration.operation_scope_digest
                != crate::model::digest_serialized(&scope.operations)
            || registration.registration_digest != registration.recomputed_digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
        })
    }

    pub fn scope(&self) -> &AwsMskScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsMskRegistration {
        &self.registration
    }

    pub fn consume(&self, proposal: AwsMskProposal) -> Result<MissionAwsMskResult, ConsumerError> {
        if self.registration.state != RegistrationState::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        proposal
            .validate()
            .map_err(|_| ConsumerError::ProposalTampered)?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != self.registration.permission_digest
            || proposal.evidence.cluster_revision != self.scope.cluster.revision
            || proposal.evidence.configuration_revision != self.scope.configuration.revision
            || proposal.evidence.operation_scope_digest
                != crate::model::digest_serialized(&self.scope.operations)
            || proposal.state != proposal.evidence.state
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        let decision_state = MissionAwsMskDecisionState::from_evidence(proposal.state);
        let decision_digest = Digest::from_parts(
            "hartevo-mission-aws-msk-decision/v1",
            &[
                self.scope.digest().to_string(),
                self.registration.registration_digest.to_string(),
                proposal.evidence.evidence_digest.to_string(),
                proposal.proposal_digest.to_string(),
                format!("{decision_state:?}"),
            ],
        );
        Ok(MissionAwsMskResult {
            consumer_id: AWS_MSK_CONSUMER_ID,
            decision_state,
            observed_state: proposal.state,
            cluster_readiness: proposal.evidence.cluster_readiness,
            configuration_readiness: proposal.evidence.configuration_readiness,
            operation_readiness: proposal.evidence.operation_readiness,
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest,
            proposal_digest: proposal.proposal_digest,
            requires_human_review: true,
            safe_to_promote: false,
            connected: false,
            native: false,
            first_party: false,
            certification_claim: false,
            adopted_outcome: false,
            truth_authority: false,
            work_product_adoption: false,
            decision_digest,
        })
    }

    pub fn verify_evidence(&self, evidence: &AwsMskEvidence) -> Result<(), ConsumerError> {
        if evidence.scope_digest != self.scope.digest()
            || evidence.permission_digest != self.registration.permission_digest
            || evidence.cluster_revision != self.scope.cluster.revision
            || evidence.configuration_revision != self.scope.configuration.revision
            || evidence.operation_scope_digest
                != crate::model::digest_serialized(&self.scope.operations)
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        evidence
            .validate()
            .map_err(|_| ConsumerError::ProposalTampered)
    }
}

pub type MissionAwsMskResultConsumer = MissionAwsMskConsumer;
pub type MissionAwsMskDecision = MissionAwsMskDecisionState;
pub type MissionAwsMskConsumerError = ConsumerError;
