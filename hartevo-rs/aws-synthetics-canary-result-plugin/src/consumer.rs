//! Mission-scoped, non-authoritative endpoint-verification consumer.

use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_SYNTHETICS_CONSUMER_ID,
    model::{
        AwsSyntheticsScope, CanaryEvidence, Digest, EndpointId, EvidenceState, MissionBinding,
        ProjectBinding, WorkProductBinding,
    },
    service::{
        AwsSyntheticsCanaryProposal, AwsSyntheticsCanaryServiceError, AwsSyntheticsRegistration,
        RegistrationState,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission AWS Synthetics consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission AWS Synthetics consumer registration or scope does not match")]
    ScopeMismatch,
    #[error("Mission AWS Synthetics consumer proposal is stale or tampered")]
    ProposalTampered,
    #[error("Mission AWS Synthetics consumer could not validate service evidence: {0}")]
    Service(#[from] AwsSyntheticsCanaryServiceError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAwsSyntheticsDecisionState {
    ObservedPassReview,
    ObservedFailure,
    Pending,
    Stopped,
    Unknown,
    Partial,
    AccessLoss,
    Throttled,
    Timeout,
    ProviderUnknown,
}

impl MissionAwsSyntheticsDecisionState {
    const fn from_evidence(state: EvidenceState) -> Self {
        match state {
            EvidenceState::Passed => Self::ObservedPassReview,
            EvidenceState::Failed => Self::ObservedFailure,
            EvidenceState::Running => Self::Pending,
            EvidenceState::Stopped => Self::Stopped,
            EvidenceState::Unknown => Self::Unknown,
            EvidenceState::Partial => Self::Partial,
            EvidenceState::AccessLoss => Self::AccessLoss,
            EvidenceState::Throttled => Self::Throttled,
            EvidenceState::Timeout => Self::Timeout,
            EvidenceState::ProviderUnknown => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsSyntheticsEndpointDecision {
    pub consumer_id: &'static str,
    pub decision_state: MissionAwsSyntheticsDecisionState,
    pub observed_evidence_state: EvidenceState,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub endpoint_id: EndpointId,
    pub endpoint_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub requires_human_review: bool,
    pub safe_to_promote: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub verification_authority: bool,
    pub certification_claim: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
    pub decision_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsSyntheticsConsumer {
    scope: AwsSyntheticsScope,
    registration: AwsSyntheticsRegistration,
}

impl MissionAwsSyntheticsConsumer {
    pub fn new(
        scope: AwsSyntheticsScope,
        registration: AwsSyntheticsRegistration,
    ) -> Result<Self, ConsumerError> {
        if registration.state != RegistrationState::Active
            || registration.scope_digest != scope.digest()
            || registration.permission_digest != scope.permission_digest
            || registration.registration_digest != registration.recomputed_digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
        })
    }

    pub fn scope(&self) -> &AwsSyntheticsScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsSyntheticsRegistration {
        &self.registration
    }

    pub fn consume(
        &self,
        proposal: AwsSyntheticsCanaryProposal,
    ) -> Result<MissionAwsSyntheticsEndpointDecision, ConsumerError> {
        if self.registration.state != RegistrationState::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        proposal
            .validate()
            .map_err(|_| ConsumerError::ProposalTampered)?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != self.registration.permission_digest
            || proposal.state != proposal.evidence.state
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        self.verify_evidence(&proposal.evidence)?;
        let decision_state = MissionAwsSyntheticsDecisionState::from_evidence(proposal.state);
        let decision_digest = Digest::from_parts(
            "hartevo-mission-aws-synthetics-endpoint-decision/v1",
            &[
                self.scope.digest().to_string(),
                self.registration.registration_digest.to_string(),
                proposal.evidence.evidence_digest.to_string(),
                proposal.proposal_digest.to_string(),
                format!("{decision_state:?}"),
            ],
        );
        Ok(MissionAwsSyntheticsEndpointDecision {
            consumer_id: AWS_SYNTHETICS_CONSUMER_ID,
            decision_state,
            observed_evidence_state: proposal.state,
            project: self.scope.project.clone(),
            mission: self.scope.mission.clone(),
            work_product: self.scope.work_product.clone(),
            endpoint_id: self.scope.target.endpoint_id.clone(),
            endpoint_digest: self.scope.target.endpoint_digest.clone(),
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest,
            proposal_digest: proposal.proposal_digest,
            requires_human_review: true,
            safe_to_promote: false,
            connected: false,
            native: false,
            first_party: false,
            verification_authority: false,
            certification_claim: false,
            adopted_outcome: false,
            truth_authority: false,
            decision_digest,
        })
    }

    pub fn verify_evidence(&self, evidence: &CanaryEvidence) -> Result<(), ConsumerError> {
        if evidence.scope_digest != self.scope.digest()
            || evidence.permission_digest != self.registration.permission_digest
            || evidence.provider_digest != self.registration.provider_digest
            || evidence.provider_revision != self.registration.provider_revision
            || evidence.api_digest != self.registration.api_digest
            || evidence.contract_digest != self.registration.contract_digest
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if evidence.runs.iter().any(|run| {
            run.canary_name != self.scope.target.canary_name
                || run.canary_revision != self.scope.target.canary_revision
                || run.endpoint_digest != self.scope.target.endpoint_digest
        }) {
            return Err(ConsumerError::ScopeMismatch);
        }
        evidence
            .validate()
            .map_err(|_| ConsumerError::ProposalTampered)
    }
}

pub type MissionAwsSyntheticsResult = MissionAwsSyntheticsEndpointDecision;
pub type MissionAwsSyntheticsDecision = MissionAwsSyntheticsEndpointDecision;
pub type MissionAwsSyntheticsConsumerError = ConsumerError;
