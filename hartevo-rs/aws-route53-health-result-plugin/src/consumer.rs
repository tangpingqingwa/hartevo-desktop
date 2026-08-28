//! Mission-facing, review-only Route 53 health evidence consumer.

use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_ROUTE53_HEALTH_CONSUMER_ID,
    model::{AwsRoute53HealthEvidence, AwsRoute53HealthScope, Digest, EvidenceState},
    service::{
        AwsRoute53HealthProposal, AwsRoute53HealthRegistration, AwsRoute53HealthServiceError,
        RegistrationState,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission Route 53 consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission Route 53 consumer scope, revision, or permission does not match")]
    ScopeMismatch,
    #[error("Mission Route 53 consumer proposal or evidence is stale or tampered")]
    ProposalTampered,
    #[error("Mission Route 53 consumer cannot adopt Layer-1 evidence")]
    AdoptionForbidden,
    #[error("Mission Route 53 service error: {0}")]
    Service(#[from] AwsRoute53HealthServiceError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAwsRoute53DecisionState {
    ReviewRequired,
    HealthyReviewRequired,
    UnhealthyReviewRequired,
    InsufficientData,
    Unsupported,
    NotFound,
    Partial,
    AccessLoss,
    Throttled,
    Timeout,
    ProviderUnknown,
}

impl MissionAwsRoute53DecisionState {
    const fn from_evidence(state: EvidenceState) -> Self {
        match state {
            EvidenceState::Healthy => Self::HealthyReviewRequired,
            EvidenceState::Unhealthy => Self::UnhealthyReviewRequired,
            EvidenceState::InsufficientData => Self::InsufficientData,
            EvidenceState::Unsupported => Self::Unsupported,
            EvidenceState::NotFound => Self::NotFound,
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
pub struct MissionAwsRoute53Result {
    pub consumer_id: &'static str,
    pub deployment: crate::model::DeploymentBinding,
    pub mission: crate::model::MissionBinding,
    pub project: crate::model::ProjectBinding,
    pub work_product: crate::model::WorkProductBinding,
    pub decision_state: MissionAwsRoute53DecisionState,
    pub observed_health_state: EvidenceState,
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

pub type MissionAwsRoute53HealthResult = MissionAwsRoute53Result;
pub type MissionAwsRoute53HealthConsumer = MissionAwsRoute53Consumer;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsRoute53Consumer {
    scope: AwsRoute53HealthScope,
    registration: AwsRoute53HealthRegistration,
    revoked: bool,
}

impl MissionAwsRoute53Consumer {
    pub fn new(
        scope: AwsRoute53HealthScope,
        registration: AwsRoute53HealthRegistration,
    ) -> Result<Self, ConsumerError> {
        if registration.state != RegistrationState::Active
            || registration.scope_digest != scope.digest()
            || registration.permission_digest != scope.permission_digest
            || registration.health_check_revision != scope.health_check.revision
            || registration.registration_digest != registration.recomputed_digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            revoked: false,
        })
    }

    pub fn scope(&self) -> &AwsRoute53HealthScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsRoute53HealthRegistration {
        &self.registration
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if self.revoked {
            return Err(ConsumerError::RegistrationRevoked);
        }
        self.revoked = true;
        Ok(())
    }

    pub fn consume(
        &self,
        proposal: AwsRoute53HealthProposal,
    ) -> Result<MissionAwsRoute53Result, ConsumerError> {
        if self.revoked || self.registration.state != RegistrationState::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        proposal
            .validate()
            .map_err(|_| ConsumerError::ProposalTampered)?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != self.registration.permission_digest
            || proposal
                .evidence
                .health_check
                .as_ref()
                .is_some_and(|health_check| {
                    health_check.id != self.scope.health_check.id
                        || health_check.revision != self.scope.health_check.revision
                        || health_check.configuration.target != self.scope.health_check.target
                })
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if proposal.connected
            || proposal.native
            || proposal.first_party
            || proposal.certification_claim
            || proposal.adopted_outcome
            || proposal.truth_authority
            || !proposal.is_review_only()
        {
            return Err(ConsumerError::AdoptionForbidden);
        }
        let decision_state = MissionAwsRoute53DecisionState::from_evidence(proposal.state);
        let decision_digest = Digest::from_parts(
            "hartevo-mission-aws-route53-health-decision/v1",
            &[
                self.scope.digest().to_string(),
                self.registration.registration_digest.to_string(),
                proposal.evidence.evidence_digest.to_string(),
                proposal.proposal_digest.to_string(),
                format!("{decision_state:?}"),
            ],
        );
        Ok(MissionAwsRoute53Result {
            consumer_id: AWS_ROUTE53_HEALTH_CONSUMER_ID,
            deployment: self.scope.deployment.clone(),
            mission: self.scope.mission.clone(),
            project: self.scope.project.clone(),
            work_product: self.scope.work_product.clone(),
            decision_state,
            observed_health_state: proposal.state,
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

    pub fn verify_evidence(
        &self,
        evidence: &AwsRoute53HealthEvidence,
    ) -> Result<(), ConsumerError> {
        if self.revoked || self.registration.state != RegistrationState::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        if evidence.registration_digest != self.registration.registration_digest
            || evidence.scope_digest != self.scope.digest()
            || evidence.permission_digest != self.registration.permission_digest
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        evidence
            .validate()
            .map_err(|_| ConsumerError::ProposalTampered)
    }
}
