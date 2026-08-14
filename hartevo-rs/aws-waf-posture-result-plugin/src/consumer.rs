//! Mission-scoped, non-authoritative AWS WAF posture consumer.

use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_WAF_POSTURE_CONSUMER_ID,
    model::{AwsWafPostureScope, Digest, WafDecisionState, WafDeploymentDecision},
    provider::AwsWafTransport,
    service::{
        AwsWafPostureEvidence, AwsWafPostureProposal, AwsWafPostureRegistration,
        AwsWafPostureService, RegistrationState, ServiceError,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission AWS WAF registration is revoked")]
    RegistrationRevoked,
    #[error("Mission AWS WAF scope or registration does not match")]
    ScopeMismatch,
    #[error("Mission AWS WAF proposal is tampered or stale")]
    ProposalTampered,
    #[error("Mission AWS WAF evidence could not be verified: {0}")]
    Service(#[from] ServiceError),
}

pub type MissionAwsWafDecisionState = WafDecisionState;
pub type MissionDeploymentDecision = WafDeploymentDecision;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsWafDecision {
    pub consumer_id: &'static str,
    pub mission: crate::MissionBinding,
    pub project: crate::ProjectBinding,
    pub work_product: crate::WorkProductBinding,
    pub state: MissionAwsWafDecisionState,
    pub deployment_decision: MissionDeploymentDecision,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub requires_human_review: bool,
    pub safe_to_deploy: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub truth_authority: bool,
    pub effective_authorization: bool,
    pub adopted_outcome: bool,
    pub adopted_work_product: bool,
    pub decision_digest: Digest,
}

pub type MissionAwsWafResult = MissionAwsWafDecision;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsWafConsumer {
    scope: AwsWafPostureScope,
    registration: AwsWafPostureRegistration,
}

impl MissionAwsWafConsumer {
    pub fn new(
        scope: AwsWafPostureScope,
        registration: AwsWafPostureRegistration,
    ) -> Result<Self, ConsumerError> {
        scope.validate().map_err(|_| ConsumerError::ScopeMismatch)?;
        if registration.state != RegistrationState::Active
            || registration.scope_digest != scope.digest()
            || registration.permission_digest != *scope.permission_digest()
            || registration.registration_digest != registration.recomputed_digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
        })
    }

    pub fn from_service<T: AwsWafTransport>(
        service: &AwsWafPostureService<T>,
    ) -> Result<Self, ConsumerError> {
        Self::new(service.scope().clone(), service.registration().clone())
    }

    pub fn scope(&self) -> &AwsWafPostureScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsWafPostureRegistration {
        &self.registration
    }

    pub fn revoke_registration(&mut self) -> Result<(), ConsumerError> {
        self.registration
            .revoke()
            .map(|_| ())
            .map_err(ConsumerError::Service)
    }

    pub fn restore_registration(&mut self) -> Result<(), ConsumerError> {
        self.registration.restore().map_err(ConsumerError::Service)
    }

    pub fn consume(
        &self,
        proposal: &AwsWafPostureProposal,
    ) -> Result<MissionAwsWafDecision, ConsumerError> {
        if self.registration.state != RegistrationState::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        proposal
            .validate_integrity()
            .map_err(|_| ConsumerError::ProposalTampered)?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != self.registration.permission_digest
            || proposal.state != proposal.evidence.state
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        let decision_digest = Digest::from_parts(
            "mission-aws-waf-decision/v1",
            &[
                self.scope.digest().to_string(),
                self.registration.registration_digest.to_string(),
                proposal.evidence.digest().to_string(),
                proposal.proposal_digest.to_string(),
                format!("{:?}", proposal.decision_state),
                format!("{:?}", proposal.deployment_decision),
            ],
        );
        Ok(MissionAwsWafDecision {
            consumer_id: AWS_WAF_POSTURE_CONSUMER_ID,
            mission: self.scope.mission.clone(),
            project: self.scope.project.clone(),
            work_product: self.scope.work_product.clone(),
            state: proposal.decision_state,
            deployment_decision: proposal.deployment_decision,
            scope_digest: self.scope.digest(),
            permission_digest: self.registration.permission_digest.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            evidence_digest: proposal.evidence.digest(),
            proposal_digest: proposal.proposal_digest.clone(),
            requires_human_review: true,
            safe_to_deploy: false,
            connected: false,
            native: false,
            first_party: false,
            truth_authority: false,
            effective_authorization: false,
            adopted_outcome: false,
            adopted_work_product: false,
            decision_digest,
        })
    }

    pub fn verify_evidence(&self, evidence: &AwsWafPostureEvidence) -> Result<(), ConsumerError> {
        if self.registration.state != RegistrationState::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        if evidence.scope_digest != self.scope.digest()
            || evidence.permission_digest != self.registration.permission_digest
            || evidence.registration_digest != self.registration.registration_digest
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        evidence
            .validate_integrity()
            .map_err(ConsumerError::Service)
    }
}
