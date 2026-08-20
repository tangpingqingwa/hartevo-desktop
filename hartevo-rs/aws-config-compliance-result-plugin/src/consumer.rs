//! Mission-scoped, non-authoritative AWS Config evidence consumer.

use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_CONFIG_CONSUMER_ID,
    model::{AwsConfigComplianceEvidence, AwsConfigScope, ComplianceState, Digest},
    service::{
        AwsConfigComplianceProposal, AwsConfigComplianceServiceError, AwsConfigRegistration,
        RegistrationState,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission AWS Config consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission AWS Config consumer registration or scope does not match")]
    ScopeMismatch,
    #[error("Mission AWS Config consumer proposal is stale or tampered")]
    ProposalTampered,
    #[error("Mission AWS Config consumer could not validate service evidence: {0}")]
    Service(#[from] AwsConfigComplianceServiceError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAwsConfigDecisionState {
    ReviewRequired,
    NonCompliant,
    NotApplicable,
    InsufficientData,
    Partial,
    AccessLoss,
    ProviderUnknown,
}

impl MissionAwsConfigDecisionState {
    const fn from_evidence(state: ComplianceState) -> Self {
        match state {
            ComplianceState::Compliant => Self::ReviewRequired,
            ComplianceState::NonCompliant => Self::NonCompliant,
            ComplianceState::NotApplicable => Self::NotApplicable,
            ComplianceState::InsufficientData => Self::InsufficientData,
            ComplianceState::Partial => Self::Partial,
            ComplianceState::AccessLoss => Self::AccessLoss,
            ComplianceState::ProviderUnknown => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsConfigResult {
    pub consumer_id: &'static str,
    pub decision_state: MissionAwsConfigDecisionState,
    pub observed_compliance_state: ComplianceState,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub requires_human_review: bool,
    pub safe_to_promote: bool,
    pub connected: bool,
    pub native: bool,
    pub certification_claim: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
    pub decision_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsConfigConsumer {
    scope: AwsConfigScope,
    registration: AwsConfigRegistration,
}

impl MissionAwsConfigConsumer {
    pub fn new(
        scope: AwsConfigScope,
        registration: AwsConfigRegistration,
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

    pub fn scope(&self) -> &AwsConfigScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsConfigRegistration {
        &self.registration
    }

    pub fn consume(
        &self,
        proposal: AwsConfigComplianceProposal,
    ) -> Result<MissionAwsConfigResult, ConsumerError> {
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
        let decision_state = MissionAwsConfigDecisionState::from_evidence(proposal.state);
        let decision_digest = Digest::from_parts(
            "hartevo-mission-aws-config-decision/v1",
            &[
                self.scope.digest().to_string(),
                self.registration.registration_digest.to_string(),
                proposal.evidence.evidence_digest.to_string(),
                proposal.proposal_digest.to_string(),
                format!("{decision_state:?}"),
            ],
        );
        Ok(MissionAwsConfigResult {
            consumer_id: AWS_CONFIG_CONSUMER_ID,
            decision_state,
            observed_compliance_state: proposal.state,
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest,
            proposal_digest: proposal.proposal_digest,
            requires_human_review: true,
            safe_to_promote: false,
            connected: false,
            native: false,
            certification_claim: false,
            adopted_outcome: false,
            truth_authority: false,
            decision_digest,
        })
    }

    pub fn verify_evidence(
        &self,
        evidence: &AwsConfigComplianceEvidence,
    ) -> Result<(), ConsumerError> {
        if evidence.scope_digest != self.scope.digest()
            || evidence.permission_digest != self.registration.permission_digest
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        evidence
            .validate()
            .map_err(|_| ConsumerError::ProposalTampered)
    }
}

pub type MissionAwsConfigComplianceConsumer = MissionAwsConfigConsumer;
pub type MissionAwsConfigComplianceResult = MissionAwsConfigResult;
pub type MissionAwsConfigConsumerError = ConsumerError;
