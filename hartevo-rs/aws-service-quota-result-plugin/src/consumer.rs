//! Mission-scoped, non-authoritative AWS Service Quotas decision consumer.

use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_SERVICE_QUOTA_CONSUMER_ID,
    model::{AwsServiceQuotaScope, Digest, QuotaEvidenceState},
    service::{
        AwsServiceQuotaProposal, AwsServiceQuotaRegistration, AwsServiceQuotaServiceError,
        RegistrationState,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission AWS Service Quotas consumer registration is revoked or reversed")]
    RegistrationRevoked,
    #[error("Mission AWS Service Quotas consumer registration or scope does not match")]
    ScopeMismatch,
    #[error("Mission AWS Service Quotas consumer proposal is stale or tampered")]
    ProposalTampered,
    #[error("Mission AWS Service Quotas consumer could not validate service evidence: {0}")]
    Service(#[from] AwsServiceQuotaServiceError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAwsServiceQuotaDecisionState {
    ReviewRequired,
    Partial,
    StaleUsage,
    PaginationIncomplete,
    InsufficientData,
    AccessLoss,
    ProviderUnknown,
}

impl MissionAwsServiceQuotaDecisionState {
    const fn from_evidence(state: QuotaEvidenceState) -> Self {
        match state {
            QuotaEvidenceState::Complete => Self::ReviewRequired,
            QuotaEvidenceState::Partial => Self::Partial,
            QuotaEvidenceState::StaleUsage => Self::StaleUsage,
            QuotaEvidenceState::PaginationIncomplete => Self::PaginationIncomplete,
            QuotaEvidenceState::InsufficientData => Self::InsufficientData,
            QuotaEvidenceState::AccessLoss => Self::AccessLoss,
            QuotaEvidenceState::ProviderUnknown | QuotaEvidenceState::RegistrationRevoked => {
                Self::ProviderUnknown
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsServiceQuotaResult {
    pub consumer_id: &'static str,
    pub decision_state: MissionAwsServiceQuotaDecisionState,
    pub observed_quota_state: QuotaEvidenceState,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub quota_posture_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub requires_human_review: bool,
    pub safe_to_promote: bool,
    pub capacity_guarantee: bool,
    pub infrastructure_guarantee: bool,
    pub financial_guarantee: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub truth_authority: bool,
    pub adopted_outcome: bool,
    pub decision_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsServiceQuotaConsumer {
    scope: AwsServiceQuotaScope,
    registration: AwsServiceQuotaRegistration,
}

impl MissionAwsServiceQuotaConsumer {
    pub fn new(
        scope: AwsServiceQuotaScope,
        registration: AwsServiceQuotaRegistration,
    ) -> Result<Self, ConsumerError> {
        if registration.state != RegistrationState::Active
            || registration.scope_digest != scope.digest()
            || registration.quota_digest != scope.quota_digest()
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

    pub fn scope(&self) -> &AwsServiceQuotaScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsServiceQuotaRegistration {
        &self.registration
    }

    pub fn consume(
        &self,
        proposal: AwsServiceQuotaProposal,
    ) -> Result<MissionAwsServiceQuotaResult, ConsumerError> {
        self.consume_ref(&proposal)
    }

    pub fn consume_ref(
        &self,
        proposal: &AwsServiceQuotaProposal,
    ) -> Result<MissionAwsServiceQuotaResult, ConsumerError> {
        if self.registration.state != RegistrationState::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        proposal
            .validate()
            .map_err(|_| ConsumerError::ProposalTampered)?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.quota_digest != self.scope.quota_digest()
            || proposal.evidence.permission_digest != self.registration.permission_digest
            || proposal.evidence.registration_evidence_digest != self.registration.evidence_digest
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        let decision_state =
            MissionAwsServiceQuotaDecisionState::from_evidence(proposal.evidence.state);
        let decision_digest = Digest::from_parts(
            "hartevo-mission-aws-service-quota-decision/v1",
            &[
                self.scope.digest().to_string(),
                self.registration.registration_digest.to_string(),
                proposal.evidence.quota_posture_digest.to_string(),
                proposal.evidence.evidence_digest.to_string(),
                proposal.proposal_digest.to_string(),
                format!("{decision_state:?}"),
            ],
        );
        Ok(MissionAwsServiceQuotaResult {
            consumer_id: AWS_SERVICE_QUOTA_CONSUMER_ID,
            decision_state,
            observed_quota_state: proposal.evidence.state,
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest.clone(),
            quota_posture_digest: proposal.evidence.quota_posture_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            requires_human_review: true,
            safe_to_promote: false,
            capacity_guarantee: false,
            infrastructure_guarantee: false,
            financial_guarantee: false,
            connected: false,
            native: false,
            first_party: false,
            truth_authority: false,
            adopted_outcome: false,
            decision_digest,
        })
    }

    pub fn verify_evidence(
        &self,
        evidence: &crate::AwsServiceQuotaEvidence,
    ) -> Result<(), ConsumerError> {
        if evidence.scope_digest != self.scope.digest()
            || evidence.quota_digest != self.scope.quota_digest()
            || evidence.permission_digest != self.registration.permission_digest
            || evidence.registration_evidence_digest != self.registration.evidence_digest
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        evidence
            .validate()
            .map_err(|_| ConsumerError::ProposalTampered)
    }
}

pub type MissionAwsServiceQuotaResultConsumer = MissionAwsServiceQuotaConsumer;
pub type MissionAwsServiceQuotaConsumerError = ConsumerError;
pub type MissionAwsServiceQuotaDecision = MissionAwsServiceQuotaResult;
