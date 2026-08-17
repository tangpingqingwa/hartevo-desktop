//! Mission-scoped, non-authoritative CloudWatch Logs evidence consumer.

use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_CLOUDWATCH_LOGS_CONSUMER_ID,
    model::{AwsCloudWatchLogsScope, Digest, EvidenceState, RegistrationState},
    service::{
        AwsCloudWatchLogsProposal, AwsCloudWatchLogsRegistration, AwsCloudWatchLogsServiceError,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission CloudWatch Logs consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission CloudWatch Logs consumer registration or scope does not match")]
    ScopeMismatch,
    #[error("Mission CloudWatch Logs consumer proposal is stale or tampered")]
    ProposalTampered,
    #[error("Mission CloudWatch Logs consumer could not validate service evidence: {0}")]
    Service(#[from] AwsCloudWatchLogsServiceError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAwsCloudWatchLogsDecisionState {
    ReviewRequired,
    Running,
    Partial,
    Expired,
    AccessLoss,
    ProviderUnknown,
    Failed,
    Replay,
    Tampered,
    RegistrationRevoked,
}

impl MissionAwsCloudWatchLogsDecisionState {
    const fn from_evidence(state: EvidenceState) -> Self {
        match state {
            EvidenceState::Complete => Self::ReviewRequired,
            EvidenceState::Running => Self::Running,
            EvidenceState::Partial => Self::Partial,
            EvidenceState::Expired => Self::Expired,
            EvidenceState::AccessLoss => Self::AccessLoss,
            EvidenceState::ProviderUnknown => Self::ProviderUnknown,
            EvidenceState::Failed => Self::Failed,
            EvidenceState::Replay => Self::Replay,
            EvidenceState::Tampered => Self::Tampered,
            EvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsCloudWatchLogsResult {
    pub consumer_id: &'static str,
    pub decision_state: MissionAwsCloudWatchLogsDecisionState,
    pub observed_state: EvidenceState,
    pub mission_id_digest: Digest,
    pub project_id_digest: Digest,
    pub work_product_id_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub requires_human_review: bool,
    pub safe_to_promote: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub truth_authority: bool,
    pub adopted_outcome: bool,
    pub adopted_work_product: bool,
    pub decision_digest: Digest,
}

impl MissionAwsCloudWatchLogsResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

pub struct MissionAwsCloudWatchLogsConsumer {
    scope: AwsCloudWatchLogsScope,
    registration: AwsCloudWatchLogsRegistration,
}

impl std::fmt::Debug for MissionAwsCloudWatchLogsConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionAwsCloudWatchLogsConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .finish()
    }
}

impl MissionAwsCloudWatchLogsConsumer {
    pub fn new<R>(scope: AwsCloudWatchLogsScope, registration: R) -> Result<Self, ConsumerError>
    where
        R: Into<AwsCloudWatchLogsRegistration>,
    {
        let registration = registration.into();
        if registration.state != RegistrationState::Active
            || registration.scope_digest != scope.digest()
            || registration.permission_digest == Digest::zero()
            || registration.registration_digest != registration.recomputed_digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
        })
    }

    pub fn scope(&self) -> &AwsCloudWatchLogsScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsCloudWatchLogsRegistration {
        &self.registration
    }

    pub fn consume<P>(&self, proposal: P) -> Result<MissionAwsCloudWatchLogsResult, ConsumerError>
    where
        P: Into<AwsCloudWatchLogsProposal>,
    {
        let proposal = proposal.into();
        if self.registration.state != RegistrationState::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        proposal
            .validate()
            .map_err(|_| ConsumerError::ProposalTampered)?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.registration_revision
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != self.registration.permission_digest
            || proposal.evidence.query_digest != *proposal.query.query_digest()
            || proposal.evidence.config_digest != *proposal.query.config_digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        let decision_state = MissionAwsCloudWatchLogsDecisionState::from_evidence(proposal.state);
        let decision_digest = Digest::from_parts(
            "hartevo-mission-aws-cloudwatch-logs-decision/v1",
            &[
                self.scope.digest().to_string(),
                self.registration.registration_digest.to_string(),
                proposal.evidence.evidence_digest.to_string(),
                proposal.proposal_digest.to_string(),
                format!("{decision_state:?}"),
            ],
        );
        Ok(MissionAwsCloudWatchLogsResult {
            consumer_id: AWS_CLOUDWATCH_LOGS_CONSUMER_ID,
            decision_state,
            observed_state: proposal.state,
            mission_id_digest: Digest::from_text(self.scope.mission.id.as_str()),
            project_id_digest: Digest::from_text(self.scope.project.id.as_str()),
            work_product_id_digest: Digest::from_text(self.scope.work_product.id.as_str()),
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest,
            proposal_digest: proposal.proposal_digest,
            requires_human_review: true,
            safe_to_promote: false,
            connected: false,
            native: false,
            first_party: false,
            truth_authority: false,
            adopted_outcome: false,
            adopted_work_product: false,
            decision_digest,
        })
    }

    pub fn verify_evidence(
        &self,
        evidence: &crate::AwsCloudWatchLogsEvidence,
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

pub type MissionAwsCloudWatchLogsConsumerError = ConsumerError;
pub type MissionAwsCloudWatchLogsDecision = MissionAwsCloudWatchLogsResult;
pub type MissionAwsCloudWatchLogsResultProposal = AwsCloudWatchLogsProposal;
