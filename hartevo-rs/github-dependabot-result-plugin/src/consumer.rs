//! Mission-scoped, non-authoritative Dependabot evidence consumer.

use serde::Serialize;
use thiserror::Error;

use crate::{
    GITHUB_DEPENDABOT_CONSUMER_ID,
    model::{
        DependabotEvidenceState, Digest, GithubDependabotEvidence, GithubDependabotScope,
        MissionId, ProjectId, WorkProductId,
    },
    service::{
        GithubDependabotProposal, GithubDependabotRegistration, GithubDependabotServiceError,
        RegistrationState,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission GitHub Dependabot consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission GitHub Dependabot consumer registration or scope does not match")]
    ScopeMismatch,
    #[error("Mission GitHub Dependabot consumer proposal is stale or tampered")]
    ProposalTampered,
    #[error("Mission GitHub Dependabot consumer could not validate service evidence: {0}")]
    Service(#[from] GithubDependabotServiceError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionGithubDependabotDecisionState {
    ReviewRequired,
    NoOpenAlerts,
    InsufficientData,
    Partial,
    AccessLoss,
    ProviderUnknown,
    NotModified,
}

impl MissionGithubDependabotDecisionState {
    const fn from_evidence(state: DependabotEvidenceState) -> Self {
        match state {
            DependabotEvidenceState::Open => Self::ReviewRequired,
            DependabotEvidenceState::Fixed
            | DependabotEvidenceState::Dismissed
            | DependabotEvidenceState::AutoDismissed => Self::NoOpenAlerts,
            DependabotEvidenceState::InsufficientData => Self::InsufficientData,
            DependabotEvidenceState::Partial => Self::Partial,
            DependabotEvidenceState::AccessLoss => Self::AccessLoss,
            DependabotEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            DependabotEvidenceState::NotModified => Self::NotModified,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionGithubDependabotDecision {
    pub consumer_id: &'static str,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub decision_state: MissionGithubDependabotDecisionState,
    pub observed_evidence_state: DependabotEvidenceState,
    pub alert_count: usize,
    pub open_alert_count: usize,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub requires_human_review: bool,
    pub remediation_authority: bool,
    pub safe_to_promote: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
    pub decision_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionGithubDependabotConsumer {
    scope: GithubDependabotScope,
    registration: GithubDependabotRegistration,
}

impl MissionGithubDependabotConsumer {
    pub fn new(
        scope: GithubDependabotScope,
        registration: GithubDependabotRegistration,
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

    pub fn scope(&self) -> &GithubDependabotScope {
        &self.scope
    }

    pub fn registration(&self) -> &GithubDependabotRegistration {
        &self.registration
    }

    pub fn consume(
        &self,
        proposal: GithubDependabotProposal,
    ) -> Result<MissionGithubDependabotDecision, ConsumerError> {
        if self.registration.state != RegistrationState::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        proposal
            .validate()
            .map_err(|_| ConsumerError::ProposalTampered)?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != self.registration.permission_digest
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        let decision_state =
            MissionGithubDependabotDecisionState::from_evidence(proposal.evidence.state);
        let decision_digest = Digest::from_parts(
            "hartevo-mission-github-dependabot-decision/v1",
            &[
                self.scope.project.id.as_str().to_owned(),
                self.scope.mission.id.as_str().to_owned(),
                self.scope.work_product.id.as_str().to_owned(),
                self.scope.digest().to_string(),
                self.registration.registration_digest.to_string(),
                proposal.evidence.evidence_digest.to_string(),
                proposal.proposal_digest.to_string(),
                format!("{decision_state:?}"),
            ],
        );
        Ok(MissionGithubDependabotDecision {
            consumer_id: GITHUB_DEPENDABOT_CONSUMER_ID,
            project_id: self.scope.project.id.clone(),
            mission_id: self.scope.mission.id.clone(),
            work_product_id: self.scope.work_product.id.clone(),
            decision_state,
            observed_evidence_state: proposal.evidence.state,
            alert_count: proposal.evidence.alerts.len(),
            open_alert_count: proposal.evidence.open_alert_count(),
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest,
            proposal_digest: proposal.proposal_digest,
            requires_human_review: true,
            remediation_authority: false,
            safe_to_promote: false,
            connected: false,
            native: false,
            first_party: false,
            adopted_outcome: false,
            truth_authority: false,
            decision_digest,
        })
    }

    pub fn verify_evidence(
        &self,
        evidence: &GithubDependabotEvidence,
    ) -> Result<(), ConsumerError> {
        if evidence.scope_digest != self.scope.digest()
            || evidence.permission_digest != self.registration.permission_digest
            || evidence.repository_digest != self.scope.repository.digest()
            || evidence.ref_digest != self.scope.ref_name.digest()
            || evidence.commit_digest != self.scope.commit_sha.digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        evidence
            .validate()
            .map_err(|_| ConsumerError::ProposalTampered)
    }
}

pub type MissionGithubDependabotResult = MissionGithubDependabotDecision;
pub type MissionGithubDependabotConsumerError = ConsumerError;
