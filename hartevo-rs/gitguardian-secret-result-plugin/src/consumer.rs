//! Mission-facing proposal consumer below kernel authority.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{Digest, EvidenceStatus, GitGuardianScope};
use crate::service::{
    GitGuardianRegistration, GitGuardianRemediationDecision, GitGuardianSecretResultProposal,
    ServiceError,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionGitGuardianSecretDecisionState {
    Open,
    Resolved,
    Ignored,
    Unknown,
    Partial,
    Denied,
    RateLimited,
    ProviderUnknown,
    Tampered,
}

impl From<EvidenceStatus> for MissionGitGuardianSecretDecisionState {
    fn from(state: EvidenceStatus) -> Self {
        match state {
            EvidenceStatus::Open => Self::Open,
            EvidenceStatus::Resolved => Self::Resolved,
            EvidenceStatus::Ignored => Self::Ignored,
            EvidenceStatus::Unknown => Self::Unknown,
            EvidenceStatus::Partial => Self::Partial,
            EvidenceStatus::Denied => Self::Denied,
            EvidenceStatus::RateLimited => Self::RateLimited,
            EvidenceStatus::ProviderUnknown => Self::ProviderUnknown,
            EvidenceStatus::Tampered => Self::Tampered,
        }
    }
}

pub type MissionGitGuardianSecretResultState = MissionGitGuardianSecretDecisionState;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("consumer scope or registration does not match proposal")]
    BindingMismatch,
    #[error("proposal validation failed: {0}")]
    Service(#[from] ServiceError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionGitGuardianSecretResult {
    pub state: MissionGitGuardianSecretDecisionState,
    pub decision: GitGuardianRemediationDecision,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub unresolved: bool,
    pub adopted: bool,
    pub creates_effect: bool,
    pub mutates_consent: bool,
    pub truth_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub security_certification_authority: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub decision_digest: Digest,
}

pub type MissionGitGuardianSecretDecision = MissionGitGuardianSecretResult;
pub type MissionGitGuardianSecretConsumerResult = MissionGitGuardianSecretResult;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionGitGuardianSecretConsumer {
    scope: GitGuardianScope,
    registration: GitGuardianRegistration,
}

impl MissionGitGuardianSecretConsumer {
    pub fn new(
        scope: GitGuardianScope,
        registration: &GitGuardianRegistration,
    ) -> Result<Self, ConsumerError> {
        scope.validate().map_err(ServiceError::from)?;
        if registration.scope_digest != scope.digest() {
            return Err(ConsumerError::BindingMismatch);
        }
        registration.validate_integrity()?;
        Ok(Self {
            scope,
            registration: registration.clone(),
        })
    }

    #[must_use]
    pub fn scope(&self) -> &GitGuardianScope {
        &self.scope
    }

    #[must_use]
    pub fn registration(&self) -> &GitGuardianRegistration {
        &self.registration
    }

    pub fn consume(
        &self,
        proposal: &GitGuardianSecretResultProposal,
    ) -> Result<MissionGitGuardianSecretResult, ConsumerError> {
        proposal.validate(&self.scope, &self.registration)?;
        let decision = proposal.decision;
        let state = proposal.evidence.state.into();
        let unresolved = matches!(
            proposal.evidence.state,
            EvidenceStatus::Open
                | EvidenceStatus::Unknown
                | EvidenceStatus::Partial
                | EvidenceStatus::Denied
                | EvidenceStatus::RateLimited
                | EvidenceStatus::ProviderUnknown
                | EvidenceStatus::Tampered
        );
        let decision_digest = Digest::from_serialized(&(
            &proposal.scope_digest,
            &proposal.evidence.evidence_digest,
            decision,
            state,
            unresolved,
        ));
        Ok(MissionGitGuardianSecretResult {
            state,
            decision,
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            unresolved,
            adopted: false,
            creates_effect: decision.creates_effect(),
            mutates_consent: false,
            truth_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            security_certification_authority: false,
            connected: false,
            native: false,
            first_party: false,
            decision_digest,
        })
    }

    pub fn decide(
        &self,
        proposal: &GitGuardianSecretResultProposal,
        decision: GitGuardianRemediationDecision,
    ) -> Result<MissionGitGuardianSecretResult, ConsumerError> {
        let mut proposal = proposal.clone();
        proposal.decision = decision;
        // The proposal digest is intentionally recomputed through the public
        // constructor, preserving the same digest fence as service output.
        let rebound = GitGuardianSecretResultProposal::new(
            &self.scope,
            &self.registration,
            proposal.evidence,
            decision,
        )?;
        self.consume(&rebound)
    }

    pub fn consume_proposal(
        &self,
        proposal: &GitGuardianSecretResultProposal,
    ) -> Result<MissionGitGuardianSecretResult, ConsumerError> {
        self.consume(proposal)
    }
}

pub type MissionGitGuardianSecretResultConsumer = MissionGitGuardianSecretConsumer;
pub type MissionConsumerError = ConsumerError;
